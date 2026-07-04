//! Beacon epoch ratification: per-validator prevotes/precommits over a
//! block hash and the pool-quorum certificate the precommits assemble
//! into.
//!
//! A beacon block — Normal or Skip — commits only through a
//! [`RatifyCert`]: a quorum of the active pool precommitting the same
//! `(anchor_hash, epoch, round, block_hash)`. Votes are over block
//! hashes, not path tags: `BeaconBlock::skip(epoch, anchor)` is
//! deterministic, so ratifying the skip block and ratifying an
//! SPC-certified candidate are the same vote shape, and any two commit
//! quorums intersect in an honest member regardless of how the pool
//! compares to the committee.
//!
//! Prevotes never aggregate into certs — a prevote quorum (polka) is
//! observed by each validator to gate its own precommit, and the phase
//! byte in the signing message keeps the two vote kinds from standing
//! in for each other. Cert lives outside the block hash — see
//! [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock); multiple
//! distinct certs (different signer subsets, different rounds) at the
//! same block hash authenticate the same block, so adoption converges.
//!
//! [`CandidateBeaconBlock`] is the SPC output before ratification: a
//! block paired with the proposal certificate that authenticates its
//! content. Verifying a candidate is the precondition for prevoting
//! its hash; it confers no commit authority.
//!
//! Wire types live up top; the verify / sign / build helpers follow.
//! The ratification tracker — rounds, polka detection, locks — lives
//! in the beacon crate; these pure verifiers see single messages.

use sbor::prelude::*;
use thiserror::Error;

use super::certified::verify_committed_proposal_binding;
use crate::{
    BeaconBlock, BeaconBlockHash, BeaconProposal, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, Epoch, NetworkDefinition, RatifyRound, ShardEpochContribution, ShardId,
    SignerBitfield, SpcCert, ValidatorId, Verified, Verify,
    aggregate_verify_bls_different_messages, ratify_vote_message, spc_context, verify_block_cert,
    verify_bls12381_v1, verify_vote_equivocation,
};

/// Which of the two ratification vote kinds a signature commits to.
///
/// The tag is baked into the signing bytes
/// ([`ratify_vote_message`](crate::ratify_vote_message)), so a prevote
/// can never be counted as a precommit or vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub enum RatifyPhase {
    /// First-phase vote; a quorum of prevotes (a polka) gates
    /// precommits but commits nothing.
    Prevote,
    /// Second-phase vote; casting one locks the signer, and a quorum
    /// assembles into a [`RatifyCert`].
    Precommit,
}

impl RatifyPhase {
    /// Fixed-width signing-byte tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Prevote => 0,
            Self::Precommit => 1,
        }
    }
}

/// One active validator's signed ratification vote for `block_hash` at
/// `(anchor_hash, epoch, round, phase)`.
///
/// Gossiped all-to-all across the active validator pool. A quorum of
/// precommit-phase signers over the same tuple assembles into a
/// [`RatifyCert`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RatifyVote {
    anchor_hash: BeaconBlockHash,
    epoch: Epoch,
    round: RatifyRound,
    phase: RatifyPhase,
    block_hash: BeaconBlockHash,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl RatifyVote {
    /// Build a `RatifyVote` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch,
            round,
            phase,
            block_hash,
            signer,
            sig,
        }
    }

    /// Hash of the anchor block the vote is pinned to — the latest
    /// finalized block whose epoch immediately precedes [`Self::epoch`].
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch whose block the signer is ratifying.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Ratification round within the epoch.
    #[must_use]
    pub const fn round(&self) -> RatifyRound {
        self.round
    }

    /// Vote kind — prevote or precommit.
    #[must_use]
    pub const fn phase(&self) -> RatifyPhase {
        self.phase
    }

    /// Hash of the block the signer votes to commit.
    #[must_use]
    pub const fn block_hash(&self) -> BeaconBlockHash {
        self.block_hash
    }

    /// Validator that signed this vote.
    #[must_use]
    pub const fn signer(&self) -> ValidatorId {
        self.signer
    }

    /// BLS signature over the canonical signing message.
    #[must_use]
    pub const fn sig(&self) -> Bls12381G2Signature {
        self.sig
    }
}

/// Pool-quorum commit certificate: a quorum of active signers
/// precommitted `block_hash` at `(anchor_hash, epoch, round)`.
///
/// Carried as side-data on a
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) — never part
/// of the block hash. Multiple valid certs with different signer
/// subsets or rounds all authenticate the same block hash; adoption
/// converges on the unique hash.
///
/// `signers` is positionally indexed against the active validator pool
/// at the anchor's epoch (the same enumeration
/// `derive_active_pool(state)` produces). `aggregate_sig` verifies
/// under the union of the set bits' pubkeys over the canonical
/// precommit signing bytes.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RatifyCert {
    anchor_hash: BeaconBlockHash,
    epoch: Epoch,
    round: RatifyRound,
    block_hash: BeaconBlockHash,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl RatifyCert {
    /// Build a `RatifyCert` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch: Epoch,
        round: RatifyRound,
        block_hash: BeaconBlockHash,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch,
            round,
            block_hash,
            signers,
            aggregate_sig,
        }
    }

    /// Anchor block hash the cert is pinned to.
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch whose block the cert commits.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Round the precommit quorum formed in.
    #[must_use]
    pub const fn round(&self) -> RatifyRound {
        self.round
    }

    /// Hash of the committed block.
    #[must_use]
    pub const fn block_hash(&self) -> BeaconBlockHash {
        self.block_hash
    }

    /// Bitfield indexing the active pool's positional ordering at the
    /// anchor's epoch.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over the canonical precommit signing
    /// bytes, verifying under the union of [`Self::signers`]' pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Number of validators contributing to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

/// Ratification quorum over a pool of `pool_size` members:
/// `M − ⌊(M−1)/3⌋` — the standard BFT quorum (`2f+1` at `M = 3f+1`).
///
/// Any two quorums intersect in at least `f + 1` members, at least one
/// of them honest — the intersection argument every commit-safety
/// property here reduces to — while tolerating `f` unresponsive
/// members, which the commit path's liveness rides on.
#[must_use]
pub const fn ratify_quorum(pool_size: usize) -> usize {
    pool_size - pool_size.saturating_sub(1) / 3
}

// ─── Verifiers ─────────────────────────────────────────────────────────────

/// Verify a single [`RatifyVote`] against the active pool.
///
/// Checks:
/// - Signer is a member of `active_pool`.
/// - BLS signature verifies under the signer's pubkey over the canonical
///   ratify-vote signing bytes.
///
/// The vote's `anchor_hash`, `epoch`, and `round` are not validated
/// against any local state — the coordinator gates those at admission
/// time before calling this helper.
///
/// # Errors
///
/// Returns a [`RatifyVoteVerifyError`] variant naming the failing predicate.
pub fn verify_ratify_vote(
    vote: &RatifyVote,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), RatifyVoteVerifyError> {
    let Some(signer_pk) = active_pool
        .iter()
        .find(|(id, _)| *id == vote.signer())
        .map(|(_, pk)| *pk)
    else {
        return Err(RatifyVoteVerifyError::SignerNotInPool);
    };
    let msg = ratify_vote_message(
        network,
        &vote.anchor_hash(),
        vote.epoch(),
        vote.round(),
        vote.phase(),
        &vote.block_hash(),
    );
    if verify_bls12381_v1(&msg, &signer_pk, &vote.sig()) {
        Ok(())
    } else {
        Err(RatifyVoteVerifyError::BadSignature)
    }
}

/// Verify a [`RatifyCert`] against `active_pool`.
///
/// Returns `Ok(())` only when:
/// - `cert.signers().num_validators() == active_pool.len()` — the bitfield
///   must be sized to the current pool; positional indexing breaks if
///   these diverge.
/// - Signer count meets the quorum threshold [`ratify_quorum`].
/// - The aggregate signature verifies under the union of pubkeys at the
///   set bits over the canonical **precommit** signing bytes — an
///   aggregate of prevote signatures can never verify as a cert.
///
/// Active-pool drift: `active_pool` is the pool *at verification time*.
/// If the active set has shifted between cert signing and verification,
/// drift produces a false-negative rejection rather than a false-positive
/// acceptance, preserving safety.
///
/// # Errors
///
/// Returns a [`RatifyCertVerifyError`] variant naming the failing predicate.
pub fn verify_ratify_cert(
    cert: &RatifyCert,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), RatifyCertVerifyError> {
    let pool_size = active_pool.len();
    if cert.signers().num_validators() != pool_size {
        return Err(RatifyCertVerifyError::BitfieldSizeMismatch);
    }
    let signer_count = cert.signers().count_ones();
    if signer_count < ratify_quorum(pool_size) {
        return Err(RatifyCertVerifyError::InsufficientSigners);
    }
    let signer_pks: Vec<Bls12381G1PublicKey> = cert
        .signers()
        .set_indices()
        .map(|i| active_pool[i].1)
        .collect();
    if signer_pks.is_empty() {
        return Err(RatifyCertVerifyError::EmptySignerSet);
    }
    let msg = ratify_vote_message(
        network,
        &cert.anchor_hash(),
        cert.epoch(),
        cert.round(),
        RatifyPhase::Precommit,
        &cert.block_hash(),
    );
    let msgs: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), signer_pks.len()).collect();
    if aggregate_verify_bls_different_messages(&msgs, &cert.aggregate_sig(), &signer_pks) {
        Ok(())
    } else {
        Err(RatifyCertVerifyError::BadAggregateSignature)
    }
}

// ─── Signing ───────────────────────────────────────────────────────────────

/// Build and sign a [`RatifyVote`] under `network`'s domain.
#[must_use]
#[allow(clippy::too_many_arguments)] // one parameter per signed field
pub fn sign_ratify_vote(
    sk: &Bls12381G1PrivateKey,
    signer: ValidatorId,
    network: &NetworkDefinition,
    anchor_hash: BeaconBlockHash,
    epoch: Epoch,
    round: RatifyRound,
    phase: RatifyPhase,
    block_hash: BeaconBlockHash,
) -> RatifyVote {
    let msg = ratify_vote_message(network, &anchor_hash, epoch, round, phase, &block_hash);
    let sig = sk.sign_v1(&msg);
    RatifyVote::new(anchor_hash, epoch, round, phase, block_hash, signer, sig)
}

// ─── Build ─────────────────────────────────────────────────────────────────

/// Assemble a [`RatifyCert`] from precommit-phase `votes` against
/// `active_pool`.
///
/// Returns `Some(cert)` when:
/// - All votes are [`RatifyPhase::Precommit`] and share the same
///   `(anchor_hash, epoch, round, block_hash)`.
/// - The set of distinct signers from `active_pool` meets
///   [`ratify_quorum`].
/// - BLS aggregation succeeds.
///
/// Returns `None` if the inputs are inconsistent, sub-quorum, or
/// aggregation fails. The assembled cert is self-verifying via
/// [`verify_ratify_cert`].
#[must_use]
pub fn build_ratify_cert(
    votes: &[RatifyVote],
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Option<RatifyCert> {
    let first = votes.first()?;
    let anchor_hash = first.anchor_hash();
    let epoch = first.epoch();
    let round = first.round();
    let block_hash = first.block_hash();
    if votes.iter().any(|v| {
        v.phase() != RatifyPhase::Precommit
            || v.anchor_hash() != anchor_hash
            || v.epoch() != epoch
            || v.round() != round
            || v.block_hash() != block_hash
    }) {
        return None;
    }

    let pool_size = active_pool.len();
    let mut signers = SignerBitfield::new(pool_size);
    let mut sigs = Vec::new();
    for vote in votes {
        if let Some(pos) = active_pool.iter().position(|(id, _)| *id == vote.signer())
            && !signers.is_set(pos)
        {
            signers.set(pos);
            sigs.push(vote.sig());
        }
    }

    if signers.count_ones() < ratify_quorum(pool_size) {
        return None;
    }

    let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).ok()?;
    Some(RatifyCert::new(
        anchor_hash,
        epoch,
        round,
        block_hash,
        signers,
        aggregate_sig,
    ))
}

// ─── Candidate ─────────────────────────────────────────────────────────────

/// An SPC-certified beacon block awaiting pool ratification.
///
/// The committee's SPC certificate authenticates the block's content —
/// which proposals the committee agreed on — but confers no commit
/// authority: the block commits only when a [`RatifyCert`] forms over
/// its hash. Verifying a candidate is the precondition for prevoting
/// its hash.
///
/// The verification predicate is exactly the Normal-block predicate of
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) minus the
/// ratify cert: SPC cert against the committee, embedded equivocation
/// witnesses, and the committed-proposal binding. An honest member
/// prevotes only hashes that would be valid blocks.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CandidateBeaconBlock {
    block: BeaconBlock,
    spc: Box<SpcCert>,
}

impl CandidateBeaconBlock {
    /// Pair a block with the SPC cert that authenticates its content.
    #[must_use]
    pub const fn new(block: BeaconBlock, spc: Box<SpcCert>) -> Self {
        Self { block, spc }
    }

    /// Inner block.
    #[must_use]
    pub const fn block(&self) -> &BeaconBlock {
        &self.block
    }

    /// SPC proposal certificate.
    #[must_use]
    pub const fn spc(&self) -> &SpcCert {
        &self.spc
    }

    /// Block hash — the value a ratify prevote names.
    #[must_use]
    pub fn block_hash(&self) -> BeaconBlockHash {
        self.block.block_hash()
    }

    /// Epoch of the inner block.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.block.epoch()
    }

    /// `prev_block_hash` of the inner block — the ratification anchor.
    #[must_use]
    pub const fn prev_block_hash(&self) -> BeaconBlockHash {
        self.block.prev_block_hash()
    }

    /// Consume and return parts.
    #[must_use]
    pub fn into_parts(self) -> (BeaconBlock, Box<SpcCert>) {
        (self.block, self.spc)
    }
}

// ─── Typestate ─────────────────────────────────────────────────────────────

/// Verification context for [`RatifyVote`] and [`RatifyCert`].
///
/// Both predicates resolve signers through the active validator pool
/// at the anchor's epoch. Active-pool drift produces a false-negative
/// rejection rather than a false-positive acceptance — safe at the
/// cost of liveness.
#[derive(Debug, Clone, Copy)]
pub struct RatifyVerifyContext<'a> {
    /// Network the signer was bound to.
    pub network: &'a NetworkDefinition,
    /// Active validator pool at verification time. Positional ordering
    /// matches the cert's signer bitfield.
    pub active_pool: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Failure modes of a single ratify vote.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RatifyVoteVerifyError {
    /// `signer` is not in the active validator pool.
    #[error("signer not in active pool")]
    SignerNotInPool,
    /// BLS sig did not verify under the signer's pubkey.
    #[error("signature did not verify")]
    BadSignature,
}

/// Failure modes of an aggregated ratify cert.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RatifyCertVerifyError {
    /// Signer bitfield size doesn't match the active pool's size.
    #[error("signer bitfield size does not match active pool size")]
    BitfieldSizeMismatch,
    /// Signer count below the [`ratify_quorum`] threshold.
    #[error("signer count below quorum threshold")]
    InsufficientSigners,
    /// Empty signer set after pool intersection.
    #[error("no signers after pool intersection")]
    EmptySignerSet,
    /// Aggregate BLS check rejected the signature bundle.
    #[error("aggregate signature did not verify")]
    BadAggregateSignature,
}

impl Verify<&RatifyVerifyContext<'_>> for RatifyVote {
    type Error = RatifyVoteVerifyError;

    /// Ratify-vote predicate: signer is in `active_pool` and the BLS
    /// signature verifies under the signer's pubkey over the canonical
    /// ratify-vote signing bytes.
    fn verify(&self, ctx: &RatifyVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_ratify_vote(self, ctx.network, ctx.active_pool)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&RatifyVerifyContext<'_>> for RatifyCert {
    type Error = RatifyCertVerifyError;

    /// Ratify-cert predicate: signer bitfield matches the active pool's
    /// size, signer count meets [`ratify_quorum`], and the aggregate
    /// sig verifies under the union of the set bits' pubkeys over the
    /// precommit signing bytes.
    fn verify(&self, ctx: &RatifyVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_ratify_cert(self, ctx.network, ctx.active_pool)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

/// Verification context for [`CandidateBeaconBlock`].
///
/// Mirrors the Normal-cert half of
/// [`CertifiedBeaconBlockVerifyContext`](crate::CertifiedBeaconBlockVerifyContext):
/// the SPC cert verifies against the beacon committee for the block's
/// epoch, and embedded equivocation witnesses bring their own
/// per-validator pubkey lookup.
#[derive(Debug, Clone, Copy)]
pub struct CandidateVerifyContext<'a> {
    /// Network the cert and equivocation evidence were bound to.
    pub network: &'a NetworkDefinition,
    /// Beacon committee for the candidate's epoch, in positional order.
    pub committee: &'a [(ValidatorId, Bls12381G1PublicKey)],
    /// Pubkeys for the validators referenced by embedded
    /// `PcVoteEquivocation` evidence.
    pub equivocation_signers: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Failure modes of a candidate beacon block.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CandidateBeaconBlockVerifyError {
    /// Candidates exist only past genesis — the genesis block is
    /// authenticated by operator config, not by certs.
    #[error("candidate at the genesis epoch")]
    CandidateAtGenesis,
    /// SPC cert did not verify under the committee.
    #[error("SPC proposal cert rejected")]
    BadCert,
    /// One or more embedded `PcVoteEquivocation` did not verify
    /// against the equivocation signer pool.
    #[error("embedded equivocation witness rejected")]
    BadEquivocationWitness,
    /// The block's committed proposals don't reconstruct the
    /// `PcVector` the SPC cert authenticates — a relay paired a
    /// genuine cert with substituted proposal bytes.
    #[error("committed proposals don't match the SPC cert")]
    ProposalCertMismatch,
}

impl Verify<&CandidateVerifyContext<'_>> for CandidateBeaconBlock {
    type Error = CandidateBeaconBlockVerifyError;

    /// Composite predicate: past-genesis epoch, SPC cert verifies under
    /// the committee, every embedded `PcVoteEquivocation` verifies
    /// against `equivocation_signers`, and the block's proposals
    /// reconstruct the cert's committed `PcVector`.
    fn verify(&self, ctx: &CandidateVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if self.epoch() == Epoch::GENESIS {
            return Err(CandidateBeaconBlockVerifyError::CandidateAtGenesis);
        }
        if verify_block_cert(
            self.spc(),
            ctx.network,
            &spc_context(self.epoch()),
            ctx.committee,
        )
        .is_err()
        {
            return Err(CandidateBeaconBlockVerifyError::BadCert);
        }
        for (_, proposal) in self.block().committed_proposals() {
            for ev in proposal.equivocations().iter() {
                if verify_vote_equivocation(
                    ev.as_unverified(),
                    ctx.network,
                    ctx.equivocation_signers,
                )
                .is_err()
                {
                    return Err(CandidateBeaconBlockVerifyError::BadEquivocationWitness);
                }
            }
        }
        if !verify_committed_proposal_binding(self.block(), self.spc(), ctx.committee) {
            return Err(CandidateBeaconBlockVerifyError::ProposalCertMismatch);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<RatifyVote> {
    /// Sign a ratify vote locally. The signer's own BLS sig holds by
    /// definition under the private key, so the produced vote is
    /// verified by construction.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one parameter per signed field
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        signer: ValidatorId,
        network: &NetworkDefinition,
        anchor_hash: BeaconBlockHash,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Self {
        Self::new_unchecked(sign_ratify_vote(
            sk,
            signer,
            network,
            anchor_hash,
            epoch,
            round,
            phase,
            block_hash,
        ))
    }
}

impl Verified<RatifyCert> {
    /// Aggregate a quorum-meeting set of verified precommits into a
    /// verified [`RatifyCert`]. Mirror of
    /// [`Verified::<PcQc1>::from_verified_votes`]; returns `None` on the
    /// same conditions as [`build_ratify_cert`].
    #[must_use]
    pub fn from_verified_votes(
        votes: &[&Verified<RatifyVote>],
        active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Option<Self> {
        let raw: Vec<RatifyVote> = votes.iter().map(|v| (*v).as_ref().clone()).collect();
        build_ratify_cert(&raw, active_pool).map(Self::new_unchecked)
    }
}

impl Verified<CandidateBeaconBlock> {
    /// Assemble a candidate from the SPC-committed proposals and the
    /// cert that authenticates them. Consumes the typed
    /// `Verified<BeaconProposal>` set and the `Verified<SpcCert>` by
    /// value, so a candidate cannot be built from unverified proposals
    /// or an unverified cert — verification is a type-level
    /// precondition, not a convention.
    #[must_use]
    pub fn assemble(
        epoch: Epoch,
        prev_block_hash: BeaconBlockHash,
        committed: Vec<(ValidatorId, Verified<BeaconProposal>)>,
        shard_contributions: BTreeMap<ShardId, ShardEpochContribution>,
        cert: Verified<SpcCert>,
    ) -> Self {
        let proposals: Vec<(ValidatorId, BeaconProposal)> = committed
            .into_iter()
            .map(|(id, proposal)| (id, proposal.into_inner()))
            .collect();
        let block = BeaconBlock::new_with_contributions(
            epoch,
            prev_block_hash,
            proposals,
            shard_contributions,
        );
        Self::new_unchecked(CandidateBeaconBlock::new(
            block,
            Box::new(cert.into_inner()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, bls_keypair_from_seed};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn block_hash() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"block"))
    }

    fn signing_key(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn pool(
        n: u64,
    ) -> (
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
        Vec<Bls12381G1PrivateKey>,
    ) {
        let mut active = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let sk = signing_key(i);
            active.push((ValidatorId::new(i), sk.public_key()));
            keys.push(sk);
        }
        (active, keys)
    }

    fn precommit(keys: &[Bls12381G1PrivateKey], i: u64, round: RatifyRound) -> RatifyVote {
        sign_ratify_vote(
            &keys[usize::try_from(i).unwrap()],
            ValidatorId::new(i),
            &net(),
            anchor(),
            Epoch::new(9),
            round,
            RatifyPhase::Precommit,
            block_hash(),
        )
    }

    fn sample_vote() -> RatifyVote {
        RatifyVote::new(
            anchor(),
            Epoch::new(7),
            RatifyRound::new(2),
            RatifyPhase::Prevote,
            block_hash(),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_cert() -> RatifyCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RatifyCert::new(
            anchor(),
            Epoch::new(7),
            RatifyRound::INITIAL,
            block_hash(),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn vote_sbor_round_trip() {
        let original = sample_vote();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RatifyVote = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_sbor_round_trip() {
        let original = sample_cert();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RatifyCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_signer_count_reflects_bitfield() {
        assert_eq!(sample_cert().signer_count(), 3);
    }

    /// The standard BFT quorum: `2f+1` at `M = 3f+1`, tolerating `f`
    /// unresponsive members while any two quorums share an honest one.
    #[test]
    fn quorum_is_the_standard_bft_threshold() {
        assert_eq!(ratify_quorum(4), 3);
        assert_eq!(ratify_quorum(7), 5);
        assert_eq!(ratify_quorum(10), 7);
        assert_eq!(ratify_quorum(13), 9);
    }

    // ─── Verifier / builder tests ──────────────────────────────────────

    #[test]
    fn verify_ratify_vote_accepts_genuine() {
        let (active, keys) = pool(4);
        let vote = precommit(&keys, 2, RatifyRound::INITIAL);
        assert!(verify_ratify_vote(&vote, &net(), &active).is_ok());
    }

    #[test]
    fn verify_ratify_vote_rejects_unknown_signer() {
        let (active, _keys) = pool(4);
        let outsider = signing_key(99);
        let vote = sign_ratify_vote(
            &outsider,
            ValidatorId::new(99),
            &net(),
            anchor(),
            Epoch::new(9),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            block_hash(),
        );
        assert!(verify_ratify_vote(&vote, &net(), &active).is_err());
    }

    #[test]
    fn verify_ratify_vote_rejects_tampered_sig() {
        let (active, keys) = pool(4);
        let vote = precommit(&keys, 2, RatifyRound::INITIAL);
        let mut sig = vote.sig();
        sig.0[0] ^= 1;
        let tampered = RatifyVote::new(
            vote.anchor_hash(),
            vote.epoch(),
            vote.round(),
            vote.phase(),
            vote.block_hash(),
            vote.signer(),
            sig,
        );
        assert!(verify_ratify_vote(&tampered, &net(), &active).is_err());
    }

    /// `build_ratify_cert` followed by `verify_ratify_cert` round-trips
    /// a quorum-meeting set of precommits.
    #[test]
    fn build_then_verify_ratify_cert_round_trips() {
        // Pool of 7, quorum = 7 − 2 = 5.
        let (active, keys) = pool(7);
        let votes: Vec<RatifyVote> = (0..6)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        let cert = build_ratify_cert(&votes, &active).expect("quorum met");
        assert_eq!(cert.signer_count(), 6);
        assert_eq!(cert.block_hash(), block_hash());
        assert!(verify_ratify_cert(&cert, &net(), &active).is_ok());
    }

    #[test]
    fn build_ratify_cert_rejects_below_quorum() {
        let (active, keys) = pool(7);
        let votes: Vec<RatifyVote> = (0..4)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        assert!(build_ratify_cert(&votes, &active).is_none());
    }

    /// Prevotes never assemble into a cert — a polka is observed, not
    /// aggregated. Quorum-many prevotes must not build.
    #[test]
    fn build_ratify_cert_rejects_prevote_phase() {
        let (active, keys) = pool(7);
        let votes: Vec<RatifyVote> = (0..6u64)
            .map(|i| {
                sign_ratify_vote(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                    RatifyRound::INITIAL,
                    RatifyPhase::Prevote,
                    block_hash(),
                )
            })
            .collect();
        assert!(build_ratify_cert(&votes, &active).is_none());
    }

    /// A cert whose aggregate was built from prevote signatures must
    /// not verify: the phase byte in the signing message is what makes
    /// a "prevote quorum laundered as a commit" cryptographically
    /// impossible, not just a builder-side refusal.
    #[test]
    fn verify_ratify_cert_rejects_prevote_aggregate_forgery() {
        let (active, keys) = pool(7);
        let prevote_sigs: Vec<Bls12381G2Signature> = (0..6u64)
            .map(|i| {
                sign_ratify_vote(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                    RatifyRound::INITIAL,
                    RatifyPhase::Prevote,
                    block_hash(),
                )
                .sig()
            })
            .collect();
        let mut signers = SignerBitfield::new(7);
        for i in 0..6 {
            signers.set(i);
        }
        let aggregate = Bls12381G2Signature::aggregate(&prevote_sigs, true).unwrap();
        let forged = RatifyCert::new(
            anchor(),
            Epoch::new(9),
            RatifyRound::INITIAL,
            block_hash(),
            signers,
            aggregate,
        );
        assert_eq!(
            verify_ratify_cert(&forged, &net(), &active),
            Err(RatifyCertVerifyError::BadAggregateSignature)
        );
    }

    #[test]
    fn build_ratify_cert_rejects_mixed_rounds() {
        let (active, keys) = pool(7);
        let mut votes: Vec<RatifyVote> = (0..6)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        votes[5] = precommit(&keys, 5, RatifyRound::new(2));
        assert!(build_ratify_cert(&votes, &active).is_none());
    }

    #[test]
    fn build_ratify_cert_rejects_mixed_block_hashes() {
        let (active, keys) = pool(7);
        let mut votes: Vec<RatifyVote> = (0..6)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"other-block"));
        votes[5] = sign_ratify_vote(
            &keys[5],
            ValidatorId::new(5),
            &net(),
            anchor(),
            Epoch::new(9),
            RatifyRound::INITIAL,
            RatifyPhase::Precommit,
            other,
        );
        assert!(build_ratify_cert(&votes, &active).is_none());
    }

    #[test]
    fn build_ratify_cert_dedupes_repeated_signer() {
        let (active, keys) = pool(7);
        // 6 distinct signers + one duplicate of signer 0 — the signer
        // count must reflect dedup, not raw vote count.
        let mut votes: Vec<RatifyVote> = (0..6)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        votes.push(precommit(&keys, 0, RatifyRound::INITIAL));
        let cert = build_ratify_cert(&votes, &active).expect("quorum met");
        assert_eq!(cert.signer_count(), 6);
        assert!(verify_ratify_cert(&cert, &net(), &active).is_ok());
    }

    #[test]
    fn verify_ratify_cert_rejects_bitfield_size_mismatch() {
        let (active, keys) = pool(7);
        let votes: Vec<RatifyVote> = (0..7)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        let cert = build_ratify_cert(&votes, &active).expect("quorum met");
        // Verify against a shrunken pool — bitfield positional indexing
        // breaks and the cert must be rejected.
        let shrunken: Vec<_> = active.into_iter().take(6).collect();
        assert!(verify_ratify_cert(&cert, &net(), &shrunken).is_err());
    }

    #[test]
    fn verify_ratify_cert_rejects_tampered_aggregate() {
        let (active, keys) = pool(7);
        let votes: Vec<RatifyVote> = (0..7)
            .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
            .collect();
        let cert = build_ratify_cert(&votes, &active).expect("quorum met");
        let mut bad_sig = cert.aggregate_sig();
        bad_sig.0[0] ^= 1;
        let tampered = RatifyCert::new(
            cert.anchor_hash(),
            cert.epoch(),
            cert.round(),
            cert.block_hash(),
            cert.signers().clone(),
            bad_sig,
        );
        assert!(verify_ratify_cert(&tampered, &net(), &active).is_err());
    }

    /// Two distinct signer subsets at the same
    /// `(anchor, epoch, round, block_hash)` both pass
    /// `verify_ratify_cert` — the property that lets adoption converge
    /// on the unique block hash however the certs were assembled.
    #[test]
    fn two_distinct_quorum_subsets_both_verify() {
        // Pool of 10, quorum = 10 − 3 = 7.
        let (active, keys) = pool(10);
        let make_subset = |range: std::ops::Range<u64>| -> Vec<RatifyVote> {
            range
                .map(|i| precommit(&keys, i, RatifyRound::INITIAL))
                .collect()
        };
        let cert_a = build_ratify_cert(&make_subset(0..8), &active).expect("quorum met");
        let cert_b = build_ratify_cert(&make_subset(2..10), &active).expect("quorum met");
        assert_ne!(
            cert_a, cert_b,
            "different signer subsets must produce different certs"
        );
        assert!(verify_ratify_cert(&cert_a, &net(), &active).is_ok());
        assert!(verify_ratify_cert(&cert_b, &net(), &active).is_ok());
    }

    // ─── Candidate tests ───────────────────────────────────────────────

    fn dummy_spc_cert() -> Box<SpcCert> {
        use crate::{PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, SpcView};
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        let qc3 = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x11; 96]),
        );
        Box::new(SpcCert::Direct {
            prev_view: SpcView::INITIAL,
            value: PcVector::empty(),
            proof: qc3.into(),
        })
    }

    #[test]
    fn candidate_sbor_round_trip() {
        let original = CandidateBeaconBlock::new(
            BeaconBlock::new(Epoch::new(3), anchor(), Vec::new()),
            dummy_spc_cert(),
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: CandidateBeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    /// The candidate's hash and anchor are the inner block's — the SPC
    /// cert is side-data, exactly like the certified wrapper.
    #[test]
    fn candidate_identity_delegates_to_block() {
        let block = BeaconBlock::new(Epoch::new(3), anchor(), Vec::new());
        let expected_hash = block.block_hash();
        let candidate = CandidateBeaconBlock::new(block, dummy_spc_cert());
        assert_eq!(candidate.block_hash(), expected_hash);
        assert_eq!(candidate.epoch(), Epoch::new(3));
        assert_eq!(candidate.prev_block_hash(), anchor());
    }

    #[test]
    fn candidate_at_genesis_rejects() {
        let (active, _) = pool(4);
        let candidate = CandidateBeaconBlock::new(BeaconBlock::genesis(), dummy_spc_cert());
        let ctx = CandidateVerifyContext {
            network: &net(),
            committee: &active,
            equivocation_signers: &[],
        };
        assert_eq!(
            candidate.verify(&ctx),
            Err(CandidateBeaconBlockVerifyError::CandidateAtGenesis)
        );
    }

    #[test]
    fn candidate_with_garbage_cert_rejects() {
        let (active, _) = pool(4);
        let candidate = CandidateBeaconBlock::new(
            BeaconBlock::new(Epoch::new(3), anchor(), Vec::new()),
            dummy_spc_cert(),
        );
        let ctx = CandidateVerifyContext {
            network: &net(),
            committee: &active,
            equivocation_signers: &[],
        };
        assert_eq!(
            candidate.verify(&ctx),
            Err(CandidateBeaconBlockVerifyError::BadCert)
        );
    }
}
