//! Quorum certificate for shard consensus.
//!
//! [`QuorumCertificate`] is the raw wire form. Its verified form is
//! `Verified<QuorumCertificate>`; predicate at
//! [`impl Verify<&QcContext<'_>>`](Verify::verify) below.

use hyperscale_crypto::Verifier;
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    AggregateSignature, BlockHash, BlockHeight, BlockVote, BlockVoteMessage, ChainOrigin,
    ConsensusPublicKey, ConsensusSignature, NetworkDefinition, Round, ShardId, SignerBitfield,
    Verified, Verify, VoteCount, WeightedTimestamp, signed_bytes,
};

/// A quorum certificate proving 2f+1 validators voted for a block.
///
/// Contains an aggregated signature from the voting validators.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct QuorumCertificate {
    block_hash: BlockHash,
    shard_id: ShardId,
    height: BlockHeight,
    parent_block_hash: BlockHash,
    round: Round,
    signers: SignerBitfield,
    aggregated_signature: AggregateSignature,
    weighted_timestamp: WeightedTimestamp,
}

impl QuorumCertificate {
    /// Build a `QuorumCertificate` from its parts.
    #[allow(clippy::too_many_arguments)] // mirrors the 8 stored fields
    #[must_use]
    pub const fn new(
        block_hash: BlockHash,
        shard_id: ShardId,
        height: BlockHeight,
        parent_block_hash: BlockHash,
        round: Round,
        signers: SignerBitfield,
        aggregated_signature: AggregateSignature,
        weighted_timestamp: WeightedTimestamp,
    ) -> Self {
        Self {
            block_hash,
            shard_id,
            height,
            parent_block_hash,
            round,
            signers,
            aggregated_signature,
            weighted_timestamp,
        }
    }

    /// Create the genesis QC of a chain with the given [`ChainOrigin`].
    ///
    /// The shard is tagged on the QC so any committee lookup keyed off
    /// `qc.shard_id` resolves the same shard the QC anchors. A
    /// fixed-`ShardId::ROOT` default would silently route shard-N
    /// committee lookups to shard 0 for any genesis-anchored header.
    /// The genesis QC has a zero block hash and zero signature.
    ///
    /// The origin supplies the genesis block's height and the chain's
    /// start-time anchor, carried as the QC's weighted timestamp: the BFT
    /// clock reads its floor from `parent_qc.weighted_timestamp`, so a
    /// chain's first blocks anchor their validity windows and committee
    /// lookups here. Chains born at network genesis pass
    /// [`ChainOrigin::ROOT`]; a child chain created by a shard split
    /// continues the parent's height line and clock instead of resetting
    /// them mid-network-life.
    #[must_use]
    pub const fn genesis(shard_id: ShardId, origin: ChainOrigin) -> Self {
        Self {
            block_hash: BlockHash::ZERO,
            shard_id,
            height: origin.genesis_height,
            parent_block_hash: BlockHash::ZERO,
            round: Round::INITIAL,
            signers: SignerBitfield::empty(),
            aggregated_signature: AggregateSignature::ZERO,
            weighted_timestamp: origin.anchor_wt,
        }
    }

    /// Hash of the block this QC certifies.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Shard group this QC belongs to (prevents cross-shard replay).
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Height of the certified block.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// Hash of the parent block (for two-chain commit rule).
    #[must_use]
    pub const fn parent_block_hash(&self) -> BlockHash {
        self.parent_block_hash
    }

    /// Round number when this QC was formed.
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Bitfield indicating which validators signed.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated signature from all signers.
    #[must_use]
    pub const fn aggregated_signature(&self) -> AggregateSignature {
        self.aggregated_signature
    }

    /// BFT-authenticated stake-weighted block timestamp.
    /// Computed as: `sum(timestamp_i` * `stake_i`) / `sum(stake_i)`
    #[must_use]
    pub const fn weighted_timestamp(&self) -> WeightedTimestamp {
        self.weighted_timestamp
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlockHash,
        ShardId,
        BlockHeight,
        BlockHash,
        Round,
        SignerBitfield,
        AggregateSignature,
        WeightedTimestamp,
    ) {
        (
            self.block_hash,
            self.shard_id,
            self.height,
            self.parent_block_hash,
            self.round,
            self.signers,
            self.aggregated_signature,
            self.weighted_timestamp,
        )
    }

    /// Build the canonical signing message for this QC.
    ///
    /// The [`BlockVoteMessage`] domain separates it from every other signature.
    /// This is the same message used for individual block vote verification.
    #[must_use]
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &BlockVoteMessage {
                shard_group: self.shard_id,
                height: self.height,
                round: self.round,
                block_hash: self.block_hash,
                parent_block_hash: self.parent_block_hash,
            },
            network,
        )
    }

    /// Check if this is a genesis QC.
    ///
    /// Structural and deliberately height-blind: a genesis QC certifies
    /// no block (zero hash) and carries no votes (empty signers), while a
    /// real QC always certifies a real block hash with 2f+1 signers. A
    /// chain's genesis height is a per-chain property — a split child's
    /// genesis continues the parent's height line — so height cannot
    /// identify genesis. Sites that bypass signature verification for
    /// genesis QCs reconstruct the canonical genesis from the chain's
    /// [`ChainOrigin`] and byte-compare, so a genesis-shape QC claiming
    /// the wrong height or anchor never verifies.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.block_hash == BlockHash::ZERO && self.signers.is_empty()
    }

    /// Get the number of signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }

    /// Two-chain commit rule: Check if this QC enables committing the parent block.
    ///
    /// A QC for block at height N allows committing the block at height
    /// N-1. A genesis QC enables no commit, and neither does a QC at the
    /// absolute height floor (no block sits below height 0 on any chain).
    #[must_use]
    pub fn has_committable_block(&self) -> bool {
        self.height != BlockHeight::GENESIS && !self.is_genesis()
    }

    /// Get the height of the committable block (parent height).
    ///
    /// Returns None for genesis QC.
    #[must_use]
    pub fn committable_height(&self) -> Option<BlockHeight> {
        if self.has_committable_block() {
            self.height.prev()
        } else {
            None
        }
    }

    /// Get the hash of the committable block (parent hash).
    ///
    /// Returns None for genesis QC.
    #[must_use]
    pub fn committable_hash(&self) -> Option<BlockHash> {
        if self.has_committable_block() {
            Some(self.parent_block_hash)
        } else {
            None
        }
    }
}

/// Inputs the QC verifier reads against. The verifier borrows everything;
/// nothing in here is consumed.
///
/// `public_keys` is indexed parallel to the QC's signer bitfield —
/// `public_keys[i]` corresponds to the validator whose bit `i` may be set in
/// `qc.signers()`. The committee size (`public_keys.len()`) bounds which set
/// bits count as votes.
#[derive(Debug, Clone, Copy)]
pub struct QcContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// Public keys for every validator in this QC's committee.
    pub public_keys: &'a [ConsensusPublicKey],
    /// Minimum vote count required to constitute a quorum.
    pub quorum_threshold: VoteCount,
    /// Scheme verifier the aggregate check runs through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`QuorumCertificate`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum QcVerifyError {
    /// The QC has no signers set in its bitfield. A QC with zero signers
    /// is rejected before any cryptographic work; the genesis QC bypasses
    /// `verify` via [`Verified::<QuorumCertificate>::genesis`](Verified::genesis).
    #[error("QC has no signers")]
    NoSigners,
    /// The aggregated signature did not validate against the aggregated
    /// public keys for the QC's signing message.
    #[error("aggregated signature invalid")]
    InvalidSignature,
    /// The signers' combined voting power is below the quorum threshold.
    #[error("insufficient quorum power: have {have:?}, need {need:?}")]
    InsufficientQuorumPower {
        /// Voting power held by the signers in the QC's bitfield.
        have: VoteCount,
        /// Voting power required to constitute a quorum.
        need: VoteCount,
    },
}

impl Verified<QuorumCertificate> {
    /// Verified form of the genesis QC. Valid by definition: the genesis
    /// QC carries no signature, and `verify` would reject it for having
    /// zero signers, so this constructor is the only path to the genesis
    /// verified value.
    #[must_use]
    pub const fn genesis(shard_id: ShardId, origin: ChainOrigin) -> Self {
        Self::new_unchecked(QuorumCertificate::genesis(shard_id, origin))
    }

    /// Re-wrap a [`QuorumCertificate`] read out of persistent storage
    /// as verified.
    ///
    /// QCs are persisted only after passing
    /// [`<QuorumCertificate as Verify>::verify`](Verify::verify) at
    /// admission, so re-reading them post-restart returns values whose
    /// predicate already held at write-time. The shard storage write
    /// entry point (the prepared commit) takes
    /// `&Arc<Verified<CertifiedBlock>>` with the QC embedded, so
    /// unverified QCs can't reach the write path. Callers in storage
    /// adapters or recovery paths use this constructor; any other
    /// caller is misusing it.
    #[must_use]
    pub const fn from_persisted(qc: QuorumCertificate) -> Self {
        Self::new_unchecked(qc)
    }

    /// Aggregate a verified vote set into a `Verified<QuorumCertificate>`.
    ///
    /// Sorts by committee index so the signer bitfield matches the order
    /// the verifier will use, aggregates the signatures, and computes
    /// the stake-weighted timestamp clamped to `parent_weighted_timestamp`
    /// (so the resulting QC's `weighted_timestamp` is monotonically `>=`
    /// the parent's).
    ///
    /// Construction asserts:
    /// 1. Every vote was verified — witnessed by the typed
    ///    `Verified<BlockVote>` input.
    /// 2. signature aggregation over the votes' signatures succeeded.
    ///
    /// The caller is responsible for ensuring `verified_votes` is
    /// non-empty and that the combined voting power clears the quorum
    /// threshold — both checks live one level up in the verify-and-build
    /// flow that calls this constructor. The
    /// `Verified<QuorumCertificate>` predicate folds in both an
    /// aggregated-signature check and a quorum-power check, so the
    /// caller's quorum pre-check is what makes the typed result honest.
    ///
    /// Returns `None` when the signature aggregation library rejects the
    /// signature set (empty input or internal validation failure).
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirrors the QC's signed-over fields
    pub fn from_verified_votes(
        verifier: &dyn Verifier,
        block_hash: BlockHash,
        shard_id: ShardId,
        height: BlockHeight,
        round: Round,
        parent_block_hash: BlockHash,
        parent_weighted_timestamp: WeightedTimestamp,
        verified_votes: &[(usize, Verified<BlockVote>)],
    ) -> Option<Self> {
        let mut sorted: Vec<_> = verified_votes.to_vec();
        sorted.sort_by_key(|(idx, _)| *idx);

        let signatures: Vec<ConsensusSignature> =
            sorted.iter().map(|(_, v)| v.signature()).collect();
        let aggregated_signature = verifier.aggregate(&signatures).ok()?;

        let floor_ms = parent_weighted_timestamp.as_millis();
        let max_idx = sorted.iter().map(|(idx, _)| *idx).max().unwrap_or(0);
        let mut signers = SignerBitfield::new(max_idx + 1);
        let mut timestamp_sum: u128 = 0;
        for (idx, vote) in &sorted {
            signers.set(*idx);
            // Per-vote monotonicity clamp: a vote timestamp below
            // parent's `weighted_timestamp` (slow honest clock or
            // Byzantine voter) is raised to the floor before
            // aggregation, so the resulting QC's `weighted_timestamp`
            // is guaranteed >= parent's.
            let clamped_ms = vote.timestamp().as_millis().max(floor_ms);
            timestamp_sum += u128::from(clamped_ms);
        }

        // Every vote weighs one, so the aggregate timestamp is the mean of
        // the clamped vote timestamps.
        let weighted_timestamp_ms = if sorted.is_empty() {
            0
        } else {
            u64::try_from(timestamp_sum / sorted.len() as u128).unwrap_or(u64::MAX)
        };

        // SAFETY: every vote in `verified_votes` carries a type-level
        // claim that its signature validates against the voter's
        // pubkey for `BlockVoteMessage`. The signature aggregation just
        // succeeded against those same signatures, so the resulting
        // aggregated signature verifies against the matching
        // aggregated public key. Quorum is the caller's precondition.
        Some(Self::new_unchecked(QuorumCertificate::new(
            block_hash,
            shard_id,
            height,
            parent_block_hash,
            round,
            signers,
            aggregated_signature,
            WeightedTimestamp::from_millis(weighted_timestamp_ms),
        )))
    }
}

/// Construction asserts: the aggregated signature over the QC's
/// signing message validates against the aggregated public keys selected
/// by the signer bitfield, **and** the signers' combined voting power
/// meets the quorum threshold. The QC↔block linkage check
/// (`qc.block_hash == block.header.hash()`) is *not* part of this
/// predicate — it belongs to the container types that hold the QC.
///
/// Construction goes through one of four gates:
///
/// - [`<QuorumCertificate as Verify>::verify`](Verify::verify) — runs the
///   full predicate.
/// - [`Verified::<QuorumCertificate>::genesis`] — produces the
///   well-defined zero-signature QC for block 0. Valid by definition; no
///   signature exists to verify.
/// - [`Verified::<QuorumCertificate>::from_verified_votes`] — aggregates
///   a typed-`Verified<BlockVote>` set into a verified QC. Per-vote
///   signatures are witnessed by the typed input; the caller supplies
///   the quorum precondition before invoking.
/// - [`Verified::<QuorumCertificate>::from_persisted`] — re-wraps a QC
///   recovered from persistent storage. The trust source is that
///   persistence runs only after [`<QuorumCertificate as Verify>::verify`](Verify::verify)
///   accepted the QC at admission.
impl Verify<&QcContext<'_>> for QuorumCertificate {
    type Error = QcVerifyError;

    fn verify(&self, ctx: &QcContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let signer_keys: Vec<ConsensusPublicKey> = ctx
            .public_keys
            .iter()
            .enumerate()
            .filter(|(i, _)| self.signers.is_set(*i))
            .map(|(_, pk)| *pk)
            .collect();
        if signer_keys.is_empty() {
            return Err(QcVerifyError::NoSigners);
        }

        let signing_message = self.signing_message(ctx.network);
        if !ctx.verifier.verify_aggregate_same_message(
            &signing_message,
            &self.aggregated_signature,
            &signer_keys,
        ) {
            return Err(QcVerifyError::InvalidSignature);
        }

        // `signer_keys` holds exactly the set bits within the committee, so its
        // length is the number of validators that signed.
        let total_votes = VoteCount::of(signer_keys.len());
        if total_votes < ctx.quorum_threshold {
            return Err(QcVerifyError::InsufficientQuorumPower {
                have: total_votes,
                need: ctx.quorum_threshold,
            });
        }

        Ok(Verified::new_unchecked(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_genesis_qc() {
        let qc = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        assert!(qc.is_genesis());
        assert_eq!(qc.height(), BlockHeight::new(0));
        assert_eq!(qc.block_hash(), BlockHash::ZERO);
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.has_committable_block());
        assert!(qc.committable_height().is_none());
        assert!(qc.committable_hash().is_none());
    }

    #[test]
    fn test_non_genesis_qc() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"block1")),
            ShardId::ROOT,
            BlockHeight::new(1),
            parent_block_hash,
            Round::INITIAL,
            signers,
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(1000),
        );

        assert!(!qc.is_genesis());
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.has_committable_block());
        assert_eq!(qc.committable_height(), Some(BlockHeight::new(0)));
        assert_eq!(qc.committable_hash(), Some(parent_block_hash));
    }

    // ─── Verify impl tests ──────────────────────────────────────────────

    /// Build a QC with `signer_indices` of the `n`-validator committee
    /// signing it. Each signer signs the canonical `BlockVoteMessage`,
    /// and the resulting signatures are aggregated into the QC. Returns
    /// the QC and the committee's public keys (in committee order).
    fn signed_qc(
        keys: &[BlsSigner],
        signer_indices: &[usize],
        block_hash: BlockHash,
        shard: ShardId,
        height: BlockHeight,
        round: Round,
    ) -> QuorumCertificate {
        let net = NetworkDefinition::simulator();
        // Sign over the same parent the QC carries, so the aggregate verifies.
        let message = signed_bytes(
            &BlockVoteMessage {
                shard_group: shard,
                height,
                round,
                block_hash,
                parent_block_hash: BlockHash::ZERO,
            },
            &net,
        );

        let sigs: Vec<ConsensusSignature> = signer_indices
            .iter()
            .map(|&i| keys[i].sign(&message).expect("sign"))
            .collect();
        let agg_sig = BlsVerifier.aggregate(&sigs).expect("aggregate sigs");

        let mut signers = SignerBitfield::new(keys.len());
        for &i in signer_indices {
            signers.set(i);
        }

        QuorumCertificate::new(
            block_hash,
            shard,
            height,
            BlockHash::ZERO,
            round,
            signers,
            agg_sig,
            WeightedTimestamp::ZERO,
        )
    }

    fn ctx<'a>(
        net: &'a NetworkDefinition,
        public_keys: &'a [ConsensusPublicKey],
        quorum_threshold: VoteCount,
    ) -> QcContext<'a> {
        QcContext {
            verifier: &BlsVerifier,
            network: net,
            public_keys,
            quorum_threshold,
        }
    }

    #[test]
    fn verify_accepts_valid_qc_with_quorum_signers() {
        let keys: Vec<_> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();

        let qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
        );

        let net = NetworkDefinition::simulator();
        let verified = qc.verify(&ctx(&net, &pubs, VoteCount::new(3))).unwrap();
        assert_eq!(verified.signer_count(), 3);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let keys: Vec<_> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();

        let mut qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
        );

        // Tamper: replace the aggregated signature with one signed over a
        // different message, so the signature check fails on aggregation.
        let net = NetworkDefinition::simulator();
        let wrong_msg = signed_bytes(
            &BlockVoteMessage {
                shard_group: ShardId::ROOT,
                height: BlockHeight::new(1),
                round: Round::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"other_block")),
                parent_block_hash: BlockHash::ZERO,
            },
            &net,
        );
        let bad_sigs: Vec<_> = [0, 1, 2]
            .iter()
            .map(|&i| keys[i].sign(&wrong_msg).expect("sign"))
            .collect();
        let bad_agg = BlsVerifier.aggregate(&bad_sigs).unwrap();
        let (block_hash, shard, height, parent, round, signers, _sig, ts) = qc.clone().into_parts();
        qc = QuorumCertificate::new(
            block_hash, shard, height, parent, round, signers, bad_agg, ts,
        );

        let err = qc.verify(&ctx(&net, &pubs, VoteCount::new(3))).unwrap_err();
        assert_eq!(err, QcVerifyError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_forged_parent_block_hash() {
        // `parent_block_hash` selects the committable block under the two-chain
        // commit rule. Repointing it at a sibling — the forged-parent fork —
        // must fail verification now that the field is in the signed message.
        let keys: Vec<_> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();

        // `signed_qc` signs over parent = ZERO; keep the genuine signature but
        // repoint the parent at a sibling block.
        let qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
        );
        let (block_hash, shard, height, _parent, round, signers, sig, ts) = qc.into_parts();
        let forged = QuorumCertificate::new(
            block_hash,
            shard,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"sibling")),
            round,
            signers,
            sig,
            ts,
        );

        let net = NetworkDefinition::simulator();
        let err = forged
            .verify(&ctx(&net, &pubs, VoteCount::new(3)))
            .unwrap_err();
        assert_eq!(err, QcVerifyError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_under_quorum_signer_set() {
        let keys: Vec<_> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();

        // Only two of four sign — quorum is three. Signatures themselves
        // are valid; the stake total falls short.
        let qc = signed_qc(
            &keys,
            &[0, 1],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
        );

        let net = NetworkDefinition::simulator();
        let err = qc.verify(&ctx(&net, &pubs, VoteCount::new(3))).unwrap_err();
        assert_eq!(
            err,
            QcVerifyError::InsufficientQuorumPower {
                have: VoteCount::new(2),
                need: VoteCount::new(3),
            }
        );
    }

    #[test]
    fn verify_rejects_qc_with_no_signers() {
        let keys: Vec<_> = (0..2).map(|_| BlsSigner::generate()).collect();
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();

        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"b")),
            ShardId::ROOT,
            BlockHeight::new(1),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(2),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );

        let net = NetworkDefinition::simulator();
        let err = qc.verify(&ctx(&net, &pubs, VoteCount::new(1))).unwrap_err();
        assert_eq!(err, QcVerifyError::NoSigners);
    }
}
