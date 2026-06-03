//! Quorum certificate for shard consensus.
//!
//! [`QuorumCertificate`] is the raw wire form. Its verified form is
//! `Verified<QuorumCertificate>`; predicate at
//! [`impl Verify<&QcContext<'_>>`](Verify::verify) below.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, BlockVote, Bls12381G1PublicKey, Bls12381G2Signature, NetworkDefinition,
    Round, ShardGroupId, SignerBitfield, Verified, Verify, VotePower, WeightedTimestamp,
    block_vote_message, verify_bls12381_v1, zero_bls_signature,
};

/// A quorum certificate proving 2f+1 validators voted for a block.
///
/// Contains an aggregated BLS signature from the voting validators.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct QuorumCertificate {
    block_hash: BlockHash,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    parent_block_hash: BlockHash,
    round: Round,
    signers: SignerBitfield,
    aggregated_signature: Bls12381G2Signature,
    weighted_timestamp: WeightedTimestamp,
}

impl QuorumCertificate {
    /// Build a `QuorumCertificate` from its parts.
    #[allow(clippy::too_many_arguments)] // mirrors the 8 stored fields
    #[must_use]
    pub const fn new(
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        parent_block_hash: BlockHash,
        round: Round,
        signers: SignerBitfield,
        aggregated_signature: Bls12381G2Signature,
        weighted_timestamp: WeightedTimestamp,
    ) -> Self {
        Self {
            block_hash,
            shard_group_id,
            height,
            parent_block_hash,
            round,
            signers,
            aggregated_signature,
            weighted_timestamp,
        }
    }

    /// Create a genesis QC (for block 0) for the given shard.
    ///
    /// The shard is tagged on the QC so any committee lookup keyed off
    /// `qc.shard_group_id` resolves the same shard the QC anchors. A
    /// fixed-`ShardGroupId::new(0)` default would silently route shard-N
    /// committee lookups to shard 0 for any genesis-anchored header.
    /// The genesis QC has a zero block hash and zero signature.
    #[must_use]
    pub const fn genesis(shard_group_id: ShardGroupId) -> Self {
        Self {
            block_hash: BlockHash::ZERO,
            shard_group_id,
            height: BlockHeight::new(0),
            parent_block_hash: BlockHash::ZERO,
            round: Round::INITIAL,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            weighted_timestamp: WeightedTimestamp::ZERO,
        }
    }

    /// Hash of the block this QC certifies.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Shard group this QC belongs to (prevents cross-shard replay).
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.shard_group_id
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

    /// Aggregated BLS signature from all signers.
    #[must_use]
    pub const fn aggregated_signature(&self) -> Bls12381G2Signature {
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
        ShardGroupId,
        BlockHeight,
        BlockHash,
        Round,
        SignerBitfield,
        Bls12381G2Signature,
        WeightedTimestamp,
    ) {
        (
            self.block_hash,
            self.shard_group_id,
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
    /// Uses `DOMAIN_BLOCK_VOTE` tag for domain separation.
    /// This is the same message used for individual block vote verification.
    #[must_use]
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        block_vote_message(
            network,
            self.shard_group_id,
            self.height,
            self.round,
            &self.block_hash,
            &self.parent_block_hash,
        )
    }

    /// Check if this is a genesis QC.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.height == BlockHeight::GENESIS && self.block_hash == BlockHash::ZERO
    }

    /// Get the number of signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }

    /// Two-chain commit rule: Check if this QC enables committing the parent block.
    ///
    /// A QC for block at height N allows committing the block at height N-1.
    /// Genesis QC (height 0) doesn't enable any commit.
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
/// `public_keys` and `voting_powers` are indexed parallel to the QC's
/// signer bitfield — `public_keys[i]` and `voting_powers[i]` correspond to
/// the validator whose bit `i` may be set in `qc.signers()`.
#[derive(Debug, Clone, Copy)]
pub struct QcContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// BLS public keys for every validator in this QC's committee.
    pub public_keys: &'a [Bls12381G1PublicKey],
    /// Stake-weighted voting power for every validator in this QC's
    /// committee. Same indexing as `public_keys`.
    pub voting_powers: &'a [VotePower],
    /// Minimum aggregate voting power required to constitute a quorum.
    pub quorum_threshold: VotePower,
}

/// Failure modes of [`QuorumCertificate`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum QcVerifyError {
    /// The QC has no signers set in its bitfield. A QC with zero signers
    /// is rejected before any cryptographic work; the genesis QC bypasses
    /// `verify` via [`VerifiedQuorumCertificate::genesis`].
    #[error("QC has no signers")]
    NoSigners,
    /// Aggregating the selected signer public keys failed (the BLS
    /// library rejected the input — typically an empty aggregate or an
    /// internal validation failure).
    #[error("failed to aggregate signer public keys")]
    PublicKeyAggregationFailed,
    /// The aggregated signature did not validate against the aggregated
    /// public keys for the QC's signing message.
    #[error("aggregated BLS signature invalid")]
    InvalidSignature,
    /// The signers' combined voting power is below the quorum threshold.
    #[error("insufficient quorum power: have {have:?}, need {need:?}")]
    InsufficientQuorumPower {
        /// Voting power held by the signers in the QC's bitfield.
        have: VotePower,
        /// Voting power required to constitute a quorum.
        need: VotePower,
    },
}

impl Verified<QuorumCertificate> {
    /// Verified form of the genesis QC. Valid by definition: the genesis
    /// QC carries no signature, and `verify` would reject it for having
    /// zero signers, so this constructor is the only path to the genesis
    /// verified value.
    #[must_use]
    pub const fn genesis(shard_group_id: ShardGroupId) -> Self {
        Self::new_unchecked(QuorumCertificate::genesis(shard_group_id))
    }

    /// Re-wrap a [`QuorumCertificate`] read out of persistent storage
    /// as verified.
    ///
    /// QCs are persisted only after passing
    /// [`<QuorumCertificate as Verify>::verify`](Verify::verify) at
    /// admission, so re-reading them post-restart returns values whose
    /// predicate already held at write-time. The shard storage write
    /// entry point (`commit_block`) takes
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
    /// the verifier will use, aggregates the BLS signatures, and computes
    /// the stake-weighted timestamp clamped to `parent_weighted_timestamp`
    /// (so the resulting QC's `weighted_timestamp` is monotonically `>=`
    /// the parent's).
    ///
    /// Construction asserts:
    /// 1. Every vote was verified — witnessed by the typed
    ///    `Verified<BlockVote>` input.
    /// 2. BLS aggregation over the votes' signatures succeeded.
    ///
    /// The caller is responsible for ensuring `verified_votes` is
    /// non-empty and that the combined voting power clears the quorum
    /// threshold — both checks live one level up in the verify-and-build
    /// flow that calls this constructor. The
    /// `Verified<QuorumCertificate>` predicate folds in both an
    /// aggregated-signature check and a quorum-power check, so the
    /// caller's quorum pre-check is what makes the typed result honest.
    ///
    /// Returns `None` when the BLS aggregation library rejects the
    /// signature set (empty input or internal validation failure).
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirrors the QC's signed-over fields
    pub fn from_verified_votes(
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        parent_block_hash: BlockHash,
        parent_weighted_timestamp: WeightedTimestamp,
        verified_votes: &[(usize, Verified<BlockVote>, VotePower)],
    ) -> Option<Self> {
        let mut sorted: Vec<_> = verified_votes.to_vec();
        sorted.sort_by_key(|(idx, _, _)| *idx);

        let signatures: Vec<Bls12381G2Signature> =
            sorted.iter().map(|(_, v, _)| v.signature()).collect();
        let aggregated_signature = Bls12381G2Signature::aggregate(&signatures, true).ok()?;

        let floor_ms = parent_weighted_timestamp.as_millis();
        let max_idx = sorted.iter().map(|(idx, _, _)| *idx).max().unwrap_or(0);
        let mut signers = SignerBitfield::new(max_idx + 1);
        let mut timestamp_weight_sum: u128 = 0;
        let mut verified_power = VotePower::ZERO;
        for (idx, vote, power) in &sorted {
            signers.set(*idx);
            // Per-vote monotonicity clamp: a vote timestamp below
            // parent's `weighted_timestamp` (slow honest clock or
            // Byzantine voter) is raised to the floor before
            // aggregation, so the resulting QC's `weighted_timestamp`
            // is guaranteed >= parent's.
            let clamped_ms = vote.timestamp().as_millis().max(floor_ms);
            timestamp_weight_sum += u128::from(clamped_ms) * u128::from(power.inner());
            verified_power += *power;
        }

        let weighted_timestamp_ms = if verified_power == VotePower::ZERO {
            0
        } else {
            // Mean of u64 timestamps weighted by u64 powers always
            // fits in u64.
            u64::try_from(timestamp_weight_sum / u128::from(verified_power.inner()))
                .unwrap_or(u64::MAX)
        };

        // SAFETY: every vote in `verified_votes` carries a type-level
        // claim that its BLS signature validates against the voter's
        // pubkey for `block_vote_message`. The BLS aggregation just
        // succeeded against those same signatures, so the resulting
        // aggregated signature verifies against the matching
        // aggregated public key. Quorum is the caller's precondition.
        Some(Self::new_unchecked(QuorumCertificate::new(
            block_hash,
            shard_group_id,
            height,
            parent_block_hash,
            round,
            signers,
            aggregated_signature,
            WeightedTimestamp::from_millis(weighted_timestamp_ms),
        )))
    }
}

/// Construction asserts: the aggregated BLS signature over the QC's
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
        let signer_keys: Vec<Bls12381G1PublicKey> = ctx
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
        let aggregated_pk = Bls12381G1PublicKey::aggregate(&signer_keys, false)
            .map_err(|_| QcVerifyError::PublicKeyAggregationFailed)?;
        if !verify_bls12381_v1(&signing_message, &aggregated_pk, &self.aggregated_signature) {
            return Err(QcVerifyError::InvalidSignature);
        }

        let total_power: VotePower = self
            .signers
            .set_indices()
            .filter_map(|idx| ctx.voting_powers.get(idx).copied())
            .fold(VotePower::ZERO, VotePower::saturating_add);
        if total_power < ctx.quorum_threshold {
            return Err(QcVerifyError::InsufficientQuorumPower {
                have: total_power,
                need: ctx.quorum_threshold,
            });
        }

        Ok(Verified::new_unchecked(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    #[test]
    fn test_genesis_qc() {
        let qc = QuorumCertificate::genesis(ShardGroupId::new(0));
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
            ShardGroupId::new(0),
            BlockHeight::new(1),
            parent_block_hash,
            Round::INITIAL,
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(1000),
        );

        assert!(!qc.is_genesis());
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.has_committable_block());
        assert_eq!(qc.committable_height(), Some(BlockHeight::new(0)));
        assert_eq!(qc.committable_hash(), Some(parent_block_hash));
    }

    // ─── Verify impl tests ──────────────────────────────────────────────

    use crate::{Bls12381G1PrivateKey, generate_bls_keypair};

    /// Build a QC with `signer_indices` of the `n`-validator committee
    /// signing it. Each signer signs the canonical `block_vote_message`,
    /// and the resulting signatures are aggregated into the QC. Returns
    /// the QC and the committee's public keys (in committee order).
    fn signed_qc(
        keys: &[Bls12381G1PrivateKey],
        signer_indices: &[usize],
        block_hash: BlockHash,
        shard: ShardGroupId,
        height: BlockHeight,
        round: Round,
    ) -> QuorumCertificate {
        let net = NetworkDefinition::simulator();
        // Sign over the same parent the QC carries, so the aggregate verifies.
        let message = block_vote_message(&net, shard, height, round, &block_hash, &BlockHash::ZERO);

        let sigs: Vec<Bls12381G2Signature> = signer_indices
            .iter()
            .map(|&i| keys[i].sign_v1(&message))
            .collect();
        let agg_sig = Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate sigs");

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
        public_keys: &'a [Bls12381G1PublicKey],
        voting_powers: &'a [VotePower],
        quorum_threshold: VotePower,
    ) -> QcContext<'a> {
        QcContext {
            network: net,
            public_keys,
            voting_powers,
            quorum_threshold,
        }
    }

    #[test]
    fn verify_accepts_valid_qc_with_quorum_signers() {
        let keys: Vec<_> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); 4];

        let qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardGroupId::new(0),
            BlockHeight::new(1),
            Round::INITIAL,
        );

        let net = NetworkDefinition::simulator();
        let verified = qc
            .verify(&ctx(&net, &pubs, &powers, VotePower::new(3)))
            .unwrap();
        assert_eq!(verified.signer_count(), 3);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let keys: Vec<_> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); 4];

        let mut qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardGroupId::new(0),
            BlockHeight::new(1),
            Round::INITIAL,
        );

        // Tamper: replace the aggregated signature with one signed over a
        // different message, so the BLS check fails on aggregation.
        let net = NetworkDefinition::simulator();
        let wrong_msg = block_vote_message(
            &net,
            ShardGroupId::new(0),
            BlockHeight::new(1),
            Round::INITIAL,
            &BlockHash::from_raw(Hash::from_bytes(b"other_block")),
            &BlockHash::ZERO,
        );
        let bad_sigs: Vec<_> = [0, 1, 2]
            .iter()
            .map(|&i| keys[i].sign_v1(&wrong_msg))
            .collect();
        let bad_agg = Bls12381G2Signature::aggregate(&bad_sigs, true).unwrap();
        let (block_hash, shard, height, parent, round, signers, _sig, ts) = qc.clone().into_parts();
        qc = QuorumCertificate::new(
            block_hash, shard, height, parent, round, signers, bad_agg, ts,
        );

        let err = qc
            .verify(&ctx(&net, &pubs, &powers, VotePower::new(3)))
            .unwrap_err();
        assert_eq!(err, QcVerifyError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_forged_parent_block_hash() {
        // `parent_block_hash` selects the committable block under the two-chain
        // commit rule. Repointing it at a sibling — the forged-parent fork —
        // must fail verification now that the field is in the signed message.
        let keys: Vec<_> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); 4];

        // `signed_qc` signs over parent = ZERO; keep the genuine signature but
        // repoint the parent at a sibling block.
        let qc = signed_qc(
            &keys,
            &[0, 1, 2],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardGroupId::new(0),
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
            .verify(&ctx(&net, &pubs, &powers, VotePower::new(3)))
            .unwrap_err();
        assert_eq!(err, QcVerifyError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_under_quorum_signer_set() {
        let keys: Vec<_> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); 4];

        // Only two of four sign — quorum is three. Signatures themselves
        // are valid; the stake total falls short.
        let qc = signed_qc(
            &keys,
            &[0, 1],
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ShardGroupId::new(0),
            BlockHeight::new(1),
            Round::INITIAL,
        );

        let net = NetworkDefinition::simulator();
        let err = qc
            .verify(&ctx(&net, &pubs, &powers, VotePower::new(3)))
            .unwrap_err();
        assert_eq!(
            err,
            QcVerifyError::InsufficientQuorumPower {
                have: VotePower::new(2),
                need: VotePower::new(3),
            }
        );
    }

    #[test]
    fn verify_rejects_qc_with_no_signers() {
        let keys: Vec<_> = (0..2).map(|_| generate_bls_keypair()).collect();
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); 2];

        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"b")),
            ShardGroupId::new(0),
            BlockHeight::new(1),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(2),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );

        let net = NetworkDefinition::simulator();
        let err = qc
            .verify(&ctx(&net, &pubs, &powers, VotePower::new(1)))
            .unwrap_err();
        assert_eq!(err, QcVerifyError::NoSigners);
    }
}
