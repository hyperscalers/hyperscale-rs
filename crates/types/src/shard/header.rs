//! Block header containing consensus metadata.
//!
//! [`BlockHeader`] is the raw wire form. Its verified form is
//! `Verified<BlockHeader>`; predicate at [`impl Verify<()>`](Verify::verify)
//! below.

use std::collections::{BTreeMap, BTreeSet};

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, BoundedBTreeMap, BoundedVec,
    CertificateRoot, Hash, InFlightCount, LocalReceiptRoot, MAX_REMOTE_SHARDS_PER_WAVE,
    MAX_TXS_PER_BLOCK, ProposerTimestamp, ProvisionTxRoot, ProvisionsRoot, QuorumCertificate,
    Round, ShardGroupId, StateRoot, TransactionRoot, ValidatorId, Verifiable, Verified, Verify,
    WaveId,
};

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
/// - State commitment (JMT root after applying committed certificates)
/// - Transaction commitment (merkle root of all transactions in the block)
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeader {
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    parent_block_hash: BlockHash,
    parent_qc: Verifiable<QuorumCertificate>,
    proposer: ValidatorId,
    timestamp: ProposerTimestamp,
    round: Round,
    is_fallback: bool,
    state_root: StateRoot,
    transaction_root: TransactionRoot,
    certificate_root: CertificateRoot,
    local_receipt_root: LocalReceiptRoot,
    provision_root: ProvisionsRoot,
    waves: BoundedVec<WaveId, MAX_TXS_PER_BLOCK>,
    provision_tx_roots: BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>,
    in_flight: InFlightCount,
    beacon_witness_root: BeaconWitnessRoot,
    beacon_witness_leaf_count: BeaconWitnessLeafCount,
}

impl BlockHeader {
    /// Build a `BlockHeader` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `waves.len() > MAX_TXS_PER_BLOCK` or
    /// `provision_tx_roots.len() > MAX_REMOTE_SHARDS_PER_WAVE`.
    #[allow(clippy::too_many_arguments)] // mirrors the 18 stored fields
    #[must_use]
    pub fn new(
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        parent_block_hash: BlockHash,
        parent_qc: impl Into<Verifiable<QuorumCertificate>>,
        proposer: ValidatorId,
        timestamp: ProposerTimestamp,
        round: Round,
        is_fallback: bool,
        state_root: StateRoot,
        transaction_root: TransactionRoot,
        certificate_root: CertificateRoot,
        local_receipt_root: LocalReceiptRoot,
        provision_root: ProvisionsRoot,
        waves: Vec<WaveId>,
        provision_tx_roots: BTreeMap<ShardGroupId, ProvisionTxRoot>,
        in_flight: InFlightCount,
        beacon_witness_root: BeaconWitnessRoot,
        beacon_witness_leaf_count: BeaconWitnessLeafCount,
    ) -> Self {
        Self {
            shard_group_id,
            height,
            parent_block_hash,
            parent_qc: parent_qc.into(),
            proposer,
            timestamp,
            round,
            is_fallback,
            state_root,
            transaction_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            waves: waves.into(),
            provision_tx_roots: provision_tx_roots.into(),
            in_flight,
            beacon_witness_root,
            beacon_witness_leaf_count,
        }
    }

    /// Create a genesis block header (height 0) with the given proposer and JMT state.
    #[must_use]
    pub fn genesis(
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        state_root: StateRoot,
    ) -> Self {
        Self {
            shard_group_id,
            height: BlockHeight::new(0),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            // Genesis QC carries no signature and is valid by definition;
            // `Verified::<QuorumCertificate>::genesis` is the only path to a
            // verified genesis value (the predicate's signer check would
            // reject the zero-signers genesis bitfield).
            parent_qc: Verifiable::Verified(Verified::<QuorumCertificate>::genesis(shard_group_id)),
            proposer,
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: BoundedVec::new(),
            provision_tx_roots: BoundedBTreeMap::new(),
            in_flight: InFlightCount::ZERO,
            beacon_witness_root: BeaconWitnessRoot::ZERO,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::ZERO,
        }
    }

    /// Shard group this block belongs to.
    ///
    /// Makes headers self-describing for cross-shard verification. A remote shard
    /// needs to know which shard's committee to verify the QC against.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.shard_group_id
    }

    /// Block height in the chain (genesis = 0).
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// Hash of parent block.
    #[must_use]
    pub const fn parent_block_hash(&self) -> BlockHash {
        self.parent_block_hash
    }

    /// Quorum certificate proving parent block was committed.
    #[must_use]
    pub fn parent_qc(&self) -> &QuorumCertificate {
        self.parent_qc.as_unverified()
    }

    /// Borrow the parent QC's [`Verifiable`] wrapper, exposing the
    /// verification marker. Used by typestate consumers that branch on
    /// whether the parent QC has already been verified.
    #[must_use]
    pub const fn parent_qc_verifiable(&self) -> &Verifiable<QuorumCertificate> {
        &self.parent_qc
    }

    /// Validator that proposed this block.
    #[must_use]
    pub const fn proposer(&self) -> ValidatorId {
        self.proposer
    }

    /// Proposer's local wall-clock when this block was proposed.
    ///
    /// **Not** BFT-authenticated. Used only for shard consensus liveness bounds (rejecting
    /// rushed/stale proposals against the local validator's clock) and local
    /// latency metrics. Never anchor a deterministic timeout on this — use
    /// `qc.weighted_timestamp` / `ts_ms` fields derived from it instead.
    #[must_use]
    pub const fn timestamp(&self) -> ProposerTimestamp {
        self.timestamp
    }

    /// View/round number for view change protocol.
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Whether this block was created as a fallback when leader timed out.
    #[must_use]
    pub const fn is_fallback(&self) -> bool {
        self.is_fallback
    }

    /// JMT state root hash after applying all certificates in this block.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// Merkle root of all transactions in this block.
    ///
    /// Each transaction's hash is a leaf in a padded binary merkle tree.
    /// For empty blocks (fallback, sync), this is `TransactionRoot::ZERO`.
    #[must_use]
    pub const fn transaction_root(&self) -> TransactionRoot {
        self.transaction_root
    }

    /// Merkle root of all certificate receipt hashes in this block.
    ///
    /// Each certificate's `receipt_hash` (hash of outcome + `event_root`) is a leaf
    /// in a binary merkle tree. This enables light-client proof of "did transaction
    /// X succeed/fail in block N?" without replaying the block.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `CertificateRoot::ZERO`.
    #[must_use]
    pub const fn certificate_root(&self) -> CertificateRoot {
        self.certificate_root
    }

    /// Merkle root of per-tx consensus-receipt hashes
    /// ([`ConsensusReceipt::local_receipt_hash`](crate::ConsensusReceipt::local_receipt_hash))
    /// for all transactions covered by this block's wave certificates.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered `DatabaseUpdates`)
    /// that were applied to produce `state_root`. Enables per-tx delta attribution
    /// and receipt integrity verification by sync nodes.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `LocalReceiptRoot::ZERO`.
    #[must_use]
    pub const fn local_receipt_root(&self) -> LocalReceiptRoot {
        self.local_receipt_root
    }

    /// Merkle root of provisions included in this block.
    ///
    /// Commits to which remote-shard provisions are available at this height.
    /// Validators who voted for the shard consensus proposal have this data locally.
    /// `ProvisionsRoot::ZERO` when no provisions are included (single-shard or empty block).
    #[must_use]
    pub const fn provision_root(&self) -> ProvisionsRoot {
        self.provision_root
    }

    /// Cross-shard execution waves in this block.
    ///
    /// Each `WaveId` is the set of remote shards that a group of transactions
    /// depends on for provisions. Transactions with identical remote shard sets
    /// share a wave. Wave-zero (single-shard txs) is excluded.
    ///
    /// QC-attested (covered by the block hash), so a byzantine proposer
    /// cannot forge it without the block being rejected by honest validators —
    /// `validate_waves` recomputes this from `transactions` and compares.
    ///
    /// Used by remote shards to know which execution certificates to expect.
    /// Provisions completeness is handled separately via
    /// [`BlockHeader::provision_tx_roots`]. Empty for genesis, fallback, and
    /// sync blocks.
    #[must_use]
    pub const fn waves(&self) -> &BoundedVec<WaveId, MAX_TXS_PER_BLOCK> {
        &self.waves
    }

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    #[must_use]
    pub const fn provision_tx_roots(
        &self,
    ) -> &BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE> {
        &self.provision_tx_roots
    }

    /// Approximate number of in-flight transactions on this shard at proposal time.
    ///
    /// "In-flight" = committed + executed transactions in the proposer's mempool,
    /// i.e. transactions actively holding state locks. Gossiped cross-shard via
    /// `CommittedBlockHeaderGossip` so RPC nodes can reject transactions targeting
    /// congested remote shards.
    ///
    /// shard-verified within tolerance (validators may differ slightly due to
    /// execution timing). Zero for genesis; fallback and sync blocks carry
    /// the parent's in-flight count forward unchanged (no txs admitted, none
    /// finalized).
    #[must_use]
    pub const fn in_flight(&self) -> InFlightCount {
        self.in_flight
    }

    /// Root of this shard's monotonic beacon-witness accumulator at
    /// this block.
    ///
    /// QC-attested (part of the signed header). Beacon validators
    /// verify a fetched [`ShardWitness`](crate::ShardWitness) against
    /// this root via the Merkle path in its
    /// [`ShardWitnessProof`](crate::ShardWitnessProof).
    ///
    /// `BeaconWitnessRoot::ZERO` for blocks that produced no witnesses.
    #[must_use]
    pub const fn beacon_witness_root(&self) -> BeaconWitnessRoot {
        self.beacon_witness_root
    }

    /// Total leaves in this shard's beacon-witness accumulator as of
    /// this block.
    ///
    /// Paired with [`Self::beacon_witness_root`] so a verifier holding
    /// only the header can check any inclusion proof anchored at this
    /// block without consulting a side channel for the tree size. `0`
    /// for blocks that produced no witnesses.
    #[must_use]
    pub const fn beacon_witness_leaf_count(&self) -> BeaconWitnessLeafCount {
        self.beacon_witness_leaf_count
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[allow(clippy::type_complexity)] // mirrors the 18 stored fields
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ShardGroupId,
        BlockHeight,
        BlockHash,
        Verifiable<QuorumCertificate>,
        ValidatorId,
        ProposerTimestamp,
        Round,
        bool,
        StateRoot,
        TransactionRoot,
        CertificateRoot,
        LocalReceiptRoot,
        ProvisionsRoot,
        BoundedVec<WaveId, MAX_TXS_PER_BLOCK>,
        BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>,
        InFlightCount,
        BeaconWitnessRoot,
        BeaconWitnessLeafCount,
    ) {
        (
            self.shard_group_id,
            self.height,
            self.parent_block_hash,
            self.parent_qc,
            self.proposer,
            self.timestamp,
            self.round,
            self.is_fallback,
            self.state_root,
            self.transaction_root,
            self.certificate_root,
            self.local_receipt_root,
            self.provision_root,
            self.waves,
            self.provision_tx_roots,
            self.in_flight,
            self.beacon_witness_root,
            self.beacon_witness_leaf_count,
        )
    }

    /// Derive provision targets from waves (union of all shards across all waves).
    ///
    /// Returns the sorted set of all remote shards that need provisions from this block.
    #[must_use]
    pub fn provision_targets(&self) -> Vec<ShardGroupId> {
        let mut set = BTreeSet::new();
        for wave in self.waves.iter() {
            set.extend(wave.remote_shards().iter().copied());
        }
        set.into_iter().collect()
    }

    /// Compute hash of this block header.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — `BlockHeader` is a closed SBOR
    /// type and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        let bytes = basic_encode(self).expect("BlockHeader serialization should never fail");
        BlockHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Check if this is the genesis block header.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.height == BlockHeight::GENESIS
    }

    /// Get the expected proposer for this height (round-robin).
    #[must_use]
    pub const fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId::new((self.height.inner() + self.round.inner()) % num_validators)
    }
}

/// Failure modes of [`BlockHeader`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockHeaderVerifyError {
    /// The header's `parent_qc` is still in [`Verifiable::Unverified`]
    /// at the point verification is requested. Callers must verify the
    /// QC (via [`<QuorumCertificate as Verify>`](Verify) or by upgrading
    /// the wrapper) before attempting to verify the header.
    #[error("parent QC has not been verified")]
    ParentQcUnverified,
}

/// Construction asserts: the header's `parent_qc` carries a
/// [`Verifiable::Verified`] marker — i.e. the parent QC has been
/// verified against its committee context. The header's `hash()` is
/// derived from its content by definition, so there is no separately
/// claimed hash to check.
///
/// Construction goes through one of two gates:
///
/// - [`<BlockHeader as Verify>::verify`](Verify::verify) — checks that
///   the embedded `parent_qc` is in [`Verifiable::Verified`].
/// - [`Verified::<BlockHeader>::new_unchecked`] — audit point. Used at
///   storage-recovery boundaries and at composite-assembly sites that
///   established the predicate by other means. Every call site carries
///   a `// SAFETY:` comment naming the trust source.
impl Verify<()> for BlockHeader {
    type Augment = ();
    type Error = BlockHeaderVerifyError;

    fn verify(&self, _ctx: ()) -> Result<Verified<Self>, Self::Error> {
        if self.parent_qc.verified().is_none() {
            return Err(BlockHeaderVerifyError::ParentQcUnverified);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<BlockHeader> {
    /// Borrow the verified parent QC. Total by the
    /// [`Verified<BlockHeader>`] predicate, which requires
    /// `parent_qc` to sit in [`Verifiable::Verified`].
    ///
    /// # Panics
    ///
    /// Panics if a caller produced a `Verified<BlockHeader>` whose
    /// `parent_qc` is `Unverified` — only reachable through a misuse of
    /// [`Verified::new_unchecked`]. The audit list at the
    /// `new_unchecked` call sites is the right place to investigate.
    #[must_use]
    pub fn parent_qc_verified(&self) -> &Verified<QuorumCertificate> {
        self.parent_qc_verifiable()
            .verified()
            .expect("Verified<BlockHeader> predicate guarantees parent_qc is Verified")
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
    };

    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO)
    }

    /// Hand-roll a `BlockHeader` whose `waves` length prefix exceeds the cap.
    /// The `BoundedVec` decoder fires before any per-element work happens.
    #[test]
    fn decode_rejects_oversized_waves_count() {
        let h = sample_header();
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            // BlockHeader has 18 fields.
            enc.write_size(18).unwrap();
            enc.encode(&h.shard_group_id).unwrap();
            enc.encode(&h.height).unwrap();
            enc.encode(&h.parent_block_hash).unwrap();
            enc.encode(&h.parent_qc).unwrap();
            enc.encode(&h.proposer).unwrap();
            enc.encode(&h.timestamp).unwrap();
            enc.encode(&h.round).unwrap();
            enc.encode(&h.is_fallback).unwrap();
            enc.encode(&h.state_root).unwrap();
            enc.encode(&h.transaction_root).unwrap();
            enc.encode(&h.certificate_root).unwrap();
            enc.encode(&h.local_receipt_root).unwrap();
            enc.encode(&h.provision_root).unwrap();
            // Oversized waves array.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(WaveId::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<BlockHeader>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    /// Hand-roll a `BlockHeader` whose `provision_tx_roots` map size exceeds
    /// the cap. The `BoundedBTreeMap` decoder fires before any per-entry
    /// work happens.
    #[test]
    fn decode_rejects_oversized_provision_tx_roots_count() {
        let h = sample_header();
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(18).unwrap();
            enc.encode(&h.shard_group_id).unwrap();
            enc.encode(&h.height).unwrap();
            enc.encode(&h.parent_block_hash).unwrap();
            enc.encode(&h.parent_qc).unwrap();
            enc.encode(&h.proposer).unwrap();
            enc.encode(&h.timestamp).unwrap();
            enc.encode(&h.round).unwrap();
            enc.encode(&h.is_fallback).unwrap();
            enc.encode(&h.state_root).unwrap();
            enc.encode(&h.transaction_root).unwrap();
            enc.encode(&h.certificate_root).unwrap();
            enc.encode(&h.local_receipt_root).unwrap();
            enc.encode(&h.provision_root).unwrap();
            // Empty waves.
            enc.encode(&Vec::<WaveId>::new()).unwrap();
            // Oversized provision_tx_roots map.
            enc.write_value_kind(ValueKind::Map).unwrap();
            enc.write_value_kind(ShardGroupId::value_kind()).unwrap();
            enc.write_value_kind(ProvisionTxRoot::value_kind()).unwrap();
            enc.write_size(MAX_REMOTE_SHARDS_PER_WAVE + 1).unwrap();
        }
        let err = basic_decode::<BlockHeader>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_REMOTE_SHARDS_PER_WAVE
                    && actual == MAX_REMOTE_SHARDS_PER_WAVE + 1
        ));
    }

    /// Genesis headers verify (`parent_qc` arrives pre-marked verified),
    /// and the resulting `Verified<BlockHeader>` projects out the
    /// verified parent QC through the type-level borrow.
    #[test]
    fn verified_header_projects_parent_qc() {
        let header = sample_header();
        let verified = header.verify(()).expect("genesis header verifies");
        let pqc = verified.parent_qc_verified();
        assert!(pqc.is_genesis());
    }

    /// A header with an unverified `parent_qc` fails `verify`, so the
    /// projector is unreachable without resorting to `new_unchecked`.
    #[test]
    fn verify_rejects_unverified_parent_qc() {
        let mut header = sample_header();
        header.parent_qc = Verifiable::Unverified(header.parent_qc.as_unverified().clone());
        let err = header
            .verify(())
            .expect_err("unverified parent_qc rejected");
        assert_eq!(err, BlockHeaderVerifyError::ParentQcUnverified);
    }
}
