//! Block header containing consensus metadata.

use std::collections::BTreeSet;

use sbor::prelude::*;

use crate::{
    BlockHash, BlockHeight, BoundedBTreeMap, BoundedVec, CertificateRoot, Hash, InFlightCount,
    LocalReceiptRoot, MAX_REMOTE_SHARDS_PER_WAVE, MAX_TXS_PER_BLOCK, ProposerTimestamp,
    ProvisionTxRoot, ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, StateRoot,
    TransactionRoot, ValidatorId, WaveId,
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
    /// Shard group this block belongs to.
    ///
    /// Makes headers self-describing for cross-shard verification. A remote shard
    /// needs to know which shard's committee to verify the QC against.
    pub shard_group_id: ShardGroupId,

    /// Block height in the chain (genesis = 0).
    pub height: BlockHeight,

    /// Hash of parent block.
    pub parent_block_hash: BlockHash,

    /// Quorum certificate proving parent block was committed.
    pub parent_qc: QuorumCertificate,

    /// Validator that proposed this block.
    pub proposer: ValidatorId,

    /// Proposer's local wall-clock when this block was proposed.
    ///
    /// **Not** BFT-authenticated. Used only for BFT liveness bounds (rejecting
    /// rushed/stale proposals against the local validator's clock) and local
    /// latency metrics. Never anchor a deterministic timeout on this — use
    /// `qc.weighted_timestamp` / `ts_ms` fields derived from it instead.
    pub timestamp: ProposerTimestamp,

    /// View/round number for view change protocol.
    pub round: Round,

    /// Whether this block was created as a fallback when leader timed out.
    pub is_fallback: bool,

    /// JMT state root hash after applying all certificates in this block.
    pub state_root: StateRoot,

    /// Merkle root of all transactions in this block.
    ///
    /// Each transaction's hash is a leaf in a padded binary merkle tree.
    /// For empty blocks (fallback, sync), this is `TransactionRoot::ZERO`.
    pub transaction_root: TransactionRoot,

    /// Merkle root of all certificate receipt hashes in this block.
    ///
    /// Each certificate's `receipt_hash` (hash of outcome + `event_root`) is a leaf
    /// in a binary merkle tree. This enables light-client proof of "did transaction
    /// X succeed/fail in block N?" without replaying the block.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `CertificateRoot::ZERO`.
    pub certificate_root: CertificateRoot,

    /// Merkle root of per-tx consensus-receipt hashes
    /// ([`ConsensusReceipt::local_receipt_hash`](crate::ConsensusReceipt::local_receipt_hash))
    /// for all transactions covered by this block's wave certificates.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered `DatabaseUpdates`)
    /// that were applied to produce `state_root`. Enables per-tx delta attribution
    /// and receipt integrity verification by sync nodes.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `LocalReceiptRoot::ZERO`.
    pub local_receipt_root: LocalReceiptRoot,

    /// Merkle root of provisions included in this block.
    ///
    /// Commits to which remote-shard provisions are available at this height.
    /// Validators who voted for the BFT proposal have this data locally.
    /// `ProvisionsRoot::ZERO` when no provisions are included (single-shard or empty block).
    pub provision_root: ProvisionsRoot,

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
    ///
    /// Capped at [`MAX_TXS_PER_BLOCK`] — every wave covers ≥1 distinct tx,
    /// so the wave count is bounded by the per-block tx count.
    pub waves: BoundedVec<WaveId, MAX_TXS_PER_BLOCK>,

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    ///
    /// Entries only exist for targets with ≥1 tx. Empty for genesis,
    /// single-shard-only blocks, and empty blocks.
    ///
    /// Capped at [`MAX_REMOTE_SHARDS_PER_WAVE`] — same domain (remote
    /// shards) as the per-wave dependency set; one entry per touched
    /// target shard.
    pub provision_tx_roots:
        BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>,

    /// Approximate number of in-flight transactions on this shard at proposal time.
    ///
    /// "In-flight" = committed + executed transactions in the proposer's mempool,
    /// i.e. transactions actively holding state locks. Gossiped cross-shard via
    /// `CommittedBlockHeaderGossip` so RPC nodes can reject transactions targeting
    /// congested remote shards.
    ///
    /// BFT-verified within tolerance (validators may differ slightly due to
    /// execution timing). Zero for genesis; fallback and sync blocks carry
    /// the parent's in-flight count forward unchanged (no txs admitted, none
    /// finalized).
    pub in_flight: InFlightCount,
}

impl BlockHeader {
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
            parent_qc: QuorumCertificate::genesis(shard_group_id),
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
        }
    }

    /// Derive provision targets from waves (union of all shards across all waves).
    ///
    /// Returns the sorted set of all remote shards that need provisions from this block.
    #[must_use]
    pub fn provision_targets(&self) -> Vec<ShardGroupId> {
        let mut set = BTreeSet::new();
        for wave in self.waves.iter() {
            set.extend(wave.remote_shards.iter().copied());
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
    pub const fn is_genesis(&self) -> bool {
        self.height.inner() == 0
    }

    /// Get the expected proposer for this height (round-robin).
    #[must_use]
    pub const fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId::new((self.height.inner() + self.round.inner()) % num_validators)
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
            // BlockHeader has 16 fields.
            enc.write_size(16).unwrap();
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
            enc.write_size(16).unwrap();
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
}
