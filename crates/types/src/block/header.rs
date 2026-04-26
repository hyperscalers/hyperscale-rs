//! Block header containing consensus metadata.

use crate::{
    BlockHash, BlockHeight, CertificateRoot, Hash, LocalReceiptRoot, ProposerTimestamp,
    ProvisionTxRoot, ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, StateRoot,
    TransactionRoot, ValidatorId, WaveId,
};
use sbor::prelude::*;
use std::collections::BTreeMap;

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
    pub parent_hash: BlockHash,

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

    /// Merkle root of per-tx `LocalReceipt` hashes for all transactions
    /// covered by this block's wave certificates.
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
    pub waves: Vec<WaveId>,

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_padded_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    ///
    /// Entries only exist for targets with ≥1 tx. Empty for genesis,
    /// single-shard-only blocks, and empty blocks.
    pub provision_tx_roots: BTreeMap<ShardGroupId, ProvisionTxRoot>,

    /// Approximate number of in-flight transactions on this shard at proposal time.
    ///
    /// "In-flight" = committed + executed transactions in the proposer's mempool,
    /// i.e. transactions actively holding state locks. Gossiped cross-shard via
    /// `CommittedBlockHeaderGossip` so RPC nodes can reject transactions targeting
    /// congested remote shards.
    ///
    /// BFT-verified within tolerance (validators may differ slightly due to
    /// execution timing). Zero for genesis, fallback, and sync blocks.
    pub in_flight: u32,
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
            height: BlockHeight(0),
            parent_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    /// Derive provision targets from waves (union of all shards across all waves).
    ///
    /// Returns the sorted set of all remote shards that need provisions from this block.
    #[must_use]
    pub fn provision_targets(&self) -> Vec<ShardGroupId> {
        let mut set = std::collections::BTreeSet::new();
        for wave in &self.waves {
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
        self.height.0 == 0
    }

    /// Get the expected proposer for this height (round-robin).
    #[must_use]
    pub const fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId((self.height.0 + self.round.0) % num_validators)
    }
}
