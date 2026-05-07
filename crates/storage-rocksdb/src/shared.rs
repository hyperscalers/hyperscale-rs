//! `SharedStorage` newtype — Arc-wrapped `RocksDbStorage` with full trait impls.
//!
//! Production wraps `Arc<RocksDbStorage>` in this newtype so that the pinned
//! `IoLoop` thread and async tasks (e.g. `InboundRouter`) can both hold the
//! same underlying database via cheap Arc clones, each going through the same
//! storage-trait implementations.
//!
//! The orphan rule prevents implementing foreign traits (`SubstateDatabase`,
//! `CommittableSubstateDatabase`) for `Arc<RocksDbStorage>` directly. This
//! newtype sidesteps that while providing zero-cost delegation.

use std::sync::Arc;

use hyperscale_jmt::{Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::{
    BaseReadCache, BlockForSync, ChainReader, ChainWriter, DatabaseUpdates, DbPartitionKey,
    DbSortKey, DbSubstateValue, GenesisCommit, JmtSnapshot, PartitionEntry, SubstateDatabase,
    SubstateStore, VersionedStore,
};
use hyperscale_types::{
    Block, BlockHash, BlockHeight, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, FinalizedWave, MerkleInclusionProof, NodeId, QuorumCertificate,
    RoutableTransaction, StateRoot, TxHash, WaveCertificate, WaveId,
};

use crate::chain_writer::RocksDbPreparedCommit;
use crate::core::RocksDbStorage;
use crate::snapshot::RocksDbSnapshot;

/// Shared `RocksDB` storage handle with full storage trait implementations.
///
/// A cheap-to-clone wrapper around `Arc<RocksDbStorage>` that implements all
/// storage traits needed by `IoLoop`. The pinned thread and async tasks
/// share the same underlying database via Arc clones of this handle.
///
/// # Why a newtype?
///
/// Rust's orphan rule prevents implementing foreign traits (`SubstateDatabase`,
/// `CommittableSubstateDatabase`) for `Arc<RocksDbStorage>`. This local newtype
/// can implement all traits while `Arc::clone` keeps sharing cheap.
#[derive(Clone)]
pub struct SharedStorage(pub Arc<RocksDbStorage>);

impl SharedStorage {
    /// Create a new shared storage handle.
    pub const fn new(storage: Arc<RocksDbStorage>) -> Self {
        Self(storage)
    }

    /// Get a reference to the underlying `Arc<RocksDbStorage>`.
    #[must_use]
    pub const fn arc(&self) -> &Arc<RocksDbStorage> {
        &self.0
    }
}

impl std::ops::Deref for SharedStorage {
    type Target = RocksDbStorage;
    fn deref(&self) -> &RocksDbStorage {
        &self.0
    }
}

impl SubstateDatabase for SharedStorage {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.0.get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        self.0
            .list_raw_values_from_db_key(partition_key, from_sort_key)
    }
}

impl GenesisCommit for SharedStorage {
    fn install_genesis(&self, merged: &DatabaseUpdates) -> StateRoot {
        self.0.commit_substates_only(merged);
        self.0.finalize_genesis_jmt(merged)
    }
}

impl SubstateStore for SharedStorage {
    type Snapshot<'a>
        = RocksDbSnapshot<'a>
    where
        Self: 'a;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        self.0.snapshot()
    }

    fn jmt_height(&self) -> BlockHeight {
        self.0.jmt_height()
    }

    fn state_root(&self) -> StateRoot {
        self.0.state_root()
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: BlockHeight,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        self.0
            .list_substates_for_node_at_height(node_id, block_height)
    }

    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: BlockHeight,
    ) -> Option<MerkleInclusionProof> {
        self.0.generate_merkle_proofs(storage_keys, block_height)
    }
}

impl VersionedStore for SharedStorage {
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        self.0.snapshot_at(height)
    }
}

impl TreeReader for SharedStorage {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        self.0.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        self.0.get_root_key(version)
    }
}

impl ChainWriter for SharedStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot {
        &prepared.jmt_snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Self::PreparedCommit) {
        self.0.prepare_block_commit(
            parent_state_root,
            parent_block_height,
            finalized_waves,
            block_height,
            pending_snapshots,
            base_reads,
        )
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(Self::PreparedCommit, Arc<Block>, Arc<QuorumCertificate>)>,
    ) -> Vec<StateRoot> {
        self.0.commit_prepared_blocks(blocks)
    }

    fn commit_block(&self, block: &Arc<Block>, qc: &Arc<QuorumCertificate>) -> StateRoot {
        self.0.commit_block(block, qc)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        self.0.memory_usage_bytes()
    }
}

impl ChainReader for SharedStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.0.get_block(height)
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        ChainReader::get_committed_header(&*self.0, height)
    }

    fn committed_height(&self) -> BlockHeight {
        self.0.committed_height()
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        self.0.committed_hash()
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.0.latest_qc()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        ChainReader::get_block_for_sync(&*self.0, height)
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        self.0.get_transactions_batch(hashes)
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
        self.0.get_certificates_batch(ids)
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.0.get_consensus_receipt(tx_hash)
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate> {
        self.0.get_execution_certificates_by_height(block_height)
    }
}

#[cfg(test)]
mod test_helpers {
    use hyperscale_storage::CommittableSubstateDatabase;

    use super::*;

    impl CommittableSubstateDatabase for SharedStorage {
        fn commit(&mut self, updates: &DatabaseUpdates) {
            RocksDbStorage::commit(&self.0, updates)
                .expect("Storage commit failed - cannot maintain consistent state");
        }
    }
}
