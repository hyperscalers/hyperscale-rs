//! SharedStorage newtype — Arc-wrapped RocksDbStorage with full trait impls.
//!
//! Production uses `CachingStorage<SharedStorage>` on the pinned IoLoop
//! thread while sharing the same underlying RocksDbStorage with async tasks
//! (InboundRouter, FetchManager) via cheap Arc clones.
//!
//! The orphan rule prevents implementing foreign traits (SubstateDatabase,
//! CommittableSubstateDatabase) for `Arc<RocksDbStorage>` directly.
//! This newtype sidesteps that while providing zero-cost delegation.

use crate::chain_writer::RocksDbPreparedCommit;
use crate::core::RocksDbStorage;
use crate::snapshot::RocksDbSnapshot;

use hyperscale_storage::{
    BlockForSync, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
    SubstateStore,
};
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, ExecutionCertificateHash, Hash, NodeId,
    QuorumCertificate, RoutableTransaction, ShardGroupId, StateRoot, TxHash, WaveCertificate,
};
use std::sync::Arc;

/// Shared RocksDB storage handle with full storage trait implementations.
///
/// A cheap-to-clone wrapper around `Arc<RocksDbStorage>` that implements all
/// storage traits needed by `IoLoop`. Use this as the storage type parameter
/// for `CachingStorage` in production.
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
    pub fn new(storage: Arc<RocksDbStorage>) -> Self {
        Self(storage)
    }

    /// Get a reference to the underlying `Arc<RocksDbStorage>`.
    pub fn arc(&self) -> &Arc<RocksDbStorage> {
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

#[cfg(test)]
impl hyperscale_storage::CommittableSubstateDatabase for SharedStorage {
    fn commit(&mut self, updates: &hyperscale_storage::DatabaseUpdates) {
        RocksDbStorage::commit(&self.0, updates)
            .expect("Storage commit failed - cannot maintain consistent state");
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

    fn state_root_hash(&self) -> hyperscale_types::StateRoot {
        self.0.state_root_hash()
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
    ) -> Option<hyperscale_types::MerkleInclusionProof> {
        self.0.generate_merkle_proofs(storage_keys, block_height)
    }
}

impl hyperscale_storage::VersionedStore for SharedStorage {
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        self.0.snapshot_at(height)
    }
}

impl hyperscale_jmt::TreeReader for SharedStorage {
    fn get_node(
        &self,
        key: &hyperscale_jmt::NodeKey,
    ) -> Option<std::sync::Arc<hyperscale_jmt::Node>> {
        self.0.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<hyperscale_jmt::NodeKey> {
        self.0.get_root_key(version)
    }
}

impl hyperscale_storage::ChainWriter for SharedStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &hyperscale_storage::JmtSnapshot {
        &prepared.jmt_snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[std::sync::Arc<hyperscale_types::FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[std::sync::Arc<hyperscale_storage::JmtSnapshot>],
        base_reads: Option<&hyperscale_storage::BaseReadCache>,
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
        blocks: Vec<(
            Self::PreparedCommit,
            Arc<hyperscale_types::Block>,
            Arc<hyperscale_types::QuorumCertificate>,
        )>,
    ) -> Vec<hyperscale_types::StateRoot> {
        self.0.commit_prepared_blocks(blocks)
    }

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
    ) -> hyperscale_types::StateRoot {
        self.0.commit_block(block, qc)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        self.0.memory_usage_bytes()
    }
}

impl hyperscale_storage::ChainReader for SharedStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.0.get_block(height)
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
        hyperscale_storage::ChainReader::get_block_for_sync(&*self.0, height)
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        self.0.get_transactions_batch(hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        self.0.get_certificates_batch(hashes)
    }

    fn get_local_receipt(&self, tx_hash: &TxHash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        self.0.get_local_receipt(tx_hash)
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<hyperscale_types::ExecutionCertificate> {
        self.0.get_execution_certificates_by_height(block_height)
    }

    fn get_wave_certificate_for_tx(&self, tx_hash: &TxHash) -> Option<WaveCertificate> {
        self.0.get_wave_certificate_for_tx(tx_hash)
    }

    fn get_ec_hashes_for_tx(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Vec<(ShardGroupId, ExecutionCertificateHash)>> {
        self.0.get_ec_hashes_for_tx(tx_hash)
    }
}
