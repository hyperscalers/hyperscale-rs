//! `SharedStorage` newtype — Arc-wrapped `RocksDbShardStorage` with full trait impls.
//!
//! Production wraps `Arc<RocksDbShardStorage>` in this newtype so that the pinned
//! `IoLoop` thread and async tasks (e.g. `InboundRouter`) can both hold the
//! same underlying database via cheap Arc clones, each going through the same
//! storage-trait implementations.
//!
//! The orphan rule prevents implementing foreign traits (`SubstateDatabase`,
//! `CommittableSubstateDatabase`) for `Arc<RocksDbShardStorage>` directly. This
//! newtype sidesteps that while providing zero-cost delegation.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::{
    BaseReadCache, BlockForSync, BoundaryStore, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, GenesisCommit, ImportLeaf, JmtSnapshot, PartitionEntry, ShardChainReader,
    ShardChainWriter, SubstateDatabase, SubstateStore, VersionedStore,
};
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, CertifiedBlock,
    CertifiedBlockHeader, ChainOrigin, ConsensusReceipt, ExecutionCertificate, FinalizedWave,
    MerkleInclusionProof, NodeId, PreparedCommit, QuorumCertificate, RoutableTransaction,
    ShardWitnessPayload, StateRoot, StoredReceipt, TxHash, Verifiable, Verified, WaveCertificate,
    WaveId,
};

use super::core::RocksDbShardStorage;
use super::snapshot::RocksDbSnapshot;

/// Shared `RocksDB` storage handle with full storage trait implementations.
///
/// A cheap-to-clone wrapper around `Arc<RocksDbShardStorage>` that implements all
/// storage traits needed by `IoLoop`. The pinned thread and async tasks
/// share the same underlying database via Arc clones of this handle.
///
/// # Why a newtype?
///
/// Rust's orphan rule prevents implementing foreign traits (`SubstateDatabase`,
/// `CommittableSubstateDatabase`) for `Arc<RocksDbShardStorage>`. This local newtype
/// can implement all traits while `Arc::clone` keeps sharing cheap.
#[derive(Clone)]
pub struct SharedStorage(pub Arc<RocksDbShardStorage>);

impl SharedStorage {
    /// Create a new shared storage handle.
    pub const fn new(storage: Arc<RocksDbShardStorage>) -> Self {
        Self(storage)
    }

    /// Get a reference to the underlying `Arc<RocksDbShardStorage>`.
    #[must_use]
    pub const fn arc(&self) -> &Arc<RocksDbShardStorage> {
        &self.0
    }
}

impl std::ops::Deref for SharedStorage {
    type Target = RocksDbShardStorage;
    fn deref(&self) -> &RocksDbShardStorage {
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
    fn install_genesis(
        &self,
        substates: &DatabaseUpdates,
        jmt_updates: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot {
        self.0.commit_substates_only(substates);
        self.0.finalize_genesis_jmt(jmt_updates, owner_map)
    }

    fn replicate_genesis_substates(&self, substates: &DatabaseUpdates) {
        self.0.commit_substates_only(substates);
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
        owner_map: &HashMap<NodeId, NodeId>,
        block_height: BlockHeight,
    ) -> Option<MerkleInclusionProof> {
        self.0
            .generate_merkle_proofs(storage_keys, owner_map, block_height)
    }
}

impl VersionedStore for SharedStorage {
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        self.0.snapshot_at(height)
    }

    fn substate_bytes_at(&self, height: BlockHeight) -> Option<u64> {
        self.0.substate_bytes_at(height)
    }
}

impl TreeReader for SharedStorage {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        self.0.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        self.0.get_root_key(version)
    }

    fn root_path(&self) -> NibblePath {
        self.0.root_path()
    }
}

impl BoundaryStore for SharedStorage {
    type Boundary = super::checkpoints::CheckpointStore;

    fn pin_boundary(&self, height: BlockHeight) -> Result<(), String> {
        self.0.pin_boundary(height)
    }

    fn open_boundary(&self, height: BlockHeight) -> Option<Self::Boundary> {
        self.0.open_boundary(height)
    }

    fn import_boundary_state(
        &self,
        height: BlockHeight,
        leaves: Vec<ImportLeaf>,
    ) -> Result<StateRoot, String> {
        self.0.import_boundary_state(height, leaves)
    }

    fn follow_block_writes(
        &self,
        height: BlockHeight,
        receipts: &[StoredReceipt],
    ) -> Result<StateRoot, String> {
        self.0.follow_block_writes(height, receipts)
    }

    fn adopt_split_child(&self, origin: ChainOrigin, genesis: &Block) -> Result<StateRoot, String> {
        BoundaryStore::adopt_split_child(&*self.0, origin, genesis)
    }

    fn adopt_followed_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        BoundaryStore::adopt_followed_child(&*self.0, origin, genesis)
    }

    fn adopt_merge_parent(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        BoundaryStore::adopt_merge_parent(&*self.0, origin, genesis)
    }

    fn substate_bytes_at_version(&self, version: u64) -> Option<u64> {
        self.0.substate_bytes_at_version(version)
    }
}

impl ShardChainWriter for SharedStorage {
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<Verifiable<FinalizedWave>>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit) {
        self.0.prepare_block_commit(
            parent_state_root,
            parent_block_height,
            finalized_waves,
            block_height,
            pending_snapshots,
            base_reads,
        )
    }

    fn commit_block(
        &self,
        certified: &Arc<Verified<CertifiedBlock>>,
        witness: &BeaconWitnessCommit,
    ) -> StateRoot {
        self.0.commit_block(certified, witness)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        self.0.memory_usage_bytes()
    }
}

impl ShardChainReader for SharedStorage {
    fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        self.0.get_block(height)
    }

    fn get_certified_header(&self, height: BlockHeight) -> Option<Verified<CertifiedBlockHeader>> {
        ShardChainReader::get_certified_header(&*self.0, height)
    }

    fn committed_height(&self) -> BlockHeight {
        self.0.committed_height()
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        self.0.committed_hash()
    }

    fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        self.0.latest_qc()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        ShardChainReader::get_block_for_sync(&*self.0, height)
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<RoutableTransaction>> {
        ShardChainReader::get_transactions_batch(&*self.0, hashes)
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
        self.0.get_certificates_batch(ids)
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.0.get_consensus_receipt(tx_hash)
    }

    fn get_execution_certificate(
        &self,
        wave_id: &WaveId,
    ) -> Option<Verified<ExecutionCertificate>> {
        self.0.get_execution_certificate(wave_id)
    }

    fn get_execution_certificates_batch(
        &self,
        wave_ids: &[WaveId],
    ) -> Vec<Verified<ExecutionCertificate>> {
        self.0.get_execution_certificates_batch(wave_ids)
    }

    fn get_beacon_witness_payloads(&self, end: BeaconWitnessLeafCount) -> Vec<ShardWitnessPayload> {
        self.0.get_beacon_witness_payloads(end)
    }

    fn get_beacon_witness_payload_range(&self, start: u64, end: u64) -> Vec<ShardWitnessPayload> {
        self.0.get_beacon_witness_payload_range(start, end)
    }
}

#[cfg(test)]
mod test_helpers {
    use hyperscale_storage::CommittableSubstateDatabase;

    use super::*;

    impl CommittableSubstateDatabase for SharedStorage {
        fn commit(&mut self, updates: &DatabaseUpdates) {
            RocksDbShardStorage::commit(&self.0, updates)
                .expect("Storage commit failed - cannot maintain consistent state");
        }
    }
}
