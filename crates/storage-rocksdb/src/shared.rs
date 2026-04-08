//! SharedStorage newtype — Arc-wrapped RocksDbStorage with full trait impls.
//!
//! Production uses `CachingStorage<SharedStorage>` on the pinned IoLoop
//! thread while sharing the same underlying RocksDbStorage with async tasks
//! (InboundRouter, FetchManager) via cheap Arc clones.
//!
//! The orphan rule prevents implementing foreign traits (SubstateDatabase,
//! CommittableSubstateDatabase) for `Arc<RocksDbStorage>` directly.
//! This newtype sidesteps that while providing zero-cost delegation.

use crate::commit::RocksDbPreparedCommit;
use crate::core::RocksDbStorage;
use crate::snapshot::RocksDbSnapshot;

use hyperscale_storage::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
    SubstateStore,
};
use hyperscale_types::{
    Block, BlockHeight, Hash, NodeId, QuorumCertificate, RoutableTransaction, ShardGroupId,
    WaveCertificate,
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
    fn commit(&mut self, updates: &DatabaseUpdates) {
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

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        self.0.list_substates_for_node(node_id)
    }

    fn jvt_version(&self) -> u64 {
        self.0.jvt_version()
    }

    fn state_root_hash(&self) -> hyperscale_types::Hash {
        self.0.state_root_hash()
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        self.0
            .list_substates_for_node_at_height(node_id, block_height)
    }

    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<hyperscale_types::SubstateInclusionProof> {
        self.0.generate_verkle_proofs(storage_keys, block_height)
    }
}

impl hyperscale_storage::CommitStore for SharedStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        merged_updates: &DatabaseUpdates,
        block_height: u64,
    ) -> (Hash, Self::PreparedCommit) {
        self.0
            .prepare_block_commit(parent_state_root, merged_updates, block_height)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        certificates: &[std::sync::Arc<WaveCertificate>],
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
        execution_certificates: &[hyperscale_types::ExecutionCertificate],
    ) -> hyperscale_types::Hash {
        self.0
            .commit_prepared_block(prepared, certificates, consensus, execution_certificates)
    }

    fn commit_block(
        &self,
        merged_updates: &DatabaseUpdates,
        certificates: &[std::sync::Arc<WaveCertificate>],
        block_height: u64,
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
        execution_certificates: &[hyperscale_types::ExecutionCertificate],
    ) -> hyperscale_types::Hash {
        self.0.commit_block(
            merged_updates,
            certificates,
            block_height,
            consensus,
            execution_certificates,
        )
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        self.0.memory_usage_bytes()
    }

    fn node_cache_len(&self) -> usize {
        self.0.node_cache_len()
    }
}

impl hyperscale_storage::ConsensusStore for SharedStorage {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        self.0.put_block(height, block, qc)
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.0.get_block(height)
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.0.set_committed_height(height)
    }

    fn committed_height(&self) -> BlockHeight {
        self.0.committed_height()
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        self.0.set_committed_state(height, hash, qc)
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.0.committed_hash()
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.0.latest_qc()
    }

    fn store_certificate(&self, certificate: &WaveCertificate) {
        self.0.store_certificate(certificate)
    }

    fn get_certificate(&self, hash: &Hash) -> Option<WaveCertificate> {
        self.0.get_certificate(hash)
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        self.0.put_own_vote(height, round, block_hash)
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        self.0.get_own_vote(height)
    }

    fn get_all_own_votes(&self) -> std::collections::HashMap<u64, (Hash, u64)> {
        self.0.get_all_own_votes()
    }

    fn prune_own_votes(&self, committed_height: u64) {
        self.0.prune_own_votes(committed_height)
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.0.get_block_for_sync(height)
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        self.0.get_transactions_batch(hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        self.0.get_certificates_batch(hashes)
    }

    fn store_receipt_bundle(&self, bundle: &hyperscale_types::ReceiptBundle) {
        self.0.store_receipt_bundle(bundle)
    }

    fn store_receipt_bundles(&self, bundles: &[hyperscale_types::ReceiptBundle]) {
        self.0.store_receipt_bundles(bundles)
    }

    fn get_ledger_receipt(
        &self,
        tx_hash: &Hash,
    ) -> Option<Arc<hyperscale_types::LedgerTransactionReceipt>> {
        self.0.get_ledger_receipt(tx_hash)
    }

    fn get_local_execution(
        &self,
        tx_hash: &Hash,
    ) -> Option<hyperscale_types::LocalTransactionExecution> {
        self.0.get_local_execution(tx_hash)
    }

    fn get_execution_certificate(
        &self,
        canonical_hash: &Hash,
    ) -> Option<hyperscale_types::ExecutionCertificate> {
        self.0.get_execution_certificate(canonical_hash)
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: u64,
    ) -> Vec<hyperscale_types::ExecutionCertificate> {
        self.0.get_execution_certificates_by_height(block_height)
    }

    fn store_execution_certificates(&self, certs: &[hyperscale_types::ExecutionCertificate]) {
        self.0.store_execution_certificates(certs)
    }

    fn get_wave_certificates_by_height(&self, height: u64) -> Vec<WaveCertificate> {
        self.0.get_wave_certificates_by_height(height)
    }

    fn get_wave_certificate_for_tx(&self, tx_hash: &Hash) -> Option<WaveCertificate> {
        self.0.get_wave_certificate_for_tx(tx_hash)
    }

    fn get_ec_hashes_for_tx(&self, tx_hash: &Hash) -> Option<Vec<(ShardGroupId, Hash)>> {
        self.0.get_ec_hashes_for_tx(tx_hash)
    }
}
