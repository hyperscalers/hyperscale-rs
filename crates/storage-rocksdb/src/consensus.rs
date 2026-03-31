//! `ConsensusStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::{
    Block, BlockHeight, Hash, QuorumCertificate, RoutableTransaction, TransactionCertificate,
};
use std::sync::Arc;

impl<D: Dispatch + 'static> hyperscale_storage::ConsensusStore for RocksDbStorage<D> {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        debug_assert_eq!(
            height, block.header.height,
            "height must match block header"
        );
        self.put_block_denormalized(block, qc);
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.get_block_denormalized(height)
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.set_chain_metadata(height, None, None);
    }

    fn committed_height(&self) -> BlockHeight {
        self.read_committed_height()
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        self.set_chain_metadata(height, Some(hash), Some(qc));
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.read_committed_hash()
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.read_latest_qc()
    }

    fn store_certificate(&self, certificate: &TransactionCertificate) {
        self.put_certificate(&certificate.transaction_hash, certificate);
    }

    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        RocksDbStorage::get_certificate(self, hash)
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        RocksDbStorage::put_own_vote(self, height, round, block_hash);
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        RocksDbStorage::get_own_vote(self, height)
    }

    fn get_all_own_votes(&self) -> std::collections::HashMap<u64, (Hash, u64)> {
        RocksDbStorage::get_all_own_votes(self)
    }

    fn prune_own_votes(&self, committed_height: u64) {
        RocksDbStorage::prune_own_votes(self, committed_height);
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        RocksDbStorage::get_block_for_sync(self, height)
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        RocksDbStorage::get_transactions_batch(self, hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        RocksDbStorage::get_certificates_batch(self, hashes)
    }

    fn store_receipt_bundle(&self, bundle: &hyperscale_types::ReceiptBundle) {
        RocksDbStorage::store_receipt_bundle(self, bundle)
    }

    fn store_receipt_bundles(&self, bundles: &[hyperscale_types::ReceiptBundle]) {
        RocksDbStorage::store_receipt_bundles(self, bundles)
    }

    fn get_ledger_receipt(
        &self,
        tx_hash: &Hash,
    ) -> Option<Arc<hyperscale_types::LedgerTransactionReceipt>> {
        RocksDbStorage::get_ledger_receipt(self, tx_hash)
    }

    fn get_local_execution(
        &self,
        tx_hash: &Hash,
    ) -> Option<hyperscale_types::LocalTransactionExecution> {
        RocksDbStorage::get_local_execution(self, tx_hash)
    }
}
