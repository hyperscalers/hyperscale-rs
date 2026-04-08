//! `ConsensusStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::typed_cf::TypedCf;

use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, Hash, QuorumCertificate, RoutableTransaction,
    ShardGroupId, WaveCertificate,
};
use std::sync::Arc;

impl hyperscale_storage::ConsensusStore for RocksDbStorage {
    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.get_block_denormalized(height)
    }

    fn committed_height(&self) -> BlockHeight {
        self.read_committed_height()
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.read_committed_hash()
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.read_latest_qc()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        RocksDbStorage::get_block_for_sync(self, height)
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        RocksDbStorage::get_transactions_batch(self, hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        RocksDbStorage::get_certificates_batch(self, hashes)
    }

    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        RocksDbStorage::get_local_receipt(self, tx_hash)
    }

    fn get_execution_certificates_by_height(&self, block_height: u64) -> Vec<ExecutionCertificate> {
        let cf = crate::column_families::ExecutionCertsByHeightCf::handle(&self.cf());
        let prefix = block_height.to_be_bytes();
        crate::typed_cf::prefix_iter::<crate::column_families::ExecutionCertsByHeightCf>(
            &self.db, cf, &prefix,
        )
        .filter_map(|((_height, canonical_hash), ())| {
            self.cf_get::<crate::column_families::ExecutionCertsCf>(&canonical_hash)
        })
        .collect()
    }

    fn store_execution_certificates(&self, certs: &[ExecutionCertificate]) {
        if certs.is_empty() {
            return;
        }
        let mut batch = rocksdb::WriteBatch::default();
        crate::execution_certs::append_execution_certs_to_batch(self, &mut batch, certs);
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT SAFETY CRITICAL: EC write failed");
    }

    fn get_wave_certificate_for_tx(&self, _tx_hash: &Hash) -> Option<WaveCertificate> {
        // TODO: populate and read a `tx_to_wave` CF at block commit time.
        None
    }

    fn get_ec_hashes_for_tx(&self, _tx_hash: &Hash) -> Option<Vec<(ShardGroupId, Hash)>> {
        // TODO: populate and read a `tx_to_ec` CF at block commit time.
        None
    }
}
