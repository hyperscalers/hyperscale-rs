//! `ConsensusStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::typed_cf::TypedCf;

use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, Hash, QuorumCertificate, RoutableTransaction,
    ShardGroupId, WaveCertificate,
};
use std::sync::Arc;

impl hyperscale_storage::ConsensusStore for RocksDbStorage {
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

    fn store_certificate(&self, certificate: &WaveCertificate) {
        RocksDbStorage::put_certificate(self, &certificate.wave_id.hash(), certificate);
    }

    fn get_certificate(&self, hash: &Hash) -> Option<WaveCertificate> {
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

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        RocksDbStorage::get_certificates_batch(self, hashes)
    }

    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        RocksDbStorage::get_local_receipt(self, tx_hash)
    }

    fn get_execution_output(&self, tx_hash: &Hash) -> Option<hyperscale_types::ExecutionOutput> {
        RocksDbStorage::get_execution_output(self, tx_hash)
    }

    fn get_execution_certificate(&self, canonical_hash: &Hash) -> Option<ExecutionCertificate> {
        self.cf_get::<crate::column_families::ExecutionCertsCf>(canonical_hash)
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

    fn get_wave_certificates_by_height(&self, block_height: u64) -> Vec<WaveCertificate> {
        // TODO: add a dedicated `wave_certs_by_height` CF for O(1) lookup.
        // For now, scan all certificates and filter by wave_id.block_height.
        let cf = crate::column_families::CertificatesCf::handle(&self.cf());
        let mut result = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for (_key, value) in iter.flatten() {
            if let Ok(cert) = sbor::basic_decode::<WaveCertificate>(&value) {
                if cert.wave_id.block_height == block_height {
                    result.push(cert);
                }
            }
        }
        result
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
