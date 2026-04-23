//! `ChainReader` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::typed_cf::TypedCf;

use hyperscale_storage::BlockForSync;
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, ExecutionCertificate, ExecutionCertificateHash,
    QuorumCertificate, RoutableTransaction, ShardGroupId, TxHash, WaveCertificate, WaveIdHash,
};
use std::sync::Arc;

impl hyperscale_storage::ChainReader for RocksDbStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.get_block_denormalized(height)
    }

    fn committed_height(&self) -> BlockHeight {
        self.read_committed_height()
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        self.read_committed_hash().map(BlockHash::from_raw)
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.read_latest_qc()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        RocksDbStorage::get_block_for_sync(self, height).map(|(block, qc, provision_hashes)| {
            BlockForSync {
                block,
                qc,
                provision_hashes,
            }
        })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        RocksDbStorage::get_transactions_batch(self, hashes)
    }

    fn get_certificates_batch(&self, hashes: &[WaveIdHash]) -> Vec<WaveCertificate> {
        RocksDbStorage::get_certificates_batch(self, hashes)
    }

    fn get_local_receipt(&self, tx_hash: &TxHash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        RocksDbStorage::get_local_receipt(self, tx_hash)
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate> {
        let cf = crate::column_families::ExecutionCertsByHeightCf::handle(&self.cf());
        let prefix = block_height.0.to_be_bytes();
        crate::typed_cf::prefix_iter::<crate::column_families::ExecutionCertsByHeightCf>(
            &self.db, cf, &prefix,
        )
        .filter_map(|((_height, canonical_hash), ())| {
            self.cf_get::<crate::column_families::ExecutionCertsCf>(&canonical_hash)
        })
        .collect()
    }

    fn get_wave_certificate_for_tx(&self, _tx_hash: &TxHash) -> Option<WaveCertificate> {
        // TODO: populate and read a `tx_to_wave` CF at block commit time.
        None
    }

    fn get_ec_hashes_for_tx(
        &self,
        _tx_hash: &TxHash,
    ) -> Option<Vec<(ShardGroupId, ExecutionCertificateHash)>> {
        // TODO: populate and read a `tx_to_ec` CF at block commit time.
        None
    }
}
