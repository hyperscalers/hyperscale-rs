//! `ChainReader` implementation for `RocksDbStorage`.

use std::sync::Arc;

use hyperscale_storage::{BlockForSync, ChainReader};
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, QuorumCertificate, RoutableTransaction, TxHash, WaveCertificate, WaveId,
};

use crate::column_families::ExecutionCertsCf;
use crate::core::RocksDbStorage;
use crate::typed_cf::{TypedCf, get};

impl ChainReader for RocksDbStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.get_block_denormalized(height)
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        let metadata = self.get_block_metadata(height)?;
        let (header, _, qc) = metadata.into_parts();
        Some(CommittedBlockHeader::new(header, qc))
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
        Self::get_block_for_sync(self, height).map(|(block, qc, provision_hashes)| BlockForSync {
            block,
            qc,
            provision_hashes,
        })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        Self::get_transactions_batch(self, hashes)
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
        Self::get_certificates_batch(self, ids)
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        Self::get_consensus_receipt(self, tx_hash)
    }

    fn get_execution_certificate(&self, wave_id: &WaveId) -> Option<ExecutionCertificate> {
        let cfs = self.cf();
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        get::<ExecutionCertsCf>(&*self.db, certs_cf, wave_id)
    }

    fn get_execution_certificates_batch(&self, wave_ids: &[WaveId]) -> Vec<ExecutionCertificate> {
        let cfs = self.cf();
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        wave_ids
            .iter()
            .filter_map(|wid| get::<ExecutionCertsCf>(&*self.db, certs_cf, wid))
            .collect()
    }
}
