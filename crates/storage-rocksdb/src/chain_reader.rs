//! `ChainReader` implementation for `RocksDbStorage`.

use std::sync::Arc;

use hyperscale_storage::{BlockForSync, ChainReader};
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, QuorumCertificate, RoutableTransaction, TxHash, WaveCertificate, WaveId,
};

use crate::column_families::{ExecutionCertsByHeightCf, ExecutionCertsCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{TypedCf, get, prefix_iter};

impl ChainReader for RocksDbStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.get_block_denormalized(height)
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        let metadata = self.get_block_metadata(height)?;
        Some(CommittedBlockHeader::new(metadata.header, metadata.qc))
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

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate> {
        // Resolve both column-family handles once. Per-call `cf_get` would
        // re-walk `RocksDB`'s name → handle map for every match returned by
        // the prefix iterator.
        let cfs = self.cf();
        let index_cf = ExecutionCertsByHeightCf::handle(&cfs);
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        let prefix = block_height.inner().to_be_bytes();
        prefix_iter::<ExecutionCertsByHeightCf>(&self.db, index_cf, &prefix)
            .filter_map(|((_height, canonical_hash), ())| {
                get::<ExecutionCertsCf>(&*self.db, certs_cf, &canonical_hash)
            })
            .collect()
    }
}
