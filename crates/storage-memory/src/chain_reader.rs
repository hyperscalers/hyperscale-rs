//! `ChainReader` implementation for `SimStorage`.

use std::sync::Arc;

use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_storage::{BlockForSync, ChainReader};
use hyperscale_types::{
    BlockHash, BlockHeight, BlockManifest, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, ExecutionCertificateHash, QuorumCertificate, RoutableTransaction,
    ShardGroupId, TxHash, WaveCertificate, WaveId,
};

use crate::core::SimStorage;

impl ChainReader for SimStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .map(|certified| {
                CommittedBlockHeader::new(certified.block.header().clone(), certified.qc.clone())
            })
    }

    fn committed_height(&self) -> BlockHeight {
        read_or_recover(&self.consensus).committed_height
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        read_or_recover(&self.consensus).committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        read_or_recover(&self.consensus).committed_qc.clone()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
            .map(|certified| {
                let provision_hashes = BlockManifest::from_block(&certified.block).provision_hashes;
                BlockForSync {
                    block: certified.block,
                    qc: certified.qc,
                    provision_hashes,
                }
            })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        let c = read_or_recover(&self.consensus);
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
        let c = read_or_recover(&self.consensus);
        ids.iter()
            .filter_map(|id| c.certificates.get(id).cloned())
            .collect()
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        read_or_recover(&self.consensus)
            .consensus_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate> {
        let c = read_or_recover(&self.consensus);
        c.execution_certs_by_height
            .get(&block_height)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| c.execution_certs.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_wave_certificate_for_tx(&self, tx_hash: &TxHash) -> Option<WaveCertificate> {
        let c = read_or_recover(&self.consensus);
        let wave_id = c.tx_to_wave.get(tx_hash)?;
        c.certificates.get(wave_id).cloned()
    }

    fn get_ec_hashes_for_tx(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Vec<(ShardGroupId, ExecutionCertificateHash)>> {
        read_or_recover(&self.consensus)
            .tx_to_ec
            .get(tx_hash)
            .cloned()
    }
}
