//! `ChainReader` implementation for `SimStorage`.

use crate::core::SimStorage;

use hyperscale_storage::{BlockForSync, ChainReader};
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, ExecutionCertificateHash, QuorumCertificate, RoutableTransaction,
    ShardGroupId, TxHash, WaveCertificate, WaveId,
};
use std::sync::Arc;

impl ChainReader for SimStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        self.consensus
            .read()
            .unwrap()
            .blocks
            .get(&height)
            .map(|certified| {
                CommittedBlockHeader::new(certified.block.header().clone(), certified.qc.clone())
            })
    }

    fn committed_height(&self) -> BlockHeight {
        self.consensus.read().unwrap().committed_height
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        self.consensus.read().unwrap().committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.consensus.read().unwrap().committed_qc.clone()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        self.consensus
            .read()
            .unwrap()
            .blocks
            .get(&height)
            .cloned()
            .map(|certified| {
                let provision_hashes =
                    hyperscale_types::BlockManifest::from_block(&certified.block).provision_hashes;
                BlockForSync {
                    block: certified.block,
                    qc: certified.qc,
                    provision_hashes,
                }
            })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        ids.iter()
            .filter_map(|id| c.certificates.get(&id.hash()).cloned())
            .collect()
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.consensus
            .read()
            .unwrap()
            .consensus_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate> {
        let c = self.consensus.read().unwrap();
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
        let c = self.consensus.read().unwrap();
        let wave_id_hash = c.tx_to_wave.get(tx_hash)?;
        c.certificates.get(wave_id_hash).cloned()
    }

    fn get_ec_hashes_for_tx(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Vec<(ShardGroupId, ExecutionCertificateHash)>> {
        self.consensus
            .read()
            .unwrap()
            .tx_to_ec
            .get(tx_hash)
            .cloned()
    }
}
