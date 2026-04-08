//! `ConsensusStore` implementation for `SimStorage`.

use crate::core::SimStorage;

use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, Hash, LocalReceipt, QuorumCertificate,
    RoutableTransaction, ShardGroupId, WaveCertificate,
};
use std::sync::Arc;

impl ConsensusStore for SimStorage {
    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn committed_height(&self) -> BlockHeight {
        self.consensus.read().unwrap().committed_height
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.consensus.read().unwrap().committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.consensus.read().unwrap().committed_qc.clone()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.certificates.get(h).cloned())
            .collect()
    }

    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<LocalReceipt>> {
        self.consensus
            .read()
            .unwrap()
            .local_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificates_by_height(&self, block_height: u64) -> Vec<ExecutionCertificate> {
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

    fn store_execution_certificates(&self, certs: &[ExecutionCertificate]) {
        let mut c = self.consensus.write().unwrap();
        for cert in certs {
            let canonical_hash = cert.canonical_hash();
            c.execution_certs.insert(canonical_hash, cert.clone());
            c.execution_certs_by_height
                .entry(cert.block_height())
                .or_default()
                .push(canonical_hash);
        }
    }

    fn get_wave_certificate_for_tx(&self, tx_hash: &Hash) -> Option<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        let wave_id_hash = c.tx_to_wave.get(tx_hash)?;
        c.certificates.get(wave_id_hash).cloned()
    }

    fn get_ec_hashes_for_tx(&self, tx_hash: &Hash) -> Option<Vec<(ShardGroupId, Hash)>> {
        self.consensus
            .read()
            .unwrap()
            .tx_to_ec
            .get(tx_hash)
            .cloned()
    }
}
