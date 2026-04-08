//! `ConsensusStore` implementation for `SimStorage`.

use crate::core::SimStorage;

use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, ExecutionOutput, Hash, LocalReceipt,
    QuorumCertificate, RoutableTransaction, ShardGroupId, WaveCertificate,
};
use std::collections::HashMap;
use std::sync::Arc;

impl ConsensusStore for SimStorage {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        let mut c = self.consensus.write().unwrap();
        // Index all transactions by hash for batch lookups
        for tx in block.transactions.iter() {
            c.transactions.insert(tx.hash(), tx.as_ref().clone());
        }
        c.blocks.insert(height, (block.clone(), qc.clone()));
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.consensus.write().unwrap().committed_height = height;
    }

    fn committed_height(&self) -> BlockHeight {
        self.consensus.read().unwrap().committed_height
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        let mut c = self.consensus.write().unwrap();
        c.committed_height = height;
        c.committed_hash = Some(hash);
        c.committed_qc = Some(qc.clone());
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.consensus.read().unwrap().committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.consensus.read().unwrap().committed_qc.clone()
    }

    fn store_certificate(&self, certificate: &WaveCertificate) {
        let mut c = self.consensus.write().unwrap();
        let wave_id_hash = certificate.wave_id.hash();
        c.certificates.insert(wave_id_hash, certificate.clone());
        c.wave_certs_by_height
            .entry(certificate.wave_id.block_height)
            .or_default()
            .push(wave_id_hash);
    }

    fn get_certificate(&self, hash: &Hash) -> Option<WaveCertificate> {
        self.consensus
            .read()
            .unwrap()
            .certificates
            .get(hash)
            .cloned()
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        self.consensus
            .write()
            .unwrap()
            .own_votes
            .insert(height, (block_hash, round));
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        self.consensus
            .read()
            .unwrap()
            .own_votes
            .get(&height)
            .copied()
    }

    fn get_all_own_votes(&self) -> HashMap<u64, (Hash, u64)> {
        self.consensus.read().unwrap().own_votes.clone()
    }

    fn prune_own_votes(&self, committed_height: u64) {
        self.consensus
            .write()
            .unwrap()
            .own_votes
            .retain(|height, _| *height > committed_height);
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

    fn get_execution_output(&self, tx_hash: &Hash) -> Option<ExecutionOutput> {
        self.consensus
            .read()
            .unwrap()
            .execution_outputs
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificate(&self, canonical_hash: &Hash) -> Option<ExecutionCertificate> {
        self.consensus
            .read()
            .unwrap()
            .execution_certs
            .get(canonical_hash)
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

    fn get_wave_certificates_by_height(&self, height: u64) -> Vec<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        c.wave_certs_by_height
            .get(&height)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| c.certificates.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
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
