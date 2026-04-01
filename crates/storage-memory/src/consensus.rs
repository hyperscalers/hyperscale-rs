//! `ConsensusStore` implementation for `SimStorage`.

use crate::core::SimStorage;

use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    Block, BlockHeight, Hash, LedgerTransactionReceipt, LocalTransactionExecution,
    QuorumCertificate, ReceiptBundle, RoutableTransaction, TransactionCertificate,
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

    fn store_certificate(&self, certificate: &TransactionCertificate) {
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.transaction_hash, certificate.clone());
    }

    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
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

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.certificates.get(h).cloned())
            .collect()
    }

    fn store_receipt_bundle(&self, bundle: &ReceiptBundle) {
        let mut c = self.consensus.write().unwrap();
        let receipt = if let Some(ref updates) = bundle.database_updates {
            let mut r = (*bundle.ledger_receipt).clone();
            r.state_changes = hyperscale_storage::extract_state_changes(updates);
            Arc::new(r)
        } else {
            Arc::clone(&bundle.ledger_receipt)
        };
        let height = c.committed_height.0;
        c.ledger_receipts.insert(bundle.tx_hash, receipt);
        c.receipt_heights.insert(bundle.tx_hash, height);
        if let Some(ref local) = bundle.local_execution {
            c.local_executions.insert(bundle.tx_hash, local.clone());
        }
    }

    fn get_ledger_receipt(&self, tx_hash: &Hash) -> Option<Arc<LedgerTransactionReceipt>> {
        self.consensus
            .read()
            .unwrap()
            .ledger_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_local_execution(&self, tx_hash: &Hash) -> Option<LocalTransactionExecution> {
        self.consensus
            .read()
            .unwrap()
            .local_executions
            .get(tx_hash)
            .cloned()
    }
}
