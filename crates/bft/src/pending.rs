//! Pending block assembly.
//!
//! Tracks blocks being assembled from headers + gossiped transactions.

use hyperscale_types::{
    Block, BlockHeader, CommitmentProof, Hash, RoutableTransaction, TransactionAbort,
    TransactionCertificate, TransactionDefer,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Tracks a block being assembled from header + gossiped transactions + certificates.
///
/// # Lifecycle
///
/// 1. Created from BlockHeader (all transactions/certificates marked as absent by hash)
/// 2. Full Transaction objects arrive via gossip (stored in received_transactions map)
/// 3. Certificates are fetched from local CertificateProvider
/// 4. When all transactions and certificates received, block can be constructed
/// 5. Block stored to storage
/// 6. Block ready for voting
#[derive(Debug, Clone)]
pub struct PendingBlock {
    /// Block header (received first).
    header: BlockHeader,

    /// Original transaction order from the gossip message.
    /// This is the canonical order the proposer intended, which must be preserved
    /// when constructing the block (priority TXs first, then others, both in hash order).
    original_tx_order: Vec<Hash>,

    /// Original certificate order from the gossip message.
    original_cert_order: Vec<Hash>,

    /// Map of transaction hash -> Arc<RoutableTransaction> (for received transactions).
    received_transactions: HashMap<Hash, Arc<RoutableTransaction>>,

    /// Set of transaction hashes we're still waiting for (HashSet for O(1) lookup).
    missing_transaction_hashes: HashSet<Hash>,

    /// Map of transaction hash -> Arc<TransactionCertificate> (for received certificates).
    received_certificates: HashMap<Hash, Arc<TransactionCertificate>>,

    /// Set of certificate hashes we're still waiting for (HashSet for O(1) lookup).
    missing_certificate_hashes: HashSet<Hash>,

    /// Deferred transactions (from block header gossip).
    /// These don't need to be fetched - they're included directly in the gossip message.
    deferred: Vec<TransactionDefer>,

    /// Aborted transactions (from block header gossip).
    /// These don't need to be fetched - they're included directly in the gossip message.
    aborted: Vec<TransactionAbort>,

    /// Commitment proofs for priority transaction ordering.
    /// Included in block gossip to make blocks self-contained for validation.
    commitment_proofs: HashMap<Hash, CommitmentProof>,

    /// The fully constructed block (None until all transactions/certs received).
    constructed_block: Option<Arc<Block>>,
}

impl PendingBlock {
    /// Create a new pending block from a header, transaction hashes, and certificate hashes.
    ///
    /// Initializes the missing sets with all hashes.
    pub fn new(
        header: BlockHeader,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
    ) -> Self {
        Self::full(
            header,
            transaction_hashes,
            certificate_hashes,
            vec![],
            vec![],
        )
    }

    /// Create a new pending block with all fields including deferrals and aborts.
    pub fn full(
        header: BlockHeader,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
    ) -> Self {
        Self::with_proofs(
            header,
            transaction_hashes,
            certificate_hashes,
            deferred,
            aborted,
            HashMap::new(),
        )
    }

    /// Create a new pending block with commitment proofs.
    pub fn with_proofs(
        header: BlockHeader,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Self {
        Self {
            header,
            original_tx_order: transaction_hashes.clone(),
            original_cert_order: certificate_hashes.clone(),
            received_transactions: HashMap::with_capacity(transaction_hashes.len()),
            missing_transaction_hashes: transaction_hashes.into_iter().collect(),
            received_certificates: HashMap::with_capacity(certificate_hashes.len()),
            missing_certificate_hashes: certificate_hashes.into_iter().collect(),
            deferred,
            aborted,
            commitment_proofs,
            constructed_block: None,
        }
    }

    /// Add a received transaction.
    ///
    /// Returns true if this transaction was needed, false if duplicate or not in this block.
    pub fn add_transaction_arc(&mut self, tx: Arc<RoutableTransaction>) -> bool {
        let hash = tx.hash();
        // O(1) lookup and removal with HashSet
        if self.missing_transaction_hashes.remove(&hash) {
            self.received_transactions.insert(hash, tx);
            true
        } else {
            false
        }
    }

    /// Add a received transaction (wraps in Arc).
    ///
    /// Returns true if this transaction was needed, false if duplicate or not in this block.
    pub fn add_transaction(&mut self, tx: RoutableTransaction) -> bool {
        self.add_transaction_arc(Arc::new(tx))
    }

    /// Add a received certificate.
    ///
    /// Returns true if this certificate was needed, false if duplicate or not in this block.
    pub fn add_certificate(&mut self, cert: Arc<TransactionCertificate>) -> bool {
        let cert_hash = cert.transaction_hash;
        // O(1) lookup and removal with HashSet
        if self.missing_certificate_hashes.remove(&cert_hash) {
            self.received_certificates.insert(cert_hash, cert);
            true
        } else {
            false
        }
    }

    /// Check if all transactions and certificates have been received.
    pub fn is_complete(&self) -> bool {
        self.missing_transaction_hashes.is_empty() && self.missing_certificate_hashes.is_empty()
    }

    /// Check if all transactions have been received (certificates may still be pending).
    pub fn has_all_transactions(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
    }

    /// Get the number of missing transaction hashes.
    pub fn missing_transaction_count(&self) -> usize {
        self.missing_transaction_hashes.len()
    }

    /// Get the missing transaction hashes as a Vec (for iteration/display).
    pub fn missing_transactions(&self) -> Vec<Hash> {
        self.missing_transaction_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific transaction.
    pub fn needs_transaction(&self, tx_hash: &Hash) -> bool {
        self.missing_transaction_hashes.contains(tx_hash)
    }

    /// Get the number of missing certificate hashes.
    pub fn missing_certificate_count(&self) -> usize {
        self.missing_certificate_hashes.len()
    }

    /// Get the missing certificate hashes as a Vec (for iteration/display).
    pub fn missing_certificates(&self) -> Vec<Hash> {
        self.missing_certificate_hashes.iter().copied().collect()
    }

    /// Construct the block from header + received transactions + received certificates.
    ///
    /// Should only be called when is_complete() returns true.
    ///
    /// # Errors
    ///
    /// Returns error if block is not yet complete.
    pub fn construct_block(&mut self) -> Result<Arc<Block>, String> {
        if !self.is_complete() {
            return Err(format!(
                "Cannot construct block: {} transactions and {} certificates still missing",
                self.missing_transaction_hashes.len(),
                self.missing_certificate_hashes.len()
            ));
        }

        if let Some(ref block) = self.constructed_block {
            return Ok(Arc::clone(block));
        }

        // Build transactions in the ORIGINAL order from the gossip message.
        // This is critical: the proposer ordered them with priority TXs first,
        // then others, both groups in hash order. We must preserve that order
        // regardless of the order transactions were received from the network.
        let transactions: Vec<Arc<RoutableTransaction>> = self
            .original_tx_order
            .iter()
            .filter_map(|hash| self.received_transactions.remove(hash))
            .collect();

        // Build certificates in the original order from the gossip message.
        let certificates: Vec<Arc<TransactionCertificate>> = self
            .original_cert_order
            .iter()
            .filter_map(|hash| self.received_certificates.remove(hash))
            .collect();

        // Take deferred, aborted, and proofs (replace with empty)
        let deferred = std::mem::take(&mut self.deferred);
        let aborted = std::mem::take(&mut self.aborted);
        let commitment_proofs = std::mem::take(&mut self.commitment_proofs);

        let block = Arc::new(Block {
            header: self.header.clone(),
            transactions,
            committed_certificates: certificates,
            deferred,
            aborted,
            commitment_proofs,
        });

        self.constructed_block = Some(Arc::clone(&block));
        Ok(block)
    }

    /// Get the constructed block, if available.
    pub fn block(&self) -> Option<Arc<Block>> {
        self.constructed_block.as_ref().map(Arc::clone)
    }

    /// Get the block header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Get the block hash.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get all transaction hashes in the original order.
    ///
    /// Used for re-broadcasting block headers after view change.
    pub fn all_transaction_hashes(&self) -> Vec<Hash> {
        self.original_tx_order.clone()
    }

    /// Get all certificate hashes in the original order.
    ///
    /// Used for re-broadcasting block headers after view change.
    pub fn all_certificate_hashes(&self) -> Vec<Hash> {
        self.original_cert_order.clone()
    }

    /// Get reference to deferred transactions.
    pub fn deferred(&self) -> &[TransactionDefer] {
        &self.deferred
    }

    /// Get reference to aborted transactions.
    pub fn aborted(&self) -> &[TransactionAbort] {
        &self.aborted
    }

    /// Get reference to commitment proofs.
    pub fn commitment_proofs(&self) -> &HashMap<Hash, CommitmentProof> {
        &self.commitment_proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, QuorumCertificate, ValidatorId};

    fn make_header(height: u64) -> BlockHeader {
        BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
        }
    }

    #[test]
    fn test_pending_block_creation() {
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let transactions = vec![tx1, tx2];
        let header = make_header(1);

        let pb = PendingBlock::new(header.clone(), transactions, vec![]);

        assert_eq!(pb.missing_transactions().len(), 2);
        assert!(pb.missing_transactions().contains(&tx1));
        assert!(pb.missing_transactions().contains(&tx2));
        assert!(!pb.is_complete());
        assert!(pb.block().is_none());
    }

    #[test]
    fn test_empty_block_is_complete() {
        let header = make_header(1);
        let pb = PendingBlock::new(header, vec![], vec![]);

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_certificates() {
        let tx1 = Hash::from_bytes(b"tx1");
        let cert1 = Hash::from_bytes(b"cert1");
        let cert2 = Hash::from_bytes(b"cert2");
        let header = make_header(1);

        let pb = PendingBlock::new(header, vec![tx1], vec![cert1, cert2]);

        assert_eq!(pb.missing_transaction_count(), 1);
        assert_eq!(pb.missing_certificate_count(), 2);
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_certificate() {
        use hyperscale_types::{TransactionCertificate, TransactionDecision};
        use std::collections::BTreeMap;

        let cert_hash = Hash::from_bytes(b"cert1");
        let header = make_header(1);

        let mut pb = PendingBlock::new(header, vec![], vec![cert_hash]);

        assert_eq!(pb.missing_certificate_count(), 1);
        assert!(!pb.is_complete());

        // Create a test certificate
        let cert = TransactionCertificate {
            transaction_hash: cert_hash,
            decision: TransactionDecision::Accept,
            shard_proofs: BTreeMap::new(),
        };

        // Add the certificate
        let added = pb.add_certificate(Arc::new(cert));
        assert!(added);

        assert_eq!(pb.missing_certificate_count(), 0);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_block_needs_both_transactions_and_certificates() {
        use hyperscale_types::{
            test_utils::test_transaction, TransactionCertificate, TransactionDecision,
        };
        use std::collections::BTreeMap;

        // Create a test transaction
        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();

        let cert_hash = Hash::from_bytes(b"cert1");
        let header = make_header(1);

        let mut pb = PendingBlock::new(header, vec![tx_hash], vec![cert_hash]);

        assert!(!pb.has_all_transactions());
        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction_arc(tx);

        assert!(pb.has_all_transactions());
        assert!(!pb.is_complete()); // Still missing certificate

        // Add certificate
        let cert = TransactionCertificate {
            transaction_hash: cert_hash,
            decision: TransactionDecision::Accept,
            shard_proofs: BTreeMap::new(),
        };
        pb.add_certificate(Arc::new(cert));

        assert!(pb.is_complete());
    }
}
