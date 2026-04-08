//! Pending block assembly.
//!
//! Tracks blocks being assembled from headers + gossiped transactions.

use hyperscale_types::{
    Block, BlockHeader, BlockManifest, Hash, RoutableTransaction, WaveCertificate,
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
///
/// # Transaction Sections
///
/// Transactions are organized into three priority sections:
/// - **Retry**: Retry transactions (highest priority, critical for liveness)
/// - **Priority**: Cross-shard transactions with commitment proofs
/// - **Other**: Fresh transactions with no special priority
#[derive(Debug, Clone)]
pub struct PendingBlock {
    /// Block header (received first).
    header: BlockHeader,

    /// Block contents manifest (transaction hashes, certificates, deferrals, etc.)
    manifest: BlockManifest,

    /// Map of transaction hash -> Arc<RoutableTransaction> (for received transactions).
    received_transactions: HashMap<Hash, Arc<RoutableTransaction>>,

    /// Set of transaction hashes we're still waiting for (HashSet for O(1) lookup).
    missing_transaction_hashes: HashSet<Hash>,

    /// Map of wave_id hash -> Arc<WaveCertificate> (for received certificates).
    received_certificates: HashMap<Hash, Arc<WaveCertificate>>,

    /// Set of certificate hashes we're still waiting for (HashSet for O(1) lookup).
    missing_certificate_hashes: HashSet<Hash>,

    /// Set of receipt tx_hashes we're still waiting for (HashSet for O(1) lookup).
    ///
    /// Populated from `BlockManifest::receipt_hashes` — the tx_hashes of non-aborted
    /// certificates. A block with certificates is not complete until receipts
    /// (DatabaseUpdates in the execution cache) are available for all non-aborted certs.
    /// This prevents voting on blocks where state_root cannot be verified.
    missing_receipt_hashes: HashSet<Hash>,

    /// The fully constructed block (None until all transactions/certs received).
    constructed_block: Option<Arc<Block>>,
}

impl PendingBlock {
    /// Create a pending block from a header and manifest.
    pub fn from_manifest(header: BlockHeader, manifest: BlockManifest) -> Self {
        let total_tx_count = manifest.transaction_count();
        let missing_transaction_hashes: HashSet<Hash> =
            manifest.tx_hashes.iter().copied().collect();
        let missing_certificate_hashes: HashSet<Hash> =
            manifest.cert_hashes.iter().copied().collect();
        let missing_receipt_hashes: HashSet<Hash> =
            manifest.receipt_hashes.iter().copied().collect();

        Self {
            header,
            received_transactions: HashMap::with_capacity(total_tx_count),
            missing_transaction_hashes,
            received_certificates: HashMap::with_capacity(manifest.cert_hashes.len()),
            missing_certificate_hashes,
            missing_receipt_hashes,
            manifest,
            constructed_block: None,
        }
    }

    /// Create a pending block from a complete block (proposer's own block).
    ///
    /// Skips the hash-extraction → re-fill round-trip since we already have
    /// all transactions and certificates. `receipt_tx_hashes` are the tx hashes
    /// with available receipts, pre-computed by the action handler which has
    /// storage access to look up each wave cert's source block.
    pub fn from_complete_block(block: &Block, receipt_tx_hashes: Vec<Hash>) -> Self {
        let manifest = BlockManifest::from_block_with_receipts(block, receipt_tx_hashes);
        let mut pending = Self {
            header: block.header.clone(),
            received_transactions: HashMap::new(),
            missing_transaction_hashes: HashSet::new(),
            received_certificates: HashMap::new(),
            missing_certificate_hashes: HashSet::new(),
            missing_receipt_hashes: HashSet::new(), // Proposer already has all receipts
            manifest,
            constructed_block: None,
        };
        // Fill in all transactions and certificates so construct_block works
        for tx in &block.transactions {
            pending
                .received_transactions
                .insert(tx.hash(), Arc::clone(tx));
        }
        for cert in &block.certificates {
            pending
                .received_certificates
                .insert(cert.wave_id.hash(), Arc::clone(cert));
        }
        pending
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

    /// Add a received certificate.
    ///
    /// Returns true if this certificate was needed, false if duplicate or not in this block.
    pub fn add_certificate(&mut self, cert: Arc<WaveCertificate>) -> bool {
        let cert_hash = cert.wave_id.hash();
        // O(1) lookup and removal with HashSet
        if self.missing_certificate_hashes.remove(&cert_hash) {
            self.received_certificates.insert(cert_hash, cert);
            true
        } else {
            false
        }
    }

    /// Add a receipt (mark as available by tx_hash).
    ///
    /// Returns true if this receipt was needed, false if duplicate or not in this block.
    pub fn add_receipt(&mut self, tx_hash: &Hash) -> bool {
        self.missing_receipt_hashes.remove(tx_hash)
    }

    /// Check if all transactions, certificates, and receipts have been received.
    pub fn is_complete(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
            && self.missing_certificate_hashes.is_empty()
            && self.missing_receipt_hashes.is_empty()
    }

    /// Check if all transactions have been received (certificates may still be pending).
    #[cfg(test)]
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

    /// Get the number of missing receipt hashes.
    pub fn missing_receipt_count(&self) -> usize {
        self.missing_receipt_hashes.len()
    }

    /// Get the missing receipt hashes as a Vec (for fetch requests).
    #[allow(dead_code)] // API parity with missing_transactions(); used when receipt fetch is added
    pub fn missing_receipts(&self) -> Vec<Hash> {
        self.missing_receipt_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific receipt.
    pub fn needs_receipt(&self, tx_hash: &Hash) -> bool {
        self.missing_receipt_hashes.contains(tx_hash)
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
                "Cannot construct block: {} transactions, {} certificates, {} receipts still missing",
                self.missing_transaction_hashes.len(),
                self.missing_certificate_hashes.len(),
                self.missing_receipt_hashes.len()
            ));
        }

        if let Some(ref block) = self.constructed_block {
            return Ok(Arc::clone(block));
        }

        // Build transactions in the ORIGINAL order from the gossip message.
        let transactions: Vec<Arc<RoutableTransaction>> = self
            .manifest
            .tx_hashes
            .iter()
            .filter_map(|hash| self.received_transactions.remove(hash))
            .collect();

        // Build certificates in the original order from the gossip message.
        let certificates: Vec<Arc<WaveCertificate>> = self
            .manifest
            .cert_hashes
            .iter()
            .filter_map(|hash| self.received_certificates.remove(hash))
            .collect();

        let abort_intents = self.manifest.abort_intents.clone();

        let block = Arc::new(Block {
            header: self.header.clone(),
            transactions,
            certificates,
            abort_intents,
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

    /// Get the block manifest.
    pub fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Get total transaction count across all sections.
    pub fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }

    /// Get certificate count.
    pub fn certificate_count(&self) -> usize {
        self.manifest.cert_hashes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, QuorumCertificate, ShardGroupId, ValidatorId};

    fn make_header(height: u64) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            waves: vec![],
        }
    }

    #[test]
    fn test_pending_block_creation() {
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let header = make_header(1);

        let pb = PendingBlock::from_manifest(
            header.clone(),
            BlockManifest {
                tx_hashes: vec![tx1, tx2],
                ..Default::default()
            },
        );

        assert_eq!(pb.missing_transactions().len(), 2);
        assert!(pb.missing_transactions().contains(&tx1));
        assert!(pb.missing_transactions().contains(&tx2));
        assert!(!pb.is_complete());
        assert!(pb.block().is_none());
    }

    #[test]
    fn test_empty_block_is_complete() {
        let header = make_header(1);
        let pb = PendingBlock::from_manifest(header, BlockManifest::default());

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_certificates() {
        let tx1 = Hash::from_bytes(b"tx1");
        let cert1 = Hash::from_bytes(b"cert1");
        let cert2 = Hash::from_bytes(b"cert2");
        let header = make_header(1);

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                tx_hashes: vec![tx1],
                cert_hashes: vec![cert1, cert2],
                ..Default::default()
            },
        );

        assert_eq!(pb.missing_transaction_count(), 1);
        assert_eq!(pb.missing_certificate_count(), 2);
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_certificate() {
        use hyperscale_types::{WaveCertificate, WaveId, WaveResolution};

        let wave_id = WaveId::new(ShardGroupId(0), 1, Default::default());
        let cert_hash = wave_id.hash();
        let header = make_header(1);

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                cert_hashes: vec![cert_hash],
                ..Default::default()
            },
        );

        assert_eq!(pb.missing_certificate_count(), 1);
        assert!(!pb.is_complete());

        // Create a test wave certificate
        let cert = WaveCertificate {
            wave_id,
            resolution: WaveResolution::Aborted,
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
            test_utils::test_transaction, WaveCertificate, WaveId, WaveResolution,
        };

        // Create a test transaction
        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();

        let wave_id = WaveId::new(ShardGroupId(0), 1, Default::default());
        let cert_hash = wave_id.hash();
        let header = make_header(1);

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                tx_hashes: vec![tx_hash],
                cert_hashes: vec![cert_hash],
                ..Default::default()
            },
        );

        assert!(!pb.has_all_transactions());
        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction_arc(tx);

        assert!(pb.has_all_transactions());
        assert!(!pb.is_complete()); // Still missing certificate

        // Add certificate
        let cert = WaveCertificate {
            wave_id,
            resolution: WaveResolution::Aborted,
        };
        pb.add_certificate(Arc::new(cert));

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_receipts() {
        let receipt1 = Hash::from_bytes(b"receipt1");
        let receipt2 = Hash::from_bytes(b"receipt2");
        let header = make_header(1);

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                receipt_hashes: vec![receipt1, receipt2],
                ..Default::default()
            },
        );

        assert_eq!(pb.missing_receipt_count(), 2);
        assert!(pb.needs_receipt(&receipt1));
        assert!(pb.needs_receipt(&receipt2));
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_receipt() {
        let receipt_hash = Hash::from_bytes(b"receipt1");
        let header = make_header(1);

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                receipt_hashes: vec![receipt_hash],
                ..Default::default()
            },
        );

        assert_eq!(pb.missing_receipt_count(), 1);
        assert!(!pb.is_complete());

        let added = pb.add_receipt(&receipt_hash);
        assert!(added);

        assert_eq!(pb.missing_receipt_count(), 0);
        assert!(pb.is_complete());

        // Duplicate add returns false
        let added_again = pb.add_receipt(&receipt_hash);
        assert!(!added_again);
    }

    #[test]
    fn test_block_needs_transactions_certificates_and_receipts() {
        use hyperscale_types::{
            test_utils::test_transaction, WaveCertificate, WaveId, WaveResolution,
        };

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let wave_id = WaveId::new(ShardGroupId(0), 1, Default::default());
        let cert_hash = wave_id.hash();
        let receipt_hash = Hash::from_bytes(b"receipt1");
        let header = make_header(1);

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                tx_hashes: vec![tx_hash],
                cert_hashes: vec![cert_hash],
                receipt_hashes: vec![receipt_hash],
                ..Default::default()
            },
        );

        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction_arc(tx);
        assert!(!pb.is_complete()); // Still missing certificate + receipt

        // Add certificate
        let cert = WaveCertificate {
            wave_id,
            resolution: WaveResolution::Aborted,
        };
        pb.add_certificate(Arc::new(cert));
        assert!(!pb.is_complete()); // Still missing receipt

        // Add receipt
        pb.add_receipt(&receipt_hash);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_from_complete_block_has_no_missing_receipts() {
        use hyperscale_types::{Block, WaveCertificate, WaveId, WaveResolution};

        let cert = Arc::new(WaveCertificate {
            wave_id: WaveId::new(ShardGroupId(0), 1, Default::default()),
            resolution: WaveResolution::Aborted,
        });

        let block = Block {
            header: make_header(1),
            transactions: vec![],
            certificates: vec![cert],
            abort_intents: vec![],
        };

        let pending = PendingBlock::from_complete_block(&block, vec![]);

        // Proposer's own block: no missing receipts
        assert_eq!(pending.missing_receipt_count(), 0);
        assert!(pending.is_complete());
    }
}
