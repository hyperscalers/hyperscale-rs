//! Consensus storage trait.
//!
//! Abstracts block, certificate, vote, and metadata storage.
//! All methods take `&self` — implementations use interior mutability.

use hyperscale_types::{
    Block, BlockHeight, Hash, LedgerTransactionReceipt, LocalTransactionExecution,
    QuorumCertificate, ReceiptBundle, RoutableTransaction, TransactionCertificate,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Abstracts consensus-related storage for both simulation and production.
///
/// Provides a uniform interface for storing blocks, certificates, votes,
/// and chain metadata across different storage backends.
pub trait ConsensusStore: Send + Sync {
    /// Store a committed block with its quorum certificate.
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate);

    /// Get a committed block by height.
    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)>;

    /// Set the highest committed block height.
    fn set_committed_height(&self, height: BlockHeight);

    /// Get the highest committed block height.
    fn committed_height(&self) -> BlockHeight;

    /// Set committed state (height + hash + QC) atomically.
    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate);

    /// Get the latest committed block hash.
    fn committed_hash(&self) -> Option<Hash>;

    /// Get the latest quorum certificate.
    fn latest_qc(&self) -> Option<QuorumCertificate>;

    /// Store a transaction certificate (extracts hash internally).
    fn store_certificate(&self, certificate: &TransactionCertificate);

    /// Get a transaction certificate by transaction hash.
    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate>;

    /// Store our own vote for a height.
    ///
    /// **BFT Safety Critical**: Must be called before broadcasting the vote.
    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash);

    /// Get our own vote for a height (if any).
    ///
    /// Returns `Some((block_hash, round))` if we previously voted at this height.
    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)>;

    /// Get all our own votes (for recovery on startup).
    ///
    /// Returns a map of height → (block_hash, round).
    fn get_all_own_votes(&self) -> HashMap<u64, (Hash, u64)>;

    /// Remove votes at or below a committed height (cleanup).
    fn prune_own_votes(&self, committed_height: u64);

    /// Get a complete block for serving sync requests.
    ///
    /// Returns `Some((block, qc))` only if the full block is available with all
    /// transactions and certificates. Returns `None` if any data is missing.
    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)>;

    /// Get multiple transactions by hash (batch read).
    ///
    /// Returns only transactions that were found (missing hashes are skipped).
    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction>;

    /// Get multiple certificates by hash (batch read).
    ///
    /// Returns only certificates that were found (missing hashes are skipped).
    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate>;

    // ─── Receipt Storage ──────────────────────────────────────────────────

    /// Store a receipt bundle (ledger receipt + optional local execution) for a transaction.
    ///
    /// If `bundle.local_execution` is `None` (e.g., receipt fetched during sync),
    /// only the ledger receipt is persisted.
    fn store_receipt_bundle(&self, bundle: &ReceiptBundle);

    /// Store multiple receipt bundles atomically.
    ///
    /// Default implementation loops, but RocksDB overrides for atomic batch write.
    fn store_receipt_bundles(&self, bundles: &[ReceiptBundle]) {
        for bundle in bundles {
            self.store_receipt_bundle(bundle);
        }
    }

    /// Retrieve the ledger receipt for a transaction.
    fn get_ledger_receipt(&self, tx_hash: &Hash) -> Option<Arc<LedgerTransactionReceipt>>;

    /// Retrieve local execution details for a transaction.
    ///
    /// Returns `None` both when the tx doesn't exist AND when it was synced
    /// (not executed locally). Use `has_receipt()` to distinguish.
    fn get_local_execution(&self, tx_hash: &Hash) -> Option<LocalTransactionExecution>;

    /// Check if a ledger receipt exists for a transaction.
    fn has_receipt(&self, tx_hash: &Hash) -> bool {
        self.get_ledger_receipt(tx_hash).is_some()
    }
}
