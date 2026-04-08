//! Consensus storage trait.
//!
//! Abstracts block, certificate, vote, and metadata storage.
//! All methods take `&self` — implementations use interior mutability.

use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, ExecutionOutput, Hash, LocalReceipt,
    QuorumCertificate, ReceiptBundle, RoutableTransaction, ShardGroupId, WaveCertificate,
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

    /// Store a wave certificate (keyed by wave_id hash).
    fn store_certificate(&self, certificate: &WaveCertificate);

    /// Get a wave certificate by wave_id hash.
    fn get_certificate(&self, hash: &Hash) -> Option<WaveCertificate>;

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
    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate>;

    // ─── Receipt Storage ──────────────────────────────────────────────────

    /// Store a receipt bundle (local receipt + optional execution output) for a transaction.
    ///
    /// If `bundle.execution_output` is `None` (e.g., receipt fetched during sync),
    /// only the local receipt is persisted.
    fn store_receipt_bundle(&self, bundle: &ReceiptBundle);

    /// Store multiple receipt bundles atomically.
    ///
    /// Default implementation loops, but RocksDB overrides for atomic batch write.
    fn store_receipt_bundles(&self, bundles: &[ReceiptBundle]) {
        for bundle in bundles {
            self.store_receipt_bundle(bundle);
        }
    }

    /// Retrieve the local receipt for a transaction.
    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<LocalReceipt>>;

    /// Retrieve execution output details for a transaction.
    ///
    /// Returns `None` both when the tx doesn't exist AND when it was synced
    /// (not executed locally). Use `has_receipt()` to distinguish.
    fn get_execution_output(&self, tx_hash: &Hash) -> Option<ExecutionOutput>;

    /// Check if a local receipt exists for a transaction.
    fn has_receipt(&self, tx_hash: &Hash) -> bool {
        self.get_local_receipt(tx_hash).is_some()
    }

    // ─── Execution Certificate Storage ───────────────────────────────────

    /// Retrieve an execution certificate by its canonical hash.
    fn get_execution_certificate(&self, canonical_hash: &Hash) -> Option<ExecutionCertificate>;

    /// Retrieve all execution certificates for a given block height.
    fn get_execution_certificates_by_height(&self, block_height: u64) -> Vec<ExecutionCertificate>;

    /// Store execution certificates (standalone write, separate WriteBatch).
    ///
    /// Used for late-arriving ECs that complete after their block was already
    /// committed. Not used on the primary commit path (D4 folds EC writes into
    /// `commit_block`/`commit_prepared_block`).
    fn store_execution_certificates(&self, certs: &[ExecutionCertificate]);

    // ─── Wave Certificate Indexes ─────────────────────────────────────────

    /// Get all wave certificates at a given block height.
    ///
    /// Used for sync serving — callers retrieve all certs committed at a
    /// height without knowing their wave_id hashes upfront.
    fn get_wave_certificates_by_height(&self, height: u64) -> Vec<WaveCertificate>;

    /// Get the wave certificate that finalized a given transaction.
    ///
    /// Returns `None` if no wave cert has been recorded for this tx.
    fn get_wave_certificate_for_tx(&self, tx_hash: &Hash) -> Option<WaveCertificate>;

    /// Get the execution certificate hashes associated with a transaction.
    ///
    /// Returns the `(ShardGroupId, ec_hash)` pairs from every shard that
    /// produced an EC covering this transaction. Returns `None` if no
    /// index entry exists for this tx.
    fn get_ec_hashes_for_tx(&self, tx_hash: &Hash) -> Option<Vec<(ShardGroupId, Hash)>>;
}
