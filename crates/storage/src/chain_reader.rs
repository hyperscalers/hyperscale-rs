//! Chain reader trait.
//!
//! Abstracts block, certificate, vote, and metadata reads.
//! All methods take `&self` — implementations use interior mutability.

use hyperscale_types::{
    Block, BlockHash, BlockHeight, CertifiedBlock, ExecutionCertificate, ExecutionCertificateHash,
    LocalReceipt, ProvisionHash, QuorumCertificate, RoutableTransaction, ShardGroupId, TxHash,
    WaveCertificate, WaveIdHash,
};
use std::sync::Arc;

/// A sync-ready block retrieved from storage. Always carries a `Sealed`
/// block — the persisted shape never includes provisions. Sync-serving
/// glue re-attaches provisions (promoting to `Live`) when the requester
/// is still within the cross-shard execution window.
#[derive(Debug, Clone)]
pub struct BlockForSync {
    /// The stored block in `Sealed` form.
    pub block: Block,
    /// The QC that certified this block.
    pub qc: QuorumCertificate,
    /// Provisions hashes from the block's manifest — the sync-serving
    /// layer uses these to look up provisions in the in-memory cache.
    pub provision_hashes: Vec<ProvisionHash>,
}

/// Abstracts consensus-related storage for both simulation and production.
///
/// Provides a uniform interface for reading blocks, certificates, receipts,
/// and chain metadata across different storage backends.
///
/// Block and certificate writes happen atomically via `ChainWriter`.
/// Vote persistence is not needed — in-memory tracking in BFT state
/// is sufficient (nodes sync past voted heights on restart).
pub trait ChainReader: Send + Sync + 'static {
    /// Get a committed block by height.
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock>;

    /// Get the highest committed block height.
    fn committed_height(&self) -> BlockHeight;

    /// Get the latest committed block hash.
    fn committed_hash(&self) -> Option<BlockHash>;

    /// Get the latest quorum certificate.
    fn latest_qc(&self) -> Option<QuorumCertificate>;

    /// Get a complete block for serving sync requests.
    ///
    /// Returns `Some(BlockForSync)` only if the full block is available
    /// with all transactions and certificates. Returns `None` if any
    /// data is missing.
    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync>;

    /// Get multiple transactions by hash (batch read).
    ///
    /// Returns only transactions that were found (missing hashes are skipped).
    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction>;

    /// Get multiple certificates by hash (batch read).
    ///
    /// Returns only certificates that were found (missing hashes are skipped).
    fn get_certificates_batch(&self, hashes: &[WaveIdHash]) -> Vec<WaveCertificate>;

    // ─── Receipt Storage ──────────────────────────────────────────────────

    /// Retrieve the local receipt for a transaction.
    fn get_local_receipt(&self, tx_hash: &TxHash) -> Option<Arc<LocalReceipt>>;

    // ─── Execution Certificate Reads ────────────────────────────────────

    /// Retrieve all execution certificates for a given block height.
    fn get_execution_certificates_by_height(
        &self,
        block_height: BlockHeight,
    ) -> Vec<ExecutionCertificate>;

    // ─── Wave Certificate Indexes ─────────────────────────────────────────

    /// Get the wave certificate that finalized a given transaction.
    ///
    /// Returns `None` if no wave cert has been recorded for this tx.
    fn get_wave_certificate_for_tx(&self, tx_hash: &TxHash) -> Option<WaveCertificate>;

    /// Get the execution certificate hashes associated with a transaction.
    ///
    /// Returns the `(ShardGroupId, ec_hash)` pairs from every shard that
    /// produced an EC covering this transaction. Returns `None` if no
    /// index entry exists for this tx.
    fn get_ec_hashes_for_tx(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Vec<(ShardGroupId, ExecutionCertificateHash)>>;
}
