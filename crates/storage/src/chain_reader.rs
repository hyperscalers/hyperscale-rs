//! Chain reader trait.
//!
//! Abstracts block, certificate, vote, and metadata reads.
//! All methods take `&self` — implementations use interior mutability.

use std::sync::Arc;

use hyperscale_types::{
    Block, BlockHash, BlockHeight, CertifiedBlock, CommittedBlockHeader, ConsensusReceipt,
    ExecutionCertificate, ProvisionHash, QuorumCertificate, RoutableTransaction, TxHash,
    WaveCertificate, WaveId,
};

/// A sync-ready block retrieved from storage.
///
/// Always carries a `Sealed` block — the persisted shape never includes
/// provisions. Sync-serving glue re-attaches provisions (promoting to
/// `Live`) when the requester is still within the cross-shard execution
/// window.
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
/// Vote persistence is not needed — in-memory tracking in shard consensus state
/// is sufficient (nodes sync past voted heights on restart).
pub trait ChainReader: Send + Sync + 'static {
    /// Get a committed block by height.
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock>;

    /// Get a committed block header (header + committing QC) by height.
    ///
    /// Lighter than [`Self::get_block`]: skips the per-tx and per-cert
    /// fan-out reads needed to rehydrate a full block. Used by the
    /// remote-header fallback serve path, which never needs the body.
    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader>;

    /// Get the highest committed block height.
    fn committed_height(&self) -> BlockHeight;

    /// Get the latest committed block hash.
    fn committed_hash(&self) -> Option<BlockHash>;

    /// Get the latest quorum certificate.
    fn latest_qc(&self) -> Option<QuorumCertificate>;

    /// Get a complete block for serving sync requests from persisted
    /// storage.
    ///
    /// Returns `Some(BlockForSync)` only if the full block is available
    /// with all transactions and certificates. Returns `None` if any
    /// data is missing — including heights that are shard-committed but
    /// not yet persisted, which on its own would cause the persistence-race
    /// livelock under cross-shard load.
    ///
    /// Network serve handlers should not call this directly. Use
    /// [`PendingChain::block_for_sync`] instead — it spans the
    /// shard-committed / JMT-persisted window before falling through to this
    /// method on the base store.
    ///
    /// [`PendingChain::block_for_sync`]: crate::PendingChain::block_for_sync
    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync>;

    /// Get multiple transactions by hash (batch read).
    ///
    /// Returns only transactions that were found (missing hashes are skipped).
    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction>;

    /// Get multiple certificates by `WaveId` (batch read).
    ///
    /// Returns only certificates that were found (missing ids are skipped).
    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate>;

    // ─── Receipt Storage ──────────────────────────────────────────────────

    /// Retrieve the consensus-bound receipt portion for a transaction.
    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>>;

    // ─── Execution Certificate Reads ────────────────────────────────────

    /// Retrieve a single execution certificate by [`WaveId`].
    fn get_execution_certificate(&self, wave_id: &WaveId) -> Option<ExecutionCertificate>;

    /// Retrieve multiple execution certificates by [`WaveId`] (batch read).
    ///
    /// Returns only certificates that were found (missing ids are skipped).
    fn get_execution_certificates_batch(&self, wave_ids: &[WaveId]) -> Vec<ExecutionCertificate>;
}
