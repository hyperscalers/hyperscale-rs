//! Chain reader trait.
//!
//! Abstracts block, certificate, vote, and metadata reads.
//! All methods take `&self` — implementations use interior mutability.

use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, BlockMetadata, CertifiedBlock,
    CertifiedBlockHeader, ConsensusReceipt, ExecutionCertificate, Finalization, FinalizationHash,
    ProvisionHash, Provisions, QuorumCertificate, ShardWitnessPayload, TickId, Transaction, TxHash,
    Verifiable, Verified,
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
/// Block and certificate writes happen atomically via `ShardChainWriter`.
/// Vote persistence is not needed — in-memory tracking in shard consensus state
/// is sufficient (nodes sync past voted heights on restart).
pub trait ShardChainReader: Send + Sync + 'static {
    /// Get a committed block by height.
    fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>>;

    /// The provision bundles the block at `height` carried.
    ///
    /// A stored block keeps only their hashes, so this is the other half
    /// of reading one back whole. Empty when the block carried none, or
    /// when the bodies have dropped below the retention floor.
    fn provisions_at(&self, height: BlockHeight) -> Vec<Arc<Verifiable<Provisions>>>;

    /// Get a committed block header (header + committing QC) by height.
    ///
    /// Lighter than [`Self::get_block`]: skips the per-tx and per-cert
    /// fan-out reads needed to rehydrate a full block. Used by the
    /// remote-header fallback serve path, which never needs the body.
    fn get_certified_header(&self, height: BlockHeight) -> Option<Verified<CertifiedBlockHeader>>;

    /// Get the block's stored metadata row by height: its header, its
    /// manifest, and the QC that committed it.
    ///
    /// The whole row is one read. What the attested window folds need of
    /// a block is all inside it — the parent-QC anchor their floors test,
    /// and the manifest's transaction hashes the committed set folds — so
    /// they read this rather than [`Self::get_block_for_sync`], which
    /// multi-gets every body, every certificate and a receipt per
    /// settling outcome to rehydrate what the folds then discard. That
    /// rehydration is also all-or-nothing, so one absent receipt used to
    /// read as an absent block.
    fn get_block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata>;

    /// Get the highest committed block height.
    fn committed_height(&self) -> BlockHeight;

    /// Get the latest committed block hash.
    fn committed_hash(&self) -> Option<BlockHash>;

    /// Get the latest quorum certificate.
    fn latest_qc(&self) -> Option<Verified<QuorumCertificate>>;

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
    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<Transaction>>;

    /// Get multiple certificates by `TickId` (batch read).
    ///
    /// Returns only certificates that were found (missing ids are skipped).
    fn get_certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization>;

    /// Retrieve the consensus-bound receipt portion for a transaction.
    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>>;

    /// Retrieve a single execution certificate by [`TickId`].
    fn get_execution_certificate(&self, tick_id: &TickId)
    -> Option<Verified<ExecutionCertificate>>;

    /// Retrieve multiple execution certificates by [`TickId`] (batch read).
    ///
    /// Returns only certificates that were found (missing ids are skipped).
    fn get_execution_certificates_batch(
        &self,
        tick_ids: &[TickId],
    ) -> Vec<Verified<ExecutionCertificate>>;

    /// Retrieve the execution certificates carrying outcomes for
    /// `tx_hashes`, deduplicated — one certificate covers every
    /// transaction of its batch, so several requested transactions
    /// commonly resolve to the same certificate.
    ///
    /// This is the key a counterpart shard asks by: it knows the
    /// transaction from our committed header and cannot know which
    /// certificate we put it in. Transactions with no attested outcome
    /// here are skipped.
    fn get_execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>>;

    /// Read retained beacon-witness payloads in leaf-index order, up to
    /// (but not including) `end`. Storage is scoped per-shard, so the
    /// shard tag is implicit in the storage handle.
    ///
    /// Reconstructs the per-block accumulator at the requested anchor;
    /// an empty result signals that the anchor's leaves have all been
    /// pruned past the retention horizon.
    fn get_beacon_witness_payloads(&self, end: BeaconWitnessLeafCount) -> Vec<ShardWitnessPayload>;

    /// Read retained beacon-witness payloads with leaf indices in
    /// `[start, end)`, in ascending index order. Pruned indices are
    /// absent from the result, so a result shorter than the requested
    /// span signals the range overlaps pruned history. Bounded reads
    /// keep page serving from materializing the whole accumulator.
    fn get_beacon_witness_payload_range(&self, start: u64, end: u64) -> Vec<ShardWitnessPayload>;
}

/// Whether a store whose tree has already reached `height` holds
/// *this* block there.
///
/// A prepared commit that finds the tree at or past its own height has
/// one benign cause: the block went in already, through a sync commit
/// that landed between prepare and flush or through a second vnode on
/// the same store. Skipping it is right, and the caller returns the root
/// the snapshot computed.
///
/// A *different* block at that height is not that. Skipping it would
/// hand back a root for a block the store never applied, and the caller
/// would take the commit as done — so both backends refuse loudly
/// instead, which is the only way a fork that reached the writer is
/// visible at all.
///
/// `true` where the store holds nothing at `height`: a chain adopted
/// from a checkpoint carries a committed height above its first blocks,
/// so there is genuinely nothing to compare and nothing to conclude.
#[must_use]
pub fn holds_this_block_at<R: ShardChainReader + ?Sized>(
    reader: &R,
    height: BlockHeight,
    block_hash: BlockHash,
) -> bool {
    reader
        .get_block(height)
        .is_none_or(|held| held.block().hash() == block_hash)
}
