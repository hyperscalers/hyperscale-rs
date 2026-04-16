//! Chain writer trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns an opaque `PreparedCommit` handle that
//! carries precomputed work; `commit_prepared_block` applies it efficiently.

use crate::JmtSnapshot;
use hyperscale_types::{Block, FinalizedWave, Hash, QuorumCertificate};
use std::sync::Arc;

/// Abstracts state commitment for both simulation and production storage.
///
/// The prepare/commit flow:
/// 1. `prepare_block_commit` computes the speculative state root and returns
///    an opaque `PreparedCommit` handle carrying all precomputed work.
/// 2. The runner stores the handle (keyed by block hash or however it likes).
/// 3. At commit time, `commit_prepared_block` applies the handle (fast path).
///    If no handle is available, `commit_block` recomputes from scratch.
///
/// Execution certificates are extracted from `block.certificates` (wave certs
/// contain the ECs directly) — no separate parameter needed.
///
/// All methods take `&self` — implementations use interior mutability.
pub trait ChainWriter: Send + Sync + 'static {
    /// Opaque handle carrying precomputed commit work.
    ///
    /// For RocksDB this contains a `WriteBatch` + `JmtSnapshot`.
    /// For SimStorage this contains a `JmtSnapshot` + pre-applied state.
    type PreparedCommit: Send + 'static;

    /// Compute speculative state root and return precomputed commit work.
    ///
    /// Extracts and merges `DatabaseUpdates` from each finalized wave's receipts
    /// internally, then computes the speculative JMT root.
    ///
    /// `parent_block_height` is the height of the parent block whose state we
    /// build on. Used as the JMT parent version for `put_at_version`. This
    /// must be a committed height or have its tree nodes provided via
    /// `pending_snapshots`.
    ///
    /// `block_height` is the height of the block being prepared (used as JMT
    /// new version).
    ///
    /// `pending_snapshots` contains JMT snapshots from prior verifications
    /// that haven't been committed yet. Their tree nodes are overlaid on the
    /// base store so chained verifications can find parent nodes.
    ///
    /// Returns `(computed_state_root, prepared_commit_handle)`.
    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        parent_block_height: u64,
        finalized_waves: &[Arc<FinalizedWave>],
        block_height: u64,
        pending_snapshots: &[Arc<JmtSnapshot>],
    ) -> (Hash, Self::PreparedCommit);

    /// Commit one or more blocks using precomputed work from `prepare_block_commit`.
    ///
    /// This is the fast path: applies cached `WriteBatch`/`JmtSnapshot` handles
    /// directly. When multiple blocks are provided, the implementation may
    /// batch I/O (e.g. deferring fsync until the final block) to amortize
    /// the per-block sync cost.
    ///
    /// Blocks must be in height-ascending order. Receipt writes are already
    /// included in each prepared handle — callers only need to supply data
    /// that wasn't known at prepare time (block, QC).
    /// Execution certificates are extracted from `block.certificates`.
    ///
    /// Returns the state root hash for each committed block, in the same order.
    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(Self::PreparedCommit, Arc<Block>, Arc<QuorumCertificate>)>,
    ) -> Vec<Hash>;

    /// Commit a block's state writes from scratch (no prepared handle).
    ///
    /// Extracts receipts and execution certificates from `block.certificates`,
    /// merges `DatabaseUpdates` internally. Used when no `PreparedCommit` is
    /// available (e.g., sync blocks, cache eviction, or proposer fast-path not
    /// applicable).
    fn commit_block(&self, block: &Arc<Block>, qc: &Arc<QuorumCertificate>) -> Hash;

    /// Extract the JMT snapshot from a prepared commit.
    ///
    /// Used by the action handler to collect pending tree nodes from prior
    /// verifications when dispatching chained `VerifyStateRoot` actions.
    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot;

    /// Memory usage of storage caches in bytes: `(block_cache, memtable)`.
    ///
    /// Returns `(0, 0)` by default. Overridden by RocksDB to report actual usage.
    fn memory_usage_bytes(&self) -> (u64, u64) {
        (0, 0)
    }
}
