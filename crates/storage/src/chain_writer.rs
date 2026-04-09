//! Chain writer trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns an opaque `PreparedCommit` handle that
//! carries precomputed work; `commit_prepared_block` applies it efficiently.

use hyperscale_types::{Block, ExecutionCertificate, Hash, QuorumCertificate, ReceiptBundle};
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
/// All methods take `&self` — implementations use interior mutability.
pub trait ChainWriter: Send + Sync {
    /// Opaque handle carrying precomputed commit work.
    ///
    /// For RocksDB this contains a `WriteBatch` + `JvtSnapshot`.
    /// For SimStorage this contains a `JvtSnapshot` + pre-applied state.
    type PreparedCommit: Send + 'static;

    /// Compute speculative state root and return precomputed commit work.
    ///
    /// Extracts and merges `DatabaseUpdates` from the receipts internally,
    /// then computes the speculative JVT root.
    ///
    /// `block_height` is the height of the block being prepared (used as JVT version).
    ///
    /// Returns `(computed_state_root, prepared_commit_handle)`.
    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        receipts: &[ReceiptBundle],
        block_height: u64,
    ) -> (Hash, Self::PreparedCommit);

    /// Commit a block using precomputed work from `prepare_block_commit`.
    ///
    /// This is the fast path: applies the cached `WriteBatch`/`JvtSnapshot`
    /// directly. Falls back to recompute from the receipts baked into the
    /// prepared handle if the prepared data is stale (base root/version mismatch).
    ///
    /// Receipt writes are already included in the prepared handle — callers
    /// only need to supply data that wasn't known at prepare time (block, QC,
    /// execution certificates).
    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
        execution_certificates: &[Arc<ExecutionCertificate>],
    ) -> Hash;

    /// Commit a block's state writes from scratch (no prepared handle).
    ///
    /// Extracts and merges `DatabaseUpdates` from the receipts internally.
    /// Used when no `PreparedCommit` is available (e.g., sync blocks,
    /// cache eviction, or proposer fast-path not applicable).
    fn commit_block(
        &self,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
        execution_certificates: &[Arc<ExecutionCertificate>],
        receipts: &[ReceiptBundle],
    ) -> Hash;

    /// Memory usage of storage caches in bytes: `(block_cache, memtable)`.
    ///
    /// Returns `(0, 0)` by default. Overridden by RocksDB to report actual usage.
    fn memory_usage_bytes(&self) -> (u64, u64) {
        (0, 0)
    }

    /// Number of entries in the JVT node cache.
    ///
    /// Returns `0` by default. Overridden by implementations with a node cache.
    fn node_cache_len(&self) -> usize {
        0
    }
}
