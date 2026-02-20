//! Commit storage trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns an opaque `PreparedCommit` handle that
//! carries precomputed work; `commit_prepared_block` applies it efficiently.

use hyperscale_types::{Hash, ShardGroupId, SubstateWrite, TransactionCertificate};
use std::sync::Arc;

/// Result of committing a block's state writes.
#[must_use]
pub struct CommitResult {
    /// The state version after commit.
    pub state_version: u64,
    /// The state root hash after commit.
    pub state_root: Hash,
}

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
pub trait CommitStore: Send + Sync {
    /// Opaque handle carrying precomputed commit work.
    ///
    /// For RocksDB this contains a `WriteBatch` + `JmtSnapshot`.
    /// For SimStorage this contains a `JmtSnapshot` + certificate data.
    type PreparedCommit: Send + 'static;

    /// Compute speculative state root and return precomputed commit work.
    ///
    /// Extracts `writes_per_cert` from certificates' shard proofs for `local_shard`,
    /// computes the speculative JMT root, and bundles all work into a
    /// `PreparedCommit` handle for efficient commit later.
    ///
    /// Returns `(computed_state_root, prepared_commit_handle)`.
    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: ShardGroupId,
    ) -> (Hash, Self::PreparedCommit);

    /// Commit a block using precomputed work from `prepare_block_commit`.
    ///
    /// This is the fast path: applies the cached `WriteBatch`/`JmtSnapshot`
    /// directly. Falls back to per-certificate recompute if the prepared
    /// data is stale (base root/version mismatch).
    fn commit_prepared_block(&self, prepared: Self::PreparedCommit) -> CommitResult;

    /// Commit a block's state writes from scratch (no prepared handle).
    ///
    /// Used when no `PreparedCommit` is available (e.g., sync blocks,
    /// cache eviction, or proposer fast-path not applicable).
    fn commit_block(
        &self,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: ShardGroupId,
    ) -> CommitResult;

    /// Commit a single certificate's writes (individual/deferred commits).
    fn commit_certificate(&self, certificate: &TransactionCertificate, writes: &[SubstateWrite]);
}
