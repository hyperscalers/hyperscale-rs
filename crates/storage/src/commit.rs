//! Commit storage trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns an opaque `PreparedCommit` handle that
//! carries precomputed work; `commit_prepared_block` applies it efficiently.

use hyperscale_types::{
    BlockHeight, ConcreteConfig, Hash, QuorumCertificate, TransactionCertificate, TypeConfig,
};
use std::sync::Arc;

/// Consensus metadata to be committed atomically with JMT + substate writes.
///
/// When provided, the storage backend folds this into the same atomic write
/// as the JMT and substate data, preventing crash-recovery inconsistencies
/// where JMT advances to height H but consensus metadata is still at H-1.
pub struct ConsensusCommitData {
    /// The committed block height.
    pub height: BlockHeight,
    /// The committed block hash.
    pub hash: Hash,
    /// The quorum certificate for this block.
    pub qc: QuorumCertificate,
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
pub trait CommitStore<C: TypeConfig = ConcreteConfig>: Send + Sync {
    /// Opaque handle carrying precomputed commit work.
    ///
    /// For RocksDB this contains a `WriteBatch` + `JmtSnapshot`.
    /// For SimStorage this contains a `JmtSnapshot` + pre-applied state.
    type PreparedCommit: Send + 'static;

    /// Compute speculative state root and return precomputed commit work.
    ///
    /// Receives pre-merged `DatabaseUpdates` (already filtered to local shard)
    /// and computes the speculative JMT root. The caller is responsible for
    /// sourcing the writes (from execution cache or receipt storage) and merging.
    ///
    /// `block_height` is the height of the block being prepared (used as JMT version).
    ///
    /// Returns `(computed_state_root, prepared_commit_handle)`.
    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        merged_updates: &C::StateUpdate,
        block_height: u64,
    ) -> (Hash, Self::PreparedCommit);

    /// Commit a block using precomputed work from `prepare_block_commit`.
    ///
    /// This is the fast path: applies the cached `WriteBatch`/`JmtSnapshot`
    /// directly. Falls back to per-certificate recompute if the prepared
    /// data is stale (base root/version mismatch).
    ///
    /// `certificates` are stored to the certificate column family for querying.
    ///
    /// When `consensus` is provided, the consensus metadata is written
    /// atomically in the same batch as the JMT + substate data.
    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        certificates: &[Arc<TransactionCertificate>],
        consensus: Option<ConsensusCommitData>,
    ) -> Hash;

    /// Commit a block's state writes from scratch (no prepared handle).
    ///
    /// Used when no `PreparedCommit` is available (e.g., sync blocks,
    /// cache eviction, or proposer fast-path not applicable).
    ///
    /// `block_height` is the height of the block being committed (used as JMT version).
    ///
    /// When `consensus` is provided, the consensus metadata is written
    /// atomically in the same batch as the JMT + substate data.
    fn commit_block(
        &self,
        merged_updates: &C::StateUpdate,
        certificates: &[Arc<TransactionCertificate>],
        block_height: u64,
        consensus: Option<ConsensusCommitData>,
    ) -> Hash;
}
