//! Chain writer trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns an opaque `PreparedCommit` handle that
//! carries precomputed work; `commit_prepared_block` applies it efficiently.

use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHeight, FinalizedWave, QuorumCertificate, ShardGroupId,
    ShardWitnessPayload, StateRoot,
};

use crate::{BaseReadCache, JmtSnapshot};

/// Beacon-witness data committed alongside a block.
///
/// Threaded into the block-commit path so the storage backend can write
/// the appended leaves into the per-shard `beacon_witnesses` column
/// family in the **same `WriteBatch`** as the block, atomically
/// stamping `BlockMetadata::beacon_witness_leaf_count_at_block_end` so
/// post-restart recovery sees a self-consistent tip. Producer-side
/// derivation lives in the shard coordinator
/// ([`crate::beacon_witnesses::derive_leaves`](../../crates/shard/src/beacon_witnesses.rs));
/// this struct is the persistence-side carrier.
#[derive(Debug, Clone)]
pub struct BeaconWitnessCommit {
    /// Shard the leaves belong to. Used as the key prefix in the
    /// `beacon_witnesses` CF.
    pub shard: ShardGroupId,
    /// Accumulator index of the first leaf in `leaves`. The leaf at
    /// position `i` in `leaves` writes to key
    /// `(shard, starting_leaf_index + i)`.
    pub starting_leaf_index: BeaconWitnessLeafCount,
    /// Witness payloads appended by this block. Encoded by the
    /// `beacon_witnesses` CF's typed-CF accessor.
    pub leaves: Vec<ShardWitnessPayload>,
    /// Total accumulator leaves after this block — i.e.
    /// `starting_leaf_index + leaves.len()`. Stamped into the block's
    /// `BlockMetadata::beacon_witness_leaf_count_at_block_end` so the
    /// fetch responder can map `block_hash` → `(first_leaf, last_leaf)`
    /// without re-walking history.
    pub leaf_count_at_block_end: BeaconWitnessLeafCount,
}

impl BeaconWitnessCommit {
    /// Witness commit that appends nothing — produced by the sync path
    /// when witness reconstruction lives elsewhere, by tests that
    /// haven't wired the shard producer, and by genesis.
    #[must_use]
    pub const fn empty(shard: ShardGroupId, starting_leaf_index: BeaconWitnessLeafCount) -> Self {
        Self {
            shard,
            starting_leaf_index,
            leaves: Vec::new(),
            leaf_count_at_block_end: starting_leaf_index,
        }
    }
}

/// One block's worth of inputs to [`ChainWriter::commit_prepared_blocks`].
///
/// Bundles the prepared-commit handle, the block + QC, and the
/// beacon-witness leaves to fold into the same atomic write. Aliased
/// because the inline tuple type trips the `clippy::type_complexity`
/// lint when used in trait signatures.
pub type PreparedCommitBatchEntry<P> = (P, Arc<Block>, Arc<QuorumCertificate>, BeaconWitnessCommit);

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
    /// For `RocksDB` this contains a `WriteBatch` + `JmtSnapshot`.
    /// For `SimStorage` this contains a `JmtSnapshot` + pre-applied state.
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
    /// `base_reads` is an optional cache of reads observed through the
    /// originating `SubstateView` during execution. When provided, it
    /// lets the commit path skip a `multi_get_cf` on `StateCf` for keys
    /// already read — a large fraction at high TPS. Callers without a
    /// view (e.g. sync / tests) pass `None`; implementations fall back
    /// to reading `StateCf` for any key missing from the cache.
    ///
    /// Returns `(computed_state_root, prepared_commit_handle)`.
    fn prepare_block_commit(
        &self,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Self::PreparedCommit);

    /// Commit one or more blocks using precomputed work from `prepare_block_commit`.
    ///
    /// This is the fast path: applies cached `WriteBatch`/`JmtSnapshot` handles
    /// directly. When multiple blocks are provided, the implementation may
    /// batch I/O (e.g. deferring fsync until the final block) to amortize
    /// the per-block sync cost.
    ///
    /// Blocks must be in height-ascending order. Receipt writes are already
    /// included in each prepared handle — callers only need to supply data
    /// that wasn't known at prepare time (block, QC, beacon-witness leaves).
    /// Execution certificates are extracted from `block.certificates`. Each
    /// block's [`BeaconWitnessCommit`] folds into the same atomic write so
    /// the appended leaves, the stamped `leaf_count_at_block_end` on
    /// `BlockMetadata`, and the rest of the per-block data commit together
    /// or not at all.
    ///
    /// Returns the state root hash for each committed block, in the same order.
    fn commit_prepared_blocks(
        &self,
        blocks: Vec<PreparedCommitBatchEntry<Self::PreparedCommit>>,
    ) -> Vec<StateRoot>;

    /// Commit a block's state writes from scratch (no prepared handle).
    ///
    /// Extracts receipts and execution certificates from `block.certificates`,
    /// merges `DatabaseUpdates` internally. The `witness` carries the
    /// beacon-witness leaves to fold into the same atomic batch. Used when
    /// no `PreparedCommit` is available (e.g., sync blocks, cache eviction,
    /// or proposer fast-path not applicable).
    fn commit_block(
        &self,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
        witness: &BeaconWitnessCommit,
    ) -> StateRoot;

    /// Extract the JMT snapshot from a prepared commit.
    ///
    /// Used by the action handler to collect pending tree nodes from prior
    /// verifications when dispatching chained `VerifyStateRoot` actions.
    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot;

    /// Memory usage of storage caches in bytes: `(block_cache, memtable)`.
    ///
    /// Returns `(0, 0)` by default. Overridden by `RocksDB` to report actual usage.
    fn memory_usage_bytes(&self) -> (u64, u64) {
        (0, 0)
    }
}
