//! Type-erased prepared-commit handle, sync hint, and beacon-witness
//! commit payload.
//!
//! Storage backends produce a [`PreparedCommit`] alongside the speculative
//! state root when preparing a block. The closure carries everything the
//! backend needs to perform the atomic write at commit time — the pre-built
//! `WriteBatch`, a clone of its `Arc<Self>`, and any stale-detect fallback
//! data. Downstream code holds the closure without a storage generic.
//!
//! Used together with [`crate::shard::state_root::StateRootContext`] to
//! drive the [`Verify`](crate::Verify) impl for [`crate::StateRoot`].

use std::sync::Arc;

use crate::{BeaconWitnessLeafCount, CertifiedBlock, ShardWitnessPayload, StateRoot, Verified};

/// Type-erased commit closure. Invoking it performs the atomic write of
/// the block, its state-root JMT, receipts, and beacon-witness leaves
/// against the backend it was produced from.
///
/// The closure receives the `Verified<CertifiedBlock>` and witness at
/// invocation because the QC is unknown at prepare time. It returns the
/// committed state root (equal to the verifier's `computed_root`).
pub type PreparedCommit = Box<
    dyn FnOnce(SyncHint, &Arc<Verified<CertifiedBlock>>, &BeaconWitnessCommit) -> StateRoot + Send,
>;

/// Sync policy for one commit invocation.
///
/// The runner batches several pending commits into one flush. Inner
/// invocations pass [`SyncHint::DeferFsync`]; the final invocation passes
/// [`SyncHint::FlushNow`] so a single WAL fsync covers the whole batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncHint {
    /// Skip fsync — a later [`SyncHint::FlushNow`] in the same batch
    /// will cover this write.
    DeferFsync,
    /// Flush the WAL now. Covers every prior [`SyncHint::DeferFsync`]
    /// write made against the same backend.
    FlushNow,
}

impl SyncHint {
    /// `true` when this hint asks the backend to flush.
    #[must_use]
    pub const fn is_flush_now(self) -> bool {
        matches!(self, Self::FlushNow)
    }
}

/// Beacon-witness data committed alongside a block. Threaded into the
/// commit closure so the appended leaves and the stamped
/// `leaf_count_at_block_end` land in the same atomic write as the
/// block.
///
/// Storage is scoped per-shard, so the shard tag is implicit in the
/// backend handle and absent from this struct.
#[derive(Debug, Clone)]
pub struct BeaconWitnessCommit {
    /// Accumulator index of the first leaf in [`Self::leaves`]. The leaf
    /// at position `i` writes to key `starting_leaf_index + i`.
    pub starting_leaf_index: BeaconWitnessLeafCount,
    /// Witness payloads appended by this block.
    pub leaves: Vec<ShardWitnessPayload>,
    /// Total accumulator leaves after this block — i.e.
    /// `starting_leaf_index + leaves.len()`. Stamped into the block's
    /// `BlockMetadata::beacon_witness_leaf_count_at_block_end` so the
    /// fetch responder can map `block_hash → (first_leaf, last_leaf)`
    /// without re-walking history.
    pub leaf_count_at_block_end: BeaconWitnessLeafCount,
}

impl BeaconWitnessCommit {
    /// Witness commit that appends nothing — produced by the sync path
    /// when witness reconstruction lives elsewhere, by tests that
    /// haven't wired the shard producer, and by genesis.
    #[must_use]
    pub const fn empty(starting_leaf_index: BeaconWitnessLeafCount) -> Self {
        Self {
            starting_leaf_index,
            leaves: Vec::new(),
            leaf_count_at_block_end: starting_leaf_index,
        }
    }
}
