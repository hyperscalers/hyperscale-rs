//! Typed cancellation into the unified fetch protocols.
//!
//! Coordinators emit [`crate::Action::AbandonFetch`] wrapping one of these
//! variants when a previously-requested id is no longer wanted — the
//! consumer's expected-set has dropped it (verified, aged out past a
//! retention horizon, orphan-cleanup) and the in-flight fetch should stop.
//!
//! Symmetric to [`crate::FetchRequest`]: one variant per binding, same
//! keying, but with no peer pool — cancellation has no destination.
//! `io_loop`'s dispatcher matches the inner enum and feeds the ids through
//! `FetchInput::Drop` on the corresponding binding.

use hyperscale_types::{BlockHeight, ShardGroupId, TxHash};

/// Fetch-cancel family — one variant per payload type. Variants are added
/// when each binding migrates to push-cancel.
#[derive(Debug, Clone)]
pub enum FetchAbandon {
    /// Per-tx fetch keyed by [`TxHash`]. Emitted by the mempool when an
    /// expected cross-shard tx is dropped from `ExpectedTxs` without ever
    /// being admitted — block-include race (tx landed via committed block
    /// while the fetch was still in flight) or retention-horizon orphan
    /// cleanup (cross-shard DA failed entirely).
    Transactions {
        /// Tx hashes whose in-flight fetch should be cancelled.
        ids: Vec<TxHash>,
    },
    /// Cross-shard provisions fetch keyed by `(source_shard, block_height)`.
    /// Emitted when [`provisions::ProvisionCoordinator`]'s expected-set drops
    /// the key — verification succeeded, the entry orphaned past retention,
    /// or the source block aged past its deadline.
    RemoteProvisions {
        /// Source shard whose provisions fetch is being cancelled.
        source_shard: ShardGroupId,
        /// Source-shard block height for the cancelled fetch.
        block_height: BlockHeight,
    },
}
