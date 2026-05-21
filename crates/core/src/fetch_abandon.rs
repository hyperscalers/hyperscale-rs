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
//! `FetchInput::Abandoned` on the corresponding binding.

use hyperscale_types::{BlockHeight, ProvisionHash, ShardGroupId, TxHash, WaveId};

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
    /// Emitted when `ProvisionCoordinator`'s expected-set drops the key —
    /// verification succeeded, the entry orphaned past retention, or the
    /// source block aged past its deadline.
    RemoteProvisions {
        /// Source shard whose provisions fetch is being cancelled.
        source_shard: ShardGroupId,
        /// Source-shard block height for the cancelled fetch.
        block_height: BlockHeight,
    },
    /// Intra-shard local-provision fetch keyed by [`ProvisionHash`]. Emitted
    /// when the provisions pipeline terminally drops a buffered batch
    /// (deadline reached, post-commit tombstone hit) so the in-flight
    /// local-DA fetch — which would otherwise stay pinned on a payload
    /// that can no longer be admitted — releases its slot.
    LocalProvisions {
        /// Provision hashes whose in-flight fetch should be cancelled.
        hashes: Vec<ProvisionHash>,
    },
    /// Per-block finalized-wave fetch keyed by [`WaveId`]. Emitted by the
    /// execution coordinator when a fetched wave fails terminal admission
    /// checks (no quorum power on a contained EC, committee keys not
    /// resolvable, BLS signature invalid) so the FSM clears the in-flight
    /// slot it would otherwise pin on a wave that cannot be admitted.
    FinalizedWaves {
        /// Wave ids whose in-flight fetch should be cancelled.
        ids: Vec<WaveId>,
    },
    /// Cross-shard execution-certificate fetch keyed by [`WaveId`]. Emitted
    /// when an EC's admission path silently drops the cert (unresolvable
    /// committee keys, invalid BLS signature, sub-quorum signers). Multiple
    /// aggregations can arrive per `wave_id`; if a later valid aggregation
    /// admits successfully, the abandon is a no-op on the FSM, while the
    /// failure-only case correctly releases the slot for cleanup-timer
    /// to re-fetch.
    ExecutionCerts {
        /// Wave ids whose in-flight EC fetch should be cancelled.
        ids: Vec<WaveId>,
    },
}
