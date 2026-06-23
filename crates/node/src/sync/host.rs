//! Per-shard sync state machines.
//!
//! [`SyncHost`] holds the block-sync and remote-header-sync state
//! machines plus their glue methods (periodic ticks, admission
//! notification, status readouts) for one shard. Keeping these here,
//! rather than on [`ShardLoop`], names "what sync state machines this
//! shard drives" as one bundle and isolates sync state from
//! per-payload fetch state.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

use std::time::Instant;

use crate::config::NodeConfig;
use crate::shard::consensus::{BlockSync, BlockSyncInput, BlockSyncOutput, BlockSyncStatus};

/// Sync state machines owned by the I/O loop.
pub struct SyncHost {
    /// Block-sync state machine.
    pub block: BlockSync,
}

impl SyncHost {
    /// Build the sync host from a node config.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            block: BlockSync::new(config.block_sync.clone()),
        }
    }

    /// True if either sync FSM has heights parked behind a backoff or is
    /// actively syncing. Keeps the `FetchTick` timer alive so deferred
    /// heights eventually retry and active sync scopes keep emitting
    /// fetches even if their consumer is slow to admit.
    #[must_use]
    pub fn has_any_pending(&self) -> bool {
        self.block.has_deferred() || self.block.is_syncing()
    }

    /// Drive the block-sync FSM's periodic tick. Returns the outputs the
    /// I/O loop should dispatch (block fetches, deliveries, sync-complete).
    pub fn block_tick(&mut self, now: Instant) -> Vec<BlockSyncOutput> {
        self.block.handle(BlockSyncInput::Tick { now })
    }

    /// Snapshot the cheap status readouts. The I/O loop flattens this
    /// into the larger `MetricsSnapshot`.
    #[must_use]
    pub fn metrics(&self) -> SyncMetrics {
        SyncMetrics {
            block_sync_status: self.block.block_sync_status(),
        }
    }
}

/// Cheap aggregate of sync status readouts.
///
/// Returned by [`SyncHost::metrics`]; flattened into the broader
/// `MetricsSnapshot` by the I/O loop.
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct SyncMetrics {
    pub block_sync_status: BlockSyncStatus,
}
