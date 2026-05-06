//! Periodic node-status snapshot for external APIs.
//!
//! [`IoLoop::status_snapshot`] is consumed by the production runner's RPC
//! layer to surface health/liveness over a status endpoint. Cheap to call
//! — pure reads from the state machine.

use std::collections::HashMap;

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHeight, MAX_TX_IN_FLIGHT, ShardGroupId, StateRoot};

use crate::io_loop::IoLoop;
use crate::io_loop::sync::block::BlockSyncStatus;

/// Snapshot of node state for external status APIs.
///
/// Produced by [`IoLoop::status_snapshot`] on the periodic metrics tick.
/// The production runner maps this into its RPC shared state types.
#[derive(Debug, Clone)]
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct NodeStatusSnapshot {
    pub committed_height: BlockHeight,
    pub view: u64,
    pub state_root: StateRoot,
    pub block_sync: BlockSyncStatus,
    pub mempool_pending: usize,
    /// Block committed, holding state locks until the wave certificate
    /// commits in a later block.
    pub mempool_in_flight: usize,
    pub mempool_total: usize,
    pub accepting_rpc_transactions: bool,
    pub at_pending_limit: bool,
    /// Per-remote-shard in-flight counts from latest verified headers.
    pub remote_shard_in_flight: HashMap<ShardGroupId, u32>,
    /// Threshold for rejecting transactions due to remote shard congestion (80% of [`MAX_TX_IN_FLIGHT`]).
    pub remote_congestion_threshold: u32,
}

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Capture a snapshot of node state for external status APIs.
    #[must_use]
    pub fn status_snapshot(&self) -> NodeStatusSnapshot {
        let state_root = self.state.last_committed_jmt_root();
        let mempool = self.state.mempool();
        let contention = mempool.lock_contention_stats();

        // u64-counter → usize and 80% threshold → u32 are status-readout casts
        // bounded by configured pool sizes; saturating coercions are fine.
        #[allow(clippy::cast_possible_truncation)]
        let remote_congestion_threshold = (MAX_TX_IN_FLIGHT * 4 / 5) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let (pending, in_flight) = (
            contention.pending_count as usize,
            contention.in_flight_count as usize,
        );

        NodeStatusSnapshot {
            committed_height: self.state.bft().committed_height(),
            view: self.state.bft().view().0,
            state_root,
            block_sync: self.syncs.block.block_sync_status(),
            mempool_pending: pending,
            mempool_in_flight: in_flight,
            mempool_total: mempool.len(),
            accepting_rpc_transactions: !mempool.at_in_flight_limit(),
            at_pending_limit: mempool.at_pending_limit(),
            remote_shard_in_flight: self.state.remote_headers().remote_shard_in_flight(),
            remote_congestion_threshold,
        }
    }
}
