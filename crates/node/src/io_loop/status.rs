//! Periodic node-status snapshot for external APIs.
//!
//! [`IoLoop::status_snapshot`] is consumed by the production runner's RPC
//! layer to surface health/liveness over a status endpoint. Cheap to call
//! — pure reads from the state machine.
//!
//! The snapshot is shaped by the three-layer architecture: per-shard
//! readouts (`ShardStatus`) and per-vnode readouts (`VnodeStatus`) sit
//! in their own maps, so callers that care about a specific shard or
//! validator don't have to thread a "primary" choice through the API.

use std::collections::HashMap;

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{
    BlockHeight, InFlightCount, MAX_TX_IN_FLIGHT, ShardGroupId, StateRoot, ValidatorId,
};

use crate::io_loop::IoLoop;
use crate::shard::sync::block::BlockSyncStatus;

/// Per-shard status readout.
#[derive(Debug, Clone)]
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct ShardStatus {
    pub block_sync: BlockSyncStatus,
}

/// Per-vnode status readout.
///
/// All fields read from one vnode's [`crate::NodeStateMachine`] — consensus
/// view, committed height, state root, mempool counts, and the
/// remote-shard in-flight tracker.
#[derive(Debug, Clone)]
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct VnodeStatus {
    pub committed_height: BlockHeight,
    pub view: u64,
    pub state_root: StateRoot,
    pub mempool_pending: usize,
    /// Block committed, holding state locks until the wave certificate
    /// commits in a later block.
    pub mempool_in_flight: usize,
    pub mempool_total: usize,
    pub accepting_rpc_transactions: bool,
    pub at_pending_limit: bool,
    /// Per-remote-shard in-flight counts from latest verified headers.
    pub remote_shard_in_flight: HashMap<ShardGroupId, InFlightCount>,
    /// Threshold for rejecting transactions due to remote shard
    /// congestion (80% of [`MAX_TX_IN_FLIGHT`]).
    pub remote_congestion_threshold: InFlightCount,
}

/// Composite node-status snapshot.
///
/// Mirrors the three-layer architecture: per-shard surface in `shards`,
/// per-vnode surface in `vnodes`. Process-level readouts (libp2p peers,
/// channel depths, pool queues) are not currently included — those are
/// collected by the runner directly.
///
/// External RPC consumers that today expose a single status per node
/// (the bulk of them) pick a representative entry via [`Self::primary`].
#[derive(Debug, Clone)]
pub struct NodeStatusSnapshot {
    /// Per-hosted-shard readouts.
    pub shards: HashMap<ShardGroupId, ShardStatus>,
    /// Per-hosted-vnode readouts.
    pub vnodes: HashMap<ValidatorId, VnodeStatus>,
}

impl NodeStatusSnapshot {
    /// Pick a single `(ShardStatus, VnodeStatus)` pair to surface to
    /// flat-shape RPC clients. Returns `None` if the host has no shards
    /// or no vnodes (shouldn't happen for a running `IoLoop`).
    ///
    /// Selection is "first hosted shard, first vnode in that shard" —
    /// stable across calls because the underlying maps are populated in
    /// the order vnodes were registered.
    #[must_use]
    pub fn primary(&self) -> Option<(&ShardStatus, &VnodeStatus)> {
        // HashMap iteration is unordered, but for V=1 (the common case)
        // there's only one entry so order doesn't matter. Multi-vnode
        // operator UX (Milestone 4) will expose a richer surface.
        let shard = self.shards.values().next()?;
        let vnode = self.vnodes.values().next()?;
        Some((shard, vnode))
    }
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
        // u64-counter → usize and 80% threshold → u32 are status-readout casts
        // bounded by configured pool sizes; saturating coercions are fine.
        #[allow(clippy::cast_possible_truncation)]
        let remote_congestion_threshold = InFlightCount::new((MAX_TX_IN_FLIGHT * 4 / 5) as u32);

        let mut shards = HashMap::new();
        let mut vnodes = HashMap::new();

        for shard in self.hosted_shards() {
            shards.insert(
                shard,
                ShardStatus {
                    block_sync: self.shard_io(shard).syncs.block.block_sync_status(),
                },
            );

            for vnode_idx in 0..self.vnodes_len(shard) {
                let vnode = self.vnode(shard, vnode_idx);
                let state = &vnode.state;
                let mempool = state.mempool();
                let contention = mempool.lock_contention_stats();
                #[allow(clippy::cast_possible_truncation)]
                let (pending, in_flight) = (
                    contention.pending_count as usize,
                    contention.in_flight_count as usize,
                );
                vnodes.insert(
                    vnode.validator_id,
                    VnodeStatus {
                        committed_height: state.bft().committed_height(),
                        view: state.bft().view().inner(),
                        state_root: state.last_committed_jmt_root(),
                        mempool_pending: pending,
                        mempool_in_flight: in_flight,
                        mempool_total: mempool.len(),
                        accepting_rpc_transactions: !mempool.at_in_flight_limit(),
                        at_pending_limit: mempool.at_pending_limit(),
                        remote_shard_in_flight: state.remote_headers().remote_shard_in_flight(),
                        remote_congestion_threshold,
                    },
                );
            }
        }

        NodeStatusSnapshot { shards, vnodes }
    }
}
