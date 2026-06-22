//! Periodic node-status snapshot for external APIs.
//!
//! [`NodeHost::status_snapshot`] is consumed by the production runner's RPC
//! layer to surface health/liveness over a status endpoint. Cheap to call
//! — pure reads from the state machine.
//!
//! The snapshot is shaped by the three-layer architecture: per-shard
//! readouts (`ShardStatus`) and per-vnode readouts (`VnodeStatus`) sit
//! in their own maps, so callers that care about a specific shard or
//! validator don't have to thread a "primary" choice through the API.

use std::collections::{BTreeMap, HashMap};

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    BlockHeight, InFlightCount, MAX_TX_IN_FLIGHT, ShardId, StateRoot, ValidatorId,
};

use crate::host::NodeHost;
use crate::sync::block::BlockSyncStatus;

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
    pub shard: ShardId,
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
    pub remote_shard_in_flight: HashMap<ShardId, InFlightCount>,
    /// Threshold for rejecting transactions due to remote shard
    /// congestion (80% of [`MAX_TX_IN_FLIGHT`]).
    pub remote_congestion_threshold: InFlightCount,
}

/// Composite node-status snapshot.
///
/// Mirrors the three-layer architecture: per-shard surface in `shards`,
/// per-vnode surface in `vnodes`. Process-level readouts (libp2p peers,
/// channel depths, pool queues) are collected by the runner directly.
///
/// Flat-shape RPC consumers pick a representative entry via [`Self::primary`].
#[derive(Debug, Clone)]
pub struct NodeStatusSnapshot {
    /// Per-hosted-shard readouts.
    pub shards: BTreeMap<ShardId, ShardStatus>,
    /// Per-hosted-vnode readouts.
    pub vnodes: BTreeMap<ValidatorId, VnodeStatus>,
}

impl NodeStatusSnapshot {
    /// Pick a single `(ShardStatus, VnodeStatus)` pair to surface to
    /// flat-shape RPC clients. Returns `None` if the host has no shards
    /// or no vnodes (shouldn't happen for a running `NodeHost`).
    ///
    /// Selection is the lowest hosted shard id and validator id —
    /// deterministic regardless of registration order.
    #[must_use]
    pub fn primary(&self) -> Option<(&ShardStatus, &VnodeStatus)> {
        let shard = self.shards.values().next()?;
        let vnode = self.vnodes.values().next()?;
        Some((shard, vnode))
    }
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Capture a snapshot of node state for external status APIs.
    #[must_use]
    pub fn status_snapshot(&self) -> NodeStatusSnapshot {
        // u64-counter → usize and 80% threshold → u32 are status-readout casts
        // bounded by configured pool sizes; saturating coercions are fine.
        #[allow(clippy::cast_possible_truncation)]
        let remote_congestion_threshold = InFlightCount::new((MAX_TX_IN_FLIGHT * 4 / 5) as u32);

        let mut shards = BTreeMap::new();
        let mut vnodes = BTreeMap::new();

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
                let mempool = state.mempool_coordinator();
                let contention = mempool.lock_contention_stats();
                #[allow(clippy::cast_possible_truncation)]
                let (pending, in_flight) = (
                    contention.pending_count as usize,
                    contention.in_flight_count as usize,
                );
                vnodes.insert(
                    vnode.validator_id,
                    VnodeStatus {
                        shard,
                        committed_height: state.shard_coordinator().committed_height(),
                        view: state.shard_coordinator().view().inner(),
                        state_root: state.last_committed_jmt_root(),
                        mempool_pending: pending,
                        mempool_in_flight: in_flight,
                        mempool_total: mempool.len(),
                        accepting_rpc_transactions: !mempool.at_in_flight_limit(),
                        at_pending_limit: mempool.at_pending_limit(),
                        remote_shard_in_flight: state
                            .remote_headers_coordinator()
                            .remote_shard_in_flight(),
                        remote_congestion_threshold,
                    },
                );
            }
        }

        NodeStatusSnapshot { shards, vnodes }
    }
}
