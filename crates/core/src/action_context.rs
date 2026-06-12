//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_shard`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate. Outcomes
//! flow back via the `notify` and `commit_prepared` callbacks.

use std::sync::Arc;

use hyperscale_dispatch::Parallelism;
use hyperscale_engine::{ProcessExecutionCache, RadixExecutor};
use hyperscale_network::Network;
use hyperscale_storage::{JmtSnapshot, PendingChain, ShardStorage};
use hyperscale_types::{
    BeaconProposal, BlockHash, BlockHeight, Bls12381G1PrivateKey, ConsensusReceipt, Epoch,
    PreparedCommit, ShardId, TopologySnapshot, ValidatorId, Verified,
};

use crate::ProtocolEvent;

/// Context for executing delegated actions.
///
/// Handlers anchor their own read view on the chain via
/// `ctx.pending_chain.view_at(block_hash)` — the field naming the relevant
/// block lives on the `Action` variant itself, so the dispatcher doesn't
/// need to know which actions read state at which anchor.
#[allow(missing_docs)] // bag of references; field names match the borrowed types
pub struct ActionContext<'a, S: ShardStorage, N: Network> {
    pub executor: &'a RadixExecutor,
    pub topology_snapshot: &'a TopologySnapshot,
    /// Dispatching vnode's validator identity. The shard dispatch site
    /// reads this off the `Vnode` that emitted the action; handlers use
    /// it for signing, vote attribution, and self-filtering recipient
    /// lists.
    pub me: ValidatorId,
    /// Dispatching vnode's shard. Equal to the vnode's `local_shard`
    /// for shard-rooted handlers; beacon handlers ignore it.
    pub shard: ShardId,
    /// Chain-state lookup. Handlers that read state call
    /// `pending_chain.view_at(block_hash)` to build an anchored view.
    pub pending_chain: &'a Arc<PendingChain<S>>,
    /// Process-scope cache of shard-invariant execution outputs.
    /// Execute handlers consult this before dispatching to `executor`;
    /// hits skip the Radix VM call and only run the per-shard
    /// projection step.
    pub execution_cache: &'a Arc<ProcessExecutionCache>,
    /// Network handle for broadcast/notify/request actions.
    pub network: &'a Arc<N>,
    /// Local validator's BLS signing key. Used by handlers that sign
    /// votes/headers before broadcast.
    pub signing_key: &'a Arc<Bls12381G1PrivateKey>,
    /// Send a [`ProtocolEvent`] back to the state machine. The single
    /// sink for delegated-action outcomes — the dispatch wrapper at
    /// the I/O loop boundary stamps the emitting vnode's shard and
    /// re-enters the next `step()`. Owned so handlers can clone it
    /// into network-callback closures that outlive the action call.
    pub notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync>,
    /// Hand a freshly prepared block to the `io_loop` for insertion into
    /// `PendingChain` + `prepared_commits`. Only `BuildProposal` and
    /// `VerifyStateRoot` produce these.
    pub commit_prepared: &'a (dyn Fn(PreparedBlock) + Send + Sync),
    /// Hand the locally signed `BeaconProposal` to the process-level
    /// cache that serves inbound `GetBeaconProposalRequest`s. Only
    /// `BuildAndBroadcastBeaconProposal` produces these; the cache is
    /// driver-owned, so coordinators never read or reset it.
    pub cache_beacon_proposal:
        &'a (dyn Fn(ValidatorId, Epoch, Arc<Verified<BeaconProposal>>) + Send + Sync),
    /// Parallelism strategy for in-handler batch fan-out. Sourced from
    /// the dispatch backend at spawn time so handlers running on
    /// `PooledDispatch` use rayon `par_iter` (work-stealing across the
    /// current pool's workers) and handlers running on `SyncDispatch`
    /// iterate sequentially for deterministic simulation.
    pub par: Parallelism,
}

impl<S: ShardStorage, N: Network> ActionContext<'_, S, N> {
    /// Invoke `notify`; common spelling at action-handler call sites.
    pub fn notify_protocol(&self, event: ProtocolEvent) {
        (self.notify)(event);
    }
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
#[allow(missing_docs)] // flat bundle threaded straight to the chain insert site
pub struct PreparedBlock {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub prepared: PreparedCommit,
    pub jmt_snapshot: Arc<JmtSnapshot>,
    pub receipts: Vec<Arc<ConsensusReceipt>>,
}
