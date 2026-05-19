//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_bft`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate. Outcomes
//! flow back via the `notify` and `commit_prepared` callbacks.

use std::sync::Arc;

use hyperscale_engine::{ProcessExecutionCache, RadixExecutor};
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, ConsensusReceipt, TopologySnapshot,
};

use crate::ProtocolEvent;

/// Context for executing delegated actions.
///
/// Handlers anchor their own read view on the chain via
/// `ctx.pending_chain.view_at(block_hash)` — the field naming the relevant
/// block lives on the `Action` variant itself, so the dispatcher doesn't
/// need to know which actions read state at which anchor.
#[allow(missing_docs)] // bag of references; field names match the borrowed types
pub struct ActionContext<'a, S: Storage, N: Network> {
    pub executor: &'a RadixExecutor,
    pub topology_snapshot: &'a TopologySnapshot,
    /// Chain-state lookup. Handlers that read state call
    /// `pending_chain.view_at(block_hash)` to build an anchored view.
    pub pending_chain: &'a Arc<PendingChain<S>>,
    /// Process-scope cache of shard-invariant execution outputs.
    /// Execute handlers consult this before dispatching to `executor`;
    /// hits skip the Radix VM call and only run the per-shard
    /// projection step.
    pub execution_cache: &'a Arc<ProcessExecutionCache>,
    /// Network handle for broadcast/notify/request actions. The local
    /// validator's identity and shard are read from `topology` (see
    /// [`TopologySnapshot::local_validator_id`] / [`TopologySnapshot::local_shard`]).
    pub network: &'a Arc<N>,
    /// Local validator's BLS signing key. Used by handlers that sign
    /// votes/headers before broadcast.
    pub signing_key: &'a Arc<Bls12381G1PrivateKey>,
    /// Send a [`ProtocolEvent`] back to the state machine. The single
    /// sink for delegated-action outcomes — the dispatch wrapper at
    /// the I/O loop boundary stamps the emitting vnode's shard and
    /// re-enters the next `step()`.
    pub notify: &'a (dyn Fn(ProtocolEvent) + Send + Sync),
    /// Hand a freshly prepared block to the `io_loop` for insertion into
    /// `PendingChain` + `prepared_commits`. Only `BuildProposal` and
    /// `VerifyStateRoot` produce these.
    pub commit_prepared: &'a (dyn Fn(PreparedBlock<S::PreparedCommit>) + Send + Sync),
}

impl<S: Storage, N: Network> ActionContext<'_, S, N> {
    /// Invoke `notify`; common spelling at action-handler call sites.
    pub fn notify_protocol(&self, event: ProtocolEvent) {
        (self.notify)(event);
    }
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
#[allow(missing_docs)] // flat bundle threaded straight to the chain insert site
pub struct PreparedBlock<P: Send> {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub prepared: P,
    pub receipts: Vec<Arc<ConsensusReceipt>>,
}
