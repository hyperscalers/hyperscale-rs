//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_bft`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate. Outcomes
//! flow back via the `notify` and `commit_prepared` callbacks.

use crate::NodeInput;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, LocalReceipt, TopologySnapshot,
};
use std::sync::Arc;

/// Context for executing delegated actions.
///
/// Handlers anchor their own read view on the chain via
/// `ctx.pending_chain.view_at(block_hash)` — the field naming the relevant
/// block lives on the `Action` variant itself, so the dispatcher doesn't
/// need to know which actions read state at which anchor.
#[allow(missing_docs)] // bag of references; field names match the borrowed types
pub struct ActionContext<'a, S: Storage, E: Engine, N: Network> {
    pub executor: &'a E,
    pub topology: &'a TopologySnapshot,
    /// Chain-state lookup. Handlers that read state call
    /// `pending_chain.view_at(block_hash)` to build an anchored view.
    pub pending_chain: &'a Arc<PendingChain<S>>,
    /// Network handle for broadcast/notify/request actions. The local
    /// validator's identity and shard are read from `topology` (see
    /// [`TopologySnapshot::local_validator_id`] / [`local_shard`]).
    pub network: &'a Arc<N>,
    /// Local validator's BLS signing key. Used by handlers that sign
    /// votes/headers before broadcast.
    pub signing_key: &'a Arc<Bls12381G1PrivateKey>,
    /// Send a `NodeInput` (typically a `ProtocolEvent`) back to the state
    /// machine. The single sink for delegated-action outcomes.
    pub notify: &'a (dyn Fn(NodeInput) + Send + Sync),
    /// Hand a freshly prepared block to the `io_loop` for insertion into
    /// `PendingChain` + `prepared_commits`. Only `BuildProposal` and
    /// `VerifyStateRoot` produce these.
    pub commit_prepared: &'a (dyn Fn(PreparedBlock<S::PreparedCommit>) + Send + Sync),
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
#[allow(missing_docs)] // flat bundle threaded straight to the chain insert site
pub struct PreparedBlock<P: Send> {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub prepared: P,
    pub receipts: Vec<Arc<LocalReceipt>>,
}
