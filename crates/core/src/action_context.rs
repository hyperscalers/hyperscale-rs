//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_bft`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate. Outcomes
//! flow back via the `notify` and `commit_prepared` callbacks.

use crate::NodeInput;
use hyperscale_engine::Engine;
use hyperscale_storage::{Storage, SubstateView};
use hyperscale_types::{BlockHash, BlockHeight, LocalReceipt, TopologySnapshot};
use std::sync::Arc;

/// Context for executing delegated actions.
#[allow(missing_docs)] // bag of references; field names match the borrowed types
pub struct ActionContext<'a, S: Storage, E: Engine> {
    pub executor: &'a E,
    pub topology: &'a TopologySnapshot,
    /// Anchored read view over base storage + the chain of unpersisted
    /// blocks back to the committed tip. Built per-dispatch by
    /// `PendingChain::view_at(parent_hash_for(action))`.
    pub view: Arc<SubstateView<S>>,
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
    pub block_height: BlockHeight,
    pub prepared: P,
    pub receipts: Vec<Arc<LocalReceipt>>,
}
