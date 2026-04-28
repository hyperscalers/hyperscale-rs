//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_bft`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate.

use hyperscale_engine::Engine;
use hyperscale_storage::{Storage, SubstateView};
use hyperscale_types::TopologySnapshot;
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
}
