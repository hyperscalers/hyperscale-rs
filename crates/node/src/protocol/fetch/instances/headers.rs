//! Header fetch instance binding.
//!
//! Wires `ScopeFetch<(ShardGroupId, BlockHeight)>` to the cross-shard
//! committed-block-header request/response. The instance module owns the
//! payload-specific knowledge: scope-to-wire-request translation, stale
//! predicate, admission triggers.

use crate::protocol::fetch::ScopeFetch;
use crate::state::NodeStateMachine;
use hyperscale_types::{BlockHeight, ShardGroupId};

/// Composite scope key for cross-shard header fetches.
pub type Scope = (ShardGroupId, BlockHeight);

/// The typed fetch protocol instance for cross-shard headers.
pub type HeaderFetch = ScopeFetch<Scope>;

/// Returns `true` when a previously requested header has already become
/// available via any path — gossip, fetch, or otherwise — and should be
/// dropped from the in-flight set on the next tick.
#[must_use]
pub fn is_stale(state: &NodeStateMachine, scope: &Scope) -> bool {
    let (shard, height) = *scope;
    state.remote_headers().has_verified(shard, height)
}

/// Build the scope key for a verified header.
#[must_use]
pub const fn scope_for(shard: ShardGroupId, height: BlockHeight) -> Scope {
    (shard, height)
}
