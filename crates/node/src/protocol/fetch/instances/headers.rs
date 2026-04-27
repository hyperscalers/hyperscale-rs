//! Header fetch instance binding.
//!
//! Wires `ScopeFetch<(ShardGroupId, BlockHeight)>` to the cross-shard
//! committed-block-header request/response. The instance module owns the
//! payload-specific knowledge: scope-to-wire-request translation, stale
//! predicate, admission triggers.

use crate::protocol::fetch::{ScopeFetch, ScopeFetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
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

/// Drain the matching scope on the canonical admission event.
pub fn apply_admission(fetch: &mut HeaderFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::RemoteHeaderVerified { committed_header } = event {
        let scope = scope_for(committed_header.shard_group_id(), committed_header.height());
        fetch.handle(ScopeFetchInput::Admitted { scope });
    }
}

/// Build the scope key for a verified header.
#[must_use]
pub const fn scope_for(shard: ShardGroupId, height: BlockHeight) -> Scope {
    (shard, height)
}
