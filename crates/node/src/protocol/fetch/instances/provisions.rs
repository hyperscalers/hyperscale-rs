//! Cross-shard provision fetch instance binding.
//!
//! Wires `ScopeFetch<(ShardGroupId, BlockHeight)>` to cross-shard provision
//! requests served by other shards' validators. The instance owns the
//! scope-to-wire-request translation and the stale-scope predicate.

use crate::protocol::fetch::{ScopeFetch, ScopeFetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHeight, ShardGroupId};

/// Scope key for cross-shard provision fetches: source shard + block height.
pub type Scope = (ShardGroupId, BlockHeight);

/// The typed fetch protocol instance for cross-shard provisions.
pub type ProvisionFetch = ScopeFetch<Scope>;

/// A scope is stale once `ProvisionCoordinator` no longer expects provisions
/// for it: the verified remote header that registered the expectation has
/// either been satisfied (provisions verified) or pruned.
#[must_use]
pub fn is_stale(state: &NodeStateMachine, scope: &Scope) -> bool {
    let (shard, height) = *scope;
    !state.provisions().is_expected(shard, height)
}

/// Drain the matching scope on the canonical admission event.
pub fn apply_admission(fetch: &mut ProvisionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ProvisionsVerified { provisions, .. } = event {
        let scope = scope_for(provisions.source_shard, provisions.block_height);
        fetch.handle(ScopeFetchInput::Admitted { scope });
    }
}

/// Build the scope key for a `(source_shard, block_height)` pair.
#[must_use]
pub const fn scope_for(source_shard: ShardGroupId, block_height: BlockHeight) -> Scope {
    (source_shard, block_height)
}
