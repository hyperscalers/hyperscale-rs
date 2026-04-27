//! Cross-shard provision fetch instance binding.
//!
//! Wires `ScopeFetch<(ShardGroupId, BlockHeight)>` to cross-shard provision
//! requests served by other shards' validators. The instance owns the
//! scope-to-wire-request translation and the stale-scope predicate.

use crate::protocol::fetch::ScopeFetch;
use crate::state::NodeStateMachine;
use hyperscale_types::{BlockHeight, ShardGroupId};

/// Scope key for cross-shard provision fetches: source shard + block height.
pub type Scope = (ShardGroupId, BlockHeight);

/// The typed fetch protocol instance for cross-shard provisions.
pub type ProvisionFetch = ScopeFetch<Scope>;

/// Stale-scope predicate. Conservative for now: rely on `Admitted` to drop
/// completed entries and the retry budget to drop unanswerable ones. A
/// more aggressive predicate could consult `ProvisionCoordinator`'s
/// expected-tracking once that exposes a public accessor.
#[must_use]
pub const fn is_stale(_state: &NodeStateMachine, _scope: &Scope) -> bool {
    false
}

/// Build the scope key for a `(source_shard, block_height)` pair.
#[must_use]
pub const fn scope_for(source_shard: ShardGroupId, block_height: BlockHeight) -> Scope {
    (source_shard, block_height)
}
