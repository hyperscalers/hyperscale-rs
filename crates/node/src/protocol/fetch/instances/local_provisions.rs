//! Local-provision fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, ProvisionHash>` to per-block local provision
//! fetches pinned to the proposer.

use crate::protocol::fetch::{HashSetFetch, HashSetFetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHash, ProvisionHash};

/// Composite scope key — the block whose provision set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for local provisions.
pub type LocalProvisionFetch = HashSetFetch<Scope, ProvisionHash>;

/// A scope is abandoned once BFT no longer holds a pending block for it.
#[must_use]
pub fn is_abandoned(state: &NodeStateMachine, scope: &Scope) -> bool {
    !state.bft().has_pending_block(*scope)
}

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event. Listens to `ProvisionsAdmitted` (per-provision admission) — same
/// event the cross-shard `ProvisionFetch` uses, but keyed by provision hash
/// rather than `(source_shard, block_height)` scope.
pub fn apply_admission(fetch: &mut LocalProvisionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
        fetch.handle(HashSetFetchInput::Admitted {
            ids: vec![provisions.hash()],
        });
    }
}
