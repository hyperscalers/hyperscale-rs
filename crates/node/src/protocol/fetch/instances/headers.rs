//! Header fetch instance binding.
//!
//! Wires `ScopeFetch<(ShardGroupId, BlockHeight)>` to the cross-shard
//! committed-block-header request/response. The instance module owns the
//! payload-specific knowledge: scope-to-wire-request translation and
//! admission triggers. No `is_abandoned` predicate needed — every path
//! that produces a verified header emits `Continuation(RemoteHeaderAdmitted)`,
//! which drains the matching scope through `apply_admission`.

use crate::protocol::fetch::{ScopeFetch, ScopeFetchInput};
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHeight, ShardGroupId};

/// Composite scope key for cross-shard header fetches.
pub type Scope = (ShardGroupId, BlockHeight);

/// The typed fetch protocol instance for cross-shard headers.
pub type HeaderFetch = ScopeFetch<Scope>;

/// Drain the matching scope on the canonical admission event.
pub fn apply_admission(fetch: &mut HeaderFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = event {
        let scope = scope_for(committed_header.shard_group_id(), committed_header.height());
        fetch.handle(ScopeFetchInput::Admitted { scope });
    }
}

/// Build the scope key for a `(source_shard, block_height)` pair.
#[must_use]
pub const fn scope_for(source_shard: ShardGroupId, block_height: BlockHeight) -> Scope {
    (source_shard, block_height)
}
