//! Execution-certificate fetch instance binding.
//!
//! Wires `HashSetFetch<(ShardGroupId, BlockHeight), WaveId>` to cross-shard
//! execution-cert fetches that rotate through the source committee. Stale
//! entries are evicted when the local committed height passes the source
//! block height — older waves are unrecoverable.

use crate::protocol::fetch::HashSetFetch;
use crate::state::NodeStateMachine;
use hyperscale_types::{BlockHeight, ShardGroupId, WaveId};

/// Composite scope key — source shard plus source block height.
pub type Scope = (ShardGroupId, BlockHeight);

/// The typed fetch protocol instance for execution certificates.
pub type ExecCertFetch = HashSetFetch<Scope, WaveId>;

/// A scope is stale once the local committed height has advanced past it:
/// the source block has been superseded and any cert we'd fetch can no
/// longer make a difference.
#[must_use]
pub fn is_stale(state: &NodeStateMachine, scope: &Scope) -> bool {
    let (_, height) = *scope;
    state.bft().committed_height() >= height
}

/// Build the scope key for a `(source_shard, block_height)` pair.
#[must_use]
pub const fn scope_for(source_shard: ShardGroupId, block_height: BlockHeight) -> Scope {
    (source_shard, block_height)
}
