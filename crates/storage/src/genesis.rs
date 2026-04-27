//! Genesis install primitive.

use hyperscale_types::StateRoot;
use radix_substate_store_interface::interface::DatabaseUpdates;

/// Storage backends that can install a genesis snapshot in one shot.
///
/// Genesis bootstrap accumulates substate writes without recomputing the JMT
/// per commit, then computes the JMT once at version 0 from the merged
/// updates. Backends compose those two steps internally; the trait obligation
/// is the single composite operation callers actually want.
pub trait GenesisCommit {
    /// Install a fully-prepared genesis snapshot: write substates, then
    /// compute the JMT root at version 0. Returns the genesis state root.
    fn install_genesis(&self, merged: &DatabaseUpdates) -> StateRoot;
}
