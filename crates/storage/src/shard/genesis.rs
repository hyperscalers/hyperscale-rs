//! Genesis install primitive.

use std::collections::HashMap;

use hyperscale_types::{NodeId, StateRoot};
use radix_substate_store_interface::interface::DatabaseUpdates;

/// Storage backends that can install a genesis snapshot in one shot.
///
/// Genesis bootstrap accumulates substate writes without recomputing the JMT
/// per commit, then computes the JMT once at version 0 from the merged
/// updates. Backends compose those two steps internally; the trait obligation
/// is the single composite operation callers actually want.
pub trait GenesisCommit {
    /// Install a fully-prepared genesis snapshot: write `substates`, then
    /// compute the JMT root at version 0 from `jmt_updates`. Returns the
    /// genesis state root.
    ///
    /// `substates` is the full genesis state, written to the substate store
    /// for read availability on every shard. `jmt_updates` is the
    /// shard-filtered subset (nodes routing to this shard) that builds the
    /// prefix-rooted JMT, so the committed `state_root` is exactly the global
    /// tree's subtree at the shard prefix. For a single-shard (empty-prefix)
    /// store the two are identical.
    ///
    /// `owner_map` owner-prefixes internal nodes (vaults, KV stores) under
    /// their owning global ancestor so each lands in its owner's prefix
    /// subtree.
    #[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
    fn install_genesis(
        &self,
        substates: &DatabaseUpdates,
        jmt_updates: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot;

    /// Write `substates` to the substate store without touching the JMT.
    ///
    /// The read-availability half of [`install_genesis`](Self::install_genesis):
    /// a store created after network genesis (a mobility joiner, a split
    /// observer) replicates the engine bootstrap through this before its
    /// authenticated span imports, so engine-implicit reads (system
    /// packages, the intent-hash tracker) resolve on every store. Must run
    /// on a store with no substates yet — the imports that follow overwrite
    /// the replicated values for keys inside the store's prefix, never the
    /// other way around.
    fn replicate_genesis_substates(&self, substates: &DatabaseUpdates);
}
