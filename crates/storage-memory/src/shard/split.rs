//! Split-child store adoption — the simulation mirror of the `RocksDB`
//! backend's checkpoint hard-link and subtree adoption.
//!
//! [`SimShardStorage::clone_for_split_child`] is the checkpoint: a deep
//! copy of the parent's substate and tree state re-rooted at the child's
//! prefix, with fresh consensus state (the parent's blocks stay with the
//! parent). [`SimShardStorage::adopt_split_child`] then re-points the
//! clone at the parent root's child-side slot;
//! [`SimShardStorage::adopt_followed_child`] re-points an observer's
//! followed store at the child root its own metadata names.

use std::sync::{Arc, RwLock};

use hyperscale_jmt::{NibblePath, Node, NodeKey, TreeReader};
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::Jmt;
use hyperscale_types::{ChainOrigin, Hash, StateRoot};

use super::core::SimShardStorage;
use super::state::ConsensusState;

/// Leaves counted per tree-walk page while seeding the child's substate
/// count.
const COUNT_PAGE: usize = 1 << 16;

impl SimShardStorage {
    /// The simulation's checkpoint hard-link: a deep copy of this
    /// store's substate and tree state, re-rooted at `child_prefix`,
    /// with fresh consensus state. The sibling half rides along as dead
    /// weight outside the child's prefix, exactly as in the hard-linked
    /// production checkpoint.
    #[must_use]
    pub fn clone_for_split_child(&self, child_prefix: NibblePath) -> Self {
        let mut shared = read_or_recover(&self.state).clone();
        shared.tree_store.set_root_path(child_prefix);
        Self {
            state: Arc::new(RwLock::new(shared)),
            consensus: Arc::new(RwLock::new(ConsensusState::new())),
            jmt_history_length: self.jmt_history_length,
            boundary_pins: Arc::new(RwLock::new(std::collections::BTreeSet::new())),
        }
    }

    /// Re-point this child-prefix-rooted clone of the parent's store at
    /// its adopted subtree: the child root hangs off the parent root's
    /// child-side slot at the clone's tip version. The node is copied to
    /// the genesis version, the substate count seeded by walking the
    /// subtree, and the chain origin recorded for recovery.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for an empty
    /// side. The caller asserts it against the beacon-verified child
    /// anchor; unlike the production backend there is no checkpoint
    /// vintage check, since the simulation harness supplies the stores.
    /// An observer's followed store adopts through
    /// [`Self::adopt_followed_child`] instead — the shapes are
    /// caller-distinguished.
    ///
    /// # Errors
    ///
    /// Fails when the store's root path is the trie root, or when the
    /// clone resolves no parent root or child subtree node.
    pub fn adopt_split_child(&self, origin: ChainOrigin) -> Result<StateRoot, String> {
        let mut shared = write_or_recover(&self.state);
        let child_path = shared.tree_store.root_path();
        if child_path.is_empty() {
            return Err("split adoption requires a non-root child prefix".to_string());
        }

        // The metadata is the parent's; the child root hangs off the
        // parent root's child-side slot.
        let current_version = shared.current_block_height.inner();
        let mut parent_path = child_path.clone();
        parent_path.truncate(child_path.len() - 1);
        let side = usize::from(child_path.bits_at(child_path.len() - 1, 1));
        let parent_root = shared
            .tree_store
            .get_node(&NodeKey::new(current_version, parent_path))
            .ok_or("clone carries no parent root node")?;
        let Node::Internal(parent_root) = parent_root.as_ref() else {
            return Err(
                "parent root collapsed to a leaf; a ≤1-key parent cannot split".to_string(),
            );
        };
        let (child_node, child_root) = match &parent_root.children[side] {
            None => (None, StateRoot::ZERO),
            Some(slot) => {
                let node = shared
                    .tree_store
                    .get_node(&NodeKey::new(slot.version, child_path))
                    .ok_or("clone carries no child subtree root node")?;
                (
                    Some(node),
                    StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash)),
                )
            }
        };
        install_adoption(&mut shared, origin, child_node, child_root)?;
        drop(shared);
        write_or_recover(&self.consensus).chain_origin = origin;
        Ok(child_root)
    }

    /// Re-point an observer's followed store at its adopted subtree —
    /// the child root the store's own metadata names at its (sparse)
    /// tip version. The simulation mirror of the production backend's
    /// `adopt_followed_child`.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for a store
    /// whose span held nothing (an empty half). The caller asserts it
    /// against the beacon-verified child anchor.
    ///
    /// # Errors
    ///
    /// Fails when the store's root path is the trie root, or when its
    /// metadata names a root its tree doesn't hold.
    pub fn adopt_followed_child(&self, origin: ChainOrigin) -> Result<StateRoot, String> {
        let mut shared = write_or_recover(&self.state);
        let child_path = shared.tree_store.root_path();
        if child_path.is_empty() {
            return Err("split adoption requires a non-root child prefix".to_string());
        }

        let child_root = shared.current_root_hash;
        let child_node = if child_root == StateRoot::ZERO {
            // An empty half: the sync imported nothing and no follow
            // ever advanced the tip.
            None
        } else {
            let tip_version = shared.current_block_height.inner();
            Some(
                shared
                    .tree_store
                    .get_node(&NodeKey::new(tip_version, child_path))
                    .ok_or("followed store holds no root node at its tip version")?,
            )
        };
        install_adoption(&mut shared, origin, child_node, child_root)?;
        drop(shared);
        write_or_recover(&self.consensus).chain_origin = origin;
        Ok(child_root)
    }
}

/// Shared adoption tail: copy the child root node (when the side is
/// non-empty) to the genesis version, seed the substate count, and
/// move the tip to the genesis.
fn install_adoption(
    shared: &mut super::state::SharedState,
    origin: ChainOrigin,
    child_node: Option<Arc<Node>>,
    child_root: StateRoot,
) -> Result<(), String> {
    let genesis_version = origin.genesis_height.inner();
    let genesis_root_key = NodeKey::new(genesis_version, shared.tree_store.root_path());
    let count = match child_node {
        None => 0,
        Some(node) => {
            shared.tree_store.insert(genesis_root_key.clone(), node);
            count_subtree_leaves(&shared.tree_store, &genesis_root_key)?
        }
    };
    shared.substate_counts.insert(genesis_version, count);
    shared.current_block_height = origin.genesis_height;
    shared.current_root_hash = child_root;
    Ok(())
}

/// Count the live leaves under `root_key` by walking the tree in pages.
fn count_subtree_leaves(store: &impl TreeReader, root_key: &NodeKey) -> Result<u64, String> {
    let mut count: u64 = 0;
    let mut start = [0u8; 32];
    loop {
        let chunk = Jmt::collect_range(store, root_key, &start, &[0xFF; 32], COUNT_PAGE)
            .map_err(|e| format!("split adoption count: {e:?}"))?;
        count += chunk.leaves.len() as u64;
        let Some((last, _)) = chunk.leaves.last() else {
            break;
        };
        if !chunk.more {
            break;
        }
        start = *last;
        for byte in start.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
    Ok(count)
}
