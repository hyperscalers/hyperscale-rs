//! Split-child store adoption — the simulation mirror of the `RocksDB`
//! backend's checkpoint hard-link and subtree adoption.
//!
//! [`SimShardStorage::clone_for_split_child`] is the checkpoint: a deep
//! copy of the parent's substate and tree state re-rooted at the child's
//! prefix, with fresh consensus state (the parent's blocks stay with the
//! parent). [`SimShardStorage::adopt_split_child`] then re-points the
//! store at the adopted subtree, covering both pre-staffed shapes: the
//! parent-half clone (the child root hangs off the parent root's
//! child-side slot) and an observer's synced store (its own metadata
//! already names the child root, at the anchor it synced at).

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

    /// Re-point this child-prefix-rooted store at its adopted subtree:
    /// locate the child root node (directly at the store's metadata for
    /// an observer's synced store, via the parent root's child-side slot
    /// for a parent-half clone), copy it to the genesis version, seed
    /// the substate count by walking the subtree, and record the chain
    /// origin for recovery.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for an empty
    /// side. The caller asserts it against the beacon-verified child
    /// anchor; unlike the production backend there is no checkpoint
    /// vintage check, since the simulation harness supplies the stores.
    ///
    /// # Errors
    ///
    /// Fails when the store's root path is the trie root, or when
    /// neither adoption shape resolves a child root node.
    pub fn adopt_split_child(&self, origin: ChainOrigin) -> Result<StateRoot, String> {
        let mut shared = write_or_recover(&self.state);
        let genesis_version = origin.genesis_height.inner();
        let child_path = shared.tree_store.root_path();
        if child_path.is_empty() {
            return Err("split adoption requires a non-root child prefix".to_string());
        }

        let current_version = shared.current_block_height.inner();
        let own_root_key = NodeKey::new(current_version, child_path.clone());
        let (child_node, child_root) = if let Some(node) = shared.tree_store.get_node(&own_root_key)
        {
            // Observer shape: the synced store's metadata names the
            // child root directly.
            (Some(node), shared.current_root_hash)
        } else {
            // Parent-half clone: the metadata is the parent's; the
            // child root hangs off the parent root's child-side slot.
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
            match &parent_root.children[side] {
                None => (None, StateRoot::ZERO),
                Some(slot) => {
                    let node = shared
                        .tree_store
                        .get_node(&NodeKey::new(slot.version, child_path.clone()))
                        .ok_or("clone carries no child subtree root node")?;
                    (
                        Some(node),
                        StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash)),
                    )
                }
            }
        };

        let genesis_root_key = NodeKey::new(genesis_version, child_path);
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
        drop(shared);
        write_or_recover(&self.consensus).chain_origin = origin;
        Ok(child_root)
    }
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
