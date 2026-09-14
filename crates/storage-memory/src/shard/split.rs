//! Reshape store adoption — the simulation mirror of the `RocksDB`
//! backend's checkpoint hard-link and subtree adoption.
//!
//! [`SimShardStorage::clone_for_split_child`] is the checkpoint: a deep
//! copy of the parent's substate and tree state re-rooted at the child's
//! prefix, with fresh consensus state (the parent's blocks stay with the
//! parent). [`SimShardStorage::adopt_genesis`] then applies what
//! [`adopt_plan`] decides: a clone re-points at the parent root's
//! child-side slot, an observer's followed store at the child root its
//! own tip carries, and a keeper's merged store — already holding both
//! children's subtrees and the stitched root — only records the merged
//! genesis as the committed tip.

use std::sync::{Arc, RwLock};

use hyperscale_jmt::{NibblePath, Node, NodeKey, TreeReader};
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::Jmt;
use hyperscale_storage::{AdoptSource, Adoption, Subtree, Vintage, adopt_plan};
use hyperscale_types::{Block, CertifiedBlock, ChainOrigin, Hash, StateRoot, Verified};

use super::core::{SimImportStaging, SimShardStorage};
use super::state::{ConsensusState, SharedState};

impl SimShardStorage {
    /// The simulation's checkpoint hard-link: a deep copy of this
    /// store's substate and tree state, re-rooted at `child_prefix`,
    /// with fresh consensus state. The sibling half rides along as dead
    /// weight outside the child's prefix, exactly as in the hard-linked
    /// production checkpoint — never read owner-scoped, and dropped from
    /// the one index that enumerates the whole shard when the clone is
    /// adopted.
    #[must_use]
    pub fn clone_for_split_child(&self, child_prefix: NibblePath) -> Self {
        let mut shared = read_or_recover(&self.state).clone();
        shared.tree_store.set_root_path(child_prefix);
        Self {
            state: Arc::new(RwLock::new(shared)),
            consensus: Arc::new(RwLock::new(ConsensusState::new())),
            boundary_pins: Arc::new(RwLock::new(std::collections::BTreeSet::new())),
            import_staging: Arc::new(RwLock::new(SimImportStaging::default())),
        }
    }

    /// Install a reshape successor's derived `genesis` as this store's
    /// chain origin and committed tip: [`adopt_plan`] decided over this
    /// store's vintage, then applied — the same decision the production
    /// backend applies, so the two harnesses cannot diverge on what an
    /// adoption admits.
    ///
    /// # Errors
    ///
    /// What [`adopt_plan`] refused, or a store that cannot yield the
    /// subtree it named.
    pub fn adopt_genesis(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
        source: AdoptSource,
    ) -> Result<StateRoot, String> {
        let recorded_origin = read_or_recover(&self.consensus).chain_origin;
        let mut shared = write_or_recover(&self.state);
        let vintage = Vintage {
            version: shared.current_block_height.inner(),
            root: shared.current_root_hash,
            prefix: shared.tree_store.root_path(),
            origin: recorded_origin,
        };
        let adoption = adopt_plan(&vintage, origin, genesis, source, |version| {
            parent_subtree(&shared, version)
        })?;
        let adopted = match adoption {
            Adoption::Recorded(root) => return Ok(root),
            Adoption::InPlace(root) => root,
            Adoption::Repoint(subtree) => {
                let root = install_adoption(&mut shared, origin, subtree)?;
                shared.sweep_index.retain_under(&vintage.prefix);
                root
            }
        };
        let pair = Verified::<CertifiedBlock>::genesis_certified(genesis.clone());
        // A child's history begins here, and its genesis QC carries the
        // chain origin's anchor: dating it is what puts the floor at the
        // adoption rather than below everything the parent held.
        shared.advance_retention_floor(
            origin.genesis_height.inner(),
            pair.qc_verified().weighted_timestamp(),
        );
        drop(shared);
        self.install_genesis_tip(origin, &pair);
        Ok(adopted)
    }

    /// Record the child's deterministic genesis as the committed tip —
    /// the consensus half of an adoption: the genesis block with its
    /// deterministic certified pairing, the committed height and hash,
    /// no latest QC (the child chain holds none at its genesis), and
    /// the chain origin for recovery.
    fn install_genesis_tip(&self, origin: ChainOrigin, pair: &Verified<CertifiedBlock>) {
        let genesis = pair.block();
        let mut consensus = write_or_recover(&self.consensus);
        consensus
            .blocks
            .insert(genesis.height(), pair.as_ref().clone());
        consensus.committed_height = genesis.height();
        consensus.committed_hash = Some(genesis.hash());
        consensus.committed_qc = None;
        consensus.chain_origin = origin;
    }
}

/// The child subtree to adopt out of a parent clone: the child-side slot
/// of the parent root node at `version` — the metadata is the parent's,
/// and the child root hangs off that slot — or `None` for an empty side.
fn parent_subtree(shared: &SharedState, version: u64) -> Result<Option<Subtree>, String> {
    let child_path = shared.tree_store.root_path();
    let mut parent_path = child_path.clone();
    parent_path.truncate(child_path.len() - 1);
    let side = usize::from(child_path.bits_at(child_path.len() - 1, 1));
    let parent_root = shared
        .tree_store
        .get_node(&NodeKey::new(version, parent_path))
        .ok_or("clone carries no parent root node")?;
    let Node::Internal(parent_root) = parent_root.as_ref() else {
        return Err("parent root collapsed to a leaf; a ≤1-key parent cannot split".to_string());
    };
    Ok(parent_root.children[side].as_ref().map(|slot| Subtree {
        version: slot.version,
        root: StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash)),
    }))
}

/// Re-root the tree at the genesis version: copy the subtree's root node
/// there (when the side is non-empty), seed the substate byte total, and
/// move the tip to the genesis. Returns the adopted root.
fn install_adoption(
    shared: &mut SharedState,
    origin: ChainOrigin,
    subtree: Option<Subtree>,
) -> Result<StateRoot, String> {
    let genesis_version = origin.genesis_height.inner();
    let path = shared.tree_store.root_path();
    let genesis_root_key = NodeKey::new(genesis_version, path.clone());
    let (bytes, root) = match subtree {
        None => (0, StateRoot::ZERO),
        Some(Subtree { version, root }) => {
            let node = shared
                .tree_store
                .get_node(&NodeKey::new(version, path))
                .ok_or("store holds no root node at the source version")?;
            shared.tree_store.insert(genesis_root_key.clone(), node);
            let bytes = Jmt::sum_subtree_value_lens(&shared.tree_store, &genesis_root_key)
                .map_err(|e| format!("split adoption byte sum: {e:?}"))?;
            (bytes, root)
        }
    };
    shared.substate_bytes.insert(genesis_version, bytes);
    shared.current_block_height = origin.genesis_height;
    shared.current_root_hash = root;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, Hasher, KEY_BYTES};
    use hyperscale_storage::test_helpers::import_boundary_state;
    use hyperscale_storage::{AdoptSource, SweepIndex, WitnessSeed};
    use hyperscale_types::test_utils::{install_stub_protocol_statics, stub_sweepable_cell};
    use hyperscale_types::{
        Address, AddressClass, Block, BlockHash, BlockHeight, ChainOrigin, Hash, SWEEP_BUCKET_MS,
        ShardId, StateRoot, SubstateKey, SubstateLeaf, SweepBucket, SweepFrontier, ValidatorId,
        WeightedTimestamp,
    };

    use super::*;

    /// An import leaf whose top byte places it under one trie half.
    fn leaf(top: u8) -> SubstateLeaf {
        let mut key = [0u8; KEY_BYTES];
        key[0] = top;
        key[31] = AddressClass::Component.tag();
        SubstateLeaf {
            key: SubstateKey::from_bytes(key).expect("a stored leaf key names an address"),
            value: vec![top],
        }
    }

    /// A merged parent store: one leaf on each half so the root is the
    /// internal node `r_p`, imported at the genesis height the terminals
    /// continue (`max(9, 8) + 1 = 10`).
    fn merged_store() -> (SimShardStorage, StateRoot) {
        let store = SimShardStorage::default();
        let root = import_boundary_state(
            &store,
            BlockHeight::new(10),
            &[leaf(0x00), leaf(0x80)],
            WitnessSeed::default(),
        )
        .unwrap();
        (store, root)
    }

    fn merge_genesis(state_root: StateRoot) -> (Block, ChainOrigin) {
        let cut = WeightedTimestamp::from_millis(10_000);
        let genesis = Block::merge_parent_genesis(
            ShardId::ROOT,
            state_root,
            (
                BlockHash::from_raw(Hash::from_bytes(b"left terminal")),
                BlockHeight::new(9),
            ),
            (
                BlockHash::from_raw(Hash::from_bytes(b"right terminal")),
                BlockHeight::new(8),
            ),
            cut,
        );
        let origin = ChainOrigin {
            genesis_height: genesis.height(),
            anchor_wt: cut,
        };
        (genesis, origin)
    }

    /// Adoption records the merged genesis as the committed tip over the
    /// already-built tree: the recovered state names the genesis, its
    /// root, origin, and the imported substate byte total.
    #[test]
    fn merge_adoption_records_the_merged_genesis_tip() {
        let (store, root) = merged_store();
        assert_ne!(root, StateRoot::ZERO, "two halves compose an internal root");
        let (genesis, origin) = merge_genesis(root);
        assert_eq!(genesis.height(), BlockHeight::new(10));

        let adopted = store
            .adopt_genesis(origin, &genesis, AdoptSource::InPlace)
            .unwrap();
        assert_eq!(adopted, root);

        let recovered = store.load_recovered_state(ShardId::ROOT);
        assert_eq!(recovered.committed_height, BlockHeight::new(10));
        assert_eq!(recovered.committed_hash, Some(genesis.hash()));
        assert_eq!(recovered.jmt_root, Some(root));
        assert_eq!(recovered.chain_origin, origin);
        assert_eq!(recovered.substate_bytes, 2);
    }

    /// A genesis claiming a different root than the store holds fails
    /// closed — the keeper's tree and the beacon's composition disagree.
    #[test]
    fn merge_adoption_rejects_a_root_mismatch() {
        let (store, root) = merged_store();
        let (_, origin) = merge_genesis(root);
        let (wrong, _) = merge_genesis(StateRoot::from_raw(Hash::from_bytes(b"forged root")));
        assert!(
            store
                .adopt_genesis(origin, &wrong, AdoptSource::InPlace)
                .is_err()
        );
    }

    /// A parent store at the trie root holding two left-side leaves and
    /// one right-side leaf, committed at height 9, with its terminal root.
    fn split_parent() -> (SimShardStorage, StateRoot) {
        let store = SimShardStorage::default();
        let root = import_boundary_state(
            &store,
            BlockHeight::new(9),
            &[leaf(0x00), leaf(0x01), leaf(0x80)],
            WitnessSeed::default(),
        )
        .unwrap();
        (store, root)
    }

    fn child_path(side: u8) -> NibblePath {
        let mut path = NibblePath::empty();
        path.push_bits(side, 1);
        path
    }

    fn origin_at_10() -> ChainOrigin {
        origin_anchored(WeightedTimestamp::from_millis(42_000))
    }

    /// A height-10 chain origin anchored at `anchor_wt` — the weighted
    /// timestamp the child's genesis QC carries, and so the date the
    /// adoption stamps on the genesis version.
    fn origin_anchored(anchor_wt: WeightedTimestamp) -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(10),
            anchor_wt,
        }
    }

    fn child_of(side: u8) -> ShardId {
        let (left, right) = ShardId::ROOT.children();
        if side == 0 { left } else { right }
    }

    /// A deterministic split-child genesis at height 10 adopting
    /// `state_root`, derived over a synthetic parent terminal at height 9.
    fn split_genesis(child: ShardId, state_root: StateRoot, anchor_wt: WeightedTimestamp) -> Block {
        let terminal = Block::genesis(
            ShardId::ROOT,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin {
                genesis_height: BlockHeight::new(9),
                anchor_wt: WeightedTimestamp::ZERO,
            },
        );
        Block::split_child_genesis(child, state_root, terminal.header(), anchor_wt)
    }

    /// The child-side slot of `parent`'s root node — the subtree a clone of
    /// it adopts, and so the root that clone's genesis must name.
    fn child_subtree_root(parent: &SimShardStorage, side: u8) -> StateRoot {
        let path = child_path(side);
        let mut parent_path = path.clone();
        parent_path.truncate(path.len() - 1);
        let slot_index = usize::from(path.bits_at(path.len() - 1, 1));
        let node = {
            let shared = read_or_recover(&parent.state);
            let version = shared.current_block_height.inner();
            shared
                .tree_store
                .get_node(&NodeKey::new(version, parent_path))
                .expect("the parent holds a root node")
        };
        let Node::Internal(root) = node.as_ref() else {
            panic!("a ≤1-key parent cannot split");
        };
        let slot = root.children[slot_index]
            .as_ref()
            .expect("both halves are populated");
        StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash))
    }

    /// Both halves adopt; their roots compose to the parent's terminal
    /// root and their counts partition the leaves. Adoption is idempotent:
    /// a re-run returns the recorded root rather than failing on the
    /// parent slot the first run consumed.
    /// A cloned child sweeps only its own cells.
    ///
    /// The clone carries the sibling's leaves, so without the adoption
    /// prune the child's walk would find them — and a replica that
    /// snap-synced the same child would not, which is a fork between two
    /// storage histories of one chain.
    #[test]
    fn a_cloned_child_does_not_sweep_its_siblings_cells() {
        install_stub_protocol_statics();
        let expiry = 3 * SWEEP_BUCKET_MS;
        let (local, value) = stub_sweepable_cell(expiry, 0x77);
        let sweepable = |side: u8| SubstateLeaf {
            key: SubstateKey {
                owner: Address::new(
                    [if side == 0 { 0x00 } else { 0x80 }; 31],
                    AddressClass::Native,
                ),
                local,
            },
            value: value.clone(),
        };
        let parent = SimShardStorage::default();
        import_boundary_state(
            &parent,
            BlockHeight::new(9),
            &[sweepable(0), sweepable(1)],
            WitnessSeed::default(),
        )
        .unwrap();
        let all = SweepBucket(u32::MAX);
        assert_eq!(
            parent.sweep_candidates(SweepFrontier::ZERO, all, 10).len(),
            2,
            "the parent holds both sides"
        );

        for side in [0u8, 1u8] {
            let child = parent.clone_for_split_child(child_path(side));
            let genesis = split_genesis(
                child_of(side),
                child_subtree_root(&parent, side),
                origin_at_10().anchor_wt,
            );
            child
                .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
                .unwrap();
            assert_eq!(
                child.sweep_candidates(SweepFrontier::ZERO, all, 10),
                vec![(sweepable(side).key, expiry)],
                "child {side} sweeps its own cell and not its sibling's"
            );
        }
    }

    #[test]
    fn split_adoption_partitions_and_is_idempotent() {
        let (parent, parent_root) = split_parent();
        let mut roots = Vec::new();
        for side in [0u8, 1u8] {
            let child = parent.clone_for_split_child(child_path(side));
            // The genesis must name the subtree the clone actually holds —
            // that equality is what gates the seat.
            let expected = child_subtree_root(&parent, side);
            let genesis = split_genesis(child_of(side), expected, origin_at_10().anchor_wt);
            let root = child
                .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
                .unwrap();
            assert_eq!(root, expected);
            assert_ne!(root, StateRoot::ZERO);
            roots.push(root);

            let recovered = child.load_recovered_state(child_of(side));
            assert_eq!(recovered.committed_height, BlockHeight::new(10));
            assert_eq!(recovered.committed_hash, Some(genesis.hash()));
            assert_eq!(recovered.chain_origin, origin_at_10());
            assert_eq!(recovered.substate_bytes, if side == 0 { 2 } else { 1 });

            assert_eq!(
                child
                    .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
                    .unwrap(),
                root,
                "re-run returns the recorded adoption",
            );
        }

        assert_eq!(
            Blake3Hasher::hash_internal(&[*roots[0].as_bytes(), *roots[1].as_bytes()]),
            *parent_root.as_bytes(),
            "adopted roots compose to the parent's terminal root",
        );
    }

    /// Adoption dates the child's genesis version with the anchor its
    /// genesis QC carries, and the floor moves past the parent's dated
    /// versions: the parent's history is not the child's to serve.
    #[test]
    fn adoption_dates_the_genesis_version_and_retires_the_parent_history() {
        let (parent, _) = split_parent();
        {
            let mut shared = write_or_recover(&parent.state);
            for version in 1..=9u64 {
                shared.version_time.insert(version, version * 1_000);
            }
        }
        // Far enough past the retention horizon that every parent
        // version the clone inherits is outside it.
        let origin = origin_anchored(WeightedTimestamp::from_millis(1_000_000));
        let child = parent.clone_for_split_child(child_path(0));
        let genesis = split_genesis(
            child_of(0),
            child_subtree_root(&parent, 0),
            origin.anchor_wt,
        );
        child
            .adopt_genesis(origin, &genesis, AdoptSource::ParentSubtree)
            .unwrap();

        let shared = read_or_recover(&child.state);
        assert_eq!(
            shared.version_time.get(&10),
            Some(&1_000_000),
            "the genesis version is dated with the anchor",
        );
        assert_eq!(
            shared.retention_floor, 10,
            "the floor sits at the adoption, not below the parent's history",
        );
    }
}
