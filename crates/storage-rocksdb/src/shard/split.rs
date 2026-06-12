//! Split-child store adoption.
//!
//! A split moves no state: when shard `p` splits, each child's subtree
//! already sits inside `p`'s store under the child's prefix, with node
//! keys that are absolute trie paths. A parent-half member therefore
//! materializes a child store by hard-linking a checkpoint of the whole
//! parent DB into the child's directory ([`RocksDbShardStorage::checkpoint_into`])
//! and re-pointing the opened store's chain metadata at the child's
//! subtree ([`RocksDbShardStorage::adopt_split_child`]). The sibling's
//! keys ride along as dead weight outside the child's prefix — never
//! read, never served, never in its `state_root` — until reclaimed.

use std::path::Path;
use std::sync::Arc;

use hyperscale_jmt::{Key, NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::tree::Jmt;
use hyperscale_types::{ChainOrigin, Hash, StateRoot};
use rocksdb::WriteBatch;
use rocksdb::checkpoint::Checkpoint;

use super::column_families::{CfHandles, JmtNodesCf, SubstateCountsCf};
use super::core::RocksDbShardStorage;
use super::jmt_stored::{StoredNodeKey, VersionedStoredNode};
use super::metadata::{
    read_chain_origin, read_jmt_metadata, write_chain_origin, write_jmt_metadata,
};
use crate::StorageError;
use crate::typed_cf::{TypedCf, batch_put};

/// Leaves counted per tree walk page while seeding the child's substate
/// count.
const COUNT_PAGE: usize = 1 << 16;

impl RocksDbShardStorage {
    /// Hard-link a checkpoint of this store's entire database into the
    /// store directory at `target` — the cheap, copy-free seed for a
    /// split child's store. The checkpoint lands at `target/db` (the
    /// database location [`Self::open`] expects), so the seeded
    /// directory opens like any other store.
    ///
    /// Creation goes through a dot-prefixed temporary name and a rename,
    /// so a crash mid-create never leaves a plausible-looking partial
    /// database. An existing database under `target` is kept as-is (a
    /// re-run after a crash must not clobber a store the flip may
    /// already have opened); [`Self::adopt_split_child`] validates the
    /// vintage either way.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if checkpoint creation or the rename
    /// fails.
    pub fn checkpoint_into(&self, target: &Path) -> Result<(), StorageError> {
        let db_path = target.join("db");
        if db_path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(target)
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint target dir: {e}")))?;
        let tmp_path = target.join(".tmp-db");
        if tmp_path.exists() {
            std::fs::remove_dir_all(&tmp_path)
                .map_err(|e| StorageError::DatabaseError(format!("checkpoint tmp sweep: {e}")))?;
        }
        Checkpoint::new(&self.db)
            .and_then(|cp| cp.create_checkpoint(&tmp_path))
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint create: {e}")))?;
        std::fs::rename(&tmp_path, &db_path)
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint rename: {e}")))?;
        Ok(())
    }

    /// Re-point this store — opened over a hard-linked checkpoint of the
    /// terminated parent, with this store's `root_path` already the
    /// child's prefix — at the child's adopted subtree.
    ///
    /// Reads the parent's root node at the checkpoint's committed
    /// version, takes the child-side slot as the adopted `state_root`,
    /// copies the child's root node to the genesis version (the same
    /// carry-forward an empty block performs), seeds the substate count
    /// by walking the subtree, and records the chain origin for
    /// recovery. The genesis block itself then commits through the
    /// normal chain-writer path, whose genesis arm expects exactly this
    /// metadata. Idempotent: a re-run over an already-adopted store
    /// returns the recorded adoption untouched.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for an empty
    /// side. The caller asserts it against the beacon-verified
    /// `split_child_roots` pair.
    ///
    /// # Errors
    ///
    /// Fails closed when the checkpoint's vintage does not match the
    /// origin (`committed version + 1 != genesis height`), when the
    /// parent's root collapsed to a leaf (a ≤1-key parent cannot split),
    /// or when the store's root path is the trie root (no parent side
    /// to adopt from).
    pub fn adopt_split_child(&self, origin: ChainOrigin) -> Result<StateRoot, StorageError> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;

        let (checkpoint_version, current_root) = read_jmt_metadata(&*self.db);
        let genesis_version = origin.genesis_height.inner();
        // A re-run over an already-adopted store (crash between adoption
        // and the genesis commit) returns the recorded adoption.
        if checkpoint_version == genesis_version && read_chain_origin(&*self.db) == origin {
            return Ok(current_root);
        }
        // The parent chain coasts past its crossing before it stops —
        // empty blocks whose no-op commits advance the JMT version with a
        // frozen root — so a checkpoint taken at termination sits at the
        // genesis height itself; one version below is the exactly-at-the-
        // crossing case. Anything else is a stale or foreign checkpoint.
        if checkpoint_version != genesis_version && checkpoint_version + 1 != genesis_version {
            return Err(StorageError::DatabaseError(format!(
                "split adoption vintage mismatch: checkpoint at version {checkpoint_version}, \
                 genesis height {genesis_version}"
            )));
        }

        let child_path = self.root_path.clone();
        if child_path.is_empty() {
            return Err(StorageError::DatabaseError(
                "split adoption requires a non-root child prefix".into(),
            ));
        }
        let mut parent_path = child_path.clone();
        parent_path.truncate(child_path.len() - 1);
        let side = usize::from(child_path.bits_at(child_path.len() - 1, 1));

        let cf = CfHandles::resolve(&self.db);
        let parent_root_key = JmtNodeKey::new(checkpoint_version, parent_path);
        let parent_root = self
            .cf_get::<JmtNodesCf>(&StoredNodeKey::from_jmt(&parent_root_key))
            .map(|v| v.into_latest().to_jmt())
            .ok_or_else(|| {
                StorageError::DatabaseError("checkpoint carries no parent root node".into())
            })?;
        let JmtNode::Internal(parent_root) = parent_root else {
            return Err(StorageError::DatabaseError(
                "parent root collapsed to a leaf; a ≤1-key parent cannot split".into(),
            ));
        };

        let mut batch = WriteBatch::default();
        let child_root = match &parent_root.children[side] {
            None => {
                // Empty side: the child starts with an empty tree — no
                // root node exists at any version, and the zero root
                // marks it so.
                batch_put::<SubstateCountsCf>(
                    &mut batch,
                    SubstateCountsCf::handle(&cf),
                    &genesis_version,
                    &0,
                );
                StateRoot::ZERO
            }
            Some(slot) => {
                let child_node_key = JmtNodeKey::new(slot.version, child_path.clone());
                let child_node = self
                    .cf_get::<JmtNodesCf>(&StoredNodeKey::from_jmt(&child_node_key))
                    .ok_or_else(|| {
                        StorageError::DatabaseError(
                            "checkpoint carries no child subtree root node".into(),
                        )
                    })?;
                let genesis_root_key = JmtNodeKey::new(genesis_version, child_path);
                batch_put::<JmtNodesCf>(
                    &mut batch,
                    JmtNodesCf::handle(&cf),
                    &StoredNodeKey::from_jmt(&genesis_root_key),
                    &child_node,
                );
                let count = self.count_subtree_leaves(&genesis_root_key, &child_node)?;
                batch_put::<SubstateCountsCf>(
                    &mut batch,
                    SubstateCountsCf::handle(&cf),
                    &genesis_version,
                    &count,
                );
                StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash))
            }
        };
        write_jmt_metadata(&mut batch, genesis_version, child_root);
        write_chain_origin(&mut batch, origin);
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(format!("split adoption write: {e}")))?;
        Ok(child_root)
    }

    /// Count the live leaves under the adopted child root by walking the
    /// tree in pages. The root node is supplied directly (it sits in the
    /// not-yet-written batch during adoption), so the walk reads it from
    /// memory and every deeper node from the checkpoint.
    fn count_subtree_leaves(
        &self,
        root_key: &JmtNodeKey,
        root_node: &VersionedStoredNode,
    ) -> Result<u64, StorageError> {
        let store = PreRootStore {
            inner: self,
            root_key,
            root_node,
        };
        let mut count: u64 = 0;
        let mut start: Key = [0u8; 32];
        loop {
            let chunk = Jmt::collect_range(&store, root_key, &start, &[0xFF; 32], COUNT_PAGE)
                .map_err(|e| StorageError::DatabaseError(format!("split adoption count: {e:?}")))?;
            count += chunk.leaves.len() as u64;
            let Some((last, _)) = chunk.leaves.last() else {
                break;
            };
            if !chunk.more {
                break;
            }
            start = *last;
            // Advance the cursor one key; saturation is unreachable
            // (`more` implies a successor exists).
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
}

/// A tree reader serving the adopted child root from memory (it is not
/// yet written) and everything else from the underlying store.
struct PreRootStore<'a> {
    inner: &'a RocksDbShardStorage,
    root_key: &'a JmtNodeKey,
    root_node: &'a VersionedStoredNode,
}

impl TreeReader for PreRootStore<'_> {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        if key == self.root_key {
            return Some(Arc::new(self.root_node.clone().into_latest().to_jmt()));
        }
        self.inner
            .cf_get::<JmtNodesCf>(&StoredNodeKey::from_jmt(key))
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        (version == self.root_key.version).then(|| self.root_key.clone())
    }

    fn root_path(&self) -> NibblePath {
        self.root_key.path.clone()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, Hasher, NibblePath};
    use hyperscale_storage::{BoundaryStore, ImportLeaf};
    use hyperscale_types::{BlockHeight, WeightedTimestamp};
    use tempfile::TempDir;

    use super::super::metadata::read_chain_origin;
    use super::*;

    /// A 32-byte leaf key with `b` as its leading byte.
    fn k(b: u8) -> Key {
        let mut key = [0u8; 32];
        key[0] = b;
        key
    }

    fn leaf(b: u8) -> ImportLeaf {
        ImportLeaf {
            leaf_key: k(b),
            storage_key: vec![b; 40],
            value: vec![b],
        }
    }

    /// A parent store at the trie root holding two left-side leaves and
    /// one right-side leaf, committed at height 9.
    fn parent_store(dir: &Path) -> RocksDbShardStorage {
        let storage = RocksDbShardStorage::open(dir, NibblePath::empty()).unwrap();
        storage
            .import_boundary_state(
                BlockHeight::new(9),
                vec![leaf(0x00), leaf(0x01), leaf(0x80)],
            )
            .unwrap();
        storage
    }

    fn child_path(side: u8) -> NibblePath {
        let mut path = NibblePath::empty();
        path.push_bits(side, 1);
        path
    }

    fn origin_at_10() -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(10),
            anchor_wt: WeightedTimestamp::from_millis(42_000),
        }
    }

    /// The full parent-half flow: checkpoint the parent, open the
    /// hard-linked copy at each child's prefix, adopt. The two adopted
    /// roots compose to the parent's root, counts partition the leaf
    /// population, and the chain origin records for recovery.
    #[test]
    fn adopted_children_partition_the_parent() {
        let parent_dir = TempDir::new().unwrap();
        let parent = parent_store(parent_dir.path());
        let (parent_version, parent_root) = parent.read_jmt_metadata();
        assert_eq!(parent_version, 9, "import committed at height 9");

        let mut roots = Vec::new();
        for side in [0u8, 1u8] {
            let child_dir = TempDir::new().unwrap();
            let target = child_dir.path().join("store");
            parent.checkpoint_into(&target).unwrap();
            let child = RocksDbShardStorage::open(&target, child_path(side)).unwrap();
            let root = child.adopt_split_child(origin_at_10()).unwrap();
            assert_ne!(root, StateRoot::ZERO);
            roots.push(root);

            assert_eq!(child.read_jmt_metadata(), (10, root));
            assert_eq!(
                child.substate_count_at_version(10),
                Some(if side == 0 { 2 } else { 1 }),
            );
            assert_eq!(read_chain_origin(&*child.db), origin_at_10());

            // Idempotent: a re-run lands on the same values.
            assert_eq!(child.adopt_split_child(origin_at_10()).unwrap(), root);
        }

        assert_eq!(
            Blake3Hasher::hash_internal(&[*roots[0].as_bytes(), *roots[1].as_bytes()]),
            *parent_root.as_bytes(),
            "adopted roots must compose to the parent's terminal root",
        );
    }

    /// A wrong-vintage checkpoint (genesis height not one past the
    /// checkpoint's committed version) fails closed.
    #[test]
    fn adoption_rejects_a_stale_checkpoint() {
        let parent_dir = TempDir::new().unwrap();
        let parent = parent_store(parent_dir.path());
        let child_dir = TempDir::new().unwrap();
        let target = child_dir.path().join("store");
        parent.checkpoint_into(&target).unwrap();
        let child = RocksDbShardStorage::open(&target, child_path(0)).unwrap();

        let stale = ChainOrigin {
            genesis_height: BlockHeight::new(12),
            anchor_wt: WeightedTimestamp::from_millis(42_000),
        };
        assert!(child.adopt_split_child(stale).is_err());
    }

    /// An empty side adopts a zero root with a zero count — the child
    /// starts from an empty tree at its genesis height.
    #[test]
    fn empty_side_adopts_a_zero_root() {
        let parent_dir = TempDir::new().unwrap();
        let storage = RocksDbShardStorage::open(parent_dir.path(), NibblePath::empty()).unwrap();
        // Both leaves on the left: the right child is empty.
        storage
            .import_boundary_state(BlockHeight::new(9), vec![leaf(0x00), leaf(0x01)])
            .unwrap();

        let child_dir = TempDir::new().unwrap();
        let target = child_dir.path().join("store");
        storage.checkpoint_into(&target).unwrap();
        let child = RocksDbShardStorage::open(&target, child_path(1)).unwrap();
        let root = child.adopt_split_child(origin_at_10()).unwrap();
        assert_eq!(root, StateRoot::ZERO);
        assert_eq!(child.read_jmt_metadata(), (10, StateRoot::ZERO));
        assert_eq!(child.substate_count_at_version(10), Some(0));
    }

    /// Partition independence over follows: two child stores each
    /// following only their half of a chain's block writes assemble
    /// exactly the two child subtrees of a root store fed the same
    /// blocks (a root prefix filters nothing, so it doubles as the
    /// unfiltered baseline). Foreign-half blocks are no-ops that leave a
    /// child's version line sparse.
    #[test]
    fn followed_children_partition_and_recompose_the_root() {
        use std::sync::Arc;

        use hyperscale_storage::test_helpers::{db_node_key, make_database_update};
        use hyperscale_types::state_key::node_routing_hash;
        use hyperscale_types::{
            BoundedVec, ConsensusReceipt, GlobalReceiptHash, Hash, NodeId, StoredReceipt, TxHash,
        };

        let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
        let whole = RocksDbShardStorage::open(dirs[0].path(), NibblePath::empty()).unwrap();
        let left = RocksDbShardStorage::open(dirs[1].path(), child_path(0)).unwrap();
        let right = RocksDbShardStorage::open(dirs[2].path(), child_path(1)).unwrap();

        let mut sides_hit = [false, false];
        let mut roots = (StateRoot::ZERO, StateRoot::ZERO, StateRoot::ZERO);
        for seed in 1u8..=8 {
            let updates = make_database_update(db_node_key(seed), 0, vec![seed], vec![seed; 4]);
            let receipts = [StoredReceipt::synced(
                TxHash::from_raw(Hash::from_bytes(&[seed])),
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    database_updates: updates,
                    owned_nodes: BoundedVec::new(),
                    application_events: Vec::new(),
                    beacon_witness_events: Vec::new(),
                }),
            )];
            let height = BlockHeight::new(u64::from(seed));
            roots = (
                whole.follow_block_writes(height, &receipts).unwrap(),
                left.follow_block_writes(height, &receipts).unwrap(),
                right.follow_block_writes(height, &receipts).unwrap(),
            );
            sides_hit[usize::from(node_routing_hash(&NodeId([seed; 30]))[0] >> 7)] = true;
        }
        assert!(
            sides_hit[0] && sides_hit[1],
            "fixture seeds must straddle the split bit",
        );
        let (whole_root, left_root, right_root) = roots;
        assert_eq!(
            Blake3Hasher::hash_internal(&[*left_root.as_bytes(), *right_root.as_bytes()]),
            *whole_root.as_bytes(),
            "followed child roots must recompose to the whole tree's root",
        );

        // The whole store advanced on every block; each child only on
        // its own half's writes.
        let (whole_version, _) = whole.read_jmt_metadata();
        assert_eq!(whole_version, 8);
        let (left_version, _) = left.read_jmt_metadata();
        let (right_version, _) = right.read_jmt_metadata();
        assert!(left_version < 8 || right_version < 8);
    }
}
