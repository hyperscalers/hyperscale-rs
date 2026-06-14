//! Reshape store adoption.
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

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::tree::Jmt;
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, CertifiedBlock, ChainOrigin, Hash, StateRoot, Verified,
};
use rocksdb::WriteBatch;
use rocksdb::checkpoint::Checkpoint;

use super::column_families::{CfHandles, JmtNodesCf, SubstateBytesCf};
use super::core::RocksDbShardStorage;
use super::jmt_stored::{StoredNodeKey, VersionedStoredNode};
use super::metadata::{
    delete_committed_qc, read_chain_origin, read_jmt_metadata, write_chain_origin,
    write_committed_hash, write_committed_height, write_jmt_metadata,
};
use crate::StorageError;
use crate::typed_cf::{TypedCf, batch_put};

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
    /// carry-forward an empty block performs), seeds the substate byte total
    /// by walking the subtree, and records the chain origin plus the
    /// `genesis` block as the committed tip — all in one atomic batch,
    /// so a crash at any later point recovers the store as a committed
    /// child chain at its genesis. Idempotent: a re-run over an
    /// already-adopted store returns the recorded adoption untouched.
    /// An observer's followed store adopts through
    /// [`Self::adopt_followed_child`] instead — the shapes are
    /// caller-distinguished, since a checkpoint can be structurally
    /// ambiguous with a followed store.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for an empty
    /// side. The caller asserts it against the beacon-verified
    /// `split_child_roots` pair.
    ///
    /// # Errors
    ///
    /// Fails closed when the checkpoint's vintage does not match the
    /// origin (`committed version + 1 != genesis height`), when the
    /// genesis block does not sit at the origin's height, when the
    /// parent's root collapsed to a leaf (a ≤1-key parent cannot split),
    /// or when the store's root path is the trie root (no parent side
    /// to adopt from).
    pub fn adopt_split_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, StorageError> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;
        if genesis.height() != origin.genesis_height {
            return Err(StorageError::DatabaseError(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            )));
        }

        let (checkpoint_version, current_root) = read_jmt_metadata(&*self.db);
        let genesis_version = origin.genesis_height.inner();
        // A re-run over an already-adopted store returns the recorded
        // adoption.
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
                batch_put::<SubstateBytesCf>(
                    &mut batch,
                    SubstateBytesCf::handle(&cf),
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
                let bytes = self.sum_subtree_value_lens(&genesis_root_key, &child_node)?;
                batch_put::<SubstateBytesCf>(
                    &mut batch,
                    SubstateBytesCf::handle(&cf),
                    &genesis_version,
                    &bytes,
                );
                StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash))
            }
        };
        write_jmt_metadata(&mut batch, genesis_version, child_root);
        write_chain_origin(&mut batch, origin);
        self.append_genesis_tip_to_batch(&mut batch, genesis);
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(format!("split adoption write: {e}")))?;
        Ok(child_root)
    }

    /// Re-point an observer's followed store at its adopted subtree —
    /// the child root the store itself holds at its tip version.
    ///
    /// The store imported the child span at the splitting parent's
    /// anchor and followed the parent's child-half writes to its
    /// crossing, so its tree *is* the adopted subtree: the tip's root
    /// node is copied to the genesis version, the substate byte total seeded
    /// by walking it, and the chain origin plus the `genesis` block
    /// recorded as the committed tip — all in one atomic batch, so a
    /// crash at any later point recovers the store as a committed child
    /// chain at its genesis. The tip version is sparse on the parent's
    /// heights (foreign-half blocks never advanced it), so no checkpoint
    /// vintage applies — the trust is the equality check against the
    /// beacon-seeded child anchor. Idempotent like
    /// [`Self::adopt_split_child`].
    ///
    /// Returns the adopted child `state_root` — `ZERO` for a store
    /// whose span held nothing (an empty half).
    ///
    /// # Errors
    ///
    /// Fails closed when the store's tip sits at or past the genesis
    /// height (a followed store only ever advances on child-half writes,
    /// which the parent's coast cannot produce), when the genesis block
    /// does not sit at the origin's height or carries a state root other
    /// than the followed one, when the store's metadata names a root its
    /// tree doesn't hold, or when the store's root path is the trie
    /// root.
    pub fn adopt_followed_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, StorageError> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;
        if genesis.height() != origin.genesis_height {
            return Err(StorageError::DatabaseError(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            )));
        }

        let (tip_version, current_root) = read_jmt_metadata(&*self.db);
        let genesis_version = origin.genesis_height.inner();
        // A re-run over an already-adopted store returns the recorded
        // adoption.
        if tip_version == genesis_version && read_chain_origin(&*self.db) == origin {
            return Ok(current_root);
        }
        if tip_version >= genesis_version {
            return Err(StorageError::DatabaseError(format!(
                "followed adoption vintage mismatch: store at version {tip_version}, \
                 genesis height {genesis_version}"
            )));
        }
        if genesis.header().state_root() != current_root {
            return Err(StorageError::DatabaseError(format!(
                "followed root {current_root:?} does not match the genesis state root {:?}",
                genesis.header().state_root(),
            )));
        }
        let child_path = self.root_path.clone();
        if child_path.is_empty() {
            return Err(StorageError::DatabaseError(
                "split adoption requires a non-root child prefix".into(),
            ));
        }

        let cf = CfHandles::resolve(&self.db);
        let mut batch = WriteBatch::default();
        if current_root == StateRoot::ZERO {
            // An empty half: the sync imported nothing and no follow
            // ever advanced the tip — the child starts from an empty
            // tree at its genesis height.
            batch_put::<SubstateBytesCf>(
                &mut batch,
                SubstateBytesCf::handle(&cf),
                &genesis_version,
                &0,
            );
        } else {
            let own_root_key = JmtNodeKey::new(tip_version, child_path.clone());
            let own_root = self
                .cf_get::<JmtNodesCf>(&StoredNodeKey::from_jmt(&own_root_key))
                .ok_or_else(|| {
                    StorageError::DatabaseError(
                        "followed store holds no root node at its tip version".into(),
                    )
                })?;
            let genesis_root_key = JmtNodeKey::new(genesis_version, child_path);
            batch_put::<JmtNodesCf>(
                &mut batch,
                JmtNodesCf::handle(&cf),
                &StoredNodeKey::from_jmt(&genesis_root_key),
                &own_root,
            );
            let bytes = self.sum_subtree_value_lens(&genesis_root_key, &own_root)?;
            batch_put::<SubstateBytesCf>(
                &mut batch,
                SubstateBytesCf::handle(&cf),
                &genesis_version,
                &bytes,
            );
        }
        write_jmt_metadata(&mut batch, genesis_version, current_root);
        write_chain_origin(&mut batch, origin);
        self.append_genesis_tip_to_batch(&mut batch, genesis);
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(format!("followed adoption write: {e}")))?;
        Ok(current_root)
    }

    /// Adopt a merged parent's store — a `parent`-rooted store already
    /// holding both children's subtrees and the stitched root `r_p` at
    /// its tip (the keeper hard-linked its own half, synced the sibling,
    /// and stitched the root with one internal-node write). The tip
    /// already sits at the genesis version, so adoption only records the
    /// deterministic merged genesis as the committed tip; unlike a split
    /// child the prefix may be the trie root, and there is no subtree
    /// re-pointing — the merged tree is already in place.
    ///
    /// Returns the adopted `r_p`. The caller asserts it against the
    /// beacon-composed parent anchor.
    ///
    /// # Errors
    ///
    /// Fails when the genesis block does not sit at the origin's height,
    /// when the store's tip does not sit at that height, or when the
    /// store's root does not match the genesis state root.
    pub fn adopt_merge_parent(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, StorageError> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;
        if genesis.height() != origin.genesis_height {
            return Err(StorageError::DatabaseError(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            )));
        }
        let (tip_version, current_root) = read_jmt_metadata(&*self.db);
        let genesis_version = origin.genesis_height.inner();
        // A re-run over an already-adopted store returns the recorded
        // adoption.
        if read_chain_origin(&*self.db) == origin {
            return Ok(current_root);
        }
        if tip_version != genesis_version {
            return Err(StorageError::DatabaseError(format!(
                "merge adoption vintage mismatch: store at version {tip_version}, \
                 genesis height {genesis_version}"
            )));
        }
        if genesis.header().state_root() != current_root {
            return Err(StorageError::DatabaseError(format!(
                "merged root {current_root:?} does not match the genesis state root {:?}",
                genesis.header().state_root(),
            )));
        }
        let mut batch = WriteBatch::default();
        write_chain_origin(&mut batch, origin);
        self.append_genesis_tip_to_batch(&mut batch, genesis);
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(format!("merge adoption write: {e}")))?;
        Ok(current_root)
    }

    /// Fold the child's deterministic genesis into an adoption batch as
    /// the committed tip: the genesis block with its deterministic
    /// certified pairing, the committed height and hash, and a reset of
    /// any checkpoint-inherited latest QC — the child chain holds no QC
    /// at its genesis, and recovery's `latest_qc: None` makes the first
    /// proposal extend the structural genesis QC reconstructed from the
    /// chain origin.
    fn append_genesis_tip_to_batch(&self, batch: &mut WriteBatch, genesis: &Block) {
        let pair = Verified::<CertifiedBlock>::genesis_certified(genesis.clone());
        self.append_block_to_batch(
            batch,
            pair.block(),
            pair.qc_verified(),
            BeaconWitnessLeafCount::ZERO,
        );
        write_committed_height(batch, genesis.height());
        write_committed_hash(batch, genesis.hash().as_raw());
        delete_committed_qc(batch);
    }

    /// Sum the value bytes under the adopted child root by walking the
    /// tree in pages. The root node is supplied directly (it sits in the
    /// not-yet-written batch during adoption), so the walk reads it from
    /// memory and every deeper node from the checkpoint.
    fn sum_subtree_value_lens(
        &self,
        root_key: &JmtNodeKey,
        root_node: &VersionedStoredNode,
    ) -> Result<u64, StorageError> {
        let store = PreRootStore {
            inner: self,
            root_key,
            root_node,
        };
        Jmt::sum_subtree_value_lens(&store, root_key)
            .map_err(|e| StorageError::DatabaseError(format!("split adoption byte sum: {e:?}")))
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
    use hyperscale_jmt::{Blake3Hasher, Hasher, Key, NibblePath};
    use hyperscale_storage::{BoundaryStore, ImportLeaf};
    use hyperscale_types::{BlockHash, BlockHeight, ShardId, ValidatorId, WeightedTimestamp};
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

    /// A deterministic child genesis at height 10 adopting `state_root`,
    /// derived over a synthetic parent terminal header at height 9.
    fn genesis_at_10(child: ShardId, state_root: StateRoot) -> Block {
        let terminal = Block::genesis(
            ShardId::ROOT,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin {
                genesis_height: BlockHeight::new(9),
                anchor_wt: WeightedTimestamp::ZERO,
            },
        );
        Block::split_child_genesis(
            child,
            state_root,
            terminal.header(),
            WeightedTimestamp::from_millis(42_000),
        )
    }

    fn child_of(side: u8) -> ShardId {
        let (left, right) = ShardId::ROOT.children();
        if side == 0 { left } else { right }
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
            let genesis = genesis_at_10(child_of(side), StateRoot::ZERO);
            let root = child.adopt_split_child(origin_at_10(), &genesis).unwrap();
            assert_ne!(root, StateRoot::ZERO);
            roots.push(root);

            assert_eq!(child.read_jmt_metadata(), (10, root));
            assert_eq!(
                child.substate_bytes_at_version(10),
                Some(if side == 0 { 2 } else { 1 }),
            );
            assert_eq!(read_chain_origin(&*child.db), origin_at_10());
            // The adoption batch records the genesis as the committed
            // tip, with no inherited latest QC.
            let recovered = child.load_recovered_state();
            assert_eq!(recovered.committed_height, BlockHeight::new(10));
            assert_eq!(recovered.committed_hash, Some(genesis.hash()));
            assert!(recovered.latest_qc.is_none());
            assert_eq!(recovered.chain_origin, origin_at_10());

            // Idempotent: a re-run lands on the same values.
            assert_eq!(
                child.adopt_split_child(origin_at_10(), &genesis).unwrap(),
                root,
            );
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
        let terminal = Block::genesis(
            ShardId::ROOT,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin {
                genesis_height: BlockHeight::new(11),
                anchor_wt: WeightedTimestamp::ZERO,
            },
        );
        let genesis = Block::split_child_genesis(
            child_of(0),
            StateRoot::ZERO,
            terminal.header(),
            WeightedTimestamp::from_millis(42_000),
        );
        assert!(child.adopt_split_child(stale, &genesis).is_err());
    }

    /// A keeper's merged parent store, built whole-keyspace from both
    /// halves, adopts its stitched root: the recorded tip is the merged
    /// genesis over the already-built tree, idempotent on re-run, and a
    /// root mismatch fails closed.
    #[test]
    fn merge_adoption_records_the_merged_genesis_tip() {
        let cut = WeightedTimestamp::from_millis(10_000);
        let merge_genesis = |state_root: StateRoot| {
            Block::merge_parent_genesis(
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
            )
        };

        let dir = TempDir::new().unwrap();
        let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).unwrap();
        // One leaf on each half so the root is the merged internal node.
        let root = storage
            .import_boundary_state(BlockHeight::new(10), vec![leaf(0x00), leaf(0x80)])
            .unwrap();
        assert_ne!(root, StateRoot::ZERO);

        let genesis = merge_genesis(root);
        assert_eq!(genesis.height(), BlockHeight::new(10));
        let origin = ChainOrigin {
            genesis_height: genesis.height(),
            anchor_wt: cut,
        };

        let adopted = storage.adopt_merge_parent(origin, &genesis).unwrap();
        assert_eq!(adopted, root);
        assert_eq!(storage.read_jmt_metadata(), (10, root));
        assert_eq!(read_chain_origin(&*storage.db), origin);
        // Idempotent re-run returns the recorded adoption.
        assert_eq!(storage.adopt_merge_parent(origin, &genesis).unwrap(), root);

        // A genesis claiming a different root fails closed.
        let dir2 = TempDir::new().unwrap();
        let other = RocksDbShardStorage::open(dir2.path(), NibblePath::empty()).unwrap();
        other
            .import_boundary_state(BlockHeight::new(10), vec![leaf(0x00), leaf(0x80)])
            .unwrap();
        let wrong = merge_genesis(StateRoot::from_raw(Hash::from_bytes(b"forged")));
        assert!(other.adopt_merge_parent(origin, &wrong).is_err());
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
        let genesis = genesis_at_10(child_of(1), StateRoot::ZERO);
        let root = child.adopt_split_child(origin_at_10(), &genesis).unwrap();
        assert_eq!(root, StateRoot::ZERO);
        assert_eq!(child.read_jmt_metadata(), (10, StateRoot::ZERO));
        assert_eq!(child.substate_bytes_at_version(10), Some(0));
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

        // The followed-store adoption: each store re-points at its own
        // root from its sparse tip version, with no checkpoint vintage
        // to satisfy.
        let origin = ChainOrigin {
            genesis_height: BlockHeight::new(9),
            anchor_wt: WeightedTimestamp::from_millis(42_000),
        };
        for (side, (store, followed_root)) in [(&left, left_root), (&right, right_root)]
            .into_iter()
            .enumerate()
        {
            let terminal = Block::genesis(
                ShardId::ROOT,
                ValidatorId::new(0),
                StateRoot::ZERO,
                ChainOrigin {
                    genesis_height: BlockHeight::new(8),
                    anchor_wt: WeightedTimestamp::ZERO,
                },
            );
            let genesis = Block::split_child_genesis(
                child_of(u8::try_from(side).unwrap()),
                followed_root,
                terminal.header(),
                WeightedTimestamp::from_millis(42_000),
            );
            let adopted = store.adopt_followed_child(origin, &genesis).unwrap();
            assert_eq!(adopted, followed_root);
            assert_eq!(store.read_jmt_metadata(), (9, followed_root));
            assert!(store.substate_bytes_at_version(9).is_some());
            assert_eq!(read_chain_origin(&*store.db), origin);
            let recovered = store.load_recovered_state();
            assert_eq!(recovered.committed_height, BlockHeight::new(9));
            assert_eq!(recovered.committed_hash, Some(genesis.hash()));
            assert!(recovered.latest_qc.is_none());
            // Idempotent: a re-run lands on the same values.
            assert_eq!(
                store.adopt_followed_child(origin, &genesis).unwrap(),
                adopted
            );
        }
    }
}
