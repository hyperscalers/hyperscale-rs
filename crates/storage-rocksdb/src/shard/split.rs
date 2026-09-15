//! Reshape store adoption.
//!
//! A split moves no state: when shard `p` splits, each child's subtree
//! already sits inside `p`'s store under the child's prefix, with node
//! keys that are absolute trie paths. A parent-half member therefore
//! materializes a child store by hard-linking a checkpoint of the whole
//! parent DB into the child's directory ([`RocksDbShardStorage::checkpoint_into`])
//! and re-pointing the opened store's chain metadata at the child's
//! subtree ([`RocksDbShardStorage::adopt_genesis`]). The sibling's
//! keys ride along as dead weight outside the child's prefix — never
//! read, never served, never in its `state_root` — until reclaimed.
//!
//! That holds because every index over the cells is read owner-scoped,
//! and a transaction on a child names only owners the child holds. The
//! sweep index is the exception, since a sweep enumerates the whole
//! shard rather than one owner, so adoption prunes its foreign rows.

use std::path::Path;
use std::sync::Arc;

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::tree::Jmt;
use hyperscale_storage::{AdoptSource, Adoption, Subtree, SweepRows, Vintage, adopt_plan};
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, CertifiedBlock, ChainOrigin, Hash, StateRoot, Verified,
};
use rocksdb::WriteBatch;
use rocksdb::checkpoint::Checkpoint;

use super::column_families::{CfHandles, JmtNodesCf, SubstateBytesCf, SweepIndexCf};
use super::core::RocksDbShardStorage;
use super::metadata::{
    delete_committed_qc, read_chain_origin, read_jmt_metadata, write_chain_origin,
    write_committed_hash, write_committed_height, write_jmt_metadata,
};
use crate::StorageError;
use crate::typed_cf::{TypedCf, batch_delete, batch_put, iter_all};

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
    /// already have opened); [`Self::adopt_genesis`] validates the
    /// vintage either way.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if checkpoint creation or the rename
    /// fails.
    pub fn checkpoint_into(&self, target: &Path) -> Result<(), StorageError> {
        // Serialize against a co-hosted sibling vnode committing this same
        // parent store: the checkpoint snapshots the live db, so it takes the
        // commit lock like every other batch path rather than relying on
        // RocksDB's internal locking alone.
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;
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

    /// Install a reshape successor's derived `genesis` as this store's
    /// chain origin and committed tip: [`adopt_plan`] decided over this
    /// store's vintage under the commit lock, then applied in one atomic
    /// batch, so a crash at any later point recovers the store as a
    /// committed chain at its genesis.
    ///
    /// # Errors
    ///
    /// What [`adopt_plan`] refused, or a store that cannot yield the
    /// subtree it named.
    pub(crate) fn adopt_genesis(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
        source: AdoptSource,
    ) -> Result<StateRoot, StorageError> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| StorageError::DatabaseError("commit lock poisoned".into()))?;
        let (version, root) = read_jmt_metadata(&*self.db);
        let vintage = Vintage {
            version,
            root,
            prefix: self.root_path.clone(),
            origin: read_chain_origin(&*self.db),
        };
        let adoption = adopt_plan(&vintage, origin, genesis, source, |version| {
            self.parent_subtree(version)
        })
        .map_err(StorageError::DatabaseError)?;

        let cf = CfHandles::resolve(&self.db);
        let mut batch = WriteBatch::default();
        let genesis_version = origin.genesis_height.inner();
        let adopted = match adoption {
            Adoption::Recorded(root) => return Ok(root),
            Adoption::InPlace(root) => root,
            Adoption::Repoint(subtree) => {
                let root = self.repoint(&cf, &mut batch, subtree, genesis_version)?;
                write_jmt_metadata(&mut batch, genesis_version, root);
                self.drop_foreign_sweep_rows(&cf, &mut batch);
                root
            }
        };
        write_chain_origin(&mut batch, origin);
        self.append_genesis_tip_to_batch(&mut batch, genesis);
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(format!("reshape adoption write: {e}")))?;
        Ok(adopted)
    }

    /// Drop the sweep-index rows of owners outside this store's prefix —
    /// the sibling half a split clone carries as dead weight; see
    /// [`SweepRows::retain_under`].
    fn drop_foreign_sweep_rows(&self, cf: &CfHandles, batch: &mut WriteBatch) {
        let sweep_cf = SweepIndexCf::handle(cf);
        let mut rows: SweepRows = iter_all::<SweepIndexCf>(&self.db, sweep_cf)
            .map(|(row, count)| (row, i64::from(count)))
            .collect();
        for row in rows.retain_under(&self.root_path) {
            batch_delete::<SweepIndexCf>(batch, sweep_cf, &row);
        }
    }

    /// The child subtree to adopt out of a parent checkpoint this store was
    /// cloned from: the child-side slot of the parent's root node at
    /// `checkpoint_version`, or `None` for an empty side.
    ///
    /// The parent chain coasts past its crossing before it stops — empty
    /// blocks whose no-op commits advance the JMT version with a frozen
    /// root. Under make-before-break it coasts an unbounded number of them
    /// (until its successors go live), so the checkpoint sits at the
    /// crossing version or any height above it, and the frozen root makes
    /// the extracted subtree identical at every one. Only a checkpoint from
    /// *below* the crossing is refused here — a stale or foreign store
    /// that never held the terminal's child-half writes. The plan's
    /// root-equality check is the real guarantee, and it rejects a
    /// non-frozen coast (a parent that changed the child's state after the
    /// crossing) however far past it lands.
    fn parent_subtree(&self, checkpoint_version: u64) -> Result<Option<Subtree>, String> {
        let child_path = &self.root_path;
        let mut parent_path = child_path.clone();
        parent_path.truncate(child_path.len() - 1);
        let side = usize::from(child_path.bits_at(child_path.len() - 1, 1));

        let parent_root_key = JmtNodeKey::new(checkpoint_version, parent_path);
        let parent_root = self
            .cf_get::<JmtNodesCf>(&parent_root_key)
            .ok_or_else(|| "checkpoint carries no parent root node".to_string())?;
        let JmtNode::Internal(parent_root) = parent_root else {
            return Err("parent root collapsed to a leaf; a ≤1-key parent cannot split".into());
        };
        Ok(parent_root.children[side].as_ref().map(|slot| Subtree {
            version: slot.version,
            root: StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash)),
        }))
    }

    /// Copy `source`'s root node to the genesis version — the same
    /// carry-forward an empty block performs — and seed the substate byte
    /// total by walking it. `None` is an empty subtree: the zero root, and
    /// no bytes.
    fn repoint(
        &self,
        cf: &CfHandles,
        batch: &mut WriteBatch,
        source: Option<Subtree>,
        genesis_version: u64,
    ) -> Result<StateRoot, StorageError> {
        let Some(Subtree { version, root }) = source else {
            batch_put::<SubstateBytesCf>(batch, SubstateBytesCf::handle(cf), &genesis_version, &0);
            return Ok(StateRoot::ZERO);
        };
        let source_key = JmtNodeKey::new(version, self.root_path.clone());
        let node = self.cf_get::<JmtNodesCf>(&source_key).ok_or_else(|| {
            StorageError::DatabaseError("store holds no root node at the source version".into())
        })?;
        let genesis_root_key = JmtNodeKey::new(genesis_version, source_key.path);
        batch_put::<JmtNodesCf>(batch, JmtNodesCf::handle(cf), &genesis_root_key, &node);
        let bytes = self.sum_subtree_value_lens(&genesis_root_key, &node)?;
        batch_put::<SubstateBytesCf>(batch, SubstateBytesCf::handle(cf), &genesis_version, &bytes);
        Ok(root)
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
        // A child's history begins here, and its genesis QC carries the
        // chain origin's anchor: dating it is what puts the floor at the
        // adoption rather than below everything the parent held.
        let floor = self.advance_retention_floor(
            batch,
            genesis.height().inner(),
            pair.qc_verified().weighted_timestamp(),
        );
        self.append_block_to_batch(
            batch,
            pair.block(),
            pair.qc_verified(),
            BeaconWitnessLeafCount::ZERO,
            floor,
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
        root_node: &JmtNode,
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
    root_node: &'a JmtNode,
}

impl TreeReader for PreRootStore<'_> {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        if key == self.root_key {
            return Some(Arc::new(self.root_node.clone()));
        }
        self.inner.cf_get::<JmtNodesCf>(key).map(Arc::new)
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
    use hyperscale_jmt::{Blake3Hasher, Hasher, KEY_BYTES, Key, NibblePath};
    use hyperscale_storage::test_helpers::import_boundary_state;
    use hyperscale_storage::{AdoptSource, BoundaryStore, SweepIndex, WitnessSeed};
    use hyperscale_types::test_utils::{install_stub_protocol_statics, stub_sweepable_cell};
    use hyperscale_types::{
        AddressClass, BlockHash, BlockHeight, SWEEP_BUCKET_MS, ShardId, SubstateKey, SubstateLeaf,
        SweepBucket, SweepFrontier, ValidatorId, WeightedTimestamp,
    };
    use tempfile::TempDir;

    use super::super::metadata::read_chain_origin;
    use super::*;

    /// A 48-byte leaf key with `b` as its leading byte.
    fn k(b: u8) -> Key {
        let mut key = [0u8; KEY_BYTES];
        key[0] = b;
        key[31] = AddressClass::Component.tag();
        key
    }

    fn leaf(b: u8) -> SubstateLeaf {
        SubstateLeaf {
            key: SubstateKey::from_bytes(k(b)).expect("a stored leaf key names an address"),
            value: vec![b],
        }
    }

    /// A parent store at the trie root holding two left-side leaves and
    /// one right-side leaf, committed at height 9.
    fn parent_store(dir: &Path) -> RocksDbShardStorage {
        let storage = RocksDbShardStorage::open(dir, NibblePath::empty()).unwrap();
        import_boundary_state(
            &storage,
            BlockHeight::new(9),
            &[leaf(0x00), leaf(0x01), leaf(0x80)],
            WitnessSeed::default(),
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

    /// The child subtree root the adoption extracts for `side` — the parent
    /// root node's child slot hash at `version`. The genesis the adoption now
    /// verifies against must carry exactly this root, so a test seeds its child
    /// genesis with it.
    fn child_root_from_parent(parent: &RocksDbShardStorage, version: u64, side: u8) -> StateRoot {
        let root_key = JmtNodeKey::new(version, NibblePath::empty());
        let node = parent
            .cf_get::<JmtNodesCf>(&root_key)
            .expect("parent root node present");
        let JmtNode::Internal(internal) = node else {
            panic!("parent root must be an internal node");
        };
        internal.children[usize::from(side)]
            .as_ref()
            .map_or(StateRoot::ZERO, |slot| {
                StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash))
            })
    }

    /// A cloned child sweeps only its own cells.
    ///
    /// The clone carries the sibling's leaves in the cell column, so
    /// without the adoption prune the child's walk would find them —
    /// and a replica that snap-synced the same child would not, which
    /// is a fork between two storage histories of one chain.
    #[test]
    fn a_cloned_child_does_not_sweep_its_siblings_cells() {
        install_stub_protocol_statics();
        let expiry = 3 * SWEEP_BUCKET_MS;
        let (local, value) = stub_sweepable_cell(expiry, 0x77);
        let sweepable = |side: u8| SubstateLeaf {
            key: SubstateKey::from_bytes({
                let mut key = k(if side == 0 { 0x00 } else { 0x80 });
                key[32..].copy_from_slice(&local.0);
                key
            })
            .expect("a stored leaf key names an address"),
            value: value.clone(),
        };

        let parent_dir = TempDir::new().unwrap();
        let parent = RocksDbShardStorage::open(parent_dir.path(), NibblePath::empty()).unwrap();
        import_boundary_state(
            &parent,
            BlockHeight::new(9),
            &[sweepable(0), sweepable(1)],
            WitnessSeed::default(),
        )
        .unwrap();
        let (parent_version, _) = parent.read_jmt_metadata();
        let all = SweepBucket(u32::MAX);
        assert_eq!(
            parent.sweep_candidates(SweepFrontier::ZERO, all, 10).len(),
            2,
            "the parent holds both sides"
        );

        for side in [0u8, 1u8] {
            let child_dir = TempDir::new().unwrap();
            let target = child_dir.path().join("store");
            parent.checkpoint_into(&target).unwrap();
            let child = RocksDbShardStorage::open(&target, child_path(side)).unwrap();
            let child_root = child_root_from_parent(&parent, parent_version, side);
            child
                .adopt_genesis(
                    origin_at_10(),
                    &genesis_at_10(child_of(side), child_root),
                    AdoptSource::ParentSubtree,
                )
                .unwrap();
            assert_eq!(
                child.sweep_candidates(SweepFrontier::ZERO, all, 10),
                vec![(sweepable(side).key, expiry)],
                "child {side} sweeps its own cell and not its sibling's"
            );
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
            let child_root = child_root_from_parent(&parent, parent_version, side);
            let genesis = genesis_at_10(child_of(side), child_root);
            let root = child
                .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
                .unwrap();
            assert_eq!(root, child_root, "adoption returns the attested child root");
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
            let recovered = child.load_recovered_state(child_of(side));
            assert_eq!(recovered.committed_height, BlockHeight::new(10));
            assert_eq!(recovered.committed_hash, Some(genesis.hash()));
            assert!(recovered.latest_qc.is_none());
            assert_eq!(recovered.chain_origin, origin_at_10());

            // Idempotent: a re-run lands on the same values.
            assert_eq!(
                child
                    .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
                    .unwrap(),
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
        assert!(
            child
                .adopt_genesis(stale, &genesis, AdoptSource::ParentSubtree)
                .is_err()
        );
    }

    /// Make-before-break coasts the parent an unbounded number of empty blocks
    /// past its terminal before the seed checkpoints it, so the checkpoint
    /// version sits above the child's genesis height. The adoption accepts it —
    /// the frozen coast leaves the child subtree unchanged — and still verifies
    /// the extracted root against the attested genesis.
    #[test]
    fn adopts_a_child_from_a_parent_coasted_past_the_terminal() {
        let parent_dir = TempDir::new().unwrap();
        let parent = RocksDbShardStorage::open(parent_dir.path(), NibblePath::empty()).unwrap();
        // The committed version (12) sits above the child genesis height (10) —
        // the coast a make-before-break predecessor runs past its cut.
        import_boundary_state(
            &parent,
            BlockHeight::new(12),
            &[leaf(0x00), leaf(0x01), leaf(0x80)],
            WitnessSeed::default(),
        )
        .unwrap();
        let (parent_version, _) = parent.read_jmt_metadata();
        assert_eq!(parent_version, 12);

        let child_dir = TempDir::new().unwrap();
        let target = child_dir.path().join("store");
        parent.checkpoint_into(&target).unwrap();
        let child = RocksDbShardStorage::open(&target, child_path(0)).unwrap();
        let child_root = child_root_from_parent(&parent, parent_version, 0);
        let genesis = genesis_at_10(child_of(0), child_root);
        // checkpoint_version 12 is three past the genesis height 10 — rejected
        // by the old at-or-one-below vintage check, accepted now.
        let root = child
            .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
            .unwrap();
        assert_eq!(root, child_root);
        assert_eq!(child.read_jmt_metadata(), (10, root));
    }

    /// A genesis claiming a child root the checkpoint does not hold fails
    /// closed — the equality check is the safety guarantee once the vintage
    /// check is relaxed to admit an arbitrarily long coast.
    #[test]
    fn adoption_rejects_a_forged_genesis_root() {
        let parent_dir = TempDir::new().unwrap();
        let parent = parent_store(parent_dir.path());
        let child_dir = TempDir::new().unwrap();
        let target = child_dir.path().join("store");
        parent.checkpoint_into(&target).unwrap();
        let child = RocksDbShardStorage::open(&target, child_path(0)).unwrap();
        let forged = genesis_at_10(
            child_of(0),
            StateRoot::from_raw(Hash::from_bytes(b"forged")),
        );
        assert!(
            child
                .adopt_genesis(origin_at_10(), &forged, AdoptSource::ParentSubtree)
                .is_err()
        );
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
        let root = import_boundary_state(
            &storage,
            BlockHeight::new(10),
            &[leaf(0x00), leaf(0x80)],
            WitnessSeed::default(),
        )
        .unwrap();
        assert_ne!(root, StateRoot::ZERO);

        let genesis = merge_genesis(root);
        assert_eq!(genesis.height(), BlockHeight::new(10));
        let origin = ChainOrigin {
            genesis_height: genesis.height(),
            anchor_wt: cut,
        };

        let adopted = storage
            .adopt_genesis(origin, &genesis, AdoptSource::InPlace)
            .unwrap();
        assert_eq!(adopted, root);
        assert_eq!(storage.read_jmt_metadata(), (10, root));
        assert_eq!(read_chain_origin(&*storage.db), origin);
        // Idempotent re-run returns the recorded adoption.
        assert_eq!(
            storage
                .adopt_genesis(origin, &genesis, AdoptSource::InPlace)
                .unwrap(),
            root
        );

        // A genesis claiming a different root fails closed.
        let dir2 = TempDir::new().unwrap();
        let other = RocksDbShardStorage::open(dir2.path(), NibblePath::empty()).unwrap();
        import_boundary_state(
            &other,
            BlockHeight::new(10),
            &[leaf(0x00), leaf(0x80)],
            WitnessSeed::default(),
        )
        .unwrap();
        let wrong = merge_genesis(StateRoot::from_raw(Hash::from_bytes(b"forged")));
        assert!(
            other
                .adopt_genesis(origin, &wrong, AdoptSource::InPlace)
                .is_err()
        );
    }

    /// An empty side adopts a zero root with a zero count — the child
    /// starts from an empty tree at its genesis height.
    #[test]
    fn empty_side_adopts_a_zero_root() {
        let parent_dir = TempDir::new().unwrap();
        let storage = RocksDbShardStorage::open(parent_dir.path(), NibblePath::empty()).unwrap();
        // Both leaves on the left: the right child is empty.
        import_boundary_state(
            &storage,
            BlockHeight::new(9),
            &[leaf(0x00), leaf(0x01)],
            WitnessSeed::default(),
        )
        .unwrap();

        let child_dir = TempDir::new().unwrap();
        let target = child_dir.path().join("store");
        storage.checkpoint_into(&target).unwrap();
        let child = RocksDbShardStorage::open(&target, child_path(1)).unwrap();
        let genesis = genesis_at_10(child_of(1), StateRoot::ZERO);
        let root = child
            .adopt_genesis(origin_at_10(), &genesis, AdoptSource::ParentSubtree)
            .unwrap();
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

        use hyperscale_storage::test_helpers::{block_settling, make_state_writes, seeded_owner};
        use hyperscale_types::{ConsensusReceipt, GlobalReceiptHash, Hash, StoredReceipt, TxHash};

        let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
        let whole = RocksDbShardStorage::open(dirs[0].path(), NibblePath::empty()).unwrap();
        let left = RocksDbShardStorage::open(dirs[1].path(), child_path(0)).unwrap();
        let right = RocksDbShardStorage::open(dirs[2].path(), child_path(1)).unwrap();

        let mut sides_hit = [false, false];
        let mut roots = (StateRoot::ZERO, StateRoot::ZERO, StateRoot::ZERO);
        for seed in 1u8..=8 {
            let owner = seeded_owner(seed);
            let writes = make_state_writes(owner, seed, vec![seed; 4]);
            let receipts = [StoredReceipt::synced(
                TxHash::from(Hash::from_bytes(&[seed])),
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes,
                    beacon_witness_events: Vec::new(),
                    events: Vec::new(),
                }),
            )];
            let block = block_settling(BlockHeight::new(u64::from(seed)), receipts.to_vec());
            roots = (
                whole.follow_block_writes(&block, &[]).unwrap(),
                left.follow_block_writes(&block, &[]).unwrap(),
                right.follow_block_writes(&block, &[]).unwrap(),
            );
            // The leaf key is the owner prefix by identity, so the side a
            // write lands on is that prefix's leading bit.
            sides_hit[usize::from(owner >> 7)] = true;
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
            let adopted = store
                .adopt_genesis(origin, &genesis, AdoptSource::FollowedTip)
                .unwrap();
            assert_eq!(adopted, followed_root);
            assert_eq!(store.read_jmt_metadata(), (9, followed_root));
            assert!(store.substate_bytes_at_version(9).is_some());
            assert_eq!(read_chain_origin(&*store.db), origin);
            let recovered = store.load_recovered_state(ShardId::ROOT);
            assert_eq!(recovered.committed_height, BlockHeight::new(9));
            assert_eq!(recovered.committed_hash, Some(genesis.hash()));
            assert!(recovered.latest_qc.is_none());
            // Idempotent: a re-run lands on the same values.
            assert_eq!(
                store
                    .adopt_genesis(origin, &genesis, AdoptSource::FollowedTip)
                    .unwrap(),
                adopted
            );
        }
    }
}
