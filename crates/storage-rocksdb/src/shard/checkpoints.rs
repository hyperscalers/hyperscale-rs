//! `RocksDB` checkpoint ring for snap-sync serving.
//!
//! A serving shard member pins its state at recent epoch-boundary blocks
//! so a joining vnode can snap-sync against the beacon-attested boundary
//! `state_root` while the live DB keeps committing and garbage-collecting.
//! `RocksDB` checkpoints are hard-link snapshots: cheap to create, immune
//! to the live DB's GC, and openable read-only at any time.
//!
//! Each checkpoint is a directory named `h-{height:020}` under the ring
//! root. The ring is stateless — entries are discovered by directory
//! scan, so retention survives restarts. Creation goes through a
//! dot-prefixed temporary name and a rename, so a crash mid-create
//! leaves only a `.tmp-*` directory, swept on the next creation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyperscale_jmt::{Key, NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::tree::{import_leaf_updates, jmt_parent_height, put_at_version};
use hyperscale_storage::{
    BOUNDARY_RETAIN, BoundaryStore, ImportLeaf, ImportProgress, JmtSnapshot, ResolveLeaf,
    WitnessSeed, filter_updates_to_prefix, merge_owned_nodes, merge_updates_from_receipts,
};
use hyperscale_types::{Block, BlockHeight, ChainOrigin, Hash, StateRoot, StoredReceipt};
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{ColumnFamily, DB, Options, WriteBatch};
use tracing::warn;

use super::column_families::{
    ALL_COLUMN_FAMILIES, BeaconWitnessesCf, CfHandles, ImportStagingCf, JmtNodesCf,
    LeafAssociationsCf, StateCf, SubstateBytesCf,
};
use super::core::RocksDbShardStorage;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::jmt_stored::{StoredNode, StoredNodeKey, VersionedStoredNode};
use super::metadata::{read_jmt_metadata, write_jmt_metadata};
use crate::StorageError;
use crate::typed_cf::{
    ImportProgressEntry, TypedCf, batch_put, batch_put_raw, get, iter_all, meta_delete, meta_read,
    meta_write,
};

/// Queue the staging CF's full range and the progress record for
/// deletion in `batch`. Staged keys are exactly 32 bytes, so a 33-byte
/// `0xFF` bound covers every possible key.
fn wipe_staging_into(batch: &mut WriteBatch, staging_cf: &ColumnFamily) {
    batch.delete_range_cf(staging_cf, &[][..], &[0xFF; 33][..]);
    meta_delete::<ImportProgressEntry>(batch);
}

/// A ring of `RocksDB` checkpoints pinned at epoch-boundary heights.
///
/// Owned by [`RocksDbShardStorage`] and driven through
/// [`BoundaryStore`]. Holds the newest [`BOUNDARY_RETAIN`] checkpoints;
/// creating a new one evicts the oldest beyond that. Entries are
/// discovered by scanning the ring directory, so the ring picks up
/// where it left off after a restart.
pub struct CheckpointRing {
    db: Arc<DB>,
    dir: PathBuf,
}

impl CheckpointRing {
    /// Create a ring over `db`, rooted at `dir`. The directory is
    /// created lazily on first checkpoint.
    pub(crate) const fn from_db(db: Arc<DB>, dir: PathBuf) -> Self {
        Self { db, dir }
    }

    /// Create a checkpoint of the database's current state, labelled with
    /// the committed block `height` it captures, then evict entries
    /// beyond the ring size.
    ///
    /// Idempotent: if a checkpoint for `height` already exists it is kept
    /// as-is (a replayed commit must not clobber a checkpoint a joiner
    /// may be reading).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if checkpoint creation or the filesystem
    /// rename fails. Eviction failures are logged, not returned — a
    /// stale extra checkpoint costs disk, not correctness.
    /// The deterministic on-disk path for `height`'s checkpoint —
    /// present only while the height is pinned.
    pub(crate) fn entry_path(&self, height: BlockHeight) -> PathBuf {
        self.dir.join(entry_name(height))
    }

    pub fn create(&self, height: BlockHeight) -> Result<(), StorageError> {
        let final_path = self.entry_path(height);
        if final_path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint dir: {e}")))?;
        self.sweep_tmp();

        // Create under a temporary name, then rename: a crash mid-create
        // leaves a `.tmp-*` directory the next creation sweeps, never a
        // plausible-looking partial checkpoint.
        let tmp_path = self.dir.join(format!(".tmp-{}", entry_name(height)));
        Checkpoint::new(&self.db)
            .and_then(|cp| cp.create_checkpoint(&tmp_path))
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint create: {e}")))?;
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint rename: {e}")))?;

        self.evict();
        Ok(())
    }

    /// All checkpoints in the ring, ascending by height.
    #[must_use]
    pub fn entries(&self) -> Vec<(BlockHeight, PathBuf)> {
        let Ok(read) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut entries: Vec<(BlockHeight, PathBuf)> = read
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name();
                let height = parse_entry_name(name.to_str()?)?;
                Some((height, e.path()))
            })
            .collect();
        entries.sort_unstable_by_key(|(h, _)| *h);
        entries
    }

    /// Remove the oldest entries beyond the ring size.
    fn evict(&self) {
        let entries = self.entries();
        let excess = entries.len().saturating_sub(BOUNDARY_RETAIN);
        for (height, path) in entries.into_iter().take(excess) {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                warn!(%height, path = %path.display(), error = %e, "checkpoint eviction failed");
            }
        }
    }

    /// Remove leftover `.tmp-*` directories from interrupted creations.
    fn sweep_tmp(&self) {
        let Ok(read) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in read.filter_map(Result::ok) {
            let name = entry.file_name();
            if name.to_str().is_some_and(|n| n.starts_with(".tmp-"))
                && let Err(e) = std::fs::remove_dir_all(entry.path())
            {
                warn!(path = %entry.path().display(), error = %e, "tmp checkpoint sweep failed");
            }
        }
    }
}

/// A checkpoint opened read-only for serving snap-sync range reads.
///
/// Exposes the JMT (via [`TreeReader`]) and raw substate values at the
/// checkpoint's pinned state. The underlying hard-linked files keep the
/// captured SSTs alive even after the live DB compacts or GCs them.
pub struct CheckpointStore {
    db: DB,
    root_path: NibblePath,
}

impl CheckpointStore {
    /// Open a checkpoint directory read-only.
    ///
    /// `root_path` must be the prefix the shard's JMT is rooted at — the
    /// same value the originating store was opened with.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the directory is not an openable
    /// `RocksDB` database with the expected column families.
    pub fn open(path: &Path, root_path: NibblePath) -> Result<Self, StorageError> {
        let opts = Options::default();
        let db = DB::open_cf_for_read_only(&opts, path, ALL_COLUMN_FAMILIES, false)
            .map_err(|e| StorageError::DatabaseError(format!("checkpoint open: {e}")))?;
        Ok(Self { db, root_path })
    }

    /// The checkpoint's JMT version and root hash — the committed tip the
    /// checkpoint captured. Returns `(version, root)`.
    #[must_use]
    pub fn read_jmt_metadata(&self) -> (u64, StateRoot) {
        read_jmt_metadata(&self.db)
    }
}

impl TreeReader for CheckpointStore {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        let cf = CfHandles::resolve(&self.db);
        let stored_key = StoredNodeKey::from_jmt(key);
        get::<JmtNodesCf>(&self.db, JmtNodesCf::handle(&cf), &stored_key)
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        let root = JmtNodeKey::new(version, self.root_path.clone());
        self.get_node(&root).map(|_| root)
    }

    fn root_path(&self) -> NibblePath {
        self.root_path.clone()
    }
}

impl ResolveLeaf for CheckpointStore {
    fn resolve_leaf(&self, leaf_key: &Key) -> Option<(Vec<u8>, Vec<u8>)> {
        let cf = CfHandles::resolve(&self.db);
        let hashed = Hash::from_hash_bytes(leaf_key);
        let storage_key =
            get::<LeafAssociationsCf>(&self.db, LeafAssociationsCf::handle(&cf), &hashed)?;
        // The association's stored bytes ARE the state CF key encoding
        // (`SubstateKeyCodec` is a raw concatenation), so the value read
        // skips the typed decode/encode round-trip.
        let value = self
            .db
            .get_cf(StateCf::handle(&cf), &storage_key)
            .ok()
            .flatten()?;
        Some((storage_key, value))
    }
}

impl BoundaryStore for RocksDbShardStorage {
    type Boundary = CheckpointStore;

    fn pin_boundary(&self, height: BlockHeight) -> Result<(), String> {
        self.checkpoints.create(height).map_err(|e| e.to_string())
    }

    fn open_boundary(&self, height: BlockHeight) -> Option<CheckpointStore> {
        let path = self.checkpoints.entry_path(height);
        path.exists()
            .then(|| CheckpointStore::open(&path, self.root_path.clone()).ok())
            .flatten()
    }

    fn stage_import_chunk(
        &self,
        progress: &ImportProgress,
        leaves: &[ImportLeaf],
    ) -> Result<(), String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let (version, root) = self.read_jmt_metadata();
        if version != 0 || root != StateRoot::ZERO {
            return Err("snap-sync staging requires an empty store".to_string());
        }

        let cf = CfHandles::resolve(&self.db);
        let staging_cf = ImportStagingCf::handle(&cf);
        let mut batch = WriteBatch::default();
        for leaf in leaves {
            let mut value = Vec::with_capacity(4 + leaf.storage_key.len() + leaf.value.len());
            let key_len =
                u32::try_from(leaf.storage_key.len()).map_err(|_| "oversized storage key")?;
            value.extend_from_slice(&key_len.to_be_bytes());
            value.extend_from_slice(&leaf.storage_key);
            value.extend_from_slice(&leaf.value);
            batch_put_raw::<ImportStagingCf>(
                &mut batch,
                staging_cf,
                &Hash::from_hash_bytes(&leaf.leaf_key),
                &(Vec::new(), Vec::new()),
                Some(&value),
            );
        }
        meta_write::<ImportProgressEntry>(&mut batch, progress);
        self.db
            .write(batch)
            .map_err(|e| format!("snap-sync staging write: {e}"))
    }

    fn read_import_progress(&self) -> Option<ImportProgress> {
        meta_read::<ImportProgressEntry>(&*self.db)
    }

    fn wipe_import_staging(&self) -> Result<(), String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let cf = CfHandles::resolve(&self.db);
        let mut batch = WriteBatch::default();
        wipe_staging_into(&mut batch, ImportStagingCf::handle(&cf));
        self.db
            .write(batch)
            .map_err(|e| format!("snap-sync staging wipe: {e}"))
    }

    fn finalize_boundary_import(
        &self,
        height: BlockHeight,
        witnesses: WitnessSeed,
    ) -> Result<StateRoot, String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let (version, root) = self.read_jmt_metadata();
        if version != 0 || root != StateRoot::ZERO {
            return Err("snap-sync import requires an empty store".to_string());
        }

        let cf = CfHandles::resolve(&self.db);
        let staging_cf = ImportStagingCf::handle(&cf);
        let leaves: Vec<ImportLeaf> = iter_all::<ImportStagingCf>(&self.db, staging_cf)
            .map(|(leaf_key, (storage_key, value))| ImportLeaf {
                leaf_key: *leaf_key.as_bytes(),
                storage_key,
                value,
            })
            .collect();

        let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
        let (imported_root, result) =
            import_leaf_updates(&snapshot_store, &self.root_path, height, &leaves)?;

        let mut batch = WriteBatch::default();
        for (node_key, node) in &result.batch.new_nodes {
            batch_put::<JmtNodesCf>(
                &mut batch,
                JmtNodesCf::handle(&cf),
                &StoredNodeKey::from_jmt(node_key),
                &VersionedStoredNode::from_latest(StoredNode::from_jmt(node)),
            );
        }
        let state_cf = StateCf::handle(&cf);
        let assoc_cf = LeafAssociationsCf::handle(&cf);
        for leaf in &leaves {
            // The raw storage key IS the state CF key encoding
            // (`SubstateKeyCodec` is a raw concatenation).
            batch.put_cf(state_cf, &leaf.storage_key, &leaf.value);
            batch_put::<LeafAssociationsCf>(
                &mut batch,
                assoc_cf,
                &Hash::from_hash_bytes(&leaf.leaf_key),
                &leaf.storage_key,
            );
        }
        // Seed the anchor window's witness payloads at their absolute leaf
        // indices, exactly where a store that committed through the
        // boundary would hold them: the accumulator rebuilds from this
        // column on restart, and the beacon fold's witness fetches answer
        // from it.
        let witness_cf = BeaconWitnessesCf::handle(&cf);
        for (offset, payload) in witnesses.payloads.iter().enumerate() {
            batch_put::<BeaconWitnessesCf>(
                &mut batch,
                witness_cf,
                &(witnesses.base.inner() + offset as u64),
                payload,
            );
        }
        // Seed the substate byte total: a fresh-tree import's byte delta IS
        // the imported leaves' value bytes.
        let bytes = u64::try_from(result.batch.bytes_delta)
            .map_err(|_| "snap-sync import produced a negative byte total".to_string())?;
        batch_put::<SubstateBytesCf>(
            &mut batch,
            SubstateBytesCf::handle(&cf),
            &height.inner(),
            &bytes,
        );
        write_jmt_metadata(&mut batch, height.inner(), imported_root);
        // The metadata write is the completion marker; the staging
        // range-delete rides the same batch so a finalized store never
        // carries staged bytes.
        wipe_staging_into(&mut batch, staging_cf);

        self.db
            .write(batch)
            .map_err(|e| format!("snap-sync import write: {e}"))?;
        Ok(imported_root)
    }

    fn follow_block_writes(
        &self,
        height: BlockHeight,
        receipts: &[StoredReceipt],
    ) -> Result<StateRoot, String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();
        if height.inner() <= base_version {
            return Err(format!(
                "follow at height {height} does not advance the store's version {base_version}",
            ));
        }

        let owner_map = merge_owned_nodes(receipts);
        let merged = merge_updates_from_receipts(receipts);
        let filtered = filter_updates_to_prefix(&merged, &owner_map, &self.root_path);
        if filtered.node_updates.is_empty() {
            return Ok(base_root);
        }

        let (mut batch, reset_old_keys) = self.build_substate_write_batch(
            &filtered,
            height.inner(),
            /* write_history */ true,
            /* base_reads */ None,
        );
        let parent_version =
            jmt_parent_height(BlockHeight::new(base_version), base_root).map(BlockHeight::inner);
        let (new_root, collected) = put_at_version(
            &snapshot_store,
            parent_version,
            height.inner(),
            &[&filtered],
            &reset_old_keys,
            &owner_map,
        );
        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            base_root,
            BlockHeight::new(base_version),
            new_root,
            height,
        );
        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, height.inner());
        self.db
            .write(batch)
            .map_err(|e| format!("follow write failed: {e}"))?;
        Ok(new_root)
    }

    fn adopt_split_child(&self, origin: ChainOrigin, genesis: &Block) -> Result<StateRoot, String> {
        Self::adopt_split_child(self, origin, genesis).map_err(|e| e.to_string())
    }

    fn adopt_followed_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        Self::adopt_followed_child(self, origin, genesis).map_err(|e| e.to_string())
    }

    fn adopt_merge_parent(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        Self::adopt_merge_parent(self, origin, genesis).map_err(|e| e.to_string())
    }

    fn substate_bytes_at_version(&self, version: u64) -> Option<u64> {
        Self::substate_bytes_at_version(self, version)
    }
}

/// Directory name for a checkpoint at `height` — zero-padded so
/// lexicographic order matches numeric order.
fn entry_name(height: BlockHeight) -> String {
    format!("h-{:020}", height.inner())
}

/// Parse a checkpoint directory name back to its height.
fn parse_entry_name(name: &str) -> Option<BlockHeight> {
    name.strip_prefix("h-")?.parse().ok().map(BlockHeight::new)
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, Tree};
    use hyperscale_storage::test_helpers::{
        completed_import_progress, import_boundary_state, make_database_update,
        test_boundary_import_roundtrip, test_boundary_retention_evicts_oldest,
        test_boundary_unpinned_height_not_served,
    };
    use hyperscale_storage::{BOUNDARY_RETAIN, SubstateStore};
    use tempfile::TempDir;

    use super::*;

    type Jmt = Tree<Blake3Hasher, 1>;

    fn open_storage(dir: &Path) -> RocksDbShardStorage {
        RocksDbShardStorage::open(dir, NibblePath::empty()).unwrap()
    }

    fn commit_one(storage: &RocksDbShardStorage, seed: u8) {
        let updates = make_database_update(vec![seed; 50], 0, vec![seed], vec![seed, seed, seed]);
        storage.commit(&updates).unwrap();
    }

    #[test]
    fn pin_open_and_serve_verified_range() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        commit_one(&storage, 1);
        commit_one(&storage, 2);
        let expected_root = storage.state_root();

        storage.pin_boundary(BlockHeight::new(2)).unwrap();

        let store = storage.open_boundary(BlockHeight::new(2)).expect("pinned");
        let (version, root) = store.read_jmt_metadata();
        assert_eq!(version, 2);
        assert_eq!(root, expected_root);

        // The checkpoint serves a completeness-checked range straight off
        // the snap-sync verifier.
        let root_key = store.get_root_key(version).expect("root resolves");
        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let chunk = Jmt::collect_range(&store, &root_key, &start, &end, 1_000).unwrap();
        assert!(!chunk.leaves.is_empty());
        assert!(!chunk.more);
        let proof = Jmt::prove_range(&store, &root_key, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            *root.as_raw().as_bytes(),
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn checkpoint_is_isolated_from_later_commits() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        commit_one(&storage, 1);
        let pinned_root = storage.state_root();

        storage.pin_boundary(BlockHeight::new(1)).unwrap();

        commit_one(&storage, 2);
        assert_ne!(storage.state_root(), pinned_root);

        let store = storage.open_boundary(BlockHeight::new(1)).expect("pinned");
        let (version, root) = store.read_jmt_metadata();
        assert_eq!(version, 1);
        assert_eq!(root, pinned_root);
    }

    #[test]
    fn retention_evicts_oldest() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        test_boundary_retention_evicts_oldest(&storage, |seed| commit_one(&storage, seed));
    }

    /// Eviction removes the checkpoint's on-disk directory, not just
    /// its serving entry.
    #[test]
    fn eviction_removes_the_checkpoint_directory() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        for height in 1..=(BOUNDARY_RETAIN as u64 + 1) {
            commit_one(&storage, u8::try_from(height).unwrap());
            storage.pin_boundary(BlockHeight::new(height)).unwrap();
        }
        assert!(
            !temp
                .path()
                .join("checkpoints")
                .join(entry_name(BlockHeight::new(1)))
                .exists()
        );
    }

    #[test]
    fn pin_is_idempotent_per_height() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        commit_one(&storage, 1);

        storage.pin_boundary(BlockHeight::new(1)).unwrap();
        storage.pin_boundary(BlockHeight::new(1)).unwrap();
        assert_eq!(storage.checkpoints.entries().len(), 1);
        assert!(storage.open_boundary(BlockHeight::new(1)).is_some());
    }

    #[test]
    fn ring_survives_reopen_via_directory_scan() {
        let temp = TempDir::new().unwrap();
        {
            let storage = open_storage(temp.path());
            commit_one(&storage, 1);
            storage.pin_boundary(BlockHeight::new(1)).unwrap();
        }

        // A fresh storage over the same directory sees the existing pin.
        let revived = open_storage(temp.path());
        assert!(revived.open_boundary(BlockHeight::new(1)).is_some());
    }

    #[test]
    fn open_missing_checkpoint_errors() {
        let temp = TempDir::new().unwrap();
        let err = CheckpointStore::open(&temp.path().join("nope"), NibblePath::empty());
        assert!(err.is_err());
    }

    #[test]
    fn unpinned_height_is_not_served() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        test_boundary_unpinned_height_not_served(&storage, |seed| commit_one(&storage, seed));
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        let fresh_dir = TempDir::new().unwrap();
        let fresh = open_storage(fresh_dir.path());
        test_boundary_import_roundtrip(&storage, &fresh, |seed| commit_one(&storage, seed));
    }

    /// An import leaf whose top byte places it under one trie half.
    fn staged_leaf(top: u8) -> ImportLeaf {
        let mut key = [0u8; 32];
        key[0] = top;
        ImportLeaf {
            leaf_key: key,
            storage_key: vec![top; 40],
            value: vec![top; 3],
        }
    }

    /// Chunk-by-chunk staging finalizes to the same root as a one-shot
    /// import of the identical leaf set, clears the staging area, and
    /// keeps the latest progress record until then.
    #[test]
    fn staged_chunks_finalize_to_the_one_shot_root() {
        let leaves = [
            staged_leaf(0x00),
            staged_leaf(0x11),
            staged_leaf(0x80),
            staged_leaf(0xEE),
        ];
        let height = BlockHeight::new(7);

        let one_shot_dir = TempDir::new().unwrap();
        let one_shot = open_storage(one_shot_dir.path());
        let expected =
            import_boundary_state(&one_shot, height, &leaves, WitnessSeed::default()).unwrap();

        let staged_dir = TempDir::new().unwrap();
        let staged = open_storage(staged_dir.path());
        // Stage out of leaf order across two chunks: the leaf-keyed CF
        // hands finalize a sorted scan regardless.
        let progress = completed_import_progress(height, 12);
        staged.stage_import_chunk(&progress, &leaves[2..]).unwrap();
        staged.stage_import_chunk(&progress, &leaves[..2]).unwrap();
        assert_eq!(staged.read_import_progress(), Some(progress));

        let root = staged
            .finalize_boundary_import(height, WitnessSeed::default())
            .unwrap();
        assert_eq!(root, expected);
        assert_eq!(staged.read_jmt_metadata(), (7, expected));
        assert_eq!(staged.read_import_progress(), None);
    }

    /// A wipe discards the staged chunks and the progress record.
    #[test]
    fn wipe_discards_staged_chunks_and_progress() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        let progress = completed_import_progress(BlockHeight::new(3), 3);
        storage
            .stage_import_chunk(&progress, &[staged_leaf(0x42)])
            .unwrap();
        assert!(storage.read_import_progress().is_some());

        storage.wipe_import_staging().unwrap();
        assert_eq!(storage.read_import_progress(), None);
        // Nothing staged: the finalize builds an empty tree.
        let root = storage
            .finalize_boundary_import(BlockHeight::new(3), WitnessSeed::default())
            .unwrap();
        assert_eq!(root, StateRoot::ZERO);
    }

    /// Staging into a store that already holds state is rejected — the
    /// import is a bootstrap, not a merge.
    #[test]
    fn staging_into_a_non_empty_store_is_rejected() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        commit_one(&storage, 1);
        let progress = completed_import_progress(BlockHeight::new(2), 3);
        assert!(
            storage
                .stage_import_chunk(&progress, &[staged_leaf(0x42)])
                .is_err()
        );
    }
}
