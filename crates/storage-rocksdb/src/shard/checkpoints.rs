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
use hyperscale_storage::tree::import_leaf_updates;
use hyperscale_storage::{BoundaryStore, ImportLeaf, ResolveLeaf};
use hyperscale_types::{BlockHeight, Hash, StateRoot};
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{DB, Options, WriteBatch};
use tracing::warn;

use super::column_families::{
    ALL_COLUMN_FAMILIES, CfHandles, JmtNodesCf, LeafAssociationsCf, StateCf,
};
use super::core::RocksDbShardStorage;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::jmt_stored::{StoredNode, StoredNodeKey, VersionedStoredNode};
use super::metadata::{read_jmt_metadata, write_jmt_metadata};
use crate::StorageError;
use crate::typed_cf::{TypedCf, batch_put, get};

/// A ring of `RocksDB` checkpoints pinned at epoch-boundary heights.
///
/// Owned by [`RocksDbShardStorage`] and driven through
/// [`BoundaryStore`]. Holds the newest [`Self::retain`] checkpoints;
/// creating a new one evicts the oldest beyond that. Entries are
/// discovered by scanning the ring directory, so the ring picks up
/// where it left off after a restart.
pub struct CheckpointRing {
    db: Arc<DB>,
    dir: PathBuf,
    retain: usize,
}

impl CheckpointRing {
    /// Create a ring over `db`, rooted at `dir`.
    ///
    /// `dir` is created lazily on first checkpoint. `retain` is the ring
    /// size — how many checkpoints survive eviction.
    ///
    /// # Panics
    ///
    /// Panics if `retain` is zero — a zero-size ring would evict every
    /// checkpoint as soon as it is created.
    pub(crate) fn from_db(db: Arc<DB>, dir: PathBuf, retain: usize) -> Self {
        assert!(retain > 0, "checkpoint ring must retain at least one entry");
        Self { db, dir, retain }
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
    pub fn create(&self, height: BlockHeight) -> Result<PathBuf, StorageError> {
        let final_path = self.dir.join(entry_name(height));
        if final_path.exists() {
            return Ok(final_path);
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
        Ok(final_path)
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
        let excess = entries.len().saturating_sub(self.retain);
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
        self.checkpoints
            .create(height)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn open_boundary(&self, height: BlockHeight) -> Option<CheckpointStore> {
        let (_, path) = self
            .checkpoints
            .entries()
            .into_iter()
            .find(|(h, _)| *h == height)?;
        CheckpointStore::open(&path, self.root_path.clone()).ok()
    }

    fn import_boundary_state(
        &self,
        height: BlockHeight,
        leaves: Vec<ImportLeaf>,
    ) -> Result<StateRoot, String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let (version, root) = self.read_jmt_metadata();
        if version != 0 || root != StateRoot::ZERO {
            return Err("snap-sync import requires an empty store".to_string());
        }

        let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
        let (imported_root, result) =
            import_leaf_updates(&snapshot_store, &self.root_path, height, &leaves)?;

        let cf = CfHandles::resolve(&self.db);
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
        write_jmt_metadata(&mut batch, height.inner(), imported_root);

        self.db
            .write(batch)
            .map_err(|e| format!("snap-sync import write: {e}"))?;
        Ok(imported_root)
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
    use hyperscale_storage::test_helpers::make_database_update;
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
        let chunk = Jmt::collect_range(&store, &root_key, &start, 1_000).unwrap();
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

        // One past the ring size: the oldest pin is evicted.
        for height in 1..=(BOUNDARY_RETAIN as u64 + 1) {
            commit_one(&storage, u8::try_from(height).unwrap());
            storage.pin_boundary(BlockHeight::new(height)).unwrap();
        }

        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        assert!(
            !temp
                .path()
                .join("checkpoints")
                .join(entry_name(BlockHeight::new(1)))
                .exists()
        );
        assert!(storage.open_boundary(BlockHeight::new(2)).is_some());
        assert!(
            storage
                .open_boundary(BlockHeight::new(BOUNDARY_RETAIN as u64 + 1))
                .is_some()
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
        commit_one(&storage, 1);
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        for seed in 1..=6u8 {
            commit_one(&storage, seed);
        }
        let source_root = storage.state_root();
        storage.pin_boundary(BlockHeight::new(6)).unwrap();

        let boundary = storage.open_boundary(BlockHeight::new(6)).expect("pinned");
        let root_key = boundary.get_root_key(6).expect("root resolves");
        let chunk = Jmt::collect_range(&boundary, &root_key, &[0u8; 32], 1_000).unwrap();
        let leaves: Vec<ImportLeaf> = chunk
            .leaves
            .iter()
            .map(|(leaf_key, _)| {
                let (storage_key, value) = boundary.resolve_leaf(leaf_key).expect("resolves");
                ImportLeaf {
                    leaf_key: *leaf_key,
                    storage_key,
                    value,
                }
            })
            .collect();

        let fresh_dir = TempDir::new().unwrap();
        let fresh = open_storage(fresh_dir.path());
        let imported_root = fresh
            .import_boundary_state(BlockHeight::new(6), leaves)
            .unwrap();
        assert_eq!(imported_root, source_root);
        assert_eq!(fresh.state_root(), source_root);

        // A second import is rejected — the store is no longer empty.
        assert!(
            fresh
                .import_boundary_state(BlockHeight::new(6), Vec::new())
                .is_err()
        );
    }
}
