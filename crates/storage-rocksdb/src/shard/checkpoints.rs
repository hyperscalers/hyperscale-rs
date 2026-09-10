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

use hyperscale_jmt::{KEY_BYTES, NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::tree::{import_leaf_updates, jmt_parent_height, put_at_version};
use hyperscale_storage::{
    AdoptSource, BoundaryStore, ImportProgress, JmtSnapshot, LeafRows, SubstateStore, Substates,
    SweepRows, WitnessSeed, followed_block_writes, holds_state, is_record_cell, key_under_prefix,
    prefix_low_key,
};
use hyperscale_types::{
    Block, BlockHeight, ChainOrigin, ShardId, StateRoot, SubstateKey, SubstateLeaf,
    shard_prefix_path,
};
use hyperscale_vm_types::{Address, CollectionId};
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{ColumnFamily, DB, Options, WriteBatch};
use tracing::warn;

use super::column_families::{
    ALL_COLUMN_FAMILIES, BeaconWitnessesCf, CfHandles, EntriesCf, ImportStagingCf, JmtNodesCf,
    PackageArtifactsCf, StateCf, SubstateBytesCf,
};
use super::core::{RocksDbShardStorage, fold_sweep_rows};
use super::entry_key::scan_entries;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::jmt_stored::{StoredNode, StoredNodeKey, VersionedStoredNode};
use super::metadata::{read_jmt_metadata, write_boundary_header, write_jmt_metadata};
use crate::StorageError;
use crate::typed_cf::{
    ImportProgressEntry, TypedCf, batch_delete, batch_put, get, iter_all, iter_from, meta_delete,
    meta_read, meta_write,
};

/// Write one import batch's leaves and re-derive every index that hangs
/// off them, returning the sweep rows for the caller to fold.
///
/// Each index is derived state, and rebuilding it from the leaves is the
/// assertion that it equals them: a row exists exactly where a leaf
/// re-derives it. That is what a successor needs — it holds the prefix
/// and no history, so the state it just imported is the only honest
/// source for what it owes.
fn index_imported_leaves(
    batch: &mut WriteBatch,
    cf: &CfHandles<'_>,
    leaves: &[SubstateLeaf],
) -> SweepRows {
    let state_cf = StateCf::handle(cf);
    let entries_cf = EntriesCf::handle(cf);
    let artifacts_cf = PackageArtifactsCf::handle(cf);
    let mut sweep_rows = SweepRows::default();
    for leaf in leaves {
        batch_put::<StateCf>(batch, state_cf, &leaf.key, &leaf.value);
        let LeafRows {
            entry,
            package,
            sweep,
        } = LeafRows::of(leaf.key, &leaf.value);
        if let Some((entry_key, value)) = entry {
            batch_put::<EntriesCf>(batch, entries_cf, &entry_key, &value);
        }
        // The package index earns its rebuild for a sharper reason: an
        // imported store whose committee turns over is the only place a
        // foreign shard can still fetch this artifact from.
        if let Some(package) = package {
            batch_put::<PackageArtifactsCf>(batch, artifacts_cf, &package, &leaf.value);
        }
        sweep_rows.delta(leaf.key.owner, None, sweep);
    }
    sweep_rows
}

/// Queue the staging CF's full range and the progress record for
/// deletion in `batch`. Staged keys are exactly [`KEY_BYTES`] long, so a
/// bound one byte longer and all `0xFF` sorts above every possible key.
fn wipe_staging_into(batch: &mut WriteBatch, staging_cf: &ColumnFamily) {
    batch.delete_range_cf(staging_cf, &[][..], &[0xFF; KEY_BYTES + 1][..]);
    meta_delete::<ImportProgressEntry>(batch);
}

/// Queue a full-range deletion of `cf` in `batch`. The exclusive upper
/// bound is the successor of the CF's current last key, so the range
/// covers every present entry regardless of key shape.
fn wipe_cf_into(batch: &mut WriteBatch, db: &DB, cf: &ColumnFamily) {
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_last();
    if let Some(last) = iter.key() {
        let mut end = last.to_vec();
        end.push(0x00);
        batch.delete_range_cf(cf, &[][..], &end[..]);
    }
}

/// Leaf-value weight applied per finalize batch: the JMT build for one
/// batch holds its leaves in memory, so this bounds finalize peak memory
/// independent of state size.
const IMPORT_BATCH_BYTES: u64 = 128 * 1024 * 1024;

/// Fixed per-leaf weight component (the 48-byte key, hashes, allocator
/// overhead), so a run of tiny values still bounds a batch's leaf count.
const IMPORT_LEAF_OVERHEAD: u64 = 96;

/// The batching weight of one staged leaf: its raw value length plus
/// the fixed overhead — [`count_staged_batches`] repeats this exact
/// arithmetic on raw staged values.
const fn leaf_weight(value: &[u8]) -> u64 {
    IMPORT_LEAF_OVERHEAD + value.len() as u64
}

/// Walk the staged leaves with the greedy batch rule — close a batch
/// once its accumulated weight reaches `limit` — returning the batch
/// count (at least 1; an empty staging area is one empty batch) and the
/// total staged weight. The apply pass repeats this exact walk, so the
/// count fixes its version numbering.
fn count_staged_batches(db: &DB, staging_cf: &ColumnFamily, limit: u64) -> (u64, u64) {
    let mut batches = 0u64;
    let mut batch_weight = 0u64;
    let mut total_weight = 0u64;
    let mut iter = db.raw_iterator_cf(staging_cf);
    iter.seek_to_first();
    while iter.valid() {
        let raw_len = iter.value().map_or(0, <[u8]>::len) as u64;
        let weight = IMPORT_LEAF_OVERHEAD + raw_len;
        batch_weight += weight;
        total_weight += weight;
        if batch_weight >= limit {
            batches += 1;
            batch_weight = 0;
        }
        iter.next();
    }
    if batch_weight > 0 || batches == 0 {
        batches += 1;
    }
    (batches, total_weight)
}

/// Seal the final import batch: the anchor window's witness payloads at
/// their absolute leaf indices (exactly where a store that committed
/// through the boundary would hold them — the accumulator rebuilds from
/// this column on restart, and the beacon fold's witness fetches answer
/// from it), the accumulated substate byte total (a fresh-tree import's
/// byte delta IS the imported leaves' value bytes), the JMT metadata —
/// the completion marker — and the staging wipe riding the same batch so
/// a finalized store never carries staged bytes.
fn seal_final_batch(
    batch: &mut WriteBatch,
    cf: &CfHandles<'_>,
    height: BlockHeight,
    witnesses: &WitnessSeed,
    bytes_total: i64,
    root: StateRoot,
) -> Result<(), String> {
    let witness_cf = BeaconWitnessesCf::handle(cf);
    for (offset, payload) in witnesses.payloads.iter().enumerate() {
        batch_put::<BeaconWitnessesCf>(
            batch,
            witness_cf,
            &(witnesses.base.inner() + offset as u64),
            payload,
        );
    }
    let bytes = u64::try_from(bytes_total)
        .map_err(|_| "snap-sync import produced a negative byte total".to_string())?;
    batch_put::<SubstateBytesCf>(batch, SubstateBytesCf::handle(cf), &height.inner(), &bytes);
    write_jmt_metadata(batch, height.inner(), root);
    wipe_staging_into(batch, ImportStagingCf::handle(cf));
    Ok(())
}

impl RocksDbShardStorage {
    /// Build the staged boundary state in JMT batches of at most
    /// `batch_limit` leaf weight, versions `height − K + 1 ..= height`
    /// (K = batch count), each persisted as one `WriteBatch` chaining on
    /// the previous batch's version. The final batch alone carries the
    /// witness seed, the accumulated substate byte total, the JMT
    /// metadata (the completion marker), and the staging wipe. When the
    /// chain is shallower than the batch count the limit grows so
    /// `K ≤ max(height, 1)`.
    ///
    /// `stop_after` truncates the build after that many batches with no
    /// completion marker — the crash-mid-finalize shape the re-run
    /// idempotence test exercises.
    /// Refuse a finalize the drivers should never request: a store that
    /// already holds state, or an assembly whose progress record binds
    /// `height` with open cursors. The drivers gate finalize on assembly
    /// completeness; a record that still claims this height while a
    /// cursor is open means a caller slipped past that gate, and
    /// refusing beats sealing a root that can never verify — that would
    /// poison the store for every later import attempt.
    fn check_finalize_preconditions(&self, height: BlockHeight) -> Result<(), String> {
        let (version, root) = self.read_jmt_metadata();
        if holds_state(BlockHeight::new(version), root) {
            return Err("snap-sync import requires an empty store".to_string());
        }
        if let Some(progress) = self.read_import_progress()
            && progress.anchor_height == height
            && !progress.cursors.iter().all(|cursor| cursor.done)
        {
            return Err("snap-sync finalize on an incomplete assembly".to_string());
        }
        Ok(())
    }

    fn finalize_staged(
        &self,
        height: BlockHeight,
        witnesses: &WitnessSeed,
        batch_limit: u64,
        stop_after: Option<u64>,
    ) -> Result<StateRoot, String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        self.check_finalize_preconditions(height)?;

        let cf = CfHandles::resolve(&self.db);
        let staging_cf = ImportStagingCf::handle(&cf);

        let k_max = height.inner().max(1);
        let (mut batches, total_weight) = count_staged_batches(&self.db, staging_cf, batch_limit);
        let mut limit = batch_limit;
        if batches > k_max {
            // A chain shallower than the batch count: grow the batches
            // to fit. With `limit ≥ ⌈total/k_max⌉` every closed batch
            // carries at least `limit` weight, so at most `k_max`
            // batches form.
            limit = batch_limit.max(total_weight.div_ceil(k_max));
            (batches, _) = count_staged_batches(&self.db, staging_cf, limit);
            assert!(
                batches <= k_max,
                "grown batch limit must fit the chain height",
            );
        }

        let mut parent: Option<u64> = None;
        let mut batch_version = height.inner() + 1 - batches;
        let mut applied = 0u64;
        let mut bytes_total: i64 = 0;
        let mut batch_leaves: Vec<SubstateLeaf> = Vec::new();
        let mut batch_weight = 0u64;

        let mut pending = iter_all::<ImportStagingCf>(&self.db, staging_cf).peekable();
        let imported_root = loop {
            let leaf = pending.next();
            if let Some((key, value)) = leaf {
                batch_weight += leaf_weight(&value);
                batch_leaves.push(SubstateLeaf { key, value });
                if batch_weight < limit && pending.peek().is_some() {
                    continue;
                }
            }
            // Close the batch: on reaching the weight limit, on the final
            // partial batch, or — for an empty staging area — as the one
            // empty batch that still lands the metadata.
            let is_final = pending.peek().is_none();
            let (root, result) = {
                let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
                import_leaf_updates(
                    &snapshot_store,
                    &self.root_path,
                    parent,
                    batch_version,
                    &batch_leaves,
                )?
            };

            let mut batch = WriteBatch::default();
            for (node_key, node) in &result.batch.new_nodes {
                batch_put::<JmtNodesCf>(
                    &mut batch,
                    JmtNodesCf::handle(&cf),
                    &StoredNodeKey::from_jmt(node_key),
                    &VersionedStoredNode::from_latest(StoredNode::from_jmt(node)),
                );
            }
            // Boundary-path nodes superseded across batches are dead the
            // moment this batch lands; deleting them here (instead of
            // routing through GC) keeps a finalized store orphan-free.
            for stale in &result.batch.stale_nodes {
                batch_delete::<JmtNodesCf>(
                    &mut batch,
                    JmtNodesCf::handle(&cf),
                    &StoredNodeKey::from_jmt(&stale.node_key),
                );
            }
            let sweep_rows = index_imported_leaves(&mut batch, &cf, &batch_leaves);
            fold_sweep_rows(&self.db, &mut batch, &cf, &sweep_rows);
            bytes_total += result.batch.bytes_delta;

            if is_final {
                seal_final_batch(&mut batch, &cf, height, witnesses, bytes_total, root)?;
            }

            self.db
                .write(batch)
                .map_err(|e| format!("snap-sync import write: {e}"))?;

            parent = Some(batch_version);
            batch_version += 1;
            applied += 1;
            batch_leaves.clear();
            batch_weight = 0;
            if is_final || stop_after.is_some_and(|stop| applied >= stop) {
                break root;
            }
        };
        Ok(imported_root)
    }
}

/// A ring of `RocksDB` checkpoints pinned at epoch-boundary heights.
///
/// Owned by [`RocksDbShardStorage`] and driven through
/// [`BoundaryStore`]. Holds the newest `retain` checkpoints (the
/// backend config's `boundary_retain`); creating a new one evicts the
/// oldest beyond that. Entries are
/// discovered by scanning the ring directory, so the ring picks up
/// where it left off after a restart.
#[derive(Clone)]
pub struct CheckpointRing {
    db: Arc<DB>,
    dir: PathBuf,
    retain: usize,
}

impl CheckpointRing {
    /// Create a ring over `db`, rooted at `dir`, retaining the newest
    /// `retain` checkpoints. The directory is created lazily on first
    /// checkpoint.
    pub(crate) const fn from_db(db: Arc<DB>, dir: PathBuf, retain: usize) -> Self {
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

impl Substates for CheckpointStore {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        let cf = CfHandles::resolve(&self.db);
        get::<StateCf>(&self.db, StateCf::handle(&cf), &key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        // The checkpoint is frozen at its pinned height, so its index is
        // the answer directly — the same trivial branch a current-tip
        // snapshot takes.
        if lo > hi || limit == 0 {
            return Vec::new();
        }
        let cf = CfHandles::resolve(&self.db);
        let entries_cf = EntriesCf::handle(&cf);
        scan_entries(
            self.db.raw_iterator_cf(entries_cf),
            owner,
            collection,
            lo,
            hi,
            Some(limit),
        )
    }
}

impl BoundaryStore for RocksDbShardStorage {
    type Boundary = CheckpointStore;

    fn escrow_records(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        let cf = self.cf();
        let prefix = shard_prefix_path(shard);
        iter_from::<StateCf>(&self.db, StateCf::handle(&cf), &prefix_low_key(&prefix))
            .take_while(|(key, _)| key_under_prefix(&key.to_bytes(), &prefix))
            .filter(|(key, value)| is_record_cell(*key, value))
            .collect()
    }

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
        leaves: &[SubstateLeaf],
    ) -> Result<(), String> {
        let _commit_guard = self
            .commit_lock
            .lock()
            .map_err(|_| "commit lock poisoned".to_string())?;
        let (version, root) = self.read_jmt_metadata();
        if holds_state(BlockHeight::new(version), root) {
            return Err("snap-sync staging requires an empty store".to_string());
        }

        let cf = CfHandles::resolve(&self.db);
        let staging_cf = ImportStagingCf::handle(&cf);
        let mut batch = WriteBatch::default();
        for leaf in leaves {
            batch_put::<ImportStagingCf>(&mut batch, staging_cf, &leaf.key, &leaf.value);
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
        // A finalize interrupted mid-build has already committed
        // JMT-node and state batches with no completion marker; a fresh
        // assembly built on top of them would leave substates readable
        // that its verified root does not attest. While the marker is
        // unset those CFs hold nothing but abandoned import batches, so
        // they are wiped with the staging area. (With the marker set the
        // store is finalized and holds no staged bytes to begin with.)
        if self.read_jmt_metadata() == (0, StateRoot::ZERO) {
            wipe_cf_into(&mut batch, &self.db, StateCf::handle(&cf));
            wipe_cf_into(&mut batch, &self.db, JmtNodesCf::handle(&cf));
        }
        self.db
            .write(batch)
            .map_err(|e| format!("snap-sync staging wipe: {e}"))
    }

    fn finalize_boundary_import(
        &self,
        height: BlockHeight,
        witnesses: WitnessSeed,
    ) -> Result<StateRoot, String> {
        let root = self.finalize_staged(height, &witnesses, IMPORT_BATCH_BYTES, None)?;
        // The store now holds exactly the boundary's state, as one that
        // committed through it would: that one holds the boundary's
        // certified header with the block and pinned the state, so this
        // one keeps the header alone and pins too. A failed pin degrades
        // serving, never the import.
        if let Some(boundary) = &witnesses.boundary {
            let mut batch = WriteBatch::default();
            write_boundary_header(&mut batch, boundary);
            self.db
                .write(batch)
                .map_err(|e| format!("boundary header write failed: {e}"))?;
        }
        if let Err(error) = self.checkpoints.create(height) {
            warn!(
                %height,
                %error,
                "boundary pin after import failed; this node won't serve this boundary"
            );
        }
        Ok(root)
    }

    fn follow_block_writes(
        &self,
        block: &Block,
        creations: &[(SubstateKey, Vec<u8>)],
    ) -> Result<StateRoot, String> {
        let height = block.height();
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

        // Anchored at this store's own tip, which the check above holds
        // only to being behind the followed block rather than one short
        // of it. A follow that skips a height resolves its movements
        // against a baseline missing what the gap left, and fails against
        // the child roots rather than committing quietly.
        let filtered =
            followed_block_writes(self, &self.snapshot(), block, creations, &self.root_path);
        if filtered.is_empty() {
            return Ok(base_root);
        }

        let (mut batch, sweep_rows) = self.build_substate_write_batch(
            &filtered,
            height.inner(),
            /* write_history */ true,
            /* base_reads */ None,
            /* pending */ &[],
        );
        // `commit_lock` is held across this whole follow and the batch is
        // written below, so the fold's read is of the state it extends.
        fold_sweep_rows(&self.db, &mut batch, &self.cf(), &sweep_rows);
        let parent_version =
            jmt_parent_height(BlockHeight::new(base_version), base_root).map(BlockHeight::inner);
        let (new_root, collected) =
            put_at_version(&snapshot_store, parent_version, height.inner(), &filtered);
        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            filtered,
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

    fn adopt_genesis(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
        source: AdoptSource,
    ) -> Result<StateRoot, String> {
        Self::adopt_genesis(self, origin, genesis, source).map_err(|e| e.to_string())
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
    use std::collections::BTreeMap;

    use blake3::hash as blake3_hash;
    use hyperscale_jmt::{Blake3Hasher, KEY_BYTES, Tree};
    use hyperscale_storage::test_helpers::{
        commit_one, completed_import_progress, import_boundary_state, pin_snap_sync_replica,
        test_boundary_import_roundtrip, test_boundary_retention_evicts_oldest,
        test_boundary_unpinned_height_not_served, test_escrow_records_are_read_off_the_state,
        test_import_gate_reads_the_trie,
    };
    use hyperscale_storage::{BOUNDARY_RETAIN, ShardChainReader, SubstateStore};
    use hyperscale_types::AddressClass;
    use tempfile::TempDir;

    use super::*;
    use crate::RocksDbConfig;
    use crate::shard::column_families::{IMPORT_STAGING_CF, JMT_NODES_CF, STATE_CF};

    type Jmt = Tree<Blake3Hasher, 1>;

    fn open_storage(dir: &Path) -> RocksDbShardStorage {
        RocksDbShardStorage::open(dir, NibblePath::empty()).unwrap()
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
        let start = [0u8; KEY_BYTES];
        let end = [0xFFu8; KEY_BYTES];
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
        test_boundary_retention_evicts_oldest(&storage);
    }

    /// A configured `boundary_retain` widens the ring beyond the
    /// default: the join budget's worth of boundaries stays served.
    #[test]
    fn configured_retention_widens_the_ring() {
        let temp = TempDir::new().unwrap();
        let config = RocksDbConfig {
            boundary_retain: 5,
            ..Default::default()
        };
        let storage =
            RocksDbShardStorage::open_with_config(temp.path(), &config, NibblePath::empty())
                .unwrap();
        for height in 1..=6u64 {
            commit_one(&storage, u8::try_from(height).unwrap());
            storage.pin_boundary(BlockHeight::new(height)).unwrap();
        }
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        for height in 2..=6u64 {
            assert!(
                storage.open_boundary(BlockHeight::new(height)).is_some(),
                "boundary {height} must stay inside the widened ring",
            );
        }
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
        test_boundary_unpinned_height_not_served(&storage);
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        let fresh_dir = TempDir::new().unwrap();
        let fresh = open_storage(fresh_dir.path());
        test_boundary_import_roundtrip(&storage, &fresh);
    }

    /// A store answers for the escrow records its state holds, which is
    /// what a merge successor's adoption reads its obligations off.
    #[test]
    fn escrow_records_are_read_off_the_state() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        test_escrow_records_are_read_off_the_state(&storage);
    }

    #[test]
    fn the_import_gate_reads_the_trie_not_the_chain() {
        let replicated_dir = TempDir::new().unwrap();
        let born_dir = TempDir::new().unwrap();
        test_import_gate_reads_the_trie(
            &open_storage(replicated_dir.path()),
            &open_storage(born_dir.path()),
        );
    }

    /// An import leaf whose top byte places it under one trie half.
    fn staged_leaf(top: u8) -> SubstateLeaf {
        let mut key = [0u8; KEY_BYTES];
        key[0] = top;
        key[31] = AddressClass::Component.tag();
        SubstateLeaf {
            key: SubstateKey::from_bytes(key).expect("a stored leaf key names an address"),
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

    /// An import keeps the anchor's certified header without its
    /// block, so the store answers the next joiner's witness history as
    /// one that committed the boundary would, and pins the anchor as
    /// that one did.
    #[test]
    fn import_keeps_the_boundary_header_without_its_block() {
        let replica_dir = TempDir::new().unwrap();
        let replica = open_storage(replica_dir.path());
        let anchor = pin_snap_sync_replica(&replica, 3, &[]);
        let boundary = replica
            .get_certified_header(anchor.height)
            .expect("the replica committed the boundary");

        let fresh_dir = TempDir::new().unwrap();
        let fresh = open_storage(fresh_dir.path());
        let progress = completed_import_progress(anchor.height, 12);
        fresh
            .stage_import_chunk(&progress, &[staged_leaf(0x11)])
            .unwrap();
        fresh
            .finalize_boundary_import(
                anchor.height,
                WitnessSeed {
                    boundary: Some((*boundary).clone()),
                    ..WitnessSeed::default()
                },
            )
            .unwrap();

        assert!(fresh.get_block(anchor.height).is_none());
        assert_eq!(
            fresh.get_certified_header(anchor.height).as_deref(),
            Some(&*boundary),
        );
        assert!(fresh.get_certified_header(BlockHeight::new(1)).is_none());
        assert!(fresh.open_boundary(anchor.height).is_some());
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

    /// Finalize refuses a progress record that binds the target height
    /// with open cursors — a partial assembly must never seal.
    #[test]
    fn finalize_refuses_an_incomplete_assembly_bound_to_the_height() {
        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        let mut progress = completed_import_progress(BlockHeight::new(3), 3);
        progress.cursors[0].done = false;
        storage
            .stage_import_chunk(&progress, &[staged_leaf(0x42)])
            .unwrap();

        let err = storage
            .finalize_boundary_import(BlockHeight::new(3), WitnessSeed::default())
            .unwrap_err();
        assert!(err.contains("incomplete assembly"), "{err}");
        // Nothing sealed and staging intact: a completed re-stage can
        // still finalize this store.
        assert_eq!(storage.read_jmt_metadata(), (0, StateRoot::ZERO));
        assert!(storage.read_import_progress().is_some());
        assert_eq!(count_cf_entries(&storage, STATE_CF), 0);
    }

    /// Deterministic pseudorandom import leaves with distinct keys and
    /// varied value lengths.
    fn random_leaves(n: usize, seed: u64) -> Vec<SubstateLeaf> {
        let mut state = seed.max(1);
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut by_key: BTreeMap<[u8; KEY_BYTES], SubstateLeaf> = BTreeMap::new();
        while by_key.len() < n {
            let mut key = [0u8; KEY_BYTES];
            for chunk in key.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_be_bytes());
            }
            // The owner half of a leaf key is an address, so its tag byte
            // is not free entropy.
            key[31] = AddressClass::Component.tag();
            #[allow(clippy::cast_possible_truncation)] // deliberate low-byte take
            let value: Vec<u8> = (0..=next() % 200).map(|_| next() as u8).collect();
            by_key.insert(
                key,
                SubstateLeaf {
                    key: SubstateKey::from_bytes(key).expect("a stored leaf key names an address"),
                    value,
                },
            );
        }
        by_key.into_values().collect()
    }

    /// Stage `leaves` in fixed-size chunks under a completed progress
    /// record.
    fn stage_in_chunks(
        storage: &RocksDbShardStorage,
        height: BlockHeight,
        leaves: &[SubstateLeaf],
    ) {
        let bytes = leaves.iter().map(|l| l.value.len() as u64).sum();
        let progress = completed_import_progress(height, bytes);
        for chunk in leaves.chunks(37) {
            storage.stage_import_chunk(&progress, chunk).unwrap();
        }
    }

    /// Raw entry count of a column family.
    fn count_cf_entries(storage: &RocksDbShardStorage, name: &str) -> usize {
        let cf = storage.db.cf_handle(name).expect("cf exists");
        let mut iter = storage.db.raw_iterator_cf(cf);
        iter.seek_to_first();
        let mut count = 0;
        while iter.valid() {
            count += 1;
            iter.next();
        }
        count
    }

    /// The chunked build converges to the single-shot build exactly:
    /// same root, same metadata, same byte total, and the same stored
    /// node count — a missed cross-batch stale deletion would leave the
    /// batched store with orphan nodes and a higher count.
    #[test]
    fn batched_finalize_matches_the_single_shot_build() {
        let leaves = random_leaves(300, 7);
        let height = BlockHeight::new(200);
        let value_bytes: u64 = leaves.iter().map(|l| l.value.len() as u64).sum();

        let one_shot_dir = TempDir::new().unwrap();
        let one_shot = open_storage(one_shot_dir.path());
        stage_in_chunks(&one_shot, height, &leaves);
        let expected = one_shot
            .finalize_boundary_import(height, WitnessSeed::default())
            .unwrap();

        let batched_dir = TempDir::new().unwrap();
        let batched = open_storage(batched_dir.path());
        stage_in_chunks(&batched, height, &leaves);
        let root = batched
            .finalize_staged(height, &WitnessSeed::default(), 512, None)
            .unwrap();

        assert_eq!(root, expected);
        assert_eq!(batched.read_jmt_metadata(), (200, expected));
        assert_eq!(batched.substate_bytes_at_version(200), Some(value_bytes));
        assert_eq!(batched.read_import_progress(), None);
        for cf in [JMT_NODES_CF, STATE_CF, IMPORT_STAGING_CF] {
            assert_eq!(
                count_cf_entries(&batched, cf),
                count_cf_entries(&one_shot, cf),
                "column family {cf} diverged between the batched and single-shot builds",
            );
        }
    }

    /// A finalize interrupted at a batch boundary re-runs to the
    /// identical root and node set: the metadata marker never landed, so
    /// the re-run deterministically overwrites the partial build.
    #[test]
    fn interrupted_finalize_reruns_to_the_identical_root() {
        let leaves = random_leaves(200, 11);
        let height = BlockHeight::new(150);

        let reference_dir = TempDir::new().unwrap();
        let reference = open_storage(reference_dir.path());
        stage_in_chunks(&reference, height, &leaves);
        let expected = reference
            .finalize_staged(height, &WitnessSeed::default(), 512, None)
            .unwrap();

        let interrupted_dir = TempDir::new().unwrap();
        let interrupted = open_storage(interrupted_dir.path());
        stage_in_chunks(&interrupted, height, &leaves);
        let partial = interrupted
            .finalize_staged(height, &WitnessSeed::default(), 512, Some(2))
            .unwrap();
        assert_ne!(partial, expected);
        // No completion marker, staging intact: the store still reads as
        // an un-imported bootstrap target.
        assert_eq!(interrupted.read_jmt_metadata(), (0, StateRoot::ZERO));
        assert!(interrupted.read_import_progress().is_some());

        let root = interrupted
            .finalize_staged(height, &WitnessSeed::default(), 512, None)
            .unwrap();
        assert_eq!(root, expected);
        assert_eq!(interrupted.read_jmt_metadata(), (150, expected));
        for cf in [JMT_NODES_CF, STATE_CF] {
            assert_eq!(
                count_cf_entries(&interrupted, cf),
                count_cf_entries(&reference, cf),
                "column family {cf} diverged after the interrupted re-run",
            );
        }
    }

    /// A wipe after an interrupted finalize clears the partial build's
    /// residue: a fresh assembly against a different anchor must not
    /// leave substates readable that its verified root does not attest.
    #[test]
    fn wipe_after_interrupted_finalize_clears_partial_build_residue() {
        let leaves = random_leaves(200, 17);
        let height_a = BlockHeight::new(150);

        let temp = TempDir::new().unwrap();
        let storage = open_storage(temp.path());
        stage_in_chunks(&storage, height_a, &leaves);
        storage
            .finalize_staged(height_a, &WitnessSeed::default(), 512, Some(2))
            .unwrap();
        assert_eq!(storage.read_jmt_metadata(), (0, StateRoot::ZERO));
        assert!(count_cf_entries(&storage, STATE_CF) > 0);

        // The advanced-anchor rebind path: wipe, then assemble a
        // different leaf set (dropping half of the first anchor's keys)
        // against a new anchor.
        storage.wipe_import_staging().unwrap();
        assert_eq!(storage.read_import_progress(), None);
        for cf in [JMT_NODES_CF, STATE_CF, IMPORT_STAGING_CF] {
            assert_eq!(
                count_cf_entries(&storage, cf),
                0,
                "column family {cf} carries residue past the wipe",
            );
        }

        let height_b = BlockHeight::new(180);
        let retained = &leaves[..100];
        stage_in_chunks(&storage, height_b, retained);
        let root = storage
            .finalize_staged(height_b, &WitnessSeed::default(), 512, None)
            .unwrap();

        // The rebuilt store matches a fresh store importing the same set.
        let reference_dir = TempDir::new().unwrap();
        let reference = open_storage(reference_dir.path());
        stage_in_chunks(&reference, height_b, retained);
        let expected = reference
            .finalize_staged(height_b, &WitnessSeed::default(), 512, None)
            .unwrap();
        assert_eq!(root, expected);
        for cf in [JMT_NODES_CF, STATE_CF] {
            assert_eq!(
                count_cf_entries(&storage, cf),
                count_cf_entries(&reference, cf),
                "column family {cf} diverged from the fresh-store build",
            );
        }
        // The dropped keys read as absent.
        let state_cf = storage.db.cf_handle(STATE_CF).expect("cf exists");
        for leaf in &leaves[100..] {
            assert!(
                storage
                    .db
                    .get_cf(state_cf, leaf.key.to_bytes())
                    .unwrap()
                    .is_none(),
                "a dropped leaf stayed readable after the rebind",
            );
        }
    }

    /// A chain shallower than the batch count grows the batches so the
    /// version chain fits under the anchor height.
    #[test]
    fn shallow_chain_grows_batches_to_fit_the_height() {
        let leaves = random_leaves(50, 13);
        let height = BlockHeight::new(2);

        let one_shot_dir = TempDir::new().unwrap();
        let one_shot = open_storage(one_shot_dir.path());
        stage_in_chunks(&one_shot, height, &leaves);
        let expected = one_shot
            .finalize_boundary_import(height, WitnessSeed::default())
            .unwrap();

        let shallow_dir = TempDir::new().unwrap();
        let shallow = open_storage(shallow_dir.path());
        stage_in_chunks(&shallow, height, &leaves);
        // A 64-byte limit would form ~50 batches; the height admits 2.
        let root = shallow
            .finalize_staged(height, &WitnessSeed::default(), 64, None)
            .unwrap();
        assert_eq!(root, expected);
        assert_eq!(shallow.read_jmt_metadata(), (2, expected));
    }

    /// GC over a batched import is a no-op: the finalize deletes
    /// superseded nodes inline and records nothing for the collector, so
    /// the version chain below the anchor survives intact.
    #[test]
    fn gc_leaves_a_batched_import_intact() {
        let leaves = random_leaves(120, 17);
        let height = BlockHeight::new(100);
        let storage_dir = TempDir::new().unwrap();
        let storage = open_storage(storage_dir.path());
        stage_in_chunks(&storage, height, &leaves);
        let root = storage
            .finalize_staged(height, &WitnessSeed::default(), 512, None)
            .unwrap();
        let nodes = count_cf_entries(&storage, JMT_NODES_CF);

        assert_eq!(storage.run_jmt_gc(), 0);
        assert_eq!(storage.run_state_history_gc(), 0);
        assert_eq!(storage.read_jmt_metadata(), (100, root));
        assert_eq!(count_cf_entries(&storage, JMT_NODES_CF), nodes);
    }

    /// GB-scale import: two different batch limits over the same
    /// generated leaf set converge to the identical root and node set,
    /// and the byte total matches — the small-tree equivalence
    /// guarantees hold where the batching actually engages.
    #[test]
    #[ignore = "GB-scale stress (minutes, ~4GB disk) — run with --ignored"]
    fn gb_scale_import_is_batch_limit_invariant() {
        const TOTAL: u64 = 2_000_000;
        const VALUE_BYTES: usize = 512;
        const STAGE_CHUNK: usize = 8_192;
        let height = BlockHeight::new(1_000);

        let import = |batch_limit: u64| {
            let dir = TempDir::new().unwrap();
            let storage = open_storage(dir.path());
            let progress = completed_import_progress(height, TOTAL * VALUE_BYTES as u64);
            let mut chunk = Vec::with_capacity(STAGE_CHUNK);
            for index in 0..TOTAL {
                // Hashed keys spread paths uniformly, like real
                // leaf keys.
                let digest = *blake3_hash(&index.to_be_bytes()).as_bytes();
                let mut key = [0u8; KEY_BYTES];
                for (chunk_index, slot) in key.chunks_mut(digest.len()).enumerate() {
                    let len = slot.len();
                    slot.copy_from_slice(&digest[..len]);
                    slot[0] = slot[0]
                        .wrapping_add(u8::try_from(chunk_index).expect("a key is a few chunks"));
                }
                key[31] = AddressClass::Component.tag();
                chunk.push(SubstateLeaf {
                    key: SubstateKey::from_bytes(key).expect("a stored leaf key names an address"),
                    // Sized off the value width, not the key width: the
                    // declared byte total is what this test checks.
                    value: digest.repeat(VALUE_BYTES / digest.len()),
                });
                if chunk.len() == STAGE_CHUNK {
                    storage.stage_import_chunk(&progress, &chunk).unwrap();
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                storage.stage_import_chunk(&progress, &chunk).unwrap();
            }
            let root = storage
                .finalize_staged(height, &WitnessSeed::default(), batch_limit, None)
                .unwrap();
            (dir, storage, root)
        };

        let (_wide_dir, wide, wide_root) = import(IMPORT_BATCH_BYTES);
        let (_narrow_dir, narrow, narrow_root) = import(32 * 1024 * 1024);

        assert_eq!(wide_root, narrow_root);
        assert_eq!(wide.read_jmt_metadata(), (1_000, wide_root));
        assert_eq!(narrow.read_jmt_metadata(), (1_000, narrow_root));
        assert_eq!(
            wide.substate_bytes_at_version(1_000),
            Some(TOTAL * VALUE_BYTES as u64),
        );
        for cf in [JMT_NODES_CF, STATE_CF] {
            assert_eq!(
                count_cf_entries(&wide, cf),
                count_cf_entries(&narrow, cf),
                "column family {cf} diverged between batch limits",
            );
        }
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
