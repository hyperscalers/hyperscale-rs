//! `SubstateStore` implementation for `RocksDbShardStorage`.

use std::sync::atomic::Ordering;
use std::time::Instant;

use hex::encode as hex_encode;
use hyperscale_metrics::{record_storage_operation, record_storage_write};
use hyperscale_storage::{
    JmtSnapshot, PackageArtifactStore, SubstateStore, Substates, SweepIndex, SweepRows,
    VersionedStore, holds_this_block_at,
};
use hyperscale_types::{
    Block, BlockHeight, DeclaredRange, Hash, QuorumCertificate, StateRoot, SubstateKey,
    SweepBucket, SweepFrontier, Verified,
};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::{PackageArtifactsCf, StateCf, SweepIndexCf};
use super::core::{RocksDbShardStorage, fold_sweep_rows};
use super::metadata::read_jmt_metadata;
use super::retention::retention_floor;
use super::snapshot::RocksDbSnapshot;
use super::substate_key::SubstateKeyCodec;
use super::sweep_key::{SweepRowCodec, row_seek};
use crate::typed_cf::{DbCodec, TypedCf, get, iter_all};

impl SubstateStore for RocksDbShardStorage {
    type Snapshot<'a> = RocksDbSnapshot<'a>;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Default version = current committed tip as seen through the
        // snapshot's own LSN. Picking the version from a separate live
        // read would race with commits (see `snapshot_at` for details).
        let snapshot = self.db.snapshot();
        let (current_version, _) = read_jmt_metadata(&snapshot);
        RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: current_version,
            current_version,
        }
    }

    fn jmt_height(&self) -> BlockHeight {
        BlockHeight::new(self.read_jmt_metadata().0)
    }

    fn state_root(&self) -> StateRoot {
        let (_, root_hash) = self.read_jmt_metadata();
        root_hash
    }

    fn get_substate_at_height(
        &self,
        key: SubstateKey,
        block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>> {
        Some(self.snapshot_held_at(block_height)?.cell(key))
    }

    fn get_entries_at_height(
        &self,
        range: DeclaredRange,
        block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>> {
        Some(self.snapshot_held_at(block_height)?.entries_in_range(
            range.owner,
            range.collection,
            range.lo,
            range.hi,
            range.cap as usize,
        ))
    }
}

impl VersionedStore for RocksDbShardStorage {
    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
        // Take the DB snapshot FIRST, then read the tip and the floor
        // THROUGH it. Reading either from the live DB and then taking the
        // snapshot races with concurrent commits: a commit between the
        // two reads leaves `current_version` stale relative to the
        // snapshot's LSN, and a reader told a version is retained by one
        // and gone by the other. Capturing everything from the one
        // snapshot gives one consistent view.
        let snapshot = self.db.snapshot();
        let (current_version, _) = read_jmt_metadata(&snapshot);
        let held =
            height.inner() <= current_version && height.inner() >= retention_floor(&snapshot);
        held.then(|| RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: height.inner(),
            current_version,
        })
    }

    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        let snapshot = self.db.snapshot();
        let (current_version, _) = read_jmt_metadata(&snapshot);
        let floor = retention_floor(&snapshot);
        assert!(
            height.inner() >= floor,
            "snapshot_at({height}) below retention floor {floor} \
             (current_version={current_version}) — \
             Shard consensus + DA invariant broken; caller must anchor within retention",
        );
        RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: height.inner(),
            current_version,
        }
    }

    fn substate_bytes_at(&self, height: BlockHeight) -> Option<u64> {
        self.substate_bytes_at_version(height.inner())
    }

    fn hold_retention_at(&self, height: BlockHeight) {
        self.retention_hold.store(height.inner(), Ordering::Relaxed);
    }

    fn retention_floor(&self) -> u64 {
        Self::retention_floor(self)
    }
}

impl RocksDbShardStorage {
    /// Try to apply a prepared block commit with a single fsync.
    ///
    /// This is the fast path for block commit. Applies the pre-built `WriteBatch`
    /// atomically with one fsync, including all JMT nodes from the snapshot.
    ///
    /// Returns `true` if successfully applied (fast path), or `false`
    /// if the JMT state has changed since preparation, which the caller
    /// judges: benign only when the store already holds this block.
    ///
    /// # Panics
    /// Only panics on unrecoverable errors (`RocksDB` write failure).
    pub(crate) fn try_apply_prepared_commit(
        &self,
        mut write_batch: WriteBatch,
        sweep_rows: &SweepRows,
        jmt_snapshot: &JmtSnapshot,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
        sync: bool,
    ) -> bool {
        let _commit_guard = self.commit_lock.lock().unwrap();
        let start = Instant::now();

        // Verify we're applying to the expected base state BEFORE writing anything.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        let (current_version, current_root_hash) = self.read_jmt_metadata();
        // A store already at this block's height holds a block there,
        // and it had better be this one. The benign cause is the same
        // block twice — a synced copy, or a co-hosted vnode's — and the
        // root check below waves an empty commit through on an unchanged
        // root, so height is the only thing that would separate a second
        // application of this block from a first application of a
        // different one at the same height. The read is confined to that
        // case rather than paid on every commit.
        assert!(
            current_version < block.height().inner()
                || holds_this_block_at(self, block.height(), block.hash()),
            "BFT CRITICAL: prepared commit for height {} meets a different block already there",
            block.height().inner(),
        );
        if current_root_hash != jmt_snapshot.base_root {
            tracing::warn!(
                expected_root = ?jmt_snapshot.base_root,
                actual_root = ?current_root_hash,
                "JMT snapshot base ROOT mismatch - falling back to slow path"
            );
            return false;
        }
        if current_version != jmt_snapshot.base_height.inner() {
            tracing::debug!(
                expected_version = jmt_snapshot.base_height.inner(),
                actual_version = current_version,
                "JMT snapshot base VERSION mismatch (root matches) - proceeding with fast path. \
                 This is expected when empty commits advance the version counter."
            );
        }

        let nodes_count = jmt_snapshot.nodes.len();
        let stale_count = jmt_snapshot.stale_node_keys.len();
        let new_version = jmt_snapshot.new_height.inner();
        let new_root = jmt_snapshot.result_root;

        self.append_jmt_to_batch(&mut write_batch, jmt_snapshot, new_version);

        // The sweep index is a total over what has committed, so its
        // fold reads the persisted rows and belongs here, under
        // `commit_lock` with the write it decides: a batch prepared over
        // unpersisted ancestors has not seen what they moved.
        fold_sweep_rows(&self.db, &mut write_batch, &self.cf(), sweep_rows);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        Self::append_consensus_to_batch(&mut write_batch, block, qc);

        // Apply everything atomically. When batching multiple blocks, only
        // the final block sets sync=true — its fsync covers all prior WAL entries.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(sync);

        self.db.write_opt(write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        // Populate the node cache with the newly committed nodes so that
        // subsequent reads (proof generation, next block's state root
        // verification) hit the cache instead of deserializing from RocksDB.

        let elapsed = start.elapsed();
        record_storage_write(elapsed.as_secs_f64());
        record_storage_operation("apply_prepared_commit", elapsed.as_secs_f64());

        tracing::debug!(
            new_version,
            new_root = %hex_encode(new_root.as_raw().to_bytes()),
            nodes_count,
            stale_count,
            elapsed_ms = elapsed.as_millis(),
            "Applied prepared commit (single fsync)"
        );

        true
    }
}

impl SweepIndex for RocksDbShardStorage {
    fn sweep_candidates(
        &self,
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
    ) -> Vec<(SubstateKey, u64)> {
        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        SweepRows::walk(
            after,
            below,
            limit,
            |bucket| {
                let mut rows = self.db.raw_iterator_cf(SweepIndexCf::handle(&cf));
                rows.seek(row_seek(bucket));
                std::iter::from_fn(move || {
                    let row = SweepRowCodec.decode(rows.key()?);
                    rows.next();
                    Some(row)
                })
            },
            |lo, hi, each| {
                let mut leaves = self.db.raw_iterator_cf(state_cf);
                leaves.seek(lo.to_bytes());
                let end = hi.to_bytes();
                while leaves.valid() {
                    let Some(raw) = leaves.key() else { break };
                    if raw > end.as_slice() {
                        break;
                    }
                    let key = SubstateKeyCodec.decode(raw);
                    if !each(key, leaves.value().unwrap_or_default()) {
                        break;
                    }
                    leaves.next();
                }
            },
        )
    }
}

impl PackageArtifactStore for RocksDbShardStorage {
    fn package_artifacts(&self) -> Vec<Vec<u8>> {
        let cf = self.cf();
        iter_all::<PackageArtifactsCf>(&self.db, PackageArtifactsCf::handle(&cf))
            .map(|(_, artifact)| artifact)
            .collect()
    }

    fn package_artifact(&self, package: Hash) -> Option<Vec<u8>> {
        let cf = self.cf();
        get::<PackageArtifactsCf>(&*self.db, PackageArtifactsCf::handle(&cf), &package)
    }
}
