//! Garbage collection for `RocksDB` storage.
//!
//! Two independent GC passes:
//! - **JMT GC**: deletes stale tree nodes below the retention floor.
//! - **State-history GC**: prunes state-history entries below the same
//!   floor. `StateCf` is always authoritative for current values, so
//!   deleting old history entries only costs the ability to serve
//!   historical reads past the retention horizon.

use rocksdb::{ColumnFamily, WriteBatch};

use super::column_families::{
    EntriesHistoryCf, JmtNodesCf, StaleEntriesHistoryCf, StaleJmtNodesCf, StaleStateHistoryCf,
    StateHistoryCf, SubstateBytesCf,
};
use super::core::RocksDbShardStorage;
use crate::typed_cf::{self, DbCodec, TypedCf};

impl RocksDbShardStorage {
    /// Run garbage collection for stale JMT nodes.
    ///
    /// Deletes JMT nodes that became stale below the retention floor,
    /// freeing disk space while preserving the ability to generate
    /// historical proofs at every version a consumer may still name.
    ///
    /// # When to Call
    ///
    /// Call this periodically (e.g., after each block commit, or on a timer).
    /// It's safe to call concurrently with commits — GC only touches old data
    /// that's no longer reachable from recent state roots.
    ///
    /// # Returns
    ///
    /// The number of stale parts entries processed (each entry may contain
    /// multiple nodes/subtrees).
    pub fn run_jmt_gc(&self) -> usize {
        let start = std::time::Instant::now();

        // Below the retention floor no reader may ask, so nothing needs
        // the tree at those versions.
        let cutoff_version = self.retention_floor();

        if cutoff_version == 0 {
            return 0;
        }

        let cf = self.cf();
        let stale_cf = StaleJmtNodesCf::handle(&cf);
        let jmt_cf = JmtNodesCf::handle(&cf);
        let counts_cf = SubstateBytesCf::handle(&cf);

        let mut processed_count = 0;
        let mut deleted_nodes = 0;
        let mut batch = WriteBatch::default();

        for (version, stale_parts) in typed_cf::iter_all::<StaleJmtNodesCf>(&self.db, stale_cf) {
            if version >= cutoff_version {
                break;
            }

            for key in stale_parts {
                typed_cf::batch_delete::<JmtNodesCf>(&mut batch, jmt_cf, &key);
                deleted_nodes += 1;
            }

            typed_cf::batch_delete::<StaleJmtNodesCf>(&mut batch, stale_cf, &version);
            processed_count += 1;
        }

        // Per-version substate byte totals share the historical-tree cutoff:
        // a count below the retention floor anchors nothing.
        for (version, _) in typed_cf::iter_all::<SubstateBytesCf>(&self.db, counts_cf) {
            if version >= cutoff_version {
                break;
            }
            typed_cf::batch_delete::<SubstateBytesCf>(&mut batch, counts_cf, &version);
        }

        if !batch.is_empty()
            && let Err(e) = self.db.write(batch)
        {
            tracing::error!("JMT GC write failed: {}", e);
            return 0;
        }

        // Force compaction over the just-tombstoned range of
        // StaleJmtNodesCf so the CF actually shrinks (tombstones alone
        // don't reclaim disk — they just mask until a compaction runs).
        // The range is small and version-ordered, so this is cheap.
        //
        // We intentionally DO NOT force-compact JmtNodesCf here:
        // deleted tree nodes are scattered across the entire keyspace
        // and a bounded range is hard to compute. Reclamation relies
        // on natural write-amplification compaction; if JmtNodesCf
        // tombstone accumulation becomes a problem, set
        // `periodic_compaction_seconds` on the CF at open time.
        if processed_count > 0 {
            let lo = 0u64.to_be_bytes();
            let hi = cutoff_version.to_be_bytes();
            self.db
                .compact_range_cf(stale_cf, Some(&lo[..]), Some(&hi[..]));
        }

        let elapsed = start.elapsed();
        if processed_count > 0 {
            tracing::debug!(
                processed_count,
                deleted_nodes,
                cutoff_version,
                elapsed_ms = elapsed.as_millis(),
                "JMT GC completed"
            );
        }

        processed_count
    }

    /// Run garbage collection for state-history entries.
    ///
    /// The `state_history` CF stores prior-value entries keyed by
    /// `(storage_key, write_version)`. Without GC, it grows without
    /// bound. Deletion is trivial: anything with `version ≤ cutoff` is
    /// beyond the retention window. No floor preservation is needed —
    /// the `state` CF is always authoritative for current values, and
    /// the retention-panic on `snapshot_at(V)` guards against internal
    /// callers ever asking for a version below `cutoff`.
    ///
    /// # Boundary invariant
    ///
    /// A reader at `V = floor` needs history entries with `v' > floor`,
    /// so the smallest surviving one must be `floor + 1`. This deletes
    /// `v' ≤ floor` — zero-margin, and the margin holds because the
    /// cutoff and the readers' floor are one stored value rather than two
    /// expressions that have to agree.
    ///
    /// # Concurrency
    ///
    /// Runs without `commit_lock`. Safe because concurrent readers hold
    /// a `rocksdb::Snapshot` whose sequence number predates any GC
    /// delete-tombstones issued afterwards: `RocksDB` compaction preserves
    /// SSTs referenced by live snapshots, so readers see pre-delete
    /// values regardless of GC progress. This isolation is load-bearing.
    ///
    /// # Returns
    ///
    /// The number of entries deleted.
    #[allow(clippy::must_use_candidate)] // run for its effect; the count is a log line
    pub fn run_state_history_gc(&self) -> usize {
        let cutoff = self.retention_floor();

        if cutoff == 0 {
            return 0;
        }

        let cf = self.cf();
        self.run_history_gc_pass::<StaleStateHistoryCf>(
            cutoff,
            StateHistoryCf::handle(&cf),
            StaleStateHistoryCf::handle(&cf),
            "state-history",
        ) + self.run_history_gc_pass::<StaleEntriesHistoryCf>(
            cutoff,
            EntriesHistoryCf::handle(&cf),
            StaleEntriesHistoryCf::handle(&cf),
            "entries-history",
        )
    }

    /// One history-GC pass: walk `Stale`'s version-indexed stale set in
    /// ascending order — each row lists the raw history keys written at
    /// that version, so cost is proportional to deletes-needed, not CF
    /// size — deleting the listed rows at or below `cutoff`, flushing
    /// incrementally, and compacting the deleted span afterwards.
    ///
    /// The compaction is load-bearing for reclamation: tombstones only
    /// free disk once compaction rewrites the affected SSTs, and the
    /// oldest rows (exactly what GC targets) live in L5-L6 (Zstd tier)
    /// which see no natural compaction pressure.
    ///
    /// Returns the rows deleted through the last successful write.
    fn run_history_gc_pass<Stale>(
        &self,
        cutoff: u64,
        history_cf: &ColumnFamily,
        stale_cf: &ColumnFamily,
        pass: &str,
    ) -> usize
    where
        Stale: TypedCf<Key = u64, Value = Vec<Vec<u8>>>,
        Stale::KeyCodec: DbCodec<u64>,
    {
        const BATCH_FLUSH_THRESHOLD: usize = 10_000;

        let start = std::time::Instant::now();
        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        let mut lowest_deleted_key: Option<Vec<u8>> = None;
        let mut highest_deleted_key: Option<Vec<u8>> = None;

        for (version, history_keys) in typed_cf::iter_all::<Stale>(&self.db, stale_cf) {
            if version > cutoff {
                break;
            }

            for raw_key in &history_keys {
                if lowest_deleted_key.is_none() {
                    lowest_deleted_key = Some(raw_key.clone());
                }
                highest_deleted_key = Some(raw_key.clone());
                batch.delete_cf(history_cf, raw_key);
                deleted += 1;
            }
            typed_cf::batch_delete::<Stale>(&mut batch, stale_cf, &version);

            if deleted >= BATCH_FLUSH_THRESHOLD {
                if let Err(e) = self.db.write(std::mem::take(&mut batch)) {
                    tracing::error!(pass, "History GC write failed: {}", e);
                    return deleted;
                }
                batch = WriteBatch::default();
            }
        }

        if !batch.is_empty()
            && let Err(e) = self.db.write(batch)
        {
            tracing::error!(pass, "History GC write failed: {}", e);
            // Return the count we already persisted in prior batches
            // rather than 0 — callers use this to log progress.
            return deleted;
        }

        if let (Some(lo), Some(hi)) = (lowest_deleted_key, highest_deleted_key) {
            self.db
                .compact_range_cf(history_cf, Some(lo.as_slice()), Some(hi.as_slice()));
        }

        let elapsed = start.elapsed();
        if deleted > 0 {
            tracing::info!(
                pass,
                deleted,
                cutoff,
                elapsed_ms = elapsed.as_millis(),
                "History GC pass completed"
            );
        }

        deleted
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_jmt::NibblePath;
    use hyperscale_storage::Substates;
    use hyperscale_storage::test_helpers::{commit_writes_at, state_key};
    use hyperscale_types::{RETENTION_HORIZON, SettledWrites, WeightedTimestamp};
    use tempfile::TempDir;

    use super::super::core::RocksDbShardStorage;

    /// Commits a whole retention horizon apart, so each one leaves the
    /// last outside the window.
    fn past(step: u64) -> WeightedTimestamp {
        let horizon = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX);
        WeightedTimestamp::from_millis(step * (horizon + 1))
    }

    /// Aggressive state-history GC must not affect current-tip reads.
    /// `StateCf` holds the authoritative current value per key; deleting
    /// history only costs the ability to serve historical reads below
    /// the retention floor.
    #[test]
    fn state_history_gc_preserves_current_state() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

        let key_a = state_key(1, 10);
        let key_b = state_key(2, 20);

        let writes = SettledWrites::from_absolutes(BTreeMap::from([
            (key_a, Some(vec![0xAA])),
            (key_b, Some(vec![0xBB])),
        ]));
        commit_writes_at(&storage, &writes, past(0));

        // Carry the tip a horizon past the first commit with empty ones,
        // so the floor leaves version 1 behind.
        for step in 1..=4 {
            commit_writes_at(&storage, &SettledWrites::default(), past(step));
        }

        storage.run_state_history_gc();

        // Current-tip reads are served from StateCf — history GC
        // cannot affect them regardless of how aggressive the retention is.
        assert_eq!(
            storage.cell(key_a),
            Some(vec![0xAA]),
            "StateCf entry for key A survives state-history GC"
        );
        assert_eq!(
            storage.cell(key_b),
            Some(vec![0xBB]),
            "StateCf entry for key B survives state-history GC"
        );
    }
}
