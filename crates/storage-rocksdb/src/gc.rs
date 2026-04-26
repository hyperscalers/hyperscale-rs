//! Garbage collection for `RocksDB` storage.
//!
//! Two independent GC passes:
//! - **JMT GC**: deletes stale tree nodes older than `jmt_history_length`.
//! - **State-history GC**: prunes state-history entries older than
//!   `jmt_history_length`. `StateCf` is always authoritative for current
//!   values, so deleting old history entries only costs the ability to
//!   serve historical reads beyond the retention window.

use crate::column_families::{JmtNodesCf, StaleJmtNodesCf, StaleStateHistoryCf, StateHistoryCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{self, TypedCf};

use crate::jmt_stored::StaleTreePart;
use hyperscale_jmt as jmt;
use rocksdb::WriteBatch;

impl RocksDbStorage {
    /// Run garbage collection for stale JMT nodes.
    ///
    /// Deletes JMT nodes that became stale at heights older than
    /// `current_height - jmt_history_length`, freeing disk space while
    /// preserving the ability to generate historical proofs within the
    /// retention window.
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

        let (current_version, _) = self.read_jmt_metadata();

        // Calculate the cutoff version — delete stale parts older than this.
        let cutoff_version = current_version.saturating_sub(self.jmt_history_length);

        if cutoff_version == 0 {
            return 0;
        }

        let cf = self.cf();
        let stale_cf = StaleJmtNodesCf::handle(&cf);
        let jmt_cf = JmtNodesCf::handle(&cf);

        let mut processed_count = 0;
        let mut deleted_nodes = 0;
        let mut batch = WriteBatch::default();

        for (version, stale_parts) in typed_cf::iter_all::<StaleJmtNodesCf>(&self.db, stale_cf) {
            if version >= cutoff_version {
                break;
            }

            for stale_part in stale_parts {
                match stale_part {
                    StaleTreePart::Node(key) => {
                        typed_cf::batch_delete::<JmtNodesCf>(&mut batch, jmt_cf, &key);
                        deleted_nodes += 1;
                    }
                }
            }

            typed_cf::batch_delete::<StaleJmtNodesCf>(&mut batch, stale_cf, &version);
            processed_count += 1;
        }

        if !batch.is_empty() {
            if let Err(e) = self.db.write(batch) {
                tracing::error!("JMT GC write failed: {}", e);
                return 0;
            }
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
                current_version,
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
    /// `cutoff` here MUST equal `floor` in `snapshot_at`: readers at
    /// `V = floor` need history entries with `v' > V = floor`, i.e. the
    /// smallest surviving `v'` must be `floor + 1 = cutoff + 1`. GC
    /// deletes `v' ≤ cutoff`, so the first preserved entry is exactly
    /// `cutoff + 1` — zero-margin. Any refactor that makes `floor <
    /// cutoff` (e.g. rounding, off-by-one in saturating math) silently
    /// breaks historical reads at the boundary without a panic.
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
    pub fn run_state_history_gc(&self) -> usize {
        const BATCH_FLUSH_THRESHOLD: usize = 10_000;

        let start = std::time::Instant::now();

        let (current_version, _) = self.read_jmt_metadata();
        // Must match `snapshot_at`'s floor calculation exactly — see
        // boundary invariant above.
        let cutoff = current_version.saturating_sub(self.jmt_history_length);

        if cutoff == 0 {
            return 0;
        }

        let cf = self.cf();
        let history_cf = StateHistoryCf::handle(&cf);
        let stale_history_cf = StaleStateHistoryCf::handle(&cf);

        // Walk the version-indexed stale set in ascending order — each
        // entry lists the raw `state_history` keys written at that
        // version. Stops as soon as we reach a version past the cutoff,
        // so GC cost is proportional to deletes-needed, not CF size.
        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        let mut lowest_deleted_key: Option<Vec<u8>> = None;
        let mut highest_deleted_key: Option<Vec<u8>> = None;

        for (version, history_keys) in
            typed_cf::iter_all::<StaleStateHistoryCf>(&self.db, stale_history_cf)
        {
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
            typed_cf::batch_delete::<StaleStateHistoryCf>(&mut batch, stale_history_cf, &version);

            if deleted >= BATCH_FLUSH_THRESHOLD {
                if let Err(e) = self.db.write(std::mem::take(&mut batch)) {
                    tracing::error!("State-history GC write failed: {}", e);
                    return deleted;
                }
                batch = WriteBatch::default();
            }
        }

        if !batch.is_empty() {
            if let Err(e) = self.db.write(batch) {
                tracing::error!("State-history GC write failed: {}", e);
                // Return the count we already persisted in prior batches
                // rather than 0 — callers use this to log progress.
                return deleted;
            }
        }

        // Tombstones only reclaim disk once compaction rewrites the
        // affected SSTs. Under write-heavy workloads the oldest entries
        // (exactly what GC targets) live in L5-L6 (Zstd tier) which see
        // no natural compaction pressure. Issue a compact_range over
        // the deleted key span to trigger reclamation.
        if let (Some(lo), Some(hi)) = (lowest_deleted_key, highest_deleted_key) {
            self.db
                .compact_range_cf(history_cf, Some(lo.as_slice()), Some(hi.as_slice()));
        }

        let elapsed = start.elapsed();
        if deleted > 0 {
            tracing::info!(
                deleted,
                cutoff,
                current_version,
                elapsed_ms = elapsed.as_millis(),
                "State-history GC completed"
            );
        }

        deleted
    }
}

// Re-export the jmt_key type alias for compatibility elsewhere if needed.
#[allow(unused)]
fn _assert_jmt_key_stable(_k: &jmt::NodeKey) {}

#[cfg(test)]
mod tests {
    use crate::core::RocksDbStorage;
    use hyperscale_storage::{
        DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
        PartitionDatabaseUpdates, SubstateDatabase,
    };
    use tempfile::TempDir;

    /// Aggressive state-history GC must not affect current-tip reads.
    /// `StateCf` holds the authoritative current value per key; deleting
    /// history only costs the ability to serve historical reads below
    /// the retention floor.
    #[test]
    fn state_history_gc_preserves_current_state() {
        let temp_dir = TempDir::new().unwrap();
        let config = crate::config::RocksDbConfig {
            jmt_history_length: 2, // tiny retention for test
            ..Default::default()
        };
        let storage = RocksDbStorage::open_with_config(temp_dir.path(), config).unwrap();

        let mk_key = |seed: u8, sort: u8| {
            (
                DbPartitionKey {
                    node_key: vec![seed; 50],
                    partition_num: 0,
                },
                DbSortKey(vec![sort]),
            )
        };
        let (pk_a, sk_a) = mk_key(1, 10);
        let (pk_b, sk_b) = mk_key(2, 20);

        let mut writes = DatabaseUpdates::default();
        for (pk, sk, v) in [
            (pk_a.clone(), sk_a.clone(), vec![0xAA]),
            (pk_b.clone(), sk_b.clone(), vec![0xBB]),
        ] {
            writes
                .node_updates
                .entry(pk.node_key.clone())
                .or_insert_with(|| NodeDatabaseUpdates {
                    #[allow(clippy::default_trait_access)] // foreign type alias varies by crate; concrete type not worth importing
                    partition_updates: Default::default(),
                })
                .partition_updates
                .insert(
                    pk.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sk, DatabaseUpdate::Set(v))].into_iter().collect(),
                    },
                );
        }
        storage.commit(&writes).unwrap();

        // Advance JMT version past the retention window with empty
        // commits so the history cutoff is above version 1.
        for _ in 0..4 {
            storage.commit(&DatabaseUpdates::default()).unwrap();
        }

        storage.run_state_history_gc();

        // Current-tip reads are served from StateCf — history GC
        // cannot affect them regardless of how aggressive the retention is.
        assert_eq!(
            storage.get_raw_substate_by_db_key(&pk_a, &sk_a),
            Some(vec![0xAA]),
            "StateCf entry for key A survives state-history GC"
        );
        assert_eq!(
            storage.get_raw_substate_by_db_key(&pk_b, &sk_b),
            Some(vec![0xBB]),
            "StateCf entry for key B survives state-history GC"
        );
    }
}
