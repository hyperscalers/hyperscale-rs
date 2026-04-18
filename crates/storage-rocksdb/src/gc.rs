//! Garbage collection for RocksDB storage.
//!
//! Two independent GC passes:
//! - **JMT GC**: deletes stale tree nodes older than `jmt_history_length`.
//! - **Versioned substates GC**: prunes MVCC history from `versioned_substates`
//!   CF, keeping only the floor entry (latest version ≤ cutoff) per substate
//!   key so historical reads within the retention window still resolve.

use crate::column_families::{JmtNodesCf, StaleJmtNodesCf, StateCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{self, TypedCf};

use crate::jmt_stored::{StaleTreePart, StoredNode, StoredNodeKey};
use hyperscale_jmt as jmt;
use rocksdb::{ColumnFamily, WriteBatch};

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
                    StaleTreePart::Subtree(key) => {
                        deleted_nodes += Self::delete_subtree(&self.db, jmt_cf, &key, &mut batch);
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

    /// Delete a JMT subtree iteratively using an explicit stack.
    ///
    /// Avoids stack overflow on deep trees. Returns the number of nodes deleted.
    fn delete_subtree(
        db: &rocksdb::DB,
        jmt_cf: &ColumnFamily,
        root_key: &StoredNodeKey,
        batch: &mut WriteBatch,
    ) -> usize {
        let mut stack = vec![root_key.clone()];
        let mut deleted = 0;

        while let Some(stored_key) = stack.pop() {
            let node = match typed_cf::get::<JmtNodesCf>(db, jmt_cf, &stored_key) {
                Some(versioned) => versioned.into_latest(),
                None => continue, // Already deleted in a previous GC run.
            };

            if let StoredNode::Internal(internal) = &node {
                // Rehydrate the parent key to construct each child's path.
                if let Ok(jmt_key) = stored_key.to_jmt() {
                    const ARITY_BITS: u8 = 1;
                    for child in &internal.children {
                        let child_jmt_key = jmt_key.child(child.version, child.bucket, ARITY_BITS);
                        stack.push(StoredNodeKey::from_jmt(&child_jmt_key));
                    }
                }
            }

            typed_cf::batch_delete::<JmtNodesCf>(batch, jmt_cf, &stored_key);
            deleted += 1;
        }

        deleted
    }

    /// Run garbage collection for versioned substates.
    ///
    /// The `versioned_substates` CF stores MVCC history: every substate
    /// write is recorded as `(storage_key, version) → value`. Without GC,
    /// this CF grows without bound.
    ///
    /// **Retention policy**: for each unique substate key, keep:
    /// - All entries with `version > cutoff` (within the retention window).
    /// - The **floor entry** — the latest entry with `version ≤ cutoff` —
    ///   so historical reads at `height = cutoff` still resolve substates
    ///   that haven't been modified within the window.
    /// - Delete everything older than the floor.
    ///
    /// The cutoff is `current_version - jmt_history_length`, matching the
    /// JMT GC retention window.
    ///
    /// # Returns
    ///
    /// The number of entries deleted.
    pub fn run_versioned_substates_gc(&self) -> usize {
        let start = std::time::Instant::now();

        let (current_version, _) = self.read_jmt_metadata();
        let cutoff = current_version.saturating_sub(self.jmt_history_length);

        if cutoff == 0 {
            return 0;
        }

        let cf = self.cf();
        let versioned_cf = StateCf::handle(&cf);

        // Full sequential scan. Keys are ordered as [storage_key][version_BE],
        // so entries for the same substate key are contiguous with versions
        // ascending. We track the previous raw storage key bytes to detect
        // group boundaries.
        let mut iter = self.db.raw_iterator_cf(versioned_cf);
        iter.seek_to_first();

        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        // Keys pending deletion within the current substate key group.
        // We buffer them because we don't know if an entry is the floor
        // until we've seen the next entry or group boundary.
        let mut pending_deletes: Vec<Vec<u8>> = Vec::new();
        let mut prev_storage_key: Option<Vec<u8>> = None;

        const VERSION_LEN: usize = 8;
        // Flush batches periodically to bound memory.
        const BATCH_FLUSH_THRESHOLD: usize = 10_000;

        while iter.valid() {
            let raw_key = match iter.key() {
                Some(k) => k,
                None => break,
            };

            if raw_key.len() < VERSION_LEN {
                iter.next();
                continue;
            }

            let key_len = raw_key.len() - VERSION_LEN;
            let storage_key = &raw_key[..key_len];
            let version = u64::from_be_bytes(raw_key[key_len..].try_into().unwrap());

            // Detect substate key group change — flush pending deletes from
            // the previous group. The last pending entry is the floor for
            // that group; keep it so reads beyond the retention window
            // still resolve. Only the post-cutoff branch below pops the
            // floor explicitly, and that only fires if the group had
            // entries > cutoff. Groups with only pre-cutoff entries reach
            // this boundary with the floor still buffered — pop it here.
            if prev_storage_key.as_deref() != Some(storage_key) {
                pending_deletes.pop(); // keep the floor from the previous group
                for dk in pending_deletes.drain(..) {
                    batch.delete_cf(versioned_cf, &dk);
                    deleted += 1;
                }
                prev_storage_key = Some(storage_key.to_vec());
            }

            if version <= cutoff {
                // This entry is at or below the cutoff. It MIGHT be the
                // floor entry. Buffer it for deletion — if a newer entry
                // (still ≤ cutoff) comes along, the buffered one is safe
                // to delete. The last one buffered before we leave the
                // ≤cutoff zone is the floor and must be kept.
                //
                // Flush all previously buffered entries (they're older
                // than this one, so definitely not the floor).
                for dk in pending_deletes.drain(..) {
                    batch.delete_cf(versioned_cf, &dk);
                    deleted += 1;
                }
                // Buffer this entry as the potential floor.
                pending_deletes.push(raw_key.to_vec());
            } else {
                // version > cutoff — within retention window. The last
                // buffered entry (if any) is the floor; pop it to keep it.
                pending_deletes.pop(); // keep the floor
                                       // Flush any remaining older entries.
                for dk in pending_deletes.drain(..) {
                    batch.delete_cf(versioned_cf, &dk);
                    deleted += 1;
                }
            }

            if deleted >= BATCH_FLUSH_THRESHOLD && !batch.is_empty() {
                if let Err(e) = self.db.write(std::mem::take(&mut batch)) {
                    tracing::error!("Versioned substates GC write failed: {}", e);
                    return deleted;
                }
                batch = WriteBatch::default();
            }

            iter.next();
        }

        // Flush final group's pending deletes. The last buffered entry is
        // the floor for a substate that has NO entries in the retention
        // window — keep it so historical reads still resolve.
        pending_deletes.pop(); // keep the floor
        for dk in pending_deletes.drain(..) {
            batch.delete_cf(versioned_cf, &dk);
            deleted += 1;
        }

        if !batch.is_empty() {
            if let Err(e) = self.db.write(batch) {
                tracing::error!("Versioned substates GC write failed: {}", e);
                return 0;
            }
        }

        let elapsed = start.elapsed();
        if deleted > 0 {
            tracing::info!(
                deleted,
                cutoff,
                current_version,
                elapsed_ms = elapsed.as_millis(),
                "Versioned substates GC completed"
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

    /// Regression test for the GC group-boundary bug: keys with only
    /// pre-cutoff versions must retain their floor entry so reads after
    /// GC still resolve. Before the fix, the group-boundary drain
    /// unconditionally deleted all pending entries (including the floor)
    /// for every group except the last one in the scan.
    #[test]
    fn gc_preserves_floor_entry_for_all_groups() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = crate::config::RocksDbConfig::default();
        config.jmt_history_length = 2; // tiny retention for test
        let storage = RocksDbStorage::open_with_config(temp_dir.path(), config).unwrap();

        // Two distinct substate keys, each written once at version 1
        // (pre-cutoff after we advance past height 3).
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

        // Advance the JMT version past the retention window with empty
        // commits so the cutoff for GC is above version 1.
        for _ in 0..4 {
            storage.commit(&DatabaseUpdates::default()).unwrap();
        }

        storage.run_versioned_substates_gc();

        // Both keys must still resolve — their floor entries survive GC.
        assert_eq!(
            storage.get_raw_substate_by_db_key(&pk_a, &sk_a),
            Some(vec![0xAA]),
            "floor entry for key A must be preserved across GC"
        );
        assert_eq!(
            storage.get_raw_substate_by_db_key(&pk_b, &sk_b),
            Some(vec![0xBB]),
            "floor entry for key B must be preserved across GC"
        );
    }
}
