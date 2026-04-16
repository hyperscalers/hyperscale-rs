//! JMT garbage collection for RocksDB storage.

use crate::column_families::{JmtNodesCf, StaleJmtNodesCf};
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
}

// Re-export the jmt_key type alias for compatibility elsewhere if needed.
#[allow(unused)]
fn _assert_jmt_key_stable(_k: &jmt::NodeKey) {}
