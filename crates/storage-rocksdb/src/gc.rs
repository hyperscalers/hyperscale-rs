//! JVT garbage collection for RocksDB storage.

use crate::column_families::{JvtNodesCf, StaleJvtNodesCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{self, TypedCf};

use hyperscale_storage::jmt::{StaleTreePart, StoredNode, StoredNodeKey};
use rocksdb::{ColumnFamily, WriteBatch};

impl RocksDbStorage {
    /// Run garbage collection for stale JVT nodes.
    ///
    /// Deletes JVT nodes that became stale at heights older than
    /// `current_height - jvt_history_length`, freeing disk space while
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
    pub fn run_jvt_gc(&self) -> usize {
        let start = std::time::Instant::now();

        let (current_version, _) = self.read_jvt_metadata();

        // Calculate the cutoff version — delete stale parts older than this.
        let cutoff_version = current_version.saturating_sub(self.jvt_history_length);

        if cutoff_version == 0 {
            return 0;
        }

        let cf = self.cf();
        let stale_cf = StaleJvtNodesCf::handle(&cf);
        let jvt_cf = JvtNodesCf::handle(&cf);

        let mut processed_count = 0;
        let mut deleted_nodes = 0;
        let mut batch = WriteBatch::default();

        for (version, stale_parts) in typed_cf::iter_all::<StaleJvtNodesCf>(&self.db, stale_cf) {
            if version >= cutoff_version {
                break;
            }

            for stale_part in stale_parts {
                match stale_part {
                    StaleTreePart::Node(key) => {
                        typed_cf::batch_delete::<JvtNodesCf>(&mut batch, jvt_cf, &key);
                        self.node_cache.remove(&key.to_jvt());
                        deleted_nodes += 1;
                    }
                    StaleTreePart::Subtree(key) => {
                        deleted_nodes += Self::delete_subtree(
                            &self.db,
                            jvt_cf,
                            &key,
                            &mut batch,
                            &self.node_cache,
                        );
                    }
                }
            }

            typed_cf::batch_delete::<StaleJvtNodesCf>(&mut batch, stale_cf, &version);
            processed_count += 1;
        }

        if !batch.is_empty() {
            if let Err(e) = self.db.write(batch) {
                tracing::error!("JVT GC write failed: {}", e);
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
                "JVT GC completed"
            );
        }

        processed_count
    }

    /// Delete a JVT subtree iteratively using an explicit stack.
    ///
    /// Avoids stack overflow on deep trees. Returns the number of nodes deleted.
    fn delete_subtree(
        db: &rocksdb::DB,
        jvt_cf: &ColumnFamily,
        root_key: &StoredNodeKey,
        batch: &mut WriteBatch,
        node_cache: &hyperscale_storage::jmt::NodeCache,
    ) -> usize {
        let mut stack = vec![root_key.clone()];
        let mut deleted = 0;

        while let Some(key) = stack.pop() {
            let node = match typed_cf::get::<JvtNodesCf>(db, jvt_cf, &key) {
                Some(versioned) => versioned.into_latest(),
                None => continue, // Already deleted in a previous GC run.
            };

            if let StoredNode::Internal(internal) = &node {
                for child in &internal.children {
                    stack.push(key.child_key(child.version, child.index));
                }
            }

            typed_cf::batch_delete::<JvtNodesCf>(batch, jvt_cf, &key);
            node_cache.remove(&key.to_jvt());
            deleted += 1;
        }

        deleted
    }
}
