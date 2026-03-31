//! JVT garbage collection for RocksDB storage.

use crate::config::{
    ASSOCIATED_STATE_TREE_VALUES_CF, JVT_NODES_CF, STALE_STATE_HASH_TREE_PARTS_CF,
};
use crate::core::RocksDbStorage;
use hyperscale_dispatch::Dispatch;
use hyperscale_storage::jmt::{
    encode_key as encode_jvt_key, StaleTreePart, StoredNode, StoredNodeKey, VersionedStoredNode,
};
use rocksdb::{ColumnFamily, WriteBatch};

impl<D: Dispatch + 'static> RocksDbStorage<D> {
    /// Run garbage collection for stale JVT nodes.
    ///
    /// This deletes JVT nodes (and their associations) that became stale at heights
    /// older than `current_height - jvt_history_length`.
    ///
    /// # When to Call
    ///
    /// Call this periodically (e.g., after each block commit, or on a timer).
    /// It's safe to call concurrently with commits - GC only touches old data
    /// that's no longer reachable from the current state root.
    ///
    /// # Returns
    ///
    /// The number of stale parts entries processed (each entry may contain
    /// multiple nodes/subtrees).
    pub fn run_jvt_gc(&self) -> usize {
        let start = std::time::Instant::now();

        let (current_version, _) = self.read_jvt_metadata();

        // Calculate the cutoff version - delete stale parts older than this
        let cutoff_version = current_version.saturating_sub(self.jvt_history_length);

        if cutoff_version == 0 {
            // Nothing to GC yet - we haven't accumulated enough history
            return 0;
        }

        let stale_cf = match self.db.cf_handle(STALE_STATE_HASH_TREE_PARTS_CF) {
            Some(cf) => cf,
            None => return 0,
        };

        let jvt_cf = match self.db.cf_handle(JVT_NODES_CF) {
            Some(cf) => cf,
            None => return 0,
        };

        let assoc_cf = self.db.cf_handle(ASSOCIATED_STATE_TREE_VALUES_CF);

        // Iterate through stale parts older than the cutoff
        let mut iter = self.db.raw_iterator_cf(stale_cf);
        iter.seek_to_first();

        let mut processed_count = 0;
        let mut deleted_nodes = 0;
        let mut batch = WriteBatch::default();

        while iter.valid() {
            let version_key = match iter.key() {
                Some(k) if k.len() == 8 => k,
                _ => {
                    iter.next();
                    continue;
                }
            };

            let version = u64::from_be_bytes(version_key.try_into().unwrap());

            // Stop if we've reached versions we want to keep
            if version >= cutoff_version {
                break;
            }

            // Decode the stale parts
            if let Some(value) = iter.value() {
                if let Ok(stale_parts) = sbor::basic_decode::<Vec<StaleTreePart>>(value) {
                    for stale_part in stale_parts {
                        match stale_part {
                            StaleTreePart::Node(key) => {
                                let encoded_key = encode_jvt_key(&key);
                                batch.delete_cf(jvt_cf, &encoded_key);
                                if let Some(cf) = assoc_cf {
                                    batch.delete_cf(cf, &encoded_key);
                                }
                                deleted_nodes += 1;
                            }
                            StaleTreePart::Subtree(key) => {
                                // For subtrees, we recursively delete all nodes.
                                // This is more expensive but ensures proper cleanup.
                                self.delete_subtree_recursive(
                                    &key,
                                    jvt_cf,
                                    assoc_cf,
                                    &mut batch,
                                    &mut deleted_nodes,
                                );
                            }
                        }
                    }
                }
            }

            // Delete the stale parts entry itself
            batch.delete_cf(stale_cf, version_key);
            processed_count += 1;

            iter.next();
        }

        // Apply all deletions
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

    /// Recursively delete a subtree and its associations.
    fn delete_subtree_recursive(
        &self,
        root_key: &StoredNodeKey,
        jvt_cf: &ColumnFamily,
        assoc_cf: Option<&ColumnFamily>,
        batch: &mut WriteBatch,
        deleted_count: &mut usize,
    ) {
        // Read the root node to find its children
        let encoded_key = encode_jvt_key(root_key);
        let node = match self.db.get_cf(jvt_cf, &encoded_key) {
            Ok(Some(bytes)) => {
                match sbor::basic_decode::<VersionedStoredNode>(&bytes) {
                    Ok(versioned) => versioned.into_latest(),
                    Err(_) => {
                        // Can't decode - just delete the root
                        batch.delete_cf(jvt_cf, &encoded_key);
                        if let Some(cf) = assoc_cf {
                            batch.delete_cf(cf, &encoded_key);
                        }
                        *deleted_count += 1;
                        return;
                    }
                }
            }
            _ => {
                // Node doesn't exist (already deleted in a previous GC run)
                return;
            }
        };

        // Process children first (post-order traversal)
        match &node {
            StoredNode::Internal(internal) => {
                for child in &internal.children {
                    let child_key = root_key.child_key(child.version, child.index);
                    self.delete_subtree_recursive(
                        &child_key,
                        jvt_cf,
                        assoc_cf,
                        batch,
                        deleted_count,
                    );
                }
            }
            StoredNode::EaS(_) => {
                // EaS nodes have no children
            }
        }

        // Delete this node
        batch.delete_cf(jvt_cf, &encoded_key);
        if let Some(cf) = assoc_cf {
            batch.delete_cf(cf, &encoded_key);
        }
        *deleted_count += 1;
    }
}
