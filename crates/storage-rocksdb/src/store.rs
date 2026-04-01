//! `SubstateStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::jvt_snapshot_store::SnapshotTreeStore;
use crate::snapshot::RocksDbSnapshot;

use hyperscale_metrics as metrics;
use hyperscale_storage::{keys, DatabaseUpdates, DbSortKey, JvtSnapshot, SubstateStore};
use hyperscale_types::NodeId;
use rocksdb::WriteBatch;
use std::time::Instant;

impl SubstateStore for RocksDbStorage {
    type Snapshot<'a> = RocksDbSnapshot<'a>;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Use RocksDB's native snapshot feature for point-in-time isolation.
        // The snapshot provides a consistent view of the database at the time
        // of creation, immune to concurrent writes.
        RocksDbSnapshot {
            snapshot: self.db.snapshot(),
            db: &self.db,
        }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

        let items = self.iter_range(&prefix, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let partition_num = full_key[prefix_len];
                let sort_key_bytes = full_key[prefix_len + 1..].to_vec();
                Some((partition_num, DbSortKey(sort_key_bytes), value.into_vec()))
            } else {
                None
            }
        }))
    }

    fn jvt_version(&self) -> u64 {
        self.read_jvt_metadata().0
    }

    fn state_root_hash(&self) -> hyperscale_types::Hash {
        let (_, root_hash) = self.read_jvt_metadata();
        root_hash
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        let (current_version, _) = self.read_jvt_metadata();
        if block_height > current_version {
            return None;
        }

        let versioned_cf = self.cf().versioned_substates;
        let entity_prefix = keys::node_entity_key(node_id);
        let entity_len = entity_prefix.len();
        let end_prefix = keys::next_prefix(&entity_prefix)?;

        // MVCC scan: iterate versioned_substates for this entity prefix.
        // Keys are storage_key ++ version_BE, sorted lexicographically.
        // For each unique storage_key, take the latest version <= block_height.
        let snap = self.db.snapshot();
        let mut iter = snap.raw_iterator_cf(versioned_cf);
        iter.seek(&entity_prefix);

        let mut results = Vec::new();
        let mut current_sk: Option<Vec<u8>> = None;
        let mut current_best: Option<Vec<u8>> = None;

        while iter.valid() {
            let full_key = match iter.key() {
                Some(k) => k,
                None => break,
            };

            // Check we're still in the entity prefix (compare storage_key portion).
            if full_key.len() < 8 {
                iter.next();
                continue;
            }
            let storage_key = &full_key[..full_key.len() - 8];
            if !storage_key.starts_with(&entity_prefix) {
                // Past the end prefix — check against the incremented prefix.
                if storage_key >= end_prefix.as_slice() {
                    break;
                }
            }

            let version = u64::from_be_bytes(full_key[full_key.len() - 8..].try_into().unwrap());

            // Storage key changed — flush previous group.
            if current_sk.as_deref() != Some(storage_key) {
                if let (Some(ref sk), Some(val)) = (&current_sk, current_best.take()) {
                    if sk.len() > entity_len {
                        let partition_num = sk[entity_len];
                        let sort_key = DbSortKey(sk[entity_len + 1..].to_vec());
                        results.push((partition_num, sort_key, val));
                    }
                }
                current_sk = Some(storage_key.to_vec());
                current_best = None;
            }

            // Ascending version order: overwrite with each version <= height.
            if version <= block_height {
                let val = iter.value().unwrap_or_default();
                if val.is_empty() {
                    current_best = None; // tombstone
                } else {
                    current_best = Some(val.to_vec());
                }
            }

            iter.next();
        }

        // Flush last group.
        if let (Some(ref sk), Some(val)) = (&current_sk, current_best) {
            if sk.len() > entity_len {
                let partition_num = sk[entity_len];
                let sort_key = DbSortKey(sk[entity_len + 1..].to_vec());
                results.push((partition_num, sort_key, val.clone()));
            }
        }

        Some(results)
    }

    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<hyperscale_types::SubstateInclusionProof> {
        // Use a RocksDB snapshot for all reads so concurrent JVT GC cannot
        // delete nodes mid-proof-generation.
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        hyperscale_storage::proofs::generate_proof(
            &snapshot_store,
            storage_keys,
            block_height,
            Some(&self.node_cache),
        )
    }
}

impl RocksDbStorage {
    /// Compute speculative state root and capture a snapshot for later application.
    ///
    /// This is used for state root verification and proposal. The caller specifies
    /// the expected base root (parent block's state_root), and we verify the JVT
    /// matches before computing the new root after applying certificate writes.
    ///
    /// Returns both the computed state root AND a [`JvtSnapshot`] containing the
    /// tree nodes created during computation. The snapshot can be cached and applied
    /// during block commit, avoiding redundant recomputation.
    pub(crate) fn compute_speculative_root_from_base(
        &self,
        expected_base_root: hyperscale_types::Hash,
        updates_per_cert: &[DatabaseUpdates],
        block_height: u64,
    ) -> (hyperscale_types::Hash, JvtSnapshot) {
        // This computation runs on the consensus-crypto thread pool, concurrent with
        // block commits on the tokio runtime threads. Block commits delete stale JVT
        // nodes from RocksDB. Without a snapshot, this computation could read nodes
        // that are deleted mid-computation, causing a panic in the Radix JVT code.
        //
        // The snapshot provides a consistent view of RocksDB at this moment. Even if
        // another thread deletes nodes, our reads through the snapshot still see them.
        // The snapshot is lightweight (just a version marker) and automatically releases
        // when dropped at the end of this function.
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jvt_metadata();

        // Verify the JVT root matches the expected base root.
        // We don't short-circuit on empty updates because even empty blocks
        // need a root node at the new version (JVT version = block height).
        if base_root != expected_base_root {
            tracing::warn!(
                ?base_root,
                ?expected_base_root,
                "JVT root mismatch - verification will likely fail"
            );
        }

        // Merge all certificates into a single update — later cert wins for conflicts.
        let merged = hyperscale_storage::merge_database_updates(updates_per_cert);

        let parent_version = hyperscale_storage::jvt_parent_height(base_version, base_root);
        let (root, collected) = hyperscale_storage::jmt::put_at_version(
            &snapshot_store,
            parent_version,
            block_height,
            &merged,
            &Default::default(),
            Some(&self.node_cache),
        );

        let snapshot = JvtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            root,
            block_height,
        );

        (root, snapshot)
    }

    /// Try to apply a prepared block commit with a single fsync.
    ///
    /// This is the fast path for block commit. Applies the pre-built WriteBatch
    /// atomically with one fsync, including all JVT nodes from the snapshot.
    ///
    /// Returns `true` if successfully applied (fast path),
    /// or `false` if the JVT state has changed since preparation
    /// (caller should fall back to slow path).
    ///
    /// # Panics
    /// Only panics on unrecoverable errors (RocksDB write failure).
    pub(crate) fn try_apply_prepared_commit(
        &self,
        mut write_batch: WriteBatch,
        jvt_snapshot: JvtSnapshot,
        consensus: Option<&hyperscale_storage::ConsensusCommitData>,
    ) -> bool {
        let _commit_guard = self.commit_lock.lock().unwrap();
        let start = Instant::now();

        // Verify we're applying to the expected base state BEFORE writing anything.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        let (current_version, current_root_hash) = self.read_jvt_metadata();
        if current_root_hash != jvt_snapshot.base_root {
            tracing::warn!(
                expected_root = ?jvt_snapshot.base_root,
                actual_root = ?current_root_hash,
                "JVT snapshot base ROOT mismatch - falling back to slow path"
            );
            return false;
        }
        if current_version != jvt_snapshot.base_version {
            tracing::debug!(
                expected_version = jvt_snapshot.base_version,
                actual_version = current_version,
                "JVT snapshot base VERSION mismatch (root matches) - proceeding with fast path. \
                 This is expected when empty commits advance the version counter."
            );
        }

        let nodes_count = jvt_snapshot.nodes.len();
        let stale_count = jvt_snapshot.stale_tree_parts.len();
        let associations_count = jvt_snapshot.leaf_substate_associations.len();
        let new_version = jvt_snapshot.new_version;
        let new_root = jvt_snapshot.result_root;

        self.append_jvt_to_batch(&mut write_batch, &jvt_snapshot, new_version);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        if let Some(consensus) = consensus {
            Self::append_consensus_to_batch(&mut write_batch, consensus);
        }

        // Apply everything atomically with a single fsync
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("apply_prepared_commit", elapsed.as_secs_f64());

        tracing::debug!(
            new_version,
            new_root = %hex::encode(new_root.to_bytes()),
            nodes_count,
            stale_count,
            associations_count,
            elapsed_ms = elapsed.as_millis(),
            "Applied prepared commit (single fsync)"
        );

        true
    }
}
