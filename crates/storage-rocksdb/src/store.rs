//! `SubstateStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::jvt_snapshot_store::SnapshotTreeStore;
use crate::snapshot::RocksDbSnapshot;
use crate::typed_cf::TypedCf;

use crate::substate_key;
use hyperscale_metrics as metrics;
use hyperscale_storage::{DatabaseUpdates, DbSortKey, JvtSnapshot, SubstateStore};
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

        let entity_prefix = substate_key::node_entity_key(node_id);
        let versioned_cf = crate::column_families::VersionedSubstatesCf::handle(&self.cf());
        let snap = self.db.snapshot();

        // MVCC scan: iterate versioned_substates for this entity prefix.
        // Keys are ((partition_key, sort_key), version), sorted lexicographically.
        // For each unique (partition_key, sort_key), take the latest version <= block_height.
        type SubstateKey = (hyperscale_storage::DbPartitionKey, DbSortKey);

        let mut results = Vec::new();
        let mut current_sk: Option<SubstateKey> = None;
        let mut current_best: Option<Vec<u8>> = None;

        for ((substate_key, version), value) in crate::typed_cf::prefix_iter_snap::<
            crate::column_families::VersionedSubstatesCf,
        >(&snap, versioned_cf, &entity_prefix)
        {
            // Substate key changed — flush previous group.
            if current_sk.as_ref() != Some(&substate_key) {
                if let (Some((pk, sk)), Some(val)) = (current_sk.take(), current_best.take()) {
                    results.push((pk.partition_num, sk, val));
                }
                current_sk = Some(substate_key);
                current_best = None;
            }

            // Ascending version order: overwrite with each version <= height.
            if version <= block_height {
                if value.is_empty() {
                    current_best = None; // tombstone
                } else {
                    current_best = Some(value);
                }
            }
        }

        // Flush last group.
        if let (Some((pk, sk)), Some(val)) = (current_sk, current_best) {
            results.push((pk.partition_num, sk, val));
        }

        Some(results)
    }

    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<hyperscale_types::VerkleInclusionProof> {
        // Use a RocksDB snapshot for all reads so concurrent JVT GC cannot
        // delete nodes mid-proof-generation.
        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);
        hyperscale_storage::tree::proofs::generate_proof(
            &snapshot_store,
            storage_keys,
            block_height,
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
        parent_block_height: u64,
        updates_per_cert: &[DatabaseUpdates],
        block_height: u64,
    ) -> (hyperscale_types::Hash, JvtSnapshot) {
        // Use a RocksDB snapshot for consistent reads during JVT computation.
        // This prevents stale node deletions mid-computation from panicking.
        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);

        // Merge all certificates into a single update — later cert wins for conflicts.
        let merged = hyperscale_storage::merge_database_updates(updates_per_cert);

        let parent_version =
            hyperscale_storage::tree::jvt_parent_height(parent_block_height, expected_base_root);
        let (root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            parent_version,
            block_height,
            &merged,
            &Default::default(),
        );

        let snapshot = JvtSnapshot::from_collected_writes(
            collected,
            expected_base_root,
            parent_block_height,
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
        block: &hyperscale_types::Block,
        qc: &hyperscale_types::QuorumCertificate,
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
        let stale_count = jvt_snapshot.stale_node_keys.len();
        let associations_count = jvt_snapshot.leaf_substate_associations.len();
        let new_version = jvt_snapshot.new_version;
        let new_root = jvt_snapshot.result_root;

        self.append_jvt_to_batch(&mut write_batch, &jvt_snapshot, new_version);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        Self::append_consensus_to_batch(&mut write_batch, block, qc);

        // Apply everything atomically with a single fsync
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        // Populate the node cache with the newly committed nodes so that
        // subsequent reads (proof generation, next block's state root
        // verification) hit the cache instead of deserializing from RocksDB.
        self.node_cache.populate(&jvt_snapshot.nodes);

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
