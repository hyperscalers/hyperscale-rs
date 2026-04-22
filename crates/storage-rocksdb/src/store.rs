//! `SubstateStore` implementation for `RocksDbStorage`.

use crate::core::RocksDbStorage;
use crate::jmt_snapshot_store::SnapshotTreeStore;
use crate::snapshot::RocksDbSnapshot;

use hyperscale_metrics as metrics;
use hyperscale_storage::{DbSortKey, JmtSnapshot, SubstateStore, VersionedStore};
use hyperscale_types::{BlockHeight, NodeId};
use rocksdb::WriteBatch;
use std::time::Instant;

impl SubstateStore for RocksDbStorage {
    type Snapshot<'a> = RocksDbSnapshot<'a>;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Default version = current committed tip as seen through the
        // snapshot's own LSN. Picking the version from a separate live
        // read would race with commits (see `snapshot_at` for details).
        let snapshot = self.db.snapshot();
        let (current_version, _) = crate::metadata::read_jmt_metadata(&snapshot);
        RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: current_version,
            current_version,
        }
    }

    fn jmt_height(&self) -> BlockHeight {
        BlockHeight(self.read_jmt_metadata().0)
    }

    fn state_root_hash(&self) -> hyperscale_types::StateRoot {
        let (_, root_hash) = self.read_jmt_metadata();
        root_hash
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: BlockHeight,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        // Take the snapshot first so bounds checks and the subsequent
        // reads all see one consistent LSN (see `snapshot_at` for why).
        let snapshot = self.db.snapshot();
        let (current_version, _) = crate::metadata::read_jmt_metadata(&snapshot);
        if block_height.0 > current_version {
            return None;
        }
        let floor = current_version.saturating_sub(self.jmt_history_length);
        if block_height.0 < floor {
            // Below retention — historical state no longer recoverable.
            // External API: return None (network-supplied heights may
            // legitimately fall out of range; `snapshot_at` would panic,
            // so don't delegate for this case).
            return None;
        }
        let snap = RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: block_height.0,
            current_version,
        };
        Some(snap.list_raw_values_for_node(node_id))
    }

    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: BlockHeight,
    ) -> Option<hyperscale_types::MerkleInclusionProof> {
        // Use a RocksDB snapshot for all reads so concurrent JMT GC cannot
        // delete nodes mid-proof-generation.
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        hyperscale_storage::tree::proofs::generate_proof(
            &snapshot_store,
            storage_keys,
            block_height,
        )
    }
}

impl VersionedStore for RocksDbStorage {
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        // Take the DB snapshot FIRST, then read metadata THROUGH it.
        // Reading metadata from the live DB and then taking the snapshot
        // races with concurrent commits: a commit between the two reads
        // leaves `current_version` stale relative to the snapshot's LSN.
        // If `version == stale_current_version`, the trivial branch fires
        // and returns post-commit StateCf values — a torn read.
        // Capturing both from the same snapshot gives one consistent view.
        let snapshot = self.db.snapshot();
        let (current_version, _) = crate::metadata::read_jmt_metadata(&snapshot);

        // Retention invariant: below the configured floor we can't
        // serve historical reads reliably (history entries have been GC'd).
        // This is an internal DA-assumption check — external APIs that
        // accept network-supplied versions (e.g. `list_substates_for_node_at_height`)
        // must check retention themselves and return None, not call
        // through here.
        //
        // `floor` MUST match the cutoff in `run_state_history_gc` — see the
        // boundary invariant there. Zero-margin by design.
        let floor = current_version.saturating_sub(self.jmt_history_length);
        assert!(
            height.0 >= floor,
            "snapshot_at({height}) below retention floor {floor} \
             (current_version={current_version}, jmt_history_length={}) — \
             BFT/DA invariant broken; caller must anchor within retention",
            self.jmt_history_length,
        );
        RocksDbSnapshot {
            snapshot,
            db: &self.db,
            version: height.0,
            current_version,
        }
    }
}

impl RocksDbStorage {
    /// Try to apply a prepared block commit with a single fsync.
    ///
    /// This is the fast path for block commit. Applies the pre-built WriteBatch
    /// atomically with one fsync, including all JMT nodes from the snapshot.
    ///
    /// Returns `true` if successfully applied (fast path),
    /// or `false` if the JMT state has changed since preparation
    /// (caller should fall back to slow path).
    ///
    /// # Panics
    /// Only panics on unrecoverable errors (RocksDB write failure).
    pub(crate) fn try_apply_prepared_commit(
        &self,
        mut write_batch: WriteBatch,
        jmt_snapshot: JmtSnapshot,
        block: &hyperscale_types::Block,
        qc: &hyperscale_types::QuorumCertificate,
        sync: bool,
    ) -> bool {
        let _commit_guard = self.commit_lock.lock().unwrap();
        let start = Instant::now();

        // Verify we're applying to the expected base state BEFORE writing anything.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        let (current_version, current_root_hash) = self.read_jmt_metadata();
        if current_root_hash != jmt_snapshot.base_root {
            tracing::warn!(
                expected_root = ?jmt_snapshot.base_root,
                actual_root = ?current_root_hash,
                "JMT snapshot base ROOT mismatch - falling back to slow path"
            );
            return false;
        }
        if current_version != jmt_snapshot.base_height.0 {
            tracing::debug!(
                expected_version = jmt_snapshot.base_height.0,
                actual_version = current_version,
                "JMT snapshot base VERSION mismatch (root matches) - proceeding with fast path. \
                 This is expected when empty commits advance the version counter."
            );
        }

        let nodes_count = jmt_snapshot.nodes.len();
        let stale_count = jmt_snapshot.stale_node_keys.len();
        let associations_count = jmt_snapshot.leaf_substate_associations.len();
        let new_version = jmt_snapshot.new_height.0;
        let new_root = jmt_snapshot.result_root;

        self.append_jmt_to_batch(&mut write_batch, &jmt_snapshot, new_version);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        Self::append_consensus_to_batch(&mut write_batch, block, qc);

        // Apply everything atomically. When batching multiple blocks, only
        // the final block sets sync=true — its fsync covers all prior WAL entries.
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(sync);

        self.db.write_opt(write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        // Populate the node cache with the newly committed nodes so that
        // subsequent reads (proof generation, next block's state root
        // verification) hit the cache instead of deserializing from RocksDB.

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("apply_prepared_commit", elapsed.as_secs_f64());

        tracing::debug!(
            new_version,
            new_root = %hex::encode(new_root.as_raw().to_bytes()),
            nodes_count,
            stale_count,
            associations_count,
            elapsed_ms = elapsed.as_millis(),
            "Applied prepared commit (single fsync)"
        );

        true
    }
}
