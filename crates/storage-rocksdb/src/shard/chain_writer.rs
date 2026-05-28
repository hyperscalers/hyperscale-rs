//! `ShardChainWriter` implementation for `RocksDbShardStorage`.

use std::sync::Arc;

use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    BaseReadCache, JmtSnapshot, ShardChainWriter, merge_database_updates,
    merge_updates_from_receipts,
};
use hyperscale_types::{
    BeaconWitnessCommit, Block, BlockHeight, CertifiedBlock, FinalizedWave, PreparedCommit,
    QuorumCertificate, StateRoot, StoredReceipt, SyncHint, Verifiable, Verified,
};
use radix_substate_store_interface::interface::DatabaseUpdates;
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::{ALL_COLUMN_FAMILIES, ConsensusReceiptsCf, ExecutionMetadataCf};
use super::core::RocksDbShardStorage;
use super::execution_certs::append_block_certs_to_batch;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::receipts::add_receipt_to_batch;
use crate::typed_cf::TypedCf;

impl ShardChainWriter for RocksDbShardStorage {
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<Verifiable<FinalizedWave>>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit) {
        let receipts: Vec<&StoredReceipt> = finalized_waves
            .iter()
            .flat_map(|fw| fw.receipts().iter())
            .collect();

        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JmtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet
        // (e.g., proposer just exited sync and BlockPersisted hasn't fired).
        if receipts.is_empty() {
            let jmt_snapshot = Arc::new(noop_jmt_snapshot(
                &SnapshotTreeStore::new(&self.db),
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            ));
            let prepared = build_prepared_commit(
                Arc::clone(self),
                WriteBatch::default(),
                Arc::clone(&jmt_snapshot),
            );
            return (parent_state_root, jmt_snapshot, prepared);
        }

        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let parent_version =
            jmt_parent_height(parent_block_height, parent_state_root).map(BlockHeight::inner);

        // Collect per-receipt DatabaseUpdates references — no merge needed.
        // State locking guarantees no key conflicts between receipts, so
        // put_at_version can flatten them directly into JMT work items.
        let per_receipt_updates: Vec<&DatabaseUpdates> = receipts
            .iter()
            .filter_map(|r| r.consensus.database_updates())
            .collect();

        let (computed_root, collected) = if pending_snapshots.is_empty() {
            put_at_version(
                &snapshot_store,
                parent_version,
                block_height.inner(),
                &per_receipt_updates,
                &std::collections::HashMap::new(),
            )
        } else {
            let overlay = OverlayTreeReader::new(&snapshot_store, pending_snapshots);
            put_at_version(
                &overlay,
                parent_version,
                block_height.inner(),
                &per_receipt_updates,
                &std::collections::HashMap::new(),
            )
        };

        let jmt_snapshot = Arc::new(JmtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            computed_root,
            block_height,
        ));

        // Merge updates for the substate WriteBatch (off the state_root critical path).
        let updates: Vec<DatabaseUpdates> = receipts
            .iter()
            .filter_map(|r| r.consensus.database_updates().cloned())
            .collect();
        let merged_updates = merge_database_updates(&updates);

        // Pre-build substate + receipt writes into a WriteBatch for efficient commit.
        let (mut write_batch, _reset_old_keys) = self.build_substate_write_batch(
            &merged_updates,
            block_height.inner(),
            /* write_history */ true,
            base_reads,
        );

        let cf = self.cf();
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);
        let metadata_cf = ExecutionMetadataCf::handle(&cf);
        for receipt in &receipts {
            add_receipt_to_batch(&mut write_batch, consensus_cf, metadata_cf, receipt);
        }

        let prepared =
            build_prepared_commit(Arc::clone(self), write_batch, Arc::clone(&jmt_snapshot));

        (computed_root, jmt_snapshot, prepared)
    }

    fn commit_block(
        &self,
        certified: &Arc<Verified<CertifiedBlock>>,
        witness: &BeaconWitnessCommit,
    ) -> StateRoot {
        let block = certified.block();
        let qc = certified.qc_verified();
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        let merged_updates = merge_updates_from_receipts(&receipts);
        let _commit_guard = self.commit_lock.lock().unwrap();
        self.commit_block_inner_locked(&merged_updates, block, qc, &receipts, witness)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        let mut block_cache_usage = 0u64;
        let mut memtable_usage = 0u64;

        for cf_name in ALL_COLUMN_FAMILIES {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                // Block cache is shared — reading from any CF gives the total.
                // We read it once from the first CF we find.
                if block_cache_usage == 0
                    && let Ok(Some(val)) = self
                        .db
                        .property_int_value_cf(&cf, "rocksdb.block-cache-usage")
                {
                    block_cache_usage = val;
                }
                if let Ok(Some(val)) = self
                    .db
                    .property_int_value_cf(&cf, "rocksdb.cur-size-all-mem-tables")
                {
                    memtable_usage += val;
                }
            }
        }
        (block_cache_usage, memtable_usage)
    }
}

/// Build the closure that performs the atomic block commit.
///
/// Captures the storage handle, the pre-built `WriteBatch`, and the JMT
/// snapshot. At invocation time the closure receives the
/// `Verified<CertifiedBlock>` and beacon-witness commit, folds them into
/// the batch, and writes — with a fallback through
/// [`RocksDbShardStorage::commit_block_inner_locked`] if a concurrent sync
/// commit advanced past us.
fn build_prepared_commit(
    storage: Arc<RocksDbShardStorage>,
    write_batch: WriteBatch,
    jmt_snapshot: Arc<JmtSnapshot>,
) -> PreparedCommit {
    Box::new(
        move |sync_hint: SyncHint,
              certified: &Arc<Verified<CertifiedBlock>>,
              witness: &BeaconWitnessCommit|
              -> StateRoot {
            let result_root = jmt_snapshot.result_root;
            let mut write_batch = write_batch;

            let block = certified.block();
            let qc = certified.qc_verified();

            storage.append_block_to_batch(
                &mut write_batch,
                block,
                qc,
                witness.leaf_count_at_block_end,
            );
            storage.append_beacon_witnesses_to_batch(
                &mut write_batch,
                witness.starting_leaf_index,
                &witness.leaves,
            );
            append_block_certs_to_batch(&storage, &mut write_batch, block);

            let applied = storage.try_apply_prepared_commit(
                write_batch,
                &jmt_snapshot,
                block,
                qc,
                sync_hint.is_flush_now(),
            );
            if applied {
                return result_root;
            }

            // Fast path failed — RocksDB state advanced since preparation
            // (sync path committed blocks between prepare and flush). Hold
            // `commit_lock` across the version check AND the commit so
            // `base_version` can't move under us; splitting the lock
            // would let a concurrent sync commit open a gap and trip the
            // contiguity assert in `commit_block_inner_locked`.
            let _guard = storage.commit_lock.lock().unwrap();
            let (current_version, _) = SnapshotTreeStore::new(&storage.db).read_jmt_metadata();
            if block.height().inner() <= current_version {
                tracing::debug!(
                    height = block.height().inner(),
                    current_version,
                    "PreparedCommit stale — block already committed, skipping"
                );
                return result_root;
            }
            tracing::debug!(
                height = block.height().inner(),
                current_version,
                "PreparedCommit stale, falling back to commit_block"
            );
            let receipts: Vec<StoredReceipt> = block
                .certificates()
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect();
            let merged_updates = merge_updates_from_receipts(&receipts);
            storage.commit_block_inner_locked(&merged_updates, block, qc, &receipts, witness)
        },
    )
}

impl RocksDbShardStorage {
    /// Internal commit path used by `commit_block` (sync blocks without a `PreparedCommit`).
    ///
    /// The caller MUST hold `self.commit_lock`. The callers that do are
    /// [`Self::commit_block`] and the fallback branch inside the closure
    /// returned by `build_prepared_commit`; the latter holds the lock
    /// across its own `read_jmt_metadata` so the contiguity check and
    /// the commit see the same `base_version`.
    pub(crate) fn commit_block_inner_locked(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
        receipts: &[StoredReceipt],
        witness: &BeaconWitnessCommit,
    ) -> StateRoot {
        let block_height = block.height().inner();

        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();

        assert!(
            block_height == base_version + 1 || (block_height == 0 && base_version == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({base_version})"
        );

        // Sync path has no view → no base-read cache → fall through to
        // multi_get_cf for all priors.
        let (mut batch, reset_old_keys) = self.build_substate_write_batch(
            merged_updates,
            block_height,
            /* write_history */ true,
            /* base_reads */ None,
        );

        self.append_block_to_batch(&mut batch, block, qc, witness.leaf_count_at_block_end);
        self.append_beacon_witnesses_to_batch(
            &mut batch,
            witness.starting_leaf_index,
            &witness.leaves,
        );

        append_block_certs_to_batch(self, &mut batch, block);

        let cf = self.cf();
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);
        let metadata_cf = ExecutionMetadataCf::handle(&cf);
        for receipt in receipts {
            add_receipt_to_batch(&mut batch, consensus_cf, metadata_cf, receipt);
        }

        // Compute JMT update.
        let parent_version =
            jmt_parent_height(BlockHeight::new(base_version), base_root).map(BlockHeight::inner);
        let (new_root, collected) = put_at_version(
            &snapshot_store,
            parent_version,
            block_height,
            &[merged_updates],
            &reset_old_keys,
        );
        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            base_root,
            BlockHeight::new(base_version),
            new_root,
            BlockHeight::new(block_height),
        );
        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, block_height);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        Self::append_consensus_to_batch(&mut batch, block, qc);

        // Single atomic write with sync — one fsync instead of N.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        new_root
    }
}
