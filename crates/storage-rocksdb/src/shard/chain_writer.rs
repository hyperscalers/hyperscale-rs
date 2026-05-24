//! `ShardChainWriter` implementation for `RocksDbShardStorage`.

use std::sync::Arc;

use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    BaseReadCache, BeaconWitnessCommit, JmtSnapshot, PreparedCommitBatchEntry, ShardChainWriter,
    merge_database_updates, merge_updates_from_receipts,
};
use hyperscale_types::{
    Block, BlockHeight, FinalizedWave, QuorumCertificate, StateRoot, StoredReceipt,
};
use radix_substate_store_interface::interface::DatabaseUpdates;
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::{ALL_COLUMN_FAMILIES, ConsensusReceiptsCf, ExecutionMetadataCf};
use super::core::RocksDbShardStorage;
use super::execution_certs::append_block_certs_to_batch;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::receipts::add_receipt_to_batch;
use crate::typed_cf::TypedCf;

/// Precomputed commit work for a `RocksDB` block commit.
///
/// Contains a pre-built `WriteBatch` (substate + receipt writes) and a
/// `JmtSnapshot` (precomputed Merkle tree nodes).
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct RocksDbPreparedCommit {
    pub(crate) write_batch: WriteBatch,
    pub(crate) jmt_snapshot: JmtSnapshot,
}

impl ShardChainWriter for RocksDbShardStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot {
        &prepared.jmt_snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Self::PreparedCommit) {
        let receipts: Vec<&StoredReceipt> = finalized_waves
            .iter()
            .flat_map(|fw| fw.receipts().iter())
            .collect();

        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JmtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet
        // (e.g., proposer just exited sync and BlockPersisted hasn't fired).
        if receipts.is_empty() {
            let jmt_snapshot = noop_jmt_snapshot(
                &SnapshotTreeStore::new(&self.db),
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            );
            let write_batch = WriteBatch::default();
            let prepared = RocksDbPreparedCommit {
                write_batch,
                jmt_snapshot,
            };
            return (parent_state_root, prepared);
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

        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            computed_root,
            block_height,
        );

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

        let prepared = RocksDbPreparedCommit {
            write_batch,
            jmt_snapshot,
        };

        (computed_root, prepared)
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<PreparedCommitBatchEntry<Self::PreparedCommit>>,
    ) -> Vec<StateRoot> {
        let total = blocks.len();
        let mut roots = Vec::with_capacity(total);

        for (i, (prepared, block, qc, witness)) in blocks.into_iter().enumerate() {
            let result_root = prepared.jmt_snapshot.result_root;

            let mut write_batch = prepared.write_batch;

            // Persist block data (header, transactions, certificates) +
            // beacon-witness leaves atomically. Receipt writes are
            // already in the write_batch from prepare time.
            self.append_block_to_batch(
                &mut write_batch,
                &block,
                &qc,
                witness.leaf_count_at_block_end,
            );
            self.append_beacon_witnesses_to_batch(
                &mut write_batch,
                witness.starting_leaf_index,
                &witness.leaves,
            );

            append_block_certs_to_batch(self, &mut write_batch, &block);

            // Defer fsync for all blocks except the last. The final sync=true
            // flushes the entire WAL, covering all prior deferred writes.
            let sync = i == total - 1;
            let applied = self.try_apply_prepared_commit(
                write_batch,
                &prepared.jmt_snapshot,
                &block,
                &qc,
                sync,
            );
            if applied {
                roots.push(result_root);
            } else {
                // Fast path failed — RocksDB state advanced since
                // preparation (sync path committed blocks between prepare
                // and flush). Hold `commit_lock` across the version check
                // AND the commit so `base_version` can't move under us;
                // splitting the lock would let a concurrent sync commit
                // open a gap and trip the contiguity assert in
                // `commit_block_inner_locked`.
                let _guard = self.commit_lock.lock().unwrap();
                let (current_version, _) = SnapshotTreeStore::new(&self.db).read_jmt_metadata();
                if block.height().inner() <= current_version {
                    tracing::debug!(
                        height = block.height().inner(),
                        current_version,
                        "PreparedCommit stale — block already committed, skipping"
                    );
                    roots.push(result_root);
                } else {
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
                    let root = self.commit_block_inner_locked(
                        &merged_updates,
                        &block,
                        &qc,
                        &receipts,
                        &witness,
                    );
                    roots.push(root);
                }
            }
        }

        roots
    }

    fn commit_block(
        &self,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
        witness: &BeaconWitnessCommit,
    ) -> StateRoot {
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

impl RocksDbShardStorage {
    /// Internal commit path used by `commit_block` (sync blocks without a `PreparedCommit`).
    ///
    /// The caller MUST hold `self.commit_lock`. The callers that do are
    /// [`Self::commit_block`] and the fallback branch in
    /// [`Self::commit_prepared_blocks`]; the latter holds the lock across
    /// its own `read_jmt_metadata` so the contiguity check and the commit
    /// see the same `base_version`.
    fn commit_block_inner_locked(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
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
