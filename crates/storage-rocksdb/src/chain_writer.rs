//! `ChainWriter` implementation for `RocksDbStorage`.

use crate::column_families::ALL_COLUMN_FAMILIES;
use crate::core::RocksDbStorage;
use crate::jvt_snapshot_store::SnapshotTreeStore;

use hyperscale_storage::JvtSnapshot;
use hyperscale_types::ReceiptBundle;
use radix_substate_store_interface::interface::DatabaseUpdates;
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Precomputed commit work for a RocksDB block commit.
///
/// Contains a pre-built `WriteBatch` (substate + receipt writes) and a
/// `JvtSnapshot` (precomputed Verkle tree nodes). Also carries the merged
/// `DatabaseUpdates` and receipts for fallback recompute if the prepared
/// data is stale.
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct RocksDbPreparedCommit {
    pub(crate) write_batch: WriteBatch,
    pub(crate) jvt_snapshot: JvtSnapshot,
    pub(crate) merged_updates: DatabaseUpdates,
    pub(crate) receipts: Vec<ReceiptBundle>,
}

impl hyperscale_storage::ChainWriter for RocksDbStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: hyperscale_types::Hash,
        parent_block_height: u64,
        receipts: &[ReceiptBundle],
        block_height: u64,
    ) -> (hyperscale_types::Hash, Self::PreparedCommit) {
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(receipts);

        let (computed_root, jvt_snapshot) = self.compute_speculative_root_from_base(
            parent_state_root,
            parent_block_height,
            std::slice::from_ref(&merged_updates),
            block_height,
        );

        // Pre-build substate + receipt writes into a WriteBatch for efficient commit.
        let (mut write_batch, _reset_old_keys) =
            self.build_substate_write_batch(&merged_updates, Some(block_height));

        for bundle in receipts {
            self.add_receipt_bundle_to_batch(&mut write_batch, bundle);
        }

        let prepared = RocksDbPreparedCommit {
            write_batch,
            jvt_snapshot,
            merged_updates,
            receipts: receipts.to_vec(),
        };

        (computed_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
    ) -> hyperscale_types::Hash {
        let result_root = prepared.jvt_snapshot.result_root;

        let mut write_batch = prepared.write_batch;

        // Persist block data (header, transactions, certificates) atomically.
        // Receipt writes are already in the write_batch from prepare time.
        self.append_block_to_batch(&mut write_batch, block, qc);

        crate::execution_certs::append_block_certs_to_batch(self, &mut write_batch, block);

        let used_fast_path =
            self.try_apply_prepared_commit(write_batch, prepared.jvt_snapshot, block, qc);

        if used_fast_path {
            result_root
        } else {
            self.commit_block_inner(&prepared.merged_updates, block, qc, &prepared.receipts)
        }
    }

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
        receipts: &[ReceiptBundle],
    ) -> hyperscale_types::Hash {
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(receipts);
        self.commit_block_inner(&merged_updates, block, qc, receipts)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        let mut block_cache_usage = 0u64;
        let mut memtable_usage = 0u64;

        for cf_name in ALL_COLUMN_FAMILIES {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                // Block cache is shared — reading from any CF gives the total.
                // We read it once from the first CF we find.
                if block_cache_usage == 0 {
                    if let Ok(Some(val)) = self
                        .db
                        .property_int_value_cf(&cf, "rocksdb.block-cache-usage")
                    {
                        block_cache_usage = val;
                    }
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

    fn node_cache_len(&self) -> usize {
        self.node_cache.len()
    }
}

impl RocksDbStorage {
    /// Internal commit path used by both `commit_block` and `commit_prepared_block` fallback.
    fn commit_block_inner(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
        receipts: &[ReceiptBundle],
    ) -> hyperscale_types::Hash {
        let block_height = block.header.height.0;
        let _commit_guard = self.commit_lock.lock().unwrap();

        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);
        let (base_version, base_root) = snapshot_store.read_jvt_metadata();

        assert!(
            block_height == base_version + 1 || (block_height == 0 && base_version == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            base_version
        );

        let (mut batch, reset_old_keys) =
            self.build_substate_write_batch(merged_updates, Some(block_height));

        // Persist block data (header, transactions, certificates) atomically.
        self.append_block_to_batch(&mut batch, block, qc);

        crate::execution_certs::append_block_certs_to_batch(self, &mut batch, block);

        // Add receipts to the batch atomically.
        for bundle in receipts {
            self.add_receipt_bundle_to_batch(&mut batch, bundle);
        }

        // Compute JVT update.
        let parent_version = hyperscale_storage::tree::jvt_parent_height(base_version, base_root);
        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            parent_version,
            block_height,
            merged_updates,
            &reset_old_keys,
        );
        let jvt_snapshot = JvtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            new_root,
            block_height,
        );
        self.append_jvt_to_batch(&mut batch, &jvt_snapshot, block_height);

        // Fold consensus metadata into the same batch for crash-safe atomicity.
        Self::append_consensus_to_batch(&mut batch, block, qc);

        // Single atomic write with sync — one fsync instead of N.
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        // Populate cache with newly committed nodes.
        self.node_cache.populate(&jvt_snapshot.nodes);

        new_root
    }
}
