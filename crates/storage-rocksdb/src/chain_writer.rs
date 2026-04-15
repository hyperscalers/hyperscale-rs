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
/// `JvtSnapshot` (precomputed Verkle tree nodes).
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct RocksDbPreparedCommit {
    pub(crate) write_batch: WriteBatch,
    pub(crate) jvt_snapshot: JvtSnapshot,
}

impl hyperscale_storage::ChainWriter for RocksDbStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn jvt_snapshot(prepared: &Self::PreparedCommit) -> &hyperscale_storage::JvtSnapshot {
        &prepared.jvt_snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: hyperscale_types::Hash,
        parent_block_height: u64,
        receipts: &[ReceiptBundle],
        block_height: u64,
        pending_snapshots: &[std::sync::Arc<hyperscale_storage::JvtSnapshot>],
    ) -> (hyperscale_types::Hash, Self::PreparedCommit) {
        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JvtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet
        // (e.g., proposer just exited sync and BlockPersisted hasn't fired).
        if receipts.is_empty() {
            let jvt_snapshot = hyperscale_storage::tree::noop_jvt_snapshot(
                &SnapshotTreeStore::new(&self.db, &self.node_cache),
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            );
            let write_batch = WriteBatch::default();
            let prepared = RocksDbPreparedCommit {
                write_batch,
                jvt_snapshot,
            };
            return (parent_state_root, prepared);
        }

        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);
        let parent_version =
            hyperscale_storage::tree::jvt_parent_height(parent_block_height, parent_state_root);

        // Collect per-receipt DatabaseUpdates references — no merge needed.
        // State locking guarantees no key conflicts between receipts, so
        // put_at_version can flatten them directly into JVT work items.
        let per_receipt_updates: Vec<&DatabaseUpdates> = receipts
            .iter()
            .map(|b| &b.local_receipt.database_updates)
            .collect();

        let (computed_root, collected) = if pending_snapshots.is_empty() {
            hyperscale_storage::tree::put_at_version(
                &snapshot_store,
                parent_version,
                block_height,
                &per_receipt_updates,
                &Default::default(),
            )
        } else {
            let overlay = hyperscale_storage::tree::OverlayTreeReader::new(
                &snapshot_store,
                pending_snapshots,
            );
            hyperscale_storage::tree::put_at_version(
                &overlay,
                parent_version,
                block_height,
                &per_receipt_updates,
                &Default::default(),
            )
        };

        let jvt_snapshot = JvtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            computed_root,
            block_height,
        );

        // Merge updates for the substate WriteBatch (off the state_root critical path).
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(receipts);

        // Pre-build substate + receipt writes into a WriteBatch for efficient commit.
        let (mut write_batch, _reset_old_keys) =
            self.build_substate_write_batch(&merged_updates, Some(block_height));

        for bundle in receipts {
            self.add_receipt_bundle_to_batch(&mut write_batch, bundle);
        }

        let prepared = RocksDbPreparedCommit {
            write_batch,
            jvt_snapshot,
        };

        (computed_root, prepared)
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(
            Self::PreparedCommit,
            Arc<hyperscale_types::Block>,
            Arc<hyperscale_types::QuorumCertificate>,
        )>,
    ) -> Vec<hyperscale_types::Hash> {
        let total = blocks.len();
        let mut roots = Vec::with_capacity(total);

        for (i, (prepared, block, qc)) in blocks.into_iter().enumerate() {
            let result_root = prepared.jvt_snapshot.result_root;

            let mut write_batch = prepared.write_batch;

            // Persist block data (header, transactions, certificates) atomically.
            // Receipt writes are already in the write_batch from prepare time.
            self.append_block_to_batch(&mut write_batch, &block, &qc);

            crate::execution_certs::append_block_certs_to_batch(self, &mut write_batch, &block);

            // Defer fsync for all blocks except the last. The final sync=true
            // flushes the entire WAL, covering all prior deferred writes.
            let sync = i == total - 1;
            let applied = self.try_apply_prepared_commit(
                write_batch,
                prepared.jvt_snapshot,
                &block,
                &qc,
                sync,
            );
            assert!(
                applied,
                "BUG: prepared commit fast path failed at height {} — \
                 serialized verification should guarantee freshness",
                block.header.height.0
            );
            roots.push(result_root);
        }

        roots
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
    /// Internal commit path used by `commit_block` (sync blocks without a PreparedCommit).
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
            &[merged_updates],
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
