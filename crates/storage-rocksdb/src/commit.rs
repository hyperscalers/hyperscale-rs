//! `CommitStore` implementation for `RocksDbStorage`.

use crate::column_families::CertificatesCf;
use crate::column_families::ALL_COLUMN_FAMILIES;
use crate::core::RocksDbStorage;
use crate::jvt_snapshot_store::SnapshotTreeStore;

use hyperscale_storage::{DatabaseUpdates, JvtSnapshot};
use hyperscale_types::TransactionCertificate;
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Precomputed commit work for a RocksDB block commit.
///
/// Contains a pre-built `WriteBatch` (all certificate + state writes) and a
/// `JvtSnapshot` (precomputed Verkle tree nodes). Also carries the certificates
/// and shard for fallback recompute if the prepared data is stale.
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct RocksDbPreparedCommit {
    pub(crate) write_batch: WriteBatch,
    pub(crate) jvt_snapshot: JvtSnapshot,
    pub(crate) merged_updates: DatabaseUpdates,
}

impl hyperscale_storage::CommitStore for RocksDbStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: hyperscale_types::Hash,
        merged_updates: &DatabaseUpdates,
        block_height: u64,
    ) -> (hyperscale_types::Hash, Self::PreparedCommit) {
        let (computed_root, jvt_snapshot) = self.compute_speculative_root_from_base(
            parent_state_root,
            std::slice::from_ref(merged_updates),
            block_height,
        );

        // Pre-build substate writes into a WriteBatch for efficient commit.
        let (write_batch, _reset_old_keys) =
            self.build_substate_write_batch(merged_updates, Some(block_height));

        let prepared = RocksDbPreparedCommit {
            write_batch,
            jvt_snapshot,
            merged_updates: merged_updates.clone(),
        };

        (computed_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        certificates: &[Arc<TransactionCertificate>],
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
    ) -> hyperscale_types::Hash {
        let block_height = prepared.jvt_snapshot.new_version;
        let result_root = prepared.jvt_snapshot.result_root;

        // Append certificate storage to the write batch.
        let mut write_batch = prepared.write_batch;
        for cert in certificates {
            self.cf_put::<CertificatesCf>(&mut write_batch, &cert.transaction_hash, cert.as_ref());
        }

        let used_fast_path =
            self.try_apply_prepared_commit(write_batch, prepared.jvt_snapshot, consensus.as_ref());

        if used_fast_path {
            result_root
        } else {
            // Stale cache: fall back to recompute from scratch.
            // The JVT base root changed, so the prepared snapshot is invalid.
            // Use the stored merged_updates to ensure substate writes aren't lost.
            self.commit_block(
                &prepared.merged_updates,
                certificates,
                block_height,
                consensus,
            )
        }
    }

    fn commit_block(
        &self,
        merged_updates: &DatabaseUpdates,
        certificates: &[Arc<TransactionCertificate>],
        block_height: u64,
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
    ) -> hyperscale_types::Hash {
        let _commit_guard = self.commit_lock.lock().unwrap();

        // Single snapshot for both validation and JVT computation.
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jvt_metadata();

        // Validate block_height is strictly greater than current version.
        // This catches accidental version gaps or duplicate commits.
        assert!(
            block_height == base_version + 1 || (block_height == 0 && base_version == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            base_version
        );

        // Build a WriteBatch for certificates + substate writes.
        let (mut batch, reset_old_keys) =
            self.build_substate_write_batch(merged_updates, Some(block_height));

        // Store certificates to the certificate CF.
        for cert in certificates {
            self.cf_put::<CertificatesCf>(&mut batch, &cert.transaction_hash, cert.as_ref());
        }

        // Compute JVT update.
        let parent_version = hyperscale_storage::jvt_parent_height(base_version, base_root);
        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &snapshot_store,
            parent_version,
            block_height,
            merged_updates,
            &reset_old_keys,
            Some(&self.node_cache),
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
        if let Some(ref consensus) = consensus {
            Self::append_consensus_to_batch(&mut batch, consensus);
        }

        // Single atomic write with sync — one fsync instead of N.
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        new_root
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
