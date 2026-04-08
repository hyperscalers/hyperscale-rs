//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JVT Integration
//!
//! Uses Jellyfish Verkle Tree (JVT) for cryptographic state commitment.
//! JVT data is stored in dedicated column families (`jmt_nodes`, `jmt_meta`).
//! On each commit, the JVT is updated and a new state root hash is computed.

use crate::column_families::{CfHandles, HOT_WRITE_COLUMN_FAMILIES};
use crate::config::RocksDbConfig;
use crate::jvt_snapshot_store::SnapshotTreeStore;
use crate::jvt_stored::{StoredNode, StoredNodeKey, VersionedStoredNode};
use crate::node_cache::NodeCache;
use crate::typed_cf::{DbCodec, TypedCf};

/// Sort keys deleted by partition Reset operations, keyed by `(entity_key, partition_num)`.
/// Passed to `put_at_version` so the JVT can reconstruct full storage keys and
/// generate deletes for the hashed keys.
pub(crate) type ResetOldKeys = std::collections::HashMap<(Vec<u8>, u8), Vec<DbSortKey>>;

use hyperscale_metrics as metrics;
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, JvtSnapshot,
    PartitionDatabaseUpdates, PartitionEntry, StateRootHash, SubstateDatabase,
};
use jellyfish_verkle_tree as jvt;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use sbor::prelude::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{instrument, Level};

/// RocksDB-based storage for production use.
///
/// Features:
/// - Column families for logical separation
/// - LZ4 compression for disk efficiency
/// - Block cache for read performance
/// - Bloom filters for key existence checks
/// - JVT for cryptographic state commitment
///
/// Implements Radix's `SubstateDatabase` directly, plus our `SubstateStore` extension
/// for snapshots, node listing, and JVT state roots.
///
/// JVT tree nodes are persisted in the `jmt_nodes` column family. JVT metadata
/// (version and root hash) is in the default CF under well-known keys and read
/// directly from RocksDB on demand — always hot in the memtable since they're
/// written on every commit.
pub struct RocksDbStorage {
    pub(crate) db: Arc<DB>,

    /// Serializes JVT-mutating commits to prevent interleaved read-modify-write
    /// sequences (e.g., `read_jvt_metadata` + `WriteBatch` write).
    pub(crate) commit_lock: Mutex<()>,

    /// Number of block heights of JVT history to retain before garbage collection.
    pub(crate) jvt_history_length: u64,

    /// Persistent cache of hydrated JVT tree nodes. Eliminates the expensive
    /// `StoredNode::to_jvt()` conversion on repeated proof generations.
    /// Populated eagerly during `put_at_version` (commit path) and lazily
    /// during proof prefetch (read path).
    pub(crate) node_cache: NodeCache,
}

/// Error type for storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl RocksDbStorage {
    /// Open or create a RocksDB database at the given path.
    ///
    /// Creates default column families: default, blocks, transactions, state, certificates.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let config = RocksDbConfig::default();
        Self::open_with_config(path, config)
    }

    /// Open with custom configuration.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        config: RocksDbConfig,
    ) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Performance tuning
        opts.set_max_background_jobs(config.max_background_jobs);
        if config.bytes_per_sync > 0 {
            opts.set_bytes_per_sync(config.bytes_per_sync as u64);
        }
        opts.set_keep_log_file_num(config.keep_log_file_num);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);
        opts.set_write_buffer_size(config.write_buffer_size);

        // Allow WAL write and memtable insertion to overlap. Safe because
        // all block commits use a single WriteBatch (already atomic).
        opts.set_enable_pipelined_write(true);

        // Compression
        opts.set_compression_type(config.compression.to_rocksdb());

        // Block cache and bloom filter — shared across ALL column families.
        // SST index/filter blocks are pinned inside this cache to prevent
        // unbounded heap growth as the database accumulates SST files.
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        if let Some(cache_size) = config.block_cache_size {
            let cache = rocksdb::Cache::new_lru_cache(cache_size);
            block_opts.set_block_cache(&cache);
        }
        if config.bloom_filter_bits > 0.0 {
            block_opts.set_bloom_filter(config.bloom_filter_bits, false);
        }
        // Pin SST index/filter blocks inside the bounded block cache instead
        // of letting them consume unbounded heap memory as the DB grows.
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        opts.set_block_based_table_factory(&block_opts);

        // Column families — all share the bounded block cache but get
        // per-CF tuning for write buffers and compression.
        //
        // Hot-write CFs get larger write buffers and tiered compression.
        // Cold/low-volume CFs use smaller write buffers (16MB) to free
        // memory for the hot CFs and block cache.
        let hot_write_cfs = HOT_WRITE_COLUMN_FAMILIES;

        // Tiered compression: L0-L1 uncompressed (fast flushes, data gets
        // compacted away quickly), L2-L4 LZ4, L5+ Zstd.
        let tiered_compression = &[
            rocksdb::DBCompressionType::None, // L0
            rocksdb::DBCompressionType::None, // L1
            rocksdb::DBCompressionType::Lz4,  // L2
            rocksdb::DBCompressionType::Lz4,  // L3
            rocksdb::DBCompressionType::Lz4,  // L4
            rocksdb::DBCompressionType::Zstd, // L5
            rocksdb::DBCompressionType::Zstd, // L6
        ];

        let cold_write_buffer_size: usize = 16 * 1024 * 1024; // 16MB

        let cf_descriptors: Vec<_> = config
            .column_families
            .into_iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_block_based_table_factory(&block_opts);
                cf_opts.set_max_write_buffer_number(config.max_write_buffer_number);

                let is_hot = hot_write_cfs.iter().any(|&cf| cf == name);
                if is_hot {
                    cf_opts.set_write_buffer_size(config.write_buffer_size);
                    cf_opts.set_compression_per_level(tiered_compression);
                } else {
                    cf_opts.set_write_buffer_size(cold_write_buffer_size);
                    cf_opts.set_compression_type(config.compression.to_rocksdb());
                }

                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Validate all expected column families exist at startup.
        // This fails fast instead of panicking on first access at runtime.
        CfHandles::resolve(&db);

        Ok(Self {
            db: Arc::new(db),
            commit_lock: Mutex::new(()),
            jvt_history_length: config.jvt_history_length,
            node_cache: NodeCache::new(),
        })
    }

    /// Get the configured JVT history retention length (in block heights).
    pub fn jvt_history_length(&self) -> u64 {
        self.jvt_history_length
    }

    /// Resolve all column family handles from the database.
    ///
    /// This is cheap (HashMap lookups only, ~10ns per CF) and provides typed
    /// access to all 12 column families without repeating
    /// `.cf_handle(NAME).expect(...)` at each call site.
    pub(crate) fn cf(&self) -> CfHandles<'_> {
        CfHandles::resolve(&self.db)
    }

    // ─── Typed CF helpers ────────────────────────────────────────────────
    //
    // Thin wrappers over the free functions in typed_cf.rs.
    // These resolve CfHandles and pass &self.db as the ReadableStore.

    /// Get a typed value from a column family.
    pub(crate) fn cf_get<CF: crate::typed_cf::TypedCf>(&self, key: &CF::Key) -> Option<CF::Value> {
        crate::typed_cf::get::<CF>(&*self.db, CF::handle(&self.cf()), key)
    }

    /// Put a typed key/value into a WriteBatch.
    pub(crate) fn cf_put<CF: crate::typed_cf::TypedCf>(
        &self,
        batch: &mut WriteBatch,
        key: &CF::Key,
        value: &CF::Value,
    ) {
        crate::typed_cf::batch_put::<CF>(batch, CF::handle(&self.cf()), key, value);
    }

    /// Batch get typed values (RocksDB multi_get_cf).
    pub(crate) fn cf_multi_get<CF: crate::typed_cf::TypedCf>(
        &self,
        keys: &[CF::Key],
    ) -> Vec<Option<CF::Value>> {
        crate::typed_cf::multi_get::<CF>(&*self.db, CF::handle(&self.cf()), keys)
    }

    /// Delete a typed key in a WriteBatch.
    #[allow(dead_code)]
    pub(crate) fn cf_delete<CF: crate::typed_cf::TypedCf>(
        &self,
        batch: &mut WriteBatch,
        key: &CF::Key,
    ) {
        crate::typed_cf::batch_delete::<CF>(batch, CF::handle(&self.cf()), key);
    }

    /// Typed single put (immediate write, no batch).
    pub(crate) fn cf_put_sync<CF: crate::typed_cf::TypedCf>(
        &self,
        key: &CF::Key,
        value: &CF::Value,
    ) {
        let cf = CF::handle(&self.cf());
        let key_bytes = CF::KeyCodec::default().encode(key);
        let value_bytes = CF::ValueCodec::default().encode(value);
        self.db
            .put_cf(cf, &key_bytes, &value_bytes)
            .expect("BFT CRITICAL: write failed");
    }

    /// Read JVT version and root hash directly from RocksDB.
    ///
    /// These are stored as a single 40-byte value under `jmt:metadata`:
    /// `[version_BE_8B][root_hash_32B]`. Always hot in the memtable since
    /// they're written on every commit.
    pub(crate) fn read_jvt_metadata(&self) -> (u64, StateRootHash) {
        crate::metadata::read_jvt_metadata(&*self.db)
    }

    /// Append JVT data from a snapshot to a WriteBatch.
    ///
    /// Writes JVT nodes, stale tree parts (for deferred GC), historical
    /// substate associations (if enabled), and JVT metadata (version + root hash).
    ///
    /// This is the write-side complement to `read_jvt_metadata`.
    pub(crate) fn append_jvt_to_batch(
        &self,
        batch: &mut WriteBatch,
        snapshot: &JvtSnapshot,
        new_version: u64,
    ) {
        // JVT nodes — serialize hydrated nodes to stored form at write time.
        let cf = self.cf();
        for (jvt_key, jvt_node) in &snapshot.nodes {
            let stored_key = StoredNodeKey::from_jvt(jvt_key);
            let stored_node = StoredNode::from_jvt(jvt_node);
            crate::typed_cf::batch_put::<crate::column_families::JvtNodesCf>(
                batch,
                crate::column_families::JvtNodesCf::handle(&cf),
                &stored_key,
                &VersionedStoredNode::from_latest(stored_node),
            );
        }

        // Stale nodes for deferred GC — keyed by the version at which they became stale.
        if !snapshot.stale_node_keys.is_empty() {
            // Wrap keys as StaleTreePart::Node for SBOR serialization.
            let stale_parts: Vec<crate::jvt_stored::StaleTreePart> = snapshot
                .stale_node_keys
                .iter()
                .map(|k| crate::jvt_stored::StaleTreePart::Node(StoredNodeKey::from_jvt(k)))
                .collect();
            crate::typed_cf::batch_put::<crate::column_families::StaleJvtNodesCf>(
                batch,
                crate::column_families::StaleJvtNodesCf::handle(&cf),
                &new_version,
                &stale_parts,
            );
        }

        // JVT metadata — single key, atomic read.
        crate::metadata::write_jvt_metadata(batch, new_version, snapshot.result_root);
    }

    /// Append consensus metadata (committed_height, committed_hash, committed_qc)
    /// to a `WriteBatch` so it is persisted atomically with JVT + substate data.
    pub(crate) fn append_consensus_to_batch(
        batch: &mut WriteBatch,
        block: &hyperscale_types::Block,
        qc: &hyperscale_types::QuorumCertificate,
    ) {
        crate::metadata::write_committed_height(batch, block.header.height);
        crate::metadata::write_committed_hash(batch, &block.hash());
        crate::metadata::write_committed_qc(batch, qc);
    }

    /// Build a `WriteBatch` containing all substate puts/deletes from `updates`.
    ///
    /// When `version` is `Some`, also writes to the `versioned_substates` CF for
    /// MVCC historical reads. Deletes are written as empty values (tombstones).
    ///
    /// Returns `(batch, reset_old_keys)` where `reset_old_keys` maps
    /// `(entity_key, partition_num)` to the old storage keys that were deleted
    /// by Reset partitions (needed for JVT delete generation).
    pub(crate) fn build_substate_write_batch(
        &self,
        updates: &DatabaseUpdates,
        version: Option<u64>,
    ) -> (WriteBatch, ResetOldKeys) {
        let mut batch = WriteBatch::default();
        let mut reset_old_keys = ResetOldKeys::new();

        use crate::column_families::{StateCf, VersionedSubstatesCf};
        use crate::typed_cf::{batch_delete, batch_put};

        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        let versioned_cf = VersionedSubstatesCf::handle(&cf);

        for (node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                let partition_key = DbPartitionKey {
                    node_key: node_key.clone(),
                    partition_num: *partition_num,
                };

                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let key = (partition_key.clone(), sort_key.clone());
                            match update {
                                DatabaseUpdate::Set(value) => {
                                    batch_put::<StateCf>(&mut batch, state_cf, &key, value);
                                    if let Some(ver) = version {
                                        batch_put::<VersionedSubstatesCf>(
                                            &mut batch,
                                            versioned_cf,
                                            &(key, ver),
                                            value,
                                        );
                                    }
                                }
                                DatabaseUpdate::Delete => {
                                    batch_delete::<StateCf>(&mut batch, state_cf, &key);
                                    if let Some(ver) = version {
                                        // Empty value = tombstone
                                        batch_put::<VersionedSubstatesCf>(
                                            &mut batch,
                                            versioned_cf,
                                            &(key, ver),
                                            &vec![],
                                        );
                                    }
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        let prefix = crate::substate_key::partition_prefix(&partition_key);
                        let snap = self.db.snapshot();
                        let mut old_sort_keys = Vec::new();

                        for ((pk, sk), _value) in
                            crate::typed_cf::prefix_iter_snap::<StateCf>(&snap, state_cf, &prefix)
                        {
                            let key = (pk, sk.clone());
                            batch_delete::<StateCf>(&mut batch, state_cf, &key);
                            old_sort_keys.push(sk);
                            if let Some(ver) = version {
                                batch_put::<VersionedSubstatesCf>(
                                    &mut batch,
                                    versioned_cf,
                                    &(key, ver),
                                    &vec![],
                                );
                            }
                        }

                        if !old_sort_keys.is_empty() {
                            reset_old_keys
                                .insert((node_key.clone(), *partition_num), old_sort_keys);
                        }

                        for (sort_key, value) in new_substate_values {
                            let key = (partition_key.clone(), sort_key.clone());
                            batch_put::<StateCf>(&mut batch, state_cf, &key, value);
                            if let Some(ver) = version {
                                batch_put::<VersionedSubstatesCf>(
                                    &mut batch,
                                    versioned_cf,
                                    &(key, ver),
                                    value,
                                );
                            }
                        }
                    }
                }
            }
        }

        (batch, reset_old_keys)
    }

    /// Write only substate data (no JVT computation).
    ///
    /// Used during genesis bootstrap so each intermediate `commit()` call from the
    /// Radix Engine writes substates without computing a JVT version.
    /// After all genesis commits complete, [`finalize_genesis_jvt`] computes the
    /// JVT once at version 0.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        // Genesis: version 0
        let (batch, _) = self.build_substate_write_batch(updates, Some(0));

        // Write substates only — no JVT, no sync (genesis isn't durability-critical).
        self.db
            .write(batch)
            .expect("genesis substate-only commit failed");
    }

    /// Compute the JVT once at version 0 from the merged genesis updates.
    ///
    /// Called after all genesis bootstrap commits are complete. This avoids
    /// computing intermediate JVT versions during genesis (which would collide
    /// with block 1's version).
    ///
    /// # Returns
    /// The genesis state root hash (JVT root at version 0).
    pub fn finalize_genesis_jvt(&self, merged: &DatabaseUpdates) -> StateRootHash {
        let _commit_guard = self.commit_lock.lock().unwrap();

        // Guard: finalize_genesis_jvt must only be called once, on an uninitialized JVT.
        let (current_version, current_root) = self.read_jvt_metadata();
        assert!(
            current_version == 0 && current_root == StateRootHash::ZERO,
            "finalize_genesis_jvt called but JVT already initialized (version={current_version})"
        );

        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);

        // parent=None, version=0: genesis is the first JVT state.
        let (root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            None,
            0,
            merged,
            &Default::default(),
        );
        let jvt_snapshot =
            JvtSnapshot::from_collected_writes(collected, StateRootHash::ZERO, 0, root, 0);

        let mut batch = WriteBatch::default();
        self.append_jvt_to_batch(&mut batch, &jvt_snapshot, 0);

        self.db
            .write(batch)
            .expect("genesis JVT finalization failed");

        self.node_cache.populate(&jvt_snapshot.nodes);

        root
    }
}

impl hyperscale_storage::SubstatesOnlyCommit for RocksDbStorage {
    fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        // Delegate to the inherent method.
        RocksDbStorage::commit_substates_only(self, updates);
    }
}

impl SubstateDatabase for RocksDbStorage {
    #[instrument(level = Level::DEBUG, skip_all, fields(
        found = tracing::field::Empty,
        latency_us = tracing::field::Empty,
    ))]
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let start = Instant::now();
        let result = self
            .cf_get::<crate::column_families::StateCf>(&(partition_key.clone(), sort_key.clone()));
        let elapsed = start.elapsed();
        metrics::record_storage_read(elapsed.as_secs_f64());

        // Record span fields
        let span = tracing::Span::current();
        span.record("found", result.is_some());
        span.record("latency_us", elapsed.as_micros() as u64);

        result
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = crate::substate_key::partition_prefix(partition_key);
        let start = match from_sort_key {
            Some(sort_key) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sort_key.0);
                s
            }
            None => prefix.clone(),
        };

        let cf = crate::column_families::StateCf::handle(&self.cf());
        Box::new(
            crate::typed_cf::prefix_iter_from::<crate::column_families::StateCf>(
                &self.db, cf, &prefix, &start,
            )
            .map(|((_pk, sk), value)| (sk, value)),
        )
    }
}

impl jvt::TreeReader for RocksDbStorage {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        // Fast path: serve from in-memory cache.
        if let Some(node) = self.node_cache.get(key) {
            return Some(node);
        }
        // Slow path: storage read + deserialize.
        let stored_key = StoredNodeKey::from_jvt(key);
        let node = self
            .cf_get::<crate::column_families::JvtNodesCf>(&stored_key)
            .map(|v| Arc::new(v.into_latest().to_jvt()));
        // Populate cache on miss so subsequent reads benefit.
        if let Some(ref n) = node {
            self.node_cache.insert(key.clone(), Arc::clone(n));
        }
        node
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        let root = jvt::NodeKey::root(version);
        if self.node_cache.get(&root).is_some() {
            return Some(root);
        }
        let stored_key = StoredNodeKey::from_jvt(&root);
        if self
            .cf_get::<crate::column_families::JvtNodesCf>(&stored_key)
            .is_some()
        {
            Some(root)
        } else {
            None
        }
    }
}

/// Test-only methods with auto-incrementing JVT version logic.
/// Production uses `commit_block` / `commit_prepared_block` instead.
#[cfg(test)]
impl RocksDbStorage {
    /// Test helper: commits database updates with auto-incrementing JVT version.
    /// Not used in production (use commit_block instead).
    #[instrument(level = Level::DEBUG, skip_all, fields(
        node_count = updates.node_updates.len(),
        latency_us = tracing::field::Empty,
    ))]
    pub fn commit(&self, updates: &DatabaseUpdates) -> Result<(), StorageError> {
        let _commit_guard = self.commit_lock.lock().unwrap();

        let start = Instant::now();

        // Compute JVT updates using a snapshot-based store for isolation
        let snapshot_store = SnapshotTreeStore::new(&self.db, &self.node_cache);
        let (base_version, base_root) = snapshot_store.read_jvt_metadata();

        // Version 0 with a non-zero root means genesis has been computed at version 0.
        // Only treat as "no parent" when the JVT is truly empty.
        let parent_version = hyperscale_storage::tree::jvt_parent_height(base_version, base_root);
        let new_version = base_version + 1;

        let (mut batch, reset_old_keys) =
            self.build_substate_write_batch(updates, Some(new_version));

        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            parent_version,
            new_version,
            updates,
            &reset_old_keys,
        );
        let jvt_snapshot = JvtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            new_root,
            new_version,
        );

        self.append_jvt_to_batch(&mut batch, &jvt_snapshot, new_version);

        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        self.node_cache.populate(&jvt_snapshot.nodes);

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());

        // Record span fields
        let span = tracing::Span::current();
        span.record("latency_us", elapsed.as_micros() as u64);
        tracing::debug!(new_version, "commit complete");

        Ok(())
    }
}

#[cfg(test)]
impl hyperscale_storage::CommittableSubstateDatabase for RocksDbStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        RocksDbStorage::commit(self, updates)
            .expect("Storage commit failed - cannot maintain consistent state")
    }
}
