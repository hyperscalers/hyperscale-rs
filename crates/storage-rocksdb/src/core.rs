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

use crate::config::{
    CfHandles, ResetOldKeys, RocksDbConfig, ASSOCIATED_STATE_TREE_VALUES_CF, JVT_NODES_CF,
    STATE_CF, VERSIONED_SUBSTATES_CF,
};
use crate::jvt_snapshot_store::SnapshotTreeStore;
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_storage::{
    jmt::{
        encode_key as encode_jvt_key, ReadableTreeStore, StoredNode, StoredNodeKey,
        VersionedStoredNode,
    },
    keys, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, JvtSnapshot,
    PartitionDatabaseUpdates, PartitionEntry, StateRootHash, SubstateDatabase,
};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use sbor::prelude::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{instrument, Level};

/// Decode JVT metadata from raw bytes.
///
/// Layout: `[version_BE_8B][root_hash_32B]` (40 bytes total).
/// Returns `(0, ZERO)` for `None` (uninitialized DB).
pub(crate) fn decode_jvt_metadata(raw: Option<impl AsRef<[u8]>>) -> (u64, StateRootHash) {
    match raw {
        Some(bytes) => {
            let bytes = bytes.as_ref();
            assert!(bytes.len() == 40, "jmt:metadata must be 40 bytes");
            let version = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            let root_hash = StateRootHash::from_hash_bytes(&bytes[8..40]);
            (version, root_hash)
        }
        None => (0, StateRootHash::ZERO),
    }
}

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
pub struct RocksDbStorage<D: Dispatch + 'static> {
    pub(crate) db: Arc<DB>,

    /// Serializes JVT-mutating commits to prevent interleaved read-modify-write
    /// sequences (e.g., `read_jvt_metadata` + `WriteBatch` write).
    pub(crate) commit_lock: Mutex<()>,

    /// Number of block heights of JVT history to retain before garbage collection.
    pub(crate) jvt_history_length: u64,

    /// Dispatch implementation for parallel JVT computation.
    pub(crate) dispatch: D,

    /// Persistent cache of hydrated JVT tree nodes. Eliminates the expensive
    /// `StoredNode::to_jvt()` conversion on repeated proof generations.
    /// Populated eagerly during `put_at_version` (commit path) and lazily
    /// during proof prefetch (read path).
    pub(crate) node_cache: hyperscale_storage::jmt::NodeCache,
}

/// Error type for storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl<D: Dispatch + 'static> RocksDbStorage<D> {
    /// Open or create a RocksDB database at the given path.
    ///
    /// Creates default column families: default, blocks, transactions, state, certificates.
    pub fn open<P: AsRef<Path>>(path: P, dispatch: D) -> Result<Self, StorageError> {
        let config = RocksDbConfig::default();
        Self::open_with_config(path, config, dispatch)
    }

    /// Open with custom configuration.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        config: RocksDbConfig,
        dispatch: D,
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
        // Hot-write CFs (state, jvt_nodes, versioned_substates,
        // associated_state_tree_values) use larger write buffers and tiered
        // compression: no compression at L0-L1 (fast flushes), LZ4 at
        // mid-levels, Zstd at the bottom level (best ratio for cold data).
        //
        // Cold/low-volume CFs use smaller write buffers (16MB) to free
        // memory for the hot CFs and block cache.
        let hot_write_cfs: &[&str] = &[
            STATE_CF,
            JVT_NODES_CF,
            VERSIONED_SUBSTATES_CF,
            ASSOCIATED_STATE_TREE_VALUES_CF,
        ];

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
            node_cache: hyperscale_storage::jmt::NodeCache::new(50_000),
            dispatch,
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

    /// Read JVT version and root hash directly from RocksDB.
    ///
    /// These are stored as a single 40-byte value under `jmt:metadata`:
    /// `[version_BE_8B][root_hash_32B]`. Always hot in the memtable since
    /// they're written on every commit.
    pub(crate) fn read_jvt_metadata(&self) -> (u64, StateRootHash) {
        decode_jvt_metadata(
            self.db
                .get(b"jmt:metadata")
                .expect("BFT CRITICAL: failed to read jmt:metadata"),
        )
    }

    /// Encode JVT metadata into a 40-byte value.
    fn encode_jvt_metadata(version: u64, root: StateRootHash) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..8].copy_from_slice(&version.to_be_bytes());
        buf[8..40].copy_from_slice(&root.to_bytes());
        buf
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
        // JVT nodes
        let cf = self.cf();
        for (key, node) in &snapshot.nodes {
            let encoded_key = encode_jvt_key(key);
            let encoded_node = sbor::basic_encode(&VersionedStoredNode::from_latest(node.clone()))
                .expect("JVT node encoding must succeed");
            batch.put_cf(cf.jvt_nodes, encoded_key, encoded_node);
        }

        // Stale parts for deferred GC
        if !snapshot.stale_tree_parts.is_empty() {
            let version_key = new_version.to_be_bytes();
            let encoded_parts = sbor::basic_encode(&snapshot.stale_tree_parts)
                .expect("encoding stale parts must succeed");
            batch.put_cf(cf.stale_state_hash_tree_parts, version_key, encoded_parts);
        }

        // Historical associations (always enabled — required for cross-shard provisions)
        for assoc in &snapshot.leaf_substate_associations {
            let encoded_key = encode_jvt_key(&assoc.tree_node_key);
            batch.put_cf(
                cf.associated_state_tree_values,
                encoded_key,
                &assoc.substate_value,
            );
        }

        // JVT metadata — single key, atomic read.
        batch.put(
            b"jmt:metadata",
            Self::encode_jvt_metadata(new_version, snapshot.result_root),
        );
    }

    /// Append consensus metadata (committed_height, committed_hash, committed_qc)
    /// to a `WriteBatch` so it is persisted atomically with JVT + substate data.
    pub(crate) fn append_consensus_to_batch(
        batch: &mut WriteBatch,
        consensus: &hyperscale_storage::ConsensusCommitData,
    ) {
        batch.put(b"chain:committed_height", consensus.height.0.to_be_bytes());
        batch.put(b"chain:committed_hash", consensus.hash.as_bytes());
        let encoded_qc = sbor::basic_encode(&consensus.qc).expect("QC encoding must succeed");
        batch.put(b"chain:committed_qc", encoded_qc);
    }

    /// Internal: iterate over a key range in the state CF.
    pub(crate) fn iter_range<'a>(
        &'a self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a {
        let mut iter = self.db.raw_iterator_cf(self.cf().state);
        iter.seek(start);
        let end = end.to_vec();
        let mut done = false;

        std::iter::from_fn(move || {
            if done {
                return None;
            }
            if iter.valid() {
                let key = iter.key()?;
                if key < end.as_slice() {
                    let k: Box<[u8]> = Box::from(key);
                    let v: Box<[u8]> = Box::from(iter.value()?);
                    iter.next();
                    Some((k, v))
                } else {
                    done = true;
                    None
                }
            } else {
                done = true;
                if let Err(e) = iter.status() {
                    panic!("RocksDB iterator error: {e}");
                }
                None
            }
        })
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

        let cf = self.cf();
        let state_cf = cf.state;
        let versioned_cf: Option<&rocksdb::ColumnFamily> = Some(cf.versioned_substates);

        // Reusable buffer for versioned keys — avoids a Vec allocation per substate write.
        let mut vkey_buf: Vec<u8> = Vec::with_capacity(256);

        for (node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                let partition_key = DbPartitionKey {
                    node_key: node_key.clone(),
                    partition_num: *partition_num,
                };

                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            match update {
                                DatabaseUpdate::Set(value) => {
                                    batch.put_cf(state_cf, &key, value);
                                    if let (Some(ver), Some(vcf)) = (version, versioned_cf) {
                                        vkey_buf.clear();
                                        vkey_buf.extend_from_slice(&key);
                                        vkey_buf.extend_from_slice(&ver.to_be_bytes());
                                        batch.put_cf(vcf, &vkey_buf, value);
                                    }
                                }
                                DatabaseUpdate::Delete => {
                                    batch.delete_cf(state_cf, &key);
                                    if let (Some(ver), Some(vcf)) = (version, versioned_cf) {
                                        vkey_buf.clear();
                                        vkey_buf.extend_from_slice(&key);
                                        vkey_buf.extend_from_slice(&ver.to_be_bytes());
                                        // Empty value = tombstone
                                        batch.put_cf(vcf, &vkey_buf, []);
                                    }
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        let prefix = keys::partition_prefix(&partition_key);
                        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

                        let snap = self.db.snapshot();
                        let mut iter = snap.raw_iterator_cf(state_cf);
                        let mut old_keys_for_partition = Vec::new();

                        iter.seek(&prefix);
                        while iter.valid() {
                            if let Some(key) = iter.key() {
                                if key >= end.as_slice() {
                                    break;
                                }
                                batch.delete_cf(state_cf, key);
                                old_keys_for_partition.push(key.to_vec());
                                if let (Some(ver), Some(vcf)) = (version, versioned_cf) {
                                    vkey_buf.clear();
                                    vkey_buf.extend_from_slice(key);
                                    vkey_buf.extend_from_slice(&ver.to_be_bytes());
                                    batch.put_cf(vcf, &vkey_buf, []); // tombstone
                                }
                                iter.next();
                            } else {
                                break;
                            }
                        }

                        if !old_keys_for_partition.is_empty() {
                            reset_old_keys
                                .insert((node_key.clone(), *partition_num), old_keys_for_partition);
                        }

                        for (sort_key, value) in new_substate_values {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            batch.put_cf(state_cf, &key, value);
                            if let (Some(ver), Some(vcf)) = (version, versioned_cf) {
                                vkey_buf.clear();
                                vkey_buf.extend_from_slice(&key);
                                vkey_buf.extend_from_slice(&ver.to_be_bytes());
                                batch.put_cf(vcf, &vkey_buf, value);
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

        let snapshot_store = SnapshotTreeStore::new(&self.db);

        // parent=None, version=0: genesis is the first JVT state.
        let (root, collected) = hyperscale_storage::jmt::put_at_version(
            &snapshot_store,
            None,
            0,
            merged,
            &self.dispatch,
            &Default::default(),
            Some(&self.node_cache),
        );
        let jvt_snapshot =
            JvtSnapshot::from_collected_writes(collected, StateRootHash::ZERO, 0, root, 0);

        let mut batch = WriteBatch::default();
        self.append_jvt_to_batch(&mut batch, &jvt_snapshot, 0);

        self.db
            .write(batch)
            .expect("genesis JVT finalization failed");

        root
    }
}

impl<D: Dispatch + 'static> hyperscale_storage::SubstatesOnlyCommit for RocksDbStorage<D> {
    fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        // Delegate to the inherent method.
        RocksDbStorage::commit_substates_only(self, updates);
    }
}

impl<D: Dispatch + 'static> SubstateDatabase for RocksDbStorage<D> {
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
        let key = keys::to_storage_key(partition_key, sort_key);
        let result = self
            .db
            .get_cf(self.cf().state, &key)
            .expect("RocksDB read failure on state CF");
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
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();

        let start = match from_sort_key {
            Some(sort_key) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sort_key.0);
                s
            }
            None => prefix.clone(),
        };
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

        let items = self.iter_range(&start, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let sort_key_bytes = full_key[prefix_len..].to_vec();
                Some((DbSortKey(sort_key_bytes), value.into_vec()))
            } else {
                None
            }
        }))
    }
}

impl<D: Dispatch + 'static> ReadableTreeStore for RocksDbStorage<D> {
    fn get_node(&self, key: &StoredNodeKey) -> Option<StoredNode> {
        let encoded_key = encode_jvt_key(key);
        self.db
            .get_cf(self.cf().jvt_nodes, &encoded_key)
            .expect("RocksDB read failure on jmt_nodes CF")
            .map(|bytes| {
                sbor::basic_decode::<VersionedStoredNode>(&bytes)
                    .unwrap_or_else(|e| panic!("JVT node corruption detected: {e:?}"))
                    .into_latest()
            })
    }
}

/// Test-only methods with auto-incrementing JVT version logic.
/// Production uses `commit_block` / `commit_prepared_block` instead.
#[cfg(test)]
impl<D: Dispatch + 'static> RocksDbStorage<D> {
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
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jvt_metadata();

        // Version 0 with a non-zero root means genesis has been computed at version 0.
        // Only treat as "no parent" when the JVT is truly empty.
        let parent_version = hyperscale_storage::jvt_parent_height(base_version, base_root);
        let new_version = base_version + 1;

        let (mut batch, reset_old_keys) =
            self.build_substate_write_batch(updates, Some(new_version));

        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &snapshot_store,
            parent_version,
            new_version,
            updates,
            &self.dispatch,
            &reset_old_keys,
            Some(&self.node_cache),
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
impl<D: Dispatch + 'static> hyperscale_storage::CommittableSubstateDatabase for RocksDbStorage<D> {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        RocksDbStorage::commit(self, updates)
            .expect("Storage commit failed - cannot maintain consistent state")
    }
}
