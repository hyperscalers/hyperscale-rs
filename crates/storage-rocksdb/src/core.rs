//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JMT Integration
//!
//! Uses a binary Jellyfish Merkle Tree (Blake3) for cryptographic state
//! commitment. JMT data is stored in dedicated column families
//! (`jmt_nodes`, `stale_jmt_nodes`) plus metadata under `jmt:metadata`.
//! On each commit, the JMT is updated and a new state root hash is
//! computed.

use crate::column_families::{CfHandles, HOT_WRITE_COLUMN_FAMILIES, STATE_HISTORY_CF};
use crate::config::RocksDbConfig;
use crate::jmt_snapshot_store::SnapshotTreeStore;
use crate::jmt_stored::{StoredNode, StoredNodeKey, VersionedStoredNode};
use crate::typed_cf::{DbCodec, TypedCf};

/// Sort keys deleted by partition Reset operations, keyed by `(entity_key, partition_num)`.
/// Passed to `put_at_version` so the JMT can reconstruct full storage keys and
/// generate deletes for the hashed keys.
pub(crate) type ResetOldKeys = std::collections::HashMap<(Vec<u8>, u8), Vec<DbSortKey>>;

use hyperscale_jmt as jmt;
use hyperscale_metrics as metrics;
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, JmtSnapshot,
    PartitionDatabaseUpdates, PartitionEntry, StateRootHash, SubstateDatabase,
};
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
/// - Binary Blake3 JMT for cryptographic state commitment
///
/// Implements Radix's `SubstateDatabase` directly, plus our `SubstateStore` extension
/// for snapshots, node listing, and JMT state roots.
///
/// JMT tree nodes are persisted in the `jmt_nodes` column family. JMT metadata
/// (version and root hash) is in the default CF under `jmt:metadata` and read
/// directly from RocksDB on demand — always hot in the memtable since they're
/// written on every commit.
pub struct RocksDbStorage {
    pub(crate) db: Arc<DB>,

    /// Serializes JMT-mutating commits to prevent interleaved read-modify-write
    /// sequences (e.g., `read_jmt_metadata` + `WriteBatch` write).
    pub(crate) commit_lock: Mutex<()>,

    /// Number of block heights of JMT history to retain before garbage collection.
    pub(crate) jmt_history_length: u64,
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
        // Whole-key bloom is enabled explicitly. StateHistoryCf has a
        // 51-byte prefix extractor, and rocksdb's default flips whole-key
        // filtering OFF once any CF uses a prefix extractor — but StateCf
        // (no prefix extractor) and the metadata / receipts / certs CFs
        // all rely on whole-key bloom for their point-lookup-dominated
        // access pattern, so we re-enable it here at the global
        // block-options level.
        block_opts.set_whole_key_filtering(true);
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

                // StateHistoryCf: fixed 51-byte prefix
                // (entity_key[50] + partition_num[1]) gates historical
                // reads and `list_at_prefix` scans. Keys carry an 8-byte
                // write_version suffix beyond the prefix, so historical
                // seeks at `storage_key ++ BE8(V+1)` and partition
                // scans both benefit from partition-granularity SST
                // pruning via prefix bloom.
                //
                // StateCf intentionally has NO prefix extractor — its
                // dominant op is `get_cf(K)` (both external point reads
                // and the commit path's `capture_history` multi_get).
                // Whole-key bloom (rocksdb default, enabled globally
                // above) is what gates those. A prefix extractor would
                // add a second bloom per SST, doubling filter-cache
                // footprint and evicting data blocks from the shared
                // block cache without improving point-read latency.
                // `list_at_prefix` on StateCf still works correctly
                // without a prefix extractor — it just can't short-
                // circuit SSTs via prefix bloom.
                if name == STATE_HISTORY_CF {
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(51));
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
            jmt_history_length: config.jmt_history_length,
        })
    }

    /// Get the configured JMT history retention length (in block heights).
    pub fn jmt_history_length(&self) -> u64 {
        self.jmt_history_length
    }

    /// Resolve all column family handles from the database.
    ///
    /// This is cheap (HashMap lookups only, ~10ns per CF) and provides typed
    /// access to all column families without repeating
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

    /// Put a typed key/value into a WriteBatch, using pre-serialized bytes if available.
    pub(crate) fn cf_put_raw<CF: crate::typed_cf::TypedCf>(
        &self,
        batch: &mut WriteBatch,
        key: &CF::Key,
        value: &CF::Value,
        raw_value: Option<&[u8]>,
    ) {
        crate::typed_cf::batch_put_raw::<CF>(batch, CF::handle(&self.cf()), key, value, raw_value);
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

    /// Read JMT version and root hash directly from RocksDB.
    ///
    /// These are stored as a single 40-byte value under `jmt:metadata`:
    /// `[version_BE_8B][root_hash_32B]`. Always hot in the memtable since
    /// they're written on every commit.
    pub(crate) fn read_jmt_metadata(&self) -> (u64, StateRootHash) {
        crate::metadata::read_jmt_metadata(&*self.db)
    }

    /// Append JMT data from a snapshot to a WriteBatch.
    ///
    /// Writes JMT nodes, stale tree parts (for deferred GC), historical
    /// substate associations (if enabled), and JMT metadata (version + root hash).
    ///
    /// This is the write-side complement to `read_jmt_metadata`.
    pub(crate) fn append_jmt_to_batch(
        &self,
        batch: &mut WriteBatch,
        snapshot: &JmtSnapshot,
        new_version: u64,
    ) {
        // JMT nodes — serialize hydrated nodes to stored form at write time.
        let cf = self.cf();
        for (jmt_key, jmt_node) in &snapshot.nodes {
            let stored_key = StoredNodeKey::from_jmt(jmt_key);
            let stored_node = StoredNode::from_jmt(jmt_node);
            crate::typed_cf::batch_put::<crate::column_families::JmtNodesCf>(
                batch,
                crate::column_families::JmtNodesCf::handle(&cf),
                &stored_key,
                &VersionedStoredNode::from_latest(stored_node),
            );
        }

        // Stale nodes for deferred GC — keyed by the version at which they became stale.
        if !snapshot.stale_node_keys.is_empty() {
            // Wrap keys as StaleTreePart::Node for SBOR serialization.
            let stale_parts: Vec<crate::jmt_stored::StaleTreePart> = snapshot
                .stale_node_keys
                .iter()
                .map(|k| crate::jmt_stored::StaleTreePart::Node(StoredNodeKey::from_jmt(k)))
                .collect();
            crate::typed_cf::batch_put::<crate::column_families::StaleJmtNodesCf>(
                batch,
                crate::column_families::StaleJmtNodesCf::handle(&cf),
                &new_version,
                &stale_parts,
            );
        }

        // JMT metadata — single key, atomic read.
        crate::metadata::write_jmt_metadata(batch, new_version, snapshot.result_root);
    }

    /// Append consensus metadata (committed_height, committed_hash, committed_qc)
    /// to a `WriteBatch` so it is persisted atomically with JMT + substate data.
    pub(crate) fn append_consensus_to_batch(
        batch: &mut WriteBatch,
        block: &hyperscale_types::Block,
        qc: &hyperscale_types::QuorumCertificate,
    ) {
        crate::metadata::write_committed_height(batch, block.header().height);
        crate::metadata::write_committed_hash(batch, &block.hash());
        crate::metadata::write_committed_qc(batch, qc);
    }

    /// Build a `WriteBatch` containing all substate puts/deletes from `updates`.
    ///
    /// For each write, captures the prior value (if `write_history`) into
    /// `StateHistoryCf` at `((pk, sk), version)` before mutating `StateCf`.
    /// The `write_history` flag lets the genesis / bootstrap path skip
    /// history writes (no pre-state to preserve).
    ///
    /// Returns `(batch, reset_old_keys)` where `reset_old_keys` maps
    /// `(entity_key, partition_num)` to the old storage keys in the
    /// partition before the Reset — needed downstream for JMT delete
    /// generation.
    pub(crate) fn build_substate_write_batch(
        &self,
        updates: &DatabaseUpdates,
        version: u64,
        write_history: bool,
        base_reads: Option<&hyperscale_storage::BaseReadCache>,
    ) -> (WriteBatch, ResetOldKeys) {
        let mut batch = WriteBatch::default();
        let reset_old_keys = self.append_substate_writes_to_batch(
            &mut batch,
            updates,
            version,
            write_history,
            base_reads,
        );
        (batch, reset_old_keys)
    }

    /// Same as `build_substate_write_batch` but appends to an existing
    /// `WriteBatch`. Used by callers that want to fold substate writes
    /// into a larger atomic batch (e.g. the test-only
    /// `commit_certificate_with_writes`).
    ///
    /// `base_reads`, when provided, is the read cache accumulated by the
    /// originating `SubstateView` during execution. Priors for keys
    /// already in the cache skip the fallback `multi_get_cf`; only keys
    /// NOT in the cache (typically blind writes that weren't preceded
    /// by a read) require a StateCf lookup.
    pub(crate) fn append_substate_writes_to_batch(
        &self,
        batch: &mut WriteBatch,
        updates: &DatabaseUpdates,
        version: u64,
        write_history: bool,
        base_reads: Option<&hyperscale_storage::BaseReadCache>,
    ) -> ResetOldKeys {
        use crate::column_families::{StaleStateHistoryCf, StateCf, StateHistoryCf};
        use crate::typed_cf::{batch_delete, batch_put, multi_get, DbCodec};

        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        let history_cf = StateHistoryCf::handle(&cf);
        let stale_history_cf = StaleStateHistoryCf::handle(&cf);

        // Each update needs its prior value for the state-history entry.
        // Fast path: the view-cache (`base_reads`) already has it from
        // execution — zero extra reads. Slow path: collect keys with no
        // cache entry, batch-`multi_get_cf` them in one FFI call.
        enum Op<'a> {
            Set {
                state_key: (DbPartitionKey, DbSortKey),
                new_value: &'a Vec<u8>,
            },
            Delete {
                state_key: (DbPartitionKey, DbSortKey),
            },
        }

        let mut ops: Vec<Op<'_>> = Vec::with_capacity(updates.node_updates.len());
        // Priors aligned 1:1 with `ops` in pass-1 iteration order.
        // `None` entry = cache miss, needs multi_get fallback.
        let mut priors: Vec<Option<Option<Vec<u8>>>> =
            Vec::with_capacity(updates.node_updates.len());
        // Cache-miss keys, recorded once per op with None prior. Paired
        // with `miss_indices` to write results back after multi_get.
        let mut miss_keys: Vec<(DbPartitionKey, DbSortKey)> = Vec::new();
        let mut miss_indices: Vec<usize> = Vec::new();
        let mut reset_old_keys = ResetOldKeys::new();

        let record_prior = |ops_len: usize,
                            priors: &mut Vec<Option<Option<Vec<u8>>>>,
                            miss_keys: &mut Vec<(DbPartitionKey, DbSortKey)>,
                            miss_indices: &mut Vec<usize>,
                            state_key: &(DbPartitionKey, DbSortKey)| {
            if let Some(cache) = base_reads {
                if let Some(cached) = cache.get(state_key) {
                    priors.push(Some(cached.clone()));
                    return;
                }
            }
            // Cache miss (or no cache provided) — defer to multi_get.
            priors.push(None);
            miss_keys.push(state_key.clone());
            miss_indices.push(ops_len);
        };

        // Pass 1: walk updates, collect ops + priors (from cache or deferred).
        for (node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                let partition_key = DbPartitionKey {
                    node_key: node_key.clone(),
                    partition_num: *partition_num,
                };

                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let state_key = (partition_key.clone(), sort_key.clone());
                            let idx = ops.len();
                            record_prior(
                                idx,
                                &mut priors,
                                &mut miss_keys,
                                &mut miss_indices,
                                &state_key,
                            );
                            match update {
                                DatabaseUpdate::Set(value) => ops.push(Op::Set {
                                    state_key,
                                    new_value: value,
                                }),
                                DatabaseUpdate::Delete => ops.push(Op::Delete { state_key }),
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        // Enumerate current live keys from StateCf (one
                        // entry per key). This is a prefix scan — the
                        // only non-batchable read, unavoidable for Reset.
                        let old_sort_keys = self.list_partition_sort_keys(&partition_key);
                        let new_keys_set: std::collections::HashSet<DbSortKey> =
                            new_substate_values
                                .iter()
                                .map(|(sk, _)| sk.clone())
                                .collect();

                        // Removed keys: old ∖ new → capture prior, delete.
                        for sk in &old_sort_keys {
                            if !new_keys_set.contains(sk) {
                                let state_key = (partition_key.clone(), sk.clone());
                                let idx = ops.len();
                                record_prior(
                                    idx,
                                    &mut priors,
                                    &mut miss_keys,
                                    &mut miss_indices,
                                    &state_key,
                                );
                                ops.push(Op::Delete { state_key });
                            }
                        }

                        if !old_sort_keys.is_empty() {
                            reset_old_keys
                                .insert((node_key.clone(), *partition_num), old_sort_keys);
                        }

                        // New values: capture prior (Some if overwriting,
                        // None if the key was absent), then write.
                        for (sort_key, value) in new_substate_values {
                            let state_key = (partition_key.clone(), sort_key.clone());
                            let idx = ops.len();
                            record_prior(
                                idx,
                                &mut priors,
                                &mut miss_keys,
                                &mut miss_indices,
                                &state_key,
                            );
                            ops.push(Op::Set {
                                state_key,
                                new_value: value,
                            });
                        }
                    }
                }
            }
        }

        // Fill cache misses with a single batched StateCf read. This is
        // the fallback for blind writes (keys execution didn't read) and
        // for callers without a view at all (sync path).
        if !miss_keys.is_empty() {
            let fetched: Vec<Option<Vec<u8>>> =
                multi_get::<StateCf>(&*self.db, state_cf, &miss_keys);
            debug_assert_eq!(fetched.len(), miss_indices.len(), "one fetched per miss");
            for (idx, value) in miss_indices.into_iter().zip(fetched) {
                priors[idx] = Some(value);
            }
        }

        // Pass 2: emit history + state batch puts.
        // Accumulate the raw history keys written so we can record the
        // stale-set entry for this version in one shot.
        let history_key_codec = crate::versioned_key::VersionedSubstateKeyCodec;
        let mut stale_history_keys: Vec<Vec<u8>> = Vec::new();
        for (op, prior_slot) in ops.into_iter().zip(priors) {
            let prior =
                prior_slot.expect("every op must have a resolved prior (cache hit or fetched)");
            match op {
                Op::Set {
                    state_key,
                    new_value,
                } => {
                    // No-op short-circuit: Set(K, X) where prior is
                    // already Some(X) changes nothing. Skip both the
                    // history entry (redundant — reads fall through to
                    // StateCf which already holds X) and the StateCf
                    // put (rocksdb would memtable/compact a useless
                    // same-value write).
                    let is_noop = matches!(&prior, Some(p) if p == new_value);
                    if is_noop {
                        continue;
                    }
                    if write_history {
                        let history_key = (state_key.clone(), version);
                        stale_history_keys.push(history_key_codec.encode(&history_key));
                        batch_put::<StateHistoryCf>(batch, history_cf, &history_key, &prior);
                    }
                    batch_put::<StateCf>(batch, state_cf, &state_key, new_value);
                }
                Op::Delete { state_key } => {
                    // No-op short-circuit: Delete on an absent key is a
                    // no-op. Skip both history and state writes.
                    if prior.is_none() {
                        continue;
                    }
                    if write_history {
                        let history_key = (state_key.clone(), version);
                        stale_history_keys.push(history_key_codec.encode(&history_key));
                        batch_put::<StateHistoryCf>(batch, history_cf, &history_key, &prior);
                    }
                    batch_delete::<StateCf>(batch, state_cf, &state_key);
                }
            }
        }

        // Index the history keys by version so GC can delete them without
        // scanning StateHistoryCf. Skipped when write_history is false
        // (genesis) — nothing was written.
        if write_history && !stale_history_keys.is_empty() {
            batch_put::<StaleStateHistoryCf>(
                batch,
                stale_history_cf,
                &version,
                &stale_history_keys,
            );
        }

        reset_old_keys
    }

    /// Enumerate sort keys currently live in the given partition.
    /// Direct prefix scan on `StateCf` — one entry per key.
    fn list_partition_sort_keys(&self, partition_key: &DbPartitionKey) -> Vec<DbSortKey> {
        use crate::column_families::StateCf;
        use crate::typed_cf::{self, TypedCf};

        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        let partition_prefix = crate::substate_key::partition_prefix(partition_key);

        typed_cf::prefix_iter::<StateCf>(&self.db, state_cf, &partition_prefix)
            .map(|((_pk, sk), _value)| sk)
            .collect()
    }

    /// Write substate data at version 0 (no JMT computation).
    ///
    /// Used during genesis bootstrap for each incremental Radix-engine
    /// commit. Writes land in the unversioned `state` CF directly — no
    /// state-history entries, because genesis has no pre-state to
    /// preserve. Subsequent bootstrap calls read the accumulated state
    /// via `snapshot_at(0)`. After all genesis commits complete,
    /// [`finalize_genesis_jmt`] computes the JMT once over the merged
    /// updates — the substates are already in place by then.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        // Genesis writes at version 0. Repeat Sets to the same key
        // overwrite — idempotent by RocksDB write semantics. No history
        // entries: genesis has no pre-state to preserve.
        let (batch, _) = self.build_substate_write_batch(
            updates, 0, /* write_history */ false, /* base_reads */ None,
        );

        // Substates only — no JMT, no sync (genesis isn't durability-critical).
        self.db
            .write(batch)
            .expect("genesis substate-only commit failed");
    }

    /// Compute the JMT once at version 0 from the merged genesis updates.
    ///
    /// Called after all genesis bootstrap commits are complete. The
    /// substates are already in the state CF at version 0 from the
    /// incremental `commit_substates_only` calls; this just adds the
    /// JMT tree for cryptographic commitment.
    ///
    /// # Returns
    /// The genesis state root hash (JMT root at version 0).
    pub fn finalize_genesis_jmt(&self, merged: &DatabaseUpdates) -> StateRootHash {
        let _commit_guard = self.commit_lock.lock().unwrap();

        // Guard: finalize_genesis_jmt must only be called once, on an uninitialized JMT.
        let (current_version, current_root) = self.read_jmt_metadata();
        assert!(
            current_version == 0 && current_root == StateRootHash::ZERO,
            "finalize_genesis_jmt called but JMT already initialized (version={current_version})"
        );

        let snapshot_store = SnapshotTreeStore::new(&self.db);

        // parent=None, version=0: genesis is the first JMT state.
        let (root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            None,
            0,
            &[merged],
            &Default::default(),
        );
        let jmt_snapshot =
            JmtSnapshot::from_collected_writes(collected, StateRootHash::ZERO, 0, root, 0);

        let mut batch = WriteBatch::default();
        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, 0);

        self.db
            .write(batch)
            .expect("genesis JMT finalization failed");

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
        // Default-version snapshot (= current committed tip) reads
        // the latest value for this key. Delegating to `snapshot()`
        // keeps a single read path.
        let start = Instant::now();
        let result = <Self as hyperscale_storage::SubstateStore>::snapshot(self)
            .get_raw_substate_by_db_key(partition_key, sort_key);
        let elapsed = start.elapsed();
        metrics::record_storage_read(elapsed.as_secs_f64());

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
        // Partition scan at current version. Same rationale as `get` —
        // one canonical read path through the snapshot.
        let items: Vec<_> = <Self as hyperscale_storage::SubstateStore>::snapshot(self)
            .list_raw_values_from_db_key(partition_key, from_sort_key)
            .collect();
        Box::new(items.into_iter())
    }
}

impl jmt::TreeReader for RocksDbStorage {
    fn get_node(&self, key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
        let stored_key = StoredNodeKey::from_jmt(key);
        self.cf_get::<crate::column_families::JmtNodesCf>(&stored_key)
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<jmt::NodeKey> {
        let root = jmt::NodeKey::root(version);
        let stored_key = StoredNodeKey::from_jmt(&root);
        if self
            .cf_get::<crate::column_families::JmtNodesCf>(&stored_key)
            .is_some()
        {
            Some(root)
        } else {
            None
        }
    }
}

/// Test-only methods with auto-incrementing JMT version logic.
/// Production uses `commit_block` / `commit_prepared_block` instead.
#[cfg(test)]
impl RocksDbStorage {
    /// Test helper: commits database updates with auto-incrementing JMT version.
    /// Not used in production (use commit_block instead).
    #[instrument(level = Level::DEBUG, skip_all, fields(
        node_count = updates.node_updates.len(),
        latency_us = tracing::field::Empty,
    ))]
    pub fn commit(&self, updates: &DatabaseUpdates) -> Result<(), StorageError> {
        let _commit_guard = self.commit_lock.lock().unwrap();

        let start = Instant::now();

        // Compute JMT updates using a snapshot-based store for isolation
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();

        // Version 0 with a non-zero root means genesis has been computed at version 0.
        // Only treat as "no parent" when the JMT is truly empty.
        let parent_version = hyperscale_storage::tree::jmt_parent_height(base_version, base_root);
        let new_version = base_version + 1;

        let (mut batch, reset_old_keys) = self.build_substate_write_batch(
            updates,
            new_version,
            /* write_history */ true,
            /* base_reads */ None,
        );

        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &snapshot_store,
            parent_version,
            new_version,
            &[updates],
            &reset_old_keys,
        );
        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            new_root,
            new_version,
        );

        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, new_version);

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
impl hyperscale_storage::CommittableSubstateDatabase for RocksDbStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        RocksDbStorage::commit(self, updates)
            .expect("Storage commit failed - cannot maintain consistent state")
    }
}
