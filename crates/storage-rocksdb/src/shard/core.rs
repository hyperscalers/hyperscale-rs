//! # `RocksDB` Storage
//!
//! Production storage implementation using `RocksDB`.
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

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_metrics::record_storage_read;
use hyperscale_storage::{
    BaseReadCache, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue,
    GenesisCommit, JmtSnapshot, PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
    SubstateStore, tree,
};
use hyperscale_types::{Block, BlockHeight, Hash, NodeId, QuorumCertificate, StateRoot, Verified};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompressionType, Options,
    SliceTransform, WriteBatch,
};
use sbor::prelude::*;
use tracing::field::Empty;
use tracing::{Level, Span, instrument};

use super::column_families::{
    ALL_COLUMN_FAMILIES, CfHandles, HOT_WRITE_COLUMN_FAMILIES, JmtNodesCf, LeafAssociationsCf,
    STATE_HISTORY_CF, StaleJmtNodesCf, StaleStateHistoryCf, StateCf, StateHistoryCf,
    SubstateBytesCf,
};
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::jmt_stored::{StaleTreePart, StoredNode, StoredNodeKey, VersionedStoredNode};
use super::metadata::{
    read_jmt_metadata, write_committed_hash, write_committed_height, write_committed_qc,
    write_jmt_metadata,
};
use super::substate_key::partition_prefix;
use super::versioned_key::VersionedSubstateKeyCodec;
use crate::StorageError;
use crate::config::RocksDbConfig;
use crate::typed_cf::{DbEncode, TypedCf, batch_delete, batch_put, get, multi_get, prefix_iter};

/// Sort keys deleted by partition Reset operations, keyed by `(entity_key, partition_num)`.
/// Passed to `put_at_version` so the JMT can reconstruct full storage keys and
/// generate deletes for the hashed keys.
pub type ResetOldKeys = HashMap<(Vec<u8>, u8), Vec<DbSortKey>>;

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
/// directly from `RocksDB` on demand — always hot in the memtable since they're
/// written on every commit.
pub struct RocksDbShardStorage {
    pub(crate) db: Arc<DB>,

    /// Serializes JMT-mutating commits to prevent interleaved read-modify-write
    /// sequences (e.g., `read_jmt_metadata` + `WriteBatch` write).
    pub(crate) commit_lock: Mutex<()>,

    /// Number of block heights of JMT history to retain before garbage collection.
    pub(crate) jmt_history_length: u64,

    /// Path this store's JMT is rooted at — its shard's prefix, so the root is
    /// the global tree's subtree at that prefix. Empty for a single-shard /
    /// whole-keyspace store. Set once at open from the shard's `ShardId`.
    pub(crate) root_path: NibblePath,

    /// Checkpoint ring for snap-sync boundary pins, rooted at the
    /// `checkpoints` directory beside the database.
    pub(crate) checkpoints: super::checkpoints::CheckpointRing,
}

impl RocksDbShardStorage {
    /// Open or create a shard store rooted at the given directory.
    ///
    /// See [`Self::open_with_config`] for the directory layout.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if `RocksDB` fails to open the database.
    pub fn open<P: AsRef<Path>>(path: P, root_path: NibblePath) -> Result<Self, StorageError> {
        Self::open_with_config(path, &RocksDbConfig::default(), root_path)
    }

    /// Open with custom configuration.
    ///
    /// `path` is the shard's storage directory: the database lives at
    /// `path/db`, and the snap-sync checkpoint ring at `path/checkpoints`
    /// (`RocksDB` checkpoints hard-link the database's SSTs, so the ring
    /// sits beside — never inside — the `RocksDB`-owned directory).
    ///
    /// `root_path` is the prefix of the shard this store serves (via
    /// [`hyperscale_types::shard_prefix_path`]), so its JMT roots there and its
    /// `state_root` is the global tree's subtree at that prefix. Pass
    /// [`NibblePath::empty`] for a single-shard / whole-keyspace store.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if `RocksDB` fails to open the database.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        config: &RocksDbConfig,
        root_path: NibblePath,
    ) -> Result<Self, StorageError> {
        let dir = path.as_ref();
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
        let mut block_opts = BlockBasedOptions::default();
        if let Some(cache_size) = config.block_cache_size {
            let cache = Cache::new_lru_cache(cache_size);
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
            DBCompressionType::None, // L0
            DBCompressionType::None, // L1
            DBCompressionType::Lz4,  // L2
            DBCompressionType::Lz4,  // L3
            DBCompressionType::Lz4,  // L4
            DBCompressionType::Zstd, // L5
            DBCompressionType::Zstd, // L6
        ];

        let cold_write_buffer_size: usize = 16 * 1024 * 1024; // 16MB

        let cf_descriptors: Vec<_> = ALL_COLUMN_FAMILIES
            .iter()
            .copied()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_block_based_table_factory(&block_opts);
                cf_opts.set_max_write_buffer_number(config.max_write_buffer_number);

                let is_hot = hot_write_cfs.contains(&name);
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
                // pruning via prefix bloom. StateCf is point-read
                // dominated and uses whole-key bloom only — see its
                // type doc.
                if name == STATE_HISTORY_CF {
                    cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(51));
                }

                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&opts, dir.join("db"), cf_descriptors)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Validate all expected column families exist at startup.
        // This fails fast instead of panicking on first access at runtime.
        CfHandles::resolve(&db);

        let db = Arc::new(db);
        let checkpoints =
            super::checkpoints::CheckpointRing::from_db(Arc::clone(&db), dir.join("checkpoints"));

        Ok(Self {
            db,
            commit_lock: Mutex::new(()),
            jmt_history_length: config.jmt_history_length,
            root_path,
            checkpoints,
        })
    }

    /// Get the configured JMT history retention length (in block heights).
    pub const fn jmt_history_length(&self) -> u64 {
        self.jmt_history_length
    }

    /// Resolve all column family handles from the database.
    ///
    /// This is cheap (`HashMap` lookups only, ~10ns per CF) and provides typed
    /// access to all column families without repeating
    /// `.cf_handle(NAME).expect(...)` at each call site.
    pub(crate) fn cf(&self) -> CfHandles<'_> {
        CfHandles::resolve(&self.db)
    }

    // ─── Typed CF helpers ────────────────────────────────────────────────
    //
    // Thin wrappers over the free functions in typed_cf.rs.
    // These resolve CfHandles and pass &self.db as the ReadableStore.
    //
    // Constrained to CFs whose `Handles<'_>` is the shard tier's
    // `CfHandles<'_>` — the beacon RocksDB instance has its own
    // handles struct and its own helper layer.

    /// Get a typed value from a column family.
    pub(crate) fn cf_get<CF>(&self, key: &CF::Key) -> Option<CF::Value>
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        get::<CF>(&*self.db, CF::handle(&self.cf()), key)
    }

    /// Put a typed key/value into a `WriteBatch`. Production per-block
    /// loops pre-resolve column-family handles outside the loop and call
    /// [`batch_put`] directly; this method is the right shape for one-shot
    /// writes where re-resolving handles per call doesn't matter.
    #[allow(dead_code)]
    pub(crate) fn cf_put<CF>(&self, batch: &mut WriteBatch, key: &CF::Key, value: &CF::Value)
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        batch_put::<CF>(batch, CF::handle(&self.cf()), key, value);
    }

    /// Batch get typed values (`RocksDB` `multi_get_cf`).
    pub(crate) fn cf_multi_get<CF>(&self, keys: &[CF::Key]) -> Vec<Option<CF::Value>>
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        multi_get::<CF>(&*self.db, CF::handle(&self.cf()), keys)
    }

    /// Delete a typed key in a `WriteBatch`.
    #[allow(dead_code)]
    pub(crate) fn cf_delete<CF>(&self, batch: &mut WriteBatch, key: &CF::Key)
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        batch_delete::<CF>(batch, CF::handle(&self.cf()), key);
    }

    /// Typed single put (immediate write, no batch).
    pub(crate) fn cf_put_sync<CF>(&self, key: &CF::Key, value: &CF::Value)
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        let cf = CF::handle(&self.cf());
        let key_bytes = CF::KeyCodec::default().encode(key);
        let value_bytes = CF::ValueCodec::default().encode(value);
        self.db
            .put_cf(cf, &key_bytes, &value_bytes)
            .expect("BFT CRITICAL: write failed");
    }

    /// Read JMT version and root hash directly from `RocksDB`.
    ///
    /// These are stored as a single 40-byte value under `jmt:metadata`:
    /// `[version_BE_8B][root_hash_32B]`. Always hot in the memtable since
    /// they're written on every commit.
    pub(crate) fn read_jmt_metadata(&self) -> (u64, StateRoot) {
        read_jmt_metadata(&*self.db)
    }

    /// Append JMT data from a snapshot to a `WriteBatch`.
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
            batch_put::<JmtNodesCf>(
                batch,
                JmtNodesCf::handle(&cf),
                &stored_key,
                &VersionedStoredNode::from_latest(stored_node),
            );
        }

        // Stale nodes for deferred GC — keyed by the version at which they became stale.
        if !snapshot.stale_node_keys.is_empty() {
            // Wrap keys as StaleTreePart::Node for SBOR serialization.
            let stale_parts: Vec<StaleTreePart> = snapshot
                .stale_node_keys
                .iter()
                .map(|k| StaleTreePart::Node(StoredNodeKey::from_jmt(k)))
                .collect();
            batch_put::<StaleJmtNodesCf>(
                batch,
                StaleJmtNodesCf::handle(&cf),
                &new_version,
                &stale_parts,
            );
        }

        // Leaf associations — keep the hashed-key → raw-key mapping in
        // lockstep with the live leaf set.
        let leaf_assoc_cf = LeafAssociationsCf::handle(&cf);
        for assoc in &snapshot.leaf_associations {
            let key = Hash::from_hash_bytes(&assoc.leaf_key);
            match &assoc.storage_key {
                Some(storage_key) => {
                    batch_put::<LeafAssociationsCf>(batch, leaf_assoc_cf, &key, storage_key);
                }
                None => batch_delete::<LeafAssociationsCf>(batch, leaf_assoc_cf, &key),
            }
        }

        // JMT metadata — single key, atomic read.
        write_jmt_metadata(batch, new_version, snapshot.result_root);

        // Committed substate byte total — derived from the byte total behind the
        // currently committed version (the parent of this commit; equal
        // across any interleaved empty commits) plus this commit's leaf
        // delta. Written in the same batch so the count is
        // crash-consistent with the tree. Consensus-critical: witness
        // derivation reads it, so it must be identical on every replica.
        let (current_version, _) = self.read_jmt_metadata();
        let prior = self.substate_bytes_at_version(current_version).unwrap_or(0);
        let count = prior
            .checked_add_signed(snapshot.bytes_delta)
            .expect("substate byte total must not go negative");
        batch_put::<SubstateBytesCf>(batch, SubstateBytesCf::handle(&cf), &new_version, &count);
    }

    /// Committed substate byte total after the commit at `version`,
    /// or `None` if no commit at that version recorded one (never
    /// committed, or pruned past the retention horizon).
    pub fn substate_bytes_at_version(&self, version: u64) -> Option<u64> {
        let cf = self.cf();
        get::<SubstateBytesCf>(&*self.db, SubstateBytesCf::handle(&cf), &version)
    }

    /// Append consensus metadata (`committed_height`, `committed_hash`, `committed_qc`)
    /// to a `WriteBatch` so it is persisted atomically with JMT + substate data.
    pub(crate) fn append_consensus_to_batch(
        batch: &mut WriteBatch,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
    ) {
        write_committed_height(batch, block.height());
        write_committed_hash(batch, block.hash().as_raw());
        write_committed_qc(batch, qc.as_ref());
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
        base_reads: Option<&BaseReadCache>,
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
    /// by a read) require a `StateCf` lookup.
    #[allow(clippy::too_many_lines)] // single dispatch over read/write paths; splitting hurts locality
    pub(crate) fn append_substate_writes_to_batch(
        &self,
        batch: &mut WriteBatch,
        updates: &DatabaseUpdates,
        version: u64,
        write_history: bool,
        base_reads: Option<&BaseReadCache>,
    ) -> ResetOldKeys {
        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        let history_cf = StateHistoryCf::handle(&cf);
        let stale_history_cf = StaleStateHistoryCf::handle(&cf);

        // Each update needs its prior value for the state-history entry.
        // Fast path: the view-cache (`base_reads`) already has it from
        // execution — zero extra reads. Slow path: collect keys with no
        // cache entry, batch-`multi_get_cf` them in one FFI call.
        #[allow(clippy::items_after_statements)] // local enum is scoped to this function
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
            if let Some(cache) = base_reads
                && let Some(cached) = cache.get(state_key)
            {
                priors.push(Some(cached.clone()));
                return;
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
        let history_key_codec = VersionedSubstateKeyCodec;
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
        let cf = self.cf();
        let state_cf = StateCf::handle(&cf);
        let prefix = partition_prefix(partition_key);

        prefix_iter::<StateCf>(&self.db, state_cf, &prefix)
            .map(|((_pk, sk), _value)| sk)
            .collect()
    }

    /// Write substate data at version 0 (no JMT computation).
    ///
    /// Genesis-install primitive: writes land in the unversioned `state` CF
    /// with **no state-history entries** — genesis has no pre-state to
    /// preserve. Pair with [`Self::finalize_genesis_jmt`] to compute the JMT
    /// root over the same updates;
    /// [`GenesisCommit::install_genesis`] composes both.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
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
    /// Called after [`Self::commit_substates_only`] has placed the substates
    /// in the state CF; this adds the JMT tree for cryptographic commitment.
    ///
    /// # Returns
    /// The genesis state root hash (JMT root at version 0).
    ///
    /// # Panics
    ///
    /// Panics if called after the JMT has already been initialized, or
    /// if the underlying `RocksDB` write fails.
    #[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
    pub fn finalize_genesis_jmt(
        &self,
        merged: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot {
        let _commit_guard = self.commit_lock.lock().unwrap();

        // Guard: finalize_genesis_jmt must only be called once, on an uninitialized JMT.
        let (current_version, current_root) = self.read_jmt_metadata();
        assert!(
            current_version == 0 && current_root == StateRoot::ZERO,
            "finalize_genesis_jmt called but JMT already initialized (version={current_version})"
        );

        let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());

        // parent=None, version=0: genesis is the first JMT state.
        let (root, collected) = tree::put_at_version(
            &snapshot_store,
            None,
            0,
            &[merged],
            &HashMap::new(),
            owner_map,
        );
        let jmt_snapshot = JmtSnapshot::from_collected_writes(
            collected,
            StateRoot::ZERO,
            BlockHeight::GENESIS,
            root,
            BlockHeight::GENESIS,
        );

        let mut batch = WriteBatch::default();
        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, 0);

        self.db
            .write(batch)
            .expect("genesis JMT finalization failed");

        root
    }
}

impl GenesisCommit for RocksDbShardStorage {
    fn install_genesis(
        &self,
        substates: &DatabaseUpdates,
        jmt_updates: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot {
        Self::commit_substates_only(self, substates);
        Self::finalize_genesis_jmt(self, jmt_updates, owner_map)
    }

    fn replicate_genesis_substates(&self, substates: &DatabaseUpdates) {
        Self::commit_substates_only(self, substates);
    }
}

impl SubstateDatabase for RocksDbShardStorage {
    #[instrument(level = Level::DEBUG, skip_all, fields(
        found = Empty,
        latency_us = Empty,
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
        let result = <Self as SubstateStore>::snapshot(self)
            .get_raw_substate_by_db_key(partition_key, sort_key);
        let elapsed = start.elapsed();
        record_storage_read(elapsed.as_secs_f64());

        let span = Span::current();
        span.record("found", result.is_some());
        span.record(
            "latency_us",
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        );

        result
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        // Partition scan at current version. Same rationale as `get` —
        // one canonical read path through the snapshot.
        #[allow(clippy::needless_collect)] // snapshot iterator borrows from temporary
        let items: Vec<_> = <Self as SubstateStore>::snapshot(self)
            .list_raw_values_from_db_key(partition_key, from_sort_key)
            .collect();
        Box::new(items.into_iter())
    }
}

impl TreeReader for RocksDbShardStorage {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        let stored_key = StoredNodeKey::from_jmt(key);
        self.cf_get::<JmtNodesCf>(&stored_key)
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        let root = JmtNodeKey::new(version, self.root_path.clone());
        let stored_key = StoredNodeKey::from_jmt(&root);
        if self.cf_get::<JmtNodesCf>(&stored_key).is_some() {
            Some(root)
        } else {
            None
        }
    }

    fn root_path(&self) -> NibblePath {
        self.root_path.clone()
    }
}

#[cfg(test)]
mod test_helpers {
    use hyperscale_metrics::record_storage_write;
    use hyperscale_storage::CommittableSubstateDatabase;

    use super::*;

    impl RocksDbShardStorage {
        /// Test helper: commits database updates with auto-incrementing JMT version.
        /// Production uses `commit_block` / `commit_prepared_block` instead.
        ///
        /// # Errors
        ///
        /// Returns [`StorageError`] if the underlying `RocksDB` write fails.
        ///
        /// # Panics
        ///
        /// Panics if the commit lock is poisoned.
        #[instrument(level = Level::DEBUG, skip_all, fields(
            node_count = updates.node_updates.len(),
            latency_us = Empty,
        ))]
        pub fn commit(&self, updates: &DatabaseUpdates) -> Result<(), StorageError> {
            let _commit_guard = self.commit_lock.lock().unwrap();

            let start = Instant::now();

            // Compute JMT updates using a snapshot-based store for isolation
            let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
            let (base_version, base_root) = snapshot_store.read_jmt_metadata();

            // Version 0 with a non-zero root means genesis has been computed at version 0.
            // Only treat as "no parent" when the JMT is truly empty.
            let parent_version = tree::jmt_parent_height(BlockHeight::new(base_version), base_root)
                .map(BlockHeight::inner);
            let new_version = base_version + 1;

            let (mut batch, reset_old_keys) = self.build_substate_write_batch(
                updates,
                new_version,
                /* write_history */ true,
                /* base_reads */ None,
            );

            let (new_root, collected) = tree::put_at_version(
                &snapshot_store,
                parent_version,
                new_version,
                &[updates],
                &reset_old_keys,
                &HashMap::new(),
            );
            let jmt_snapshot = JmtSnapshot::from_collected_writes(
                collected,
                base_root,
                BlockHeight::new(base_version),
                new_root,
                BlockHeight::new(new_version),
            );

            self.append_jmt_to_batch(&mut batch, &jmt_snapshot, new_version);

            self.db
                .write(batch)
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

            let elapsed = start.elapsed();
            record_storage_write(elapsed.as_secs_f64());

            // Record span fields
            let span = Span::current();
            span.record(
                "latency_us",
                u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            );
            tracing::debug!(new_version, "commit complete");

            Ok(())
        }
    }

    impl CommittableSubstateDatabase for RocksDbShardStorage {
        fn commit(&mut self, updates: &DatabaseUpdates) {
            Self::commit(self, updates)
                .expect("Storage commit failed - cannot maintain consistent state");
        }
    }
}
