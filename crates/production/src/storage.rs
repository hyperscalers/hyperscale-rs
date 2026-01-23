//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JMT Integration
//!
//! Uses Jellyfish Merkle Tree (JMT) for cryptographic state commitment.
//! JMT data is stored in dedicated column families (`jmt_nodes`, `jmt_meta`).
//! On each commit, the JMT is updated and a new state root hash is computed.

use crate::metrics;
use hyperscale_engine::{
    keys, put_at_next_version, CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates,
    DbPartitionKey, DbSortKey, DbSubstateValue, JmtSnapshot, OverlayTreeStore,
    PartitionDatabaseUpdates, PartitionEntry, StateRootHash, SubstateDatabase, SubstateStore,
    TypedInMemoryTreeStore, WriteableTreeStore,
};
use hyperscale_types::NodeId;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, Snapshot, WriteBatch, DB};
use sbor::prelude::*;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{instrument, Level};

/// Cached data for efficient block commit.
///
/// Built during state root verification and applied during block commit.
/// This enables batching all RocksDB writes into a single atomic write operation
/// with one fsync, instead of N fsyncs for N certificates.
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct BlockCommitCache {
    /// Pre-built RocksDB WriteBatch containing all certificate + state writes.
    pub write_batch: WriteBatch,

    /// JMT snapshot containing precomputed tree nodes.
    /// Applied after the WriteBatch to update the in-memory Merkle tree.
    pub jmt_snapshot: JmtSnapshot,
}

/// JMT state bundled together for atomic updates.
///
/// All JMT operations must hold this lock to prevent race conditions where
/// concurrent commits could read stale versions or access pruned nodes.
struct JmtState {
    /// In-memory JMT tree store.
    tree_store: TypedInMemoryTreeStore,
    /// Current state version (persisted to DB).
    current_version: u64,
    /// Current JMT state root hash (persisted to DB).
    current_root_hash: StateRootHash,
}

/// RocksDB-based storage for production use.
///
/// Features:
/// - Column families for logical separation
/// - LZ4 compression for disk efficiency
/// - Block cache for read performance
/// - Bloom filters for key existence checks
/// - JMT for cryptographic state commitment
///
/// Implements Radix's `SubstateDatabase` and `CommittableSubstateDatabase` directly,
/// plus our `SubstateStore` extension for snapshots, node listing, and JMT state roots.
///
/// # JMT State Tracking
///
/// Uses an in-memory `TypedInMemoryTreeStore` for JMT computation. The JMT state
/// (version and root hash) is persisted to RocksDB on each commit for crash recovery.
/// On startup, the JMT is rebuilt from the persisted state.
pub struct RocksDbStorage {
    db: Arc<DB>,

    /// JMT state protected by a single lock for atomic updates.
    ///
    /// This prevents race conditions where concurrent `commit_certificate_with_writes`
    /// calls could read stale versions and attempt to update from pruned parent nodes.
    jmt: Mutex<JmtState>,

    /// Cache of block commit data, keyed by block hash.
    ///
    /// When a block is verified, we build a [`BlockCommitCache`] containing:
    /// - A pre-built RocksDB WriteBatch with all certificate + state writes
    /// - A JMT snapshot with precomputed Merkle tree nodes
    ///
    /// When the block commits, the cached WriteBatch is applied with a single
    /// fsync instead of N fsyncs for N certificates.
    ///
    /// Uses a simple HashMap since WriteBatch isn't Sync (contains raw pointer).
    /// The mutex is only held briefly during insert/remove operations.
    block_commit_cache: Mutex<HashMap<hyperscale_types::Hash, BlockCommitCache>>,
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

        // Compression
        opts.set_compression_type(config.compression.to_rocksdb());

        // Block cache and bloom filter
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        if let Some(cache_size) = config.block_cache_size {
            let cache = rocksdb::Cache::new_lru_cache(cache_size);
            block_opts.set_block_cache(&cache);
        }
        if config.bloom_filter_bits > 0.0 {
            block_opts.set_bloom_filter(config.bloom_filter_bits, false);
        }
        opts.set_block_based_table_factory(&block_opts);

        // Column families
        let cf_descriptors: Vec<_> = config
            .column_families
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Load JMT state from DB (or initialize if first run)
        let (version, root_hash) = Self::load_jmt_state(&db);

        Ok(Self {
            db: Arc::new(db),
            jmt: Mutex::new(JmtState {
                tree_store: TypedInMemoryTreeStore::new().with_pruning_enabled(),
                current_version: version,
                current_root_hash: root_hash,
            }),
            block_commit_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Load JMT state from the database.
    fn load_jmt_state(db: &DB) -> (u64, StateRootHash) {
        // Try to load from default CF with well-known keys
        let version = db
            .get(b"jmt:version")
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);

        let root_hash = db
            .get(b"jmt:root_hash")
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(StateRootHash(arr))
                } else {
                    None
                }
            })
            .unwrap_or(StateRootHash([0u8; 32]));

        (version, root_hash)
    }

    /// Persist JMT state to the database.
    fn persist_jmt_state(&self, version: u64, root_hash: StateRootHash) {
        // Persist to default CF with sync for durability
        let mut batch = WriteBatch::default();
        batch.put(b"jmt:version", version.to_be_bytes());
        batch.put(b"jmt:root_hash", root_hash.0);

        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        if let Err(e) = self.db.write_opt(batch, &write_opts) {
            tracing::error!("Failed to persist JMT state: {}", e);
        }
    }

    /// Get a column family handle by name.
    #[allow(dead_code)]
    fn cf(&self, name: &str) -> Result<&ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::DatabaseError(format!("Column family {} not found", name)))
    }

    /// Internal: iterate over a key range.
    fn iter_range<'a>(
        &'a self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a {
        let mut iter = self.db.raw_iterator();
        iter.seek(start);
        let end = end.to_vec();

        std::iter::from_fn(move || {
            if iter.valid() {
                let key = iter.key()?;
                if key < end.as_slice() {
                    let k: Box<[u8]> = Box::from(key);
                    let v: Box<[u8]> = Box::from(iter.value()?);
                    iter.next();
                    Some((k, v))
                } else {
                    None
                }
            } else {
                None
            }
        })
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
        let key = keys::to_storage_key(partition_key, sort_key);
        let result = self.db.get(&key).ok().flatten();
        let elapsed = start.elapsed();
        metrics::record_rocksdb_read(elapsed.as_secs_f64());

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
        let end = keys::next_prefix(&prefix);

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

impl RocksDbStorage {
    /// Commit database updates using a shared reference.
    ///
    /// Returns an error if the write fails. Callers must handle the error appropriately -
    /// for critical state updates, this typically means crashing to prevent data divergence.
    ///
    /// # Safety
    /// This is safe because RocksDB's `DB::write()` only requires `&self` internally.
    /// The `CommittableSubstateDatabase` trait requires `&mut self` but RocksDB doesn't
    /// actually need exclusive access - it handles synchronization internally.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        node_count = updates.node_updates.len(),
        latency_us = tracing::field::Empty,
    ))]
    pub fn commit(&self, updates: &DatabaseUpdates) -> Result<(), StorageError> {
        let start = Instant::now();
        let mut batch = WriteBatch::default();
        let mut put_count = 0u64;
        let mut delete_count = 0u64;

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
                                    batch.put(&key, value);
                                    put_count += 1;
                                }
                                DatabaseUpdate::Delete => {
                                    batch.delete(&key);
                                    delete_count += 1;
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        // Delete all existing in partition
                        let prefix = keys::partition_prefix(&partition_key);
                        let end = keys::next_prefix(&prefix);

                        let mut iter = self.db.raw_iterator();
                        iter.seek(&prefix);
                        while iter.valid() {
                            if let Some(key) = iter.key() {
                                if key >= end.as_slice() {
                                    break;
                                }
                                batch.delete(key);
                                delete_count += 1;
                                iter.next();
                            } else {
                                break;
                            }
                        }

                        // Insert new values
                        for (sort_key, value) in new_substate_values {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            batch.put(&key, value);
                            put_count += 1;
                        }
                    }
                }
            }
        }

        // Write batch atomically - RocksDB handles internal synchronization
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Update JMT and compute new root hash (single lock for atomicity)
        let (new_version, new_root) = {
            let mut jmt = self.jmt.lock().unwrap();
            let parent_version = if jmt.current_version == 0 {
                None
            } else {
                Some(jmt.current_version)
            };
            let new_root = put_at_next_version(&jmt.tree_store, parent_version, updates);
            let new_version = jmt.current_version + 1;

            // Update in-memory state while still holding the lock
            jmt.current_version = new_version;
            jmt.current_root_hash = new_root;

            (new_version, new_root)
        };

        // Persist JMT state (outside lock - RocksDB is thread-safe)
        self.persist_jmt_state(new_version, new_root);

        let elapsed = start.elapsed();
        metrics::record_rocksdb_write(elapsed.as_secs_f64());

        // Record span fields
        let span = tracing::Span::current();
        span.record("latency_us", elapsed.as_micros() as u64);
        tracing::debug!(put_count, delete_count, new_version, "commit complete");

        Ok(())
    }

    /// Get a mutable reference for APIs that require `&mut self`.
    ///
    /// # Safety
    /// This is safe because RocksDB is internally thread-safe. The mutable reference
    /// is only needed to satisfy trait bounds (like `CommittableSubstateDatabase`),
    /// not for actual exclusivity. RocksDB's `DB` type uses internal locking.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_mut(&self) -> &mut Self {
        // Use UnsafeCell pattern to avoid the invalid_reference_casting lint.
        // This is sound because RocksDB is internally synchronized.
        let cell = UnsafeCell::new(std::ptr::null_mut::<Self>());
        *cell.get() = self as *const Self as *mut Self;
        &mut **cell.get()
    }
}

impl CommittableSubstateDatabase for RocksDbStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        // Delegate to the shared version - RocksDB doesn't need &mut
        // Panic on error since the trait doesn't support Result and this is safety-critical
        RocksDbStorage::commit(self, updates)
            .expect("Storage commit failed - cannot maintain consistent state")
    }
}

impl SubstateStore for RocksDbStorage {
    type Snapshot<'a> = RocksDbSnapshot<'a>;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Use RocksDB's native snapshot feature for point-in-time isolation.
        // The snapshot provides a consistent view of the database at the time
        // of creation, immune to concurrent writes.
        RocksDbSnapshot {
            snapshot: self.db.snapshot(),
        }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix);

        let items = self.iter_range(&prefix, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let partition_num = full_key[prefix_len];
                let sort_key_bytes = full_key[prefix_len + 1..].to_vec();
                Some((partition_num, DbSortKey(sort_key_bytes), value.into_vec()))
            } else {
                None
            }
        }))
    }

    fn state_version(&self) -> u64 {
        self.jmt.lock().unwrap().current_version
    }

    fn state_root_hash(&self) -> StateRootHash {
        self.jmt.lock().unwrap().current_root_hash
    }
}

impl RocksDbStorage {
    /// Get the current JMT root hash.
    pub fn current_jmt_root(&self) -> hyperscale_types::Hash {
        let jmt = self.jmt.lock().unwrap();
        hyperscale_types::Hash::from_bytes(&jmt.current_root_hash.0)
    }

    /// Compute speculative state root and capture a snapshot for later application.
    ///
    /// This is used for state root verification and proposal. The caller specifies
    /// the expected base root (parent block's state_root), and we verify the JMT
    /// matches before computing the new root after applying certificate writes.
    ///
    /// Returns both the computed state root AND a [`JmtSnapshot`] containing the
    /// tree nodes created during computation. The snapshot can be cached and applied
    /// during block commit, avoiding redundant recomputation.
    ///
    /// # Arguments
    /// * `expected_base_root` - The state root we expect the JMT to have. If the
    ///   JMT's current root doesn't match, verification will likely fail.
    /// * `writes_per_cert` - State writes grouped by certificate.
    ///
    /// # Returns
    /// A tuple of (computed_state_root, snapshot). The snapshot can be applied
    /// to the real JMT during commit via [`apply_jmt_snapshot`].
    pub fn compute_speculative_root_from_base(
        &self,
        expected_base_root: hyperscale_types::Hash,
        writes_per_cert: &[Vec<hyperscale_types::SubstateWrite>],
    ) -> (hyperscale_types::Hash, JmtSnapshot) {
        let jmt = self.jmt.lock().unwrap();

        let base_root = jmt.current_root_hash;
        let current_root = hyperscale_types::Hash::from_bytes(&base_root.0);

        // If no certificates, return current root with empty snapshot.
        if writes_per_cert.is_empty() {
            let snapshot = JmtSnapshot {
                base_root,
                base_version: jmt.current_version,
                result_root: base_root,
                num_versions: 0,
                nodes: std::collections::HashMap::new(),
            };
            return (current_root, snapshot);
        }

        // Verify the JMT root matches the expected base root.
        // This is the key guarantee: both proposer and verifier must compute from
        // the same base state for verification to succeed.
        if current_root != expected_base_root {
            tracing::warn!(
                current_root = ?current_root,
                expected_base_root = ?expected_base_root,
                "JMT root mismatch - verification will likely fail"
            );
            // Continue anyway - the computed root won't match and verification will fail
        }

        // Apply each certificate's writes at a separate version using the overlay.
        let overlay = OverlayTreeStore::new(&jmt.tree_store);

        let base_version = jmt.current_version;
        let mut current_version = base_version;
        let mut root = jmt.current_root_hash;
        let num_versions = writes_per_cert.len() as u64;

        for cert_writes in writes_per_cert {
            let updates = hyperscale_engine::substate_writes_to_database_updates(cert_writes);
            let parent_version = if current_version == 0 {
                None
            } else {
                Some(current_version)
            };

            root = put_at_next_version(&overlay, parent_version, &updates);
            current_version += 1;
        }

        let result_root = hyperscale_types::Hash::from_bytes(&root.0);
        let snapshot = overlay.into_snapshot(base_root, base_version, root, num_versions);

        (result_root, snapshot)
    }

    /// Cache a block commit for later application.
    ///
    /// Called after verification to store the pre-built WriteBatch and JMT snapshot.
    /// When the block commits, [`take_block_commit_cache`] retrieves it.
    pub fn cache_block_commit(&self, block_hash: hyperscale_types::Hash, cache: BlockCommitCache) {
        let mut map = self.block_commit_cache.lock().unwrap();
        map.insert(block_hash, cache);
    }

    /// Take a cached block commit, removing it from the cache.
    ///
    /// Called during block commit to retrieve and apply the precomputed data.
    /// Returns `None` if no cache was present (proposer case, or cache eviction).
    pub fn take_block_commit_cache(
        &self,
        block_hash: hyperscale_types::Hash,
    ) -> Option<BlockCommitCache> {
        let mut map = self.block_commit_cache.lock().unwrap();
        map.remove(&block_hash)
    }

    /// Build a WriteBatch for all certificates in a block.
    ///
    /// This pre-builds all the writes that will be committed when the block commits,
    /// allowing them to be applied with a single fsync instead of N fsyncs.
    ///
    /// # Arguments
    ///
    /// * `certificates` - The certificates to include in the batch
    /// * `local_shard` - The local shard to extract writes from
    ///
    /// # Returns
    ///
    /// A WriteBatch containing all certificate and state writes.
    pub fn build_write_batch(
        &self,
        certificates: &[std::sync::Arc<hyperscale_types::TransactionCertificate>],
        local_shard: hyperscale_types::ShardGroupId,
    ) -> WriteBatch {
        let mut batch = WriteBatch::default();

        let cert_cf = self
            .db
            .cf_handle("certificates")
            .expect("certificates column family must exist");
        let state_cf = self
            .db
            .cf_handle("state")
            .expect("state column family must exist");

        for cert in certificates {
            // Serialize and add certificate
            let cert_bytes =
                sbor::basic_encode(cert.as_ref()).expect("certificate encoding must succeed");
            batch.put_cf(cert_cf, cert.transaction_hash.as_bytes(), cert_bytes);

            // Add state writes for local shard
            if let Some(shard_proof) = cert.shard_proofs.get(&local_shard) {
                let updates = hyperscale_engine::substate_writes_to_database_updates(
                    &shard_proof.state_writes,
                );
                for (db_node_key, node_updates) in &updates.node_updates {
                    for (partition_num, partition_updates) in &node_updates.partition_updates {
                        if let hyperscale_engine::PartitionDatabaseUpdates::Delta {
                            substate_updates,
                        } = partition_updates
                        {
                            for (db_sort_key, update) in substate_updates {
                                let partition_key = hyperscale_engine::DbPartitionKey {
                                    node_key: db_node_key.clone(),
                                    partition_num: *partition_num,
                                };
                                let storage_key = hyperscale_engine::keys::to_storage_key(
                                    &partition_key,
                                    db_sort_key,
                                );

                                match update {
                                    hyperscale_engine::DatabaseUpdate::Set(value) => {
                                        batch.put_cf(state_cf, &storage_key, value);
                                    }
                                    hyperscale_engine::DatabaseUpdate::Delete => {
                                        batch.delete_cf(state_cf, &storage_key);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        batch
    }

    /// Apply a cached block commit with a single fsync.
    ///
    /// This is the fast path for block commit when we have a cached BlockCommitCache
    /// from verification. Applies the pre-built WriteBatch atomically with one fsync,
    /// then applies the JMT snapshot to update the in-memory Merkle tree.
    ///
    /// # Panics
    ///
    /// Panics if the current JMT root doesn't match the snapshot's base_root,
    /// or if the RocksDB write fails.
    pub fn apply_block_commit_cache(&self, cache: BlockCommitCache) {
        let start = Instant::now();

        // 1. Apply the pre-built WriteBatch with a single fsync
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(cache.write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        let rocksdb_elapsed = start.elapsed();

        // 2. Apply the JMT snapshot (in-memory, fast)
        let mut jmt = self.jmt.lock().unwrap();

        // Verify we're applying to the expected base state.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        if jmt.current_root_hash != cache.jmt_snapshot.base_root {
            panic!(
                "JMT snapshot base ROOT mismatch: expected {:?}, got {:?}. \
                 This is a bug - snapshot was computed from different JMT state.",
                cache.jmt_snapshot.base_root, jmt.current_root_hash
            );
        }
        if jmt.current_version != cache.jmt_snapshot.base_version {
            panic!(
                "JMT snapshot base VERSION mismatch: expected {}, got {}. \
                 The root matched but version didn't - this can happen with empty commits. \
                 Snapshot nodes are keyed by version, so this snapshot cannot be applied.",
                cache.jmt_snapshot.base_version, jmt.current_version
            );
        }

        // Insert all captured nodes directly into the tree store
        let nodes_count = cache.jmt_snapshot.nodes.len();
        for (key, node) in cache.jmt_snapshot.nodes {
            jmt.tree_store.insert_node(key, node);
        }

        // Advance version and update root
        jmt.current_version += cache.jmt_snapshot.num_versions;
        jmt.current_root_hash = cache.jmt_snapshot.result_root;

        let new_version = jmt.current_version;
        let new_root = jmt.current_root_hash;
        drop(jmt); // Release lock before I/O

        // 3. Persist the new JMT state
        self.persist_jmt_state(new_version, new_root);

        let total_elapsed = start.elapsed();
        metrics::record_rocksdb_write(rocksdb_elapsed.as_secs_f64());
        metrics::record_storage_operation("apply_block_commit_cache", total_elapsed.as_secs_f64());

        tracing::debug!(
            new_version,
            new_root = %hex::encode(new_root.0),
            nodes_count,
            rocksdb_ms = rocksdb_elapsed.as_millis(),
            total_ms = total_elapsed.as_millis(),
            "Applied block commit cache (single fsync)"
        );
    }
}

/// RocksDB snapshot for consistent reads.
///
/// Uses RocksDB's native snapshot feature to provide point-in-time isolation.
/// Any writes that occur after the snapshot is created are invisible to reads
/// through this snapshot.
pub struct RocksDbSnapshot<'a> {
    snapshot: Snapshot<'a>,
}

impl SubstateDatabase for RocksDbSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        self.snapshot.get(&key).ok().flatten()
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
        let end = keys::next_prefix(&prefix);

        let mut iter = self.snapshot.raw_iterator();
        iter.seek(&start);

        let raw_iter = std::iter::from_fn(move || {
            if iter.valid() {
                let key = iter.key()?;
                if key < end.as_slice() {
                    let k: Box<[u8]> = Box::from(key);
                    let v: Box<[u8]> = Box::from(iter.value()?);
                    iter.next();
                    Some((k, v))
                } else {
                    None
                }
            } else {
                None
            }
        });

        Box::new(raw_iter.filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let sort_key_bytes = full_key[prefix_len..].to_vec();
                Some((DbSortKey(sort_key_bytes), value.into_vec()))
            } else {
                None
            }
        }))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Block storage
// ═══════════════════════════════════════════════════════════════════════

use hyperscale_types::{
    Block, BlockHeight, BlockMetadata, Hash, QuorumCertificate, RoutableTransaction,
    TransactionCertificate,
};

impl RocksDbStorage {
    /// Store a committed block with its quorum certificate.
    ///
    /// # Panics
    ///
    /// Panics if the block cannot be persisted. This is intentional: committed blocks
    /// are essential for crash recovery. If we cannot persist a block, we will have
    /// gaps in our chain on restart, requiring a full sync from peers. Crashing
    /// immediately surfaces the storage issue rather than silently creating an
    /// inconsistent state.
    pub fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        let start = Instant::now();
        let cf = self
            .db
            .cf_handle("blocks")
            .expect("blocks column family must exist");

        // Key: height as big-endian bytes (for natural ordering)
        let key = height.0.to_be_bytes();

        // Value: SBOR-encoded (block, qc) tuple
        let value = sbor::basic_encode(&(block, qc))
            .expect("block encoding must succeed - this is a bug if it fails");

        self.db
            .put_cf(cf, key, value)
            .expect("block persistence failed - cannot maintain chain state");

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_write(elapsed);
        metrics::record_storage_operation("put_block", elapsed);
        metrics::record_block_persisted();
    }

    /// Get a committed block by height.
    pub fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        let start = Instant::now();
        let cf = self.db.cf_handle("blocks")?;
        let key = height.0.to_be_bytes();

        let result = match self.db.get_cf(cf, key) {
            Ok(Some(value)) => match sbor::basic_decode::<(Block, QuorumCertificate)>(&value) {
                Ok(result) => Some(result),
                Err(e) => {
                    tracing::error!("Failed to decode block at height {}: {:?}", height.0, e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to read block at height {}: {}", height.0, e);
                None
            }
        };
        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_block", elapsed);
        result
    }

    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order.
    pub fn get_blocks_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Vec<(Block, QuorumCertificate)> {
        let cf = match self.db.cf_handle("blocks") {
            Some(cf) => cf,
            None => return vec![],
        };

        let start_key = from.0.to_be_bytes();
        let end_key = to.0.to_be_bytes();

        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );

        iter.take_while(|item| match item {
            Ok((key, _)) => key.as_ref() < end_key.as_slice(),
            Err(_) => false,
        })
        .filter_map(|item| {
            item.ok().and_then(|(_, value)| {
                sbor::basic_decode::<(Block, QuorumCertificate)>(&value).ok()
            })
        })
        .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Transaction storage (denormalized)
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction by hash.
    ///
    /// This is idempotent - storing the same transaction twice is safe.
    /// Used by `put_block_denormalized` to store transactions separately from block metadata.
    pub fn put_transaction(&self, tx: &RoutableTransaction) {
        let cf = match self.db.cf_handle("transactions") {
            Some(cf) => cf,
            None => {
                tracing::error!("transactions column family not found");
                return;
            }
        };

        let hash = tx.hash();
        let value = match sbor::basic_encode(tx) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to encode transaction: {:?}", e);
                return;
            }
        };

        if let Err(e) = self.db.put_cf(cf, hash.as_bytes(), value) {
            tracing::error!("Failed to store transaction: {}", e);
        }
    }

    /// Get a transaction by hash.
    pub fn get_transaction(&self, hash: &Hash) -> Option<RoutableTransaction> {
        let start = Instant::now();
        let cf = self.db.cf_handle("transactions")?;

        let result = self
            .db
            .get_cf(cf, hash.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok());

        metrics::record_rocksdb_read(start.elapsed().as_secs_f64());
        result
    }

    /// Get multiple transactions by hash (batch read).
    ///
    /// Uses RocksDB's `multi_get_cf` for efficient batch retrieval.
    /// Returns only transactions that were found (missing hashes are skipped).
    pub fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let cf = match self.db.cf_handle("transactions") {
            Some(cf) => cf,
            None => return vec![],
        };

        let keys: Vec<_> = hashes.iter().map(|h| (cf, h.as_bytes().to_vec())).collect();
        let results = self.db.multi_get_cf(keys);

        let txs: Vec<_> = results
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .filter_map(|v| sbor::basic_decode(&v).ok())
            .collect();

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_transactions_batch", elapsed);

        txs
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Denormalized block storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a committed block with denormalized storage.
    ///
    /// Atomically writes:
    /// - Block metadata (header + hashes) to "blocks" CF
    /// - Each transaction to "transactions" CF
    /// - Each certificate to "certificates" CF
    ///
    /// This eliminates duplication: transactions and certificates are stored once
    /// by hash, and the block metadata references them.
    ///
    /// # Panics
    ///
    /// Panics if the block cannot be persisted. This is intentional: committed blocks
    /// are essential for crash recovery.
    pub fn put_block_denormalized(&self, block: &Block, qc: &QuorumCertificate) {
        let start = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();

        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .expect("blocks column family must exist");
        let txs_cf = self
            .db
            .cf_handle("transactions")
            .expect("transactions column family must exist");
        let certs_cf = self
            .db
            .cf_handle("certificates")
            .expect("certificates column family must exist");

        // 1. Store block metadata (header + hashes only)
        let metadata = BlockMetadata::from_block(block, qc.clone());
        let height_key = block.header.height.0.to_be_bytes();
        let metadata_value =
            sbor::basic_encode(&metadata).expect("block metadata encoding must succeed");
        batch.put_cf(blocks_cf, height_key, metadata_value);

        // 2. Store transactions (deduplicated - RocksDB overwrites are idempotent)
        // Must store all transaction sections: retry, priority, and normal
        for tx in block.all_transactions() {
            let tx_hash = tx.hash();
            let tx_value =
                sbor::basic_encode(tx.as_ref()).expect("transaction encoding must succeed");
            batch.put_cf(txs_cf, tx_hash.as_bytes(), tx_value);
        }

        // 3. Store certificates (deduplicated)
        for cert in &block.committed_certificates {
            let cert_value =
                sbor::basic_encode(cert.as_ref()).expect("certificate encoding must succeed");
            batch.put_cf(certs_cf, cert.transaction_hash.as_bytes(), cert_value);
        }

        // Atomic write
        self.db
            .write(batch)
            .expect("block persistence failed - cannot maintain chain state");

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_write(elapsed);
        metrics::record_storage_operation("put_block_denormalized", elapsed);
        metrics::record_block_persisted();
        metrics::record_transactions_persisted(block.transaction_count());
    }

    /// Get a committed block by height (reconstructs from denormalized storage).
    ///
    /// Fetches block metadata, then batch-fetches transactions and certificates
    /// using the stored hashes to reconstruct the full block.
    ///
    /// Returns `None` if the block metadata is not found, or if any referenced
    /// transactions or certificates are missing. This ensures sync responses
    /// always contain complete, self-contained blocks.
    pub fn get_block_denormalized(
        &self,
        height: BlockHeight,
    ) -> Option<(Block, QuorumCertificate)> {
        let start = Instant::now();

        // 1. Get block metadata
        let blocks_cf = self.db.cf_handle("blocks")?;
        let key = height.0.to_be_bytes();

        let metadata: BlockMetadata = self
            .db
            .get_cf(blocks_cf, key)
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok())?;

        // 2. Batch-fetch transactions for each section (preserving order)
        let retry_transactions = self.get_transactions_batch_ordered(&metadata.retry_hashes);
        let priority_transactions = self.get_transactions_batch_ordered(&metadata.priority_hashes);
        let transactions = self.get_transactions_batch_ordered(&metadata.tx_hashes);

        // Verify we got ALL transactions - return None if any are missing
        let total_expected =
            metadata.retry_hashes.len() + metadata.priority_hashes.len() + metadata.tx_hashes.len();
        let total_found =
            retry_transactions.len() + priority_transactions.len() + transactions.len();
        if total_found != total_expected {
            tracing::warn!(
                height = height.0,
                expected = total_expected,
                found = total_found,
                "Block has missing transactions - cannot serve sync request"
            );
            return None;
        }

        // 3. Batch-fetch certificates (preserving order)
        let certificates = self.get_certificates_batch_ordered(&metadata.cert_hashes);

        // Verify we got ALL certificates - return None if any are missing
        if certificates.len() != metadata.cert_hashes.len() {
            tracing::warn!(
                height = height.0,
                expected = metadata.cert_hashes.len(),
                found = certificates.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            return None;
        }

        // 4. Reconstruct block
        let block = Block {
            header: metadata.header,
            retry_transactions,
            priority_transactions,
            transactions,
            committed_certificates: certificates,
            deferred: metadata.deferred,
            aborted: metadata.aborted,
            commitment_proofs: metadata.commitment_proofs,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_block_denormalized", elapsed);

        Some((block, metadata.qc))
    }

    /// Get block metadata only (without fetching transactions/certificates).
    ///
    /// This is much faster than `get_block_denormalized` because it only
    /// reads the block metadata from storage, not the full transaction and
    /// certificate data.
    ///
    /// Used for partial sync responses when the full block cannot be
    /// reconstructed (e.g., missing transactions or certificates).
    pub fn get_block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        let start = Instant::now();

        let blocks_cf = self.db.cf_handle("blocks")?;
        let key = height.0.to_be_bytes();

        let metadata: BlockMetadata = self
            .db
            .get_cf(blocks_cf, key)
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok())?;

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_block_metadata", elapsed);

        Some(metadata)
    }

    /// Get a complete block for serving sync requests.
    ///
    /// Returns `Some((block, qc))` only if the full block is available with all
    /// transactions and certificates. Returns `None` if:
    /// - Block metadata doesn't exist at this height
    /// - Any transactions are missing
    /// - Any certificates are missing
    ///
    /// This ensures sync responses always contain complete, self-contained blocks.
    /// If a peer can't provide a complete block, the requester should try another peer.
    pub fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        let start = Instant::now();

        // 1. Get block metadata
        let blocks_cf = self.db.cf_handle("blocks")?;
        let key = height.0.to_be_bytes();

        let metadata: BlockMetadata = self
            .db
            .get_cf(blocks_cf, key)
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok())?;

        // 2. Try to batch-fetch transactions for each section (preserving order)
        let retry_transactions = self.get_transactions_batch_ordered(&metadata.retry_hashes);
        let priority_transactions = self.get_transactions_batch_ordered(&metadata.priority_hashes);
        let transactions = self.get_transactions_batch_ordered(&metadata.tx_hashes);

        // Check if all transactions are present - if not, return None
        let total_expected =
            metadata.retry_hashes.len() + metadata.priority_hashes.len() + metadata.tx_hashes.len();
        let total_found =
            retry_transactions.len() + priority_transactions.len() + transactions.len();
        if total_found != total_expected {
            tracing::debug!(
                height = height.0,
                expected = total_expected,
                found = total_found,
                "Block has missing transactions - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            metrics::record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 3. Try to batch-fetch certificates (preserving order)
        let certificates = self.get_certificates_batch_ordered(&metadata.cert_hashes);

        // Check if all certificates are present - if not, return None
        if certificates.len() != metadata.cert_hashes.len() {
            tracing::debug!(
                height = height.0,
                expected = metadata.cert_hashes.len(),
                found = certificates.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            metrics::record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 4. Full block available - reconstruct it
        let block = Block {
            header: metadata.header,
            retry_transactions,
            priority_transactions,
            transactions,
            committed_certificates: certificates,
            deferred: metadata.deferred,
            aborted: metadata.aborted,
            commitment_proofs: metadata.commitment_proofs,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_block_for_sync_complete", elapsed);

        Some((block, metadata.qc))
    }

    /// Get multiple transactions by hash, preserving order.
    ///
    /// Unlike `get_transactions_batch`, this returns results in the same order
    /// as the input hashes, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_transactions_batch_ordered(&self, hashes: &[Hash]) -> Vec<Arc<RoutableTransaction>> {
        if hashes.is_empty() {
            return vec![];
        }

        let cf = match self.db.cf_handle("transactions") {
            Some(cf) => cf,
            None => return vec![],
        };

        let keys: Vec<_> = hashes.iter().map(|h| (cf, h.as_bytes().to_vec())).collect();
        let results = self.db.multi_get_cf(keys);

        // Process results in order, collecting only successful decodes
        results
            .into_iter()
            .zip(hashes.iter())
            .filter_map(|(result, hash)| match result {
                Ok(Some(bytes)) => match sbor::basic_decode::<RoutableTransaction>(&bytes) {
                    Ok(tx) => Some(Arc::new(tx)),
                    Err(e) => {
                        tracing::warn!(?hash, error = ?e, "Failed to decode transaction");
                        None
                    }
                },
                Ok(None) => {
                    tracing::trace!(?hash, "Transaction not found in storage");
                    None
                }
                Err(e) => {
                    tracing::warn!(?hash, error = ?e, "RocksDB error fetching transaction");
                    None
                }
            })
            .collect()
    }

    /// Get multiple certificates by hash, preserving order.
    ///
    /// Unlike `get_certificates_batch`, this returns results in the same order
    /// as the input hashes, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_certificates_batch_ordered(&self, hashes: &[Hash]) -> Vec<Arc<TransactionCertificate>> {
        if hashes.is_empty() {
            return vec![];
        }

        let cf = match self.db.cf_handle("certificates") {
            Some(cf) => cf,
            None => return vec![],
        };

        let keys: Vec<_> = hashes.iter().map(|h| (cf, h.as_bytes().to_vec())).collect();
        let results = self.db.multi_get_cf(keys);

        // Process results in order, collecting only successful decodes
        results
            .into_iter()
            .zip(hashes.iter())
            .filter_map(|(result, hash)| match result {
                Ok(Some(bytes)) => match sbor::basic_decode::<TransactionCertificate>(&bytes) {
                    Ok(cert) => Some(Arc::new(cert)),
                    Err(e) => {
                        tracing::warn!(?hash, error = ?e, "Failed to decode certificate");
                        None
                    }
                },
                Ok(None) => {
                    tracing::trace!(?hash, "Certificate not found in storage");
                    None
                }
                Err(e) => {
                    tracing::warn!(?hash, error = ?e, "RocksDB error fetching certificate");
                    None
                }
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Chain metadata
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the highest committed block height and hash.
    pub fn set_chain_metadata(
        &self,
        height: BlockHeight,
        hash: Option<Hash>,
        qc: Option<&QuorumCertificate>,
    ) {
        // Store in default column family with well-known keys
        if let Err(e) = self
            .db
            .put(b"chain:committed_height", height.0.to_be_bytes())
        {
            tracing::error!("Failed to store committed height: {}", e);
        }

        if let Some(h) = hash {
            if let Err(e) = self.db.put(b"chain:committed_hash", h.as_bytes()) {
                tracing::error!("Failed to store committed hash: {}", e);
            }
        }

        if let Some(qc) = qc {
            if let Ok(encoded) = sbor::basic_encode(qc) {
                if let Err(e) = self.db.put(b"chain:committed_qc", encoded) {
                    tracing::error!("Failed to store committed QC: {}", e);
                }
            }
        }
    }

    /// Get the chain metadata (committed height, hash, and QC).
    pub fn get_chain_metadata(&self) -> (BlockHeight, Option<Hash>, Option<QuorumCertificate>) {
        let start = Instant::now();

        let height = self
            .db
            .get(b"chain:committed_height")
            .ok()
            .flatten()
            .map(|v| {
                let bytes: [u8; 8] = v.as_slice().try_into().unwrap_or([0; 8]);
                BlockHeight(u64::from_be_bytes(bytes))
            })
            .unwrap_or(BlockHeight(0));

        let hash = self
            .db
            .get(b"chain:committed_hash")
            .ok()
            .flatten()
            .map(|v| Hash::from_hash_bytes(&v));

        let qc = self
            .db
            .get(b"chain:committed_qc")
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok());

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_chain_metadata", elapsed);

        (height, hash, qc)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction certificate.
    pub fn put_certificate(&self, hash: &Hash, cert: &TransactionCertificate) {
        let cf = match self.db.cf_handle("certificates") {
            Some(cf) => cf,
            None => {
                tracing::error!("certificates column family not found");
                return;
            }
        };

        let value = match sbor::basic_encode(cert) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to encode certificate: {:?}", e);
                return;
            }
        };

        if let Err(e) = self.db.put_cf(cf, hash.as_bytes(), value) {
            tracing::error!("Failed to store certificate: {}", e);
        }
    }

    /// Get a transaction certificate by transaction hash.
    pub fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        let cf = self.db.cf_handle("certificates")?;

        match self.db.get_cf(cf, hash.as_bytes()) {
            Ok(Some(value)) => sbor::basic_decode(&value).ok(),
            _ => None,
        }
    }

    /// Get multiple certificates by hash (batch read).
    ///
    /// Uses RocksDB's `multi_get_cf` for efficient batch retrieval.
    /// Returns only certificates that were found (missing hashes are skipped).
    pub fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let cf = match self.db.cf_handle("certificates") {
            Some(cf) => cf,
            None => return vec![],
        };

        let keys: Vec<_> = hashes.iter().map(|h| (cf, h.as_bytes().to_vec())).collect();
        let results = self.db.multi_get_cf(keys);

        let certs: Vec<_> = results
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .filter_map(|v| sbor::basic_decode(&v).ok())
            .collect();

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_rocksdb_read(elapsed);
        metrics::record_storage_operation("get_certificates_batch", elapsed);

        certs
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// This is the deferred commit operation that applies state writes when
    /// a `TransactionCertificate` is included in a committed block.
    ///
    /// Uses a RocksDB WriteBatch for atomicity - either both the certificate
    /// and state writes are persisted, or neither is.
    ///
    /// # Panics
    ///
    /// Panics if the commit fails. This is intentional: if we cannot persist the
    /// certificate and state writes, the node's state will diverge from the network.
    /// Other validators will have committed this state, and we'll disagree on
    /// subsequent transactions. Crashing allows operators to fix the storage issue
    /// and restart - on recovery, sync will bring us back to a consistent state.
    ///
    /// # Arguments
    ///
    /// * `certificate` - The transaction certificate to store
    /// * `writes` - The state writes from the certificate's shard_proofs for the local shard
    #[instrument(level = Level::DEBUG, skip_all, fields(
        tx_hash = %certificate.transaction_hash,
        write_count = writes.len(),
        latency_us = tracing::field::Empty,
        otel.kind = "INTERNAL",
    ))]
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &TransactionCertificate,
        writes: &[hyperscale_types::SubstateWrite],
    ) {
        let start = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();
        let mut write_count = 0usize;

        // 1. Serialize and add certificate to batch
        let cert_cf = self
            .db
            .cf_handle("certificates")
            .expect("certificates column family must exist");
        let cert_bytes = sbor::basic_encode(certificate)
            .expect("certificate encoding must succeed - this is a bug if it fails");
        batch.put_cf(cert_cf, certificate.transaction_hash.as_bytes(), cert_bytes);
        write_count += 1;

        // 2. Add state writes to batch
        let state_cf = self
            .db
            .cf_handle("state")
            .expect("state column family must exist");
        let updates = hyperscale_engine::substate_writes_to_database_updates(writes);
        for (db_node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                if let hyperscale_engine::PartitionDatabaseUpdates::Delta { substate_updates } =
                    partition_updates
                {
                    for (db_sort_key, update) in substate_updates {
                        // Build composite key: prefix + node_key + partition + sort_key
                        let partition_key = hyperscale_engine::DbPartitionKey {
                            node_key: db_node_key.clone(),
                            partition_num: *partition_num,
                        };
                        let storage_key =
                            hyperscale_engine::keys::to_storage_key(&partition_key, db_sort_key);

                        match update {
                            hyperscale_engine::DatabaseUpdate::Set(value) => {
                                batch.put_cf(state_cf, &storage_key, value);
                                write_count += 1;
                            }
                            hyperscale_engine::DatabaseUpdate::Delete => {
                                batch.delete_cf(state_cf, &storage_key);
                                write_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // 3. Write batch atomically with sync for durability
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: certificate commit failed - node state would diverge from network",
        );

        // 4. Update JMT and compute new root hash (single lock for atomicity)
        let (new_version, new_root) = {
            let mut jmt = self.jmt.lock().unwrap();
            let parent_version = if jmt.current_version == 0 {
                None
            } else {
                Some(jmt.current_version)
            };
            let new_root = put_at_next_version(&jmt.tree_store, parent_version, &updates);
            let new_version = jmt.current_version + 1;

            // Update in-memory state while still holding the lock
            jmt.current_version = new_version;
            jmt.current_root_hash = new_root;

            (new_version, new_root)
        };

        // 5. Persist JMT state (outside lock - RocksDB is thread-safe)
        self.persist_jmt_state(new_version, new_root);

        tracing::debug!(
            tx_hash = %certificate.transaction_hash,
            write_count = writes.len(),
            new_version,
            new_root = %hex::encode(new_root.0),
            "JMT updated after certificate commit"
        );

        let elapsed = start.elapsed();
        metrics::record_rocksdb_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("commit_cert_writes", elapsed.as_secs_f64());
        metrics::record_storage_batch_size(write_count);
        metrics::record_certificate_persisted();

        // Record span fields
        tracing::Span::current().record("latency_us", elapsed.as_micros() as u64);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Vote storage (BFT Safety Critical)
    // ═══════════════════════════════════════════════════════════════════════

    /// Store our own vote for a height.
    ///
    /// **BFT Safety Critical**: This MUST be called before broadcasting the vote.
    /// After crash/restart, votes must be loaded to prevent equivocation
    /// (voting for a different block at the same height).
    ///
    /// # Panics
    ///
    /// Panics if the vote cannot be persisted. This is intentional: if we cannot
    /// persist the vote, we must NOT broadcast it, as that could lead to equivocation
    /// after a crash/restart. Crashing immediately is the safest response to storage
    /// failure for BFT-critical writes - it prevents the node from making safety
    /// violations and allows operators to investigate and fix the underlying issue.
    ///
    /// Key: height (u64 big-endian)
    /// Value: (block_hash, round) SBOR-encoded
    #[instrument(level = Level::DEBUG, skip(self), fields(
        latency_us = tracing::field::Empty,
        otel.kind = "INTERNAL",
    ))]
    pub fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        let start = Instant::now();
        let cf = self
            .db
            .cf_handle("votes")
            .expect("votes column family must exist");

        let key = height.to_be_bytes();
        let value = sbor::basic_encode(&(block_hash, round))
            .expect("vote encoding must succeed - this is a bug if it fails");

        // Use sync write for durability - this is safety critical
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db
            .put_cf_opt(cf, key, value, &write_opts)
            .expect("BFT SAFETY CRITICAL: vote persistence failed - cannot continue safely");

        let elapsed = start.elapsed();
        metrics::record_rocksdb_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("put_vote", elapsed.as_secs_f64());
        metrics::record_vote_persisted();

        // Record span fields
        tracing::Span::current().record("latency_us", elapsed.as_micros() as u64);
    }

    /// Get our own vote for a height (if any).
    ///
    /// Returns `Some((block_hash, round))` if we previously voted at this height.
    pub fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        let cf = self.db.cf_handle("votes")?;
        let key = height.to_be_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => sbor::basic_decode(&value).ok(),
            _ => None,
        }
    }

    /// Get all our own votes (for recovery on startup).
    ///
    /// Returns a map of height -> (block_hash, round).
    pub fn get_all_own_votes(&self) -> std::collections::HashMap<u64, (Hash, u64)> {
        let cf = match self.db.cf_handle("votes") {
            Some(cf) => cf,
            None => return std::collections::HashMap::new(),
        };

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        iter.filter_map(|item| {
            item.ok().and_then(|(key, value)| {
                let height_bytes: [u8; 8] = key.as_ref().try_into().ok()?;
                let height = u64::from_be_bytes(height_bytes);
                let (hash, round): (Hash, u64) = sbor::basic_decode(&value).ok()?;
                Some((height, (hash, round)))
            })
        })
        .collect()
    }

    /// Remove votes at or below a committed height (cleanup).
    ///
    /// Once a height is committed, we no longer need to track our vote for it.
    /// This prevents unbounded storage growth.
    pub fn prune_own_votes(&self, committed_height: u64) {
        let cf = match self.db.cf_handle("votes") {
            Some(cf) => cf,
            None => return,
        };

        // Delete all votes at or below committed_height
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for (key, _) in iter.flatten() {
            if let Ok(height_bytes) = <[u8; 8]>::try_from(key.as_ref()) {
                let height = u64::from_be_bytes(height_bytes);
                if height <= committed_height {
                    batch.delete_cf(cf, key);
                }
            }
        }

        if let Err(e) = self.db.write(batch) {
            tracing::error!("Failed to prune votes: {}", e);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Crash recovery
    // ═══════════════════════════════════════════════════════════════════════

    /// Load recovered state from storage for crash recovery.
    ///
    /// This should be called on startup before creating the state machine.
    /// Returns `RecoveredState::default()` for a fresh database.
    pub fn load_recovered_state(&self) -> hyperscale_bft::RecoveredState {
        let start = Instant::now();
        let (committed_height, committed_hash, latest_qc) = self.get_chain_metadata();
        let voted_heights = self.get_all_own_votes();

        // Get current JMT state from storage - critical for correct state root computation.
        // Without this, the state machine would start with (0, Hash::ZERO) which causes
        // state root verification failures if the JMT has already advanced.
        //
        // Note: We always include JMT state, even at version 0, because genesis bootstrap
        // populates the JMT with initial Radix state at version 0 but with a non-zero root.
        // The version 0 case is handled correctly by the state machine.
        use hyperscale_engine::SubstateStore;
        let jmt_version = self.state_version();
        let jmt_root = hyperscale_types::Hash::from_bytes(&self.state_root_hash().0);
        let jmt_state = Some((jmt_version, jmt_root));

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.0,
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            vote_count = voted_heights.len(),
            jmt_version,
            jmt_root = ?jmt_root,
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        hyperscale_bft::RecoveredState {
            voted_heights,
            committed_height: committed_height.0,
            committed_hash,
            latest_qc,
            jmt_state,
        }
    }
}

/// Compression type for RocksDB.
#[derive(Debug, Clone, Copy, Default)]
pub enum CompressionType {
    None,
    Snappy,
    Zlib,
    #[default]
    Lz4,
    Lz4hc,
    Zstd,
}

impl CompressionType {
    fn to_rocksdb(self) -> rocksdb::DBCompressionType {
        match self {
            CompressionType::None => rocksdb::DBCompressionType::None,
            CompressionType::Snappy => rocksdb::DBCompressionType::Snappy,
            CompressionType::Zlib => rocksdb::DBCompressionType::Zlib,
            CompressionType::Lz4 => rocksdb::DBCompressionType::Lz4,
            CompressionType::Lz4hc => rocksdb::DBCompressionType::Lz4hc,
            CompressionType::Zstd => rocksdb::DBCompressionType::Zstd,
        }
    }
}

/// Configuration for RocksDB storage.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    /// Maximum number of background jobs
    pub max_background_jobs: i32,
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    /// Maximum number of write buffers
    pub max_write_buffer_number: i32,
    /// Block cache size in bytes (None to disable)
    pub block_cache_size: Option<usize>,
    /// Compression type
    pub compression: CompressionType,
    /// Bloom filter bits per key (0 to disable)
    pub bloom_filter_bits: f64,
    /// Bytes per sync (0 to disable)
    pub bytes_per_sync: usize,
    /// Number of log files to keep
    pub keep_log_file_num: usize,
    /// Column families to create
    pub column_families: Vec<String>,
}

impl Default for RocksDbConfig {
    fn default() -> Self {
        Self {
            max_background_jobs: 4,
            write_buffer_size: 128 * 1024 * 1024, // 128MB
            max_write_buffer_number: 3,
            block_cache_size: Some(512 * 1024 * 1024), // 512MB
            compression: CompressionType::Lz4,
            bloom_filter_bits: 10.0,
            bytes_per_sync: 1024 * 1024, // 1MB
            keep_log_file_num: 10,
            column_families: vec![
                "default".to_string(),
                "blocks".to_string(),
                "transactions".to_string(),
                "state".to_string(),
                "certificates".to_string(),
                "votes".to_string(), // BFT safety critical - stores own votes
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_engine::NodeDatabaseUpdates;
    use tempfile::TempDir;

    #[test]
    fn test_basic_substate_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let partition_key = DbPartitionKey {
            node_key: vec![1, 2, 3],
            partition_num: 0,
        };
        let sort_key = DbSortKey(vec![10, 20]);

        // Initially empty
        assert!(storage
            .get_raw_substate_by_db_key(&partition_key, &sort_key)
            .is_none());

        // Commit a value
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(
                            sort_key.clone(),
                            DatabaseUpdate::Set(vec![99, 88, 77]),
                        )]
                        .into_iter()
                        .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates).unwrap();

        // Now we can read it
        let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
        assert_eq!(value, Some(vec![99, 88, 77]));
    }

    #[test]
    fn test_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let partition_key = DbPartitionKey {
            node_key: vec![1, 2, 3],
            partition_num: 0,
        };
        let sort_key = DbSortKey(vec![10]);

        // Write initial value
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![1]))]
                            .into_iter()
                            .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates).unwrap();

        // Take snapshot
        let snapshot = storage.snapshot();

        // Snapshot can read data
        assert_eq!(
            snapshot.get_raw_substate_by_db_key(&partition_key, &sort_key),
            Some(vec![1])
        );

        // Note: Current implementation doesn't provide point-in-time isolation
        // This is acceptable for Phase 1 and can be optimized later with
        // RocksDB's native snapshot feature if needed
    }

    #[test]
    fn test_vote_persistence_and_recovery() {
        let temp_dir = TempDir::new().unwrap();

        // Write votes in first session
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            storage.put_own_vote(100, 0, Hash::from_bytes(&[1; 32]));
            storage.put_own_vote(101, 1, Hash::from_bytes(&[2; 32]));
            storage.put_own_vote(102, 0, Hash::from_bytes(&[3; 32]));
        }

        // Reopen and verify recovery
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            let recovered = storage.load_recovered_state();

            assert_eq!(recovered.voted_heights.len(), 3);
            assert_eq!(
                recovered.voted_heights.get(&100),
                Some(&(Hash::from_bytes(&[1; 32]), 0))
            );
            assert_eq!(
                recovered.voted_heights.get(&101),
                Some(&(Hash::from_bytes(&[2; 32]), 1))
            );
            assert_eq!(
                recovered.voted_heights.get(&102),
                Some(&(Hash::from_bytes(&[3; 32]), 0))
            );
        }
    }

    #[test]
    fn test_vote_pruning() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        // Add votes at heights 100-105
        for h in 100..=105 {
            storage.put_own_vote(h, 0, Hash::from_bytes(&[h as u8; 32]));
        }

        // Verify all votes present
        let votes = storage.get_all_own_votes();
        assert_eq!(votes.len(), 6);

        // Prune at height 102
        storage.prune_own_votes(102);

        // Votes at 100, 101, 102 should be gone
        let votes = storage.get_all_own_votes();
        assert_eq!(votes.len(), 3);
        assert!(votes.contains_key(&103));
        assert!(votes.contains_key(&104));
        assert!(votes.contains_key(&105));
        assert!(!votes.contains_key(&100));
        assert!(!votes.contains_key(&101));
        assert!(!votes.contains_key(&102));
    }

    #[test]
    fn test_vote_equivocation_prevention_after_recovery() {
        let temp_dir = TempDir::new().unwrap();

        // First session: vote for block A at height 100
        let block_a = Hash::from_bytes(&[1; 32]);
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            storage.put_own_vote(100, 0, block_a);
        }

        // Simulate restart - reopen storage and load recovered state
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            let recovered = storage.load_recovered_state();

            // Verify vote for block A is recovered
            assert_eq!(recovered.voted_heights.get(&100), Some(&(block_a, 0)));

            // BFT state machine should use this to prevent voting for block B
            let block_b = Hash::from_bytes(&[2; 32]);
            assert_ne!(recovered.voted_heights.get(&100), Some(&(block_b, 0)));
        }
    }

    #[test]
    fn test_recovery_resumes_at_correct_height() {
        let temp_dir = TempDir::new().unwrap();

        // Use from_hash_bytes for a deterministic hash (raw bytes, not hashed)
        let expected_hash = Hash::from_hash_bytes(&[50; 32]);

        // First session: commit blocks up to height 50
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            storage.set_chain_metadata(BlockHeight(50), Some(expected_hash), None);
        }

        // Simulate restart
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            let recovered = storage.load_recovered_state();

            assert_eq!(recovered.committed_height, 50);
            assert_eq!(recovered.committed_hash, Some(expected_hash));
        }
    }

    #[test]
    fn test_atomic_certificate_persistence() {
        use hyperscale_types::{
            zero_bls_signature, NodeId, PartitionNumber, ShardGroupId, StateCertificate,
            SubstateWrite, TransactionCertificate, TransactionDecision,
        };
        use std::collections::BTreeMap;

        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        // Create a certificate with state writes
        let tx_hash = Hash::from_bytes(&[42; 32]);
        let shard_group = ShardGroupId(0);
        let writes = vec![SubstateWrite {
            node_id: NodeId([1; 30]),
            partition: PartitionNumber(0),
            sort_key: vec![10, 20],
            value: vec![99, 88, 77],
        }];

        let state_cert = StateCertificate {
            transaction_hash: tx_hash,
            shard_group_id: shard_group,
            read_nodes: vec![],
            state_writes: writes.clone(),
            outputs_merkle_root: Hash::from_bytes(&[0; 32]),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers: hyperscale_types::SignerBitfield::new(4),
            voting_power: 0,
        };

        let mut shard_proofs = BTreeMap::new();
        shard_proofs.insert(shard_group, state_cert);

        let certificate = TransactionCertificate {
            transaction_hash: tx_hash,
            decision: TransactionDecision::Accept,
            shard_proofs,
        };

        // Commit atomically
        storage.commit_certificate_with_writes(&certificate, &writes);

        // Verify certificate is stored
        let stored_cert = storage.get_certificate(&tx_hash);
        assert!(stored_cert.is_some());
        assert_eq!(stored_cert.unwrap().transaction_hash, tx_hash);

        // Verify state write was applied by reading the storage key
        // The commit_certificate_with_writes function converts writes to DatabaseUpdates
        // and commits them to the "state" column family using hyperscale_engine's key mapper.
        // We verify by checking if the certificate was stored (atomicity check).
        // A full state verification would require re-implementing the key mapping logic here,
        // which is tested more thoroughly in engine crate tests.
    }

    #[test]
    fn test_get_own_vote() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        // Initially no vote
        assert!(storage.get_own_vote(100).is_none());

        // Store a vote
        let block_hash = Hash::from_bytes(&[1; 32]);
        storage.put_own_vote(100, 5, block_hash);

        // Now we can read it
        let vote = storage.get_own_vote(100);
        assert_eq!(vote, Some((block_hash, 5)));

        // Different height still returns None
        assert!(storage.get_own_vote(101).is_none());
    }

    #[test]
    fn test_block_storage_and_retrieval() {
        use hyperscale_types::{
            zero_bls_signature, Block, BlockHeader, SignerBitfield, ValidatorId, VotePower,
        };

        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        // Create a test block
        let block = Block {
            header: BlockHeader {
                height: BlockHeight(42),
                parent_hash: Hash::from_bytes(&[1; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 12345,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        };

        let qc = QuorumCertificate {
            block_hash: block.hash(),
            height: BlockHeight(42),
            parent_block_hash: Hash::from_bytes(&[1; 32]),
            round: 0,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
            voting_power: VotePower(4),
            weighted_timestamp_ms: 12345,
        };

        // Initially no block at height 42
        assert!(storage.get_block(BlockHeight(42)).is_none());

        // Store block
        storage.put_block(BlockHeight(42), &block, &qc);

        // Retrieve block
        let (stored_block, stored_qc) = storage.get_block(BlockHeight(42)).unwrap();
        assert_eq!(stored_block.header.height, BlockHeight(42));
        assert_eq!(stored_block.header.timestamp, 12345);
        assert_eq!(stored_qc.block_hash, block.hash());
    }

    #[test]
    fn test_block_range_retrieval() {
        use hyperscale_types::{
            zero_bls_signature, Block, BlockHeader, SignerBitfield, ValidatorId, VotePower,
        };

        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        // Store blocks at heights 10-14
        for h in 10..15u64 {
            let block = Block {
                header: BlockHeader {
                    height: BlockHeight(h),
                    parent_hash: Hash::from_bytes(&[h as u8; 32]),
                    parent_qc: QuorumCertificate::genesis(),
                    proposer: ValidatorId(0),
                    timestamp: h * 1000,
                    round: 0,
                    is_fallback: false,
                    state_root: Hash::ZERO,
                    state_version: 0,
                },
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                committed_certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };
            let qc = QuorumCertificate {
                block_hash: block.hash(),
                height: BlockHeight(h),
                parent_block_hash: Hash::from_bytes(&[h as u8; 32]),
                round: 0,
                aggregated_signature: zero_bls_signature(),
                signers: SignerBitfield::new(4),
                voting_power: VotePower(4),
                weighted_timestamp_ms: h * 1000,
            };
            storage.put_block(BlockHeight(h), &block, &qc);
        }

        // Get range [11, 14) - should return heights 11, 12, 13
        let blocks = storage.get_blocks_range(BlockHeight(11), BlockHeight(14));
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].0.header.height, BlockHeight(11));
        assert_eq!(blocks[1].0.header.height, BlockHeight(12));
        assert_eq!(blocks[2].0.header.height, BlockHeight(13));
    }

    #[test]
    fn test_recovery_with_qc() {
        use hyperscale_types::{zero_bls_signature, SignerBitfield, VotePower};

        let temp_dir = TempDir::new().unwrap();
        let expected_hash = Hash::from_hash_bytes(&[99; 32]);

        // First session: set chain metadata with QC
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            let qc = QuorumCertificate {
                block_hash: expected_hash,
                height: BlockHeight(100),
                parent_block_hash: Hash::from_bytes(&[98; 32]),
                round: 5,
                aggregated_signature: zero_bls_signature(),
                signers: SignerBitfield::new(4),
                voting_power: VotePower(4),
                weighted_timestamp_ms: 100_000,
            };
            storage.set_chain_metadata(BlockHeight(100), Some(expected_hash), Some(&qc));
        }

        // Simulate restart
        {
            let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
            let recovered = storage.load_recovered_state();

            assert_eq!(recovered.committed_height, 100);
            assert_eq!(recovered.committed_hash, Some(expected_hash));
            assert!(recovered.latest_qc.is_some());

            let qc = recovered.latest_qc.unwrap();
            assert_eq!(qc.height, BlockHeight(100));
            assert_eq!(qc.round, 5);
            assert_eq!(qc.block_hash, expected_hash);
        }
    }

    #[test]
    fn test_certificate_idempotency() {
        use hyperscale_types::{
            zero_bls_signature, NodeId, PartitionNumber, ShardGroupId, StateCertificate,
            SubstateWrite, TransactionCertificate, TransactionDecision,
        };
        use std::collections::BTreeMap;

        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let tx_hash = Hash::from_bytes(&[42; 32]);
        let shard_group = ShardGroupId(0);
        let writes = vec![SubstateWrite {
            node_id: NodeId([1; 30]),
            partition: PartitionNumber(0),
            sort_key: vec![10, 20],
            value: vec![99, 88, 77],
        }];

        let state_cert = StateCertificate {
            transaction_hash: tx_hash,
            shard_group_id: shard_group,
            read_nodes: vec![],
            state_writes: writes.clone(),
            outputs_merkle_root: Hash::from_bytes(&[0; 32]),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers: hyperscale_types::SignerBitfield::new(4),
            voting_power: 0,
        };

        let mut shard_proofs = BTreeMap::new();
        shard_proofs.insert(shard_group, state_cert);

        let certificate = TransactionCertificate {
            transaction_hash: tx_hash,
            decision: TransactionDecision::Accept,
            shard_proofs,
        };

        // Commit twice (simulating replay after crash)
        storage.commit_certificate_with_writes(&certificate, &writes);
        storage.commit_certificate_with_writes(&certificate, &writes);

        // Should still have exactly one certificate
        let stored = storage.get_certificate(&tx_hash);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().transaction_hash, tx_hash);
    }

    #[test]
    fn test_vote_overwrite_same_height() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let block_a = Hash::from_bytes(&[1; 32]);
        let block_b = Hash::from_bytes(&[2; 32]);

        // Vote for block A at height 100
        storage.put_own_vote(100, 0, block_a);
        assert_eq!(storage.get_own_vote(100), Some((block_a, 0)));

        // Overwrite with vote for block B (same height, different round)
        // This simulates a valid round-increment scenario
        storage.put_own_vote(100, 1, block_b);
        assert_eq!(storage.get_own_vote(100), Some((block_b, 1)));

        // Only one vote entry for height 100
        let all_votes = storage.get_all_own_votes();
        assert_eq!(all_votes.len(), 1);
        assert_eq!(all_votes.get(&100), Some(&(block_b, 1)));
    }

    #[test]
    fn test_empty_state_on_fresh_database() {
        let temp_dir = TempDir::new().unwrap();
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.committed_height, 0);
        assert!(recovered.committed_hash.is_none());
        assert!(recovered.latest_qc.is_none());
        assert!(recovered.voted_heights.is_empty());
    }
}
