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

use hyperscale_metrics as metrics;
use hyperscale_storage::{
    jmt::{
        encode_key as encode_jmt_key, put_at_next_version, ReadableTreeStore, StaleTreePart,
        StoredTreeNodeKey, TreeNode, VersionedTreeNode,
    },
    keys, CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, JmtSnapshot, OverlayTreeStore, PartitionDatabaseUpdates, PartitionEntry,
    StateRootHash, SubstateDatabase, SubstateLookup, SubstateStore,
};
use hyperscale_types::NodeId;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, Options, Snapshot, WriteBatch, WriteOptions, DB,
};
use sbor::prelude::*;
use std::collections::HashMap;
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
/// - JMT for cryptographic state commitment
///
/// Implements Radix's `SubstateDatabase` and `CommittableSubstateDatabase` directly,
/// plus our `SubstateStore` extension for snapshots, node listing, and JMT state roots.
///
/// JMT tree nodes are persisted in the `jmt_nodes` column family. JMT metadata
/// (version and root hash) is in the default CF under well-known keys and read
/// directly from RocksDB on demand — always hot in the memtable since they're
/// written on every commit.
pub struct RocksDbStorage {
    db: Arc<DB>,

    /// Serializes JMT-mutating commits to prevent interleaved read-modify-write
    /// sequences (e.g., `read_jmt_metadata` + `WriteBatch` write).
    commit_lock: Mutex<()>,

    /// Whether to persist historical substate values for historical queries.
    enable_historical_substate_values: bool,

    /// Number of state versions to retain before garbage collection.
    state_version_history_length: u64,
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

        // Column families - use the same options as the DB for consistency
        let cf_descriptors: Vec<_> = config
            .column_families
            .into_iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(config.compression.to_rocksdb());
                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            commit_lock: Mutex::new(()),
            enable_historical_substate_values: config.enable_historical_substate_values,
            state_version_history_length: config.state_version_history_length,
        })
    }

    /// Check if historical substate values are enabled.
    pub fn is_historical_substate_values_enabled(&self) -> bool {
        self.enable_historical_substate_values
    }

    /// Get the configured state version history length.
    pub fn state_version_history_length(&self) -> u64 {
        self.state_version_history_length
    }

    /// Read JMT version and root hash directly from RocksDB.
    ///
    /// These keys are written on every commit, so they're always hot in the
    /// memtable — this is effectively a hashtable lookup, not a disk read.
    fn read_jmt_metadata(&self) -> (u64, StateRootHash) {
        let version = self
            .db
            .get(b"jmt:version")
            .expect("BFT CRITICAL: failed to read jmt:version")
            .map(|v| {
                u64::from_be_bytes(
                    <[u8; 8]>::try_from(v.as_slice()).expect("jmt:version must be 8 bytes"),
                )
            })
            .unwrap_or(0);

        let root_hash = self
            .db
            .get(b"jmt:root_hash")
            .expect("BFT CRITICAL: failed to read jmt:root_hash")
            .map(|v| {
                StateRootHash(
                    <[u8; 32]>::try_from(v.as_slice()).expect("jmt:root_hash must be 32 bytes"),
                )
            })
            .unwrap_or(StateRootHash([0u8; 32]));

        (version, root_hash)
    }

    /// Append JMT data from a snapshot to a WriteBatch.
    ///
    /// Writes JMT nodes, stale tree parts (for deferred GC), historical
    /// substate associations (if enabled), and JMT metadata (version + root hash).
    ///
    /// This is the write-side complement to `read_jmt_metadata`.
    fn append_jmt_to_batch(
        &self,
        batch: &mut WriteBatch,
        snapshot: &JmtSnapshot,
        new_version: u64,
    ) {
        // JMT nodes
        let jmt_cf = self
            .db
            .cf_handle(JMT_NODES_CF)
            .expect("jmt_nodes column family must exist");
        for (key, node) in &snapshot.nodes {
            let encoded_key = encode_jmt_key(key);
            let encoded_node =
                sbor::basic_encode(&VersionedTreeNode::from_latest_version(node.clone()))
                    .expect("JMT node encoding must succeed");
            batch.put_cf(jmt_cf, encoded_key, encoded_node);
        }

        // Stale parts for deferred GC
        if !snapshot.stale_tree_parts.is_empty() {
            let stale_cf = self
                .db
                .cf_handle(STALE_STATE_HASH_TREE_PARTS_CF)
                .expect("stale_state_hash_tree_parts column family must exist");
            let version_key = new_version.to_be_bytes();
            let encoded_parts = sbor::basic_encode(&snapshot.stale_tree_parts)
                .expect("encoding stale parts must succeed");
            batch.put_cf(stale_cf, version_key, encoded_parts);
        }

        // Historical associations
        if self.enable_historical_substate_values {
            let assoc_cf = self
                .db
                .cf_handle(ASSOCIATED_STATE_TREE_VALUES_CF)
                .expect("associated_state_tree_values column family must exist");
            for assoc in &snapshot.leaf_substate_associations {
                let encoded_key = encode_jmt_key(&assoc.tree_node_key);
                batch.put_cf(assoc_cf, encoded_key, &assoc.substate_value);
            }
        }

        // JMT metadata
        batch.put(b"jmt:version", new_version.to_be_bytes());
        batch.put(b"jmt:root_hash", snapshot.result_root.0);
    }

    /// Internal: iterate over a key range in the state CF.
    fn iter_range<'a>(
        &'a self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a {
        let state_cf = self
            .db
            .cf_handle(STATE_CF)
            .expect("state column family must exist");
        let mut iter = self.db.raw_iterator_cf(state_cf);
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
        let state_cf = self
            .db
            .cf_handle(STATE_CF)
            .expect("state column family must exist");
        let result = self
            .db
            .get_cf(state_cf, &key)
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

/// Column family name for substate data.
const STATE_CF: &str = "state";

/// Column family name for JMT tree nodes.
const JMT_NODES_CF: &str = "jmt_nodes";

/// Column family name for associated state tree values.
/// Used for historical substate queries - maps JMT leaf node keys to substate values.
const ASSOCIATED_STATE_TREE_VALUES_CF: &str = "associated_state_tree_values";

/// Column family name for stale state hash tree parts.
/// Stores stale JMT nodes/subtrees keyed by the version at which they became stale.
/// A background GC process deletes these after the retention window expires.
const STALE_STATE_HASH_TREE_PARTS_CF: &str = "stale_state_hash_tree_parts";

impl ReadableTreeStore for RocksDbStorage {
    fn get_node(&self, key: &StoredTreeNodeKey) -> Option<TreeNode> {
        let cf = self.db.cf_handle(JMT_NODES_CF)?;
        let encoded_key = encode_jmt_key(key);
        self.db
            .get_cf(cf, &encoded_key)
            .expect("RocksDB read failure on jmt_nodes CF")
            .map(|bytes| {
                sbor::basic_decode::<VersionedTreeNode>(&bytes)
                    .unwrap_or_else(|e| panic!("JMT node corruption detected: {e:?}"))
                    .fully_update_and_into_latest_version()
            })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Snapshot-based tree store for concurrent JMT reads
// ═══════════════════════════════════════════════════════════════════════

/// A tree store that reads JMT nodes from a RocksDB snapshot.
///
/// This provides point-in-time isolation for JMT reads: any nodes deleted by
/// concurrent block commits remain visible through this snapshot. This prevents
/// the race condition where speculative JMT computation reads nodes that are
/// being deleted by a concurrent commit.
///
/// # Lifetime
/// The snapshot must outlive all reads through this store. When dropped, the
/// snapshot releases its hold on the RocksDB version, allowing garbage collection.
pub(crate) struct SnapshotTreeStore<'a> {
    /// RocksDB snapshot for point-in-time reads.
    snapshot: Snapshot<'a>,
    /// Reference to the DB for column family handles.
    db: &'a DB,
}

impl<'a> SnapshotTreeStore<'a> {
    /// Create a new snapshot-based tree store.
    ///
    /// Takes a RocksDB snapshot at the current point in time. All reads through
    /// this store will see the database state as of this moment, regardless of
    /// any concurrent writes.
    pub fn new(db: &'a DB) -> Self {
        Self {
            snapshot: db.snapshot(),
            db,
        }
    }

    /// Read a substate value from this snapshot.
    ///
    /// Used by [`OverlayTreeStore`] to look up unchanged substate values when
    /// collecting historical state associations.
    pub fn get_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        let cf = self.db.cf_handle(STATE_CF)?;
        let key = keys::to_storage_key(partition_key, sort_key);
        self.snapshot
            .get_cf(cf, &key)
            .expect("RocksDB snapshot read failure on state CF")
            .map(|v| v.to_vec())
    }

    /// Read the JMT version and root hash from this snapshot.
    ///
    /// This reads the `jmt:version` and `jmt:root_hash` keys from the snapshot,
    /// ensuring the returned version is consistent with the nodes visible through
    /// this snapshot.
    ///
    /// Returns `(version, root_hash)`. For an empty/uninitialized JMT, returns `(0, [0; 32])`.
    pub fn read_jmt_metadata(&self) -> (u64, StateRootHash) {
        let version = self
            .snapshot
            .get(b"jmt:version")
            .expect("BFT CRITICAL: failed to read jmt:version from snapshot")
            .map(|bytes| {
                u64::from_be_bytes(
                    <[u8; 8]>::try_from(bytes.as_slice()).expect("jmt:version must be 8 bytes"),
                )
            })
            .unwrap_or(0);

        let root_hash = self
            .snapshot
            .get(b"jmt:root_hash")
            .expect("BFT CRITICAL: failed to read jmt:root_hash from snapshot")
            .map(|bytes| {
                StateRootHash(
                    <[u8; 32]>::try_from(bytes.as_slice()).expect("jmt:root_hash must be 32 bytes"),
                )
            })
            .unwrap_or(StateRootHash([0u8; 32]));

        (version, root_hash)
    }
}

impl ReadableTreeStore for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &StoredTreeNodeKey) -> Option<TreeNode> {
        let cf = self.db.cf_handle(JMT_NODES_CF)?;
        let encoded_key = encode_jmt_key(key);
        self.snapshot
            .get_cf(cf, &encoded_key)
            .expect("RocksDB snapshot read failure on jmt_nodes CF")
            .map(|bytes| {
                sbor::basic_decode::<VersionedTreeNode>(&bytes)
                    .unwrap_or_else(|e| panic!("JMT node corruption detected: {e:?}"))
                    .fully_update_and_into_latest_version()
            })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Substate lookup for historical JMT associations
// Uses the unified OverlayTreeStore from hyperscale_storage.
// ═══════════════════════════════════════════════════════════════════════

impl SubstateLookup for SnapshotTreeStore<'_> {
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        self.get_substate(partition_key, sort_key)
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
        let _commit_guard = self.commit_lock.lock().unwrap();
        let start = Instant::now();
        let mut batch = WriteBatch::default();
        let mut put_count = 0u64;
        let mut delete_count = 0u64;

        let state_cf = self
            .db
            .cf_handle(STATE_CF)
            .expect("state column family must exist");

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
                                    put_count += 1;
                                }
                                DatabaseUpdate::Delete => {
                                    batch.delete_cf(state_cf, &key);
                                    delete_count += 1;
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        // Delete all existing in partition using a snapshot iterator
                        let prefix = keys::partition_prefix(&partition_key);
                        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

                        let snap = self.db.snapshot();
                        let mut iter = snap.raw_iterator_cf(state_cf);
                        iter.seek(&prefix);
                        while iter.valid() {
                            if let Some(key) = iter.key() {
                                if key >= end.as_slice() {
                                    break;
                                }
                                batch.delete_cf(state_cf, key);
                                delete_count += 1;
                                iter.next();
                            } else {
                                break;
                            }
                        }

                        // Insert new values
                        for (sort_key, value) in new_substate_values {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            batch.put_cf(state_cf, &key, value);
                            put_count += 1;
                        }
                    }
                }
            }
        }

        // Compute JMT updates using a snapshot-based overlay for isolation
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();

        let overlay = if self.enable_historical_substate_values {
            OverlayTreeStore::new(&snapshot_store).with_substate_lookup(&snapshot_store)
        } else {
            OverlayTreeStore::new(&snapshot_store)
        };
        let parent_version = if base_version == 0 {
            None
        } else {
            Some(base_version)
        };
        let new_root = put_at_next_version(&overlay, parent_version, updates);
        let new_version = base_version + 1;
        let jmt_snapshot = overlay.into_snapshot(base_root, base_version, new_root, 1);

        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, new_version);

        // Write everything atomically. No sync needed here — this method is only
        // used for genesis bootstrap via CommittableSubstateDatabase. RocksDB WAL
        // provides crash safety; the subsequent block commit path uses sync writes.
        self.db
            .write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());

        // Record span fields
        let span = tracing::Span::current();
        span.record("latency_us", elapsed.as_micros() as u64);
        tracing::debug!(put_count, delete_count, new_version, "commit complete");

        Ok(())
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
            db: &self.db,
        }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

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
        self.read_jmt_metadata().0
    }

    fn state_root_hash(&self) -> hyperscale_types::Hash {
        let (_, root_hash) = self.read_jmt_metadata();
        hyperscale_types::Hash::from_hash_bytes(&root_hash.0)
    }
}

impl RocksDbStorage {
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
    pub(crate) fn compute_speculative_root_from_base(
        &self,
        expected_base_root: hyperscale_types::Hash,
        updates_per_cert: &[DatabaseUpdates],
    ) -> (hyperscale_types::Hash, JmtSnapshot) {
        // This computation runs on the consensus-crypto thread pool, concurrent with
        // block commits on the tokio runtime threads. Block commits delete stale JMT
        // nodes from RocksDB. Without a snapshot, this computation could read nodes
        // that are deleted mid-computation, causing a panic in the Radix JMT code.
        //
        // The snapshot provides a consistent view of RocksDB at this moment. Even if
        // another thread deletes nodes, our reads through the snapshot still see them.
        // The snapshot is lightweight (just a version marker) and automatically releases
        // when dropped at the end of this function.
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();

        let current_root = hyperscale_types::Hash::from_hash_bytes(&base_root.0);

        // If no certificates, return current root with empty snapshot.
        if updates_per_cert.is_empty() {
            let snapshot = JmtSnapshot {
                base_root,
                base_version,
                result_root: base_root,
                num_versions: 0,
                nodes: HashMap::new(),
                stale_tree_parts: Vec::new(),
                leaf_substate_associations: Vec::new(),
            };
            return (current_root, snapshot);
        }

        // Verify the JMT root matches the expected base root.
        if current_root != expected_base_root {
            tracing::warn!(
                current_root = ?current_root,
                expected_base_root = ?expected_base_root,
                "JMT root mismatch - verification will likely fail"
            );
        }

        // Create overlay, optionally enabling historical value collection
        let overlay = if self.enable_historical_substate_values {
            OverlayTreeStore::new(&snapshot_store).with_substate_lookup(&snapshot_store)
        } else {
            OverlayTreeStore::new(&snapshot_store)
        };

        let mut current_version = base_version;
        let mut root = base_root;
        let num_versions = updates_per_cert.len() as u64;

        for updates in updates_per_cert {
            let parent_version = if current_version == 0 {
                None
            } else {
                Some(current_version)
            };

            root = put_at_next_version(&overlay, parent_version, updates);
            current_version += 1;
        }

        let result_root = hyperscale_types::Hash::from_hash_bytes(&root.0);
        let snapshot = overlay.into_snapshot(base_root, base_version, root, num_versions);

        (result_root, snapshot)
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
    pub(crate) fn build_write_batch(
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
            .cf_handle(STATE_CF)
            .expect("state column family must exist");

        for cert in certificates {
            // Serialize and add certificate
            let cert_bytes =
                sbor::basic_encode(cert.as_ref()).expect("certificate encoding must succeed");
            batch.put_cf(cert_cf, cert.transaction_hash.as_bytes(), cert_bytes);

            // Add state writes for local shard (iterate SubstateWrite directly,
            // avoiding intermediate DatabaseUpdates allocation)
            if let Some(shard_proof) = cert.shard_proofs.get(&local_shard) {
                for write in &shard_proof.state_writes {
                    let storage_key = hyperscale_storage::keys::storage_key_from_write(
                        &write.node_id,
                        &write.partition,
                        &write.sort_key,
                    );
                    batch.put_cf(state_cf, &storage_key, &write.value);
                }
            }
        }

        batch
    }

    /// Try to apply a prepared block commit with a single fsync.
    ///
    /// This is the fast path for block commit. Applies the pre-built WriteBatch
    /// atomically with one fsync, including all JMT nodes from the snapshot.
    ///
    /// Returns `true` if successfully applied (fast path),
    /// or `false` if the JMT state has changed since preparation
    /// (caller should fall back to slow path).
    ///
    /// # Panics
    /// Only panics on unrecoverable errors (RocksDB write failure).
    pub(crate) fn try_apply_prepared_commit(
        &self,
        mut write_batch: WriteBatch,
        jmt_snapshot: JmtSnapshot,
    ) -> bool {
        let _commit_guard = self.commit_lock.lock().unwrap();
        let start = Instant::now();

        // Verify we're applying to the expected base state BEFORE writing anything.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        let (current_version, current_root_hash) = self.read_jmt_metadata();
        if current_root_hash != jmt_snapshot.base_root {
            tracing::warn!(
                expected_root = ?jmt_snapshot.base_root,
                actual_root = ?current_root_hash,
                "JMT snapshot base ROOT mismatch - falling back to slow path"
            );
            return false;
        }
        if current_version != jmt_snapshot.base_version {
            tracing::warn!(
                expected_version = jmt_snapshot.base_version,
                actual_version = current_version,
                "JMT snapshot base VERSION mismatch - falling back to slow path. \
                 This can happen with empty commits or concurrent block processing."
            );
            return false;
        }

        let nodes_count = jmt_snapshot.nodes.len();
        let stale_count = jmt_snapshot.stale_tree_parts.len();
        let associations_count = jmt_snapshot.leaf_substate_associations.len();
        let new_version = jmt_snapshot.base_version + jmt_snapshot.num_versions;
        let new_root = jmt_snapshot.result_root;

        self.append_jmt_to_batch(&mut write_batch, &jmt_snapshot, new_version);

        // Apply everything atomically with a single fsync
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(write_batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: block commit failed - node state would diverge from network",
        );

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("apply_prepared_commit", elapsed.as_secs_f64());

        tracing::debug!(
            new_version,
            new_root = %hex::encode(new_root.0),
            nodes_count,
            stale_count,
            associations_count,
            elapsed_ms = elapsed.as_millis(),
            "Applied prepared commit (single fsync)"
        );

        true
    }
}

/// RocksDB snapshot for consistent reads.
///
/// Uses RocksDB's native snapshot feature to provide point-in-time isolation.
/// Any writes that occur after the snapshot is created are invisible to reads
/// through this snapshot.
pub struct RocksDbSnapshot<'a> {
    snapshot: Snapshot<'a>,
    db: &'a DB,
}

impl SubstateDatabase for RocksDbSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        let state_cf = self.db.cf_handle(STATE_CF)?;
        self.snapshot
            .get_cf(state_cf, &key)
            .expect("RocksDB snapshot read failure on state CF")
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

        let state_cf = self
            .db
            .cf_handle(STATE_CF)
            .expect("state column family must exist");
        let mut iter = self.snapshot.raw_iterator_cf(state_cf);
        iter.seek(&start);

        let mut done = false;
        let raw_iter = std::iter::from_fn(move || {
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
                    panic!("RocksDB snapshot iterator error: {e}");
                }
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
    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order. Uses `get_block_denormalized`
    /// for each height to properly reconstruct blocks from metadata + individual
    /// transaction/certificate entries.
    pub fn get_blocks_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Vec<(Block, QuorumCertificate)> {
        let mut result = Vec::new();
        let mut h = from.0;
        while h < to.0 {
            if let Some(block_qc) = self.get_block_denormalized(BlockHeight(h)) {
                result.push(block_qc);
            }
            h += 1;
        }
        result
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Transaction storage (denormalized)
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction by hash.
    ///
    /// This is idempotent - storing the same transaction twice is safe.
    /// Used by `put_block_denormalized` to store transactions separately from block metadata.
    pub fn put_transaction(&self, tx: &RoutableTransaction) {
        let cf = self
            .db
            .cf_handle("transactions")
            .expect("transactions column family must exist");

        let hash = tx.hash();
        let value = sbor::basic_encode(tx).expect("transaction encoding must succeed");

        self.db
            .put_cf(cf, hash.as_bytes(), value)
            .expect("failed to persist transaction");
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

        metrics::record_storage_read(start.elapsed().as_secs_f64());
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
        metrics::record_storage_read(elapsed);
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
    pub(crate) fn put_block_denormalized(&self, block: &Block, qc: &QuorumCertificate) {
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
        for cert in &block.certificates {
            let cert_value =
                sbor::basic_encode(cert.as_ref()).expect("certificate encoding must succeed");
            batch.put_cf(certs_cf, cert.transaction_hash.as_bytes(), cert_value);
        }

        // Atomic write with sync for crash safety
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("block persistence failed - cannot maintain chain state");

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_write(elapsed);
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
    pub(crate) fn get_block_denormalized(
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
            certificates,
            deferred: metadata.deferred,
            aborted: metadata.aborted,
            commitment_proofs: metadata.commitment_proofs,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
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
        metrics::record_storage_read(elapsed);
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
            certificates,
            deferred: metadata.deferred,
            aborted: metadata.aborted,
            commitment_proofs: metadata.commitment_proofs,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
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
        let mut batch = WriteBatch::default();
        batch.put(b"chain:committed_height", height.0.to_be_bytes());
        if let Some(h) = hash {
            batch.put(b"chain:committed_hash", h.as_bytes());
        }
        if let Some(qc) = qc {
            let encoded = sbor::basic_encode(qc).expect("QC encoding must succeed");
            batch.put(b"chain:committed_qc", encoded);
        }
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.db
            .write_opt(batch, &opts)
            .expect("BFT SAFETY CRITICAL: chain metadata write failed");
    }

    /// Get the chain metadata (committed height, hash, and QC).
    ///
    /// Reads all three chain metadata keys in one call. Use the individual
    /// `read_committed_height`, `read_committed_hash`, `read_latest_qc`
    /// methods when only one value is needed.
    pub fn get_chain_metadata(&self) -> (BlockHeight, Option<Hash>, Option<QuorumCertificate>) {
        let start = Instant::now();

        let height = self.read_committed_height();
        let hash = self.read_committed_hash();
        let qc = self.read_latest_qc();

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_chain_metadata", elapsed);

        (height, hash, qc)
    }

    /// Read only the committed height from RocksDB.
    fn read_committed_height(&self) -> BlockHeight {
        self.db
            .get(b"chain:committed_height")
            .ok()
            .flatten()
            .map(|v| {
                let bytes: [u8; 8] = v.as_slice().try_into().unwrap_or([0; 8]);
                BlockHeight(u64::from_be_bytes(bytes))
            })
            .unwrap_or(BlockHeight(0))
    }

    /// Read only the committed hash from RocksDB.
    fn read_committed_hash(&self) -> Option<Hash> {
        self.db
            .get(b"chain:committed_hash")
            .ok()
            .flatten()
            .map(|v| Hash::from_hash_bytes(&v))
    }

    /// Read only the latest QC from RocksDB.
    fn read_latest_qc(&self) -> Option<QuorumCertificate> {
        self.db
            .get(b"chain:committed_qc")
            .ok()
            .flatten()
            .and_then(|v| sbor::basic_decode(&v).ok())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction certificate.
    pub fn put_certificate(&self, hash: &Hash, cert: &TransactionCertificate) {
        let cf = self
            .db
            .cf_handle("certificates")
            .expect("certificates column family must exist");

        let value = sbor::basic_encode(cert).expect("certificate encoding must succeed");

        self.db
            .put_cf(cf, hash.as_bytes(), value)
            .expect("failed to persist certificate");
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
        metrics::record_storage_read(elapsed);
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
        let _commit_guard = self.commit_lock.lock().unwrap();
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
            .cf_handle(STATE_CF)
            .expect("state column family must exist");
        let updates = hyperscale_storage::substate_writes_to_database_updates(writes);
        for (db_node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                if let hyperscale_storage::PartitionDatabaseUpdates::Delta { substate_updates } =
                    partition_updates
                {
                    for (db_sort_key, update) in substate_updates {
                        // Build composite key: prefix + node_key + partition + sort_key
                        let partition_key = hyperscale_storage::DbPartitionKey {
                            node_key: db_node_key.clone(),
                            partition_num: *partition_num,
                        };
                        let storage_key =
                            hyperscale_storage::keys::to_storage_key(&partition_key, db_sort_key);

                        match update {
                            hyperscale_storage::DatabaseUpdate::Set(value) => {
                                batch.put_cf(state_cf, &storage_key, value);
                                write_count += 1;
                            }
                            hyperscale_storage::DatabaseUpdate::Delete => {
                                batch.delete_cf(state_cf, &storage_key);
                                write_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // 3. Compute JMT updates using a snapshot-based overlay for isolation
        let snapshot_store = SnapshotTreeStore::new(&self.db);
        let (base_version, base_root) = snapshot_store.read_jmt_metadata();

        let overlay = if self.enable_historical_substate_values {
            OverlayTreeStore::new(&snapshot_store).with_substate_lookup(&snapshot_store)
        } else {
            OverlayTreeStore::new(&snapshot_store)
        };
        let parent_version = if base_version == 0 {
            None
        } else {
            Some(base_version)
        };
        let new_root = put_at_next_version(&overlay, parent_version, &updates);
        let new_version = base_version + 1;
        let jmt_snapshot = overlay.into_snapshot(base_root, base_version, new_root, 1);

        // 4. Add JMT data to the batch
        self.append_jmt_to_batch(&mut batch, &jmt_snapshot, new_version);

        // 5. Write batch atomically with sync for durability
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: certificate commit failed - node state would diverge from network",
        );

        tracing::debug!(
            tx_hash = %certificate.transaction_hash,
            write_count = writes.len(),
            new_version,
            new_root = %hex::encode(new_root.0),
            "JMT updated after certificate commit"
        );

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
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
        metrics::record_storage_write(elapsed.as_secs_f64());
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
        use hyperscale_storage::SubstateStore;
        let jmt_version = self.state_version();
        let jmt_root = self.state_root_hash();
        let jmt_state = Some((jmt_version, jmt_root));

        // Recovery invariant: committed_height must not exceed the JMT state.
        // If committed_height is ahead of JMT, a previous run persisted committed
        // metadata before the JMT commit completed (the bug fixed by moving
        // set_committed_state to after JMT commit). Detect and warn so operators
        // can investigate.
        if committed_height.0 > 0 {
            if let Some((block, _qc)) = self.get_block_denormalized(committed_height) {
                let expected_version = block.header.state_version;
                if jmt_version < expected_version {
                    tracing::error!(
                        committed_height = committed_height.0,
                        expected_jmt_version = expected_version,
                        actual_jmt_version = jmt_version,
                        "RECOVERY: committed_height ahead of JMT state — \
                         this node may have been affected by the premature \
                         set_committed_state bug. Manual intervention required."
                    );
                }
            }
        }

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

    // ═══════════════════════════════════════════════════════════════════════
    // JMT Garbage Collection
    // ═══════════════════════════════════════════════════════════════════════

    /// Run garbage collection for stale JMT nodes.
    ///
    /// This deletes JMT nodes (and their associations) that became stale at versions
    /// older than `current_version - state_version_history_length`.
    ///
    /// # When to Call
    ///
    /// Call this periodically (e.g., after each block commit, or on a timer).
    /// It's safe to call concurrently with commits - GC only touches old data
    /// that's no longer reachable from the current state root.
    ///
    /// # Returns
    ///
    /// The number of stale parts entries processed (each entry may contain
    /// multiple nodes/subtrees).
    pub fn run_jmt_gc(&self) -> usize {
        let start = Instant::now();

        let (current_version, _) = self.read_jmt_metadata();

        // Calculate the cutoff version - delete stale parts older than this
        let cutoff_version = current_version.saturating_sub(self.state_version_history_length);

        if cutoff_version == 0 {
            // Nothing to GC yet - we haven't accumulated enough history
            return 0;
        }

        let stale_cf = match self.db.cf_handle(STALE_STATE_HASH_TREE_PARTS_CF) {
            Some(cf) => cf,
            None => return 0,
        };

        let jmt_cf = match self.db.cf_handle(JMT_NODES_CF) {
            Some(cf) => cf,
            None => return 0,
        };

        let assoc_cf = if self.enable_historical_substate_values {
            self.db.cf_handle(ASSOCIATED_STATE_TREE_VALUES_CF)
        } else {
            None
        };

        // Iterate through stale parts older than the cutoff
        let mut iter = self.db.raw_iterator_cf(stale_cf);
        iter.seek_to_first();

        let mut processed_count = 0;
        let mut deleted_nodes = 0;
        let mut batch = WriteBatch::default();

        while iter.valid() {
            let version_key = match iter.key() {
                Some(k) if k.len() == 8 => k,
                _ => {
                    iter.next();
                    continue;
                }
            };

            let version = u64::from_be_bytes(version_key.try_into().unwrap());

            // Stop if we've reached versions we want to keep
            if version >= cutoff_version {
                break;
            }

            // Decode the stale parts
            if let Some(value) = iter.value() {
                if let Ok(stale_parts) = sbor::basic_decode::<Vec<StaleTreePart>>(value) {
                    for stale_part in stale_parts {
                        match stale_part {
                            StaleTreePart::Node(key) => {
                                let encoded_key = encode_jmt_key(&key);
                                batch.delete_cf(jmt_cf, &encoded_key);
                                if let Some(cf) = assoc_cf {
                                    batch.delete_cf(cf, &encoded_key);
                                }
                                deleted_nodes += 1;
                            }
                            StaleTreePart::Subtree(key) => {
                                // For subtrees, we recursively delete all nodes.
                                // This is more expensive but ensures proper cleanup.
                                self.delete_subtree_recursive(
                                    &key,
                                    jmt_cf,
                                    assoc_cf,
                                    &mut batch,
                                    &mut deleted_nodes,
                                );
                            }
                        }
                    }
                }
            }

            // Delete the stale parts entry itself
            batch.delete_cf(stale_cf, version_key);
            processed_count += 1;

            iter.next();
        }

        // Apply all deletions
        if !batch.is_empty() {
            if let Err(e) = self.db.write(batch) {
                tracing::error!("JMT GC write failed: {}", e);
                return 0;
            }
        }

        let elapsed = start.elapsed();
        if processed_count > 0 {
            tracing::debug!(
                processed_count,
                deleted_nodes,
                cutoff_version,
                current_version,
                elapsed_ms = elapsed.as_millis(),
                "JMT GC completed"
            );
        }

        processed_count
    }

    /// Recursively delete a subtree and its associations.
    fn delete_subtree_recursive(
        &self,
        root_key: &StoredTreeNodeKey,
        jmt_cf: &ColumnFamily,
        assoc_cf: Option<&ColumnFamily>,
        batch: &mut WriteBatch,
        deleted_count: &mut usize,
    ) {
        // Read the root node to find its children
        let encoded_key = encode_jmt_key(root_key);
        let node = match self.db.get_cf(jmt_cf, &encoded_key) {
            Ok(Some(bytes)) => {
                match sbor::basic_decode::<VersionedTreeNode>(&bytes) {
                    Ok(versioned) => versioned.fully_update_and_into_latest_version(),
                    Err(_) => {
                        // Can't decode - just delete the root
                        batch.delete_cf(jmt_cf, &encoded_key);
                        if let Some(cf) = assoc_cf {
                            batch.delete_cf(cf, &encoded_key);
                        }
                        *deleted_count += 1;
                        return;
                    }
                }
            }
            _ => {
                // Node doesn't exist (already deleted in a previous GC run)
                return;
            }
        };

        // Process children first (post-order traversal)
        match &node {
            TreeNode::Internal(internal) => {
                for child in &internal.children {
                    let child_key = root_key.gen_child_node_key(child.version, child.nibble);
                    self.delete_subtree_recursive(
                        &child_key,
                        jmt_cf,
                        assoc_cf,
                        batch,
                        deleted_count,
                    );
                }
            }
            TreeNode::Leaf(_) | TreeNode::Null => {
                // Leaf nodes have no children
            }
        }

        // Delete this node
        batch.delete_cf(jmt_cf, &encoded_key);
        if let Some(cf) = assoc_cf {
            batch.delete_cf(cf, &encoded_key);
        }
        *deleted_count += 1;
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
    /// Enable historical substate values storage.
    ///
    /// When enabled, the storage will persist associations between JMT leaf nodes
    /// and their substate values. This enables historical state queries - looking
    /// up substate values at any past state version (within the retention window).
    ///
    /// This adds storage overhead proportional to the number of substates modified.
    /// Defaults to `false` for minimal overhead; enable for Mesh API compatibility
    /// or when historical state queries are needed.
    pub enable_historical_substate_values: bool,

    /// Number of state versions to retain before garbage collection.
    ///
    /// Stale JMT nodes and their associations are kept for this many versions
    /// before being eligible for deletion. This enables historical queries within
    /// this window.
    ///
    /// Set to 0 for immediate deletion (no history retention).
    /// Defaults to 60,000 versions (matching Babylon's default).
    pub state_version_history_length: u64,
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
                "votes".to_string(),     // BFT safety critical - stores own votes
                "jmt_nodes".to_string(), // JMT tree nodes for state commitment
                "associated_state_tree_values".to_string(), // Historical substate values (leaf key -> value)
                "stale_state_hash_tree_parts".to_string(),  // Deferred GC queue for stale JMT nodes
            ],
            enable_historical_substate_values: false, // Disabled by default, like Babylon
            state_version_history_length: 60_000,     // Match Babylon's default
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CommitStore implementation
// ═══════════════════════════════════════════════════════════════════════

use hyperscale_storage::extract_writes_per_cert;

/// Precomputed commit work for a RocksDB block commit.
///
/// Contains a pre-built `WriteBatch` (all certificate + state writes) and a
/// `JmtSnapshot` (precomputed Merkle tree nodes). Also carries the certificates
/// and shard for fallback recompute if the prepared data is stale.
///
/// # Performance
///
/// Without batching: 40 certificates × ~5ms fsync = ~200ms per block commit
/// With batching: 1 fsync = ~5ms per block commit
pub struct RocksDbPreparedCommit {
    write_batch: WriteBatch,
    jmt_snapshot: JmtSnapshot,
    certificates: Vec<Arc<TransactionCertificate>>,
    local_shard: hyperscale_types::ShardGroupId,
}

impl hyperscale_storage::CommitStore for RocksDbStorage {
    type PreparedCommit = RocksDbPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: hyperscale_types::Hash,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: hyperscale_types::ShardGroupId,
    ) -> (hyperscale_types::Hash, Self::PreparedCommit) {
        let writes_per_cert = extract_writes_per_cert(certificates, local_shard);

        // Convert SubstateWrites → DatabaseUpdates once upfront, reuse for JMT.
        let updates_per_cert: Vec<DatabaseUpdates> = writes_per_cert
            .iter()
            .map(|writes| hyperscale_storage::substate_writes_to_database_updates(writes))
            .collect();

        let (computed_root, jmt_snapshot) =
            self.compute_speculative_root_from_base(parent_state_root, &updates_per_cert);

        let write_batch = self.build_write_batch(certificates, local_shard);

        let prepared = RocksDbPreparedCommit {
            write_batch,
            jmt_snapshot,
            certificates: certificates.to_vec(),
            local_shard,
        };

        (computed_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
    ) -> hyperscale_storage::CommitResult {
        let used_fast_path =
            self.try_apply_prepared_commit(prepared.write_batch, prepared.jmt_snapshot);

        if !used_fast_path {
            // Stale cache: fall back to per-certificate recompute
            for cert in &prepared.certificates {
                let writes = cert
                    .shard_proofs
                    .get(&prepared.local_shard)
                    .map(|proof| proof.state_writes.as_slice())
                    .unwrap_or(&[]);
                self.commit_certificate_with_writes(cert, writes);
            }
        }

        use hyperscale_storage::SubstateStore;
        hyperscale_storage::CommitResult {
            state_version: self.state_version(),
            state_root: self.state_root_hash(),
        }
    }

    fn commit_block(
        &self,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: hyperscale_types::ShardGroupId,
    ) -> hyperscale_storage::CommitResult {
        for cert in certificates {
            let writes = cert
                .shard_proofs
                .get(&local_shard)
                .map(|proof| proof.state_writes.as_slice())
                .unwrap_or(&[]);
            self.commit_certificate_with_writes(cert, writes);
        }

        use hyperscale_storage::SubstateStore;
        hyperscale_storage::CommitResult {
            state_version: self.state_version(),
            state_root: self.state_root_hash(),
        }
    }

    fn commit_certificate(
        &self,
        certificate: &TransactionCertificate,
        writes: &[hyperscale_types::SubstateWrite],
    ) {
        self.commit_certificate_with_writes(certificate, writes);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ConsensusStore implementation
// ═══════════════════════════════════════════════════════════════════════

impl hyperscale_storage::ConsensusStore for RocksDbStorage {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        debug_assert_eq!(
            height, block.header.height,
            "height must match block header"
        );
        self.put_block_denormalized(block, qc);
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.get_block_denormalized(height)
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.set_chain_metadata(height, None, None);
    }

    fn committed_height(&self) -> BlockHeight {
        self.read_committed_height()
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        self.set_chain_metadata(height, Some(hash), Some(qc));
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.read_committed_hash()
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.read_latest_qc()
    }

    fn store_certificate(&self, certificate: &TransactionCertificate) {
        self.put_certificate(&certificate.transaction_hash, certificate);
    }

    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        RocksDbStorage::get_certificate(self, hash)
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        RocksDbStorage::put_own_vote(self, height, round, block_hash);
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        RocksDbStorage::get_own_vote(self, height)
    }

    fn get_all_own_votes(&self) -> std::collections::HashMap<u64, (Hash, u64)> {
        RocksDbStorage::get_all_own_votes(self)
    }

    fn prune_own_votes(&self, committed_height: u64) {
        RocksDbStorage::prune_own_votes(self, committed_height);
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        RocksDbStorage::get_block_for_sync(self, height)
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        RocksDbStorage::get_transactions_batch(self, hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        RocksDbStorage::get_certificates_batch(self, hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_storage::{ConsensusStore, NodeDatabaseUpdates};
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
                transaction_root: Hash::ZERO,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
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
                    transaction_root: Hash::ZERO,
                },
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                certificates: vec![],
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
