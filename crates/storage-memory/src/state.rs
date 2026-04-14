//! Shared state types for simulated storage.
//!
//! Contains the internal state structures protected by RwLocks in `SimStorage`.

use crate::tree_store::SimTreeStore;

use hyperscale_storage::{
    keys, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, JvtSnapshot, PartitionDatabaseUpdates,
    StateRootHash,
};
use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, ExecutionMetadata, Hash, LocalReceipt,
    QuorumCertificate, RoutableTransaction, ShardGroupId, WaveCertificate,
};
use im::OrdMap;
use jellyfish_verkle_tree as jvt;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════
// Shared substate + JVT state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// Substate data and JVT state protected by a single RwLock.
///
/// A single lock ensures association resolution can read substate data
/// atomically, avoiding deadlock.
///
/// Using RwLock (instead of Mutex) allows concurrent read access: speculative
/// JVT computations from `prepare_block_commit` take a read lock and can run
/// concurrently with other readers, while commits take a write lock.
pub(crate) struct SharedState {
    /// Radix substate data. `im::OrdMap` for O(1) structural-sharing clones.
    pub data: OrdMap<Vec<u8>, Vec<u8>>,
    pub tree_store: SimTreeStore,
    pub current_block_height: u64,
    pub current_root_hash: StateRootHash,
    /// Leaf-key → substate-value associations for historical queries.
    pub associations: HashMap<jvt::NodeKey, Vec<u8>>,
    /// MVCC versioned substate store: `(storage_key, version) → Option<value>`.
    /// BTreeMap ordering gives prefix scans and version ordering for free.
    /// A `None` value is a tombstone (deleted substate).
    pub versioned_substates: VersionedSubstateStore,
}

impl SharedState {
    pub(crate) fn new() -> Self {
        Self {
            data: OrdMap::new(),
            // Pruning disabled: historical substate reads traverse the JVT at
            // past heights and need old nodes to still exist. In production,
            // RocksDB GC respects `jvt_history_length` (default 256).
            // In simulation, tests are short-lived so retaining all nodes is fine.
            tree_store: SimTreeStore::new(),
            current_block_height: 0,
            current_root_hash: Hash::ZERO,
            versioned_substates: BTreeMap::new(),
            associations: HashMap::new(),
        }
    }

    /// Apply a JVT snapshot directly, inserting precomputed nodes.
    ///
    /// The snapshot's tree nodes are consensus-verified (2f+1 validators
    /// agreed on the resulting state root). We apply unconditionally —
    /// the overlay may have computed from a base state ahead of the
    /// tree store, so base_root mismatches are expected and safe.
    pub(crate) fn apply_jvt_snapshot(&mut self, snapshot: JvtSnapshot) {
        for (jvt_key, jvt_node) in &snapshot.nodes {
            self.tree_store
                .insert(jvt_key.clone(), Arc::clone(jvt_node));
        }
        // NOTE: stale JVT nodes are NOT deleted here. Historical JVT nodes
        // must be retained so that provision fetch (generate_verkle_proofs) can
        // read the tree at past block heights. In production, RocksDB GC handles
        // pruning after `jvt_history_length` blocks (default 256). In simulation,
        // we retain all nodes (tests are short-lived).
        //
        // Previously this deleted stale nodes immediately, causing a race: the
        // delegated FetchAndBroadcastProvision action would run after the next
        // block committed, finding the proof-generation root already pruned.
        for a in snapshot.leaf_substate_associations {
            self.associations.insert(a.tree_node_key, a.substate_value);
        }

        self.current_block_height = snapshot.new_version;
        self.current_root_hash = snapshot.result_root;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Consolidated consensus state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// All consensus-related metadata bundled into a single RwLock.
pub(crate) struct ConsensusState {
    /// Committed blocks indexed by height.
    pub blocks: BTreeMap<BlockHeight, (Block, QuorumCertificate)>,
    /// Committed height.
    pub committed_height: BlockHeight,
    /// Committed block hash.
    pub committed_hash: Option<Hash>,
    /// Latest QC.
    pub committed_qc: Option<QuorumCertificate>,
    /// Transactions indexed by hash.
    pub transactions: HashMap<Hash, RoutableTransaction>,
    /// Wave certificates indexed by identity hash.
    pub certificates: HashMap<Hash, WaveCertificate>,
    /// Local receipts keyed by transaction hash.
    pub local_receipts: HashMap<Hash, Arc<LocalReceipt>>,
    /// Execution output details keyed by transaction hash.
    pub execution_outputs: HashMap<Hash, ExecutionMetadata>,
    /// Insertion height for each receipt, enabling height-based pruning.
    pub receipt_heights: HashMap<Hash, u64>,
    /// Execution certificates keyed by canonical hash.
    pub execution_certs: HashMap<Hash, ExecutionCertificate>,
    /// Index: block_height → set of canonical hashes for that height.
    pub execution_certs_by_height: HashMap<u64, Vec<Hash>>,
    /// Index: block_height → wave_id hashes at that height.
    pub wave_certs_by_height: HashMap<u64, Vec<Hash>>,
    /// Index: tx_hash → wave_id hash of the wave cert that finalized it.
    pub tx_to_wave: HashMap<Hash, Hash>,
    /// Index: tx_hash → vec of (shard_group_id, ec_hash) pairs covering it.
    pub tx_to_ec: HashMap<Hash, Vec<(ShardGroupId, Hash)>>,
}

/// Maximum number of blocks worth of receipts to retain in simulation storage.
const SIM_RECEIPT_RETENTION_BLOCKS: u64 = 1_000;

impl ConsensusState {
    pub(crate) fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            committed_height: BlockHeight(0),
            committed_hash: None,
            committed_qc: None,
            transactions: HashMap::new(),
            certificates: HashMap::new(),
            local_receipts: HashMap::new(),
            execution_outputs: HashMap::new(),
            receipt_heights: HashMap::new(),
            execution_certs: HashMap::new(),
            execution_certs_by_height: HashMap::new(),
            wave_certs_by_height: HashMap::new(),
            tx_to_wave: HashMap::new(),
            tx_to_ec: HashMap::new(),
        }
    }

    /// Prune receipts older than the retention window.
    pub(crate) fn prune_receipts(&mut self, committed_height: u64) {
        let cutoff = committed_height.saturating_sub(SIM_RECEIPT_RETENTION_BLOCKS);
        if cutoff == 0 {
            return;
        }
        self.receipt_heights.retain(|tx_hash, height| {
            if *height <= cutoff {
                self.local_receipts.remove(tx_hash);
                self.execution_outputs.remove(tx_hash);
                false
            } else {
                true
            }
        });
    }
}

/// MVCC versioned substate store type: `(storage_key, version) → Option<value>`.
pub(crate) type VersionedSubstateStore = BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>;

/// Apply database updates to the data OrdMap and optionally the MVCC versioned store.
///
/// When `versioned` is `Some((version, btree))`, also writes each update to the
/// versioned store keyed by `(storage_key, version)`. Deletes are written as
/// `None` (tombstone).
pub(crate) fn apply_updates_to_ordmap(
    data: &mut OrdMap<Vec<u8>, Vec<u8>>,
    updates: &DatabaseUpdates,
    mut versioned: Option<(u64, &mut VersionedSubstateStore)>,
) {
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
                                data.insert(key.clone(), value.clone());
                                if let Some((ver, vs)) = &mut versioned {
                                    vs.insert((key, *ver), Some(value.clone()));
                                }
                            }
                            DatabaseUpdate::Delete => {
                                data.remove(&key);
                                if let Some((ver, vs)) = &mut versioned {
                                    vs.insert((key, *ver), None);
                                }
                            }
                        }
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // Delete all existing in partition using range scan
                    let prefix = keys::partition_prefix(&partition_key);
                    let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

                    let existing_keys: Vec<Vec<u8>> =
                        data.range(prefix..end).map(|(k, _)| k.clone()).collect();

                    for key in existing_keys {
                        data.remove(&key);
                        if let Some((ver, vs)) = &mut versioned {
                            vs.insert((key, *ver), None);
                        }
                    }

                    // Insert new values
                    for (sort_key, value) in new_substate_values {
                        let key = keys::to_storage_key(&partition_key, sort_key);
                        data.insert(key.clone(), value.clone());
                        if let Some((ver, vs)) = &mut versioned {
                            vs.insert((key, *ver), Some(value.clone()));
                        }
                    }
                }
            }
        }
    }
}
