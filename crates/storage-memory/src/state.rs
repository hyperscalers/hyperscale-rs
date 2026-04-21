//! Shared state types for simulated storage.
//!
//! Contains the internal state structures protected by RwLocks in `SimStorage`.

use crate::tree_store::SimTreeStore;

use hyperscale_jmt as jmt;
use hyperscale_storage::{
    keys, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, JmtSnapshot, PartitionDatabaseUpdates,
    StateRootHash,
};
use hyperscale_types::{
    BlockHeight, CertifiedBlock, ExecutionCertificate, ExecutionMetadata, Hash, LocalReceipt,
    QuorumCertificate, RoutableTransaction, ShardGroupId, WaveCertificate,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════
// Shared substate + JMT state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// Substate data and JMT state protected by a single RwLock.
///
/// A single lock ensures association resolution can read substate data
/// atomically, avoiding deadlock.
///
/// Using RwLock (instead of Mutex) allows concurrent read access: speculative
/// JMT computations from `prepare_block_commit` take a read lock and can run
/// concurrently with other readers, while commits take a write lock.
pub(crate) struct SharedState {
    pub tree_store: SimTreeStore,
    pub current_block_height: u64,
    pub current_root_hash: StateRootHash,
    /// Leaf-key → substate-value associations for historical queries.
    pub associations: HashMap<jmt::NodeKey, Vec<u8>>,
    /// Current value per `storage_key`. Absent key = no value. This is
    /// the authoritative source of truth for reads at the current tip.
    pub current_state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per-write prior-value entries keyed by `(storage_key,
    /// write_version)`. `None` means the key was absent immediately
    /// before the write at that version. Consumed by historical reads
    /// and the retention GC.
    pub state_history: BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>,
}

impl SharedState {
    pub(crate) fn new() -> Self {
        Self {
            // Pruning disabled: historical substate reads traverse the JMT at
            // past heights and need old nodes to still exist. In production,
            // RocksDB GC respects `jmt_history_length` (default 256).
            // In simulation, tests are short-lived so retaining all nodes is fine.
            tree_store: SimTreeStore::new(),
            current_block_height: 0,
            current_root_hash: Hash::ZERO,
            current_state: BTreeMap::new(),
            state_history: BTreeMap::new(),
            associations: HashMap::new(),
        }
    }

    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    ///
    /// The snapshot's tree nodes are consensus-verified (2f+1 validators
    /// agreed on the resulting state root). We apply unconditionally —
    /// the overlay may have computed from a base state ahead of the
    /// tree store, so base_root mismatches are expected and safe.
    pub(crate) fn apply_jmt_snapshot(&mut self, snapshot: JmtSnapshot) {
        for (jmt_key, jmt_node) in &snapshot.nodes {
            self.tree_store
                .insert(jmt_key.clone(), Arc::clone(jmt_node));
        }
        // NOTE: stale JMT nodes are NOT deleted here. Historical JMT nodes
        // must be retained so that provision fetch (generate_merkle_proofs) can
        // read the tree at past block heights. In production, RocksDB GC handles
        // pruning after `jmt_history_length` blocks (default 256). In simulation,
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
    pub blocks: BTreeMap<BlockHeight, CertifiedBlock>,
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

/// Apply database updates to the substate store at `version`.
///
/// Each write mutates `current_state` directly. If `write_history` is
/// true, the pre-write value (or `None` if absent) is captured into
/// `state_history` at `(storage_key, version)` before the write is
/// applied — this is the mechanism that lets historical reads at any
/// earlier version recover the value-at-that-version. Genesis and
/// other bootstrap paths pass `write_history: false` because there is
/// no pre-state to preserve.
///
/// For Reset partitions, the helper enumerates current keys in the
/// partition (via `current_state`) and treats each the same way:
/// capture history, then set (if re-written by `new_substate_values`)
/// or delete.
pub(crate) fn apply_updates(
    state: &mut SharedState,
    updates: &DatabaseUpdates,
    version: u64,
    write_history: bool,
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
                        let prior = state.current_state.get(&key).cloned();
                        if write_history {
                            state.state_history.insert((key.clone(), version), prior);
                        }
                        match update {
                            DatabaseUpdate::Set(v) => {
                                state.current_state.insert(key, v.clone());
                            }
                            DatabaseUpdate::Delete => {
                                state.current_state.remove(&key);
                            }
                        }
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // Enumerate keys currently live in the partition
                    // from `current_state` directly (one entry per key,
                    // no version walk).
                    let existing_keys = live_partition_keys(&state.current_state, &partition_key);
                    let new_keys: std::collections::HashSet<Vec<u8>> = new_substate_values
                        .iter()
                        .map(|(sk, _)| keys::to_storage_key(&partition_key, sk))
                        .collect();

                    // Remove old keys that aren't in the new set.
                    for key in &existing_keys {
                        if !new_keys.contains(key) {
                            let prior = state.current_state.remove(key);
                            if write_history {
                                state.state_history.insert((key.clone(), version), prior);
                            }
                        }
                    }

                    // Write new values; capture history for each.
                    for (sort_key, value) in new_substate_values {
                        let key = keys::to_storage_key(&partition_key, sort_key);
                        let prior = state.current_state.get(&key).cloned();
                        if write_history {
                            state.state_history.insert((key.clone(), version), prior);
                        }
                        state.current_state.insert(key, value.clone());
                    }
                }
            }
        }
    }
}

/// Return storage keys currently live in the given partition.
pub(crate) fn live_partition_keys(
    current_state: &BTreeMap<Vec<u8>, Vec<u8>>,
    partition_key: &DbPartitionKey,
) -> Vec<Vec<u8>> {
    let prefix = keys::partition_prefix(partition_key);
    let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");
    current_state
        .range(prefix..end)
        .map(|(k, _)| k.clone())
        .collect()
}
