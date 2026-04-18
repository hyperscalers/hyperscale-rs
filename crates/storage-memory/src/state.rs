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
    Block, BlockHeight, ExecutionCertificate, ExecutionMetadata, Hash, LocalReceipt,
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
    /// MVCC versioned substate store — the single source of truth for
    /// substates. `(storage_key, version) → Option<value>`, where `None`
    /// is a tombstone. BTreeMap ordering gives prefix scans and version
    /// ordering for free; "current state" is simply the latest entry per
    /// key.
    pub substates: VersionedSubstateStore,
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
            substates: BTreeMap::new(),
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

/// Apply database updates to the MVCC substate store at `version`.
///
/// Every write lands as `(storage_key, version) → Some(value)` (Set) or
/// `(storage_key, version) → None` (Delete / Reset tombstone). "Current
/// state" is derived by walking each key's version list and taking the
/// latest non-tombstone entry.
///
/// For Reset partitions, the helper enumerates existing non-tombstone
/// keys in the partition (latest entry per key at or below `version - 1`)
/// and emits tombstones for each at `version` before writing the new
/// values.
pub(crate) fn apply_updates(
    substates: &mut VersionedSubstateStore,
    updates: &DatabaseUpdates,
    version: u64,
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
                        let value = match update {
                            DatabaseUpdate::Set(v) => Some(v.clone()),
                            DatabaseUpdate::Delete => None,
                        };
                        substates.insert((key, version), value);
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // Enumerate keys currently live in the partition
                    // (latest non-tombstone entry at or below `version`
                    // pre-write), tombstone each at `version`.
                    let existing_keys = live_partition_keys_at(
                        substates,
                        &partition_key,
                        version.saturating_sub(1),
                    );
                    for key in existing_keys {
                        substates.insert((key, version), None);
                    }

                    for (sort_key, value) in new_substate_values {
                        let key = keys::to_storage_key(&partition_key, sort_key);
                        substates.insert((key, version), Some(value.clone()));
                    }
                }
            }
        }
    }
}

/// Return storage keys that have a live (non-tombstone) entry in the
/// partition at or below `version`.
fn live_partition_keys_at(
    substates: &VersionedSubstateStore,
    partition_key: &DbPartitionKey,
    version: u64,
) -> Vec<Vec<u8>> {
    let prefix = keys::partition_prefix(partition_key);
    let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");
    let range_start = (prefix, 0u64);
    let range_end = (end, 0u64);

    let mut result: Vec<Vec<u8>> = Vec::new();
    let mut current_key: Option<&Vec<u8>> = None;
    let mut current_best_is_live = false;

    for ((sk_full, ver), value) in substates.range(range_start..range_end) {
        if current_key != Some(sk_full) {
            if let Some(prev) = current_key {
                if current_best_is_live {
                    result.push(prev.clone());
                }
            }
            current_key = Some(sk_full);
            current_best_is_live = false;
        }
        if *ver <= version {
            current_best_is_live = value.is_some();
        }
    }
    if let Some(prev) = current_key {
        if current_best_is_live {
            result.push(prev.clone());
        }
    }
    result
}
