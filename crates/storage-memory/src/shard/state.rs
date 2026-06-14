//! Shared state types for simulated storage.
//!
//! Contains the internal state structures protected by `RwLocks` in `SimShardStorage`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use hyperscale_jmt::Key;
use hyperscale_storage::shard::keys;
use hyperscale_storage::tree::{jmt_parent_height, put_at_version};
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, JmtSnapshot, PartitionDatabaseUpdates,
};
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, ChainOrigin, ConsensusReceipt, ExecutionCertificate,
    ExecutionMetadata, NodeId, QuorumCertificate, RoutableTransaction, ShardWitnessPayload,
    StateRoot, StoredReceipt, TxHash, WaveCertificate, WaveId,
};

use super::tree_store::SimTreeStore;

// ═══════════════════════════════════════════════════════════════════════
// Shared substate + JMT state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// Substate data and JMT state protected by a single `RwLock`.
///
/// A single lock ensures association resolution can read substate data
/// atomically, avoiding deadlock.
///
/// Using `RwLock` (instead of Mutex) allows concurrent read access: speculative
/// JMT computations from `prepare_block_commit` take a read lock and can run
/// concurrently with other readers, while commits take a write lock.
#[derive(Clone)]
pub struct SharedState {
    pub tree_store: SimTreeStore,
    pub current_block_height: BlockHeight,
    pub current_root_hash: StateRoot,
    /// Hashed-leaf-key → raw-storage-key associations for snap-sync
    /// range serving. Entries for deleted leaves are retained — the
    /// mapping is deterministic and immutable per key, and pinned
    /// boundaries serve versions where the leaf may still be live.
    pub associations: HashMap<Key, Vec<u8>>,
    /// Current value per `storage_key`. Absent key = no value. This is
    /// the authoritative source of truth for reads at the current tip.
    pub current_state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per-write prior-value entries keyed by `(storage_key,
    /// write_version)`. `None` means the key was absent immediately
    /// before the write at that version. Consumed by historical reads
    /// and the retention GC.
    pub state_history: BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>,
    /// Committed substate byte total per version, written in
    /// lockstep with each applied snapshot. Consensus-critical:
    /// shard-witness derivation reads it, so it must be identical on
    /// every replica.
    pub substate_bytes: BTreeMap<u64, u64>,
}

impl SharedState {
    pub(crate) fn new() -> Self {
        Self {
            // Pruning disabled: historical substate reads traverse the JMT at
            // past heights and need old nodes to still exist. In production,
            // RocksDB GC respects `jmt_history_length` (default 256).
            // In simulation, tests are short-lived so retaining all nodes is fine.
            tree_store: SimTreeStore::new(),
            current_block_height: BlockHeight::GENESIS,
            current_root_hash: StateRoot::ZERO,
            current_state: BTreeMap::new(),
            state_history: BTreeMap::new(),
            associations: HashMap::new(),
            substate_bytes: BTreeMap::new(),
        }
    }

    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    ///
    /// The snapshot's tree nodes are consensus-verified (2f+1 validators
    /// agreed on the resulting state root). We apply unconditionally —
    /// the overlay may have computed from a base state ahead of the
    /// tree store, so `base_root` mismatches are expected and safe.
    pub(crate) fn apply_jmt_snapshot(&mut self, snapshot: JmtSnapshot) {
        for (jmt_key, jmt_node) in &snapshot.nodes {
            self.tree_store
                .insert(jmt_key.clone(), Arc::clone(jmt_node));
        }
        // Stale JMT nodes are NOT deleted here. Historical JMT nodes must be
        // retained so that provision fetch (generate_merkle_proofs) can read
        // the tree at past block heights. In production, RocksDB GC handles
        // pruning after `jmt_history_length` blocks (default 256). In
        // simulation, we retain all nodes (tests are short-lived).
        for a in snapshot.leaf_associations {
            if let Some(storage_key) = a.storage_key {
                self.associations.insert(a.leaf_key, storage_key);
            }
        }

        // Substate bytes: the byte total behind the currently applied version
        // (equal across any interleaved empty commits) plus this
        // snapshot's leaf delta.
        let prior = self
            .substate_bytes
            .get(&self.current_block_height.inner())
            .copied()
            .unwrap_or(0);
        let count = prior
            .checked_add_signed(snapshot.bytes_delta)
            .expect("substate byte total must not go negative");
        self.substate_bytes
            .insert(snapshot.new_height.inner(), count);

        self.current_block_height = snapshot.new_height;
        self.current_root_hash = snapshot.result_root;
    }
}

/// Apply `updates` at `height` over the shared state — substate values
/// (with history), the JMT (owner-routed via `owner_map`), leaf
/// associations, the substate byte total, and the tip version/root — and
/// return the resulting root. The state-level half of a block commit,
/// shared by the chain writer's sync path and a split observer's
/// follow path.
pub fn apply_state_writes(
    s: &mut SharedState,
    updates: &DatabaseUpdates,
    owner_map: &HashMap<NodeId, NodeId>,
    height: BlockHeight,
) -> StateRoot {
    apply_updates(s, updates, height.inner(), /* write_history */ true);

    let parent_version =
        jmt_parent_height(s.current_block_height, s.current_root_hash).map(BlockHeight::inner);
    let (new_root, collected) = put_at_version(
        &s.tree_store,
        parent_version,
        height.inner(),
        &[updates],
        &HashMap::new(),
        owner_map,
    );

    for (key, node) in &collected.nodes {
        s.tree_store.insert(key.clone(), Arc::clone(node));
    }
    // Stale JMT nodes are intentionally NOT deleted here: historical
    // roots must be retained for provision proof generation at past
    // block heights. RocksDB GC handles pruning in production. See
    // also `apply_jmt_snapshot`.
    for a in collected.leaf_associations {
        if let Some(storage_key) = a.storage_key {
            s.associations.insert(a.leaf_key, storage_key);
        }
    }

    // Substate bytes: prior byte total behind the current version plus
    // this application's leaf delta — same rule as `apply_jmt_snapshot`.
    let prior = s
        .substate_bytes
        .get(&s.current_block_height.inner())
        .copied()
        .unwrap_or(0);
    let count = prior
        .checked_add_signed(collected.bytes_delta)
        .expect("substate byte total must not go negative");
    s.substate_bytes.insert(height.inner(), count);

    s.current_block_height = height;
    s.current_root_hash = new_root;
    new_root
}

// ═══════════════════════════════════════════════════════════════════════
// Consolidated consensus state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// All consensus-related metadata bundled into a single `RwLock`.
pub struct ConsensusState {
    /// Committed blocks indexed by height.
    pub blocks: BTreeMap<BlockHeight, CertifiedBlock>,
    /// Committed height.
    pub committed_height: BlockHeight,
    /// Committed block hash.
    pub committed_hash: Option<BlockHash>,
    /// Latest QC.
    pub committed_qc: Option<QuorumCertificate>,
    /// Transactions indexed by hash.
    pub transactions: HashMap<TxHash, RoutableTransaction>,
    /// Wave certificates indexed by `WaveId`.
    pub certificates: HashMap<WaveId, WaveCertificate>,
    /// Consensus receipts keyed by transaction hash.
    pub consensus_receipts: HashMap<TxHash, Arc<ConsensusReceipt>>,
    /// Execution output details keyed by transaction hash.
    pub execution_metadata: HashMap<TxHash, ExecutionMetadata>,
    /// Insertion height for each receipt, enabling height-based pruning.
    pub receipt_heights: HashMap<TxHash, BlockHeight>,
    /// Execution certificates keyed by [`WaveId`].
    pub execution_certs: HashMap<WaveId, ExecutionCertificate>,
    /// Index: `block_height` → `WaveId`s at that height.
    pub wave_certs_by_height: HashMap<BlockHeight, Vec<WaveId>>,
    /// Beacon-witness leaves keyed by leaf index. Mirrors the production
    /// `RocksDB` `beacon_witnesses` CF so simulation integration tests
    /// can serve fetches and replay the accumulator on restart. Shard
    /// is implicit — storage is scoped per-shard.
    pub beacon_witnesses: BTreeMap<u64, ShardWitnessPayload>,
    /// The chain's origin — `ChainOrigin::ROOT` except for a split
    /// child's adopted store, where recovery must reconstruct the
    /// continued height line and clock.
    pub chain_origin: ChainOrigin,
}

/// Maximum number of blocks worth of receipts to retain in simulation storage.
const SIM_RECEIPT_RETENTION_BLOCKS: u64 = 1_000;

impl ConsensusState {
    pub(crate) fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            committed_height: BlockHeight::new(0),
            committed_hash: None,
            committed_qc: None,
            transactions: HashMap::new(),
            certificates: HashMap::new(),
            consensus_receipts: HashMap::new(),
            execution_metadata: HashMap::new(),
            receipt_heights: HashMap::new(),
            execution_certs: HashMap::new(),
            wave_certs_by_height: HashMap::new(),
            beacon_witnesses: BTreeMap::new(),
            chain_origin: ChainOrigin::ROOT,
        }
    }

    /// Insert a slice of stored receipts into the consensus + metadata maps.
    pub(crate) fn insert_receipts(&mut self, receipts: &[StoredReceipt]) {
        for receipt in receipts {
            self.consensus_receipts
                .insert(receipt.tx_hash, Arc::clone(&receipt.consensus));
            if let Some(ref metadata) = receipt.metadata {
                self.execution_metadata
                    .insert(receipt.tx_hash, metadata.clone());
            }
        }
    }

    /// Prune receipts older than the retention window.
    pub(crate) fn prune_receipts(&mut self, committed_height: BlockHeight) {
        let cutoff = committed_height.saturating_sub(SIM_RECEIPT_RETENTION_BLOCKS);
        if cutoff == BlockHeight::GENESIS {
            return;
        }
        self.receipt_heights.retain(|tx_hash, height| {
            if *height <= cutoff {
                self.consensus_receipts.remove(tx_hash);
                self.execution_metadata.remove(tx_hash);
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
pub fn apply_updates(
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
pub fn live_partition_keys(
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
