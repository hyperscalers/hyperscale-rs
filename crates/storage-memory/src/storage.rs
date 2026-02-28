//! # Simulated Storage
//!
//! In-memory storage implementation for deterministic simulation testing (DST).
//!
//! Uses `im::OrdMap` for O(1) structural-sharing clones, enabling efficient
//! snapshots without copying the entire dataset. This is critical for parallel
//! transaction execution where each transaction needs an isolated view.
//!
//! # JMT Integration
//!
//! Uses `TypedInMemoryTreeStore` for Jellyfish Merkle Tree tracking, providing
//! `state_version()` and `state_root_hash()` for state commitment. This ensures
//! simulation has identical JMT behavior to production.

use hyperscale_storage::{
    jmt::{put_at_next_version, StoredTreeNodeKey, TypedInMemoryTreeStore, WriteableTreeStore},
    keys, CommitResult, CommitStore, CommittableSubstateDatabase, ConsensusStore, DatabaseUpdate,
    DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, JmtSnapshot, OverlayTreeStore,
    PartitionDatabaseUpdates, PartitionEntry, StateRootHash, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{
    Block, BlockHeight, Hash, NodeId, QuorumCertificate, RoutableTransaction, ShardGroupId,
    SubstateWrite, TransactionCertificate,
};
use im::OrdMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

// ═══════════════════════════════════════════════════════════════════════
// Overlay tree store for speculative JMT computation
// Uses the unified OverlayTreeStore from hyperscale_storage.
// ═══════════════════════════════════════════════════════════════════════

/// Inner state protected by a single lock to prevent TOCTOU races.
pub(crate) struct JmtInner {
    pub tree_store: TypedInMemoryTreeStore,
    pub current_version: u64,
    pub current_root_hash: StateRootHash,
}

/// JMT state bundled for thread-safe access.
///
/// All fields are protected by a single Mutex to ensure atomic
/// reads and updates of version + root hash + tree store.
pub(crate) struct SharedJmtState {
    inner: Mutex<JmtInner>,
}

impl SharedJmtState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(JmtInner {
                tree_store: TypedInMemoryTreeStore::new().with_pruning_enabled(),
                current_version: 0,
                current_root_hash: StateRootHash([0u8; 32]),
            }),
        }
    }

    fn state_version(&self) -> u64 {
        self.inner.lock().unwrap().current_version
    }

    /// Get the current JMT root as a Hash.
    pub(crate) fn current_jmt_root(&self) -> Hash {
        let inner = self.inner.lock().unwrap();
        Hash::from_hash_bytes(&inner.current_root_hash.0)
    }

    /// Compute speculative state root from pre-converted DatabaseUpdates.
    ///
    /// This verifies the JMT root matches expected_base_root before computing.
    /// Used for state root verification to ensure proposer and verifier compute
    /// from the same base state.
    ///
    /// Returns both the computed state root AND a snapshot of the JMT nodes
    /// created during computation, which can be applied during commit.
    ///
    /// # Arguments
    /// * `expected_base_root` - The expected JMT root to verify against
    /// * `updates_per_cert` - Pre-converted DatabaseUpdates for each certificate
    /// * `substate_db` - Reference to the substate database for looking up unchanged values
    fn compute_speculative_root(
        &self,
        expected_base_root: Hash,
        updates_per_cert: &[DatabaseUpdates],
        substate_db: &dyn SubstateDatabase,
    ) -> (Hash, JmtSnapshot) {
        let inner = self.inner.lock().unwrap();
        let base_root = inner.current_root_hash;
        let base_version = inner.current_version;
        let current_root_hash = Hash::from_hash_bytes(&base_root.0);

        if updates_per_cert.is_empty() {
            let snapshot = JmtSnapshot {
                base_root,
                base_version,
                result_root: base_root,
                num_versions: 0,
                nodes: std::collections::HashMap::new(),
                stale_tree_parts: Vec::new(),
                leaf_substate_associations: Vec::new(),
            };
            return (current_root_hash, snapshot);
        }

        // Verify the JMT root matches expected base root
        if current_root_hash != expected_base_root {
            tracing::warn!(
                ?current_root_hash,
                ?expected_base_root,
                "JMT root mismatch - verification will likely fail"
            );
        }

        // Simulation always collects associations for testing/debugging.
        let lookup = hyperscale_storage::SubstateDbLookup(substate_db);
        let overlay = OverlayTreeStore::new(&inner.tree_store).with_substate_lookup(&lookup);

        let mut current_version = base_version;
        let mut result_root = base_root;
        let num_versions = updates_per_cert.len() as u64;

        // Apply each certificate's updates at a separate version
        for updates in updates_per_cert {
            let parent_version = if current_version == 0 {
                None
            } else {
                Some(current_version)
            };

            result_root = put_at_next_version(&overlay, parent_version, updates);
            current_version += 1;
        }

        let result_hash = Hash::from_hash_bytes(&result_root.0);
        let snapshot = overlay.into_snapshot(base_root, base_version, result_root, num_versions);

        (result_hash, snapshot)
    }

    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    fn apply_snapshot(&self, snapshot: JmtSnapshot) {
        let mut inner = self.inner.lock().unwrap();

        // Verify we're applying to the expected base state.
        // Must check BOTH root AND version. Root can be unchanged with empty commits
        // (same root, different version), but the nodes are keyed by version.
        if inner.current_root_hash != snapshot.base_root {
            panic!(
                "JMT snapshot base ROOT mismatch: expected {:?}, got {:?}. \
                 This indicates a race condition where the JMT advanced between \
                 verification and commit.",
                snapshot.base_root, inner.current_root_hash
            );
        }
        if inner.current_version != snapshot.base_version {
            panic!(
                "JMT snapshot base VERSION mismatch: expected {}, got {}. \
                 The root matched but version didn't - this can happen with empty commits. \
                 Snapshot nodes are keyed by version, so this snapshot cannot be applied.",
                snapshot.base_version, inner.current_version
            );
        }

        // Insert all captured nodes
        for (key, node) in snapshot.nodes {
            inner.tree_store.insert_node(key, node);
        }

        // Prune stale nodes
        for stale_part in snapshot.stale_tree_parts {
            inner.tree_store.record_stale_tree_part(stale_part);
        }

        // Advance version and update root
        inner.current_version += snapshot.num_versions;
        inner.current_root_hash = snapshot.result_root;
    }

    fn commit(&self, updates: &DatabaseUpdates) {
        let mut inner = self.inner.lock().unwrap();

        let parent_version = if inner.current_version == 0 {
            None
        } else {
            Some(inner.current_version)
        };

        let new_root = put_at_next_version(&inner.tree_store, parent_version, updates);
        inner.current_version += 1;
        inner.current_root_hash = new_root;
    }
}

/// In-memory storage for simulation and testing.
///
/// Uses `im::OrdMap` which provides:
/// - Deterministic ordering (like BTreeMap)
/// - O(1) clone via structural sharing
/// - Thread-safe with Arc internally
///
/// This is critical for DST - same operations produce identical results,
/// and snapshots are cheap regardless of data size.
///
/// Implements Radix's `SubstateDatabase` and `CommittableSubstateDatabase` directly,
/// plus our `SubstateStore` extension for snapshots, node listing, and JMT state roots.
///
/// # JMT State Tracking
///
/// Uses `TypedInMemoryTreeStore` to maintain a Jellyfish Merkle Tree alongside
/// the substate data. On each `commit()`, the JMT is updated and a new state
/// root hash is computed. This provides:
/// - `state_version()` - Monotonically increasing version number
/// - `state_root_hash()` - Cryptographic commitment to entire state
///
/// Also stores consensus metadata:
/// - Committed blocks indexed by height
/// - Transaction certificates indexed by hash
/// - Chain metadata (committed height)
/// - Own votes (for BFT safety across restarts)
/// - Historical substate value associations (for historical queries)
///
/// # Interior Mutability
///
/// Consensus fields use `RwLock` so all methods can take `&self`. This enables
/// trait implementations (`CommitStore`, `ConsensusStore`) which require `&self`.
/// Committed consensus state bundled for atomic updates.
struct CommittedConsensusState {
    height: BlockHeight,
    hash: Option<Hash>,
    qc: Option<QuorumCertificate>,
}

pub struct SimStorage {
    /// Radix substate data.
    data: Arc<RwLock<OrdMap<Vec<u8>, Vec<u8>>>>,

    // ═══════════════════════════════════════════════════════════════════════
    // JMT state tracking
    // ═══════════════════════════════════════════════════════════════════════
    /// JMT state (tree store, version, root hash).
    jmt: Arc<SharedJmtState>,

    /// Historical substate value associations.
    /// Maps JMT leaf node keys to substate values for historical queries.
    /// Simulation always collects these for testing/debugging.
    associated_state_tree_values: Arc<RwLock<HashMap<StoredTreeNodeKey, Vec<u8>>>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Consensus storage (interior mutability via RwLock)
    // ═══════════════════════════════════════════════════════════════════════
    /// Committed blocks indexed by height.
    /// BTreeMap for efficient range queries.
    blocks: RwLock<BTreeMap<BlockHeight, (Block, QuorumCertificate)>>,

    /// Committed consensus state (height + hash + QC) bundled for atomic updates.
    committed_state: RwLock<CommittedConsensusState>,

    /// Transactions indexed by hash.
    /// Populated when blocks are committed via `put_block`.
    transactions: RwLock<HashMap<Hash, RoutableTransaction>>,

    /// Transaction certificates indexed by transaction hash.
    /// Used for cross-shard transaction finalization.
    certificates: RwLock<HashMap<Hash, TransactionCertificate>>,

    /// Our own votes indexed by height.
    /// **BFT Safety Critical**: Used to prevent equivocation after restart.
    /// Key: height → (block_hash, round)
    own_votes: RwLock<HashMap<u64, (Hash, u64)>>,
}

impl SimStorage {
    /// Create a new empty simulated storage.
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(OrdMap::new())),
            jmt: Arc::new(SharedJmtState::new()),
            associated_state_tree_values: Arc::new(RwLock::new(HashMap::new())),
            blocks: RwLock::new(BTreeMap::new()),
            committed_state: RwLock::new(CommittedConsensusState {
                height: BlockHeight(0),
                hash: None,
                qc: None,
            }),
            transactions: RwLock::new(HashMap::new()),
            certificates: RwLock::new(HashMap::new()),
            own_votes: RwLock::new(HashMap::new()),
        }
    }

    /// Get the current JMT version.
    pub fn current_jmt_version(&self) -> u64 {
        self.jmt.state_version()
    }

    /// Clear all data (useful for testing).
    pub fn clear(&mut self) {
        self.data.write().unwrap().clear();
        // Replace the shared JMT state with a fresh one
        self.jmt = Arc::new(SharedJmtState::new());
        self.associated_state_tree_values.write().unwrap().clear();
        self.blocks.write().unwrap().clear();
        {
            let mut state = self.committed_state.write().unwrap();
            state.height = BlockHeight(0);
            state.hash = None;
            state.qc = None;
        }
        self.certificates.write().unwrap().clear();
        self.own_votes.write().unwrap().clear();
    }

    /// Get number of substate keys stored.
    pub fn len(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Check if substate storage is empty.
    pub fn is_empty(&self) -> bool {
        self.data.read().unwrap().is_empty()
    }

    /// Internal: iterate over a key range using OrdMap::range() for O(log n + k) lookup.
    fn iter_range(&self, start: &[u8], end: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let data = self.data.read().unwrap();
        data.range(start.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// This is the deferred commit operation that applies state writes when
    /// a `TransactionCertificate` is included in a committed block. It mirrors
    /// the production `RocksDbStorage::commit_certificate_with_writes()` to
    /// ensure DST catches timing bugs where code incorrectly assumes state
    /// is available before certificate persistence.
    ///
    /// # Arguments
    ///
    /// * `certificate` - The transaction certificate to store
    /// * `writes` - The state writes from the certificate's shard_proofs for the local shard
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &TransactionCertificate,
        writes: &[SubstateWrite],
    ) {
        // 1. Commit state writes (updates JMT)
        let updates = hyperscale_storage::substate_writes_to_database_updates(writes);
        self.commit_shared(&updates);

        // 2. Store certificate
        self.certificates
            .write()
            .unwrap()
            .insert(certificate.transaction_hash, certificate.clone());
    }

    /// Commit database updates using a shared reference.
    ///
    /// Mirrors `CommittableSubstateDatabase::commit` but takes `&self`.
    /// The Radix trait impl delegates to this method.
    pub fn commit_shared(&self, updates: &DatabaseUpdates) {
        // 1. Update substate data
        {
            let mut data = self.data.write().unwrap();
            apply_updates_to_ordmap(&mut data, updates);
        }

        // 2. Update JMT and compute new root hash (via shared state)
        self.jmt.commit(updates);
    }
}

impl Default for SimStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SubstateDatabase for SimStorage {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        let data = self.data.read().unwrap();
        data.get(&key).cloned()
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
                Some((DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }
}

impl CommittableSubstateDatabase for SimStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        // Delegate to the shared version
        self.commit_shared(updates);
    }
}

impl SubstateStore for SimStorage {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // O(1) clone with structural sharing!
        let data = self.data.read().unwrap().clone();
        SimSnapshot { data }
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
                Some((partition_num, DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }

    fn state_version(&self) -> u64 {
        self.jmt.state_version()
    }

    fn state_root_hash(&self) -> Hash {
        self.jmt.current_jmt_root()
    }
}

impl SimStorage {
    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    ///
    /// This is the fast path for block commit when we have a cached snapshot
    /// from verification. Also stores leaf-to-substate associations for
    /// historical queries.
    pub fn apply_jmt_snapshot(&self, snapshot: JmtSnapshot) {
        // Store associations for historical queries
        {
            let mut assoc = self.associated_state_tree_values.write().unwrap();
            for a in &snapshot.leaf_substate_associations {
                assoc.insert(a.tree_node_key.clone(), a.substate_value.clone());
            }
        }

        // Apply JMT nodes
        self.jmt.apply_snapshot(snapshot);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CommitStore implementation
// ═══════════════════════════════════════════════════════════════════════

use hyperscale_storage::extract_writes_per_cert;

/// Apply database updates to a bare `OrdMap`, mutating it in place.
///
/// This is the core write-application logic shared by both prepare-time
/// (building the pre-applied OrdMap) and `commit_data_only`.
fn apply_updates_to_ordmap(data: &mut OrdMap<Vec<u8>, Vec<u8>>, updates: &DatabaseUpdates) {
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
                                data.insert(key, value.clone());
                            }
                            DatabaseUpdate::Delete => {
                                data.remove(&key);
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
                    }

                    // Insert new values
                    for (sort_key, value) in new_substate_values {
                        let key = keys::to_storage_key(&partition_key, sort_key);
                        data.insert(key, value.clone());
                    }
                }
            }
        }
    }
}

/// Precomputed commit work for a SimStorage block commit.
///
/// Contains a `JmtSnapshot` (precomputed Merkle tree nodes), a pre-built
/// `OrdMap` with all certificate substate writes already applied (for O(1)
/// swap at commit time), plus the certificates and shard needed for
/// `store_certificate` calls and fallback recompute.
pub struct SimPreparedCommit {
    snapshot: JmtSnapshot,
    /// Pre-built OrdMap with all certificate substate writes already applied.
    /// O(1) clone from base at prepare time; O(1) swap at commit time.
    resulting_data: OrdMap<Vec<u8>, Vec<u8>>,
    certificates: Vec<Arc<TransactionCertificate>>,
    local_shard: ShardGroupId,
}

impl CommitStore for SimStorage {
    type PreparedCommit = SimPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: ShardGroupId,
    ) -> (Hash, Self::PreparedCommit) {
        let writes_per_cert = extract_writes_per_cert(certificates, local_shard);

        // Convert SubstateWrites → DatabaseUpdates once, reuse for both JMT and OrdMap.
        let updates_per_cert: Vec<DatabaseUpdates> = writes_per_cert
            .iter()
            .map(|writes| hyperscale_storage::substate_writes_to_database_updates(writes))
            .collect();

        // Read data once to avoid TOCTOU between snapshot and pre-apply.
        let base_data = self.data.read().unwrap().clone();

        // Compute speculative JMT root
        let data_snapshot = SimSnapshot {
            data: base_data.clone(),
        };
        let (computed_root, snapshot) =
            self.jmt
                .compute_speculative_root(parent_state_root, &updates_per_cert, &data_snapshot);

        // Pre-apply all substate writes to a cloned OrdMap (O(1) clone).
        // At commit time, this becomes an O(1) swap instead of iterating writes.
        let mut resulting_data = base_data;
        for updates in &updates_per_cert {
            apply_updates_to_ordmap(&mut resulting_data, updates);
        }

        let prepared = SimPreparedCommit {
            snapshot,
            resulting_data,
            certificates: certificates.to_vec(),
            local_shard,
        };

        (computed_root, prepared)
    }

    fn commit_prepared_block(&self, prepared: Self::PreparedCommit) -> CommitResult {
        let current_root = self.state_root_hash();
        let current_version = self.current_jmt_version();
        let snapshot_base = Hash::from_hash_bytes(&prepared.snapshot.base_root.0);
        let use_fast_path =
            current_root == snapshot_base && current_version == prepared.snapshot.base_version;

        if use_fast_path {
            // Fast path: apply precomputed JMT snapshot
            self.apply_jmt_snapshot(prepared.snapshot);
            // Swap in the pre-built OrdMap (O(1) instead of iterating writes)
            *self.data.write().unwrap() = prepared.resulting_data;
            // Still need to store certificates
            for cert in &prepared.certificates {
                self.store_certificate(cert);
            }
        } else {
            // Stale cache: fall back to per-certificate recompute.
            // The pre-built OrdMap is based on stale state so can't be used.
            for cert in &prepared.certificates {
                let writes = cert
                    .shard_proofs
                    .get(&prepared.local_shard)
                    .map(|proof| proof.state_writes.as_slice())
                    .unwrap_or(&[]);
                self.commit_certificate_with_writes(cert, writes);
            }
        }

        CommitResult {
            state_version: self.jmt.state_version(),
            state_root: self.state_root_hash(),
        }
    }

    fn commit_block(
        &self,
        certificates: &[Arc<TransactionCertificate>],
        local_shard: ShardGroupId,
    ) -> CommitResult {
        for cert in certificates {
            let writes = cert
                .shard_proofs
                .get(&local_shard)
                .map(|proof| proof.state_writes.as_slice())
                .unwrap_or(&[]);
            self.commit_certificate_with_writes(cert, writes);
        }

        CommitResult {
            state_version: self.jmt.state_version(),
            state_root: self.state_root_hash(),
        }
    }

    fn commit_certificate(&self, certificate: &TransactionCertificate, writes: &[SubstateWrite]) {
        self.commit_certificate_with_writes(certificate, writes);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ConsensusStore implementation
// ═══════════════════════════════════════════════════════════════════════

impl ConsensusStore for SimStorage {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        // Index all transactions by hash for batch lookups
        let mut txs = self.transactions.write().unwrap();
        for tx in block
            .retry_transactions
            .iter()
            .chain(block.priority_transactions.iter())
            .chain(block.transactions.iter())
        {
            txs.insert(tx.hash(), tx.as_ref().clone());
        }
        drop(txs);

        self.blocks
            .write()
            .unwrap()
            .insert(height, (block.clone(), qc.clone()));
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.blocks.read().unwrap().get(&height).cloned()
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.committed_state.write().unwrap().height = height;
    }

    fn committed_height(&self) -> BlockHeight {
        self.committed_state.read().unwrap().height
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        let mut state = self.committed_state.write().unwrap();
        state.height = height;
        state.hash = Some(hash);
        state.qc = Some(qc.clone());
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.committed_state.read().unwrap().hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.committed_state.read().unwrap().qc.clone()
    }

    fn store_certificate(&self, certificate: &TransactionCertificate) {
        self.certificates
            .write()
            .unwrap()
            .insert(certificate.transaction_hash, certificate.clone());
    }

    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        self.certificates.read().unwrap().get(hash).cloned()
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        self.own_votes
            .write()
            .unwrap()
            .insert(height, (block_hash, round));
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        self.own_votes.read().unwrap().get(&height).copied()
    }

    fn get_all_own_votes(&self) -> HashMap<u64, (Hash, u64)> {
        self.own_votes.read().unwrap().clone()
    }

    fn prune_own_votes(&self, committed_height: u64) {
        self.own_votes
            .write()
            .unwrap()
            .retain(|height, _| *height > committed_height);
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        // SimStorage stores complete blocks, so this is the same as get_block
        self.blocks.read().unwrap().get(&height).cloned()
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        let txs = self.transactions.read().unwrap();
        hashes.iter().filter_map(|h| txs.get(h).cloned()).collect()
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        let certs = self.certificates.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| certs.get(h).cloned())
            .collect()
    }
}

/// Snapshot of in-memory storage.
///
/// Contains a structurally-shared copy of the data at snapshot time.
/// The clone is O(1) - only increments reference counts internally.
///
/// Implements `SubstateDatabase` for read-only access.
pub struct SimSnapshot {
    data: OrdMap<Vec<u8>, Vec<u8>>,
}

impl SubstateDatabase for SimSnapshot {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        self.data.get(&key).cloned()
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

        // Use range() for O(log n + k) instead of O(n) full scan.
        // Collect to Vec to avoid lifetime issues with the range iterator.
        let items: Vec<_> = self
            .data
            .range(start..end)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let sort_key_bytes = full_key[prefix_len..].to_vec();
                Some((DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_storage::test_helpers::{
        make_database_update, make_substate_write, make_test_block, make_test_certificate,
        make_test_qc,
    };
    use hyperscale_storage::{
        CommitStore, ConsensusStore, NodeDatabaseUpdates, SubstateDatabase, SubstateStore,
    };
    use hyperscale_types::{zero_bls_signature, Hash, NodeId, SignerBitfield, VotePower};

    #[test]
    fn test_basic_substate_operations() {
        let mut storage = SimStorage::new();

        // Create a partition key and sort key
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
        storage.commit(&updates);

        // Now we can read it
        let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
        assert_eq!(value, Some(vec![99, 88, 77]));
    }

    #[test]
    fn test_snapshot_isolation() {
        let mut storage = SimStorage::new();

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
        storage.commit(&updates);

        // Take snapshot
        let snapshot = storage.snapshot();

        // Modify storage
        let mut updates2 = DatabaseUpdates::default();
        updates2.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![2]))]
                            .into_iter()
                            .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates2);

        // Snapshot has old value
        assert_eq!(
            snapshot.get_raw_substate_by_db_key(&partition_key, &sort_key),
            Some(vec![1])
        );

        // Storage has new value
        assert_eq!(
            storage.get_raw_substate_by_db_key(&partition_key, &sort_key),
            Some(vec![2])
        );
    }

    #[test]
    fn test_snapshot_structural_sharing_performance() {
        let mut storage = SimStorage::new();

        // Insert 10,000 items
        for i in 0..10_000u32 {
            let partition_key = DbPartitionKey {
                node_key: i.to_be_bytes().to_vec(),
                partition_num: 0,
            };
            let sort_key = DbSortKey(vec![0]);

            let mut updates = DatabaseUpdates::default();
            updates.node_updates.insert(
                partition_key.node_key.clone(),
                NodeDatabaseUpdates {
                    partition_updates: [(
                        partition_key.partition_num,
                        PartitionDatabaseUpdates::Delta {
                            substate_updates: [(sort_key, DatabaseUpdate::Set(vec![i as u8]))]
                                .into_iter()
                                .collect(),
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            );
            storage.commit(&updates);
        }

        // Snapshot should be nearly instant (O(1), not O(n))
        let start = std::time::Instant::now();
        let _snap1 = storage.snapshot();
        let _snap2 = storage.snapshot();
        let _snap3 = storage.snapshot();
        let _snap4 = storage.snapshot();
        let _snap5 = storage.snapshot();
        let elapsed = start.elapsed();

        // 5 snapshots of 10k items should be very fast
        // With BTreeMap clone this would take 10+ ms; with OrdMap it's < 1ms
        assert!(
            elapsed.as_millis() < 50,
            "5 snapshots took {:?}, expected < 50ms",
            elapsed
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Consensus operations
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_block_storage_and_retrieval() {
        let storage = SimStorage::new();
        let block = make_test_block(42);
        let qc = make_test_qc(&block);

        assert!(storage.get_block(BlockHeight(42)).is_none());

        storage.put_block(BlockHeight(42), &block, &qc);

        let (stored_block, stored_qc) = storage.get_block(BlockHeight(42)).unwrap();
        assert_eq!(stored_block.header.height, BlockHeight(42));
        assert_eq!(stored_block.header.timestamp, 42_000);
        assert_eq!(stored_qc.block_hash, block.hash());
    }

    #[test]
    fn test_block_get_nonexistent() {
        let storage = SimStorage::new();
        assert!(storage.get_block(BlockHeight(999)).is_none());
    }

    #[test]
    fn test_committed_state() {
        let storage = SimStorage::new();
        let hash = Hash::from_bytes(&[42; 32]);
        let qc = QuorumCertificate {
            block_hash: hash,
            height: BlockHeight(10),
            parent_block_hash: Hash::ZERO,
            round: 3,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
            voting_power: VotePower(4),
            weighted_timestamp_ms: 10_000,
        };

        storage.set_committed_state(BlockHeight(10), hash, &qc);

        assert_eq!(storage.committed_height(), BlockHeight(10));
        assert_eq!(storage.committed_hash(), Some(hash));
        let stored_qc = storage.latest_qc().unwrap();
        assert_eq!(stored_qc.height, BlockHeight(10));
        assert_eq!(stored_qc.round, 3);
    }

    #[test]
    fn test_committed_height_default() {
        let storage = SimStorage::new();
        assert_eq!(storage.committed_height(), BlockHeight(0));
        assert!(storage.committed_hash().is_none());
        assert!(storage.latest_qc().is_none());
    }

    #[test]
    fn test_certificate_store_and_retrieve() {
        let storage = SimStorage::new();
        let cert = make_test_certificate(1, ShardGroupId(0), vec![]);
        let tx_hash = cert.transaction_hash;

        storage.store_certificate(&cert);

        let stored = storage.get_certificate(&tx_hash).unwrap();
        assert_eq!(stored.transaction_hash, tx_hash);
    }

    #[test]
    fn test_certificate_get_missing() {
        let storage = SimStorage::new();
        assert!(storage
            .get_certificate(&Hash::from_bytes(&[99; 32]))
            .is_none());
    }

    #[test]
    fn test_vote_persistence() {
        let storage = SimStorage::new();
        let block_hash = Hash::from_bytes(&[1; 32]);

        storage.put_own_vote(100, 5, block_hash);

        let vote = storage.get_own_vote(100);
        assert_eq!(vote, Some((block_hash, 5)));
    }

    #[test]
    fn test_vote_get_missing() {
        let storage = SimStorage::new();
        assert!(storage.get_own_vote(100).is_none());
    }

    #[test]
    fn test_vote_overwrite() {
        let storage = SimStorage::new();
        let hash_a = Hash::from_bytes(&[1; 32]);
        let hash_b = Hash::from_bytes(&[2; 32]);

        storage.put_own_vote(100, 0, hash_a);
        assert_eq!(storage.get_own_vote(100), Some((hash_a, 0)));

        storage.put_own_vote(100, 1, hash_b);
        assert_eq!(storage.get_own_vote(100), Some((hash_b, 1)));

        let all = storage.get_all_own_votes();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_vote_pruning() {
        let storage = SimStorage::new();
        let hash = Hash::from_bytes(&[1; 32]);

        storage.put_own_vote(10, 0, hash);
        storage.put_own_vote(20, 0, hash);
        storage.put_own_vote(30, 0, hash);

        storage.prune_own_votes(20);

        assert!(storage.get_own_vote(10).is_none());
        assert!(storage.get_own_vote(20).is_none());
        assert!(storage.get_own_vote(30).is_some());
    }

    #[test]
    fn test_get_all_own_votes() {
        let storage = SimStorage::new();
        let hash = Hash::from_bytes(&[1; 32]);

        storage.put_own_vote(10, 0, hash);
        storage.put_own_vote(20, 1, hash);

        let all = storage.get_all_own_votes();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get(&10), Some(&(hash, 0)));
        assert_eq!(all.get(&20), Some(&(hash, 1)));
    }

    #[test]
    fn test_get_block_for_sync() {
        let storage = SimStorage::new();
        let block = make_test_block(5);
        let qc = make_test_qc(&block);
        storage.put_block(BlockHeight(5), &block, &qc);

        let result = storage.get_block_for_sync(BlockHeight(5));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.header.height, BlockHeight(5));

        assert!(storage.get_block_for_sync(BlockHeight(999)).is_none());
    }

    #[test]
    fn test_transactions_batch_missing() {
        let storage = SimStorage::new();
        let result = storage.get_transactions_batch(&[Hash::from_bytes(&[1; 32])]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_transactions_batch_with_indexed_block() {
        let storage = SimStorage::new();
        let mut block = make_test_block(1);

        let tx = Arc::new(hyperscale_types::test_utils::test_transaction(42));
        let tx_hash = tx.hash();
        block.transactions = vec![tx];

        let qc = make_test_qc(&block);
        storage.put_block(BlockHeight(1), &block, &qc);

        let result = storage.get_transactions_batch(&[tx_hash]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hash(), tx_hash);

        // Missing hash still excluded
        let missing = Hash::from_bytes(&[99; 32]);
        let partial = storage.get_transactions_batch(&[tx_hash, missing]);
        assert_eq!(partial.len(), 1);
    }

    #[test]
    fn test_certificates_batch() {
        let storage = SimStorage::new();
        let cert1 = make_test_certificate(1, ShardGroupId(0), vec![]);
        let cert2 = make_test_certificate(2, ShardGroupId(0), vec![]);
        let hash1 = cert1.transaction_hash;
        let hash2 = cert2.transaction_hash;

        storage.store_certificate(&cert1);
        storage.store_certificate(&cert2);

        let result = storage.get_certificates_batch(&[hash1, hash2]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_certificates_batch_partial() {
        let storage = SimStorage::new();
        let cert = make_test_certificate(1, ShardGroupId(0), vec![]);
        let hash = cert.transaction_hash;
        storage.store_certificate(&cert);

        let missing = Hash::from_bytes(&[99; 32]);
        let result = storage.get_certificates_batch(&[hash, missing]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].transaction_hash, hash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // JMT state tracking
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_initial_state_version_is_zero() {
        let storage = SimStorage::new();
        assert_eq!(storage.state_version(), 0);
    }

    #[test]
    fn test_initial_state_root_is_zero() {
        let storage = SimStorage::new();
        assert_eq!(storage.state_root_hash(), Hash::ZERO);
    }

    #[test]
    fn test_state_version_increments_on_commit() {
        let storage = SimStorage::new();
        assert_eq!(storage.state_version(), 0);

        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        assert_eq!(storage.state_version(), 1);

        storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
        assert_eq!(storage.state_version(), 2);
    }

    #[test]
    fn test_state_root_changes_on_commit() {
        let storage = SimStorage::new();
        let root0 = storage.state_root_hash();

        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        let root1 = storage.state_root_hash();
        assert_ne!(root0, root1, "root should change after first commit");

        storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
        let root2 = storage.state_root_hash();
        assert_ne!(root1, root2, "root should change after second commit");
    }

    #[test]
    fn test_state_root_deterministic() {
        // Two storage instances with identical commits should have identical roots
        let s1 = SimStorage::new();
        let s2 = SimStorage::new();

        let updates = make_database_update(vec![1, 2, 3], 0, vec![10], vec![42]);
        s1.commit_shared(&updates);
        s2.commit_shared(&updates);

        assert_eq!(s1.state_root_hash(), s2.state_root_hash());
        assert_eq!(s1.state_version(), s2.state_version());
    }

    #[test]
    fn test_state_root_differs_for_different_data() {
        let s1 = SimStorage::new();
        let s2 = SimStorage::new();

        s1.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        s2.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![2]));

        assert_ne!(s1.state_root_hash(), s2.state_root_hash());
    }

    #[test]
    fn test_empty_commit_still_advances_version() {
        let storage = SimStorage::new();
        let updates = DatabaseUpdates::default();
        storage.commit_shared(&updates);
        assert_eq!(storage.state_version(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CommitStore
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_commit_block_single_cert() {
        let storage = SimStorage::new();
        let shard = ShardGroupId(0);
        let writes = vec![make_substate_write(1, 0, vec![10], vec![42])];
        let cert = Arc::new(make_test_certificate(1, shard, writes));

        let result = storage.commit_block(&[cert], shard);
        assert_eq!(result.state_version, 1);
        assert_ne!(result.state_root, Hash::ZERO);
    }

    #[test]
    fn test_commit_block_multiple_certs() {
        let storage = SimStorage::new();
        let shard = ShardGroupId(0);
        let cert1 = Arc::new(make_test_certificate(
            1,
            shard,
            vec![make_substate_write(1, 0, vec![10], vec![1])],
        ));
        let cert2 = Arc::new(make_test_certificate(
            2,
            shard,
            vec![make_substate_write(2, 0, vec![20], vec![2])],
        ));

        let result = storage.commit_block(&[cert1, cert2], shard);
        // Two certificates = two JMT versions
        assert_eq!(result.state_version, 2);
    }

    #[test]
    fn test_commit_block_empty_certs() {
        let storage = SimStorage::new();
        let result = storage.commit_block(&[], ShardGroupId(0));
        assert_eq!(result.state_version, 0);
        assert_eq!(result.state_root, Hash::ZERO);
    }

    #[test]
    fn test_prepare_then_commit_fast_path() {
        // Two identical storage instances: one uses prepare+commit, other uses commit_block.
        // Both should produce the same result.
        let s_prepared = SimStorage::new();
        let s_direct = SimStorage::new();
        let shard = ShardGroupId(0);
        let writes = vec![make_substate_write(1, 0, vec![10], vec![42])];
        let cert = Arc::new(make_test_certificate(1, shard, writes));

        // Prepare path
        let parent_root = s_prepared.state_root_hash();
        let (spec_root, prepared) =
            s_prepared.prepare_block_commit(parent_root, &[cert.clone()], shard);
        let result_prepared = s_prepared.commit_prepared_block(prepared);

        // Direct path
        let result_direct = s_direct.commit_block(&[cert], shard);

        assert_eq!(result_prepared.state_version, result_direct.state_version);
        assert_eq!(result_prepared.state_root, result_direct.state_root);
        assert_eq!(spec_root, result_prepared.state_root);
    }

    #[test]
    fn test_prepare_commit_state_root_matches() {
        let storage = SimStorage::new();
        let shard = ShardGroupId(0);
        let cert = Arc::new(make_test_certificate(
            1,
            shard,
            vec![make_substate_write(1, 0, vec![10], vec![42])],
        ));

        let parent_root = storage.state_root_hash();
        let (spec_root, prepared) = storage.prepare_block_commit(parent_root, &[cert], shard);
        let result = storage.commit_prepared_block(prepared);

        assert_eq!(spec_root, result.state_root);
    }

    #[test]
    fn test_commit_certificate_individual() {
        let storage = SimStorage::new();
        let writes = vec![make_substate_write(1, 0, vec![10], vec![42])];
        let cert = make_test_certificate(1, ShardGroupId(0), writes.clone());

        storage.commit_certificate(&cert, &writes);

        assert_eq!(storage.state_version(), 1);
        assert_ne!(storage.state_root_hash(), Hash::ZERO);
        // Certificate should also be stored
        assert!(storage.get_certificate(&cert.transaction_hash).is_some());
    }

    #[test]
    fn test_commit_block_stores_certificates() {
        let storage = SimStorage::new();
        let shard = ShardGroupId(0);
        let cert = Arc::new(make_test_certificate(
            1,
            shard,
            vec![make_substate_write(1, 0, vec![10], vec![42])],
        ));
        let tx_hash = cert.transaction_hash;

        let _ = storage.commit_block(&[cert], shard);

        assert!(storage.get_certificate(&tx_hash).is_some());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Utility methods
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_clear() {
        let mut storage = SimStorage::new();

        // Add some data
        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        let hash = Hash::from_bytes(&[1; 32]);
        storage.put_own_vote(10, 0, hash);
        assert!(storage.state_version() > 0);
        assert!(!storage.is_empty());

        storage.clear();

        assert_eq!(storage.state_version(), 0);
        assert_eq!(storage.state_root_hash(), Hash::ZERO);
        assert!(storage.is_empty());
        assert!(storage.get_own_vote(10).is_none());
    }

    #[test]
    fn test_len_and_is_empty() {
        let storage = SimStorage::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);

        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        assert!(!storage.is_empty());
        assert_eq!(storage.len(), 1);

        storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
        assert_eq!(storage.len(), 2);
    }

    #[test]
    fn test_list_substates_for_node() {
        let storage = SimStorage::new();
        let node_id = NodeId([1; 30]);

        // Commit two substates for the same node
        let write1 = make_substate_write(1, 0, vec![10], vec![100]);
        let write2 = make_substate_write(1, 0, vec![20], vec![200]);
        let cert = make_test_certificate(1, ShardGroupId(0), vec![write1, write2]);
        storage.commit_certificate(
            &cert,
            &cert
                .shard_proofs
                .get(&ShardGroupId(0))
                .unwrap()
                .state_writes,
        );

        let substates: Vec<_> = storage.list_substates_for_node(&node_id).collect();
        assert_eq!(substates.len(), 2, "should find exactly 2 substates");

        // Verify actual values
        let values: Vec<&Vec<u8>> = substates.iter().map(|(_, _, v)| v).collect();
        assert!(values.contains(&&vec![100u8]), "should contain first value");
        assert!(
            values.contains(&&vec![200u8]),
            "should contain second value"
        );

        // Different node should have no substates
        let other_node = NodeId([99; 30]);
        let other_substates: Vec<_> = storage.list_substates_for_node(&other_node).collect();
        assert!(other_substates.is_empty());
    }
}
