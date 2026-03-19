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
//! `jmt_version()` and `state_root_hash()` for state commitment. This ensures
//! simulation has identical JMT behavior to production.

use hyperscale_dispatch::Dispatch;
use hyperscale_storage::{
    jmt::{EntityTier, StoredTreeNodeKey, TypedInMemoryTreeStore, WriteableTreeStore},
    keys, CommitStore, ConsensusStore, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, JmtSnapshot, PartitionDatabaseUpdates, PartitionEntry, StateRootHash,
    SubstateDatabase, SubstateReader, SubstateStore,
};
use hyperscale_types::{
    Block, BlockHeight, Hash, LedgerTransactionReceipt, LocalTransactionExecution, NodeId,
    QuorumCertificate, ReceiptBundle, RoutableTransaction, TransactionCertificate, TypeConfig,
};
use im::OrdMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

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
    /// Radix substate data. `im::OrdMap` for O(1) structural-sharing clones.
    pub data: OrdMap<Vec<u8>, Vec<u8>>,
    pub tree_store: TypedInMemoryTreeStore,
    pub current_block_height: u64,
    pub current_root_hash: StateRootHash,
    /// Leaf-key → substate-value associations for historical queries.
    pub associations: HashMap<StoredTreeNodeKey, Vec<u8>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            data: OrdMap::new(),
            // Pruning disabled: historical substate reads traverse the JMT at
            // past heights and need old nodes to still exist. In production,
            // RocksDB GC respects `jmt_history_length` (default 256).
            // In simulation, tests are short-lived so retaining all nodes is fine.
            tree_store: TypedInMemoryTreeStore::new(),
            current_block_height: 0,
            current_root_hash: Hash::ZERO,
            associations: HashMap::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Consolidated consensus state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// All consensus-related metadata bundled into a single RwLock.
struct ConsensusState {
    /// Committed blocks indexed by height.
    blocks: BTreeMap<BlockHeight, (Block, QuorumCertificate)>,
    /// Committed height.
    committed_height: BlockHeight,
    /// Committed block hash.
    committed_hash: Option<Hash>,
    /// Latest QC.
    committed_qc: Option<QuorumCertificate>,
    /// Transactions indexed by hash.
    transactions: HashMap<Hash, RoutableTransaction>,
    /// Transaction certificates indexed by transaction hash.
    certificates: HashMap<Hash, TransactionCertificate>,
    /// Our own votes indexed by height.
    /// **BFT Safety Critical**: Used to prevent equivocation after restart.
    own_votes: HashMap<u64, (Hash, u64)>,
    /// Ledger receipts keyed by transaction hash.
    ledger_receipts: HashMap<Hash, Arc<LedgerTransactionReceipt>>,
    /// Local execution details keyed by transaction hash.
    local_executions: HashMap<Hash, LocalTransactionExecution>,
    /// Insertion height for each receipt, enabling height-based pruning.
    receipt_heights: HashMap<Hash, u64>,
}

/// Maximum number of blocks worth of receipts to retain in simulation storage.
const SIM_RECEIPT_RETENTION_BLOCKS: u64 = 1_000;

impl ConsensusState {
    fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            committed_height: BlockHeight(0),
            committed_hash: None,
            committed_qc: None,
            transactions: HashMap::new(),
            certificates: HashMap::new(),
            own_votes: HashMap::new(),
            ledger_receipts: HashMap::new(),
            local_executions: HashMap::new(),
            receipt_heights: HashMap::new(),
        }
    }

    /// Prune receipts older than the retention window.
    fn prune_receipts(&mut self, committed_height: u64) {
        let cutoff = committed_height.saturating_sub(SIM_RECEIPT_RETENTION_BLOCKS);
        if cutoff == 0 {
            return;
        }
        self.receipt_heights.retain(|tx_hash, height| {
            if *height <= cutoff {
                self.ledger_receipts.remove(tx_hash);
                self.local_executions.remove(tx_hash);
                false
            } else {
                true
            }
        });
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
/// Implements Radix's `SubstateDatabase` directly, plus our `SubstateStore` extension
/// for snapshots, node listing, and JMT state roots.
///
/// # Locking Strategy
///
/// Two RwLocks with independent lifetimes — no ordering constraint:
/// - `state`: Substate data + JMT tree store + version/root/associations.
///   Read lock for substate reads, JMT lookups, and speculative computation.
///   Write lock for commits (substate writes + JMT updates in one acquisition).
/// - `consensus`: Block metadata, certificates, votes, committed state.
///   Separate because consensus metadata is independent of substate/JMT state.
pub struct SimStorage<D: Dispatch + 'static> {
    /// Substate data + JMT state (single RwLock).
    state: Arc<RwLock<SharedState>>,

    /// Dispatch implementation for parallel JMT computation.
    dispatch: D,

    /// Consensus metadata (single RwLock).
    consensus: RwLock<ConsensusState>,
}

impl<D: Dispatch + 'static> SimStorage<D> {
    /// Create a new empty simulated storage with the given dispatch implementation.
    pub fn new(dispatch: D) -> Self {
        Self {
            state: Arc::new(RwLock::new(SharedState::new())),
            dispatch,
            consensus: RwLock::new(ConsensusState::new()),
        }
    }

    /// Get the current JMT version.
    pub fn current_jmt_version(&self) -> u64 {
        self.state.read().unwrap().current_block_height
    }

    /// Clear all data (useful for testing).
    pub fn clear(&mut self) {
        *self.state.write().unwrap() = SharedState::new();
        *self.consensus.write().unwrap() = ConsensusState::new();
    }

    /// Get number of substate keys stored.
    pub fn len(&self) -> usize {
        self.state.read().unwrap().data.len()
    }

    /// Check if substate storage is empty.
    pub fn is_empty(&self) -> bool {
        self.state.read().unwrap().data.is_empty()
    }

    /// Internal: iterate over a key range using OrdMap::range() for O(log n + k) lookup.
    fn iter_range(&self, start: &[u8], end: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let s = self.state.read().unwrap();
        s.data
            .range(start.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// Applies database updates and stores certificate metadata.
    /// JMT is deferred to block commit — this mirrors the production
    /// `RocksDbStorage::commit_certificate_with_writes()` to ensure DST
    /// catches timing bugs where code incorrectly assumes state is available
    /// before certificate persistence.
    #[cfg(test)]
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &TransactionCertificate,
        updates: &hyperscale_storage::DatabaseUpdates,
    ) {
        {
            let mut s = self.state.write().unwrap();
            apply_updates_to_ordmap(&mut s.data, &updates);
        }
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.transaction_hash, certificate.clone());
    }

    /// Test helper: commits database updates with auto-incrementing JMT version.
    /// Not used in production (use commit_block instead).
    ///
    /// Computes JMT updates and applies them to the tree store, resolving
    /// leaf-substate associations for historical reads.
    #[cfg(test)]
    pub fn commit_shared(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();

        // Apply substate updates first (visible for association resolution below).
        apply_updates_to_ordmap(&mut s.data, updates);

        let parent_version =
            hyperscale_storage::jmt_parent_height(s.current_block_height, s.current_root_hash);

        let new_version = s.current_block_height + 1;
        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            new_version,
            updates,
            &self.dispatch,
        );

        let associations = collected.apply_to(&s.tree_store);

        s.current_block_height = new_version;
        s.current_root_hash = new_root;

        // Resolve and store associations for historical queries.
        // Because data and JMT are in the same struct under one lock,
        // we can read substates directly without a second lock.
        for a in associations {
            if let Some((key, value)) = a.resolve(|pk, sk| ordmap_lookup(&s.data, pk, sk)) {
                s.associations.insert(key, value);
            }
        }
    }

    /// Write only substate data (no JMT computation).
    ///
    /// Used during genesis bootstrap so each intermediate `commit()` call from the
    /// Radix Engine writes substates without computing a JMT version.
    /// After all genesis commits complete, [`finalize_genesis_jmt`] computes the
    /// JMT once at version 0.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();
        apply_updates_to_ordmap(&mut s.data, updates);
    }

    /// Compute the JMT once at version 0 from the merged genesis updates.
    ///
    /// Called after all genesis bootstrap commits are complete. This avoids
    /// computing intermediate JMT versions during genesis (which would collide
    /// with block 1's version).
    ///
    /// # Returns
    /// The genesis state root hash (JMT root at version 0).
    pub fn finalize_genesis_jmt(&self, merged: &DatabaseUpdates) -> Hash {
        let mut s = self.state.write().unwrap();

        // Guard: finalize_genesis_jmt must only be called once, on an uninitialized JMT.
        assert!(
            s.current_block_height == 0 && s.current_root_hash == Hash::ZERO,
            "finalize_genesis_jmt called but JMT already initialized"
        );

        // parent=None, version=0: genesis is the first JMT state.
        let (root, collected) =
            hyperscale_storage::jmt::put_at_version(&s.tree_store, None, 0, merged, &self.dispatch);

        let associations = collected.apply_to(&s.tree_store);

        s.current_block_height = 0;
        s.current_root_hash = root;

        for a in associations {
            if let Some((key, value)) = a.resolve(|pk, sk| ordmap_lookup(&s.data, pk, sk)) {
                s.associations.insert(key, value);
            }
        }

        root
    }
}

/// Look up a substate value directly from an OrdMap.
///
/// This avoids going through the `SubstateDatabase` trait (and its lock)
/// when we already hold a reference to the data.
fn ordmap_lookup(
    data: &OrdMap<Vec<u8>, Vec<u8>>,
    partition_key: &DbPartitionKey,
    sort_key: &DbSortKey,
) -> Option<Vec<u8>> {
    let key = keys::to_storage_key(partition_key, sort_key);
    data.get(&key).cloned()
}

impl<D: Dispatch + 'static> hyperscale_storage::SubstatesOnlyCommit for SimStorage<D> {
    fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        SimStorage::commit_substates_only(self, updates);
    }
}

impl<D: Dispatch + 'static> SubstateDatabase for SimStorage<D> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        let s = self.state.read().unwrap();
        s.data.get(&key).cloned()
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

impl<D: Dispatch + 'static> SubstateReader for SimStorage<D> {
    fn get_raw_substate(
        &self,
        node_key: &[u8],
        partition_num: u8,
        sort_key: &[u8],
    ) -> Option<Vec<u8>> {
        let pk = DbPartitionKey {
            node_key: node_key.to_vec(),
            partition_num,
        };
        self.get_raw_substate_by_db_key(&pk, &DbSortKey(sort_key.to_vec()))
    }

    fn list_raw_substates(
        &self,
        node_key: &[u8],
        partition_num: u8,
        from_sort_key: Option<&[u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_> {
        let pk = DbPartitionKey {
            node_key: node_key.to_vec(),
            partition_num,
        };
        let from = from_sort_key.map(|k| DbSortKey(k.to_vec()));
        Box::new(
            self.list_raw_values_from_db_key(&pk, from.as_ref())
                .map(|(k, v)| (k.0, v)),
        )
    }
}

#[cfg(test)]
impl<D: Dispatch + 'static> hyperscale_storage::CommittableSubstateDatabase for SimStorage<D> {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.commit_shared(updates);
    }
}

impl<D: Dispatch + 'static> SubstateStore for SimStorage<D> {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // O(1) clone with structural sharing!
        let data = self.state.read().unwrap().data.clone();
        SimSnapshot { data }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, Vec<u8>, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

        let items = self.iter_range(&prefix, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let partition_num = full_key[prefix_len];
                let sort_key_bytes = full_key[prefix_len + 1..].to_vec();
                Some((partition_num, sort_key_bytes, value))
            } else {
                None
            }
        }))
    }

    fn jmt_version(&self) -> u64 {
        self.state.read().unwrap().current_block_height
    }

    fn state_root_hash(&self) -> Hash {
        self.state.read().unwrap().current_root_hash
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, Vec<u8>, Vec<u8>)>> {
        let entity_key = keys::node_entity_key(node_id);

        let s = self.state.read().unwrap();

        if block_height > s.current_block_height {
            return None;
        }

        let entity_tier = EntityTier::new(&s.tree_store, Some(block_height));
        let partition_tier = entity_tier.get_entity_partition_tier(entity_key);
        let mut results = Vec::new();

        for substate_tier in partition_tier.into_iter_partition_substate_tiers_from(None) {
            let partition_num = substate_tier.partition_key().partition_num;
            for summary in substate_tier.into_iter_substate_summaries_from(None) {
                if let Some(value) = s.associations.get(&summary.state_tree_leaf_key) {
                    results.push((partition_num, summary.sort_key.0, value.clone()));
                }
            }
        }
        Some(results)
    }

    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Vec<hyperscale_types::SubstateInclusionProof> {
        let s = self.state.read().unwrap();
        hyperscale_storage::proofs::generate_merkle_proofs(
            &s.tree_store,
            storage_keys,
            block_height,
        )
    }
}

impl<D: Dispatch + 'static> SimStorage<D> {
    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    ///
    /// This is the fast path for block commit when we have a cached snapshot
    /// from verification. Also stores leaf-to-substate associations for
    /// historical queries.
    fn apply_jmt_snapshot(s: &mut SharedState, snapshot: JmtSnapshot) {
        if s.current_root_hash != snapshot.base_root {
            panic!(
                "JMT snapshot base ROOT mismatch: expected {:?}, got {:?}.",
                snapshot.base_root, s.current_root_hash
            );
        }
        if s.current_block_height != snapshot.base_version {
            tracing::debug!(
                expected_version = snapshot.base_version,
                actual_version = s.current_block_height,
                "JMT snapshot base VERSION mismatch (root matches) - proceeding. \
                 This is expected when empty commits advance the version counter."
            );
        }

        for (key, node) in snapshot.nodes {
            s.tree_store.insert_node(key, node);
        }
        for stale_part in snapshot.stale_tree_parts {
            s.tree_store.record_stale_tree_part(stale_part);
        }
        for a in snapshot.leaf_substate_associations {
            s.associations.insert(a.tree_node_key, a.substate_value);
        }

        s.current_block_height = snapshot.new_version;
        s.current_root_hash = snapshot.result_root;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CommitStore implementation
// ═══════════════════════════════════════════════════════════════════════

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
    merged_updates: DatabaseUpdates,
}

impl<C: TypeConfig<StateUpdate = DatabaseUpdates>, D: Dispatch + 'static> CommitStore<C>
    for SimStorage<D>
{
    type PreparedCommit = SimPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        merged_updates: &DatabaseUpdates,
        block_height: u64,
    ) -> (Hash, Self::PreparedCommit) {
        // Read lock: clone data + compute speculative JMT root concurrently.
        let s = self.state.read().unwrap();
        let base_data = s.data.clone();
        let base_root = s.current_root_hash;
        let base_version = s.current_block_height;

        if base_root != parent_state_root {
            tracing::warn!(
                ?base_root,
                ?parent_state_root,
                "JMT root mismatch - verification will likely fail"
            );
        }

        let parent_version = hyperscale_storage::jmt_parent_height(base_version, base_root);
        let (result_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            merged_updates,
            &self.dispatch,
        );

        let data_snapshot = SimSnapshot {
            data: base_data.clone(),
        };
        let lookup = hyperscale_storage::SubstateDbLookup(&data_snapshot);
        let snapshot = JmtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            result_root,
            block_height,
            Some(&lookup),
        );

        drop(s); // Release read lock

        // Pre-apply all substate writes to a cloned OrdMap (O(1) clone).
        let mut resulting_data = base_data;
        apply_updates_to_ordmap(&mut resulting_data, merged_updates);

        let prepared = SimPreparedCommit {
            snapshot,
            resulting_data,
            merged_updates: merged_updates.clone(),
        };

        (result_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        certificates: &[Arc<TransactionCertificate>],
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
    ) -> Hash {
        let block_height = prepared.snapshot.new_version;
        let result_root = prepared.snapshot.result_root;

        {
            let mut s = self.state.write().unwrap();
            let use_fast_path = s.current_root_hash == prepared.snapshot.base_root;

            if use_fast_path {
                // Fast path: apply precomputed JMT snapshot + swap OrdMap
                Self::apply_jmt_snapshot(&mut s, prepared.snapshot);
                s.data = prepared.resulting_data;
                drop(s);

                // Store certificates + consensus metadata atomically in consensus lock.
                let mut c = self.consensus.write().unwrap();
                for cert in certificates {
                    c.certificates
                        .insert(cert.transaction_hash, (**cert).clone());
                }
                if let Some(consensus) = consensus {
                    c.committed_height = consensus.height;
                    c.committed_hash = Some(consensus.hash);
                    c.committed_qc = Some(consensus.qc);
                    c.prune_receipts(consensus.height.0);
                }

                return result_root;
            }
        }

        // Stale cache: fall back to full block commit which recomputes JMT.
        // Use the stored merged_updates to ensure substate writes aren't lost.
        <Self as CommitStore<C>>::commit_block(
            self,
            &prepared.merged_updates,
            certificates,
            block_height,
            consensus,
        )
    }

    fn commit_block(
        &self,
        merged_updates: &DatabaseUpdates,
        certificates: &[Arc<TransactionCertificate>],
        block_height: u64,
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
    ) -> Hash {
        let mut s = self.state.write().unwrap();

        assert!(
            block_height == s.current_block_height + 1
                || (block_height == 0 && s.current_block_height == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            s.current_block_height
        );

        // Apply substate writes to OrdMap.
        apply_updates_to_ordmap(&mut s.data, merged_updates);

        let parent_version =
            hyperscale_storage::jmt_parent_height(s.current_block_height, s.current_root_hash);

        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            merged_updates,
            &self.dispatch,
        );

        let associations = collected.apply_to(&s.tree_store);

        s.current_block_height = block_height;
        s.current_root_hash = new_root;

        // Resolve associations directly from the OrdMap (same lock).
        for a in associations {
            if let Some((key, value)) = a.resolve(|pk, sk| ordmap_lookup(&s.data, pk, sk)) {
                s.associations.insert(key, value);
            }
        }

        drop(s);

        // Store certificate metadata + consensus state atomically in consensus lock.
        {
            let mut c = self.consensus.write().unwrap();
            for cert in certificates {
                c.certificates
                    .insert(cert.transaction_hash, (**cert).clone());
            }
            if let Some(consensus) = consensus {
                c.committed_height = consensus.height;
                c.committed_hash = Some(consensus.hash);
                c.committed_qc = Some(consensus.qc);
                c.prune_receipts(consensus.height.0);
            }
        }

        new_root
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ConsensusStore implementation
// ═══════════════════════════════════════════════════════════════════════

impl<D: Dispatch + 'static> ConsensusStore for SimStorage<D> {
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate) {
        let mut c = self.consensus.write().unwrap();
        // Index all transactions by hash for batch lookups
        for tx in block
            .retry_transactions
            .iter()
            .chain(block.priority_transactions.iter())
            .chain(block.transactions.iter())
        {
            c.transactions.insert(tx.hash(), tx.as_ref().clone());
        }
        c.blocks.insert(height, (block.clone(), qc.clone()));
    }

    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn set_committed_height(&self, height: BlockHeight) {
        self.consensus.write().unwrap().committed_height = height;
    }

    fn committed_height(&self) -> BlockHeight {
        self.consensus.read().unwrap().committed_height
    }

    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate) {
        let mut c = self.consensus.write().unwrap();
        c.committed_height = height;
        c.committed_hash = Some(hash);
        c.committed_qc = Some(qc.clone());
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.consensus.read().unwrap().committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.consensus.read().unwrap().committed_qc.clone()
    }

    fn store_certificate(&self, certificate: &TransactionCertificate) {
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.transaction_hash, certificate.clone());
    }

    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        self.consensus
            .read()
            .unwrap()
            .certificates
            .get(hash)
            .cloned()
    }

    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        self.consensus
            .write()
            .unwrap()
            .own_votes
            .insert(height, (block_hash, round));
    }

    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        self.consensus
            .read()
            .unwrap()
            .own_votes
            .get(&height)
            .copied()
    }

    fn get_all_own_votes(&self) -> HashMap<u64, (Hash, u64)> {
        self.consensus.read().unwrap().own_votes.clone()
    }

    fn prune_own_votes(&self, committed_height: u64) {
        self.consensus
            .write()
            .unwrap()
            .own_votes
            .retain(|height, _| *height > committed_height);
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<TransactionCertificate> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.certificates.get(h).cloned())
            .collect()
    }

    fn store_receipt_bundle(&self, bundle: &ReceiptBundle) {
        let mut c = self.consensus.write().unwrap();
        let receipt = if let Some(ref updates) = bundle.database_updates {
            let mut r = (*bundle.ledger_receipt).clone();
            r.state_changes = hyperscale_storage::extract_state_changes(updates);
            Arc::new(r)
        } else {
            Arc::clone(&bundle.ledger_receipt)
        };
        let height = c.committed_height.0;
        c.ledger_receipts.insert(bundle.tx_hash, receipt);
        c.receipt_heights.insert(bundle.tx_hash, height);
        if let Some(ref local) = bundle.local_execution {
            c.local_executions.insert(bundle.tx_hash, local.clone());
        }
    }

    fn get_ledger_receipt(&self, tx_hash: &Hash) -> Option<Arc<LedgerTransactionReceipt>> {
        self.consensus
            .read()
            .unwrap()
            .ledger_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_local_execution(&self, tx_hash: &Hash) -> Option<LocalTransactionExecution> {
        self.consensus
            .read()
            .unwrap()
            .local_executions
            .get(tx_hash)
            .cloned()
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

impl SubstateReader for SimSnapshot {
    fn get_raw_substate(
        &self,
        node_key: &[u8],
        partition_num: u8,
        sort_key: &[u8],
    ) -> Option<Vec<u8>> {
        let pk = DbPartitionKey {
            node_key: node_key.to_vec(),
            partition_num,
        };
        self.get_raw_substate_by_db_key(&pk, &DbSortKey(sort_key.to_vec()))
    }

    fn list_raw_substates(
        &self,
        node_key: &[u8],
        partition_num: u8,
        from_sort_key: Option<&[u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_> {
        let pk = DbPartitionKey {
            node_key: node_key.to_vec(),
            partition_num,
        };
        let from = from_sort_key.map(|k| DbSortKey(k.to_vec()));
        Box::new(
            self.list_raw_values_from_db_key(&pk, from.as_ref())
                .map(|(k, v)| (k.0, v)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_dispatch_sync::SyncDispatch;
    use hyperscale_storage::test_helpers::{
        make_database_update, make_mapped_database_update, make_test_block, make_test_certificate,
        make_test_qc,
    };
    use hyperscale_storage::{
        CommitStore, CommittableSubstateDatabase, ConsensusStore, NodeDatabaseUpdates,
        SubstateDatabase, SubstateStore,
    };
    use hyperscale_types::{
        zero_bls_signature, ConcreteConfig, Hash, NodeId, ShardGroupId, SignerBitfield,
    };

    #[test]
    fn test_basic_substate_operations() {
        let mut storage = SimStorage::new(SyncDispatch::new());

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
        let mut storage = SimStorage::new(SyncDispatch::new());

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
        let mut storage = SimStorage::new(SyncDispatch::new());

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
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
        assert!(storage.get_block(BlockHeight(999)).is_none());
    }

    #[test]
    fn test_committed_state() {
        let storage = SimStorage::new(SyncDispatch::new());
        let hash = Hash::from_bytes(&[42; 32]);
        let qc = QuorumCertificate {
            block_hash: hash,
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(10),
            parent_block_hash: Hash::ZERO,
            round: 3,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
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
        let storage = SimStorage::new(SyncDispatch::new());
        assert_eq!(storage.committed_height(), BlockHeight(0));
        assert!(storage.committed_hash().is_none());
        assert!(storage.latest_qc().is_none());
    }

    #[test]
    fn test_certificate_store_and_retrieve() {
        let storage = SimStorage::new(SyncDispatch::new());
        let cert = make_test_certificate(1, ShardGroupId(0));
        let tx_hash = cert.transaction_hash;

        storage.store_certificate(&cert);

        let stored = storage.get_certificate(&tx_hash).unwrap();
        assert_eq!(stored.transaction_hash, tx_hash);
    }

    #[test]
    fn test_certificate_get_missing() {
        let storage = SimStorage::new(SyncDispatch::new());
        assert!(storage
            .get_certificate(&Hash::from_bytes(&[99; 32]))
            .is_none());
    }

    #[test]
    fn test_vote_persistence() {
        let storage = SimStorage::new(SyncDispatch::new());
        let block_hash = Hash::from_bytes(&[1; 32]);

        storage.put_own_vote(100, 5, block_hash);

        let vote = storage.get_own_vote(100);
        assert_eq!(vote, Some((block_hash, 5)));
    }

    #[test]
    fn test_vote_get_missing() {
        let storage = SimStorage::new(SyncDispatch::new());
        assert!(storage.get_own_vote(100).is_none());
    }

    #[test]
    fn test_vote_overwrite() {
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
        let result = storage.get_transactions_batch(&[Hash::from_bytes(&[1; 32])]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_transactions_batch_with_indexed_block() {
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
        let cert1 = make_test_certificate(1, ShardGroupId(0));
        let cert2 = make_test_certificate(2, ShardGroupId(0));
        let hash1 = cert1.transaction_hash;
        let hash2 = cert2.transaction_hash;

        storage.store_certificate(&cert1);
        storage.store_certificate(&cert2);

        let result = storage.get_certificates_batch(&[hash1, hash2]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_certificates_batch_partial() {
        let storage = SimStorage::new(SyncDispatch::new());
        let cert = make_test_certificate(1, ShardGroupId(0));
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
    fn test_initial_jmt_version_is_zero() {
        let storage = SimStorage::new(SyncDispatch::new());
        assert_eq!(storage.jmt_version(), 0);
    }

    #[test]
    fn test_initial_state_root_is_zero() {
        let storage = SimStorage::new(SyncDispatch::new());
        assert_eq!(storage.state_root_hash(), Hash::ZERO);
    }

    #[test]
    fn test_jmt_version_increments_on_commit() {
        let storage = SimStorage::new(SyncDispatch::new());
        assert_eq!(storage.jmt_version(), 0);

        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        assert_eq!(storage.jmt_version(), 1);

        storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
        assert_eq!(storage.jmt_version(), 2);
    }

    #[test]
    fn test_state_root_changes_on_commit() {
        let storage = SimStorage::new(SyncDispatch::new());
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
        let s1 = SimStorage::new(SyncDispatch::new());
        let s2 = SimStorage::new(SyncDispatch::new());

        let updates = make_database_update(vec![1, 2, 3], 0, vec![10], vec![42]);
        s1.commit_shared(&updates);
        s2.commit_shared(&updates);

        assert_eq!(s1.state_root_hash(), s2.state_root_hash());
        assert_eq!(s1.jmt_version(), s2.jmt_version());
    }

    #[test]
    fn test_state_root_differs_for_different_data() {
        let s1 = SimStorage::new(SyncDispatch::new());
        let s2 = SimStorage::new(SyncDispatch::new());

        s1.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        s2.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![2]));

        assert_ne!(s1.state_root_hash(), s2.state_root_hash());
    }

    #[test]
    fn test_empty_commit_still_advances_version() {
        let storage = SimStorage::new(SyncDispatch::new());
        let updates = DatabaseUpdates::default();
        storage.commit_shared(&updates);
        assert_eq!(storage.jmt_version(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CommitStore
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_commit_block_single_cert() {
        let storage = SimStorage::new(SyncDispatch::new());
        let shard = ShardGroupId(0);
        let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
        let cert = Arc::new(make_test_certificate(1, shard));

        let result =
            CommitStore::<ConcreteConfig>::commit_block(&storage, &updates, &[cert], 1, None);
        assert_ne!(result, Hash::ZERO);
    }

    #[test]
    fn test_commit_block_multiple_certs() {
        let storage = SimStorage::new(SyncDispatch::new());
        let shard = ShardGroupId(0);
        let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
        let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
        let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
        let cert1 = Arc::new(make_test_certificate(1, shard));
        let cert2 = Arc::new(make_test_certificate(2, shard));

        let result = CommitStore::<ConcreteConfig>::commit_block(
            &storage,
            &merged,
            &[cert1, cert2],
            1,
            None,
        );
        // Certificate merging: all certs applied as single JMT version = block_height
        assert_ne!(result, Hash::ZERO);
    }

    #[test]
    fn test_commit_block_empty_certs() {
        let storage = SimStorage::new(SyncDispatch::new());
        CommitStore::<ConcreteConfig>::commit_block(
            &storage,
            &DatabaseUpdates::default(),
            &[],
            1,
            None,
        );
        // Empty block: JMT version still advances to block_height
        assert_eq!(storage.jmt_version(), 1);
    }

    #[test]
    fn test_prepare_then_commit_fast_path() {
        // Two identical storage instances: one uses prepare+commit, other uses commit_block.
        // Both should produce the same result.
        let s_prepared = SimStorage::new(SyncDispatch::new());
        let s_direct = SimStorage::new(SyncDispatch::new());
        let shard = ShardGroupId(0);
        let cert = Arc::new(make_test_certificate(1, shard));

        // Prepare path
        let parent_root = s_prepared.state_root_hash();
        let (spec_root, prepared) = CommitStore::<ConcreteConfig>::prepare_block_commit(
            &s_prepared,
            parent_root,
            &DatabaseUpdates::default(),
            1,
        );
        let certs = std::slice::from_ref(&cert);
        let result_prepared = CommitStore::<ConcreteConfig>::commit_prepared_block(
            &s_prepared,
            prepared,
            certs,
            None,
        );

        // Direct path
        let result_direct = CommitStore::<ConcreteConfig>::commit_block(
            &s_direct,
            &DatabaseUpdates::default(),
            std::slice::from_ref(&cert),
            1,
            None,
        );

        assert_eq!(result_prepared, result_direct);
        assert_eq!(spec_root, result_prepared);
    }

    #[test]
    fn test_prepare_commit_state_root_matches() {
        let storage = SimStorage::new(SyncDispatch::new());
        let shard = ShardGroupId(0);
        let cert = Arc::new(make_test_certificate(1, shard));

        let parent_root = storage.state_root_hash();
        let (spec_root, prepared) = CommitStore::<ConcreteConfig>::prepare_block_commit(
            &storage,
            parent_root,
            &DatabaseUpdates::default(),
            1,
        );
        let result =
            CommitStore::<ConcreteConfig>::commit_prepared_block(&storage, prepared, &[cert], None);

        assert_eq!(spec_root, result);
    }

    #[test]
    fn test_commit_certificate_individual() {
        let storage = SimStorage::new(SyncDispatch::new());
        let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
        let cert = make_test_certificate(1, ShardGroupId(0));

        storage.commit_certificate_with_writes(&cert, &updates);

        // Individual cert commits persist substate data + certificate metadata,
        // but JMT is deferred to block commit.
        assert_eq!(storage.jmt_version(), 0);
        assert_eq!(storage.state_root_hash(), Hash::ZERO);
        // Certificate should be stored
        assert!(storage.get_certificate(&cert.transaction_hash).is_some());
    }

    #[test]
    fn test_commit_block_stores_certificates() {
        let storage = SimStorage::new(SyncDispatch::new());
        let shard = ShardGroupId(0);
        let cert = Arc::new(make_test_certificate(1, shard));
        let tx_hash = cert.transaction_hash;

        let _ = CommitStore::<ConcreteConfig>::commit_block(
            &storage,
            &DatabaseUpdates::default(),
            &[cert],
            1,
            None,
        );

        assert!(storage.get_certificate(&tx_hash).is_some());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Utility methods
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_clear() {
        let mut storage = SimStorage::new(SyncDispatch::new());

        // Add some data
        storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
        let hash = Hash::from_bytes(&[1; 32]);
        storage.put_own_vote(10, 0, hash);
        assert!(storage.jmt_version() > 0);
        assert!(!storage.is_empty());

        storage.clear();

        assert_eq!(storage.jmt_version(), 0);
        assert_eq!(storage.state_root_hash(), Hash::ZERO);
        assert!(storage.is_empty());
        assert!(storage.get_own_vote(10).is_none());
    }

    #[test]
    fn test_len_and_is_empty() {
        let storage = SimStorage::new(SyncDispatch::new());
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
        let storage = SimStorage::new(SyncDispatch::new());
        let node_id = NodeId([1; 30]);

        // Commit two substates for the same node
        let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
        let updates2 = make_mapped_database_update(1, 0, vec![20], vec![200]);
        let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
        let cert = make_test_certificate(1, ShardGroupId(0));
        storage.commit_certificate_with_writes(&cert, &merged);

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

    #[test]
    fn test_list_substates_for_node_at_height_returns_historical_data() {
        let storage = SimStorage::new(SyncDispatch::new());
        let node_id = NodeId([1; 30]);
        let shard = ShardGroupId(0);

        // Block height 1: commit value [100] for node 1
        let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
        let cert1 = Arc::new(make_test_certificate(1, shard));
        let result1 =
            CommitStore::<ConcreteConfig>::commit_block(&storage, &updates1, &[cert1], 1, None);
        let root_v1 = result1;

        // Block height 2: overwrite with value [200]
        let updates2 = make_mapped_database_update(1, 0, vec![10], vec![200]);
        let cert2 = Arc::new(make_test_certificate(2, shard));
        let result2 =
            CommitStore::<ConcreteConfig>::commit_block(&storage, &updates2, &[cert2], 2, None);
        let root_v2 = result2;
        assert_ne!(root_v1, root_v2, "roots must differ after overwrite");

        // Read at version 1: should get the original value [100]
        let v1_substates = storage
            .list_substates_for_node_at_height(&node_id, 1)
            .expect("version 1 should be available");
        assert_eq!(v1_substates.len(), 1, "should find 1 substate at v1");
        assert_eq!(v1_substates[0].2, vec![100u8], "v1 value should be [100]");

        // Read at version 2: should get the overwritten value [200]
        let v2_substates = storage
            .list_substates_for_node_at_height(&node_id, 2)
            .expect("version 2 should be available");
        assert_eq!(v2_substates.len(), 1, "should find 1 substate at v2");
        assert_eq!(v2_substates[0].2, vec![200u8], "v2 value should be [200]");

        // Read for a nonexistent node: should be Some(empty)
        let other = storage
            .list_substates_for_node_at_height(&NodeId([99; 30]), 1)
            .expect("version 1 should be available even for unknown node");
        assert!(other.is_empty());

        // Read at a future version: should be None
        assert!(
            storage
                .list_substates_for_node_at_height(&node_id, 99)
                .is_none(),
            "future version should return None"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Receipt storage
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_receipt_storage_roundtrip() {
        let storage = SimStorage::new(SyncDispatch::new());
        hyperscale_storage::test_helpers::test_receipt_storage_roundtrip(&storage);
    }

    #[test]
    fn test_receipt_storage_synced() {
        let storage = SimStorage::new(SyncDispatch::new());
        hyperscale_storage::test_helpers::test_receipt_storage_synced(&storage);
    }

    #[test]
    fn test_receipt_batch_storage() {
        let storage = SimStorage::new(SyncDispatch::new());
        hyperscale_storage::test_helpers::test_receipt_batch_storage(&storage);
    }

    #[test]
    fn test_receipt_idempotent_overwrite() {
        let storage = SimStorage::new(SyncDispatch::new());
        hyperscale_storage::test_helpers::test_receipt_idempotent_overwrite(&storage);
    }
}
