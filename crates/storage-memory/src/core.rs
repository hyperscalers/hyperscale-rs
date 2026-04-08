//! Core `SimStorage` struct and basic implementations.
//!
//! In-memory storage for deterministic simulation testing (DST).
//! Uses `im::OrdMap` for O(1) structural-sharing clones.

use crate::state::{apply_updates_to_ordmap, ConsensusState, SharedState};

use hyperscale_storage::{
    jmt::NodeCache, keys, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue,
    PartitionEntry, SubstateDatabase,
};
use hyperscale_types::Hash;
#[cfg(test)]
use hyperscale_types::TransactionCertificate;
use std::sync::{Arc, RwLock};

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
/// for snapshots, node listing, and JVT state roots.
///
/// # Locking Strategy
///
/// Two RwLocks with independent lifetimes — no ordering constraint:
/// - `state`: Substate data + JVT tree store + version/root/associations.
///   Read lock for substate reads, JVT lookups, and speculative computation.
///   Write lock for commits (substate writes + JVT updates in one acquisition).
/// - `consensus`: Block metadata, certificates, votes, committed state.
///   Separate because consensus metadata is independent of substate/JVT state.
pub struct SimStorage {
    /// Substate data + JVT state (single RwLock).
    pub(crate) state: Arc<RwLock<SharedState>>,

    /// Consensus metadata (single RwLock).
    pub(crate) consensus: RwLock<ConsensusState>,

    /// JVT node cache — enables speculative proof generation at proposal time
    /// (before the block is committed to the tree store).
    pub(crate) node_cache: NodeCache,
}

impl Default for SimStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SimStorage {
    /// Create a new empty simulated storage.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SharedState::new())),
            consensus: RwLock::new(ConsensusState::new()),
            node_cache: NodeCache::new(),
        }
    }

    /// Get the current JVT version.
    pub fn current_jvt_version(&self) -> u64 {
        self.state.read().unwrap().current_block_height
    }

    /// Clear all data (useful for testing).
    pub fn clear(&mut self) {
        *self.state.write().unwrap() = SharedState::new();
        *self.consensus.write().unwrap() = ConsensusState::new();
        self.node_cache = NodeCache::new();
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
    pub(crate) fn iter_range(&self, start: &[u8], end: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let s = self.state.read().unwrap();
        s.data
            .range(start.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// Applies database updates and stores certificate metadata.
    /// JVT is deferred to block commit — this mirrors the production
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
            let ver = s.current_block_height;
            let crate::state::SharedState {
                ref mut data,
                ref mut versioned_substates,
                ..
            } = *s;
            apply_updates_to_ordmap(data, updates, Some((ver, versioned_substates)));
        }
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.transaction_hash, certificate.clone());
    }

    /// Test helper: commits database updates with auto-incrementing JVT version.
    /// Not used in production (use commit_block instead).
    ///
    /// Computes JVT updates and applies them to the tree store, resolving
    /// leaf-substate associations for historical reads.
    #[cfg(test)]
    pub fn commit_shared(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();

        let new_version = s.current_block_height + 1;

        // Apply substate updates first (visible for association resolution below).
        {
            let crate::state::SharedState {
                ref mut data,
                ref mut versioned_substates,
                ..
            } = *s;
            apply_updates_to_ordmap(data, updates, Some((new_version, versioned_substates)));
        }

        let parent_version =
            hyperscale_storage::jvt_parent_height(s.current_block_height, s.current_root_hash);
        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            new_version,
            updates,
            &Default::default(),
            &self.node_cache,
        );

        self.node_cache.populate(&collected.nodes);
        collected.apply_to(&s.tree_store);

        s.current_block_height = new_version;
        s.current_root_hash = new_root;
    }

    /// Write only substate data (no JVT computation).
    ///
    /// Used during genesis bootstrap so each intermediate `commit()` call from the
    /// Radix Engine writes substates without computing a JVT version.
    /// After all genesis commits complete, [`finalize_genesis_jvt`] computes the
    /// JVT once at version 0.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();
        // Genesis: no version tracking, write at version 0.
        let crate::state::SharedState {
            ref mut data,
            ref mut versioned_substates,
            ..
        } = *s;
        apply_updates_to_ordmap(data, updates, Some((0, versioned_substates)));
    }

    /// Compute the JVT once at version 0 from the merged genesis updates.
    ///
    /// Called after all genesis bootstrap commits are complete. This avoids
    /// computing intermediate JVT versions during genesis (which would collide
    /// with block 1's version).
    ///
    /// # Returns
    /// The genesis state root hash (JVT root at version 0).
    pub fn finalize_genesis_jvt(&self, merged: &DatabaseUpdates) -> Hash {
        let mut s = self.state.write().unwrap();

        // Guard: finalize_genesis_jvt must only be called once, on an uninitialized JVT.
        assert!(
            s.current_block_height == 0 && s.current_root_hash == Hash::ZERO,
            "finalize_genesis_jvt called but JVT already initialized"
        );

        // parent=None, version=0: genesis is the first JVT state.
        let (root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            None,
            0,
            merged,
            &Default::default(),
            &self.node_cache,
        );

        self.node_cache.populate(&collected.nodes);
        collected.apply_to(&s.tree_store);

        s.current_block_height = 0;
        s.current_root_hash = root;

        root
    }
}

impl hyperscale_storage::SubstatesOnlyCommit for SimStorage {
    fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        SimStorage::commit_substates_only(self, updates);
    }
}

impl SubstateDatabase for SimStorage {
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

#[cfg(test)]
impl hyperscale_storage::CommittableSubstateDatabase for SimStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.commit_shared(updates);
    }
}
