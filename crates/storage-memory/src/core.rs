//! Core `SimStorage` struct and basic implementations.
//!
//! In-memory storage for deterministic simulation testing (DST).
//! Uses `im::OrdMap` for O(1) structural-sharing clones.

use crate::state::{apply_updates_to_ordmap, ConsensusState, SharedState};

use hyperscale_storage::{
    keys, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry,
    SubstateDatabase,
};
use hyperscale_types::Hash;
#[cfg(test)]
use hyperscale_types::WaveCertificate;
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
pub struct SimStorage {
    /// Substate data + JMT state (single RwLock).
    pub(crate) state: Arc<RwLock<SharedState>>,

    /// Consensus metadata (single RwLock).
    pub(crate) consensus: RwLock<ConsensusState>,
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
    /// JMT is deferred to block commit — this mirrors the production
    /// `RocksDbStorage::commit_certificate_with_writes()` to ensure DST
    /// catches timing bugs where code incorrectly assumes state is available
    /// before certificate persistence.
    #[cfg(test)]
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &WaveCertificate,
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
            .insert(certificate.wave_id.hash(), certificate.clone());
    }

    /// Test helper: commits database updates with auto-incrementing JMT version.
    /// Not used in production (use commit_block instead).
    ///
    /// Computes JMT updates and applies them to the tree store, resolving
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

        let parent_version = hyperscale_storage::tree::jmt_parent_height(
            s.current_block_height,
            s.current_root_hash,
        );
        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            parent_version,
            new_version,
            &[updates],
            &Default::default(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }

        s.current_block_height = new_version;
        s.current_root_hash = new_root;
    }

    /// Write only substate data (no JMT computation).
    ///
    /// Used during genesis bootstrap so each intermediate `commit()` call from the
    /// Radix Engine writes substates without computing a JMT version.
    /// After all genesis commits complete, [`finalize_genesis_jmt`] computes the
    /// JMT once at version 0.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();
        // Skip MVCC writes during bootstrap — intermediate Reset partitions
        // could tombstone values that later commits re-add, leaving holes in
        // version-0 history. `finalize_genesis_jmt` writes the merged final
        // state to `versioned_substates` in a single pass.
        let crate::state::SharedState { ref mut data, .. } = *s;
        apply_updates_to_ordmap(data, updates, None);
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
        let (root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            None,
            0,
            &[merged],
            &Default::default(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }

        // Populate MVCC history from the merged genesis updates in one pass.
        // Bootstrap intentionally skipped versioned writes to avoid Reset
        // tombstones masking later re-writes at version 0.
        Self::write_merged_versioned_at(&mut s.versioned_substates, merged, 0);

        s.current_block_height = 0;
        s.current_root_hash = root;

        root
    }

    fn write_merged_versioned_at(
        versioned: &mut crate::state::VersionedSubstateStore,
        updates: &DatabaseUpdates,
        version: u64,
    ) {
        use hyperscale_storage::{keys, DatabaseUpdate, DbPartitionKey, PartitionDatabaseUpdates};
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
                                    versioned.insert((key, version), Some(value.clone()));
                                }
                                DatabaseUpdate::Delete => {
                                    versioned.insert((key, version), None);
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        for (sort_key, value) in new_substate_values {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            versioned.insert((key, version), Some(value.clone()));
                        }
                    }
                }
            }
        }
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
