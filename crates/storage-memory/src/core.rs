//! Core `SimStorage` struct and basic implementations.
//!
//! In-memory storage for deterministic simulation testing (DST).
//! Substates are held in a single MVCC store: `(storage_key, version) →
//! Option<value>`. "Current state" is derived by walking the latest entry
//! per key; historical reads anchor to any version in the retention window.

use crate::state::{apply_updates, ConsensusState, SharedState};

use hyperscale_storage::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use hyperscale_types::Hash;
#[cfg(test)]
use hyperscale_types::WaveCertificate;
use std::sync::{Arc, RwLock};

/// In-memory storage for simulation and testing.
///
/// All substates live in an MVCC-versioned BTreeMap — the single source
/// of truth. This mirrors `RocksDbStorage`'s single-CF design and avoids
/// the dual-write / divergence class of bugs that a separate "current
/// state" structure would introduce.
///
/// Implements Radix's `SubstateDatabase` directly, plus our `SubstateStore` /
/// `VersionedStore` extensions for snapshots, node listing, and JMT state
/// roots.
///
/// # Locking Strategy
///
/// Two RwLocks with independent lifetimes — no ordering constraint:
/// - `state`: MVCC substate store + JMT tree store + version/root/associations.
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

    /// Number of MVCC substate entries. Approximates "size" — a single
    /// key with many historical versions counts as multiple entries.
    pub fn len(&self) -> usize {
        self.state.read().unwrap().substates.len()
    }

    /// Whether the MVCC substate store has any entries.
    pub fn is_empty(&self) -> bool {
        self.state.read().unwrap().substates.is_empty()
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
            apply_updates(&mut s.substates, updates, ver);
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
        apply_updates(&mut s.substates, updates, new_version);

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

    /// Write substate data at version 0 (no JMT computation).
    ///
    /// Used during genesis bootstrap for each incremental Radix-engine
    /// commit. Writes go into the MVCC store at version 0 so reads during
    /// subsequent bootstrap calls see the accumulated state. After all
    /// genesis commits, [`finalize_genesis_jmt`] computes the JMT once.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();
        apply_updates(&mut s.substates, updates, 0);
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
        // Default-version snapshot (= current committed tip) reads the
        // latest value via MVCC walk-back.
        <Self as hyperscale_storage::SubstateStore>::snapshot(self)
            .get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let items: Vec<_> = <Self as hyperscale_storage::SubstateStore>::snapshot(self)
            .list_raw_values_from_db_key(partition_key, from_sort_key)
            .collect();
        Box::new(items.into_iter())
    }
}

#[cfg(test)]
impl hyperscale_storage::CommittableSubstateDatabase for SimStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.commit_shared(updates);
    }
}
