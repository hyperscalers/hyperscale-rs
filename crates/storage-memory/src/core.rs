//! Core `SimStorage` struct and basic implementations.
//!
//! In-memory storage for deterministic simulation testing (DST).
//! Substates live in two `BTreeMaps`: `current_state: (storage_key →
//! value)` for current-tip reads, and `state_history: ((storage_key,
//! write_version) → Option<prior>)` for historical reads. A read at
//! version V below the current tip uses a single forward seek on
//! `state_history` to find the smallest write after V; its prior value
//! is the state at V.

use crate::state::{ConsensusState, SharedState, apply_updates};

use hyperscale_storage::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
#[cfg(test)]
use hyperscale_types::WaveCertificate;
use hyperscale_types::{BlockHeight, StateRoot};
use std::sync::{Arc, RwLock};

/// In-memory storage for simulation and testing.
///
/// Substates live in a `current_state` `BTreeMap` (authoritative for
/// current-tip reads) with a companion `state_history` `BTreeMap`
/// capturing per-write prior values for historical reads. This mirrors
/// `RocksDbStorage`'s two-CF layout.
///
/// Implements Radix's `SubstateDatabase` directly, plus our `SubstateStore` /
/// `VersionedStore` extensions for snapshots, node listing, and JMT state
/// roots.
///
/// # Locking Strategy
///
/// Two `RwLocks` with independent lifetimes — no ordering constraint:
/// - `state`: `current_state` + state-history log + JMT tree store + version/root/associations.
///   Read lock for substate reads, JMT lookups, and speculative computation.
///   Write lock for commits (substate writes + JMT updates in one acquisition).
/// - `consensus`: Block metadata, certificates, votes, committed state.
///   Separate because consensus metadata is independent of substate/JMT state.
pub struct SimStorage {
    /// Substate data + JMT state (single `RwLock`).
    pub(crate) state: Arc<RwLock<SharedState>>,

    /// Consensus metadata (single `RwLock`).
    pub(crate) consensus: RwLock<ConsensusState>,

    /// Retention window for historical substate reads. `snapshot_at(V)`
    /// panics if `V < current_version - jmt_history_length` (saturating).
    /// Defaults to `u64::MAX` so tests keep working — deliberately set
    /// a smaller value in tests that want to exercise retention
    /// behaviour.
    pub(crate) jmt_history_length: u64,
}

impl Default for SimStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SimStorage {
    /// Create a new empty simulated storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SharedState::new())),
            consensus: RwLock::new(ConsensusState::new()),
            jmt_history_length: u64::MAX,
        }
    }

    /// Create storage with a specific retention window. Used by tests
    /// that exercise the retention panic.
    #[must_use]
    pub fn with_jmt_history_length(jmt_history_length: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(SharedState::new())),
            consensus: RwLock::new(ConsensusState::new()),
            jmt_history_length,
        }
    }

    /// Clear all data (useful for testing).
    ///
    /// # Panics
    ///
    /// Panics if either internal `RwLock` is poisoned.
    pub fn clear(&mut self) {
        *self.state.write().unwrap() = SharedState::new();
        *self.consensus.write().unwrap() = ConsensusState::new();
    }

    /// Number of live substate entries (current tip). Historical
    /// state-history entries are not counted — use
    /// `.state.read().state_history.len()` for that.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.read().unwrap().current_state.len()
    }

    /// Whether the substate store has any live entries.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.read().unwrap().current_state.is_empty()
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// Applies database updates and stores certificate metadata.
    /// JMT is deferred to block commit — this mirrors the production
    /// `RocksDbStorage::commit_certificate_with_writes()` to ensure DST
    /// catches timing bugs where code incorrectly assumes state is available
    /// before certificate persistence.
    ///
    /// # Panics
    ///
    /// Panics if either internal `RwLock` is poisoned.
    #[cfg(test)]
    #[allow(clippy::significant_drop_tightening)] // both reads need the lock
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &WaveCertificate,
        updates: &hyperscale_storage::DatabaseUpdates,
    ) {
        {
            let mut s = self.state.write().unwrap();
            let ver = s.current_block_height.0;
            apply_updates(&mut s, updates, ver, /* write_history */ true);
        }
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.wave_id.hash(), certificate.clone());
    }

    /// Test helper: commits database updates with auto-incrementing JMT version.
    /// Not used in production (use `commit_block` instead).
    ///
    /// Computes JMT updates and applies them to the tree store, resolving
    /// leaf-substate associations for historical reads.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[cfg(test)]
    pub fn commit_shared(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();

        let new_version = s.current_block_height.0 + 1;

        // Apply substate updates first (visible for association resolution below).
        apply_updates(&mut s, updates, new_version, /* write_history */ true);

        let parent_version = hyperscale_storage::tree::jmt_parent_height(
            s.current_block_height,
            s.current_root_hash,
        )
        .map(|h| h.0);
        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            parent_version,
            new_version,
            &[updates],
            &std::collections::HashMap::new(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }

        s.current_block_height = BlockHeight(new_version);
        s.current_root_hash = new_root;
    }

    /// Write substate data at version 0 (no JMT computation).
    ///
    /// Genesis-install primitive: writes land in `current_state` at version 0
    /// with **no state-history entries** — genesis has no pre-state to
    /// preserve. Pair with [`Self::finalize_genesis_jmt`] to compute the JMT
    /// root over the same updates; [`hyperscale_storage::GenesisCommit::install_genesis`]
    /// composes both.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();
        apply_updates(&mut s, updates, 0, /* write_history */ false);
    }

    /// Compute the JMT once at version 0 from the merged genesis updates.
    ///
    /// Called after [`Self::commit_substates_only`] has placed the substates
    /// in `current_state`; this adds the JMT tree at version 0 so block 1
    /// writes cleanly at version 1.
    ///
    /// # Returns
    /// The genesis state root hash (JMT root at version 0).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned, or if the JMT has
    /// already been initialized.
    pub fn finalize_genesis_jmt(&self, merged: &DatabaseUpdates) -> StateRoot {
        let mut s = self.state.write().unwrap();

        // Guard: finalize_genesis_jmt must only be called once, on an uninitialized JMT.
        assert!(
            s.current_block_height == BlockHeight::GENESIS
                && s.current_root_hash == StateRoot::ZERO,
            "finalize_genesis_jmt called but JMT already initialized"
        );

        // parent=None, version=0: genesis is the first JMT state.
        let (root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            None,
            0,
            &[merged],
            &std::collections::HashMap::new(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }

        s.current_block_height = BlockHeight::GENESIS;
        s.current_root_hash = root;

        root
    }
}

impl hyperscale_storage::GenesisCommit for SimStorage {
    fn install_genesis(&self, merged: &DatabaseUpdates) -> StateRoot {
        Self::commit_substates_only(self, merged);
        Self::finalize_genesis_jmt(self, merged)
    }
}

impl SubstateDatabase for SimStorage {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        // Default-version snapshot (= current committed tip) reads the
        // latest value from `current_state`.
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
