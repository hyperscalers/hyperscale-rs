//! Core `SimShardStorage` struct and basic implementations.
//!
//! In-memory storage for deterministic simulation testing (DST).
//! Substates live in two `BTreeMaps`: `current_state: (storage_key →
//! value)` for current-tip reads, and `state_history: ((storage_key,
//! write_version) → Option<prior>)` for historical reads. A read at
//! version V below the current tip uses a single forward seek on
//! `state_history` to find the smallest write after V; its prior value
//! is the state at V.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use hyperscale_jmt::NibblePath;
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::put_at_version;
use hyperscale_storage::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue, GenesisCommit, PartitionEntry,
    RecoveredState, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHeight, Hash, NodeId, QuorumCertificate, StateRoot, Verified,
};

use super::state::{ConsensusState, SharedState, apply_updates};

/// In-memory storage for simulation and testing.
///
/// Substates live in a `current_state` `BTreeMap` (authoritative for
/// current-tip reads) with a companion `state_history` `BTreeMap`
/// capturing per-write prior values for historical reads. This mirrors
/// `RocksDbShardStorage`'s two-CF layout.
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
///
/// Every field is behind a shared handle, so a [`Clone`] is another
/// handle onto the *same* store — the in-memory analogue of
/// production's `SharedStorage` wrapper over one `RocksDB` instance. A
/// shard's storage can therefore be retained across a runtime
/// leave/rejoin cycle.
#[derive(Clone)]
pub struct SimShardStorage {
    /// Substate data + JMT state (single `RwLock`).
    pub(crate) state: Arc<RwLock<SharedState>>,

    /// Consensus metadata (single `RwLock`).
    pub(crate) consensus: Arc<RwLock<ConsensusState>>,

    /// Retention window for historical substate reads. `snapshot_at(V)`
    /// panics if `V < current_version - jmt_history_length` (saturating).
    /// Defaults to `u64::MAX` so tests keep working — deliberately set
    /// a smaller value in tests that want to exercise retention
    /// behaviour.
    pub(crate) jmt_history_length: u64,

    /// Boundary heights pinned for snap-sync serving. The in-memory
    /// store retains every JMT version, so a pin is pure bookkeeping —
    /// kept under the production ring's retention so eviction behaviour
    /// is observable in simulation too.
    pub(crate) boundary_pins: Arc<RwLock<BTreeSet<BlockHeight>>>,
}

impl Default for SimShardStorage {
    /// Whole-keyspace (empty-prefix) store — the single-shard / test default.
    fn default() -> Self {
        Self::new(NibblePath::empty())
    }
}

impl SimShardStorage {
    /// Create a new empty simulated storage rooted at `root_path` — the prefix
    /// of the shard it serves (via [`hyperscale_types::shard_prefix_path`]), so
    /// its `state_root` is the global tree's subtree at that prefix. Pass
    /// [`NibblePath::empty`] (or use [`Self::default`]) for a single-shard /
    /// whole-keyspace store.
    #[must_use]
    pub fn new(root_path: NibblePath) -> Self {
        let mut shared = SharedState::new();
        shared.tree_store.set_root_path(root_path);
        Self {
            state: Arc::new(RwLock::new(shared)),
            consensus: Arc::new(RwLock::new(ConsensusState::new())),
            jmt_history_length: u64::MAX,
            boundary_pins: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    /// Create storage with a specific retention window. Used by tests
    /// that exercise the retention panic.
    #[must_use]
    pub fn with_jmt_history_length(jmt_history_length: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(SharedState::new())),
            consensus: Arc::new(RwLock::new(ConsensusState::new())),
            jmt_history_length,
            boundary_pins: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    /// Clear all data (useful for testing).
    ///
    /// # Panics
    ///
    /// Panics if either internal `RwLock` is poisoned.
    pub fn clear(&mut self) {
        *write_or_recover(&self.state) = SharedState::new();
        *write_or_recover(&self.consensus) = ConsensusState::new();
        write_or_recover(&self.boundary_pins).clear();
    }

    /// Load recovered state for restarting a state machine on this
    /// store — the in-memory analogue of
    /// `RocksDbShardStorage::load_recovered_state`. A fresh store
    /// reads back at genesis with `jmt_root` pinned to the empty
    /// root.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    #[must_use]
    pub fn load_recovered_state(&self) -> RecoveredState {
        let c = read_or_recover(&self.consensus);
        let committed_height = c.committed_height;
        let committed_hash = c.committed_hash;
        let latest_qc = c
            .committed_qc
            .clone()
            .map(Verified::<QuorumCertificate>::from_persisted);
        let committed_anchor_ts = c
            .blocks
            .get(&committed_height)
            .map(|block| block.block().header().parent_qc().weighted_timestamp());
        // The accumulator window starts at the tip's witness base;
        // retained entries below it are the persistence layer's
        // hysteresis stock — serving data, not accumulator state.
        let beacon_witness_start = c
            .blocks
            .get(&committed_height)
            .map_or(BeaconWitnessLeafCount::ZERO, |block| {
                block.block().header().beacon_witness_base()
            });
        let beacon_witness_leaf_hashes: Vec<Hash> = c
            .beacon_witnesses
            .range(beacon_witness_start.inner()..)
            .map(|(_, payload)| payload.leaf_hash())
            .collect();
        let chain_origin = c.chain_origin;
        // Records tagged with a different chain origin belong to a
        // previous incarnation of this store's chain and are excluded.
        let safe_vote_registers = c
            .safe_vote_registers
            .iter()
            .filter(|(_, (origin, _))| *origin == chain_origin)
            .map(|(validator, (_, registers))| (*validator, *registers))
            .collect();
        drop(c);

        RecoveredState {
            committed_height,
            committed_hash,
            latest_qc,
            anchor_qc: None,
            committed_in_flight: None,
            committed_anchor_ts,
            jmt_root: Some(self.state_root()),
            beacon_witness_start,
            beacon_witness_leaf_hashes,
            substate_bytes: read_or_recover(&self.state)
                .substate_bytes
                .get(&committed_height.inner())
                .copied()
                .unwrap_or(0),
            chain_origin,
            safe_vote_registers,
        }
    }

    /// Committed substate byte total recorded at `version`, if any.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn substate_bytes_at_version(&self, version: u64) -> Option<u64> {
        read_or_recover(&self.state)
            .substate_bytes
            .get(&version)
            .copied()
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
        read_or_recover(&self.state).current_state.len()
    }

    /// Whether the substate store has any live entries.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        read_or_recover(&self.state).current_state.is_empty()
    }

    /// Write substate data at version 0 (no JMT computation).
    ///
    /// Genesis-install primitive: writes land in `current_state` at version 0
    /// with **no state-history entries** — genesis has no pre-state to
    /// preserve. Pair with [`Self::finalize_genesis_jmt`] to compute the JMT
    /// root over the same updates; [`GenesisCommit::install_genesis`]
    /// composes both.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn commit_substates_only(&self, updates: &DatabaseUpdates) {
        let mut s = write_or_recover(&self.state);
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
    #[must_use]
    #[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
    pub fn finalize_genesis_jmt(
        &self,
        merged: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot {
        let mut s = write_or_recover(&self.state);

        // Guard: finalize_genesis_jmt must only be called once, on an uninitialized JMT.
        assert!(
            s.current_block_height == BlockHeight::GENESIS
                && s.current_root_hash == StateRoot::ZERO,
            "finalize_genesis_jmt called but JMT already initialized"
        );

        // parent=None, version=0: genesis is the first JMT state.
        let (root, collected) = put_at_version(
            &s.tree_store,
            None,
            0,
            &[merged],
            &HashMap::new(),
            owner_map,
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }
        // Genesis leaves must be resolvable for snap-sync serving like
        // any other commit's — every path that writes JMT leaves applies
        // its collected associations.
        for a in collected.leaf_associations {
            if let Some(storage_key) = a.storage_key {
                s.associations.insert(a.leaf_key, storage_key);
            }
        }

        let genesis_count =
            u64::try_from(collected.bytes_delta).expect("genesis leaf delta must be non-negative");
        s.substate_bytes
            .insert(BlockHeight::GENESIS.inner(), genesis_count);

        s.current_block_height = BlockHeight::GENESIS;
        s.current_root_hash = root;

        root
    }
}

impl GenesisCommit for SimShardStorage {
    fn install_genesis(
        &self,
        substates: &DatabaseUpdates,
        jmt_updates: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot {
        Self::commit_substates_only(self, substates);
        Self::finalize_genesis_jmt(self, jmt_updates, owner_map)
    }

    fn replicate_genesis_substates(&self, substates: &DatabaseUpdates) {
        Self::commit_substates_only(self, substates);
    }
}

impl SubstateDatabase for SimShardStorage {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        // Default-version snapshot (= current committed tip) reads the
        // latest value from `current_state`.
        <Self as SubstateStore>::snapshot(self).get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        #[allow(clippy::needless_collect)] // snapshot iterator borrows from temporary
        let items: Vec<_> = <Self as SubstateStore>::snapshot(self)
            .list_raw_values_from_db_key(partition_key, from_sort_key)
            .collect();
        Box::new(items.into_iter())
    }
}
