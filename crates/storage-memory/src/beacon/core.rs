//! Core `SimBeaconStorage` struct.
//!
//! In-memory beacon-chain storage for deterministic simulation testing.
//! Holds three maps under a single `RwLock`: a primary `epoch → block`
//! store, a secondary `block_hash → epoch` index, and a parallel
//! `epoch → state` store. All three update atomically on commit so
//! reads observe a consistent (block, state) pair for any committed
//! epoch.
//!
//! Used by `SimulationRunner`; one `Arc<SimBeaconStorage>` per process
//! is shared across every vnode's `BeaconCoordinator`.

use std::sync::{Arc, RwLock};

use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_types::{
    Address, BeaconBlockHash, BeaconState, BeaconVoteRecord, CertifiedBeaconBlock, Epoch, Hash,
    RatifyVoteRecord, ValidatorId, Verified,
};
use im::OrdMap;

/// In-memory implementation of the beacon storage tier.
///
/// Backs `SimulationRunner`'s process-level beacon chain. One
/// `Arc<SimBeaconStorage>` is shared across every vnode's
/// `BeaconCoordinator`.
#[derive(Debug, Default)]
pub struct SimBeaconStorage {
    pub(super) inner: RwLock<Inner>,
    /// The store as its last synced write left it: what survives a
    /// machine that loses power. `None` until a write syncs.
    durable: RwLock<Option<Inner>>,
}

#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_field_names)] // every map is keyed by epoch; the postfix IS the key axis
pub(super) struct Inner {
    /// Primary block store keyed by epoch. `BTreeMap` so iteration is
    /// naturally epoch-ordered for latest-key lookup.
    pub(super) blocks_by_epoch: OrdMap<Epoch, Arc<Verified<CertifiedBeaconBlock>>>,
    /// Secondary index `block_hash → epoch`.
    pub(super) hash_to_epoch: OrdMap<BeaconBlockHash, Epoch>,
    /// Parallel state store keyed by epoch. Written in the same
    /// critical section as `blocks_by_epoch` so the pair never drifts.
    pub(super) state_by_epoch: OrdMap<Epoch, Arc<BeaconState>>,
    /// Per-validator durable ratification registers. Mirrors the
    /// production `ratify_registers` CF.
    pub(super) ratify_records: OrdMap<ValidatorId, RatifyVoteRecord>,
    /// Per-validator durable beacon consensus registers. Mirrors the
    /// production `beacon_vote_registers` CF.
    pub(super) beacon_vote_records: OrdMap<ValidatorId, BeaconVoteRecord>,
    /// Fetched package artifacts by content address. Mirrors the
    /// production `fetched_packages` CF.
    pub(super) fetched_packages: OrdMap<Hash, Vec<u8>>,
    /// Fetched component records by the address each derives. Mirrors
    /// the production `fetched_instances` CF.
    pub(super) fetched_instances: OrdMap<Address, Vec<u8>>,
}

impl SimBeaconStorage {
    /// Construct an empty in-memory beacon store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every write so far durable, as a synced write does.
    pub(super) fn sync(&self) {
        let image = read_or_recover(&self.inner).clone();
        *write_or_recover(&self.durable) = Some(image);
    }

    /// Lose every write since the last synced one, as a machine that
    /// loses power does; a store no write has synced comes back empty.
    pub fn lose_unsynced(&self) {
        let image = read_or_recover(&self.durable).clone().unwrap_or_default();
        *write_or_recover(&self.inner) = image;
    }
}
