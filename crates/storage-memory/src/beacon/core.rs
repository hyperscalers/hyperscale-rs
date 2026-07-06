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

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use hyperscale_types::{
    BeaconBlockHash, BeaconState, CertifiedBeaconBlock, Epoch, RatifyVoteRecord, ValidatorId,
    Verified,
};

/// In-memory implementation of the beacon storage tier.
///
/// Backs `SimulationRunner`'s process-level beacon chain. One
/// `Arc<SimBeaconStorage>` is shared across every vnode's
/// `BeaconCoordinator`.
#[derive(Debug, Default)]
pub struct SimBeaconStorage {
    pub(super) inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)] // every map is keyed by epoch; the postfix IS the key axis
pub(super) struct Inner {
    /// Primary block store keyed by epoch. `BTreeMap` so iteration is
    /// naturally epoch-ordered for latest-key lookup.
    pub(super) blocks_by_epoch: BTreeMap<Epoch, Arc<Verified<CertifiedBeaconBlock>>>,
    /// Secondary index `block_hash → epoch`.
    pub(super) hash_to_epoch: BTreeMap<BeaconBlockHash, Epoch>,
    /// Parallel state store keyed by epoch. Written in the same
    /// critical section as `blocks_by_epoch` so the pair never drifts.
    pub(super) state_by_epoch: BTreeMap<Epoch, Arc<BeaconState>>,
    /// Per-validator durable ratification registers. Mirrors the
    /// production `ratify_registers` CF.
    pub(super) ratify_records: HashMap<ValidatorId, RatifyVoteRecord>,
}

impl SimBeaconStorage {
    /// Construct an empty in-memory beacon store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
