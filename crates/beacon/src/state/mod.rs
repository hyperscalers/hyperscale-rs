//! Beacon state machinery — `apply_epoch` pipeline plus derived
//! helpers over [`BeaconState`](hyperscale_types::BeaconState).
//!
//! The data shapes themselves live in
//! [`hyperscale_types::beacon::state`]; this module hosts the behavior
//! that mutates them and the pure helpers that depend on beacon-side
//! protocol constants. Every helper re-derives its value from state —
//! no caching, no two-piece state to keep in sync.
//!
//! Pipeline modules:
//!
//! - [`derived`]: pure queries (`min_stake`, `effective_stake`,
//!   `pooled_validators`, `derive_topology_snapshot`, …).
//! - [`pool`]: [`pool_draw`] — draw a `Pooled` validator onto a shard.
//! - [`vrf`]: VRF reveal filter, randomness roll, `jail_validator`
//!   cascade primitive.
//! - [`witness`]: shard-lift dispatch and equivocation re-verification.
//! - [`withdrawals`]: pending-withdrawal maturation and the shared
//!   `deactivate_to_insufficient_stake` primitive.
//! - [`lifecycle`]: auto-reactivation, reward distribution, auto-ready
//!   timeout.
//! - [`committee`]: shuffle step, beacon-committee resample, per-shard
//!   membership diff.
//! - [`epoch`]: top-level [`apply_epoch`] orchestration.

mod committee;
mod derived;
mod epoch;
mod lifecycle;
mod pool;
mod vrf;
mod withdrawals;
mod witness;

pub use derived::{
    beacon_eligible, current_active_count, derive_active_pool, derive_beacon_committee,
    derive_topology_snapshot, effective_stake, max_active_count, min_stake, pooled_validators,
};
pub use epoch::{ApplyEpochInput, apply_epoch, apply_recovery_or_resample};
pub use pool::pool_draw;

#[cfg(test)]
mod test_fixtures;
