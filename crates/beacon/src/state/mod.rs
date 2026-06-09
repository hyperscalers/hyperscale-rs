//! Beacon state machinery — the `apply_epoch` pipeline over
//! [`BeaconState`](hyperscale_types::BeaconState).
//!
//! Data shapes and pure derived queries (`min_stake`,
//! `effective_stake`, `derive_topology_snapshot`, …) live as inherent
//! methods on `BeaconState` / `StakePool` in
//! [`hyperscale_types::beacon::state`]. This module hosts only the
//! behavior that mutates state.
//!
//! Pipeline modules:
//!
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
mod epoch;
mod lifecycle;
mod pool;
mod vrf;
mod withdrawals;
mod witness;

pub(crate) use epoch::epoch_boundary_below;
pub use epoch::{ApplyEpochInput, apply_epoch, apply_input_for};
pub use pool::pool_draw;
pub(crate) use witness::{chunk_bounds, contribution_chunk_valid};

#[cfg(test)]
mod test_fixtures;
