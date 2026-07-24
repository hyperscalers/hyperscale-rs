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
//! - [`committee`]: shuffle step, beacon-committee resample, per-shard
//!   membership diff.
//! - [`epoch`]: top-level [`apply_epoch`] orchestration.
//! - [`governance`]: per-epoch network-parameter vote tally
//!   ([`tally_param_votes`](governance::tally_param_votes)).
//! - [`lifecycle`]: auto-reactivation, reward distribution, auto-ready
//!   timeout.
//! - [`pool`]: [`pool_draw`] — draw a `Pooled` validator onto a shard —
//!   and `exit_placement`, the inverse cascade shared by every
//!   shard-placement teardown.
//! - [`reshape`]: split observer-cohort draw and release.
//! - [`vrf`]: VRF reveal filter, randomness roll, `jail_validator`
//!   transition.
//! - [`withdrawals`]: pending-withdrawal maturation and the
//!   `deactivate_to_insufficient_stake` transition.
//! - [`witness`]: shard-lift dispatch and equivocation re-verification.

mod committee;
mod conviction;
mod epoch;
mod governance;
mod lifecycle;
mod pool;
mod reshape;
mod vrf;
mod withdrawals;
mod witness;

pub use epoch::{ApplyEpochInput, apply_epoch, apply_input_for};
pub use pool::pool_draw;

#[cfg(test)]
mod test_fixtures;
