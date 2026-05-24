//! Protocol-invariant constants governing beacon-chain state transitions.
//!
//! Every value here is consensus-critical: two validators that disagree on
//! any of these can't share a chain. They're declared as `pub const` (not
//! a `BeaconConfig` struct) so that altering one is a visible source-level
//! edit, not a runtime knob someone can tweak by accident.
//!
//! Consumed by `BeaconState::apply_slot` (Phase B.5) to drive shuffles,
//! jail cooldowns, unbonding windows, and reward emission. Workspace-wide
//! timing constants ([`EPOCH_DURATION`](hyperscale_types::EPOCH_DURATION)
//! and friends) live in [`hyperscale_types::time`].
//!
//! # Slots vs epochs
//!
//! Time-scoped constants are denominated in **epochs**, never slots.
//! Recovery slots can wedge in mid-epoch without representing real
//! elapsed time, so anything counting wall-clock duration (cooldowns,
//! unbonding windows, shuffle cadence) keys off epoch transitions to
//! stay faithful to time even when consensus stalls and recovers.
//!
//! The numerical values are ported from the prototype's defaults — fine
//! for tests, almost certainly wrong for production (e.g. a 32-epoch
//! unbonding window is ≈ 2.5 hours at 5-min epochs, where real networks
//! use weeks). Tuning lands when operational data warrants.

use hyperscale_types::Stake;

// ─── Committee sizing ──────────────────────────────────────────────────────

/// Target signer count for the global (beacon) committee.
pub const BEACON_SIGNER_COUNT: usize = 4;

/// Members per shard.
///
/// Sized to accommodate signer target plus a small headroom for in-sync
/// newcomers and jail churn.
pub const SHARD_CAPACITY: usize = 4;

// ─── Validator admission ───────────────────────────────────────────────────

/// Hard floor under the per-node minimum stake.
///
/// Even when the network has very few staked validators, a stake pool
/// must hold at least this much stake per active node to support it.
/// The dynamic per-node minimum clamps up to this floor as a
/// Sybil-resistance backstop.
pub const MIN_STAKE_FLOOR: Stake = Stake::from_whole_tokens(1_000_000);

/// Target buffer of unplaced (`Pooled`) validators in the global pool.
///
/// Drives the admit-threshold half of the dynamic per-node minimum
/// stake: the value floats down to admit enough registrations to keep
/// this many validators available for jail- or exit-triggered pool
/// draws.
pub const POOL_BUFFER_TARGET: usize = 4;

// ─── Lifecycle cadences ────────────────────────────────────────────────────

/// One validator rotates out of a shard back to the pool every this
/// many epochs.
///
/// The opened slot triggers an immediate pool draw on the same shard.
pub const SHUFFLE_INTERVAL_EPOCHS: u64 = 16;

/// Cap on how long a placed validator can sit `OnShard { ready: false }`
/// before beacon auto-flips them to `ready: true`.
///
/// The shard's natural miss-counter then catches anyone who was never
/// actually synced.
pub const READY_TIMEOUT_EPOCHS: u64 = 32;

// ─── Penalties ─────────────────────────────────────────────────────────────

/// How long a fault-cause jail must elapse before an `Unjail` lift can
/// return the validator to `Pooled`.
///
/// Applies to performance and recovery jail reasons; equivocation jail
/// is permanent regardless of this value.
pub const JAIL_COOLDOWN_EPOCHS: u64 = 16;

/// How long a stake-pool withdrawal request remains pending before its
/// amount is released and any resulting auto-deactivations apply.
///
/// Long enough that late-arriving equivocation evidence can still mark
/// byzantine validators permanently before their pool's stake fully
/// escapes.
pub const UNBONDING_WINDOW_EPOCHS: u64 = 32;

// ─── Economics ─────────────────────────────────────────────────────────────

/// Target annual emission envelope in whole tokens.
pub const TOKENS_PER_YEAR_TARGET: u64 = 300_000_000;

/// Epochs per year at the target epoch cadence.
///
/// `(60 / 5) * 24 * 365` at 5-minute epochs
/// ([`EPOCH_DURATION`](hyperscale_types::EPOCH_DURATION)). Maintainers
/// who change `EPOCH_DURATION` must update this number too.
pub const EPOCHS_PER_YEAR: u64 = (60 / 5) * 24 * 365;

/// Per-epoch tokens credited to active stake pools, split pro-rata
/// across pools by their count of `OnShard { ready: true }` validators.
///
/// Computed as `TOKENS_PER_YEAR_TARGET / EPOCHS_PER_YEAR` in attos, so
/// the annual sum equals the target modulo per-epoch attos rounding
/// (remainder of ≈ 10⁻¹⁴ tokens/year, well below any display
/// precision). Epochs with zero ready validators mint nothing.
pub const EMISSIONS_PER_EPOCH: Stake = Stake::from_attos(
    (TOKENS_PER_YEAR_TARGET as u128) * Stake::ATTOS_PER_WHOLE / (EPOCHS_PER_YEAR as u128),
);
