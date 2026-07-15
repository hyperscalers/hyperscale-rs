//! Protocol-invariant constants governing beacon-chain state transitions.
//!
//! Every value here is consensus-critical: two validators that disagree on
//! any of these can't share a chain. They're declared as `pub const` (not
//! a `BeaconConfig` struct) so that altering one is a visible source-level
//! edit, not a runtime knob someone can tweak by accident.
//!
//! Consumed by [`BeaconState::apply_epoch`](crate::BeaconState) (in
//! `hyperscale_beacon`) to drive shuffles, jail cooldowns, unbonding
//! windows, and reward emission. Workspace-wide timing constants
//! ([`EPOCH_DURATION`](crate::EPOCH_DURATION) and friends) live in
//! [`crate::time`].
//!
//! # Epoch-keyed time
//!
//! Time-scoped constants are denominated in **epochs**. Every committed
//! block (Normal or Skip) advances the epoch counter by exactly one
//! and represents roughly one [`EPOCH_DURATION`](crate::EPOCH_DURATION)
//! of wall-clock time, so anything counting wall-clock duration
//! (cooldowns, unbonding windows, shuffle cadence) keys off epoch
//! transitions to stay faithful to time even when the chain skips a
//! stalled epoch.
//!
//! The numerical values are test-grade defaults — fine for tests,
//! almost certainly wrong for production (e.g. a 32-epoch
//! unbonding window is ≈ 2.5 hours at 5-min epochs, where real networks
//! use weeks). Tuning lands when operational data warrants.

use std::time::Duration;

use crate::Stake;

// ─── Consensus timeouts ────────────────────────────────────────────────────

/// Leader-proposal grace per SPC view.
///
/// Once this elapses without an `SpcProposalObject` from the view's
/// leader, the local participant fires its empty-view path so a
/// silent or Byzantine leader can't stall the view indefinitely.
///
/// Sized as the `2Δ` cap on a single view: long enough for a healthy
/// leader to broadcast the proposal-object, gather inner-PC voting
/// material, and circulate the cert; short enough that a stalled
/// epoch clears via view rotation well inside the 45 s
/// [`SKIP_TIMEOUT`](crate::SKIP_TIMEOUT) trigger.
pub const SPC_VIEW_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a beacon committee member collects peer proposals after
/// bootstrapping an epoch's SPC instance before feeding the view-1 PC
/// input from whatever the pool holds.
///
/// Members bootstrap near-simultaneously at the epoch's wall-clock
/// boundary, so feeding on own-proposal feedback alone would hand PC
/// disjoint singleton vectors whose only common prefix is empty — the
/// dwell gives peers' proposals one propagation window to arrive. The
/// fast path feeds early once a quorum (`2f+1`, including the local
/// proposal) is pooled; this timer is the laggard fallback, sized
/// well under any practical epoch duration.
pub const SPC_INPUT_DWELL: Duration = Duration::from_millis(500);

// ─── Committee sizing ──────────────────────────────────────────────────────

/// Target signer count for the global (beacon) committee — the dev/sim
/// default.
///
/// Small so simulations run at low validator counts; production caps the
/// committee at [`PRODUCTION_BEACON_COMMITTEE_SIZE`] instead.
pub const BEACON_SIGNER_COUNT: usize = 4;

/// Beacon committee size cap for a production chain.
///
/// A Byzantine beacon member steers next-epoch committee placement only by
/// including or omitting its own randomness proposal, so the space it can
/// grind over grows with the committee size — the width is exponential in
/// the number of such members, `~ Binomial(b, β)`. Holding `b` small caps
/// that width. The floor is the other side of the trade: a smaller
/// committee crosses its own Byzantine threshold (`≥ f+1` corrupt) more
/// often, which degrades beacon liveness and randomness bias — bounded by
/// pool ratification — rather than a safety break. `b = 16` balances the
/// two; the dev/sim default stays at [`BEACON_SIGNER_COUNT`]. Seated by
/// [`BeaconChainConfig::production`](crate::BeaconChainConfig::production).
///
/// A cap, not a floor: genesis seats `min(eligible, b)`, so a small
/// network runs a smaller committee that grows toward `b` as validators
/// join.
pub const PRODUCTION_BEACON_COMMITTEE_SIZE: usize = 16;

/// Smallest beacon committee that can run PC/SPC consensus.
///
/// `n >= 3f + 1` with `f >= 1` collapses to `n >= 4`: below this the
/// committee can't tolerate a single Byzantine fault. The coordinator in
/// `hyperscale_beacon` gates SPC bootstrap on this floor and falls back
/// to the skip path when the ready on-shard set drops beneath it; PC
/// instance construction also asserts on it as a tripwire.
pub const MIN_BEACON_COMMITTEE_SIZE: usize = 4;

/// Byzantine fault threshold for a committee of size `n` — classic BFT
/// `f = (n - 1) / 3`.
///
/// Committees too small to tolerate any faults (`n < 4`) return `0`;
/// callers deriving `n - f` quorums or `f + 1` indirect-cert thresholds
/// rely on the committee being sized at or above
/// [`MIN_BEACON_COMMITTEE_SIZE`].
#[must_use]
pub const fn byzantine_threshold(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

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

/// How many consecutive boundary folds may observe a live shard missing
/// before the beacon flags it as halted.
///
/// A shard committing normally contributes a crossing to most folds; a
/// miss count past this bound means the shard has stopped committing
/// entirely — e.g. `f + 1` of its committee withholding votes, leaving
/// the honest remainder short of a `2f + 1` quorum. The count advances
/// only on epochs the beacon folded boundaries at all, so a beacon-side
/// commit drought never reads as a shard halt. Shards involved in a
/// pending reshape or coasting to a scheduled terminal are legitimately
/// quiet and exempt from the check; this bound therefore only needs to
/// sit above [`RESHAPE_HANDOFF_TTL_EPOCHS`] (a successor's
/// post-execution seating lag) and the occasional missed fold.
///
/// The bound is two-sided. It must sit *above* the longest legitimate
/// quiet spell so a healthy shard never false-flags — a hard floor of
/// `RESHAPE_HANDOFF_TTL_EPOCHS` (12; reshaping shards are also exempt
/// outright) plus the occasional missed fold. But it also caps a *safety*
/// exposure: until the freeze fires at detection, a beyond-f committee can
/// export forged cross-shard artifacts, so the detection latency is the
/// window that exposure runs, and a lower threshold is a smaller window.
/// So the value wants to be as low as the false-trigger floor allows.
///
/// Set to `16` — just above the 12-epoch floor, so a healthy shard never
/// false-flags while the exposure window stays near its minimum (one
/// shuffle interval of detection latency). The scenario sims exercise the
/// halt-and-recover path at this value with no spurious flags.
pub const HALT_THRESHOLD_EPOCHS: u64 = 16;

// ─── Penalties ─────────────────────────────────────────────────────────────

/// How long a `JailReason::Performance` jail must elapse before an
/// `Unjail` lift can return the validator to `Pooled`.
///
/// A `JailReason::Withholding` jail (a beacon-committee member absent
/// from the committed set) instead holds for a full
/// [`BeaconState::beacon_recency_period`](crate::BeaconState::beacon_recency_period)
/// — far longer at production scale — so a grinder cannot return inside
/// the window its resample weight would still suppress it. Equivocation
/// jail is permanent regardless of either value.
pub const JAIL_COOLDOWN_EPOCHS: u64 = 16;

/// How many quiet epochs cancel a pending shard reshape.
///
/// Reshape triggers re-derive once per witness window while the load
/// condition holds, so an admitted reshape whose condition lapsed (a
/// split target that drained, a merge child that regrew) stops
/// re-asserting and its record drops once `current_epoch −
/// last_asserted` reaches this bound. The same bound expires a lone
/// merge half whose sibling never asserts.
///
/// A live trigger's folded re-assertions land roughly every third
/// epoch, not every epoch: the asserted leaf is consumed one fold
/// after its window, and the once-per-window dedup clears one window
/// after that (window bases freeze pre-fold). The bound sits above
/// that cadence with one epoch of slack, so a continuously held
/// condition never churns through cancel-and-readmit.
pub const RESHAPE_TRIGGER_TTL_EPOCHS: u64 = 4;

/// How long an admitted reshape may wait for readiness before being
/// abandoned.
///
/// Execution needs each pending child's ready membership at quorum; a
/// cohort that never gets there (stalled sync, member attrition) holds
/// a committee's worth of validators out of the pool, so the reshape
/// is abandoned and the cohort released once this many epochs pass
/// after admission. Re-emission retries while the load condition
/// holds.
pub const RESHAPE_READY_TTL_EPOCHS: u64 = 8;

/// How long a reshape's successors may take to go live after the reshape
/// executes before the handoff is flagged as stalled.
///
/// Under make-before-break a predecessor coasts past its weighted-time cut
/// until the beacon shows its successors live (a split's two children, or a
/// merge's reformed parent, have produced past their seeded genesis). The
/// terminal commits and serves reliably, so the successors should seat and
/// produce well inside this bound. Measured from execution (the terminal
/// boundary's `terminal_epoch`), the analogue of [`RESHAPE_READY_TTL_EPOCHS`]
/// for the post-execution phase. Sits a touch above the readiness TTL because
/// the window also absorbs the empty-commit lag across the reshape committee
/// transition before the successors' first crossing can fold.
pub const RESHAPE_HANDOFF_TTL_EPOCHS: u64 = 12;

/// How long a stake-pool withdrawal request remains pending before its
/// amount is released and any resulting auto-deactivations apply.
///
/// Long enough that late-arriving equivocation evidence can still mark
/// byzantine validators permanently before their pool's stake fully
/// escapes.
pub const UNBONDING_WINDOW_EPOCHS: u64 = 32;

/// Per-epoch `MissedProposal` count that trips a `JailReason::Performance`
/// jail on a placed validator.
///
/// One `MissedProposal` lands per skipped round whenever a shard's
/// fallback commits past the originally-scheduled proposer. The counter
/// scopes to the validator's current `OnShard { shard }`: witnesses from
/// other shards never count, and any status transition out of `OnShard`
/// resets the count along with the natural per-epoch reset.
///
/// Starting value provisional — pending operational data on per-shard
/// miss cadence under real workloads. Revisit once `MissedProposal`
/// emission rates settle.
pub const MISSED_PROPOSAL_JAIL_THRESHOLD: u32 = 16;

// ─── Economics ─────────────────────────────────────────────────────────────

/// Target annual emission envelope in whole tokens.
pub const TOKENS_PER_YEAR_TARGET: u64 = 300_000_000;

/// Epochs per year at the target epoch cadence.
///
/// `(60 / 5) * 24 * 365` at 5-minute epochs
/// ([`EPOCH_DURATION`](crate::EPOCH_DURATION)). Maintainers who change
/// `EPOCH_DURATION` must update this number too.
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
