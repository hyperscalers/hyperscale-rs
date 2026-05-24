//! Global beacon state and the epoch pipeline that drives it.
//!
//! [`apply_epoch`] mutates this state deterministically from each epoch's
//! committed `BeaconProposal` set; the derived helpers
//! ([`min_stake`], [`effective_stake`], [`current_active_count`],
//! [`max_active_count`], [`pooled_validators`]) are pure functions of
//! state — every call site re-derives the value rather than caching,
//! so there's no two-piece state to keep in sync.
//!
//! # Epoch-time vs epoch-time
//!
//! Validator-lifecycle fields ([`PendingWithdrawal::initiated_at_epoch`],
//! [`ValidatorStatus::Jailed::since_epoch`],
//! [`ValidatorStatus::OnShard::placed_at_epoch`],
//! [`ValidatorRecord::registered_at_epoch`]) are denominated in
//! **epochs**, not slots. Recovery slots can wedge in mid-epoch without
//! representing real elapsed time, so anything counting wall-clock
//! duration (cooldowns, unbonding windows, ready timeouts) keys off
//! `current_epoch` against the corresponding `*_EPOCHS` constant in
//! [`crate::constants`].

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconProposal, Bls12381G1PublicKey, Epoch, EquivocationEvidence, LeafIndex, NetworkDefinition,
    Randomness, RecoveryCertificate, ShardGroupId, ShardWitnessPayload, Stake, StakePoolId,
    ValidatorId, VrfOutput, vrf_verify,
};
use rand::RngExt;

use crate::constants::{
    EMISSIONS_PER_EPOCH, JAIL_COOLDOWN_EPOCHS, MIN_STAKE_FLOOR, MISSED_PROPOSAL_JAIL_THRESHOLD,
    POOL_BUFFER_TARGET, READY_TIMEOUT_EPOCHS, SHARD_CAPACITY, SHUFFLE_INTERVAL_EPOCHS,
    UNBONDING_WINDOW_EPOCHS,
};
use crate::pc::verify_vote_equivocation;
use crate::sampling::{draw_from_pool, prng_from};

/// Domain tag for the beacon-randomness mixer. Binds the BLAKE3 input
/// to "beacon randomness v1" so the digest can't collide with any
/// other 32-byte BLAKE3 hash in the codebase (committee draw seed,
/// pool draw seed, etc.).
const DOMAIN_BEACON_RANDOMNESS: &[u8] = b"hyperscale-beacon-randomness-v1";

/// Domain tag for [`run_shuffle_step`]'s victim-selection seed. Distinct
/// from [`crate::sampling`]'s pool-draw tag so the two PRNG streams
/// never collide on the same `(randomness, epoch, shard)` input.
const DOMAIN_SHUFFLE_EXIT: &[u8] = b"hyperscale-shuffle-exit-v1";

// ─── pool types ─────────────────────────────────────────────────────────────

/// One pending withdrawal against a [`StakePool`].
///
/// Completes [`UNBONDING_WINDOW_EPOCHS`](crate::constants::UNBONDING_WINDOW_EPOCHS)
/// epochs after `initiated_at_epoch`; on completion the amount is
/// removed from `total_stake` and any resulting auto-deactivations
/// apply. Until then `effective_stake` reflects the withdrawal even
/// though `total_stake` does not — so new registrations can't lean on
/// stake that's already pledged to leave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWithdrawal {
    /// Amount the withdrawal removes from effective stake immediately
    /// and from total stake on unbonding completion.
    pub amount: Stake,
    /// Epoch when the withdrawal was placed.
    pub initiated_at_epoch: Epoch,
}

/// Aggregate stake-pool record.
///
/// Delegator-level accounting lives in the staking contract on the
/// shard layer; beacon tracks only the aggregate state that determines
/// validator activation count. Pool entries are created implicitly on
/// the first `StakeDeposit` witness for an unknown id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakePool {
    /// Identifier — same key the pool sits under in
    /// [`BeaconState::pools`].
    pub id: StakePoolId,
    /// Total stake locked to this pool, including amounts currently in
    /// `pending_withdrawals`. Increases on `StakeDeposit`; decreases
    /// only when a pending withdrawal matures.
    pub total_stake: Stake,
    /// Validators operated under this pool. Includes
    /// `InsufficientStake` validators — they remain associated with
    /// their pool indefinitely so equivocation evidence can still apply
    /// retroactively and so they can auto-reactivate when the pool's
    /// stake recovers.
    pub validators: BTreeSet<ValidatorId>,
    /// Withdrawals waiting out the unbonding window.
    pub pending_withdrawals: Vec<PendingWithdrawal>,
}

// ─── validator types ────────────────────────────────────────────────────────

/// What caused a validator to be jailed.
///
/// Determines unjail eligibility — fault-cause reasons unjail after
/// [`JAIL_COOLDOWN_EPOCHS`](crate::constants::JAIL_COOLDOWN_EPOCHS)
/// once an `Unjail` witness arrives; provable-byzantine reasons never
/// unjail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JailReason {
    /// Performance failure. Surfaces from a shard's local miss-counter
    /// crossing threshold (witness emits with this reason), from the
    /// beacon-side `MissedProposal` counter crossing
    /// [`MISSED_PROPOSAL_JAIL_THRESHOLD`](crate::constants::MISSED_PROPOSAL_JAIL_THRESHOLD),
    /// or from a malformed VRF reveal in the validator's own proposal
    /// (self-inflicted cryptographic fault, jailed on first sighting).
    /// Unjails after cooldown.
    Performance,
    /// Jailed by recovery-cert application — the validator was on the
    /// dead committee at recovery time. Unjails after cooldown (genuine
    /// outages aren't permanent).
    Recovery,
    /// Cryptographic proof of byzantine signing. Permanent — the key is
    /// provably hostile, no cooldown unjails it.
    Equivocation,
}

/// Operational status of one validator.
///
/// Transitions are driven by `apply_epoch` from witnesses, withdrawal
/// completion, jail cascades, and pool draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// In the global pool. Registered, supported by stake, but not
    /// placed on any shard. Picked up by the next pool draw driven by
    /// a shard epoch opening.
    Pooled,
    /// Placed on `shard`. `ready: true` once a `Ready` witness from
    /// the shard has been applied or
    /// [`READY_TIMEOUT_EPOCHS`](crate::constants::READY_TIMEOUT_EPOCHS)
    /// has elapsed since `placed_at_epoch`. Until then the validator
    /// occupies a committee epoch but doesn't sign.
    OnShard {
        /// Shard the validator is on.
        shard: ShardGroupId,
        /// Whether the validator has signalled sync-completion.
        ready: bool,
        /// Epoch when the placement happened.
        placed_at_epoch: Epoch,
    },
    /// Jailed and removed from any prior shard. `Unjail` (after
    /// cooldown) returns the validator to `Pooled` iff the pool can
    /// still support the additional active epoch; otherwise the unjail
    /// is rejected. Equivocation jails are permanent regardless.
    Jailed {
        /// Epoch the jail entered.
        since_epoch: Epoch,
        /// Why.
        reason: JailReason,
    },
    /// The validator's pool no longer has effective stake to support
    /// them. Removed from any shard at the moment of transition. When
    /// `max_active_count` rises above `current_active_count` —
    /// `StakeDeposit` arrival or dynamic `min_stake` drop —
    /// `InsufficientStake` validators auto-reactivate to `Pooled`
    /// (highest-`validator_id` first). Record persists indefinitely so
    /// late-arriving equivocation evidence can still apply.
    InsufficientStake,
}

/// On-chain record for one validator node.
///
/// Stake lives on the validator's [`StakePool`], not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// Same id this record sits under in [`BeaconState::validators`].
    pub id: ValidatorId,
    /// Pool that operates this validator. One pool can operate many
    /// validators; one validator belongs to exactly one pool.
    pub pool: StakePoolId,
    /// Operational status.
    pub status: ValidatorStatus,
    /// Epoch when registration was applied.
    pub registered_at_epoch: Epoch,
    /// Compressed BLS pubkey. Carried in the on-chain record so
    /// verifiers (committee aggregates, VRF reveals, light clients)
    /// read it from state instead of relying on any side-channel
    /// registry. Lifted verbatim from
    /// `ShardWitnessPayload::RegisterValidator` at registration and
    /// from the genesis input at chain bootstrap.
    pub pubkey: Bls12381G1PublicKey,
}

// ─── shard committee ────────────────────────────────────────────────────────

/// Per-shard committee.
///
/// Every member's status is `OnShard { shard: this_shard, .. }`. Jail,
/// deactivation, and withdrawal-completion auto-deactivation
/// transitions remove the validator from `members` synchronously.
/// Order is incidental — the active signer set is filtered from
/// `members` by status, not by position. `members.len() ≤
/// SHARD_CAPACITY` at every epoch boundary; the list shrinks transiently
/// when a epoch opens, then refills via `pool_draw` within the same
/// step.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShardCommittee {
    /// Ordered list of validators on this shard.
    pub members: Vec<ValidatorId>,
}

// ─── beacon state ───────────────────────────────────────────────────────────

/// Global beacon state. Updated atomically per epoch by `apply_epoch`.
///
/// Cross-validator agreement on every field at every epoch follows from
/// `apply_epoch` being a pure deterministic function of `(state, epoch,
/// committed)` and SPC's Agreement guaranteeing all honest parties see
/// the same `committed` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconState {
    /// Highest epoch whose block has been applied. Advances by 1 per
    /// successful `apply_epoch`.
    pub current_epoch: Epoch,
    /// Per-id validator records.
    pub validators: BTreeMap<ValidatorId, ValidatorRecord>,
    /// Per-id stake pools.
    pub pools: BTreeMap<StakePoolId, StakePool>,
    /// Running beacon randomness — BLAKE3 mix of the prior value with
    /// each epoch's accepted VRF outputs.
    pub randomness: Randomness,
    /// Beacon committee for the current epoch — the validators running
    /// the SPC instance producing this epoch's block.
    pub committee: Vec<ValidatorId>,
    /// Per-shard ordered committee. Membership evolves via the
    /// trickled shuffle (slow per-interval churn), jail/exit/
    /// deactivate (immediate removal), and pool draws (filling slots
    /// that just opened).
    pub shard_committees: BTreeMap<ShardGroupId, ShardCommittee>,
    /// Per-shard high-water mark over each shard's beacon-witness
    /// accumulator: the largest [`LeafIndex`] this beacon has lifted
    /// from that shard. A `ShardWitness` with `proof.leaf_index !=
    /// consumed_through[shard] + 1` is silently dropped (already
    /// consumed, or a gap that must be filled first). Updates
    /// monotonically; never reset.
    ///
    /// `BeaconWitness::Equivocation` is not tracked here — it has no
    /// shard provenance and re-application is idempotent once the
    /// validator is `Jailed { Equivocation }`.
    pub consumed_through: BTreeMap<ShardGroupId, LeafIndex>,
    /// Most recent recovery cert applied to this state, if any. Drives
    /// the double-application guard inside recovery-cert handling: a
    /// later cert at the same anchor only supersedes when its
    /// `recovery_round` is strictly higher than this one's. Cleared
    /// implicitly by anchor change.
    pub last_recovery_cert: Option<RecoveryCertificate>,
    /// Per-validator `MissedProposal` counter, scoped to the current
    /// epoch and the validator's current shard. Incremented when a
    /// `MissedProposal` witness arrives whose proposer is currently
    /// `OnShard { shard }` matching the witness's source shard. Reset
    /// on epoch boundaries and on any status transition out of
    /// `OnShard { shard }`. Crossing
    /// [`MISSED_PROPOSAL_JAIL_THRESHOLD`](crate::constants::MISSED_PROPOSAL_JAIL_THRESHOLD)
    /// jails the validator under `JailReason::Performance` in the same
    /// epoch.
    pub miss_counters: BTreeMap<ValidatorId, u32>,
}

// ─── epoch effects ───────────────────────────────────────────────────────────

/// What caused a [`CommitteeTransition`].
///
/// The runner uses this to tell "scheduled rotation, no anomaly" apart
/// from "the old committee failed and was replaced" — different
/// operator-facing signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionCause {
    /// Natural rotation at an epoch boundary — the trickled shuffle for
    /// per-shard committees, the epoch-rotation step for the beacon
    /// committee.
    NaturalShuffle,
    /// Committee replaced by a [`RecoveryCertificate`] after the old
    /// committee stalled past the recovery timeout.
    Recovery,
    /// A mid-epoch jail, deactivation, or withdrawal-driven
    /// auto-deactivation changed a shard's `members` list without a
    /// fresh shuffle.
    MembershipChange,
}

/// Structured description of a committee handover.
///
/// Surfaced both by natural epoch boundaries (in
/// [`SlotEffects::beacon_committee_transition`] and
/// [`SlotEffects::shard_committee_transitions`]) and by recovery-cert
/// application, so the runner has a unified signal for "tear down the
/// SPC instance you were running for `from` and bootstrap a fresh one
/// with `to`."
///
/// Honest committee members of `from` whose membership has ended see
/// `to` and either bootstrap a new SPC instance (if `to` contains them)
/// or shut down SPC participation cleanly (if `to` excludes them).
///
/// Cross-validator agreement on `(from, to, cause, at_slot)` follows
/// from `apply_epoch` being deterministic; every honest party computes
/// the same transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeTransition {
    /// Outgoing committee.
    pub from: Vec<ValidatorId>,
    /// Incoming committee.
    pub to: Vec<ValidatorId>,
    /// Why the transition fired.
    pub cause: TransitionCause,
    /// Epoch the transition was applied at.
    pub at_slot: Epoch,
}

/// Effects of applying one epoch, returned by `apply_epoch`.
///
/// Surfaced for observability, runner-side wiring (committee handover
/// detection), and tests. Empty defaults match "nothing happened" — a
/// epoch with no commits and no boundary crossings returns
/// [`SlotEffects::default()`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SlotEffects {
    /// New validators registered via a `RegisterValidator` witness.
    pub registered: Vec<ValidatorId>,
    /// Validators transitioned to `InsufficientStake` — via explicit
    /// `DeactivateValidator` witness or via withdrawal-completion
    /// auto-deactivation.
    pub deactivated: Vec<ValidatorId>,
    /// Validators jailed this epoch (`Jail` witness, malformed VRF
    /// reveal, beacon-side `MissedProposal` threshold crossing, or
    /// equivocation evidence).
    pub jailed: Vec<ValidatorId>,
    /// Validators returned from `Jailed` to `Pooled` via a successful
    /// `Unjail` lift.
    pub unjailed: Vec<ValidatorId>,
    /// `InsufficientStake` validators returned to `Pooled` by the
    /// auto-reactivation scan.
    pub reactivated: Vec<ValidatorId>,
    /// `OnShard` validators whose `ready` flag flipped to `true` —
    /// via `Ready` witness or auto-ready timeout.
    pub readied: Vec<ValidatorId>,
    /// True iff `state.committee` (beacon committee) was re-sampled
    /// this epoch.
    pub committee_changed: bool,
    /// Beacon-committee handover when `committee_changed`.
    pub beacon_committee_transition: Option<CommitteeTransition>,
    /// Per-shard transitions emitted for any shard whose `members`
    /// list changed this epoch.
    pub shard_committee_transitions: BTreeMap<ShardGroupId, CommitteeTransition>,
    /// Committee members whose `vrf_reveal` failed verification —
    /// their reveal did not contribute to the new randomness and their
    /// witnesses were also dropped (a malformed reveal is treated as a
    /// malformed proposal).
    pub rejected_reveals: Vec<ValidatorId>,
    /// Per-pool emission credit applied to `pool.total_stake` this
    /// epoch. Sum equals one epoch's emission share minus the burned
    /// integer-division remainder. Empty when no pool had a ready
    /// `OnShard` validator (whole epoch's share burned).
    pub rewards_credited: BTreeMap<StakePoolId, Stake>,
}

// ─── derived helpers ────────────────────────────────────────────────────────

/// Stake available to support active validators on this pool after
/// accounting for in-flight withdrawals.
///
/// Pending withdrawals reduce effective stake immediately even though
/// `total_stake` doesn't drop until the unbonding window completes —
/// this is what blocks new registrations that would have relied on the
/// withdrawn amount.
#[must_use]
pub fn effective_stake(pool: &StakePool) -> Stake {
    let pending = pool
        .pending_withdrawals
        .iter()
        .fold(Stake::ZERO, |acc, w| acc.saturating_add(w.amount));
    pool.total_stake.saturating_sub(pending)
}

/// How many of `pool`'s validators are currently consuming an
/// activation epoch.
///
/// Counts `Pooled` and `OnShard`; excludes `Jailed` (epoch may stay
/// jailed indefinitely; locking stake against an uncertain return is
/// wrong) and `InsufficientStake` (already represents "not consuming a
/// epoch").
#[must_use]
pub fn current_active_count(pool: &StakePool, state: &BeaconState) -> usize {
    pool.validators
        .iter()
        .filter(|id| {
            matches!(
                state.validators.get(id).map(|r| &r.status),
                Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
            )
        })
        .count()
}

/// Cap on how many of `pool`'s validators can be active at the current
/// dynamic [`min_stake`].
///
/// Equals `effective_stake(pool) / min_stake(state)`. The invariant
/// `current_active_count(pool) ≤ max_active_count(pool, state)` is
/// enforced at `RegisterValidator` and `Unjail` application.
#[must_use]
pub fn max_active_count(pool: &StakePool, state: &BeaconState) -> usize {
    let t = min_stake(state);
    if t == Stake::ZERO {
        return usize::MAX;
    }
    let e = effective_stake(pool).attos();
    (e / t.attos()) as usize
}

/// Validators currently waiting in the global pool.
///
/// Derived from `state.validators` rather than stored as a separate
/// field, so there's no two-piece state to keep in sync. Returned
/// sorted by `ValidatorId` for deterministic indexing inside pool draws.
///
/// Membership is exactly `status == Pooled`. A validator becomes
/// `Pooled` on registration, on `Unjail` after cooldown, on trickled
/// shuffle exit, and on auto-reactivation; they leave `Pooled` when a
/// pool draw flips them to `OnShard`, or when a witness moves them to
/// another status.
#[must_use]
pub fn pooled_validators(state: &BeaconState) -> Vec<ValidatorId> {
    state
        .validators
        .iter()
        .filter(|(_, r)| matches!(r.status, ValidatorStatus::Pooled))
        .map(|(id, _)| *id)
        .collect()
}

/// Dynamic per-validator minimum stake.
///
/// Pure function of state — no stored "current `min_stake`" field.
/// Evaluated fresh at every site that needs it (registration
/// validation, unjail validation, withdrawal-completion checks).
///
/// Three forces:
///   - `t_no_eject`: the highest level that wouldn't force any
///     currently-active validator into `InsufficientStake`. The
///     tightest pool's `effective_stake / current_active_count`.
///   - `t_admit`: the level low enough that pools collectively *could*
///     support the target validator population (one full shard
///     committee per shard plus [`POOL_BUFFER_TARGET`] reserves).
///   - [`MIN_STAKE_FLOOR`]: governance-set absolute minimum, Sybil
///     backstop.
///
/// Resolution: `min(t_no_eject, t_admit).max(MIN_STAKE_FLOOR)`.
/// `t_no_eject` is a ceiling, not a trigger — a rising `min_stake`
/// doesn't cause involuntary deactivations.
#[must_use]
pub fn min_stake(state: &BeaconState) -> Stake {
    let ne = t_no_eject(state);
    let ad = admit_threshold(state);
    Stake::from_attos(ne.attos().min(ad.attos()).max(MIN_STAKE_FLOOR.attos()))
}

/// Highest `min_stake` could be without forcing any active validator
/// into `InsufficientStake`.
///
/// Equals the minimum across pools (with at least one active
/// validator) of `effective_stake / current_active_count`.
/// [`Stake::MAX`] when no pool yet has an active validator (e.g. at
/// bootstrap).
fn t_no_eject(state: &BeaconState) -> Stake {
    state
        .pools
        .values()
        .filter_map(|pool| {
            let active = current_active_count(pool, state);
            if active == 0 {
                None
            } else {
                Some(effective_stake(pool).attos() / active as u128)
            }
        })
        .min()
        .map_or(Stake::MAX, Stake::from_attos)
}

/// Marginal price at which exactly the target epoch count is offered
/// across all pools.
///
/// Each pool offers a descending sequence (`effective_stake / 1, / 2,
/// …`) — "if I had to support k validators, my budget per validator
/// would be e/k." Gather every pool's offerings, sort descending,
/// return the entry at position `target - 1`.
///
/// Target is `shard_count × SHARD_CAPACITY + POOL_BUFFER_TARGET`. The
/// shard count isn't a stored field — it's `state.shard_committees.len()`.
/// Returns [`Stake::MAX`] for a zero target; returns [`MIN_STAKE_FLOOR`]
/// when pools collectively can't fill the target even at floor pricing
/// (anything below the floor would be clamped away by `min_stake`'s
/// `.max(...)` anyway).
fn admit_threshold(state: &BeaconState) -> Stake {
    let target = state.shard_committees.len() * SHARD_CAPACITY + POOL_BUFFER_TARGET;
    if target == 0 {
        return Stake::MAX;
    }

    let mut offerings: Vec<u128> = Vec::new();
    for pool in state.pools.values() {
        let e = effective_stake(pool).attos();
        if e == 0 {
            continue;
        }
        // Cap per-pool at `target`: a pool's k-th offering for
        // k > target can't enter the global top-`target`, because the
        // same pool already contributed k-1 higher offerings ranked
        // ahead of it. Also cap at `floor(e / MIN_STAKE_FLOOR)` since
        // offerings below the floor would be clamped away in
        // `min_stake` anyway.
        let floor_cap = if MIN_STAKE_FLOOR == Stake::ZERO {
            target
        } else {
            (e / MIN_STAKE_FLOOR.attos()) as usize
        };
        let k_max = floor_cap.min(target);
        for k in 1..=k_max {
            offerings.push(e / k as u128);
        }
    }

    if offerings.len() < target {
        return MIN_STAKE_FLOOR;
    }

    offerings.sort_unstable_by(|a, b| b.cmp(a));
    Stake::from_attos(offerings[target - 1])
}

// ─── state-mutating sampling glue ──────────────────────────────────────────

/// Draw one validator from the global pool and place them on `shard`
/// as `OnShard { ready: false, placed_at_epoch: state.current_epoch }`.
///
/// Returns the chosen validator id, or `None` when the pool is empty
/// (the epoch stays open and refills on the next pool draw against a
/// non-empty pool).
///
/// The pool is derived per-call via [`pooled_validators`] rather than
/// stored. Seeding binds to `(state.randomness, state.current_epoch,
/// shard)` so draws across shards within one epoch — and across slots
/// on one shard — use distinct PRNG streams.
///
/// Multiple draws on the same `(epoch, shard)` re-seed with the same
/// bytes, but each subsequent call sees a strictly smaller derived
/// pool: the previously-chosen validator's status is now `OnShard`,
/// excluding them from the next call's `pooled_validators`. Picks
/// remain distinct even when the raw PRNG index collides.
///
/// # Panics
///
/// Panics if the chosen validator id (which came from
/// [`pooled_validators`] filtering `state.validators` immediately
/// above) is absent from `state.validators`. Structurally
/// unreachable.
pub fn pool_draw(state: &mut BeaconState, shard: ShardGroupId) -> Option<ValidatorId> {
    let pool = pooled_validators(state);
    let chosen = draw_from_pool(
        &pool,
        state.randomness.as_bytes(),
        state.current_epoch,
        shard,
    )?;
    state
        .validators
        .get_mut(&chosen)
        .expect("chosen comes from the derived pool, must be in validators")
        .status = ValidatorStatus::OnShard {
        shard,
        ready: false,
        placed_at_epoch: state.current_epoch,
    };
    state
        .shard_committees
        .entry(shard)
        .or_default()
        .members
        .push(chosen);
    Some(chosen)
}

// ─── epoch pipeline ─────────────────────────────────────────────────────────

/// Apply one epoch's SPC commit to `state`.
///
/// `committed` is the per-epoch proposals SPC's Agreement layer has
/// agreed on. Pure deterministic function of `(state, network, epoch,
/// committed)` — every honest party with byte-identical inputs lands
/// at byte-identical state.
///
/// # Panics
///
/// Panics if `epoch <= state.current_epoch`. The epoch watermark must
/// strictly advance: a regressed or repeated epoch from the runner
/// would silently corrupt epoch-difference math (cooldowns, unbonding,
/// ready timeout) and replay witnesses against a watermark that
/// already accounts for them. Genesis sits at `current_epoch =
/// GENESIS` and the first apply is `epoch > GENESIS`, so strict `>` is
/// the right bound. Tests sometimes skip slots, so we don't require
/// strict-linear `epoch == current_epoch + 1`.
pub fn apply_epoch(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
) -> SlotEffects {
    assert!(
        epoch > state.current_epoch,
        "apply_epoch regression: epoch {epoch} <= state.current_epoch {}",
        state.current_epoch,
    );
    // Set `current_epoch` before the pipeline runs so every downstream
    // helper (including `pool_draw`'s seed binding) reads "the epoch
    // I'm in," not "the epoch before mine."
    state.current_epoch = epoch;

    // Snapshot each shard's member list before the pipeline runs so the
    // end-of-epoch set-diff against this snapshot can surface
    // membership changes through `SlotEffects.shard_committee_transitions`.
    let pre_shard_members: BTreeMap<ShardGroupId, Vec<ValidatorId>> = state
        .shard_committees
        .iter()
        .map(|(s, c)| (*s, c.members.clone()))
        .collect();

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
    let witness = ingest_witnesses(state, network, &vrf.accepted);
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    let rewards_credited = distribute_epoch_rewards(state);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);

    let mut jailed = vrf.jailed;
    jailed.extend(witness.jailed);
    let mut deactivated = witness.deactivated;
    deactivated.extend(withdrawal.deactivated);
    let mut readied = witness.readied;
    readied.extend(timeout_readied);

    let shard_committee_transitions = diff_shard_committees(state, &pre_shard_members);

    SlotEffects {
        registered: witness.registered,
        deactivated,
        jailed,
        unjailed: witness.unjailed,
        reactivated,
        readied,
        rejected_reveals: vrf.rejected_reveals,
        rewards_credited,
        shard_committee_transitions,
        ..SlotEffects::default()
    }
}

/// Outcome of [`filter_and_roll_randomness`]. The borrowed `accepted`
/// slice lets [`ingest_witnesses`] iterate the proposals that survived
/// the VRF check without re-running the filter.
struct VrfStageOutcome<'a> {
    /// Proposals from committee members whose VRF reveal verified.
    /// References into the `committed` slice supplied to
    /// [`apply_epoch`].
    accepted: Vec<&'a (ValidatorId, BeaconProposal)>,
    /// Validators in `state.committee` whose VRF reveal failed to
    /// verify. Their entire proposal — including any witnesses — was
    /// dropped on the same grounds.
    rejected_reveals: Vec<ValidatorId>,
    /// Validators jailed during the cascade triggered by malformed VRF
    /// reveals. Subset of `rejected_reveals` (only `OnShard` rejected
    /// proposers cascade through to jail).
    jailed: Vec<ValidatorId>,
}

/// Filter `committed` to proposals whose proposer is in
/// `state.committee` and whose VRF reveal verifies under their
/// pubkey, roll `state.randomness` over the accepted VRF outputs, and
/// jail proposers whose reveals were rejected.
///
/// `state.randomness` advances *always* — even when no proposal is
/// accepted, the BLAKE3 mix runs against the prior randomness alone.
/// An "all-rejected" epoch still advances randomness as a
/// deterministic function of `prev_randomness`. An adversary who can
/// suppress every VRF reveal can therefore predict the next epoch's
/// randomness from the previous one; the mitigation is the
/// jail-on-first-sighting cascade here plus committee resampling at
/// epoch boundaries.
///
/// A malformed VRF reveal under the proposer's own key is a
/// self-inflicted cryptographic fault — an unmodified honest binary
/// can't produce one. Jail on first sighting under
/// `JailReason::Performance`; the freed shard epoch refills via
/// `pool_draw` in the same step as the status transition. Operators
/// restart with a fixed binary and lift via `Unjail` once cooldown
/// elapses. Non-`OnShard` rejected proposers (shouldn't normally
/// happen — non-committee filter already ran) silently fail the cascade
/// gate without jailing.
fn filter_and_roll_randomness<'a>(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &'a [(ValidatorId, BeaconProposal)],
) -> VrfStageOutcome<'a> {
    let committee_set: BTreeSet<ValidatorId> = state.committee.iter().copied().collect();

    let mut accepted: Vec<&'a (ValidatorId, BeaconProposal)> = Vec::new();
    let mut rejected_reveals = Vec::new();
    let mut accepted_outputs: Vec<VrfOutput> = Vec::new();
    for entry in committed {
        let (party, prop) = entry;
        if !committee_set.contains(party) {
            continue;
        }
        // Defensive: committee membership should imply a validator
        // record. If a runner bug or future refactor breaks that
        // invariant, treat the proposer as rejected rather than
        // panic.
        let Some(pk) = state.validators.get(party).map(|r| r.pubkey) else {
            rejected_reveals.push(*party);
            continue;
        };
        let output = prop.vrf_output();
        let proof = prop.vrf_proof();
        if vrf_verify(&pk, network, epoch, &output, &proof) {
            accepted_outputs.push(output);
            accepted.push(entry);
        } else {
            rejected_reveals.push(*party);
        }
    }

    // Roll randomness from accepted VRF outputs. Always runs — see
    // function-level doc for the "all-rejected" semantics.
    let mut h = Hasher::new();
    h.update(DOMAIN_BEACON_RANDOMNESS);
    h.update(state.randomness.as_bytes());
    for o in &accepted_outputs {
        h.update(o.as_bytes());
    }
    state.randomness = Randomness(*h.finalize().as_bytes());

    // Cascade jail for rejected proposers currently `OnShard`.
    let mut jailed = Vec::new();
    let since_epoch = state.current_epoch;
    for party in &rejected_reveals {
        let prior_status = state.validators.get(party).map(|r| r.status);
        if !matches!(prior_status, Some(ValidatorStatus::OnShard { .. })) {
            continue;
        }
        jail_validator(state, *party, JailReason::Performance, since_epoch);
        jailed.push(*party);
    }

    VrfStageOutcome {
        accepted,
        rejected_reveals,
        jailed,
    }
}

/// Transition `victim` to `Jailed { since_epoch, reason }` and run
/// the shared cleanup: clear any per-validator state scoped to their
/// old placement (currently [`BeaconState::miss_counters`]); if they
/// were `OnShard`, remove from that shard's committee and draw a
/// refill from the global pool.
///
/// Silent no-op if `victim` isn't in `state.validators`. Callers that
/// want to gate on the prior status (e.g. equivocation's "skip
/// already-permanent `Equivocation` jails") must do that gate before
/// calling.
fn jail_validator(
    state: &mut BeaconState,
    victim: ValidatorId,
    reason: JailReason,
    since_epoch: Epoch,
) {
    let Some(rec) = state.validators.get_mut(&victim) else {
        return;
    };
    let prior_status = rec.status;
    rec.status = ValidatorStatus::Jailed {
        since_epoch,
        reason,
    };
    state.miss_counters.remove(&victim);
    if let ValidatorStatus::OnShard { shard, .. } = prior_status {
        if let Some(committee) = state.shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != victim);
        }
        pool_draw(state, shard);
    }
}

// ─── witness ingestion ────────────────────────────────────────────────────

/// Outcome of [`ingest_witnesses`].
///
/// Each field is a deterministic-order list of validator ids
/// transitioned by witness application this epoch, used by `apply_epoch`
/// to populate the matching [`SlotEffects`] fields.
#[derive(Default)]
struct WitnessOutcome {
    registered: Vec<ValidatorId>,
    deactivated: Vec<ValidatorId>,
    jailed: Vec<ValidatorId>,
    unjailed: Vec<ValidatorId>,
    readied: Vec<ValidatorId>,
}

/// Validator-status effect of one shard-lift application.
///
/// `StakeDeposit` and `StakeWithdraw` payloads mutate pool state but
/// produce no validator-level event (caller sees `None`).
#[allow(dead_code)] // not every variant is constructed by the apply_shard_payload arms in place
enum ShardEvent {
    Registered(ValidatorId),
    Deactivated(ValidatorId),
    Jailed(ValidatorId),
    Unjailed(ValidatorId),
    Readied(ValidatorId),
}

/// Collect, dedup, and apply the witnesses ridden by `accepted`
/// proposals.
///
/// Shard lifts pass the per-shard `consumed_through` watermark — only
/// `watermark + 1` is admitted, gaps and already-consumed leaves are
/// silently dropped. The watermark advances on apply (regardless of
/// whether the variant produced a validator-level event), so an
/// honest committee can re-include a missing leaf next epoch once the
/// gap is filled.
///
/// `Witness::Beacon::Equivocation` variants are collected alongside
/// shard lifts and re-verified before applying. No dedup is needed —
/// re-application is idempotent once the validator is `Jailed {
/// Equivocation }`.
///
/// # Defense-in-depth caps
///
/// The wire decoder already bounds proposals at
/// [`MAX_WITNESSES_PER_PROPOSER`](hyperscale_types::MAX_WITNESSES_PER_PROPOSER)
/// via [`BeaconProposal`]'s `BoundedVec`. The epoch-level cap
/// [`MAX_WITNESSES_PER_SLOT`](crate::constants::MAX_WITNESSES_PER_SLOT)
/// is the product `BEACON_SIGNER_COUNT × MAX_WITNESSES_PER_PROPOSER`,
/// which the wire bounds already imply for a well-formed committee.
/// The check here exists as defence in depth: if the committee size
/// ever grows without the epoch cap being re-derived, the epoch cap
/// bounds aggregate witness work regardless.
fn ingest_witnesses(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    accepted: &[&(ValidatorId, BeaconProposal)],
) -> WitnessOutcome {
    use hyperscale_types::{BeaconWitness, ShardWitness, Witness};

    use crate::constants::MAX_WITNESSES_PER_SLOT;

    // Collect Shard witnesses with within-epoch dedup keyed by
    // `(shard_id, leaf_index)` — the unique identity of a witness in
    // its source shard's accumulator. `ShardWitnessProof` isn't `Ord`
    // (it's a wire type), so we key the dedup set on the tuple
    // directly. Beacon witnesses collect without dedup; their jail
    // gate ("not already permanently jailed") provides the idempotence.
    let mut shard_seen: BTreeSet<(ShardGroupId, LeafIndex)> = BTreeSet::new();
    let mut shard_lifts: Vec<&ShardWitness> = Vec::new();
    let mut equivocations: Vec<&BeaconWitness> = Vec::new();
    'collect: for (_, prop) in accepted {
        for w in prop.witnesses().iter() {
            if shard_lifts.len() + equivocations.len() >= MAX_WITNESSES_PER_SLOT {
                break 'collect;
            }
            match w {
                Witness::Shard(sw) => {
                    if !shard_seen.insert((sw.proof.shard_id, sw.proof.leaf_index)) {
                        continue;
                    }
                    shard_lifts.push(sw);
                }
                Witness::Beacon(bw) => {
                    equivocations.push(bw);
                }
            }
        }
    }

    let mut outcome = WitnessOutcome::default();

    // Apply shard lifts in `(shard_id, leaf_index)` order, gated by
    // the per-shard watermark. Watermark advances on apply regardless
    // of whether the variant produced a validator-level event, so a
    // no-op variant (e.g. stake adjustment) doesn't stall the shard's
    // accumulator.
    shard_lifts.sort_by_key(|sw| (sw.proof.shard_id, sw.proof.leaf_index));
    for sw in shard_lifts {
        let watermark = state
            .consumed_through
            .get(&sw.proof.shard_id)
            .copied()
            .unwrap_or(LeafIndex::new(0));
        if sw.proof.leaf_index.inner() != watermark.inner() + 1 {
            continue;
        }
        match apply_shard_payload(state, sw.proof.shard_id, &sw.payload) {
            Some(ShardEvent::Registered(id)) => outcome.registered.push(id),
            Some(ShardEvent::Deactivated(id)) => outcome.deactivated.push(id),
            Some(ShardEvent::Jailed(id)) => outcome.jailed.push(id),
            Some(ShardEvent::Unjailed(id)) => outcome.unjailed.push(id),
            Some(ShardEvent::Readied(id)) => outcome.readied.push(id),
            None => {}
        }
        state
            .consumed_through
            .insert(sw.proof.shard_id, sw.proof.leaf_index);
    }

    // Apply equivocations. Each is re-verified independently before
    // jailing; permanent-Equivocation already-jailed validators are
    // the no-op idempotence case. The validator-id→pubkey lookup is
    // built once per epoch, only when at least one equivocation is
    // present (most slots carry none).
    if !equivocations.is_empty() {
        let lookup: Vec<(ValidatorId, Bls12381G1PublicKey)> = state
            .validators
            .iter()
            .map(|(id, rec)| (*id, rec.pubkey))
            .collect();
        for bw in equivocations {
            let BeaconWitness::Equivocation { evidence } = bw;
            if !verify_equivocation_evidence(evidence, network, &lookup) {
                continue;
            }
            let validator_id = evidence.validator();
            let Some(rec) = state.validators.get(&validator_id) else {
                continue;
            };
            // Equivocation supersedes every status except an existing
            // permanent equivocation jail. The race-exit defence covers
            // `InsufficientStake` (operator tried to escape via
            // `DeactivateValidator`) and fault-cause `Jailed` (the
            // existing jail is upgraded to permanent).
            let already_permanent = matches!(
                rec.status,
                ValidatorStatus::Jailed {
                    reason: JailReason::Equivocation,
                    ..
                }
            );
            if already_permanent {
                continue;
            }
            jail_validator(
                state,
                validator_id,
                JailReason::Equivocation,
                state.current_epoch,
            );
            outcome.jailed.push(validator_id);
        }
    }

    outcome
}

/// Re-validate an [`EquivocationEvidence`] under the current
/// validator-set pubkey lookup. `Vote` re-runs the PC double-sign
/// check; `Recovery` evidence requires recovery-cert infrastructure
/// that hasn't been built yet and currently always returns `false`
/// (silently dropped at the ingestion site).
fn verify_equivocation_evidence(
    evidence: &EquivocationEvidence,
    network: &NetworkDefinition,
    lookup: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match evidence {
        EquivocationEvidence::Vote(v) => verify_vote_equivocation(v, network, lookup),
        EquivocationEvidence::Recovery(_) => false,
    }
}

/// Dispatch a single shard-witness payload to its handler.
///
/// `StakeDeposit` and `StakeWithdraw` mutate pool state without
/// producing a validator-level event — they return `None`. Variants
/// that change validator status return the corresponding
/// [`ShardEvent`] for [`ingest_witnesses`] to route into
/// [`WitnessOutcome`].
///
/// `source_shard` is the shard that emitted the witness (carried in
/// the wrapping [`ShardWitnessProof`](hyperscale_types::ShardWitnessProof)).
/// Most variants ignore it; `MissedProposal` uses it to scope the
/// miss-counter increment to the witness's source committee — a
/// `MissedProposal` from shard S only counts against validators
/// currently `OnShard { shard: S, .. }`.
#[allow(clippy::too_many_lines)] // single dispatch over ShardWitnessPayload variants
fn apply_shard_payload(
    state: &mut BeaconState,
    source_shard: ShardGroupId,
    payload: &ShardWitnessPayload,
) -> Option<ShardEvent> {
    match payload {
        ShardWitnessPayload::StakeDeposit { pool_id, amount } => {
            // Implicit pool creation on first deposit; subsequent
            // deposits accumulate into `total_stake`.
            let pool = state.pools.entry(*pool_id).or_insert_with(|| StakePool {
                id: *pool_id,
                total_stake: Stake::ZERO,
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
            });
            pool.total_stake = pool.total_stake.saturating_add(*amount);
            None
        }
        ShardWitnessPayload::StakeWithdraw { pool_id, amount } => {
            // Withdrawal request enters the unbonding window.
            // `total_stake` is unchanged until maturation;
            // `effective_stake` drops immediately via the added
            // `pending_withdrawals` entry.
            //
            // Defense-in-depth: reject `amount > effective_stake`.
            // Shard staking contracts validate before emitting; the
            // re-check here keeps total_stake whole through the
            // maturation cycle even if a buggy or hostile shard emits
            // an over-withdrawal that `saturating_sub` would silently
            // clamp.
            let pool = state.pools.get_mut(pool_id)?;
            if *amount > effective_stake(pool) {
                return None;
            }
            pool.pending_withdrawals.push(PendingWithdrawal {
                amount: *amount,
                initiated_at_epoch: state.current_epoch,
            });
            None
        }
        ShardWitnessPayload::RegisterValidator {
            pool_id,
            validator_id,
            pubkey,
        } => {
            // Re-registration policy: once a `ValidatorRecord` exists
            // for `validator_id`, no second `RegisterValidator` for
            // that id ever takes effect. The id is dead for the
            // lifetime of the chain.
            if state.validators.contains_key(validator_id) {
                return None;
            }
            // Pool must exist and have capacity at the current dynamic
            // `min_stake` for one more active validator.
            let pool = state.pools.get(pool_id)?;
            if current_active_count(pool, state) + 1 > max_active_count(pool, state) {
                return None;
            }
            // We accept any 48-byte BLS pubkey at registration. Radix's
            // `Bls12381G1PublicKey` doesn't validate G1 membership at
            // construction and exposes no public validator, so the
            // prototype's eager-reject path isn't available here. A
            // malformed key just fails every signature verification it
            // touches; the validator never signs successfully and gets
            // jailed via the miss-counter, costing at most one stalled
            // epoch per malformed registration.
            state.validators.insert(
                *validator_id,
                ValidatorRecord {
                    id: *validator_id,
                    pool: *pool_id,
                    status: ValidatorStatus::Pooled,
                    registered_at_epoch: state.current_epoch,
                    pubkey: *pubkey,
                },
            );
            state
                .pools
                .get_mut(pool_id)
                .expect("pool existence checked above")
                .validators
                .insert(*validator_id);
            Some(ShardEvent::Registered(*validator_id))
        }
        ShardWitnessPayload::DeactivateValidator { validator_id } => {
            // Operator-initiated retirement. Flips to
            // `InsufficientStake` from every status except those that
            // already represent "not consuming a epoch" or "permanently
            // out": `InsufficientStake` itself and
            // `Jailed { Equivocation }`. Fault-cause jails
            // (`Performance`, `Recovery`) can still be deactivated —
            // the operator chooses to retire a jailed validator rather
            // than wait out the cooldown.
            let rec = state.validators.get(validator_id)?;
            let should_deactivate = !matches!(
                rec.status,
                ValidatorStatus::InsufficientStake
                    | ValidatorStatus::Jailed {
                        reason: JailReason::Equivocation,
                        ..
                    }
            );
            if !should_deactivate {
                return None;
            }
            deactivate_to_insufficient_stake(state, *validator_id);
            Some(ShardEvent::Deactivated(*validator_id))
        }
        ShardWitnessPayload::Unjail { id } => {
            // Fault-cause jails return to `Pooled` once cooldown has
            // elapsed AND the pool can still support the additional
            // active epoch at the current dynamic `min_stake`. A pool
            // that over-committed while the validator was jailed
            // strands them — operator recourse is to deactivate
            // another validator or deposit more stake before lifting.
            // Equivocation jails are permanent regardless.
            let rec = state.validators.get(id)?;
            let ValidatorStatus::Jailed {
                since_epoch,
                reason,
            } = rec.status
            else {
                return None;
            };
            if reason == JailReason::Equivocation {
                return None;
            }
            if state.current_epoch.inner() < since_epoch.inner() + JAIL_COOLDOWN_EPOCHS {
                return None;
            }
            let pool_id = rec.pool;
            let pool = state.pools.get(&pool_id)?;
            if current_active_count(pool, state) + 1 > max_active_count(pool, state) {
                return None;
            }
            state
                .validators
                .get_mut(id)
                .expect("rec read above guarantees presence")
                .status = ValidatorStatus::Pooled;
            Some(ShardEvent::Unjailed(*id))
        }
        ShardWitnessPayload::Ready { id } => {
            // Flip `ready: false → true` for an `OnShard` validator.
            // Other statuses (including already-ready `OnShard`) are
            // silent no-ops — re-signalling ready isn't an error,
            // just irrelevant.
            let rec = state.validators.get_mut(id)?;
            if let ValidatorStatus::OnShard {
                shard,
                ready: false,
                placed_at_epoch,
            } = rec.status
            {
                rec.status = ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch,
                };
                Some(ShardEvent::Readied(*id))
            } else {
                None
            }
        }
        ShardWitnessPayload::MissedProposal { proposer_id, .. } => {
            // Shard-binding filter: only count the miss if the named
            // proposer is currently on the *witness's source shard*.
            // Misses from any other shard against this validator —
            // including stale misses after rotation — are silently
            // dropped. Bounds the threat surface to byzantine
            // majorities on the validator's own shard, which already
            // breaks safety locally.
            let rec = state.validators.get(proposer_id)?;
            let ValidatorStatus::OnShard {
                shard: placement_shard,
                ..
            } = rec.status
            else {
                return None;
            };
            if placement_shard != source_shard {
                return None;
            }
            let count = state.miss_counters.entry(*proposer_id).or_insert(0);
            *count += 1;
            if *count < MISSED_PROPOSAL_JAIL_THRESHOLD {
                return None;
            }
            // Threshold crossed: jail under Performance. `jail_validator`
            // re-reads the status to find the shard for the cascade
            // and clears `miss_counters[proposer]` as part of the
            // shared cleanup.
            jail_validator(
                state,
                *proposer_id,
                JailReason::Performance,
                state.current_epoch,
            );
            Some(ShardEvent::Jailed(*proposer_id))
        }
    }
}

/// Transition `victim_id` to `InsufficientStake` with the standard
/// `OnShard` cascade (remove from shard committee + `pool_draw`
/// refill). Other statuses (`Pooled`, fault-cause `Jailed`) flip in
/// place. Already-`InsufficientStake` and already-permanent
/// `Jailed { Equivocation }` callers should not invoke this — there's
/// no transition to make. Callers gate on those cases at the variant
/// dispatch level (see `DeactivateValidator`).
fn deactivate_to_insufficient_stake(state: &mut BeaconState, victim_id: ValidatorId) {
    let Some(rec) = state.validators.get_mut(&victim_id) else {
        return;
    };
    let prior_status = rec.status;
    rec.status = ValidatorStatus::InsufficientStake;
    if let ValidatorStatus::OnShard { shard, .. } = prior_status {
        if let Some(committee) = state.shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != victim_id);
        }
        pool_draw(state, shard);
    }
    // Miss counters are scoped to the validator's current `OnShard`
    // placement; any transition out clears them.
    state.miss_counters.remove(&victim_id);
}

// ─── withdrawal completion ─────────────────────────────────────────────────

/// Outcome of [`complete_pending_withdrawals`].
#[derive(Default)]
struct WithdrawalOutcome {
    /// Validators auto-deactivated to `InsufficientStake` because
    /// their pool's released amount left it over `max_active_count`.
    /// Listed in deactivation order: per-pool by `StakePoolId`
    /// ascending, then highest-`ValidatorId` first within each pool.
    deactivated: Vec<ValidatorId>,
}

/// Mature any [`PendingWithdrawal`] whose unbonding window has
/// elapsed (`current_epoch − initiated_at_epoch ≥
/// UNBONDING_WINDOW_EPOCHS`), subtract the released amount from each
/// affected pool's `total_stake`, and auto-deactivate the pool's
/// highest-id active validators if the release leaves
/// `current_active_count > max_active_count` at the resulting dynamic
/// `min_stake`.
///
/// Per-pool batching: all matured withdrawals on a pool release
/// together. The cumulative `effective_stake` after batch release is
/// identical to processing them one-by-one, and batch avoids
/// spurious intermediate `min_stake` evaluations.
///
/// Cross-pool side effect: this pool's deactivations can raise
/// network-wide `min_stake` (the deactivating pool's `e/k` rises as
/// `k` drops), which in turn lowers every pool's `max_active_count`.
/// Other pools may end up temporarily over-committed as a result.
/// The design explicitly forbids retroactive ejections from a rising
/// `min_stake`; those pools stay over-committed until their own
/// withdrawal or operator action reconciles them.
///
/// Termination: each iteration of the inner loop strictly decreases
/// `current_active_count(pool)` by 1 (the victim flips from
/// `Pooled|OnShard` to `InsufficientStake`; the refill `pool_draw`
/// inside `deactivate_to_insufficient_stake` runs `Pooled → OnShard`
/// and both statuses count). The loop terminates in at most `cur`
/// iterations per over-committed pool.
fn complete_pending_withdrawals(state: &mut BeaconState) -> WithdrawalOutcome {
    let mut outcome = WithdrawalOutcome::default();
    let current_epoch = state.current_epoch.inner();
    let pool_ids: Vec<StakePoolId> = state.pools.keys().copied().collect();
    for pool_id in pool_ids {
        let released = {
            let pool = state.pools.get_mut(&pool_id).expect("just iterated");
            let mut sum = Stake::ZERO;
            pool.pending_withdrawals.retain(|w| {
                if current_epoch.saturating_sub(w.initiated_at_epoch.inner())
                    >= UNBONDING_WINDOW_EPOCHS
                {
                    sum = sum.saturating_add(w.amount);
                    false
                } else {
                    true
                }
            });
            sum
        };
        if released == Stake::ZERO {
            continue;
        }
        {
            let pool = state.pools.get_mut(&pool_id).expect("present");
            pool.total_stake = pool.total_stake.saturating_sub(released);
        }
        // Auto-deactivate highest-id active validators until balanced.
        // `min_stake` is re-evaluated each iteration because dropping
        // this pool's active count by 1 raises its `e/k` contribution
        // to `t_no_eject`, weakly raising `min_stake` and weakly
        // shrinking `max_active_count`. The loop only shrinks the
        // budget — never grows it.
        loop {
            let (cur, max) = {
                let pool = state.pools.get(&pool_id).expect("present");
                (
                    current_active_count(pool, state),
                    max_active_count(pool, state),
                )
            };
            if cur <= max {
                break;
            }
            let victim = {
                let pool = state.pools.get(&pool_id).expect("present");
                pool.validators
                    .iter()
                    .rev()
                    .find(|id| {
                        matches!(
                            state.validators.get(id).map(|r| &r.status),
                            Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
                        )
                    })
                    .copied()
            };
            let Some(victim_id) = victim else {
                break;
            };
            deactivate_to_insufficient_stake(state, victim_id);
            outcome.deactivated.push(victim_id);
        }
    }
    outcome
}

// ─── auto reactivation ─────────────────────────────────────────────────────

/// Promote `InsufficientStake` validators back to `Pooled` for every
/// pool that has newly-available capacity, looping until no pool can
/// reactivate further.
///
/// Capacity becomes available when a `StakeDeposit` arrives or when
/// any pool's reactivation lowers network-wide `min_stake` (each
/// reactivation drops the pool's contribution to `t_no_eject` from
/// `e/cur` to `e/(cur + 1)`, weakly smaller). The downstream effect
/// is that every pool's `max_active_count` is weakly non-decreasing
/// through the loop, so reactivation in pool A can unlock further
/// reactivations in pool B.
///
/// Per-iteration progress: each successful flip removes one validator
/// from the `InsufficientStake` set, which monotonically shrinks
/// since the only way to *enter* `InsufficientStake` is via
/// withdrawal completion or an explicit deactivation — neither of
/// which runs inside this loop. The loop terminates in O(N²) at
/// worst, in practice O(N).
///
/// The "doesn't immediately re-promote a just-deactivated validator"
/// property is provided by the gate: the pool that triggered the
/// deactivation in `complete_pending_withdrawals` now has
/// `cur >= max` (the deactivation was *because* of over-commitment),
/// so this loop skips it.
fn auto_reactivate(state: &mut BeaconState) -> Vec<ValidatorId> {
    let mut reactivated = Vec::new();
    loop {
        let mut did_any = false;
        let pool_ids: Vec<StakePoolId> = state.pools.keys().copied().collect();
        for pool_id in pool_ids {
            let (cur, max) = {
                let pool = state.pools.get(&pool_id).expect("just iterated");
                (
                    current_active_count(pool, state),
                    max_active_count(pool, state),
                )
            };
            if cur >= max {
                continue;
            }
            let candidate = {
                let pool = state.pools.get(&pool_id).expect("present");
                pool.validators
                    .iter()
                    .rev()
                    .find(|id| {
                        matches!(
                            state.validators.get(id).map(|r| &r.status),
                            Some(ValidatorStatus::InsufficientStake),
                        )
                    })
                    .copied()
            };
            let Some(rev_id) = candidate else {
                continue;
            };
            state
                .validators
                .get_mut(&rev_id)
                .expect("just found via the pool's validator set")
                .status = ValidatorStatus::Pooled;
            reactivated.push(rev_id);
            did_any = true;
        }
        if !did_any {
            break;
        }
    }
    reactivated
}

// ─── epoch rewards ─────────────────────────────────────────────────────────

/// Credit one epoch's emissions across stake pools pro-rata to each
/// pool's count of `OnShard { ready: true }` validators.
///
/// Pure deterministic function of `(state)`. Returns the per-pool
/// credits actually applied; zero-share pools are omitted.
///
/// Integer-division rounding remainder is burned — the per-year
/// emission envelope ([`TOKENS_PER_YEAR_TARGET`](crate::constants::TOKENS_PER_YEAR_TARGET))
/// is a sizing target, not a hard cap, so the per-epoch remainder
/// (at most `active_pools − 1` attos) drops on the floor rather than
/// accumulating in state.
/// Epochs where no pool has a ready `OnShard` validator return an
/// empty map without crediting — the whole epoch's emission burns.
///
/// `u128` intermediate arithmetic is overflow-safe for the full
/// `Stake` range: the multiplication is `emission × validators_in_pool`,
/// both bounded well below `u128::MAX / u128::MAX` headroom.
fn distribute_epoch_rewards(state: &mut BeaconState) -> BTreeMap<StakePoolId, Stake> {
    let mut active_count: BTreeMap<StakePoolId, u64> = BTreeMap::new();
    for record in state.validators.values() {
        if matches!(record.status, ValidatorStatus::OnShard { ready: true, .. }) {
            *active_count.entry(record.pool).or_insert(0) += 1;
        }
    }
    let total_active: u64 = active_count.values().sum();
    if total_active == 0 {
        return BTreeMap::new();
    }
    let emission = EMISSIONS_PER_EPOCH.attos();
    let total = u128::from(total_active);
    let mut credited = BTreeMap::new();
    for (pool_id, n) in active_count {
        let share_attos = emission * u128::from(n) / total;
        if share_attos == 0 {
            continue;
        }
        let share = Stake::from_attos(share_attos);
        let pool = state
            .pools
            .get_mut(&pool_id)
            .expect("OnShard validator's pool must be present in state.pools");
        pool.total_stake = pool.total_stake.saturating_add(share);
        credited.insert(pool_id, share);
    }
    credited
}

// ─── auto-ready timeout ────────────────────────────────────────────────────

/// Flip `OnShard { ready: false }` validators to `ready: true` once
/// `current_epoch − placed_at_epoch ≥ READY_TIMEOUT_EPOCHS`.
///
/// Backstop for the event-driven ready path: validators normally
/// signal sync-completion via a `Ready` shard witness; the timeout
/// catches the case where that signal never arrives. A validator
/// auto-readied while still mid-sync exposes themselves to a
/// `MissedProposal` jail cascade — they'll miss votes, accumulate
/// misses, and the threshold trips the normal performance jail.
///
/// Returns the ids that flipped this epoch, deterministic ascending
/// by `BTreeMap` iteration.
fn auto_ready_timeout(state: &mut BeaconState) -> Vec<ValidatorId> {
    let current_epoch = state.current_epoch.inner();
    let mut readied = Vec::new();
    for (id, rec) in &mut state.validators {
        if let ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch,
        } = rec.status
            && current_epoch.saturating_sub(placed_at_epoch.inner()) >= READY_TIMEOUT_EPOCHS
        {
            rec.status = ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch,
            };
            readied.push(*id);
        }
    }
    readied
}

// ─── shuffle step ──────────────────────────────────────────────────────────

/// Trickled committee rotation. When `state.current_epoch` lands on a
/// [`SHUFFLE_INTERVAL_EPOCHS`] boundary (and `epoch > 0`), each shard
/// rotates one of its ready `OnShard` validators back to `Pooled` and
/// immediately refills the freed slot via [`pool_draw`]. The system-wide
/// rotation rate is one validator per shard per
/// [`SHUFFLE_INTERVAL_EPOCHS`] epochs, keeping per-shard composition
/// churn uniform and bounded.
///
/// Shards iterate in sorted [`ShardGroupId`] order; the victim within
/// each shard is picked deterministically by hashing
/// `(state.randomness, current_epoch, shard)` under a domain tag
/// distinct from [`pool_draw`]'s. Shards whose `OnShard { ready: true }`
/// member set is empty are skipped.
///
/// Ordering invariant — pinned by `shuffle_avoids_self_replacement`:
///
/// 1. Remove the victim from the shard committee.
/// 2. [`pool_draw`] to refill — the derived pool excludes the victim
///    because their status is still `OnShard` here.
/// 3. Flip the victim's status to `Pooled`.
///
/// Flipping status *after* the draw is what prevents self-replacement:
/// derivation makes "in the pool" mean "status == Pooled", so flipping
/// early would put the victim in the pool just in time for the same
/// draw to pick them. A later shard's draw in the same step may pick
/// the victim and place them on a different shard — a legitimate
/// cross-shard reassignment.
fn run_shuffle_step(state: &mut BeaconState) {
    let epoch = state.current_epoch;
    if epoch.inner() == 0 || !epoch.inner().is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
        return;
    }
    let shard_ids: Vec<ShardGroupId> = state.shard_committees.keys().copied().collect();
    for shard in shard_ids {
        // Bind the candidate set to validators whose status records
        // *this* shard. The global invariant `members ⇔ status ==
        // OnShard { shard: s, .. }` holds today; matching the shard
        // here means a future bug that drops a transition site (a
        // stale `members` entry pointing at a different shard) fails
        // to a skipped shuffle rather than picking from the wrong
        // shard.
        let ready_members: Vec<ValidatorId> = state
            .shard_committees
            .get(&shard)
            .expect("just iterated")
            .members
            .iter()
            .copied()
            .filter(|id| {
                matches!(
                    state.validators.get(id).map(|r| &r.status),
                    Some(ValidatorStatus::OnShard { shard: s, ready: true, .. }) if *s == shard
                )
            })
            .collect();
        if ready_members.is_empty() {
            continue;
        }
        let mut h = Hasher::new();
        h.update(DOMAIN_SHUFFLE_EXIT);
        h.update(state.randomness.as_bytes());
        h.update(&epoch.inner().to_le_bytes());
        h.update(&shard.inner().to_le_bytes());
        let seed = *h.finalize().as_bytes();
        let mut prng = prng_from(&seed);
        let idx = prng.random_range(0..ready_members.len());
        let victim = ready_members[idx];

        state
            .shard_committees
            .get_mut(&shard)
            .expect("present")
            .members
            .retain(|v| *v != victim);
        pool_draw(state, shard);
        state
            .validators
            .get_mut(&victim)
            .expect("victim is in state.validators")
            .status = ValidatorStatus::Pooled;
    }
}

// ─── shard committee diff ──────────────────────────────────────────────────

/// Compare each shard's current `members` against the epoch-start
/// snapshot and emit one [`CommitteeTransition`] per shard whose
/// membership *set* changed. Members are compared as sets, so a no-op
/// churn (e.g. jail one validator, [`pool_draw`] refills with the same
/// one) doesn't register as a transition.
///
/// The cause is shared across all transitions emitted in one epoch:
///
/// - [`TransitionCause::NaturalShuffle`] when the epoch landed on a
///   shuffle interval boundary (the dominant cadence on those epochs).
/// - [`TransitionCause::MembershipChange`] otherwise — irregular events
///   like jail, deactivate, or withdrawal-completion auto-deactivation
///   drove the change.
///
/// Shards present in the snapshot but missing from the current state
/// (or vice versa) aren't normal under a stable shard count, but the
/// diff is robust to either case by treating the missing side as an
/// empty member list.
fn diff_shard_committees(
    state: &BeaconState,
    pre_shard_members: &BTreeMap<ShardGroupId, Vec<ValidatorId>>,
) -> BTreeMap<ShardGroupId, CommitteeTransition> {
    let epoch = state.current_epoch;
    let cause = if epoch.inner() > 0 && epoch.inner().is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
        TransitionCause::NaturalShuffle
    } else {
        TransitionCause::MembershipChange
    };
    let mut shard_ids: BTreeSet<ShardGroupId> = pre_shard_members.keys().copied().collect();
    shard_ids.extend(state.shard_committees.keys().copied());
    let mut transitions = BTreeMap::new();
    for shard in shard_ids {
        let prior = pre_shard_members.get(&shard).cloned().unwrap_or_default();
        let current = state
            .shard_committees
            .get(&shard)
            .map(|c| c.members.clone())
            .unwrap_or_default();
        let prior_set: BTreeSet<ValidatorId> = prior.iter().copied().collect();
        let current_set: BTreeSet<ValidatorId> = current.iter().copied().collect();
        if prior_set != current_set {
            transitions.insert(
                shard,
                CommitteeTransition {
                    from: prior,
                    to: current,
                    cause,
                    at_slot: epoch,
                },
            );
        }
    }
    transitions
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Bls12381G1PrivateKey, bls_keypair_from_seed, vrf_output_from_proof, vrf_sign,
    };

    use super::*;

    // ─── fixture helpers ──────────────────────────────────────────────────

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        keypair(seed).public_key()
    }

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    /// Build an honest VRF-signed empty `BeaconProposal` for validator
    /// `id` at `epoch`. No witnesses (witness ingestion is a later
    /// stage); just a deterministic VRF reveal.
    fn vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
        let sk = keypair(id);
        let (output, proof) = vrf_sign(&sk, &net(), epoch);
        BeaconProposal::new(Vec::new(), output, proof)
    }

    /// Build a `BeaconProposal` whose VRF proof has been tampered with
    /// so verification fails. The (output, proof) pair is internally
    /// consistent by hash binding, but the BLS sig is broken.
    fn malformed_vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
        let p = vrf_proposal(id, epoch);
        let mut proof = p.vrf_proof();
        proof.0[0] ^= 1;
        // Output binding still matches the tampered proof (so we get
        // past the binding check); only the BLS verify fails.
        let output = vrf_output_from_proof(&proof);
        BeaconProposal::new(Vec::new(), output, proof)
    }

    fn validator_record(id: u64, pool: u32, status: ValidatorStatus) -> ValidatorRecord {
        ValidatorRecord {
            id: ValidatorId::new(id),
            pool: StakePoolId::new(pool),
            status,
            registered_at_epoch: Epoch::GENESIS,
            pubkey: pubkey(id),
        }
    }

    fn empty_state() -> BeaconState {
        BeaconState {
            current_epoch: Epoch::GENESIS,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            randomness: Randomness::ZERO,
            committee: Vec::new(),
            shard_committees: BTreeMap::new(),
            consumed_through: BTreeMap::new(),
            last_recovery_cert: None,
            miss_counters: BTreeMap::new(),
        }
    }

    /// Build a state with one shard, one pool, and `n_active` validators
    /// placed `OnShard { ready: true }`. The pool's `total_stake` is
    /// `n_active * MIN_STAKE_FLOOR` — just enough to cover the active
    /// set at the floor.
    fn single_pool_state(n_active: u64) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);

        let mut pool_validators = BTreeSet::new();
        let mut members = Vec::new();
        for i in 0..n_active {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_attos(u128::from(n_active) * MIN_STAKE_FLOOR.attos()),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
            .shard_committees
            .insert(shard, ShardCommittee { members });
        state
    }

    // ─── effective_stake ──────────────────────────────────────────────────

    #[test]
    fn effective_stake_subtracts_pending_withdrawals() {
        let pool = StakePool {
            id: StakePoolId::new(0),
            total_stake: Stake::from_whole_tokens(1_000),
            validators: BTreeSet::new(),
            pending_withdrawals: vec![
                PendingWithdrawal {
                    amount: Stake::from_whole_tokens(100),
                    initiated_at_epoch: Epoch::new(1),
                },
                PendingWithdrawal {
                    amount: Stake::from_whole_tokens(250),
                    initiated_at_epoch: Epoch::new(2),
                },
            ],
        };
        assert_eq!(effective_stake(&pool), Stake::from_whole_tokens(650));
    }

    /// Defense-in-depth: an over-withdrawal (bookkeeping drift, hostile
    /// shard) clamps `effective_stake` to zero rather than wrapping.
    #[test]
    fn effective_stake_saturates_when_pending_exceeds_total() {
        let pool = StakePool {
            id: StakePoolId::new(0),
            total_stake: Stake::from_whole_tokens(100),
            validators: BTreeSet::new(),
            pending_withdrawals: vec![PendingWithdrawal {
                amount: Stake::from_whole_tokens(500),
                initiated_at_epoch: Epoch::GENESIS,
            }],
        };
        assert_eq!(effective_stake(&pool), Stake::ZERO);
    }

    // ─── current_active_count ────────────────────────────────────────────

    #[test]
    fn current_active_count_includes_pooled_and_on_shard() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(current_active_count(pool, &state), 4);
    }

    #[test]
    fn current_active_count_excludes_jailed_and_insufficient_stake() {
        let mut state = single_pool_state(4);
        // Jail one, mark another InsufficientStake — both must drop out.
        state
            .validators
            .get_mut(&ValidatorId::new(0))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };
        state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::InsufficientStake;
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(current_active_count(pool, &state), 2);
    }

    // ─── pooled_validators ───────────────────────────────────────────────

    #[test]
    fn pooled_validators_returns_only_pooled_in_id_order() {
        let mut state = single_pool_state(0);
        // Insert out of id order to confirm BTreeMap iteration sorts.
        for id in [3u64, 0, 2, 1] {
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        // Insert a non-Pooled validator that must be filtered out.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::InsufficientStake),
        );
        assert_eq!(
            pooled_validators(&state),
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }

    // ─── min_stake ───────────────────────────────────────────────────────

    /// Empty state — no pools, no active validators. `t_no_eject` and
    /// `admit_threshold` both default high; `min_stake` clamps to
    /// `MIN_STAKE_FLOOR`.
    #[test]
    fn min_stake_floor_on_empty_state() {
        let state = empty_state();
        assert_eq!(min_stake(&state), MIN_STAKE_FLOOR);
    }

    /// One pool, four active validators, total stake exactly `4 ×
    /// MIN_STAKE_FLOOR`. `t_no_eject = MIN_STAKE_FLOOR` (tightest
    /// pool's ratio), so `min_stake` lands at the floor.
    #[test]
    fn min_stake_clamps_to_floor_at_tight_pool() {
        let state = single_pool_state(4);
        assert_eq!(min_stake(&state), MIN_STAKE_FLOOR);
    }

    // ─── max_active_count ────────────────────────────────────────────────

    #[test]
    fn max_active_count_equals_effective_over_min_stake() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        // 4 floors of stake, `min_stake = floor` ⇒ cap of 4.
        assert_eq!(max_active_count(pool, &state), 4);
    }

    /// A pending withdrawal that empties the pool's effective stake
    /// drops `max_active_count` to zero, even though `total_stake`
    /// remains funded.
    #[test]
    fn max_active_count_respects_pending_withdrawals() {
        let mut state = single_pool_state(4);
        let pool_mut = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool_mut.pending_withdrawals.push(PendingWithdrawal {
            amount: pool_mut.total_stake,
            initiated_at_epoch: Epoch::GENESIS,
        });
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(max_active_count(pool, &state), 0);
    }

    // ─── miss counter sanity ──────────────────────────────────────────────

    /// Pins the `miss_counters` field shape (per-validator `u32`
    /// counter) so a future refactor that changes the value type is
    /// caught. The scoping invariants (per-epoch reset, status-
    /// transition reset) live with `apply_epoch`, not the type.
    #[test]
    fn miss_counters_field_is_per_validator_u32_map() {
        let mut state = empty_state();
        state.miss_counters.insert(ValidatorId::new(5), 3);
        state.miss_counters.insert(ValidatorId::new(7), 12);
        assert_eq!(state.miss_counters.get(&ValidatorId::new(5)), Some(&3));
        assert_eq!(state.miss_counters.get(&ValidatorId::new(7)), Some(&12));
    }

    // ─── pool_draw ───────────────────────────────────────────────────────

    /// Build a state with `n` validators all sitting in the global pool
    /// (status `Pooled`), one empty shard, and the given randomness +
    /// `current_epoch`. `pool_draw` reads `state.current_epoch` and
    /// `state.current_epoch` so the caller sets it up explicitly.
    fn state_with_pool(n: u64, randomness: Randomness, current_epoch: Epoch) -> BeaconState {
        let mut state = empty_state();
        state.current_epoch = current_epoch;
        state.randomness = randomness;
        let pool_id = StakePoolId::new(0);
        let mut pool_validators = BTreeSet::new();
        for i in 0..n {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            state
                .validators
                .insert(id, validator_record(i, 0, ValidatorStatus::Pooled));
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_attos(u128::from(n) * MIN_STAKE_FLOOR.attos()),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
            .shard_committees
            .insert(ShardGroupId::new(0), ShardCommittee::default());
        state
    }

    #[test]
    fn pool_draw_returns_none_when_pool_empty() {
        let mut state = empty_state();
        state
            .shard_committees
            .insert(ShardGroupId::new(0), ShardCommittee::default());
        assert_eq!(pool_draw(&mut state, ShardGroupId::new(0)), None);
        assert!(
            state.shard_committees[&ShardGroupId::new(0)]
                .members
                .is_empty()
        );
    }

    /// Two states built from byte-identical inputs must produce the
    /// same pick. Determinism is what lets every honest replica
    /// converge after a pool-draw event.
    #[test]
    fn pool_draw_is_deterministic_across_replicas() {
        let mut a = state_with_pool(8, Randomness([0x5A; 32]), Epoch::new(1));
        let mut b = state_with_pool(8, Randomness([0x5A; 32]), Epoch::new(1));
        let pick_a = pool_draw(&mut a, ShardGroupId::new(0)).unwrap();
        let pick_b = pool_draw(&mut b, ShardGroupId::new(0)).unwrap();
        assert_eq!(pick_a, pick_b);
        assert_eq!(a.shard_committees, b.shard_committees);
        assert_eq!(pooled_validators(&a), pooled_validators(&b));
    }

    /// Two draws at the same `(epoch, shard)` pick distinct validators
    /// even though the PRNG seed re-derives identically. The first
    /// draw flips its chosen validator to `OnShard`; the second draw's
    /// `pooled_validators` re-derivation excludes them, so the second
    /// draw indexes into a strictly smaller pool of different members.
    #[test]
    fn pool_draw_two_calls_same_slot_shard_pick_distinct_validators() {
        let mut state = state_with_pool(8, Randomness([0x42; 32]), Epoch::new(1));
        let first = pool_draw(&mut state, ShardGroupId::new(0)).unwrap();
        let second = pool_draw(&mut state, ShardGroupId::new(0)).unwrap();
        assert_ne!(first, second);
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 2);
        assert!(members.contains(&first));
        assert!(members.contains(&second));
        assert_eq!(pooled_validators(&state).len(), 8 - 2);
    }

    /// Chosen validator transitions to `OnShard { ready: false }` with
    /// `placed_at_epoch` set to `state.current_epoch`.
    #[test]
    fn pool_draw_places_chosen_validator_with_current_epoch() {
        let placed_epoch = Epoch::new(5);
        let mut state = state_with_pool(4, Randomness([0x99; 32]), placed_epoch);
        let chosen = pool_draw(&mut state, ShardGroupId::new(0)).unwrap();
        let status = state.validators.get(&chosen).unwrap().status;
        assert_eq!(
            status,
            ValidatorStatus::OnShard {
                shard: ShardGroupId::new(0),
                ready: false,
                placed_at_epoch: placed_epoch,
            },
        );
    }

    /// Different shards within the same `(state, epoch)` use distinct
    /// PRNG streams. Across multiple randomness values at least one
    /// pair must differ — if the shard id were collapsed out of the
    /// seed, no pair would ever differ.
    #[test]
    fn pool_draw_across_shards_uses_distinct_seeds() {
        let any_differ = (0u8..16).any(|i| {
            let mut a = state_with_pool(8, Randomness([i; 32]), Epoch::GENESIS);
            // Add a second shard so the draw target exists.
            a.shard_committees
                .insert(ShardGroupId::new(1), ShardCommittee::default());
            let mut b = a.clone();
            let pick_a = pool_draw(&mut a, ShardGroupId::new(0)).unwrap();
            let pick_b = pool_draw(&mut b, ShardGroupId::new(1)).unwrap();
            pick_a != pick_b
        });
        assert!(any_differ);
    }

    // ─── apply_epoch regression check + epoch advance ──────────────────────

    /// `apply_epoch` rejects a epoch that doesn't strictly advance
    /// `state.current_epoch`. Catches runner bugs that replay or
    /// re-order SPC commits before the chain-difference math
    /// (cooldown, unbonding, ready-timeout) silently underflows.
    #[test]
    #[should_panic(expected = "apply_epoch regression")]
    fn apply_epoch_panics_on_slot_replay() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(&mut state, &net(), Epoch::new(5), &[]);
        // Replay of epoch 5: current_epoch is now 5, so epoch=5 is
        // neither advance nor regression — must panic.
        apply_epoch(&mut state, &net(), Epoch::new(5), &[]);
    }

    #[test]
    #[should_panic(expected = "apply_epoch regression")]
    fn apply_epoch_panics_on_slot_going_backwards() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(&mut state, &net(), Epoch::new(5), &[]);
        apply_epoch(&mut state, &net(), Epoch::new(3), &[]);
    }

    #[test]
    fn apply_epoch_advances_current_epoch() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(&mut state, &net(), Epoch::new(7), &[]);
        assert_eq!(state.current_epoch, Epoch::new(7));
    }

    // ─── filter_and_roll_randomness ──────────────────────────────────────

    /// Randomness rolls even on an all-empty epoch. The mixer runs over
    /// `prev_randomness` alone — needed so the "all rejected" path is
    /// well-defined and the chain doesn't stall on a silent epoch.
    #[test]
    fn randomness_rolls_with_empty_committed() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let prior = state.randomness;
        apply_next_epoch(&mut state, &[]);
        assert_ne!(state.randomness, prior);
    }

    /// A proposal from a non-committee party is silently dropped — no
    /// jail, no randomness contribution, no `rejected_reveals` entry.
    /// Defends against runner-level bugs that pass a stray proposal in.
    #[test]
    fn non_committee_proposal_is_silently_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert validator 5 with a record but NOT in the committee.
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );
        let prior = state.randomness;
        let bad = vec![(
            ValidatorId::new(5),
            vrf_proposal(5, state.current_epoch.next()),
        )];
        let effects = apply_next_epoch(&mut state, &bad);
        // Randomness rolled (over prev alone), but no contribution
        // from the dropped proposal — and no rejected_reveals entry.
        assert_ne!(state.randomness, prior);
        assert!(effects.rejected_reveals.is_empty());
        assert!(effects.jailed.is_empty());
    }

    /// Honest VRF reveal verifies and contributes to randomness;
    /// `rejected_reveals` stays empty.
    #[test]
    fn honest_proposal_advances_randomness_without_rejection() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let committed = vec![
            (
                ValidatorId::new(0),
                vrf_proposal(0, state.current_epoch.next()),
            ),
            (
                ValidatorId::new(1),
                vrf_proposal(1, state.current_epoch.next()),
            ),
        ];
        let prior = state.randomness;
        let effects = apply_next_epoch(&mut state, &committed);
        assert_ne!(state.randomness, prior);
        assert!(effects.rejected_reveals.is_empty());
        assert!(effects.jailed.is_empty());
    }

    /// Two states fed byte-identical inputs land on byte-identical
    /// randomness — pins the determinism the chain relies on.
    #[test]
    fn randomness_roll_is_deterministic_across_replicas() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        a.committee = (0u64..4).map(ValidatorId::new).collect();
        b.committee = a.committee.clone();
        let target = a.current_epoch.next();
        let committed = vec![
            (ValidatorId::new(0), vrf_proposal(0, target)),
            (ValidatorId::new(1), vrf_proposal(1, target)),
        ];
        apply_next_epoch(&mut a, &committed);
        apply_next_epoch(&mut b, &committed);
        assert_eq!(a.randomness, b.randomness);
    }

    /// Malformed VRF reveal jails the proposer under
    /// `JailReason::Performance` and cascades: removal from the shard
    /// committee + `pool_draw` refill from any remaining pooled
    /// validators.
    #[test]
    fn malformed_vrf_jails_proposer_and_refills_via_pool_draw() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add a fifth validator sitting in the pool; pool stake bumped
        // to support them.
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let committed = vec![(
            ValidatorId::new(0),
            malformed_vrf_proposal(0, state.current_epoch.next()),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        // Proposer 0 in rejected_reveals AND jailed.
        assert_eq!(effects.rejected_reveals, vec![ValidatorId::new(0)]);
        assert_eq!(effects.jailed, vec![ValidatorId::new(0)]);
        // Status flipped to Jailed { Performance, since_epoch = current }.
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        // Shard committee size stays at 4 — validator 4 drawn from
        // pool to refill the freed epoch.
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
        // Validator 4 is now OnShard (refill from pool).
        let refill_status = state.validators.get(&ValidatorId::new(4)).unwrap().status;
        assert!(matches!(
            refill_status,
            ValidatorStatus::OnShard { shard, ready: false, .. } if shard == ShardGroupId::new(0),
        ));
    }

    /// Malformed VRF still rejects the proposal's randomness
    /// contribution even though it jails the proposer — the rejected
    /// reveal's output is NOT mixed in. Pinning this prevents a
    /// regression where a "rejected but contributes anyway" bug would
    /// let a byzantine proposer grind randomness while accepting the
    /// jail.
    #[test]
    fn malformed_vrf_does_not_contribute_to_randomness() {
        let mut state_a = single_pool_state(4);
        let mut state_b = single_pool_state(4);
        state_a.committee = (0u64..4).map(ValidatorId::new).collect();
        state_b.committee = state_a.committee.clone();

        // A: one honest proposer at epoch 1.
        let target = state_a.current_epoch.next();
        let honest_only = vec![(ValidatorId::new(1), vrf_proposal(1, target))];
        apply_next_epoch(&mut state_a, &honest_only);

        // B: same honest proposer + one malformed reveal from proposer 0.
        let mixed = vec![
            (ValidatorId::new(0), malformed_vrf_proposal(0, target)),
            (ValidatorId::new(1), vrf_proposal(1, target)),
        ];
        apply_next_epoch(&mut state_b, &mixed);

        // Randomness identical — the malformed reveal contributed nothing.
        assert_eq!(state_a.randomness, state_b.randomness);
    }

    // ─── ingest_witnesses framework + stake variants ─────────────────────

    use hyperscale_types::{
        BlockHash, BoundedVec, ShardWitness, ShardWitnessPayload, ShardWitnessProof, Witness,
    };

    /// Build a VRF-signed proposal for `id` at `epoch` carrying the given
    /// witnesses. The `BoundedVec` inside `BeaconProposal` still caps
    /// witness count at construction.
    fn vrf_proposal_with_witnesses(
        id: u64,
        epoch: Epoch,
        witnesses: Vec<Witness>,
    ) -> BeaconProposal {
        let sk = keypair(id);
        let (output, proof) = vrf_sign(&sk, &net(), epoch);
        BeaconProposal::new(witnesses, output, proof)
    }

    /// Apply the next epoch on top of `state.current_epoch`. Helper to
    /// avoid the borrow-checker complaint of calling `apply_epoch`
    /// with `state.current_epoch.next()` inline.
    fn apply_next_epoch(
        state: &mut BeaconState,
        committed: &[(ValidatorId, BeaconProposal)],
    ) -> SlotEffects {
        let next = state.current_epoch.next();
        apply_epoch(state, &net(), next, committed)
    }

    fn shard_witness(shard_id: u64, leaf_index: u64, payload: ShardWitnessPayload) -> Witness {
        Witness::Shard(ShardWitness {
            payload,
            proof: ShardWitnessProof {
                shard_id: ShardGroupId::new(shard_id),
                committed_block_hash: BlockHash::ZERO,
                leaf_index: LeafIndex::new(leaf_index),
                siblings: BoundedVec::new(),
            },
        })
    }

    /// `StakeDeposit` for an unknown pool implicitly creates the pool
    /// and accumulates `total_stake`. Subsequent deposits accumulate
    /// further.
    #[test]
    fn stake_deposit_creates_pool_implicitly_and_accumulates() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool 7 doesn't exist yet — first StakeDeposit creates it.
        let w0 = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(100),
            },
        );
        // Second deposit on the same pool accumulates.
        let w1 = shard_witness(
            0,
            2,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(50),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w0, w1]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(150));
        // Watermark advanced to 2 for shard 0.
        assert_eq!(
            state.consumed_through.get(&ShardGroupId::new(0)),
            Some(&LeafIndex::new(2))
        );
    }

    /// `StakeWithdraw` appends a `PendingWithdrawal` tagged with the
    /// current epoch; `total_stake` is unchanged but `effective_stake`
    /// drops immediately.
    #[test]
    fn stake_withdraw_records_pending_withdrawal_at_current_epoch() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(3);
        let pool_id = StakePoolId::new(0);
        let pre_total = state.pools.get(&pool_id).unwrap().total_stake;
        let pre_effective = effective_stake(state.pools.get(&pool_id).unwrap());

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: Stake::from_whole_tokens(1_000),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&pool_id).unwrap();
        // StakeWithdraw doesn't touch total_stake; the epoch's emission
        // credit (single ready pool collects the full share) accounts
        // for the only delta.
        assert_eq!(
            pool.total_stake,
            pre_total.saturating_add(EMISSIONS_PER_EPOCH)
        );
        // pending_withdrawals records the request at current_epoch.
        assert_eq!(pool.pending_withdrawals.len(), 1);
        assert_eq!(
            pool.pending_withdrawals[0].amount,
            Stake::from_whole_tokens(1_000)
        );
        assert_eq!(
            pool.pending_withdrawals[0].initiated_at_epoch,
            state.current_epoch
        );
        // effective_stake = total_stake − pending; pending up by 1000
        // whole tokens, total up by the epoch emission.
        assert_eq!(
            effective_stake(pool),
            pre_effective
                .saturating_add(EMISSIONS_PER_EPOCH)
                .saturating_sub(Stake::from_whole_tokens(1_000)),
        );
    }

    /// Defense-in-depth: an over-withdrawal (`amount > effective_stake`)
    /// is rejected outright — no `pending_withdrawals` entry added.
    /// Without this, `saturating_sub` in `effective_stake` would
    /// silently clamp accounting to zero.
    #[test]
    fn stake_withdraw_rejects_over_effective_stake() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        let effective = effective_stake(state.pools.get(&pool_id).unwrap());

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: effective.saturating_add(Stake::from_whole_tokens(1)),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&pool_id).unwrap();
        assert!(pool.pending_withdrawals.is_empty());
        // Watermark still advances on apply (the witness was consumed,
        // even though the variant rejected it).
        assert_eq!(
            state.consumed_through.get(&ShardGroupId::new(0)),
            Some(&LeafIndex::new(1))
        );
    }

    /// Within-epoch dedup: the same `(shard_id, leaf_index)` carried by
    /// multiple proposers counts as one event. Pins the dedup gate
    /// against a future refactor.
    #[test]
    fn witness_dedup_by_shard_and_leaf_index() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Same deposit witness submitted by three proposers — should
        // apply exactly once.
        let payload = ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(7),
            amount: Stake::from_whole_tokens(100),
        };
        let committed: Vec<(ValidatorId, BeaconProposal)> = (0u64..3)
            .map(|i| {
                (
                    ValidatorId::new(i),
                    vrf_proposal_with_witnesses(
                        i,
                        Epoch::new(1),
                        vec![shard_witness(0, 1, payload.clone())],
                    ),
                )
            })
            .collect();
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        // Only one deposit applied — total_stake reflects a single 100.
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(100));
    }

    /// Watermark gate: a witness with `leaf_index != consumed + 1` is
    /// silently dropped. Gaps and re-plays don't apply.
    #[test]
    fn watermark_gate_drops_gap_and_replay() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-set the watermark to 5; submit a witness for leaf_index 7
        // (gap) and another for leaf_index 5 (replay). Neither applies.
        state
            .consumed_through
            .insert(ShardGroupId::new(0), LeafIndex::new(5));

        let gap = shard_witness(
            0,
            7,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(1),
            },
        );
        let replay = shard_witness(
            0,
            5,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(8),
                amount: Stake::from_whole_tokens(1),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![gap, replay]),
        )];
        apply_next_epoch(&mut state, &committed);

        // Neither pool was touched.
        assert!(!state.pools.contains_key(&StakePoolId::new(7)));
        assert!(!state.pools.contains_key(&StakePoolId::new(8)));
        // Watermark unchanged.
        assert_eq!(
            state.consumed_through.get(&ShardGroupId::new(0)),
            Some(&LeafIndex::new(5))
        );
    }

    /// In-order application: a sequence of consecutive `leaf_index` from
    /// the same shard, even when submitted out of order in the
    /// proposal, applies in order and advances the watermark by all.
    #[test]
    fn witnesses_applied_in_leaf_index_order() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Three deposits at indices 1, 2, 3 to pool 7, submitted in
        // reverse order in the proposal.
        let ws = vec![
            shard_witness(
                0,
                3,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(3),
                },
            ),
            shard_witness(
                0,
                1,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(1),
                },
            ),
            shard_witness(
                0,
                2,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(2),
                },
            ),
        ];
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(6));
        assert_eq!(
            state.consumed_through.get(&ShardGroupId::new(0)),
            Some(&LeafIndex::new(3))
        );
    }

    // ─── RegisterValidator + DeactivateValidator ─────────────────────────

    /// Happy path: a `RegisterValidator` for an unknown id with a pool
    /// that has capacity adds the validator at `Pooled` with
    /// `registered_at_epoch = state.current_epoch`, and the pool's
    /// validator set includes the new id.
    #[test]
    fn register_validator_happy_path() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(2);
        // Bump pool 0's stake to cover one more at floor.
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let new_id = ValidatorId::new(5);
        let new_pubkey = pubkey(5);
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: new_pubkey,
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.registered, vec![new_id]);
        let rec = state.validators.get(&new_id).unwrap();
        assert_eq!(rec.pool, pool_id);
        assert_eq!(rec.status, ValidatorStatus::Pooled);
        assert_eq!(rec.registered_at_epoch, state.current_epoch);
        assert_eq!(rec.pubkey, new_pubkey);
        assert!(state.pools[&pool_id].validators.contains(&new_id));
    }

    /// A registration for an already-known id is silently dropped —
    /// no state change, no effect, no entry in `registered`. The
    /// id-is-dead-forever policy.
    #[test]
    fn register_validator_duplicate_id_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let existing_id = ValidatorId::new(0); // already on shard
        let prior = state.validators.get(&existing_id).unwrap().clone();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: existing_id,
                pubkey: pubkey(99),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.registered.is_empty());
        // Record unchanged — pubkey from the duplicate witness didn't
        // overwrite the prior one.
        assert_eq!(state.validators.get(&existing_id).unwrap(), &prior);
    }

    /// A registration that would push the pool over `max_active_count`
    /// at the current dynamic `min_stake` is silently dropped.
    #[test]
    fn register_validator_rejected_when_pool_lacks_capacity() {
        let mut state = single_pool_state(4); // pool stake = 4 * MIN_STAKE_FLOOR
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool already supports 4 actives at the floor; a 5th would
        // exceed max_active_count without bumping stake.
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(5),
                pubkey: pubkey(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&ValidatorId::new(5)));
        // Watermark still advances — the witness was consumed even
        // though the variant rejected it.
        assert_eq!(
            state.consumed_through.get(&ShardGroupId::new(0)),
            Some(&LeafIndex::new(1))
        );
    }

    /// `DeactivateValidator` from `OnShard` flips status to
    /// `InsufficientStake` AND cascades: shard committee loses the
    /// validator, `pool_draw` refills from any remaining pooled.
    #[test]
    fn deactivate_validator_on_shard_cascades() {
        // 4 actives + 1 pooled. Pool stake exactly covers 4
        // (`max_active_count = 4`), so after the cascade refills the
        // freed epoch the pool sits at `cur = max` and `auto_reactivate`
        // doesn't reverse the deactivation.
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// `DeactivateValidator` from `Pooled` flips status; no cascade
    /// (validator wasn't on a shard).
    #[test]
    fn deactivate_validator_pooled_flips_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        // Add a pooled validator and try to deactivate them.
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(5));

        let pre_members = state.shard_committees[&ShardGroupId::new(0)]
            .members
            .clone();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(5)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        // Shard committee unchanged (the validator wasn't there).
        assert_eq!(
            state.shard_committees[&ShardGroupId::new(0)].members,
            pre_members,
        );
    }

    /// `DeactivateValidator` against an already-`InsufficientStake`
    /// or an already-permanent `Jailed { Equivocation }` validator is
    /// a silent no-op.
    #[test]
    fn deactivate_validator_no_op_for_insufficient_or_equivocation() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert two unreachable-status validators.
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::InsufficientStake),
        );
        state.validators.insert(
            ValidatorId::new(11),
            validator_record(
                11,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Equivocation,
                },
            ),
        );

        let ws = vec![
            shard_witness(
                0,
                1,
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(10),
                },
            ),
            shard_witness(
                0,
                2,
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(11),
                },
            ),
        ];
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.deactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(11)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: Epoch::GENESIS,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// `DeactivateValidator` against a fault-cause `Jailed` validator
    /// IS allowed (operator retires a jailed node rather than waiting
    /// out the cooldown). No cascade — they were already off-shard.
    #[test]
    fn deactivate_validator_allowed_for_fault_cause_jailed() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert a Jailed{Performance} validator.
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    // ─── Unjail ──────────────────────────────────────────────────────────

    /// Insert a Jailed{Performance} validator under pool 0 at
    /// `since_epoch`. The fixture state's pool has been bumped to
    /// support one extra active validator at the floor, so the
    /// capacity gate inside `Unjail` won't reject.
    fn state_with_jailed(since_epoch: Epoch, reason: JailReason) -> BeaconState {
        let mut state = single_pool_state(3);
        state.committee = (0u64..3).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(10));
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch,
                    reason,
                },
            ),
        );
        state
    }

    /// Unjail after cooldown with pool capacity transitions to `Pooled`.
    #[test]
    fn unjail_after_cooldown_returns_to_pooled() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.unjailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// Unjail before cooldown elapses is a silent no-op — the
    /// validator stays Jailed.
    #[test]
    fn unjail_before_cooldown_is_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        // current_epoch two short of cooldown — apply_next_epoch's
        // advance lands at (since + cooldown - 1), still under.
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS - 2);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Performance,
            },
        );
    }

    /// Equivocation jails never unjail, even past the cooldown.
    #[test]
    fn unjail_of_equivocation_jail_is_permanent_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Equivocation);
        state.current_epoch = Epoch::new(since.inner() + 10 * JAIL_COOLDOWN_EPOCHS);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Unjail rejected when the pool can't support one more active
    /// epoch at the current `min_stake`. Validator stays Jailed.
    #[test]
    fn unjail_rejected_when_pool_at_capacity() {
        // single_pool_state(4) saturates the pool exactly: 4 actives,
        // pool stake = 4 * MIN_STAKE_FLOOR, max_active_count = 4. Add
        // a Jailed validator that would push count to 5 if unjailed.
        let since = Epoch::new(5);
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS);
        let pool_id = StakePoolId::new(0);
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(10));
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: since,
                    reason: JailReason::Performance,
                },
            ),
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Performance,
            },
        );
    }

    /// Unjail against a non-jailed validator (e.g. `Pooled`, `OnShard`)
    /// is a silent no-op.
    #[test]
    fn unjail_of_non_jailed_validator_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Validator 0 is OnShard, not Jailed.
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    // ─── Ready ───────────────────────────────────────────────────────────

    /// Ready on `OnShard { ready: false }` flips to `ready: true` —
    /// `placed_at_epoch` and `shard` carry through unchanged.
    #[test]
    fn ready_flips_on_shard_false_to_true() {
        let mut state = single_pool_state(0);
        state.committee = Vec::new();
        let shard = ShardGroupId::new(0);
        let placed = Epoch::new(3);
        // Put validator 1 on shard 0 as not-yet-ready.
        let pool_id = StakePoolId::new(0);
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: [ValidatorId::new(0), ValidatorId::new(1)]
                    .into_iter()
                    .collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(1),
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: placed,
                },
            ),
        );
        state.committee = vec![ValidatorId::new(0)];
        state.shard_committees.insert(
            shard,
            ShardCommittee {
                members: vec![ValidatorId::new(0), ValidatorId::new(1)],
            },
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(1),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.readied, vec![ValidatorId::new(1)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch: placed,
            },
        );
    }

    /// Ready on an already-ready `OnShard` validator is a silent
    /// no-op — re-signalling ready isn't an error.
    #[test]
    fn ready_on_already_ready_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pre = state.validators.get(&ValidatorId::new(0)).unwrap().clone();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.readied.is_empty());
        assert_eq!(state.validators.get(&ValidatorId::new(0)).unwrap(), &pre);
    }

    /// Ready against a `Pooled` validator is a silent no-op (the
    /// validator isn't on a shard yet).
    #[test]
    fn ready_on_pooled_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.readied.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    // ─── MissedProposal ──────────────────────────────────────────────────

    use hyperscale_types::{BlockHeight, Round};

    fn missed_proposal_witness(
        source_shard: u64,
        leaf_index: u64,
        proposer_id: ValidatorId,
    ) -> Witness {
        shard_witness(
            source_shard,
            leaf_index,
            ShardWitnessPayload::MissedProposal {
                proposer_id,
                height: BlockHeight::GENESIS,
                round: Round::INITIAL,
            },
        )
    }

    /// A `MissedProposal` from shard S against a validator currently
    /// `OnShard { shard: S, .. }` increments their miss counter. Below
    /// threshold, no jail effect.
    #[test]
    fn missed_proposal_increments_counter_for_on_shard_proposer() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&1));
        // Status unchanged — still OnShard.
        assert!(matches!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    /// A `MissedProposal` from shard B against a validator currently
    /// on shard A is silently dropped — the witness's source shard
    /// doesn't match the validator's placement.
    #[test]
    fn missed_proposal_from_wrong_shard_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add shard 1 with one validator on it.
        let target = ValidatorId::new(10);
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(target);
        state.validators.insert(
            target,
            validator_record(
                10,
                0,
                ValidatorStatus::OnShard {
                    shard: ShardGroupId::new(1),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.shard_committees.insert(
            ShardGroupId::new(1),
            ShardCommittee {
                members: vec![target],
            },
        );

        // Witness emitted by shard 0, targeting validator on shard 1.
        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// A `MissedProposal` against a validator not currently `OnShard`
    /// (`Pooled`, `Jailed`, `InsufficientStake`) is silently dropped.
    #[test]
    fn missed_proposal_against_non_on_shard_validator_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(10);
        state
            .validators
            .insert(target, validator_record(10, 0, ValidatorStatus::Pooled));

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// One `MissedProposal` per witness — multiple in a single epoch
    /// against the same validator accumulate. Below threshold, no
    /// jail.
    #[test]
    fn multiple_missed_proposals_in_one_slot_accumulate() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        // Three distinct misses at leaf indices 1..3.
        let ws: Vec<Witness> = (1u64..=3)
            .map(|leaf| missed_proposal_witness(0, leaf, target))
            .collect();
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&3));
    }

    /// Crossing `MISSED_PROPOSAL_JAIL_THRESHOLD` jails the validator
    /// under `Performance`, cascades the committee removal +
    /// `pool_draw` refill, and clears the miss counter.
    #[test]
    fn missed_proposal_at_threshold_jails_and_clears_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        // Add a 5th validator in the pool to fuel the refill draw.
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let target = ValidatorId::new(1);
        // Pre-seed counter to threshold - 1 so a single witness
        // crosses the boundary.
        state
            .miss_counters
            .insert(target, MISSED_PROPOSAL_JAIL_THRESHOLD - 1);

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![target]);
        // Jailed under Performance at current_epoch.
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        // Counter cleared.
        assert!(!state.miss_counters.contains_key(&target));
        // Shard committee refilled from pool.
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// VRF jail cascade also clears the miss counter — pinning the
    /// "any out-of-OnShard transition clears `miss_counters`" contract.
    #[test]
    fn vrf_jail_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-seed a non-zero miss counter for validator 0.
        state.miss_counters.insert(ValidatorId::new(0), 7);

        let committed = vec![(
            ValidatorId::new(0),
            malformed_vrf_proposal(0, state.current_epoch.next()),
        )];
        apply_next_epoch(&mut state, &committed);

        // Validator 0 jailed via VRF; counter must be cleared.
        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    /// `DeactivateValidator` cascade also clears the miss counter for
    /// the deactivated `OnShard` validator.
    #[test]
    fn deactivate_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.miss_counters.insert(ValidatorId::new(0), 5);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    // ─── BeaconWitness equivocation ──────────────────────────────────────

    use hyperscale_types::{
        BeaconWitness, DOMAIN_PC_VOTE1, EquivocationEvidence as Evidence, PcValueElement, PcVector,
        PcVoteEquivocation, PcVoteRound, RecoveryEquivocation, SpcView, pc_context,
        pc_vote_signing_message, spc_context,
    };

    /// Build a valid `PcVoteEquivocation` for `equivocator` at
    /// `(epoch, view)` over two distinct round-1 vectors. Both sigs
    /// verify under the equivocator's pubkey; the value mismatch is
    /// what makes it a contradiction.
    fn build_vote_equivocation(
        equivocator: u64,
        epoch: Epoch,
        view: SpcView,
    ) -> PcVoteEquivocation {
        let sk = keypair(equivocator);
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, view);
        let value_a = PcVector::new([PcValueElement::new([0xAA; 32])]);
        let value_b = PcVector::new([PcValueElement::new([0xBB; 32])]);
        let msg_a = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE1, &pc_ctx, &value_a);
        let msg_b = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE1, &pc_ctx, &value_b);
        PcVoteEquivocation {
            validator: ValidatorId::new(equivocator),
            epoch,
            view,
            round: PcVoteRound::Vote1,
            value_a,
            sig_a: sk.sign_v1(&msg_a),
            value_b,
            sig_b: sk.sign_v1(&msg_b),
        }
    }

    fn vote_equivocation_witness(equivocator: u64, epoch: Epoch, view: SpcView) -> Witness {
        let ev = build_vote_equivocation(equivocator, epoch, view);
        Witness::Beacon(BeaconWitness::Equivocation {
            evidence: Box::new(Evidence::Vote(Box::new(ev))),
        })
    }

    /// Verified PC vote equivocation against an `OnShard` validator
    /// jails permanently under `Equivocation` and cascades the
    /// committee removal + `pool_draw` refill.
    #[test]
    fn vote_equivocation_jails_on_shard_validator_with_cascade() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add a 5th validator in the pool to fuel refill.
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let target = ValidatorId::new(1);
        let w = vote_equivocation_witness(target.inner(), Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![target]);
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// Verified equivocation against a `Pooled` validator flips
    /// status to permanent `Jailed { Equivocation }`; no cascade
    /// (validator wasn't on a shard).
    #[test]
    fn vote_equivocation_jails_pooled_validator_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::Pooled),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Equivocation promotes a fault-cause `Jailed{Performance}` to
    /// permanent `Jailed{Equivocation}` — race-defence so a validator
    /// can't escape permanent record via an earlier soft jail.
    #[test]
    fn vote_equivocation_promotes_performance_jail_to_equivocation() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Equivocation against an already-permanent `Jailed{Equivocation}`
    /// is a silent no-op — re-application is idempotent.
    #[test]
    fn vote_equivocation_against_already_equivocation_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let prior_epoch = Epoch::new(2);
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: prior_epoch,
                    reason: JailReason::Equivocation,
                },
            ),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        // since_epoch unchanged — no jail re-applied.
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: prior_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Invalid equivocation evidence (sigs don't verify) is silently
    /// dropped. Tampered `sig_a` here; verify rejects.
    #[test]
    fn vote_equivocation_with_invalid_sig_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let mut ev = build_vote_equivocation(1, Epoch::new(5), SpcView::new(0));
        ev.sig_a.0[0] ^= 1;
        let w = Witness::Beacon(BeaconWitness::Equivocation {
            evidence: Box::new(Evidence::Vote(Box::new(ev))),
        });
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        // Validator 1's status unchanged — still OnShard.
        assert!(matches!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    /// `Recovery` equivocation always rejects under the current
    /// verifier (recovery-cert infrastructure not yet wired). Pins
    /// the "drop silently" behaviour against a regression that
    /// silently jails on unverified evidence.
    #[test]
    fn recovery_equivocation_always_rejects() {
        use hyperscale_types::{
            BeaconBlockHash, BeaconBlockHeader, BeaconStateRoot, Hash, RecoveryRequest,
            RecoveryRound, SignerBitfield, zero_bls_signature,
        };

        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();

        // Construct a minimally-valid-looking RecoveryEquivocation;
        // the verifier returns false regardless of contents.
        let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"));
        let request = RecoveryRequest::new(
            anchor,
            Epoch::new(7),
            RecoveryRound::new(1),
            ValidatorId::new(1),
            zero_bls_signature(),
        );
        let block_header =
            BeaconBlockHeader::genesis(BeaconStateRoot::from_raw(Hash::from_bytes(b"state")));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let ev = RecoveryEquivocation {
            validator: ValidatorId::new(1),
            request,
            block_header,
            block_signers: signers,
            block_aggregate_sig: zero_bls_signature(),
        };
        let w = Witness::Beacon(BeaconWitness::Equivocation {
            evidence: Box::new(Evidence::Recovery(Box::new(ev))),
        });
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    // ─── complete_pending_withdrawals ────────────────────────────────────

    /// Build a single-pool state with `n_actives` active validators
    /// (placed `OnShard`) and one pre-loaded `PendingWithdrawal`. The
    /// fixture parks `current_epoch` at a value past the unbonding
    /// window so the test can run `apply_epoch` and watch the
    /// withdrawal mature.
    fn state_with_pending_withdrawal(
        n_actives: u64,
        total_stake: Stake,
        withdrawal_amount: Stake,
        initiated_at_epoch: Epoch,
        current_epoch: Epoch,
    ) -> BeaconState {
        let mut state = empty_state();
        state.current_epoch = current_epoch;
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let mut pool_validators = BTreeSet::new();
        let mut members = Vec::new();
        for i in 0..n_actives {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake,
                validators: pool_validators,
                pending_withdrawals: vec![PendingWithdrawal {
                    amount: withdrawal_amount,
                    initiated_at_epoch,
                }],
            },
        );
        state
            .shard_committees
            .insert(shard, ShardCommittee { members });
        state.committee = (0..n_actives).map(ValidatorId::new).collect();
        state
    }

    /// A withdrawal still within the unbonding window stays pending —
    /// `total_stake` unchanged, no deactivation.
    #[test]
    fn unmatured_withdrawal_stays_pending() {
        let initiated = Epoch::new(2);
        // current_epoch two short of maturity — apply_next_epoch
        // advances by 1 and the check runs at the still-unmature value.
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS - 2);
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            Stake::from_whole_tokens(100),
            initiated,
            current,
        );
        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.deactivated.is_empty());
        let pool = &state.pools[&StakePoolId::new(0)];
        // Unmatured withdrawal leaves total_stake alone; the only
        // delta is the epoch emission credit.
        assert_eq!(
            pool.total_stake,
            pre_total.saturating_add(EMISSIONS_PER_EPOCH)
        );
        assert_eq!(pool.pending_withdrawals.len(), 1);
    }

    /// A withdrawal whose unbonding window has elapsed releases its
    /// amount from `total_stake` and clears the `pending_withdrawals`
    /// entry. With no over-commitment, no auto-deactivation.
    #[test]
    fn matured_withdrawal_releases_amount_without_deactivation() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Pool over-staked relative to the active set — even after a
        // small release, capacity comfortably covers the actives.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR, // small release
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.deactivated.is_empty());
        let pool = &state.pools[&StakePoolId::new(0)];
        // 99 × FLOOR after release, plus the epoch emission credit.
        assert_eq!(
            pool.total_stake,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos() - MIN_STAKE_FLOOR.attos())
                .saturating_add(EMISSIONS_PER_EPOCH),
        );
        assert!(pool.pending_withdrawals.is_empty());
    }

    /// Multiple matured withdrawals release in a single batch — sum
    /// hits `total_stake` once, all matured entries drop from the
    /// pending list.
    #[test]
    fn multiple_matured_withdrawals_batch() {
        let initiated_a = Epoch::new(2);
        let initiated_b = Epoch::new(3);
        // Set `current` one epoch before maturity so apply_next_epoch's
        // advance lands exactly at the maturity boundary for `initiated_b`.
        let current = Epoch::new(initiated_b.inner() + UNBONDING_WINDOW_EPOCHS - 1);
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR, // first one already in the fixture
            initiated_a,
            current,
        );
        // Add a second matured + a third unmatured.
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.pending_withdrawals.push(PendingWithdrawal {
            amount: Stake::from_attos(2 * MIN_STAKE_FLOOR.attos()),
            initiated_at_epoch: initiated_b,
        });
        // still-pending withdrawal initiated late enough that
        // post-apply current_epoch - still_pending < WINDOW.
        let still_pending_epoch =
            Epoch::new(current.inner().saturating_sub(UNBONDING_WINDOW_EPOCHS - 2));
        pool.pending_withdrawals.push(PendingWithdrawal {
            amount: Stake::from_whole_tokens(7),
            initiated_at_epoch: still_pending_epoch,
        });

        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        apply_next_epoch(&mut state, &[]);

        let pool = &state.pools[&StakePoolId::new(0)];
        // Released = MIN_STAKE_FLOOR + 2 * MIN_STAKE_FLOOR; epoch
        // emission credit goes back on top.
        assert_eq!(
            pool.total_stake,
            pre_total
                .saturating_sub(Stake::from_attos(3 * MIN_STAKE_FLOOR.attos()))
                .saturating_add(EMISSIONS_PER_EPOCH),
        );
        // One pending entry remains.
        assert_eq!(pool.pending_withdrawals.len(), 1);
        assert_eq!(
            pool.pending_withdrawals[0].initiated_at_epoch,
            still_pending_epoch,
        );
    }

    /// Release that over-commits the pool deactivates the highest-id
    /// active validator (here 4 validators, stake drops to support
    /// 3 → validator 3 flips to `InsufficientStake`).
    #[test]
    fn matured_withdrawal_overcommits_deactivates_highest_id() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Pool stake exactly covers 4 actives; release MIN_STAKE_FLOOR
        // leaves capacity for 3.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR,
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(3)]);
        // Validator 3 transitioned to InsufficientStake.
        assert_eq!(
            state.validators.get(&ValidatorId::new(3)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        // Shard committee shrank (the only pool has no Pooled validators
        // to refill from, so `pool_draw` returns None and the committee
        // stays at 3).
        let members = &state.shard_committees[&ShardGroupId::new(0)].members;
        assert_eq!(members.len(), 3);
        assert!(!members.contains(&ValidatorId::new(3)));
    }

    /// A release that requires multiple deactivations runs the loop
    /// to fixed point — validators flip highest-id first until
    /// `current_active_count ≤ max_active_count`.
    #[test]
    fn over_commitment_loop_runs_to_fixed_point() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Start with 4 actives at exactly 4 * MIN_STAKE_FLOOR. Release
        // 3 * MIN_STAKE_FLOOR — only 1 active can be supported.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            Stake::from_attos(3 * MIN_STAKE_FLOOR.attos()),
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        // 3 highest-id validators flipped to InsufficientStake.
        assert_eq!(
            effects.deactivated,
            vec![
                ValidatorId::new(3),
                ValidatorId::new(2),
                ValidatorId::new(1),
            ],
        );
        for id in [3u64, 2, 1].map(ValidatorId::new) {
            assert_eq!(
                state.validators.get(&id).unwrap().status,
                ValidatorStatus::InsufficientStake,
            );
        }
        // Validator 0 still OnShard.
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    // ─── auto_reactivate ─────────────────────────────────────────────────

    /// Build a pool with `n_active` validators (`OnShard`) plus
    /// `insufficient` `InsufficientStake` validators in the same pool.
    /// Pool stake is `total_stake_attos` attos; caller picks it to
    /// engineer specific `max_active_count` outcomes.
    fn state_with_insufficient(
        n_active: u64,
        insufficient: &[u64],
        total_stake_attos: u128,
    ) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let mut pool_validators = BTreeSet::new();
        let mut members = Vec::new();
        for i in 0..n_active {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        for &id in insufficient {
            pool_validators.insert(ValidatorId::new(id));
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::InsufficientStake),
            );
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_attos(total_stake_attos),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
            .shard_committees
            .insert(shard, ShardCommittee { members });
        state.committee = (0..n_active).map(ValidatorId::new).collect();
        state
    }

    /// Pool with capacity for one more active and an
    /// `InsufficientStake` validator → that validator reactivates to
    /// `Pooled`.
    #[test]
    fn auto_reactivate_promotes_insufficient_when_capacity_available() {
        // 3 actives, 1 insufficient, stake covers 4. After
        // reactivation cur=4 ≤ max=4.
        let mut state = state_with_insufficient(3, &[5], 4 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.reactivated, vec![ValidatorId::new(5)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// Pool with `InsufficientStake` validator but no capacity
    /// (cur >= max) → no reactivation.
    #[test]
    fn auto_reactivate_skips_pool_at_capacity() {
        // 4 actives, 1 insufficient, stake covers 4 only. cur=4, max=4
        // → no reactivation.
        let mut state = state_with_insufficient(4, &[5], 4 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.reactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    /// Pool with capacity but no `InsufficientStake` validators → no
    /// reactivation.
    #[test]
    fn auto_reactivate_noop_when_no_candidates() {
        let mut state = state_with_insufficient(3, &[], 10 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.reactivated.is_empty());
    }

    /// Multiple `InsufficientStake` candidates: highest-id picked
    /// first; subsequent iterations pick next-highest if capacity
    /// still allows.
    #[test]
    fn auto_reactivate_picks_highest_id_first() {
        // 1 active, 3 insufficient (ids 5, 7, 9), stake covers 3.
        // Each iteration adds one validator: iteration 1 adds 9
        // (cur=2), iteration 2 adds 7 (cur=3), iteration 3 sees
        // cur=3=max, no further picks.
        let mut state = state_with_insufficient(1, &[5, 7, 9], 3 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            effects.reactivated,
            vec![ValidatorId::new(9), ValidatorId::new(7)],
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(9)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(7)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        // Validator 5 stays insufficient — pool full.
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    /// A validator just deactivated by `complete_pending_withdrawals`
    /// in the same epoch is NOT re-promoted: the pool that deactivated
    /// them has `cur = max` after the release, so the auto-reactivate
    /// gate skips it.
    #[test]
    fn auto_reactivate_does_not_unwind_same_slot_withdrawal_deactivation() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // 4 actives, stake covers 4 exactly. Release MIN_STAKE_FLOOR
        // — deactivates validator 3, leaves cur=3 max=3.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR,
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        // Validator 3 was deactivated this epoch.
        assert_eq!(effects.deactivated, vec![ValidatorId::new(3)]);
        // …and NOT re-promoted.
        assert!(effects.reactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(3)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    // ─── distribute_epoch_rewards ────────────────────────────────────────

    use crate::constants::EMISSIONS_PER_EPOCH;

    /// State with no `OnShard { ready: true }` validators returns no
    /// credits — the whole epoch's emission burns.
    #[test]
    fn distribute_epoch_rewards_no_op_when_no_ready_actives() {
        let mut state = empty_state();
        // Empty pool entry so the function has something to iterate
        // over without hitting the no-active branch via empty
        // validators.
        state.pools.insert(
            StakePoolId::new(0),
            StakePool {
                id: StakePoolId::new(0),
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
            },
        );
        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        let credited = distribute_epoch_rewards(&mut state);

        assert!(credited.is_empty());
        assert_eq!(state.pools[&StakePoolId::new(0)].total_stake, pre_total);
    }

    /// Validators with `ready: false` don't count — pool with one
    /// ready + one not-ready credits as if it had one active.
    #[test]
    fn distribute_epoch_rewards_excludes_unready_validators() {
        let mut state = single_pool_state(0);
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        // Two validators: ready and not-ready, both OnShard.
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(1),
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .extend([ValidatorId::new(0), ValidatorId::new(1)]);
        let pre_total = state.pools[&pool_id].total_stake;

        let credited = distribute_epoch_rewards(&mut state);

        // One pool got credited (the only one with ready actives).
        assert_eq!(credited.len(), 1);
        let credit = credited[&pool_id];
        // Single-active-validator-only-pool case: the credit equals
        // the full epoch emission (no rounding remainder when total =
        // count = 1).
        assert_eq!(credit, EMISSIONS_PER_EPOCH);
        assert_eq!(
            state.pools[&pool_id].total_stake,
            pre_total.saturating_add(credit),
        );
    }

    /// Multi-pool distribution: pro-rata by ready-active count.
    /// Two pools with 1 vs 3 ready actives get 1/4 vs 3/4 of the
    /// emission respectively (integer-division remainder burned).
    #[test]
    fn distribute_epoch_rewards_splits_pro_rata_by_ready_count() {
        let mut state = empty_state();
        let pool_a = StakePoolId::new(1);
        let pool_b = StakePoolId::new(2);
        let shard = ShardGroupId::new(0);

        // Pool A: 1 ready active.
        state.pools.insert(
            pool_a,
            StakePool {
                id: pool_a,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(10)).collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        state.validators.insert(
            ValidatorId::new(10),
            ValidatorRecord {
                id: ValidatorId::new(10),
                pool: pool_a,
                status: ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(10),
            },
        );

        // Pool B: 3 ready actives.
        state.pools.insert(
            pool_b,
            StakePool {
                id: pool_b,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: (20u64..23).map(ValidatorId::new).collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        for i in 20u64..23 {
            state.validators.insert(
                ValidatorId::new(i),
                ValidatorRecord {
                    id: ValidatorId::new(i),
                    pool: pool_b,
                    status: ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                    registered_at_epoch: Epoch::GENESIS,
                    pubkey: pubkey(i),
                },
            );
        }

        let credited = distribute_epoch_rewards(&mut state);

        // Pool A's share = EMISSIONS_PER_EPOCH * 1 / 4 (integer
        // div). Pool B's share = EMISSIONS_PER_EPOCH * 3 / 4.
        let total = 4u128;
        let expected_a = Stake::from_attos(EMISSIONS_PER_EPOCH.attos() / total);
        let expected_b = Stake::from_attos(EMISSIONS_PER_EPOCH.attos() * 3 / total);
        assert_eq!(credited[&pool_a], expected_a);
        assert_eq!(credited[&pool_b], expected_b);
        // Sum is at most EMISSIONS_PER_EPOCH (remainder burns at most
        // total_pools - 1 = 1 atto).
        let sum = credited[&pool_a].attos() + credited[&pool_b].attos();
        assert!(sum <= EMISSIONS_PER_EPOCH.attos());
        assert!(EMISSIONS_PER_EPOCH.attos() - sum < total);
    }

    /// Zero-share pools (in this case: pool with only `Pooled`
    /// validators, no `OnShard { ready: true }`) are omitted from
    /// the returned map.
    #[test]
    fn distribute_epoch_rewards_omits_zero_share_pools() {
        let mut state = empty_state();
        let pool_a = StakePoolId::new(1);
        let pool_b = StakePoolId::new(2);

        // Pool A: 1 ready active. Pool B: only a Pooled validator.
        state.pools.insert(
            pool_a,
            StakePool {
                id: pool_a,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(10)).collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        state.pools.insert(
            pool_b,
            StakePool {
                id: pool_b,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(20)).collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        state.validators.insert(
            ValidatorId::new(10),
            ValidatorRecord {
                id: ValidatorId::new(10),
                pool: pool_a,
                status: ValidatorStatus::OnShard {
                    shard: ShardGroupId::new(0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(10),
            },
        );
        state.validators.insert(
            ValidatorId::new(20),
            validator_record(20, 2, ValidatorStatus::Pooled),
        );

        let credited = distribute_epoch_rewards(&mut state);

        // Only pool A credited.
        assert_eq!(credited.len(), 1);
        assert!(credited.contains_key(&pool_a));
        assert!(!credited.contains_key(&pool_b));
    }

    /// Deterministic: two states with byte-identical inputs produce
    /// byte-identical credits.
    #[test]
    fn distribute_epoch_rewards_is_deterministic() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        let credits_a = distribute_epoch_rewards(&mut a);
        let credits_b = distribute_epoch_rewards(&mut b);
        assert_eq!(credits_a, credits_b);
        assert_eq!(a.pools, b.pools);
    }

    // ─── auto_ready_timeout ──────────────────────────────────────────────

    use crate::constants::READY_TIMEOUT_EPOCHS;

    /// Helper: place validator `id` on shard 0 at `placed_at_epoch`
    /// with `ready: false`. Inserts into pool 0's validator set so
    /// derived helpers see the pool correctly.
    fn insert_unready_on_shard(state: &mut BeaconState, id: u64, placed_at_epoch: Epoch) {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        state
            .pools
            .entry(pool_id)
            .or_insert_with(|| StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
            })
            .validators
            .insert(ValidatorId::new(id));
        state.validators.insert(
            ValidatorId::new(id),
            validator_record(
                id,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch,
                },
            ),
        );
    }

    /// Validator placed `READY_TIMEOUT_EPOCHS` epochs ago flips to
    /// `ready: true` (with `placed_at_epoch` preserved).
    #[test]
    fn auto_ready_timeout_flips_after_threshold() {
        let placed = Epoch::new(3);
        let current = Epoch::new(placed.inner() + READY_TIMEOUT_EPOCHS);
        let mut state = empty_state();
        state.current_epoch = current;
        state.committee = vec![ValidatorId::new(0)];
        insert_unready_on_shard(&mut state, 0, placed);

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.readied, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard {
                shard: ShardGroupId::new(0),
                ready: true,
                placed_at_epoch: placed,
            },
        );
    }

    /// Validator placed just under the threshold stays `ready: false`.
    #[test]
    fn auto_ready_timeout_holds_before_threshold() {
        let placed = Epoch::new(3);
        // Two short of maturity — apply_next_epoch's advance lands at
        // (placed + THRESHOLD - 1), still under.
        let current = Epoch::new(placed.inner() + READY_TIMEOUT_EPOCHS - 2);
        let mut state = empty_state();
        state.current_epoch = current;
        state.committee = vec![ValidatorId::new(0)];
        insert_unready_on_shard(&mut state, 0, placed);

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.readied.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { ready: false, .. },
        ));
    }

    /// Validators in non-`OnShard{ready:false}` statuses are
    /// unchanged — `Pooled`, `Jailed`, already-ready `OnShard`,
    /// `InsufficientStake` all bypass the timeout.
    #[test]
    fn auto_ready_timeout_ignores_non_unready_on_shard() {
        let mut state = single_pool_state(4); // 4 ready OnShard
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(10 * READY_TIMEOUT_EPOCHS);
        // Add a Pooled and a Jailed validator — neither should flip.
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::Pooled),
        );
        state.validators.insert(
            ValidatorId::new(11),
            validator_record(
                11,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.readied.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(11)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: Epoch::GENESIS,
                reason: JailReason::Performance,
            },
        );
    }

    /// Multiple unready validators: only those past the threshold
    /// flip; the under-threshold ones stay.
    #[test]
    fn auto_ready_timeout_flips_selectively_by_placed_epoch() {
        let current = Epoch::new(2 * READY_TIMEOUT_EPOCHS);
        let mut state = empty_state();
        state.current_epoch = current;
        // Three validators at distinct ages: 2T past, 1 under, exactly T past.
        insert_unready_on_shard(&mut state, 0, Epoch::GENESIS);
        insert_unready_on_shard(&mut state, 1, Epoch::new(current.inner() - 1));
        insert_unready_on_shard(
            &mut state,
            2,
            Epoch::new(current.inner() - READY_TIMEOUT_EPOCHS),
        );

        let effects = apply_next_epoch(&mut state, &[]);

        // Ids 0 and 2 flipped; 1 didn't.
        assert_eq!(
            effects.readied,
            vec![ValidatorId::new(0), ValidatorId::new(2)]
        );
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { ready: true, .. },
        ));
        assert!(matches!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard { ready: false, .. },
        ));
        assert!(matches!(
            state.validators.get(&ValidatorId::new(2)).unwrap().status,
            ValidatorStatus::OnShard { ready: true, .. },
        ));
    }

    /// `Ready` witness this epoch and `auto_ready_timeout` flipping
    /// other validators both populate `SlotEffects.readied` —
    /// witness path first, timeout path appended. Pins the
    /// dual-source field semantics.
    #[test]
    fn readied_field_carries_both_witness_and_timeout_flips() {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(5 * READY_TIMEOUT_EPOCHS);
        state.committee = vec![ValidatorId::new(0)];

        // Validator 0: OnShard{ready:true} — needed to sign the
        // proposal.
        let pool_id = StakePoolId::new(0);
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: [
                    ValidatorId::new(0),
                    ValidatorId::new(1),
                    ValidatorId::new(2),
                ]
                .into_iter()
                .collect(),
                pending_withdrawals: Vec::new(),
            },
        );
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard: ShardGroupId::new(0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state
            .shard_committees
            .insert(ShardGroupId::new(0), ShardCommittee::default());
        state
            .shard_committees
            .get_mut(&ShardGroupId::new(0))
            .unwrap()
            .members
            .push(ValidatorId::new(0));

        // Validator 1: not-yet-ready, gets explicit Ready witness.
        insert_unready_on_shard(&mut state, 1, Epoch::new(0));
        // Validator 2: not-yet-ready, will hit timeout.
        insert_unready_on_shard(&mut state, 2, Epoch::new(0));
        // Wait — both were placed at 0, both past timeout. Place
        // validator 1 fresh so the witness path is exercised
        // distinctly from the timeout path.
        state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::OnShard {
            shard: ShardGroupId::new(0),
            ready: false,
            placed_at_epoch: state.current_epoch, // age 0 — under threshold
        };

        let ready_witness = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(1),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![ready_witness]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        // Both ended up in readied: validator 1 via witness, validator
        // 2 via timeout. Order: witness path appends first, then
        // timeout.
        assert_eq!(
            effects.readied,
            vec![ValidatorId::new(1), ValidatorId::new(2)]
        );
    }

    // ─── run_shuffle_step + shard_committee_transitions diff ─────────────

    /// Two shards, `per_shard` ready members each, `pool_extras`
    /// `Pooled` validators kept in reserve so refills have stock.
    /// Pool stake is sized generously to keep `min_stake` at the floor.
    fn multi_shard_state(shard_count: u64, per_shard: u64, pool_extras: u64) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let total = shard_count * per_shard + pool_extras;
        let mut pool_validators = BTreeSet::new();
        let mut next_id = 0u64;
        for s in 0..shard_count {
            let shard = ShardGroupId::new(s);
            let mut members = Vec::new();
            for _ in 0..per_shard {
                let id = ValidatorId::new(next_id);
                pool_validators.insert(id);
                members.push(id);
                state.validators.insert(
                    id,
                    validator_record(
                        next_id,
                        0,
                        ValidatorStatus::OnShard {
                            shard,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    ),
                );
                next_id += 1;
            }
            state
                .shard_committees
                .insert(shard, ShardCommittee { members });
        }
        for _ in 0..pool_extras {
            let id = ValidatorId::new(next_id);
            pool_validators.insert(id);
            state
                .validators
                .insert(id, validator_record(next_id, 0, ValidatorStatus::Pooled));
            next_id += 1;
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                // Generous stake so `min_stake` stays clamped at the
                // floor and no admission gate trips during the test.
                total_stake: Stake::from_attos(u128::from(total) * MIN_STAKE_FLOOR.attos() * 4),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
    }

    /// Off-interval epoch: shard committees and the pool stay
    /// byte-identical; no transition emitted.
    #[test]
    fn shuffle_doesnt_fire_off_interval() {
        // Land at epoch 1 — not a multiple of SHUFFLE_INTERVAL_EPOCHS.
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Park a Pooled extra so a hypothetical refill would have stock.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .validators
            .insert(ValidatorId::new(99));
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        let initial_members = state.shard_committees[&ShardGroupId::new(0)]
            .members
            .clone();
        let initial_pool = pooled_validators(&state);

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.shard_committees[&ShardGroupId::new(0)].members,
            initial_members
        );
        assert_eq!(pooled_validators(&state), initial_pool);
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// On a `SHUFFLE_INTERVAL_EPOCHS` boundary, each shard rotates one
    /// of its ready `OnShard` validators back to `Pooled` and refills
    /// the freed slot via `pool_draw`.
    #[test]
    fn shuffle_rotates_one_validator_per_shard_at_interval() {
        // 2 shards × 4 ready actives + 2 pool extras = 10 validators.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let initial_shard_0 = state.shard_committees[&ShardGroupId::new(0)]
            .members
            .clone();
        let initial_shard_1 = state.shard_committees[&ShardGroupId::new(1)]
            .members
            .clone();

        apply_next_epoch(&mut state, &[]);

        let final_shard_0 = state.shard_committees[&ShardGroupId::new(0)]
            .members
            .clone();
        let final_shard_1 = state.shard_committees[&ShardGroupId::new(1)]
            .members
            .clone();

        // Capacity preserved.
        assert_eq!(final_shard_0.len(), 4);
        assert_eq!(final_shard_1.len(), 4);
        // Each shard saw at most one membership change (zero is
        // possible if a cross-shard rotation lands the same set
        // back).
        let shard_0_diff = final_shard_0
            .iter()
            .filter(|id| !initial_shard_0.contains(id))
            .count();
        let shard_1_diff = final_shard_1
            .iter()
            .filter(|id| !initial_shard_1.contains(id))
            .count();
        assert!(shard_0_diff <= 1, "shard 0 churned by {shard_0_diff}");
        assert!(shard_1_diff <= 1, "shard 1 churned by {shard_1_diff}");
    }

    /// Not-ready members are ineligible to be rotated out — only
    /// `OnShard { ready: true }` validators are picked.
    #[test]
    fn shuffle_picks_only_from_ready_members() {
        let shard = ShardGroupId::new(0);
        let mut state = single_pool_state(4);
        // Mark validators 2 and 3 as not-yet-ready.
        for id in [2u64, 3] {
            state
                .validators
                .get_mut(&ValidatorId::new(id))
                .unwrap()
                .status = ValidatorStatus::OnShard {
                shard,
                ready: false,
                placed_at_epoch: Epoch::GENESIS,
            };
        }
        state.committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        // Pool extra and headroom so refill has stock and admission
        // gates stay clear.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let initial_members = state.shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        // Not-ready validators must still be on the shard.
        for not_ready_id in [2u64, 3] {
            assert!(
                state.shard_committees[&shard]
                    .members
                    .contains(&ValidatorId::new(not_ready_id)),
                "not-ready validator {not_ready_id} got shuffled out"
            );
        }
        // Exactly one of the ready members (0 or 1) was rotated out.
        let rotated = initial_members
            .iter()
            .filter(|id| !state.shard_committees[&shard].members.contains(id))
            .count();
        assert_eq!(rotated, 1, "exactly one ready member rotates out");
    }

    /// With the pool empty before the shuffle, the per-shard
    /// `pool_draw` must not pick the just-rotated victim and restore
    /// them. Victim flips to `Pooled` *after* the draw, so the draw
    /// sees an empty pool and returns `None` — the shard shrinks by
    /// one (no validator was available to fill).
    #[test]
    fn shuffle_avoids_self_replacement() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);
        assert!(pooled_validators(&state).is_empty());

        let initial_members = state.shard_committees[&ShardGroupId::new(0)]
            .members
            .clone();
        apply_next_epoch(&mut state, &[]);

        // Shard shrunk by one — empty pool, no refill possible.
        assert_eq!(
            state.shard_committees[&ShardGroupId::new(0)].members.len(),
            3
        );
        // Victim ended up in the pool, not back on the shard.
        let pool_now = pooled_validators(&state);
        assert_eq!(pool_now.len(), 1);
        let victim = pool_now[0];
        assert!(initial_members.contains(&victim));
        assert!(
            !state.shard_committees[&ShardGroupId::new(0)]
                .members
                .contains(&victim)
        );
        assert!(matches!(
            state.validators[&victim].status,
            ValidatorStatus::Pooled,
        ));
    }

    /// On a shuffle-boundary epoch, any shard membership change is
    /// attributed to `NaturalShuffle` (the dominant cause on those
    /// epochs).
    #[test]
    fn shuffle_emits_shard_committee_transition_with_natural_shuffle_cause() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool extra so the rotation swaps in a fresh validator
        // rather than just shrinking the shard.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let effects = apply_next_epoch(&mut state, &[]);
        let transition = effects
            .shard_committee_transitions
            .get(&ShardGroupId::new(0))
            .expect("shuffle on shard 0 emits a transition");
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert_eq!(transition.at_slot, Epoch::new(SHUFFLE_INTERVAL_EPOCHS));
    }

    /// Empty epoch with no witnesses and no shuffle boundary leaves
    /// shard committees untouched and emits no transitions.
    #[test]
    fn no_membership_change_emits_no_transition() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_next_epoch(&mut state, &[]);
        assert!(effects.shard_committee_transitions.is_empty());
    }
}
