//! Global beacon state and the derived helpers that gate validator
//! lifecycle decisions.
//!
//! `apply_slot` (landing in subsequent sub-commits) mutates this state
//! deterministically from each slot's committed `BeaconProposal` set.
//! The helpers here (`min_stake`, `effective_stake`,
//! `current_active_count`, `max_active_count`, `pooled_validators`) are
//! pure functions of state — every call site re-derives the value
//! rather than caching, so there's no two-piece state to keep in sync.
//!
//! # Slot-time vs epoch-time
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

use hyperscale_types::{
    Bls12381G1PublicKey, Epoch, LeafIndex, Randomness, RecoveryCertificate, ShardGroupId, Slot,
    Stake, StakePoolId, ValidatorId,
};

use crate::constants::{MIN_STAKE_FLOOR, POOL_BUFFER_TARGET, SHARD_CAPACITY};

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
/// Transitions are driven by `apply_slot` from witnesses, withdrawal
/// completion, jail cascades, and pool draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// In the global pool. Registered, supported by stake, but not
    /// placed on any shard. Picked up by the next pool draw driven by
    /// a shard slot opening.
    Pooled,
    /// Placed on `shard`. `ready: true` once a `Ready` witness from
    /// the shard has been applied or
    /// [`READY_TIMEOUT_EPOCHS`](crate::constants::READY_TIMEOUT_EPOCHS)
    /// has elapsed since `placed_at_epoch`. Until then the validator
    /// occupies a committee slot but doesn't sign.
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
    /// still support the additional active slot; otherwise the unjail
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
/// SHARD_CAPACITY` at every slot boundary; the list shrinks transiently
/// when a slot opens, then refills via `pool_draw` within the same
/// step.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShardCommittee {
    /// Ordered list of validators on this shard.
    pub members: Vec<ValidatorId>,
}

// ─── beacon state ───────────────────────────────────────────────────────────

/// Global beacon state. Updated atomically per slot by `apply_slot`.
///
/// Cross-validator agreement on every field at every slot follows from
/// `apply_slot` being a pure deterministic function of `(state, slot,
/// committed)` and MSC's Agreement guaranteeing all honest parties see
/// the same `committed` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconState {
    /// Highest slot whose commit has been applied.
    pub current_slot: Slot,
    /// Highest epoch whose committee rotation has been applied.
    pub current_epoch: Epoch,
    /// Per-id validator records.
    pub validators: BTreeMap<ValidatorId, ValidatorRecord>,
    /// Per-id stake pools.
    pub pools: BTreeMap<StakePoolId, StakePool>,
    /// Running beacon randomness — BLAKE3 mix of the prior value with
    /// each slot's accepted VRF outputs.
    pub randomness: Randomness,
    /// Beacon committee for the current epoch — the validators running
    /// the MSC instance producing this chain.
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
    /// slot.
    pub miss_counters: BTreeMap<ValidatorId, u32>,
}

// ─── slot effects ───────────────────────────────────────────────────────────

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
/// MSC instance you were running for `from` and bootstrap a fresh one
/// with `to`."
///
/// Honest committee members of `from` whose membership has ended see
/// `to` and either bootstrap a new MSC instance (if `to` contains them)
/// or shut down MSC participation cleanly (if `to` excludes them).
///
/// Cross-validator agreement on `(from, to, cause, at_slot)` follows
/// from `apply_slot` being deterministic; every honest party computes
/// the same transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeTransition {
    /// Outgoing committee.
    pub from: Vec<ValidatorId>,
    /// Incoming committee.
    pub to: Vec<ValidatorId>,
    /// Why the transition fired.
    pub cause: TransitionCause,
    /// Slot the transition was applied at.
    pub at_slot: Slot,
}

/// Effects of applying one slot, returned by `apply_slot`.
///
/// Surfaced for observability, runner-side wiring (committee handover
/// detection), and tests. Empty defaults match "nothing happened" — a
/// slot with no commits and no boundary crossings returns
/// [`SlotEffects::default()`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SlotEffects {
    /// New validators registered via a `RegisterValidator` witness.
    pub registered: Vec<ValidatorId>,
    /// Validators transitioned to `InsufficientStake` — via explicit
    /// `DeactivateValidator` witness or via withdrawal-completion
    /// auto-deactivation.
    pub deactivated: Vec<ValidatorId>,
    /// Validators jailed this slot (`Jail` witness, malformed VRF
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
    /// this slot.
    pub committee_changed: bool,
    /// Beacon-committee handover when `committee_changed`.
    pub beacon_committee_transition: Option<CommitteeTransition>,
    /// Per-shard transitions emitted for any shard whose `members`
    /// list changed this slot.
    pub shard_committee_transitions: BTreeMap<ShardGroupId, CommitteeTransition>,
    /// Committee members whose `vrf_reveal` failed verification —
    /// their reveal did not contribute to the new randomness and their
    /// witnesses were also dropped (a malformed reveal is treated as a
    /// malformed proposal).
    pub rejected_reveals: Vec<ValidatorId>,
    /// Per-pool emission credit applied to `pool.total_stake` this
    /// slot. Sum equals one epoch's emission share minus the burned
    /// integer-division remainder. Empty when no pool had a ready
    /// `OnShard` validator (whole slot's share burned).
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
/// activation slot.
///
/// Counts `Pooled` and `OnShard`; excludes `Jailed` (slot may stay
/// jailed indefinitely; locking stake against an uncertain return is
/// wrong) and `InsufficientStake` (already represents "not consuming a
/// slot").
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

/// Marginal price at which exactly the target slot count is offered
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

#[cfg(test)]
mod tests {
    use hyperscale_types::bls_keypair_from_seed;

    use super::*;

    // ─── fixture helpers ──────────────────────────────────────────────────

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
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
            current_slot: Slot::GENESIS,
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
    /// transition reset) live with `apply_slot`, not the type.
    #[test]
    fn miss_counters_field_is_per_validator_u32_map() {
        let mut state = empty_state();
        state.miss_counters.insert(ValidatorId::new(5), 3);
        state.miss_counters.insert(ValidatorId::new(7), 12);
        assert_eq!(state.miss_counters.get(&ValidatorId::new(5)), Some(&3));
        assert_eq!(state.miss_counters.get(&ValidatorId::new(7)), Some(&12));
    }
}
