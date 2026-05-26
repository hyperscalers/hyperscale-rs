//! Beacon-chain data types: validator records, pool aggregates, the
//! full `BeaconState`, and the effect bundle returned by
//! `apply_epoch`.
//!
//! Pure data shapes only. The epoch-pipeline behavior
//! (`apply_epoch` and its sub-stages) and the pure derived helpers
//! (`effective_stake`, `current_active_count`, etc.) live in
//! `hyperscale_beacon::state` — they need beacon-side protocol
//! constants and are not part of the consumer-facing type surface.
//!
//! Light clients re-execute `apply_epoch` over committed
//! [`BeaconBlock`](crate::BeaconBlock)s instead of verifying merkle
//! proofs against an on-chain state root: the SPC cert is the sole
//! block authenticator and there is no on-chain commitment to the
//! resulting `BeaconState` to prove against.
//!
//! # Epoch-time vs slot-time
//!
//! Validator-lifecycle fields ([`PendingWithdrawal::initiated_at_epoch`],
//! [`ValidatorStatus::Jailed::since_epoch`],
//! [`ValidatorStatus::OnShard::placed_at_epoch`],
//! [`ValidatorRecord::registered_at_epoch`]) are denominated in
//! **epochs**, not slots. Anything counting wall-clock duration
//! (cooldowns, unbonding windows, ready timeouts) keys off
//! `current_epoch` against the corresponding `*_EPOCHS` constant in
//! `hyperscale_beacon::constants`.

use std::collections::{BTreeMap, BTreeSet};

use sbor::prelude::*;

use crate::{
    Bls12381G1PublicKey, Epoch, LeafIndex, Randomness, ShardGroupId, Stake, StakePoolId,
    ValidatorId,
};

// ─── pool types ──────────────────────────────────────────────────────────────

/// One pending withdrawal against a [`StakePool`].
///
/// Completes one `UNBONDING_WINDOW_EPOCHS` after `initiated_at_epoch`;
/// on completion the amount is removed from `total_stake` and any
/// resulting auto-deactivations apply. Until then `effective_stake`
/// reflects the withdrawal even though `total_stake` does not — so
/// new registrations can't lean on stake that's already pledged to
/// leave.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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

// ─── validator types ─────────────────────────────────────────────────────────

/// What caused a validator to be jailed.
///
/// Determines unjail eligibility — fault-cause reasons unjail after
/// a cooldown once an `Unjail` witness arrives; provable-byzantine
/// reasons never unjail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
pub enum JailReason {
    /// Performance failure. Surfaces from a shard's local miss-counter
    /// crossing threshold (witness emits with this reason), from the
    /// beacon-side `MissedProposal` counter crossing the jail
    /// threshold, or from a malformed VRF reveal in the validator's
    /// own proposal (self-inflicted cryptographic fault, jailed on
    /// first sighting). Unjails after cooldown.
    Performance,
    /// Cryptographic proof of byzantine signing. Permanent — the key is
    /// provably hostile, no cooldown unjails it.
    Equivocation,
}

/// Operational status of one validator.
///
/// Transitions are driven by `apply_epoch` from witnesses, withdrawal
/// completion, jail cascades, and pool draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub enum ValidatorStatus {
    /// In the global pool. Registered, supported by stake, but not
    /// placed on any shard. Picked up by the next pool draw driven by
    /// a shard epoch opening.
    Pooled,
    /// Placed on `shard`. `ready: true` once a `Ready` witness from
    /// the shard has been applied or the ready-timeout has elapsed
    /// since `placed_at_epoch`. Until then the validator occupies a
    /// committee epoch but doesn't sign.
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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

// ─── shard committee ─────────────────────────────────────────────────────────

/// Per-shard committee.
///
/// Every member's status is `OnShard { shard: this_shard, .. }`. Jail,
/// deactivation, and withdrawal-completion auto-deactivation
/// transitions remove the validator from `members` synchronously.
/// Order is incidental — the active signer set is filtered from
/// `members` by status, not by position. `members.len() ≤
/// SHARD_CAPACITY` at every epoch boundary; the list shrinks
/// transiently when an epoch opens, then refills via `pool_draw`
/// within the same step.
#[derive(Debug, Default, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardCommittee {
    /// Ordered list of validators on this shard.
    pub members: Vec<ValidatorId>,
}

// ─── beacon state ────────────────────────────────────────────────────────────

/// Global beacon state. Updated atomically per epoch by `apply_epoch`.
///
/// Cross-validator agreement on every field at every epoch follows from
/// `apply_epoch` being a pure deterministic function of `(state, epoch,
/// committed)` and SPC's Agreement guaranteeing all honest parties see
/// the same `committed` argument.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
    /// Per-validator `MissedProposal` counter, scoped to the current
    /// epoch and the validator's current shard. Incremented when a
    /// `MissedProposal` witness arrives whose proposer is currently
    /// `OnShard { shard }` matching the witness's source shard. Reset
    /// on epoch boundaries and on any status transition out of
    /// `OnShard { shard }`. Crossing the jail threshold jails the
    /// validator under `JailReason::Performance` in the same epoch.
    pub miss_counters: BTreeMap<ValidatorId, u32>,
}

// ─── epoch effects ───────────────────────────────────────────────────────────

/// What caused a [`CommitteeTransition`].
///
/// The runner uses this to tell "scheduled rotation, no anomaly" apart
/// from "the old committee failed and was replaced" — different
/// operator-facing signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub enum TransitionCause {
    /// Natural rotation at an epoch boundary — the trickled shuffle for
    /// per-shard committees, the epoch-rotation step for the beacon
    /// committee.
    NaturalShuffle,
    /// Committee resampled because the pool-quorum
    /// [`SkipEpochCert`](crate::SkipEpochCert) abandoned the prior
    /// epoch. Same pipeline as `NaturalShuffle` over an empty proposal
    /// set, distinguished only for observability so operators can tell
    /// "scheduled rotation" apart from "the chain just skipped."
    Skip,
    /// A mid-epoch jail, deactivation, or withdrawal-driven
    /// auto-deactivation changed a shard's `members` list without a
    /// fresh shuffle.
    MembershipChange,
}

/// Structured description of a committee handover.
///
/// Surfaced by natural epoch boundaries (in
/// [`SlotEffects::beacon_committee_transition`] and
/// [`SlotEffects::shard_committee_transitions`]) and by skip-cert
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
/// detection), and tests. Empty defaults match "nothing happened" — an
/// epoch with no commits and no boundary crossings returns
/// [`SlotEffects::default()`].
#[derive(Debug, Default, Clone, PartialEq, Eq, BasicSbor)]
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
