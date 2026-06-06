//! Beacon-chain data types: validator records, pool aggregates, the
//! full `BeaconState`, and the effect bundle returned by `apply_epoch`.
//!
//! Pure derived queries over these shapes (`effective_stake`,
//! `current_active_count`, `min_stake`, `derive_topology_snapshot`, …)
//! sit as inherent methods on [`BeaconState`] and [`StakePool`] at the
//! bottom of this file. The epoch-pipeline behavior (`apply_epoch` and
//! its sub-stages) lives in `hyperscale_beacon::state`.
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
//! [`crate::beacon::constants`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use radix_common::network::NetworkDefinition;
use sbor::prelude::*;

use crate::beacon::cert::BeaconCert;
use crate::beacon::certified::CertifiedBeaconBlock;
use crate::beacon::constants::{MIN_STAKE_FLOOR, POOL_BUFFER_TARGET};
use crate::beacon::genesis::BeaconChainConfig;
use crate::topology::snapshot::TopologySnapshot;
use crate::topology::validator::{ValidatorInfo, ValidatorSet};
use crate::{
    Bls12381G1PublicKey, Epoch, LeafIndex, Randomness, ShardGroupId, Stake, StakePoolId,
    ValidatorId, VotePower,
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
    /// Sizing knobs copied from `BeaconGenesisConfig.chain_config` at
    /// genesis. Frozen for the chain's lifetime — every consensus path
    /// reads from here instead of compile-time constants.
    pub chain_config: BeaconChainConfig,
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
    /// Per-shard committee governing shard consensus **during**
    /// `current_epoch` — the committee that signs shard blocks whose
    /// weighted timestamp falls in `[current_epoch · EPOCH_DURATION,
    /// (current_epoch + 1) · EPOCH_DURATION)`.
    ///
    /// Frozen for the epoch: it's the value `next_shard_committees`
    /// held at the end of the prior `apply_epoch`, promoted here at the
    /// start of this one. Unlike `next_shard_committees` it carries **no**
    /// `members ⇔ status == OnShard` invariant — a validator jailed by a
    /// witness in `current_epoch` is removed from `next_shard_committees`
    /// (so it leaves the committee one epoch out) but stays listed here,
    /// because it was a member for this window. The shard's `2f+1` quorum
    /// tolerates the absent member.
    pub shard_committees: BTreeMap<ShardGroupId, ShardCommittee>,
    /// Lookahead per-shard committee — governs the **next** epoch's
    /// window and is finalized here, one epoch before it takes effect,
    /// so every shard holds it well before its window opens (one-epoch
    /// committee lookahead).
    ///
    /// This is the live set the epoch pipeline mutates: membership
    /// evolves via the trickled shuffle (slow per-interval churn),
    /// jail/exit/deactivate (immediate removal), and pool draws (filling
    /// slots that just opened). The `members ⇔ status == OnShard{shard}`
    /// invariant holds here. At the start of the next `apply_epoch` this
    /// value is promoted into `shard_committees`.
    pub next_shard_committees: BTreeMap<ShardGroupId, ShardCommittee>,
    /// Per-shard high-water mark over each shard's beacon-witness
    /// accumulator: the largest [`LeafIndex`] this beacon has lifted
    /// from that shard. A `ShardWitness` with `proof.leaf_index !=
    /// consumed_through[shard] + 1` is silently dropped (already
    /// consumed, or a gap that must be filled first). Updates
    /// monotonically; never reset.
    ///
    /// `PcVoteEquivocation` is not tracked here — it has no shard
    /// provenance and re-application is idempotent once the validator
    /// is `Jailed { Equivocation }`.
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

// ─── derived queries ────────────────────────────────────────────────────────
//
// Every helper re-derives its value from `self` — no caching, no
// two-piece state to keep in sync. Inherent methods rather than free
// functions so consumers chain `state.min_stake()` directly instead of
// threading a separate module path.

impl StakePool {
    /// Stake available to support active validators on this pool after
    /// accounting for in-flight withdrawals.
    ///
    /// Pending withdrawals reduce effective stake immediately even though
    /// `total_stake` doesn't drop until the unbonding window completes —
    /// this is what blocks new registrations that would have relied on the
    /// withdrawn amount.
    #[must_use]
    pub fn effective_stake(&self) -> Stake {
        let pending = self
            .pending_withdrawals
            .iter()
            .fold(Stake::ZERO, |acc, w| acc.saturating_add(w.amount));
        self.total_stake.saturating_sub(pending)
    }

    /// How many of this pool's validators are currently consuming an
    /// activation epoch under `state`.
    ///
    /// Counts `Pooled` and `OnShard`; excludes `Jailed` (epoch may stay
    /// jailed indefinitely; locking stake against an uncertain return is
    /// wrong) and `InsufficientStake` (already represents "not consuming
    /// an epoch").
    #[must_use]
    pub fn current_active_count(&self, state: &BeaconState) -> usize {
        self.validators
            .iter()
            .filter(|id| {
                matches!(
                    state.validators.get(id).map(|r| &r.status),
                    Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
                )
            })
            .count()
    }

    /// Cap on how many of this pool's validators can be active at the
    /// current dynamic [`min_stake`](BeaconState::min_stake).
    ///
    /// Equals `effective_stake / min_stake(state)`. The invariant
    /// `current_active_count(state) ≤ max_active_count(state)` is
    /// enforced at `RegisterValidator` and `Unjail` application.
    #[must_use]
    pub fn max_active_count(&self, state: &BeaconState) -> usize {
        self.max_active_count_at(state.min_stake())
    }

    /// [`max_active_count`](Self::max_active_count) evaluated against a
    /// precomputed `min_stake`.
    ///
    /// The per-epoch reactivation fixpoint tests capacity across every
    /// pool under a single `min_stake`. Deriving it per pool is an
    /// O(pools) walk each time; since it shifts only when a validator's
    /// active status flips, the caller computes it once and refreshes
    /// after each flip, keeping the sweep linear in the pool count.
    #[must_use]
    pub fn max_active_count_at(&self, min_stake: Stake) -> usize {
        if min_stake == Stake::ZERO {
            return usize::MAX;
        }
        let e = self.effective_stake().attos();
        (e / min_stake.attos()) as usize
    }
}

impl BeaconState {
    /// Validators currently waiting in the global pool.
    ///
    /// Derived from `validators` rather than stored as a separate
    /// field, so there's no two-piece state to keep in sync. Returned
    /// sorted by `ValidatorId` for deterministic indexing inside pool
    /// draws.
    ///
    /// Membership is exactly `status == Pooled`. A validator becomes
    /// `Pooled` on registration, on `Unjail` after cooldown, on trickled
    /// shuffle exit, and on auto-reactivation; they leave `Pooled` when a
    /// pool draw flips them to `OnShard`, or when a witness moves them to
    /// another status.
    #[must_use]
    pub fn pooled_validators(&self) -> Vec<ValidatorId> {
        self.validators
            .iter()
            .filter(|(_, r)| matches!(r.status, ValidatorStatus::Pooled))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Validators eligible to serve on the beacon committee: status is
    /// `OnShard { ready: true, .. }` on any shard.
    ///
    /// Every beacon committee member is therefore a signer on some shard
    /// — an offline validator can't escape detection by hiding in the
    /// beacon set. Pooled, jailed, insufficient-stake, and not-yet-ready
    /// validators are all excluded.
    ///
    /// Returned sorted by `ValidatorId` (`BTreeMap` iteration order) for
    /// deterministic Fisher–Yates input downstream.
    #[must_use]
    pub fn beacon_eligible(&self) -> Vec<ValidatorId> {
        self.validators
            .iter()
            .filter(|(_, r)| matches!(r.status, ValidatorStatus::OnShard { ready: true, .. }))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Resolve the beacon committee into `(validator_id, pubkey)` pairs
    /// in committee-declaration order.
    ///
    /// The order matches `self.committee` exactly, which is the same
    /// positional enumeration `SignerBitfield` is indexed against. SPC
    /// cert verifiers, beacon-block verifiers, and the SPC FSM all
    /// consume this resolved form.
    ///
    /// Validators present in `self.committee` but missing from
    /// `self.validators` are silently dropped. The caller should treat
    /// any length mismatch from `self.committee.len()` as a state
    /// invariant violation; this function does not panic so callers can
    /// make their own decision.
    #[must_use]
    pub fn derive_beacon_committee(&self) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        self.committee
            .iter()
            .filter_map(|id| self.validators.get(id).map(|r| (*id, r.pubkey)))
            .collect()
    }

    /// Derive the immutable [`TopologySnapshot`] for the window this
    /// state governs — the **active** committee (`shard_committees`).
    ///
    /// The snapshot is the read-only consumer-facing view of validator
    /// placement: shard committees, per-validator pubkeys, and the
    /// global validator set. Re-derived on every epoch commit and
    /// shared via `ArcSwap` with the `io_loop`.
    ///
    /// All validators are assigned uniform [`VotePower::new(1)`].
    #[must_use]
    pub fn derive_topology_snapshot(&self, network: NetworkDefinition) -> TopologySnapshot {
        self.derive_topology_from(&self.shard_committees, network)
    }

    /// Derive the [`TopologySnapshot`] for the **next** epoch's window —
    /// the lookahead committee (`next_shard_committees`) that becomes
    /// active one epoch from now. The coordinator inserts this under the
    /// next epoch's key so a shard can resolve its committee before the
    /// window opens.
    #[must_use]
    pub fn derive_next_topology_snapshot(&self, network: NetworkDefinition) -> TopologySnapshot {
        self.derive_topology_from(&self.next_shard_committees, network)
    }

    fn derive_topology_from(
        &self,
        committees: &BTreeMap<ShardGroupId, ShardCommittee>,
        network: NetworkDefinition,
    ) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = self
            .validators
            .values()
            .map(|r| ValidatorInfo {
                validator_id: r.id,
                public_key: r.pubkey,
                voting_power: VotePower::new(1),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        let shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = committees
            .iter()
            .map(|(sid, sc)| (*sid, sc.members.clone()))
            .collect();

        TopologySnapshot::from_explicit_committees(network, &validator_set, shard_committees)
    }

    /// Active-duty validator pool: every validator `OnShard { ready: true }`
    /// on any shard, paired with their pubkey. Returned in `BTreeMap`
    /// iteration order over `self.validators` (sorted by `ValidatorId`).
    ///
    /// This is the quorum substrate for skip:
    /// [`SkipRequest`](crate::SkipRequest)s are signed by members of this
    /// pool and assembled into a [`SkipEpochCert`](crate::SkipEpochCert)
    /// whose `signers` bitfield is positionally indexed against the same
    /// ordering.
    #[must_use]
    pub fn derive_active_pool(&self) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        self.validators
            .iter()
            .filter(|(_, r)| matches!(r.status, ValidatorStatus::OnShard { ready: true, .. }))
            .map(|(id, r)| (*id, r.pubkey))
            .collect()
    }

    /// Pick the signer pool a certified block's cert verifies against.
    ///
    /// Beacon committee for a Normal cert, active pool for a Skip cert.
    /// Returns `None` for `BeaconCert::Genesis` — past-tip genesis blocks
    /// have no signer pool to verify against.
    #[must_use]
    pub fn signer_pool_for(
        &self,
        block: &CertifiedBeaconBlock,
    ) -> Option<Vec<(ValidatorId, Bls12381G1PublicKey)>> {
        match block.cert() {
            BeaconCert::Normal(_) => Some(self.derive_beacon_committee()),
            BeaconCert::Skip(_) => Some(self.derive_active_pool()),
            BeaconCert::Genesis(_) => None,
        }
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
    pub fn min_stake(&self) -> Stake {
        let ne = self.t_no_eject();
        let ad = self.admit_threshold();
        Stake::from_attos(ne.attos().min(ad.attos()).max(MIN_STAKE_FLOOR.attos()))
    }

    /// Highest `min_stake` could be without forcing any active validator
    /// into `InsufficientStake`.
    ///
    /// Equals the minimum across pools (with at least one active
    /// validator) of `effective_stake / current_active_count`.
    /// [`Stake::MAX`] when no pool yet has an active validator (e.g. at
    /// bootstrap).
    fn t_no_eject(&self) -> Stake {
        self.pools
            .values()
            .filter_map(|pool| {
                let active = pool.current_active_count(self);
                if active == 0 {
                    None
                } else {
                    Some(pool.effective_stake().attos() / active as u128)
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
    /// Target is `shard_count × chain_config.shard_size +
    /// POOL_BUFFER_TARGET`. The shard count isn't a stored field — it's
    /// `next_shard_committees.len()`. Returns [`Stake::MAX`] for a zero
    /// target; returns [`MIN_STAKE_FLOOR`] when pools collectively
    /// can't fill the target even at floor pricing (anything below the
    /// floor would be clamped away by `min_stake`'s `.max(...)` anyway).
    fn admit_threshold(&self) -> Stake {
        let target = self.next_shard_committees.len() * self.chain_config.shard_size as usize
            + POOL_BUFFER_TARGET;
        if target == 0 {
            return Stake::MAX;
        }

        let mut offerings: Vec<u128> = Vec::new();
        for pool in self.pools.values() {
            let e = pool.effective_stake().attos();
            if e == 0 {
                continue;
            }
            // Cap per-pool at `target`: a pool's k-th offering for
            // k > target can't enter the global top-`target`, because
            // the same pool already contributed k-1 higher offerings
            // ranked ahead of it. Also cap at `floor(e / MIN_STAKE_FLOOR)`
            // since offerings below the floor would be clamped away in
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JailReason;
    use crate::crypto::keys::bls_keypair_from_seed;

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
            chain_config: BeaconChainConfig::default(),
            current_epoch: Epoch::GENESIS,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            randomness: Randomness::ZERO,
            committee: Vec::new(),
            shard_committees: BTreeMap::new(),
            next_shard_committees: BTreeMap::new(),
            consumed_through: BTreeMap::new(),
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
        let shard = ShardGroupId::ROOT;

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
            .next_shard_committees
            .insert(shard, ShardCommittee { members });
        state
    }

    // ─── effective_stake ──────────────────────────────────────────────

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
        assert_eq!(pool.effective_stake(), Stake::from_whole_tokens(650));
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
        assert_eq!(pool.effective_stake(), Stake::ZERO);
    }

    // ─── current_active_count ─────────────────────────────────────────

    #[test]
    fn current_active_count_includes_pooled_and_on_shard() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(pool.current_active_count(&state), 4);
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
        assert_eq!(pool.current_active_count(&state), 2);
    }

    // ─── pooled_validators ────────────────────────────────────────────

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
            state.pooled_validators(),
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }

    // ─── min_stake ────────────────────────────────────────────────────

    /// Empty state — no pools, no active validators. `t_no_eject` and
    /// `admit_threshold` both default high; `min_stake` clamps to
    /// `MIN_STAKE_FLOOR`.
    #[test]
    fn min_stake_floor_on_empty_state() {
        let state = empty_state();
        assert_eq!(state.min_stake(), MIN_STAKE_FLOOR);
    }

    /// One pool, four active validators, total stake exactly `4 ×
    /// MIN_STAKE_FLOOR`. `t_no_eject = MIN_STAKE_FLOOR` (tightest
    /// pool's ratio), so `min_stake` lands at the floor.
    #[test]
    fn min_stake_clamps_to_floor_at_tight_pool() {
        let state = single_pool_state(4);
        assert_eq!(state.min_stake(), MIN_STAKE_FLOOR);
    }

    // ─── max_active_count ─────────────────────────────────────────────

    #[test]
    fn max_active_count_equals_effective_over_min_stake() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        // 4 floors of stake, `min_stake = floor` ⇒ cap of 4.
        assert_eq!(pool.max_active_count(&state), 4);
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
        assert_eq!(pool.max_active_count(&state), 0);
    }

    // ─── miss counter sanity ──────────────────────────────────────────

    /// Pins the `miss_counters` field shape: a per-validator `u32` map.
    /// The scoping invariants (per-epoch reset, status-transition reset)
    /// live with `apply_epoch`, not the type.
    #[test]
    fn miss_counters_field_is_per_validator_u32_map() {
        let mut state = empty_state();
        state.miss_counters.insert(ValidatorId::new(5), 3);
        state.miss_counters.insert(ValidatorId::new(7), 12);
        assert_eq!(state.miss_counters.get(&ValidatorId::new(5)), Some(&3));
        assert_eq!(state.miss_counters.get(&ValidatorId::new(7)), Some(&12));
    }
}
