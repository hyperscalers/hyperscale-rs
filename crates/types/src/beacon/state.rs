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
//! proofs against an on-chain state root: a block is authenticated by
//! recomputing the fold — the `BeaconCert` authenticates
//! `committed_proposals`, the canonical-projection check re-derives
//! `shard_contributions`, and the deterministic fold ties them — and
//! there is no on-chain commitment to the resulting `BeaconState` to
//! prove against.
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
use crate::beacon::params::{NetworkParams, ParamProposal};
use crate::topology::snapshot::{ShardAnchor, TopologySnapshot};
use crate::topology::validator::{ValidatorInfo, ValidatorSet};
use crate::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, Bls12381G1PublicKey, Epoch, Randomness,
    SettledWavesRoot, ShardId, Stake, StakePoolId, StateRoot, ValidatorId, WeightedTimestamp,
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
        shard: ShardId,
        /// Whether the validator has signalled sync-completion.
        ready: bool,
        /// Epoch when the placement happened.
        placed_at_epoch: Epoch,
    },
    /// Drawn from the pool into a pending split's observer cohort.
    /// Carried in `shard`'s committee for the networking view (serving,
    /// gossip, ready-signal admission) but never in its consensus
    /// subset: the observer syncs its assigned pending child and joins
    /// that child's committee when the reshape executes. The child
    /// assignment and sync readiness live on the
    /// [`PendingReshape::Split`] record's cohort.
    Observing {
        /// The splitting shard whose committee carries the observer.
        shard: ShardId,
        /// Epoch the cohort draw placed the observer.
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
/// Every member's status is `OnShard { shard: this_shard, .. }` —
/// or `Observing { shard: this_shard, .. }` while a split of this
/// shard pends, carrying the observer cohort in the networking view
/// without touching the consensus subset. Jail, deactivation, and
/// withdrawal-completion auto-deactivation transitions remove the
/// validator from `members` synchronously. Order is incidental — the
/// active signer set is filtered from `members` by status, not by
/// position. `members.len() ≤ SHARD_CAPACITY` plus any observer
/// cohort at every epoch boundary; the list shrinks transiently when
/// an epoch opens, then refills via `pool_draw` within the same step.
#[derive(Debug, Default, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardCommittee {
    /// Ordered list of validators on this shard.
    pub members: Vec<ValidatorId>,
}

// ─── beacon state ────────────────────────────────────────────────────────────

/// Per-shard boundary record: where a shard's chain sat at the epoch
/// boundary, plus its liveness history.
///
/// The `state_root` is the snap-sync anchor a re-tasked node reconstructs
/// against; `witness_leaf_count` is the beacon's **applied** high-water
/// mark over the shard's beacon-witness accumulator — how many leaves the
/// fold has consumed, which equals the boundary block's count in steady
/// state and lags it while a backlog drains in bounded chunks.
/// `consecutive_misses` is
/// the per-*shard* counter (distinct from the per-*validator*
/// [`BeaconState::miss_counters`]) bumped each epoch the beacon committee
/// observes no boundary crossing for this shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ShardBoundary {
    /// Subtree root at the shard's most recent committed boundary block —
    /// the snap-sync anchor.
    pub state_root: StateRoot,
    /// Hash of that boundary block — the checkpoint identifier.
    pub block_hash: BlockHash,
    /// Height of that boundary block — where a snap-synced joiner's tail
    /// block-sync starts.
    pub height: BlockHeight,
    /// Canonical (parent-QC) weighted timestamp at the boundary block.
    /// Projects onto [`ShardAnchor`](crate::ShardAnchor) as the clock a
    /// freshly placed member or cohort observer opens its
    /// [`ReadySignal`](crate::ReadySignal) window from.
    pub weighted_timestamp: WeightedTimestamp,
    /// Beacon-witness accumulator high-water mark at the boundary.
    pub witness_leaf_count: BeaconWitnessLeafCount,
    /// Epoch in which this boundary was last refreshed by an observed
    /// crossing — the anchor's freshness.
    pub last_live_epoch: Epoch,
    /// Epochs in a row the beacon committee observed no crossing for this
    /// shard. Reset to `0` on a refresh; carried forward (not reset) on a
    /// `Skip` epoch.
    pub consecutive_misses: u32,
    /// The shard's final epoch, set when a reshape's execution schedules
    /// its chain to terminate at that epoch's cut — a split's parent, or
    /// a merge's two children. A terminal record stops bumping misses,
    /// keeps being sourced so the fold can consume the terminal
    /// contribution (which seeds a split's children or composes a merge's
    /// parent) and drain the witness backlog, and drops once both have
    /// happened. `None` for a live shard.
    pub terminal_epoch: Option<Epoch>,
    /// Weighted timestamp of the QC certifying the terminal block. A merge
    /// parent floors it to its epoch start to anchor the composed genesis,
    /// the same value the keeper reads off the child's terminal QC, so both
    /// reconstruct identical genesis bytes regardless of how far the child
    /// coasted past its cut. `Some` once the terminal contribution has
    /// folded — which lets the parent compose across separate folds when its
    /// two children's terminals land in different epochs. `None` for a live
    /// shard or a scheduled terminal whose contribution hasn't folded yet.
    pub terminal_qc_wt: Option<WeightedTimestamp>,
    /// The terminal header's `settled_waves_root` — the beacon-attested
    /// commitment over the wave-ids this shard settled in its retention
    /// window up to its terminal block. `Some` only on a terminated
    /// shard's boundary record; a surviving counterpart projects it onto
    /// [`ShardAnchor`](crate::ShardAnchor) and resolves split-straddling
    /// waves against it. `None` for a live shard.
    pub settled_waves_root: Option<SettledWavesRoot>,
}

/// One observer drawn into a pending split's cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct CohortSeat {
    /// Pending child the observer syncs and joins at execution.
    pub child: ShardId,
    /// Whether the observer's `ReshapeReady` witness has folded.
    pub ready: bool,
}

/// One keeper drawn into a paired merge's committee.
///
/// A keeper stays `OnShard` on its child for the whole grow — it keeps
/// running that chain and hard-links the merged store from it — so a
/// seat carries no status, only the child it runs and whether it has
/// synced the sibling half into the merged `p`-rooted store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct KeeperSeat {
    /// The child whose half this keeper runs and hard-links from.
    pub child: ShardId,
    /// Whether the keeper's `ReshapeReady` witness has folded — it has
    /// synced the sibling half and stitched the merged root.
    pub ready: bool,
}

/// An admitted, not-yet-executed shard reshape, keyed in
/// [`BeaconState::pending_reshapes`] by its target: the splitting shard
/// itself, or the parent a merge reforms under.
///
/// Liveness is assertion-driven: a shard's trigger re-derives once per
/// witness window while its load condition holds, each fold refreshing
/// the recorded epoch. A split whose trigger goes quiet for
/// [`RESHAPE_TRIGGER_TTL_EPOCHS`](crate::RESHAPE_TRIGGER_TTL_EPOCHS)
/// epochs *lapses*: its cohort returns to the pool but the record is
/// retained, so a re-assertion before the deadline re-staffs the same
/// cohort from `cohort_seed`. The record is only removed — abandoning
/// the split outright — when its readiness gate isn't met within
/// [`RESHAPE_READY_TTL_EPOCHS`](crate::RESHAPE_READY_TTL_EPOCHS) of
/// admission, which also bounds how long a lapsed record (and its seed)
/// survives. A merge child that goes quiet for the trigger TTL cancels
/// the paired merge outright, returning its keepers to rotation.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum PendingReshape {
    /// The target shard splits into its two children.
    Split {
        /// Epoch the shard's trigger last folded.
        last_asserted: Epoch,
        /// Epoch the split was admitted — starts the readiness TTL.
        admitted_at: Epoch,
        /// Observer cohort drawn at admission, each seat assigned the
        /// child it syncs. Seats drop with the validator's jail or
        /// deactivation; the execution gate reads ready seats per
        /// child. Empty while the record is lapsed (trigger went quiet
        /// but the readiness TTL hasn't elapsed) — a re-assertion
        /// re-staffs it from [`cohort_seed`](Self::Split::cohort_seed).
        cohort: BTreeMap<ValidatorId, CohortSeat>,
        /// Beacon randomness snapshotted at the split's first admission,
        /// the sole entropy the cohort draw seeds on. Frozen for the
        /// record's life so a re-staff after a lapse re-derives the
        /// identical selection and child assignment (given an unchanged
        /// free pool) — an observer's synced child never moves under it.
        cohort_seed: Randomness,
    },
    /// The target parent's two children merge back under it. The merge
    /// is paired — keepers drawn, eligible for execution — once both
    /// children hold a live half.
    Merge {
        /// Per-child epoch of the most recent folded assertion. Both
        /// children must keep a live half; a half quiet for
        /// [`RESHAPE_TRIGGER_TTL_EPOCHS`](crate::RESHAPE_TRIGGER_TTL_EPOCHS)
        /// cancels the paired merge.
        halves: BTreeMap<ShardId, Epoch>,
        /// Keeper committee drawn when both halves pair: half the merged
        /// committee from each child, each seat the child it runs and
        /// whether it has synced the sibling half. The execution gate
        /// reads ready seats; rotation on the children skips keepers.
        /// Empty until paired.
        keepers: BTreeMap<ValidatorId, KeeperSeat>,
        /// Epoch the merge paired and drew its keepers — starts the
        /// readiness TTL. `None` until paired.
        admitted_at: Option<Epoch>,
    },
}

/// Global beacon state. Updated atomically per epoch by `apply_epoch`.
///
/// Cross-validator agreement on every field at every epoch follows from
/// `apply_epoch` being a pure deterministic function of `(state, epoch,
/// committed)` and SPC's Agreement guaranteeing all honest parties see
/// the same `committed` argument.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconState {
    /// Sizing knobs copied from `BeaconGenesisConfig.chain_config` at
    /// genesis. Frozen for the chain's lifetime and authenticated by the
    /// genesis hash — the home for the structural and historical
    /// parameters (`genesis_timestamp_ms`) and the not-yet-governable
    /// sizing knobs. Governable policy parameters
    /// (today `reshape_thresholds`) are seeded into [`Self::params`] at
    /// genesis and read from there; resolve a governable parameter
    /// against `params`, never here.
    pub chain_config: BeaconChainConfig,
    /// Live, governable network parameters — the policy subset a running
    /// network retunes through committed parameter-change votes. Seeded
    /// from `chain_config` at genesis and mutated only by the fold, so it
    /// stays a pure function of committed beacon history and every
    /// replica resolves the same value at every epoch.
    ///
    /// Promoted from [`Self::next_params`] at the top of each `apply_epoch`,
    /// the same one-epoch lookahead discipline as
    /// [`Self::shard_committees`] / [`Self::next_shard_committees`], so a
    /// window's params are fixed an epoch before the window opens and a
    /// block carries the params every member resolves off its
    /// weighted-time-bound topology snapshot.
    pub params: NetworkParams,
    /// The lookahead params governing the next epoch: what a parameter
    /// vote folded this epoch installs at its `activate_at`, decided one
    /// epoch early (`activate_at - 1`) so it is frozen into the next
    /// epoch's topology snapshot before any block resolves against it.
    /// Promoted into [`Self::params`] at the next `apply_epoch`.
    pub next_params: NetworkParams,
    /// Each stake pool's one active parameter-change vote — the proposal
    /// `(params, activate_at)` it backs. Folded from `ParamVote`
    /// witnesses (cast/replace/clear); a pool with no entry abstains.
    /// Each epoch the tally buckets these by proposal, sums backers'
    /// stake, and applies any proposal a majority of total pool stake
    /// backs at its `activate_at`, then prunes spent votes — so the set
    /// stays bounded at one slot per pool.
    pub param_votes: BTreeMap<StakePoolId, ParamProposal>,
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
    pub shard_committees: BTreeMap<ShardId, ShardCommittee>,
    /// Lookahead per-shard committee — governs the **next** epoch's
    /// window and is finalized here, one epoch before it takes effect,
    /// so every shard holds it well before its window opens (one-epoch
    /// committee lookahead).
    ///
    /// This is the live set the epoch pipeline mutates: membership
    /// evolves via the trickled shuffle (slow per-interval churn),
    /// jail/exit/deactivate (immediate removal), and pool draws (filling
    /// slots that just opened). The `members ⇔ status ==
    /// OnShard{shard} ∨ Observing{shard}` invariant holds here. At the
    /// start of the next `apply_epoch` this value is promoted into
    /// `shard_committees`.
    pub next_shard_committees: BTreeMap<ShardId, ShardCommittee>,
    /// Ready-filtered consensus subset of `shard_committees`, frozen at
    /// promotion: each shard's members whose status was `OnShard { shard,
    /// ready: true }` when the lookahead committee was promoted — i.e.
    /// statuses as of the end of the prior epoch's fold, before this
    /// epoch's witnesses apply. Proposer rotation, quorum thresholds, and
    /// vote-bitfield indexing for the window this state governs read this
    /// subset; full `shard_committees` membership remains the networking
    /// view.
    ///
    /// Freezing here keeps the subset byte-identical to what the prior
    /// state's lookahead derivation computed live from the same statuses,
    /// so a window's consensus committee is the same whether a node
    /// resolves it from the lookahead schedule entry or the re-derived
    /// active one — a Ready or Jail witness folding this epoch takes
    /// consensus effect one window out, exactly like membership changes.
    pub shard_consensus_members: BTreeMap<ShardId, Vec<ValidatorId>>,
    /// Per-shard beacon-witness window base for the window this state
    /// governs, frozen at promotion: each shard's applied witness
    /// watermark (`boundaries[shard].witness_leaf_count`) as it stood
    /// when the lookahead committee was promoted — before this epoch's
    /// fold advances it.
    ///
    /// Freezing here keeps the base byte-identical to what the prior
    /// state's lookahead derivation read live from the same boundaries
    /// (nothing mutates `boundaries` between the end of one
    /// `apply_epoch` and the start of the next), so a window's base is
    /// the same whether a node resolves it from the lookahead schedule
    /// entry or the re-derived active one — the
    /// [`Self::shard_consensus_members`] discipline.
    pub witness_window_bases: BTreeMap<ShardId, BeaconWitnessLeafCount>,
    /// Shards with an admitted, not-yet-executed split as of this
    /// epoch's promotion, frozen under the
    /// [`Self::witness_window_bases`] discipline so a window's value is
    /// byte-identical whether resolved from the lookahead schedule entry
    /// or the re-derived active one. The schedule's split-at-boundary
    /// predicate reads it to answer "no split lands at this window's
    /// end" without the next window's entry.
    pub split_pending_window: BTreeSet<ShardId>,
    /// Each pending split's observer cohort (keyed by parent, mapping
    /// observer → child sub-shard) as of this epoch's promotion, frozen
    /// under the [`Self::split_pending_window`] discipline. A window's
    /// `ReshapeReady` leaf classification reads it, so freezing keeps it
    /// byte-identical whether a node resolves the window from the
    /// lookahead schedule entry or the re-derived active one — the split
    /// execution fold flips the cohort to `OnShard` mid-fold, so a live
    /// projection would differ between the two writes and fork the
    /// beacon-witness root across replicas at different fold heights.
    pub reshape_observers_window: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// Each pending merge's keepers (keyed by the child each keeper runs,
    /// mapping keeper → merging parent) as of this epoch's promotion,
    /// frozen under the same discipline. Drives both a child's
    /// `ReshapeReady` leaf classification and the merge-terminal
    /// settled-waves carry (`TopologySnapshot::merge_pending`); the merge
    /// execution fold consumes the keepers mid-fold, so a live projection
    /// would diverge between the lookahead and active writes of the
    /// execution window.
    pub reshape_keepers_window: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// Parent-half cohorts of executed splits, keyed by the freshly split
    /// child each member seats on, mapping member → the parent it re-roots
    /// its local store from. Written when a split executes (the members that
    /// landed on a child from its parent committee, the inverse of the
    /// child's observer cohort), and dropped once the child commits past its
    /// genesis. Projected onto the head [`TopologySnapshot`] so the reshape
    /// orchestrator discovers and seats parent halves from the committed view.
    /// Not window-frozen: a parent half is seated within the window its split
    /// executes in, so the projection carries the live map unchanged.
    pub reshape_parent_halves: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// Per-shard boundary record: the snap-sync anchor (`state_root` /
    /// `block_hash`), the applied witness high-water mark, and the
    /// liveness history. Seeded for every genesis shard so it is never
    /// empty for an active shard; a shard gains its entry when it first
    /// appears in the trie. Refreshed by the boundary fold each epoch,
    /// which also advances `witness_leaf_count` as it applies each
    /// boundary contribution's witness chunk.
    pub boundaries: BTreeMap<ShardId, ShardBoundary>,
    /// Shards the boundary fold has observed cross an epoch boundary past
    /// their seeded genesis — i.e. producing on their own chain, not merely
    /// seeded. A freshly seeded reshape successor (a split's child, a merge's
    /// reformed parent) is absent until its first crossing folds; the reshape
    /// handoff reads this as "successor live". GC'd alongside
    /// [`Self::boundaries`].
    pub advanced: BTreeSet<ShardId>,
    /// Admitted shard reshapes awaiting execution, keyed by target
    /// (the splitting shard / the merge parent). Written by the witness
    /// fold's trigger admission; pruned by the per-epoch staleness
    /// sweep when assertions go quiet.
    pub pending_reshapes: BTreeMap<ShardId, PendingReshape>,
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

/// One observer seat of a pending split, as surfaced in
/// [`SlotEffects`]: who holds it, the splitting shard whose committee
/// carries it, and the assigned pending child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ObserverSeat {
    /// Validator holding the seat.
    pub validator: ValidatorId,
    /// The splitting shard.
    pub shard: ShardId,
    /// The pending child the observer syncs.
    pub child: ShardId,
}

/// One keeper seat of a pending merge, as surfaced in [`SlotEffects`]:
/// who holds it, the parent they reform, and the child they run (and
/// hard-link the merged store from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct KeptSeat {
    /// Validator holding the seat.
    pub validator: ValidatorId,
    /// The merged parent the keeper reforms.
    pub parent: ShardId,
    /// The child the keeper currently runs.
    pub child: ShardId,
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
    pub shard_committee_transitions: BTreeMap<ShardId, CommitteeTransition>,
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
    /// Observer seats drawn into pending splits' cohorts this epoch.
    pub observers_drawn: Vec<ObserverSeat>,
    /// Observer seats that left their cohort this epoch without
    /// executing — the staleness cancel, the readiness TTL, jail, or
    /// deactivation. Seats a split consumed land on their child and
    /// surface through the committee transitions instead.
    pub observers_released: Vec<ObserverSeat>,
    /// Keeper seats drawn into pending merges this epoch — when both
    /// halves paired and the keeper committee was fixed.
    pub keepers_drawn: Vec<KeptSeat>,
    /// Keeper seats released this epoch without executing — the merge
    /// cancelled (a required half went quiet or the readiness TTL
    /// elapsed). Seats a merge consumed land on the parent and surface
    /// through the committee transitions instead.
    pub keepers_released: Vec<KeptSeat>,
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
    /// Counts `Pooled`, `OnShard`, and `Observing` (a cohort seat is a
    /// stake-backed placement like any other); excludes `Jailed` (epoch
    /// may stay jailed indefinitely; locking stake against an uncertain
    /// return is wrong) and `InsufficientStake` (already represents
    /// "not consuming an epoch").
    #[must_use]
    pub fn current_active_count(&self, state: &BeaconState) -> usize {
        self.validators
            .iter()
            .filter(|id| {
                matches!(
                    state.validators.get(id).map(|r| &r.status),
                    Some(
                        ValidatorStatus::Pooled
                            | ValidatorStatus::OnShard { .. }
                            | ValidatorStatus::Observing { .. }
                    )
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

/// The per-window projections subject to the freeze discipline. Each is
/// frozen at promotion and read on the active path, or re-derived live and
/// read on the lookahead path, so a window's schedule entry is byte-identical
/// whether resolved from its lookahead write or its active overwrite. They
/// travel together because they share that discipline — and because
/// `reshape_observers`/`reshape_keepers` are the same type, a named struct
/// keeps a positional swap from compiling silently.
struct WindowProjection {
    consensus_members: BTreeMap<ShardId, Vec<ValidatorId>>,
    witness_bases: BTreeMap<ShardId, BeaconWitnessLeafCount>,
    reshape_observers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    reshape_keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// The live retained parent-half cohorts — not window-frozen like the
    /// fields above, since a parent half is discovered and seated entirely
    /// within the window the split executes in, so the head and lookahead
    /// snapshots project the same map.
    reshape_parent_halves: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    split_pending: BTreeSet<ShardId>,
    /// Governable params for this window: `params` (head) or `next_params`
    /// (lookahead). Frozen one epoch ahead like the committee.
    params: NetworkParams,
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

    /// Whether `shard` is already involved in a pending reshape — as a
    /// split target, or as a child of a pending merge. Reshapes never
    /// overlap: trigger admission rejects a target this returns `true`
    /// for.
    #[must_use]
    pub fn reshape_involves(&self, shard: ShardId) -> bool {
        self.pending_reshapes
            .iter()
            .any(|(target, reshape)| match reshape {
                PendingReshape::Split { .. } => *target == shard,
                PendingReshape::Merge { .. } => {
                    let (left, right) = target.children();
                    shard == left || shard == right
                }
            })
    }

    /// Whether `validator` holds a keeper seat for the pending merge of
    /// `child`'s parent. Keepers must sync the sibling half before the
    /// boundary, so rotation on `child` pins them while the merge pends.
    #[must_use]
    pub fn is_merge_keeper(&self, child: ShardId, validator: ValidatorId) -> bool {
        let Some(parent) = child.parent() else {
            return false;
        };
        matches!(
            self.pending_reshapes.get(&parent),
            Some(PendingReshape::Merge { keepers, .. })
                if keepers.get(&validator).is_some_and(|seat| seat.child == child)
        )
    }

    /// Validators eligible to serve on the beacon committee: status is
    /// `OnShard { ready: true, .. }` on a shard whose chain has started.
    ///
    /// Every beacon committee member is therefore a signer on some shard
    /// — an offline validator can't escape detection by hiding in the
    /// beacon set. Pooled, jailed, insufficient-stake, and not-yet-ready
    /// validators are all excluded.
    ///
    /// The pending-anchor clause covers the one case where `ready` does
    /// not yet prove a serving consensus node: a split execution places
    /// its consumed observers `ready: true` (their synced stores carry
    /// the child's consensus subset from the boundary), but their nodes
    /// only flip onto the child once its anchor seeds from the parent's
    /// terminal contribution — folds after the execution. Drafting one
    /// into the beacon committee before that could cost the beacon its
    /// quorum exactly when the anchor seeding depends on it. So a
    /// validator placed at a still-pending child record's creation
    /// (`placed_at_epoch >= last_live_epoch`, which a pending placeholder
    /// never advances) is excluded until the record seeds. Parent-half
    /// members keep their original placement epoch across the flip and
    /// stay eligible — their hosts have been serving all along — and a
    /// normal joiner's shard always has a live record. Chains born at
    /// network genesis (pending placeholders with a `GENESIS` creation
    /// epoch) start unconditionally — no flip gates them, so their
    /// members are eligible from the first fold.
    ///
    /// Returned sorted by `ValidatorId` (`BTreeMap` iteration order) for
    /// deterministic Fisher–Yates input downstream.
    #[must_use]
    pub fn beacon_eligible(&self) -> Vec<ValidatorId> {
        self.validators
            .iter()
            .filter(|(_, r)| match r.status {
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch,
                } => !self.boundaries.get(&shard).is_some_and(|b| {
                    b.block_hash == BlockHash::ZERO
                        && b.last_live_epoch > Epoch::GENESIS
                        && placed_at_epoch >= b.last_live_epoch
                }),
                _ => false,
            })
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
    /// state governs — the **active** committee (`shard_committees`)
    /// with the promotion-frozen consensus subset
    /// (`shard_consensus_members`).
    ///
    /// The snapshot is the read-only consumer-facing view of validator
    /// placement: shard committees, per-validator pubkeys, and the
    /// global validator set. Re-derived on every epoch commit and
    /// shared via `ArcSwap` with the `io_loop`.
    ///
    /// All validators are assigned uniform [`VoteCount::new(1)`].
    #[must_use]
    pub fn derive_topology_snapshot(&self, network: NetworkDefinition) -> TopologySnapshot {
        self.derive_topology_from(
            &self.shard_committees,
            WindowProjection {
                consensus_members: self.shard_consensus_members.clone(),
                witness_bases: self.witness_window_bases.clone(),
                reshape_observers: self.reshape_observers_window.clone(),
                reshape_keepers: self.reshape_keepers_window.clone(),
                reshape_parent_halves: self.reshape_parent_halves.clone(),
                split_pending: self.split_pending_window.clone(),
                params: self.params,
            },
            network,
        )
    }

    /// Derive the [`TopologySnapshot`] for the **next** epoch's window —
    /// the lookahead committee (`next_shard_committees`) that becomes
    /// active one epoch from now, with its consensus subset resolved live
    /// from current validator statuses (the same statuses promotion will
    /// freeze when that window opens). The coordinator inserts this under
    /// the next epoch's key so a shard can resolve its committee before
    /// the window opens.
    #[must_use]
    pub fn derive_next_topology_snapshot(&self, network: NetworkDefinition) -> TopologySnapshot {
        self.derive_topology_from(
            &self.next_shard_committees,
            WindowProjection {
                consensus_members: self.ready_consensus_members(&self.next_shard_committees),
                witness_bases: self.live_witness_bases(),
                reshape_observers: self.live_reshape_observers(),
                reshape_keepers: self.live_reshape_keepers(),
                reshape_parent_halves: self.reshape_parent_halves.clone(),
                split_pending: self.live_split_pending(),
                params: self.next_params,
            },
            network,
        )
    }

    /// Ready-filtered consensus subset of `committees`, resolved per
    /// `(member, shard)` against current validator statuses: a member of
    /// shard `s` counts iff its status is `OnShard { shard: s, ready:
    /// true }`. Member order is preserved, so bitfield indices are stable
    /// across every node deriving from the same state.
    #[must_use]
    pub fn ready_consensus_members(
        &self,
        committees: &BTreeMap<ShardId, ShardCommittee>,
    ) -> BTreeMap<ShardId, Vec<ValidatorId>> {
        committees
            .iter()
            .map(|(shard, committee)| {
                let ready: Vec<ValidatorId> = committee
                    .members
                    .iter()
                    .filter(|id| {
                        matches!(
                            self.validators.get(id).map(|r| r.status),
                            Some(ValidatorStatus::OnShard { shard: s, ready: true, .. })
                                if s == *shard
                        )
                    })
                    .copied()
                    .collect();
                (*shard, ready)
            })
            .collect()
    }

    /// Each shard's applied witness watermark as `boundaries` stand right
    /// now — the value the next promotion freezes into
    /// [`Self::witness_window_bases`], and what the lookahead snapshot
    /// projects for the window it describes.
    #[must_use]
    pub fn live_witness_bases(&self) -> BTreeMap<ShardId, BeaconWitnessLeafCount> {
        self.boundaries
            .iter()
            .map(|(shard, boundary)| (*shard, boundary.witness_leaf_count))
            .collect()
    }

    /// Shards with an admitted, not-yet-executed split as `pending_reshapes`
    /// stand right now — the value the next promotion freezes into
    /// [`Self::split_pending_window`], and what the lookahead snapshot
    /// projects for the window it describes.
    #[must_use]
    pub fn live_split_pending(&self) -> BTreeSet<ShardId> {
        self.pending_reshapes
            .iter()
            .filter(|(_, r)| matches!(r, PendingReshape::Split { .. }))
            .map(|(target, _)| *target)
            .collect()
    }

    /// Each pending split's observer cohort (parent → observer → child
    /// sub-shard) as `pending_reshapes` stand right now — the value the
    /// next promotion freezes into [`Self::reshape_observers_window`], and
    /// what the lookahead snapshot projects for the window it describes.
    #[must_use]
    pub fn live_reshape_observers(&self) -> BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.pending_reshapes
            .iter()
            .filter_map(|(target, reshape)| match reshape {
                PendingReshape::Split { cohort, .. } => Some((
                    *target,
                    cohort.iter().map(|(id, seat)| (*id, seat.child)).collect(),
                )),
                PendingReshape::Merge { .. } => None,
            })
            .collect()
    }

    /// Each pending merge's keepers keyed by the child each one runs
    /// (child → keeper → merging parent) as `pending_reshapes` stand right
    /// now — the value the next promotion freezes into
    /// [`Self::reshape_keepers_window`]. One merge contributes both
    /// children's keeper sets.
    #[must_use]
    pub fn live_reshape_keepers(&self) -> BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        let mut keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> = BTreeMap::new();
        for (parent, reshape) in &self.pending_reshapes {
            if let PendingReshape::Merge { keepers: seats, .. } = reshape {
                for (validator, seat) in seats {
                    keepers
                        .entry(seat.child)
                        .or_default()
                        .insert(*validator, *parent);
                }
            }
        }
        keepers
    }

    fn derive_topology_from(
        &self,
        committees: &BTreeMap<ShardId, ShardCommittee>,
        projection: WindowProjection,
        network: NetworkDefinition,
    ) -> TopologySnapshot {
        let WindowProjection {
            consensus_members,
            witness_bases,
            reshape_observers,
            reshape_keepers,
            reshape_parent_halves,
            split_pending,
            params,
        } = projection;
        let validators: Vec<ValidatorInfo> = self
            .validators
            .values()
            .map(|r| ValidatorInfo {
                validator_id: r.id,
                public_key: r.pubkey,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        let shard_committees: HashMap<ShardId, Vec<ValidatorId>> = committees
            .iter()
            .map(|(sid, sc)| (*sid, sc.members.clone()))
            .collect();
        let consensus_members: HashMap<ShardId, Vec<ValidatorId>> =
            consensus_members.into_iter().collect();

        // Project each shard's snap-sync anchor into the snapshot.
        // Genesis seeds zeroed placeholder boundaries until a shard's first
        // observed crossing; those aren't attested anchors, so they don't
        // project — `boundary(shard)` returns `None` and a joiner replays
        // from genesis instead of snap-syncing.
        let boundaries: HashMap<ShardId, ShardAnchor> = self
            .boundaries
            .iter()
            .filter(|(_, b)| b.block_hash != BlockHash::ZERO)
            .map(|(sid, b)| {
                (
                    *sid,
                    ShardAnchor {
                        state_root: b.state_root,
                        block_hash: b.block_hash,
                        height: b.height,
                        weighted_timestamp: b.weighted_timestamp,
                        settled_waves_root: b.settled_waves_root,
                    },
                )
            })
            .collect();

        let witness_bases: HashMap<ShardId, BeaconWitnessLeafCount> =
            witness_bases.into_iter().collect();

        // The reshape-seat projections — each pending split's observer
        // cohort and each pending merge's keepers, keyed by the child they
        // run — are passed in already frozen (active) or live (lookahead),
        // so a window's `ReshapeReady` leaf classification is byte-identical
        // across both writes of its schedule entry.
        TopologySnapshot::from_explicit_committees(
            network,
            &validator_set,
            shard_committees,
            consensus_members,
            boundaries,
            witness_bases,
            reshape_observers,
            reshape_keepers,
            reshape_parent_halves,
            split_pending,
        )
        .with_params(params)
        .with_advanced(self.advanced.iter().copied().collect())
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
    use crate::crypto::keys::bls_keypair_from_seed;
    use crate::{Hash, JailReason};

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
            params: NetworkParams::default(),
            next_params: NetworkParams::default(),
            param_votes: BTreeMap::new(),
            current_epoch: Epoch::GENESIS,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            randomness: Randomness::ZERO,
            committee: Vec::new(),
            shard_committees: BTreeMap::new(),
            next_shard_committees: BTreeMap::new(),
            shard_consensus_members: BTreeMap::new(),
            witness_window_bases: BTreeMap::new(),
            split_pending_window: BTreeSet::new(),
            reshape_observers_window: BTreeMap::new(),
            reshape_keepers_window: BTreeMap::new(),
            reshape_parent_halves: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            advanced: BTreeSet::new(),
            pending_reshapes: BTreeMap::new(),
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
        let shard = ShardId::ROOT;

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

    // ─── beacon_eligible ──────────────────────────────────────────────

    /// The pending-anchor exclusion: a member placed at a runtime-born
    /// child record's creation (an unflipped split observer) is not
    /// beacon-eligible until the record seeds; a member placed earlier
    /// (a parent half) and members of genesis-created pending records
    /// stay eligible throughout.
    #[test]
    fn beacon_eligible_excludes_members_of_pending_runtime_chains() {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(5);
        let child = ShardId::leaf(1, 0);
        let genesis_shard = ShardId::leaf(1, 1);
        let pending = |creation: Epoch| ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            last_live_epoch: creation,
            consecutive_misses: 0,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
        };
        state.boundaries.insert(child, pending(Epoch::new(4)));
        state
            .boundaries
            .insert(genesis_shard, pending(Epoch::GENESIS));
        let on = |shard, placed_at_epoch| ValidatorStatus::OnShard {
            shard,
            ready: true,
            placed_at_epoch,
        };
        // Observer: placed at the child record's creation.
        let observer = ValidatorId::new(0);
        // Parent half: carried its earlier placement across the flip.
        let parent_half = ValidatorId::new(1);
        // Genesis-shard member: pending record, but the chain starts
        // unconditionally at network birth.
        let genesis_member = ValidatorId::new(2);
        state
            .validators
            .insert(observer, validator_record(0, 0, on(child, Epoch::new(4))));
        state.validators.insert(
            parent_half,
            validator_record(1, 0, on(child, Epoch::new(1))),
        );
        state.validators.insert(
            genesis_member,
            validator_record(2, 0, on(genesis_shard, Epoch::GENESIS)),
        );

        assert_eq!(state.beacon_eligible(), vec![parent_half, genesis_member]);

        // The child anchor seeds: the observer's flip can proceed, and
        // it becomes eligible.
        state.boundaries.get_mut(&child).unwrap().block_hash =
            BlockHash::from_raw(Hash::from_bytes(b"seeded"));
        assert_eq!(
            state.beacon_eligible(),
            vec![observer, parent_half, genesis_member],
        );
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

    // ─── ready_consensus_members ──────────────────────────────────────

    /// The consensus subset resolves per `(member, shard)`: a member of
    /// shard `s` counts only when its status is `OnShard { shard: s,
    /// ready: true }`. Not-ready, jailed, and elsewhere-placed members
    /// stay in the committee (the networking view) but drop out of the
    /// subset, in member order.
    #[test]
    fn ready_consensus_members_filters_per_member_shard_status() {
        let mut state = single_pool_state(4);
        let shard = ShardId::ROOT;
        state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch: Epoch::GENESIS,
        };
        state
            .validators
            .get_mut(&ValidatorId::new(2))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };
        state
            .validators
            .get_mut(&ValidatorId::new(3))
            .unwrap()
            .status = ValidatorStatus::OnShard {
            shard: ShardId::leaf(1, 1),
            ready: true,
            placed_at_epoch: Epoch::GENESIS,
        };

        let subset = state.ready_consensus_members(&state.next_shard_committees);
        assert_eq!(subset[&shard], vec![ValidatorId::new(0)]);

        // The lookahead snapshot reflects the same split: full
        // membership intact, consensus queries over the subset only.
        let snapshot = state.derive_next_topology_snapshot(NetworkDefinition::simulator());
        assert_eq!(snapshot.committee_for_shard(shard).len(), 4);
        assert_eq!(
            snapshot.consensus_committee_for_shard(shard),
            [ValidatorId::new(0)]
        );
    }

    // ─── witness window bases ─────────────────────────────────────────

    /// The head snapshot projects the promotion-frozen window bases; the
    /// lookahead snapshot projects the live watermarks the next promotion
    /// will freeze. A fold advancing `boundaries` mid-window must not
    /// retroactively move the active window's base.
    #[test]
    fn head_projects_frozen_bases_lookahead_projects_live() {
        let mut state = single_pool_state(4);
        let shard = ShardId::ROOT;
        state.witness_window_bases = state.live_witness_bases();
        let frozen = state.witness_window_bases.get(&shard).copied();

        // The fold advances the live watermark mid-window.
        state
            .boundaries
            .entry(shard)
            .or_insert(ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
            })
            .witness_leaf_count = BeaconWitnessLeafCount::new(7);

        let head = state.derive_topology_snapshot(NetworkDefinition::simulator());
        assert_eq!(
            head.witness_base(shard),
            frozen.unwrap_or(BeaconWitnessLeafCount::ZERO)
        );

        let lookahead = state.derive_next_topology_snapshot(NetworkDefinition::simulator());
        assert_eq!(
            lookahead.witness_base(shard),
            BeaconWitnessLeafCount::new(7)
        );
    }

    // ─── reshape observer projection ──────────────────────────────────

    /// A pending split's cohort projects live into the lookahead snapshot,
    /// and into the active snapshot only once a promotion freezes it. The
    /// frozen active window stays stable while the live set mutates, so a
    /// window's `ReshapeReady` classification is identical whether resolved
    /// from its lookahead write or its active overwrite.
    #[test]
    fn pending_split_cohort_projects_into_snapshots() {
        let mut state = single_pool_state(4);
        let p = ShardId::ROOT;
        let (left, right) = p.children();
        let observer = ValidatorId::new(9);
        state.validators.insert(
            observer,
            validator_record(
                9,
                0,
                ValidatorStatus::Observing {
                    shard: p,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state
            .next_shard_committees
            .get_mut(&p)
            .unwrap()
            .members
            .push(observer);
        state.shard_committees = state.next_shard_committees.clone();
        state.pending_reshapes.insert(
            p,
            PendingReshape::Split {
                last_asserted: Epoch::GENESIS,
                admitted_at: Epoch::GENESIS,
                cohort: BTreeMap::from([(
                    observer,
                    CohortSeat {
                        child: left,
                        ready: false,
                    },
                )]),
                cohort_seed: Randomness::ZERO,
            },
        );

        // Live in the lookahead immediately; absent from the active
        // snapshot until a promotion freezes the projection.
        let lookahead = state.derive_next_topology_snapshot(NetworkDefinition::simulator());
        assert_eq!(lookahead.reshape_observer_child(p, observer), Some(left));
        assert_eq!(
            lookahead.reshape_observer_child(p, ValidatorId::new(0)),
            None
        );
        assert_eq!(lookahead.reshape_observer_child(right, observer), None);
        assert_eq!(
            state
                .derive_topology_snapshot(NetworkDefinition::simulator())
                .reshape_observer_child(p, observer),
            None,
        );

        // Promotion freezes the projection into the active window.
        state.reshape_observers_window = state.live_reshape_observers();
        assert_eq!(
            state
                .derive_topology_snapshot(NetworkDefinition::simulator())
                .reshape_observer_child(p, observer),
            Some(left),
        );

        // Dropping the pending record clears the lookahead at once; the
        // frozen active window holds until the next promotion re-freezes it.
        state.pending_reshapes.clear();
        assert_eq!(
            state
                .derive_next_topology_snapshot(NetworkDefinition::simulator())
                .reshape_observer_child(p, observer),
            None,
        );
        state.reshape_observers_window = state.live_reshape_observers();
        assert_eq!(
            state
                .derive_topology_snapshot(NetworkDefinition::simulator())
                .reshape_observer_child(p, observer),
            None,
        );
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
