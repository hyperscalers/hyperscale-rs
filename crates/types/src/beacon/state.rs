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

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{DeclaredWork, PriceTable};

use crate::beacon::constants::{HALT_THRESHOLD_EPOCHS, MIN_STAKE_FLOOR, POOL_BUFFER_TARGET};
use crate::beacon::genesis::BeaconChainConfig;
use crate::beacon::params::{NetworkParams, ParamProposal};
use crate::topology::snapshot::{ReshapeSeat, ShardAnchor, TopologySnapshot};
use crate::topology::validator::{ValidatorInfo, ValidatorSet};
use crate::{
    Address, BeaconWitnessLeafCount, BlockHash, BlockHeight, ConsensusPublicKey, Epoch, Hash,
    NetworkDefinition, RETENTION_HORIZON, Randomness, SeedRing, ShardFullness, ShardId, Stake,
    StakePoolId, StateRoot, TerminalRoots, ValidatorId, WeightedTimestamp,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct PendingWithdrawal {
    /// Amount the withdrawal removes from effective stake immediately
    /// and from total stake on unbonding completion.
    pub amount: Stake,
    /// Epoch when the withdrawal was placed.
    pub initiated_at_epoch: Epoch,
}

/// A pool-level byzantine conviction: equivocation evidence against any
/// of the pool's validators convicts the whole pool, since one operator
/// runs them all.
///
/// Set at most once and never cleared. A convicted pool is permanently
/// retired from validation — registration, unjail, and reactivation all
/// reject — and its withdrawals are impounded until `lifts_at`, after
/// which the stake exits whole through the normal unbonding path. The
/// punishment is the time-premium of the capital, never the capital.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct PoolConviction {
    /// Epoch the convicting evidence folded.
    pub convicted_at: Epoch,
    /// First epoch withdrawals mature again — `convicted_at` plus the
    /// `impound_epochs` governance parameter as it stood at conviction.
    /// Later governance changes never shorten an in-force impound.
    pub lifts_at: Epoch,
}
/// Epochs a registered package waits before a transaction may name it.
///
/// The window is what every node fetches the artifact's bytes in. Two
/// rather than one because a package registered moments before an epoch
/// cut would otherwise mature moments later: at two, the shortest wait
/// any package can draw is still a whole epoch.
pub const PACKAGE_MATURITY_EPOCHS: u64 = 2;

/// One published package, as the beacon registers it: the fact every
/// node prefetches the artifact's bytes on.
///
/// The publisher locates the bytes — the package cell sits under its
/// prefix, and the owning shard at any later moment follows from the
/// current trie — so the fact stays valid across reshapes without
/// naming a shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct PackageFact {
    /// The prefix the package cell sits under.
    pub publisher: Address,
    /// First epoch a transaction may name this package.
    ///
    /// [`PACKAGE_MATURITY_EPOCHS`] past the registration for a published
    /// package, and the genesis epoch for the packages the chain is born
    /// running. Held on the fact rather than recomputed, so the two
    /// answer the same question through one field.
    pub usable_from: Epoch,
}

impl PackageFact {
    /// Whether a block governed by `epoch` may name this package.
    #[must_use]
    pub const fn usable_in(&self, epoch: Epoch) -> bool {
        epoch.inner() >= self.usable_from.inner()
    }
}

/// Aggregate stake-pool record.
///
/// Delegator-level accounting lives in the staking contract on the
/// shard layer; beacon tracks only the aggregate state that determines
/// validator activation count. Pool entries are created implicitly on
/// the first `StakeDeposit` witness for an unknown id.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    /// Monotone lifetime sum of matured (released) withdrawals — the
    /// beacon-side source of truth for the per-pool withdrawal
    /// allowance the shard-layer staking component enforces (lifetime
    /// payouts never exceed the projected allowance). Only withdrawal
    /// maturation bumps it, so an impound reads as a plateau and the
    /// component needs no unbonding clock or conviction knowledge of
    /// its own.
    pub released_cumulative: Stake,
    /// The pool's byzantine conviction, if any. `Some` permanently
    /// retires the pool from validation and impounds its stake until
    /// the recorded lift epoch.
    pub conviction: Option<PoolConviction>,
}

// ─── validator types ─────────────────────────────────────────────────────────

/// What caused a validator to be jailed.
///
/// Every jail is temporary: it determines the cooldown an `Unjail`
/// witness must wait out. Provably byzantine signing is not a jail —
/// it revokes the key permanently ([`ValidatorStatus::Revoked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum JailReason {
    /// Performance failure. Surfaces from a shard's local miss-counter
    /// crossing threshold (witness emits with this reason), from the
    /// beacon-side `MissedProposal` counter crossing the jail
    /// threshold, or from a malformed VRF reveal in the validator's
    /// own proposal (self-inflicted cryptographic fault, jailed on
    /// first sighting). Unjails after `JAIL_COOLDOWN_EPOCHS`.
    Performance,
    /// A beacon-committee member was absent from the committed proposal
    /// set — the include-or-omit lever the randomness grind steers.
    /// Jailed on first absence like a performance fault, but held out
    /// for a full recency period ([`BeaconState::beacon_recency_period`])
    /// rather than the short performance cooldown: a shorter jail would
    /// let a grinder cycle its foothold back inside one committee
    /// turnover, defeating the recency weighting that rate-limits its
    /// service. Recoverable — an honest member cut off for a whole epoch
    /// unjails once the period elapses.
    Withholding,
}

/// Operational status of one validator.
///
/// Transitions are driven by `apply_epoch` from witnesses, withdrawal
/// completion, jail cascades, and pool draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
    /// Jailed and removed from any prior shard. `Unjail` (after the
    /// reason's cooldown) returns the validator to `Pooled` iff the
    /// pool can still support the additional active epoch; otherwise
    /// the unjail is rejected.
    Jailed {
        /// Epoch the jail entered.
        since_epoch: Epoch,
        /// Why.
        reason: JailReason,
    },
    /// The key is cryptographically proven byzantine — a double-signed
    /// beacon ballot or shard vote — and permanently revoked. Removed
    /// from any prior placement at the moment of transition; no
    /// witness, cooldown, or capacity change ever transitions out. The
    /// record persists so replayed evidence stays a no-op and the dead
    /// id can never re-register.
    Revoked {
        /// Epoch the evidence folded.
        at_epoch: Epoch,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    /// Compressed consensus pubkey. Carried in the on-chain record so
    /// verifiers (committee aggregates, VRF reveals, light clients)
    /// read it from state instead of relying on any side-channel
    /// registry. Lifted verbatim from
    /// `ShardWitnessPayload::RegisterValidator` at registration and
    /// from the genesis input at chain bootstrap.
    pub pubkey: ConsensusPublicKey,
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
/// cohort and one entrant per open rotation
/// ([`BeaconState::pending_rotations`], bounded by
/// [`BeaconChainConfig::max_rotations_in_flight`]) at every epoch
/// boundary; the list shrinks transiently when an epoch opens, then
/// refills via `pool_draw` within the same step.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hbor)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
    /// What the shard's chain has charged over its whole history, in
    /// quanta, as of the boundary header. A high-water mark, so one
    /// epoch's fees are the difference against the value the previous
    /// crossing recorded — which makes a missed crossing absorbed by the
    /// next rather than lost. Zero on a freshly seeded record: a chain
    /// starts its own count at zero, including a split child or merged
    /// parent that inherits state but not its predecessor's takings.
    pub cumulative_fees: u128,
    /// What the shard's blocks have reserved against their per-block
    /// caps over its whole history, as of the boundary header.
    ///
    /// A high-water mark on [`cumulative_fees`](Self::cumulative_fees)'s
    /// terms, and per dimension because the price controller moves each
    /// row by its own dimension's use. Differenced against the previous
    /// crossing's, it is one epoch's declared consumption — the
    /// numerator of the utilization the fold steps the table on.
    pub used: DeclaredWork,
    /// How many blocks the shard's chain has committed over its whole
    /// history, as of the boundary header.
    ///
    /// The denominator to [`used`](Self::used)'s numerator, and the one
    /// count either may be read against: both restart at the chain's own
    /// genesis, where the [`height`](Self::height) line is inherited
    /// across a reshape. Differencing the heights of a split child's two
    /// records would charge it every block its parent ever produced.
    pub blocks: u64,
    /// Committed substate byte total behind the boundary header's parent
    /// state — a level, not a running total, so a crossing whose header
    /// resolved no total (the halt-recovery case) leaves the recorded value
    /// unrefreshed rather than zeroing it.
    pub substate_bytes: u64,
    /// The boundary header's own witness window base — the low edge of
    /// the leaf range its `beacon_witness_root` commits. Serving
    /// committee members retain persisted witness payloads down to this
    /// index so a snap-syncing joiner can assemble the anchor's window.
    pub witness_base: BeaconWitnessLeafCount,
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
    /// The epoch the fold first observed this terminal shard's reshape
    /// successors live (produced past genesis). The terminal-evidence
    /// window counts from here, not from the cut: evidence is only
    /// acquirable once the boundary has folded and the network has
    /// caught up, and the handoff's completion is the one deterministic
    /// milestone that bounds both. `None` while the handoff is pending —
    /// an open window — and always `None` for a live shard.
    pub handoff_complete: Option<Epoch>,
    /// Whether this shard's terminal contribution has folded — set on a
    /// merge child, whose parent composes from both children's terminal
    /// roots and so must wait for the pair.
    ///
    /// Persisted rather than derived per fold: the two children's
    /// terminals can land in different epochs, and the earlier one's record
    /// is not refreshed while the later one is still outstanding. A split
    /// parent never sets it — its children seed in the same fold that
    /// records its terminal, so there is nothing to wait for.
    pub terminal_delivered: bool,
    /// The terminal header's [`TerminalRoots`] — the beacon-attested
    /// commitments this shard left the chains that outlive it. `Some` only
    /// on a terminated shard's boundary record, `None` for a live shard,
    /// and projected onto [`ShardAnchor`](crate::ShardAnchor) for both its
    /// readers.
    ///
    /// This projection is the durable delivery. Both readers also take the
    /// roots straight off the terminal header, which is the only path fast
    /// enough while the successor's rule is live; but a successor derives
    /// its `RecoveredState` afresh on every boot and cannot reconstruct
    /// the roots from its own chain, so a restart inside the window — or a
    /// validator rotated onto the successor committee after the flip —
    /// reads them here or not at all.
    pub terminal_roots: Option<TerminalRoots>,
    /// Epoch the reshape that terminates this shard was admitted (split)
    /// or paired (merge), stamped at the reshape's execution alongside
    /// [`terminal_epoch`](Self::terminal_epoch). Floors the shard's
    /// attested settled-transaction window: counterpart fences hold straddlers
    /// from the moment the reshape projects, so the window must reach back
    /// to that point, not a fixed span behind the terminal. `None` for a
    /// live shard.
    pub reshape_admitted_epoch: Option<Epoch>,
}

/// One observer drawn into a pending split's cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
///
/// Once the readiness gate passes the record is *scheduled*: its cut is
/// fixed a window out and neither TTL can retract it. The fold at that
/// cut consumes the record and applies the reshape.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
        /// The cut this split will land on, stamped once the readiness
        /// gate passes and never moved after. `None` while the split is
        /// admitted but unscheduled.
        scheduled: Option<ScheduledSplit>,
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
        /// Seats drop with the validator's jail or deactivation.
        /// Empty until paired.
        keepers: BTreeMap<ValidatorId, KeeperSeat>,
        /// Epoch the merge paired and drew its keepers — starts the
        /// readiness TTL. `None` until paired.
        admitted_at: Option<Epoch>,
        /// The children's final epoch window, stamped once the readiness
        /// gate passes and never moved after — both children share it, so
        /// they leave the trie on the same cut. `None` while the merge is
        /// paired but unscheduled.
        scheduled_terminal: Option<Epoch>,
    },
}

/// A split whose readiness gate has passed: its cut is fixed and the
/// parent's committee is already carved between the two children.
///
/// Both halves are frozen here rather than recomputed when the split
/// applies. The gate approves one specific partition — each child's
/// parent half plus its ready cohort seats reaching `2f+1` — and the
/// schedule is irrevocable, so there is no second gate to re-approve a
/// different carve. Membership holds still across the scheduled window
/// because rotation skips a shard with a live split record.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ScheduledSplit {
    /// The parent's final epoch window — the cut its chain terminates on
    /// and the children take over at.
    pub terminal: Epoch,
    /// Each child's half of the parent committee, in assignment order.
    pub halves: BTreeMap<ShardId, Vec<ValidatorId>>,
}

impl PendingReshape {
    /// The final epoch window this reshape's terminating leaves are
    /// scheduled to leave the trie at, or `None` while the readiness gate
    /// has yet to pass.
    ///
    /// A `Some` answer is irrevocable: the schedule reaches the affected
    /// shards' proposers a window before the fold that applies it, and they
    /// stamp their boundary verdict from it, so neither the readiness TTL
    /// nor a trigger going quiet may retract it.
    #[must_use]
    pub fn scheduled_terminal(&self) -> Option<Epoch> {
        match self {
            Self::Split { scheduled, .. } => scheduled.as_ref().map(|s| s.terminal),
            Self::Merge {
                scheduled_terminal, ..
            } => *scheduled_terminal,
        }
    }
}

/// A committee rotation with its entrant seated and its victim not yet
/// retired, held in [`BeaconState::pending_rotations`] under the
/// rotating shard and keyed by the victim it will retire.
///
/// The shuffle rotates make-before-break: the entrant joins `members`
/// unready, syncing and gossiping, while the victim holds the consensus
/// seat that keeps the shard's quorum denominator at `shard_size`. The
/// pair is frozen at the opening fold rather than recomputed at
/// resolution, so the seat the victim holds is the seat the entrant
/// takes. The rotation resolves in the fold after the entrant's
/// readiness lands, and every entrant becomes ready — by witness or by
/// the auto-ready timeout — so no rotation stays open indefinitely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct PendingRotation {
    /// The drawn member syncing into the seat, `OnShard { ready: false }`
    /// until its readiness folds.
    pub entrant: ValidatorId,
    /// Epoch the shuffle opened this rotation. Diagnostic: resolution is
    /// driven by the entrant's readiness, not by an elapsed count.
    pub opened_at: Epoch,
}

/// Why a shard's committee was recovered. Fence, re-draw, retention,
/// bridge, and clearing are identical across causes; the cause records
/// provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum RecoveryCause {
    /// The committee went quiet: its committed-boundary watermark
    /// stopped advancing past the halt threshold.
    Halt,
    /// The committee provably committed two conflicting chains at one
    /// height — impossible below f+1 corrupt seats, so the committee
    /// itself is compromised.
    Fork,
}

/// One in-flight shard recovery: the shard's failed committee has been
/// replaced by a fresh pool draw, and the shard has not yet committed a
/// boundary crossing under the new one.
///
/// Written when the fold re-draws a shard's committee — which also
/// resets the boundary's miss count, so the fresh committee gets a
/// full threshold of observed folds to produce before the shard
/// re-flags — and cleared by the shard's next observed crossing. While
/// it stands, the replaced members stay in the shard's routing view so
/// incomers can fetch the retained chain's tip from nodes that hold it,
/// the shard's members sit out beacon eligibility (seated on trust,
/// they prove themselves serving only at that first crossing), and
/// [`rotated_at`](Self::rotated_at) anchors the recovery bridge that
/// binds blocks extending the retained tip to the fresh committee.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ShardRecovery {
    /// What the recovery answers. Provenance only: every consequence of
    /// the record is cause-agnostic.
    pub cause: RecoveryCause,
    /// Epoch the fresh committee was seated.
    pub rotated_at: Epoch,
    /// The replaced committee, retained for routing until the shard
    /// commits again. A recovery that itself stalls folds its own fresh
    /// committee into the successor recovery's retention, so every
    /// member that might hold the tip stays reachable.
    pub retained: Vec<ValidatorId>,
    /// The last boundary height the beacon had folded for the shard when
    /// the recovery was stamped — the beacon-authenticated frontier below
    /// which the retained committee's certified history is legitimate.
    /// Above it, an old-committee artifact is one the beyond-f committee
    /// could only have forged after its failure, so the local bridge and
    /// cross-shard consumers reject it once they fold this record. It is
    /// unforgeable by the retained committee: a pure function of the
    /// committed beacon boundaries, not a claim that committee makes
    /// about its own tip.
    pub attested_frontier: BlockHeight,
}

/// The permanent record of a shard's most recent completed recovery.
///
/// Stamped when the pending [`ShardRecovery`] clears on the shard's
/// first observed crossing under its fresh committee. One entry per
/// recovered shard, overwritten by a later recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct CompletedRecovery {
    /// Epoch the fresh committee was seated
    /// ([`ShardRecovery::rotated_at`]). Certified resolution of the
    /// recovery's bridge band reads it so blocks anchored below the
    /// bridge keep binding to the fresh committee that produced them,
    /// no matter when a replica commits them.
    pub rotated_at: Epoch,
    /// The recovery's beacon-attested frontier
    /// ([`ShardRecovery::attested_frontier`]). A fork proof whose forked
    /// height sits at or below it is a replay of already-recovered
    /// history and must not re-arm a recovery.
    pub attested_frontier: BlockHeight,
}

/// The window-frozen half of a beacon projection — see
/// [`BeaconState::window`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hbor)]
pub struct FrozenWindow {
    /// Each shard's beacon-witness accumulator base for this window: the
    /// applied watermark (`boundaries[shard].witness_leaf_count`) as it
    /// stood at promotion, before this epoch's fold advances it.
    pub witness_bases: BTreeMap<ShardId, BeaconWitnessLeafCount>,
    /// Shards with an admitted, not-yet-applied split. The schedule's
    /// boundary predicates read it to tell which reshape a scheduled cut
    /// belongs to, and it marks the shards whose settled-transaction window is
    /// fenced open.
    pub split_pending: BTreeSet<ShardId>,
    /// Each terminating leaf's scheduled final window — the affirmative
    /// counterpart of `split_pending`, letting a boundary predicate answer
    /// "this window *is* the shard's last" from this entry alone.
    ///
    /// Soundness rests on no fold scheduling a terminal for the window it
    /// opens (INV-RESHAPE-9). The freeze runs before the reshape folds, so
    /// a self-naming schedule would land after this snapshot and diverge a
    /// window's two writes.
    pub scheduled_terminals: BTreeMap<ShardId, Epoch>,
    /// Each terminating leaf's settled-transaction window floor: pending split
    /// targets and paired merge children from the live records, plus
    /// shards already coasting to their terminal.
    pub settled_window_floors: BTreeMap<ShardId, WeightedTimestamp>,
    /// Each pending split's observer cohort, keyed by parent, mapping
    /// observer to its seat. A window's `ReshapeReady` leaf
    /// classification reads it, and the applying fold flips the cohort to
    /// `OnShard` mid-fold — so a live projection would differ between the
    /// two writes and fork the beacon-witness root across replicas at
    /// different fold heights.
    ///
    /// The seat's `ready` bit rides the same freeze: it moves only at a
    /// fold, and an emitter reads it to tell whether its `ReshapeReady`
    /// has landed.
    pub reshape_observers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
    /// Each pending merge's keepers, keyed by the child each keeper runs,
    /// mapping keeper to its seat on the merging parent. Drives a child's
    /// `ReshapeReady` classification and the merge-terminal settled-transaction
    /// carry; the applying fold consumes the keepers mid-fold, under the
    /// same argument as the observer cohort.
    pub reshape_keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
}

/// Global beacon state. Updated atomically per epoch by `apply_epoch`.
///
/// Cross-validator agreement on every field at every epoch follows from
/// `apply_epoch` being a pure deterministic function of `(state, epoch,
/// committed)` and SPC's Agreement guaranteeing all honest parties see
/// the same `committed` argument.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    /// The price of each dimension in force this epoch, inside the
    /// bounds [`Self::params`] carries.
    ///
    /// A level rather than a vote: the fold moves each row by that
    /// dimension's utilization across the shards whose boundary
    /// advanced, so capacity and demand set the price between them and
    /// nobody has to name it. Frozen a window ahead like the committee
    /// and promoted beside [`Self::params`], so a block's anchor names
    /// one table and every participant of a cross-shard transaction
    /// prices it the same.
    pub prices: PriceTable,
    /// The lookahead table governing the next epoch: what this epoch's
    /// fold computed, promoted into [`Self::prices`] at the next
    /// `apply_epoch`. The freeze [`Self::next_params`] describes, for
    /// the same reason.
    pub next_prices: PriceTable,
    /// The share of its block caps each live shard has been spending,
    /// per dimension, as a mean over
    /// [`FULLNESS_EPOCHS`](crate::FULLNESS_EPOCHS).
    ///
    /// Advanced at the fold from the same per-shard deltas the price
    /// controller sums, and read by the shard's own reshape predicate:
    /// the controller's reading is the network's mean, which cannot see
    /// one hot shard among idle ones, so a shard that has been running
    /// near its caps is owed capacity rather than a price every sender
    /// pays. Keyed by live shard; a shard the fold retires leaves with
    /// its entry, and one it creates starts idle.
    pub fullness: BTreeMap<ShardId, ShardFullness>,
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
    /// The global package registry: every published artifact's content
    /// address, folded from `PackagePublished` witnesses. The fact every
    /// node prefetches a package's bytes on, and the registry a restart
    /// or snap-synced joiner reconciles its artifact stores against —
    /// the leaf is transport, this map is the durable record.
    pub packages: BTreeMap<Hash, PackageFact>,
    /// Running beacon randomness — BLAKE3 mix of the prior value with
    /// the shard reveal chains folded this epoch; an epoch where no
    /// reveal folds mixes the accepted ceremony VRF outputs instead.
    pub randomness: Randomness,
    /// The seeds of the epochs still inside [`SEED_WINDOW_EPOCHS`], each
    /// beside the roll that produced it.
    ///
    /// `randomness` is the head of this: what a draw resolving against a
    /// past epoch needs is the value as it stood then, and reading the
    /// head instead would make the answer depend on when it was asked.
    pub seeds: SeedRing,
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
    /// Everything else a window's schedule entry fixes at its promotion,
    /// frozen in one step before this epoch's folds mutate any of it.
    ///
    /// A window's entry is written twice — once as the preceding fold's
    /// lookahead, once re-derived as the active entry when the window
    /// opens — and consensus stamps boundary verdicts into signed headers
    /// from whichever copy a node holds. The two must therefore agree, so
    /// every field here is frozen rather than read live, and they are
    /// frozen together: [`Self::live_window`] is the one source and the
    /// promotion assigns its result whole, so a field that gains a live
    /// value but no freeze cannot arise.
    ///
    /// Not everything a snapshot carries belongs here. Boundary anchors,
    /// [`Self::advanced`], the recovery records and
    /// [`Self::reshape_parent_halves`] are the current view of the chain
    /// rather than a property of the window: both writes take them live,
    /// and no verdict is stamped from them.
    pub window: FrozenWindow,
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
    /// Shards with a folded-but-unanswered fork proof, mapped to the
    /// proven fork height. Set the moment `ingest_fork_proofs` observes a
    /// committed proof and consulted by every fold's recovery pass —
    /// exactly as the halt trigger re-derives from the boundary record
    /// each fold — so a fork that folds while the free pool is short of a
    /// full committee retries until the re-draw is actually stamped.
    /// Cleared only when the shard's fork-caused recovery enters
    /// [`Self::pending_recoveries`]. While a shard is flagged, the
    /// boundary fold fences its crossings, so the forked committee can
    /// neither advance the boundary nor accumulate halt misses.
    pub fork_flagged: BTreeMap<ShardId, BlockHeight>,
    /// In-flight shard recoveries, keyed by the recovered shard.
    /// Written when the fold re-draws a failed committee; an entry
    /// drops on the shard's next observed crossing (the fresh committee
    /// produced) and is GC'd with the shard's boundary record.
    pub pending_recoveries: BTreeMap<ShardId, ShardRecovery>,
    /// In-flight committee rotations per shard, each keyed by the victim
    /// it retires, bounded by
    /// [`BeaconChainConfig::max_rotations_in_flight`]. The shuffle opens
    /// one per shard per interval; the fold that observes an entrant
    /// ready retires its victim and consumes that entry. An entry is
    /// dropped without retiring when either party leaves the shard some
    /// other way, and a shard's whole map is dropped when a reshape or
    /// recovery re-carves it.
    pub pending_rotations: BTreeMap<ShardId, BTreeMap<ValidatorId, PendingRotation>>,
    /// Each shard's most recent completed recovery, stamped when the
    /// pending record clears on the shard's first crossing. Permanent —
    /// one entry per recovered shard, overwritten by a later recovery —
    /// so certified resolution of the recovery's bridge band stays a
    /// pure function of folded chain content (a bridge block re-derived
    /// after the pending record clears still resolves the fresh
    /// committee it was produced under), and a replayed fork proof at or
    /// below the recovered frontier stays inert forever.
    pub completed_recoveries: BTreeMap<ShardId, CompletedRecovery>,
    /// Per-validator `MissedProposal` counter, scoped to the current
    /// epoch and the validator's current shard. Incremented when a
    /// `MissedProposal` witness arrives whose proposer is currently
    /// `OnShard { shard }` matching the witness's source shard. Reset
    /// on epoch boundaries and on any status transition out of
    /// `OnShard { shard }`. Crossing the jail threshold jails the
    /// validator under `JailReason::Performance` in the same epoch.
    pub miss_counters: BTreeMap<ValidatorId, u32>,
    /// Epoch of each validator's most recent beacon-committee service,
    /// stamped after every resample for the drawn members. The
    /// recency-weighted resample reads it: a member's draw weight starts
    /// low right after it serves and recovers additively over one full
    /// committee turnover, rate-limiting how often any one validator sits
    /// on the beacon committee so a grinder steering the draw cannot
    /// over-seat its corrupt set. A validator absent here has never
    /// served, and its baseline is `registered_at_epoch` — a fresh
    /// registrant ramps in from low weight like a just-served member.
    /// Never cleared: validator records persist for the chain's life
    /// (ids are never reused), so the map needs no GC and a
    /// deregister-then-reregister cannot reset the penalty.
    pub last_beacon_service: BTreeMap<ValidatorId, Epoch>,
}

// ─── epoch effects ───────────────────────────────────────────────────────────

/// What caused a [`CommitteeTransition`].
///
/// The runner uses this to tell "scheduled rotation, no anomaly" apart
/// from "the old committee failed and was replaced" — different
/// operator-facing signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum TransitionCause {
    /// Natural rotation at an epoch boundary — the trickled shuffle for
    /// per-shard committees, the epoch-rotation step for the beacon
    /// committee.
    NaturalShuffle,
    /// Committee resampled because the pool ratified the epoch's
    /// canonical skip block — the epoch closed with no committed
    /// proposals. Same pipeline as `NaturalShuffle` over an empty
    /// proposal set, distinguished only for observability so operators
    /// can tell "scheduled rotation" apart from "the chain just
    /// skipped."
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
/// [`SlotEffects::shard_committee_transitions`]) and by skip-block
/// commits, so the runner has a unified signal for "tear down the
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
#[derive(Debug, Default, Clone, PartialEq, Eq, Hbor)]
pub struct SlotEffects {
    /// New validators registered via a `RegisterValidator` witness.
    pub registered: Vec<ValidatorId>,
    /// Validators transitioned to `InsufficientStake` — via explicit
    /// `DeactivateValidator` witness or via withdrawal-completion
    /// auto-deactivation.
    pub deactivated: Vec<ValidatorId>,
    /// Validators jailed this epoch (`Jail` witness, malformed VRF
    /// reveal, or a beacon-side `MissedProposal` threshold crossing).
    pub jailed: Vec<ValidatorId>,
    /// Validators permanently revoked this epoch on equivocation
    /// evidence.
    pub revoked: Vec<ValidatorId>,
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
    /// Live shards flagged as halted at this fold — their boundary
    /// watermark stalled past [`HALT_THRESHOLD_EPOCHS`]
    /// ([`BeaconState::halted_shards`]). Reshaping and terminal shards
    /// are legitimately quiet and never land here. Surfaced so the
    /// runner can raise the alarm and tests can assert the detection.
    pub halted_shards: BTreeSet<ShardId>,
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
        let e = self.effective_stake().quanta();
        (e / min_stake.quanta()) as usize
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
    reshape_observers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
    reshape_keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
    /// The live retained parent-half cohorts — not window-frozen like the
    /// fields above, since a parent half is discovered and seated entirely
    /// within the window the split executes in, so the head and lookahead
    /// snapshots project the same map.
    reshape_parent_halves: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    split_pending: BTreeSet<ShardId>,
    scheduled_terminals: BTreeMap<ShardId, Epoch>,
    settled_window_floors: BTreeMap<ShardId, WeightedTimestamp>,
    /// Governable params for this window: `params` (head) or `next_params`
    /// (lookahead). Frozen one epoch ahead like the committee.
    params: NetworkParams,
    /// The price level for this window, frozen beside the params whose
    /// bounds hold it.
    prices: PriceTable,
    /// The fullest dimension of each shard's spending mean, in basis
    /// points, frozen beside the table it is read with.
    fullness: BTreeMap<ShardId, u32>,
    /// The packages a block governed by this window may name.
    usable_packages: BTreeSet<Hash>,
    /// The retained seed window. Not frozen a window ahead like the
    /// committee: a seed is a fact about an epoch that has already
    /// closed, so the head and lookahead projections carry the same ring.
    seeds: SeedRing,
}

impl BeaconState {
    /// An empty state under `chain_config`: no validators, pools,
    /// committees, or boundaries; genesis epoch; zero randomness; default
    /// network params. The base every construction site builds on —
    /// genesis seeds its validators and committees into it, fixtures seat
    /// what a scenario needs — so a new field is defaulted in exactly one
    /// place.
    #[must_use]
    pub fn empty(chain_config: BeaconChainConfig) -> Self {
        Self {
            chain_config,
            params: NetworkParams::default(),
            next_params: NetworkParams::default(),
            prices: PriceTable::GENESIS,
            next_prices: PriceTable::GENESIS,
            fullness: BTreeMap::new(),
            param_votes: BTreeMap::new(),
            packages: BTreeMap::new(),
            current_epoch: Epoch::GENESIS,
            validators: BTreeMap::new(),
            pools: BTreeMap::new(),
            randomness: Randomness::ZERO,
            seeds: SeedRing::default(),
            committee: Vec::new(),
            shard_committees: BTreeMap::new(),
            next_shard_committees: BTreeMap::new(),
            shard_consensus_members: BTreeMap::new(),
            window: FrozenWindow::default(),
            reshape_parent_halves: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            advanced: BTreeSet::new(),
            pending_reshapes: BTreeMap::new(),
            fork_flagged: BTreeMap::new(),
            pending_recoveries: BTreeMap::new(),
            pending_rotations: BTreeMap::new(),
            completed_recoveries: BTreeMap::new(),
            miss_counters: BTreeMap::new(),
            last_beacon_service: BTreeMap::new(),
        }
    }

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

    /// Shards whose chains have halted: live shards the boundary fold
    /// has observed missing for more than [`HALT_THRESHOLD_EPOCHS`]
    /// consecutive folds ([`ShardBoundary::consecutive_misses`]).
    ///
    /// That many missed folds means the shard has stopped committing
    /// boundary crossings — the signature of a liveness halt, e.g.
    /// `f + 1` corrupt members withholding votes so the honest remainder
    /// can't form a `2f + 1` quorum. The count advances only on epochs
    /// the beacon folded boundaries at all, so a beacon-side commit
    /// drought (a run of skip epochs) never reads as a shard halt — a
    /// wall-clock watermark would false-flag every shard at once there,
    /// and a false flag costs a needless full committee reset.
    ///
    /// Legitimately quiet chains never flag: shards involved in a
    /// pending reshape ([`Self::reshape_involves`]), terminal records
    /// coasting to a scheduled end, and reshape-pending placeholders
    /// that have no chain to advance until their genesis seeds. A
    /// genesis-born shard (pending record created at `Epoch::GENESIS`)
    /// is *not* exempt — nothing gates its start, so never producing is
    /// The applied witness-fold watermark for `shard` — how many of its
    /// accumulator leaves the fold has consumed
    /// ([`ShardBoundary::witness_leaf_count`]), or `0` for a shard with no
    /// recorded boundary yet. The proposer's chunk sourcing, the witness
    /// fetch driver, and the fold itself all key the next chunk off this
    /// one value, so they must read it identically or a contribution
    /// strands against the wrong crossing.
    #[must_use]
    pub fn fold_watermark(&self, shard: ShardId) -> u64 {
        self.boundaries
            .get(&shard)
            .map_or(0, |b| b.witness_leaf_count.inner())
    }

    /// a halt. A recovery resets the count, so the fresh committee gets
    /// a full threshold of observed folds to produce before the shard
    /// re-flags (and re-draws).
    ///
    /// A pure function of `self`, so every replica flags the identical
    /// set at the identical fold.
    #[must_use]
    pub fn halted_shards(&self) -> BTreeSet<ShardId> {
        let reshape_involved = self.reshape_involved_shards();
        self.boundaries
            .iter()
            .filter(|(shard, b)| {
                b.terminal_epoch.is_none()
                    && !(b.block_hash == BlockHash::ZERO && b.last_live_epoch > Epoch::GENESIS)
                    && !reshape_involved.contains(*shard)
                    && u64::from(b.consecutive_misses) > HALT_THRESHOLD_EPOCHS
            })
            .map(|(shard, _)| *shard)
            .collect()
    }

    /// Every shard a pending reshape involves — [`Self::reshape_involves`]
    /// as a set, for callers testing many shards against one fold's
    /// pending reshapes.
    fn reshape_involved_shards(&self) -> BTreeSet<ShardId> {
        let mut involved = BTreeSet::new();
        for (target, reshape) in &self.pending_reshapes {
            match reshape {
                PendingReshape::Split { .. } => {
                    involved.insert(*target);
                }
                PendingReshape::Merge { .. } => {
                    let (left, right) = target.children();
                    involved.insert(left);
                    involved.insert(right);
                }
            }
        }
        involved
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
    /// A recovering shard's fresh committee is excluded under the same
    /// principle: it is seated `ready: true` on trust (the halted chain
    /// can fold no readiness witness) and proves itself serving only at
    /// the shard's first crossing, which clears the recovery. Drafting
    /// an unproven recovery seat into the beacon committee — or the
    /// ratification pool this set derives — could cost the beacon its
    /// quorum on nodes that are still syncing the halted chain.
    ///
    /// Returned sorted by `ValidatorId` (`BTreeMap` iteration order) for
    /// deterministic Fisher–Yates input downstream.
    #[must_use]
    pub fn beacon_eligible(&self) -> Vec<ValidatorId> {
        self.beacon_eligible_ids().collect()
    }

    /// [`Self::beacon_eligible`]'s size without materializing the set,
    /// for the per-shard shuffle floor and the recency period — both
    /// consume only the count.
    #[must_use]
    pub fn beacon_eligible_count(&self) -> usize {
        self.beacon_eligible_ids().count()
    }

    /// The eligibility predicate behind [`Self::beacon_eligible`], in
    /// `ValidatorId` order.
    fn beacon_eligible_ids(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.validators
            .iter()
            .filter(|(_, r)| match r.status {
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch,
                } => {
                    !self.pending_recoveries.contains_key(&shard)
                        && !self.boundaries.get(&shard).is_some_and(|b| {
                            b.block_hash == BlockHash::ZERO
                                && b.last_live_epoch > Epoch::GENESIS
                                && placed_at_epoch >= b.last_live_epoch
                        })
                }
                _ => false,
            })
            .map(|(id, _)| *id)
    }

    /// The recency period — `beacon_eligible / beacon_committee_size`
    /// epochs, at least one — over which a served member's resample
    /// weight recovers additively, and the cooldown a
    /// [`JailReason::Withholding`] jail holds for.
    ///
    /// One period is one full committee turnover: on average every
    /// eligible member serves once per period, so weighting service down
    /// for a period caps a grinder's sustained beacon-committee foothold
    /// near the natural `β · committee_size`. The withholding jail and
    /// the resample weight read the same period so a jailed grinder
    /// cannot return inside the window its recency weight would still
    /// suppress it.
    #[must_use]
    pub fn beacon_recency_period(&self) -> u64 {
        self.recency_period_for(self.beacon_eligible_count())
    }

    /// [`Self::beacon_recency_period`] for a pre-computed eligible count,
    /// so a caller that already materialized the eligible set derives the
    /// period without a second scan.
    #[must_use]
    pub fn recency_period_for(&self, eligible_count: usize) -> u64 {
        let b = u64::from(self.chain_config.beacon_committee_size.max(1));
        (eligible_count as u64 / b).max(1)
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
    pub fn derive_beacon_committee(&self) -> Vec<(ValidatorId, ConsensusPublicKey)> {
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
                witness_bases: self.window.witness_bases.clone(),
                reshape_observers: self.window.reshape_observers.clone(),
                reshape_keepers: self.window.reshape_keepers.clone(),
                reshape_parent_halves: self.reshape_parent_halves.clone(),
                split_pending: self.window.split_pending.clone(),
                scheduled_terminals: self.window.scheduled_terminals.clone(),
                settled_window_floors: self.window.settled_window_floors.clone(),
                params: self.params,
                prices: self.prices,
                fullness: self.fullness_peaks(),
                usable_packages: self.usable_packages(self.current_epoch),
                seeds: self.seeds.clone(),
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
        let live = self.live_window();
        self.derive_topology_from(
            &self.next_shard_committees,
            WindowProjection {
                consensus_members: self.ready_consensus_members(&self.next_shard_committees),
                witness_bases: live.witness_bases,
                reshape_observers: live.reshape_observers,
                reshape_keepers: live.reshape_keepers,
                reshape_parent_halves: self.reshape_parent_halves.clone(),
                split_pending: live.split_pending,
                scheduled_terminals: live.scheduled_terminals,
                settled_window_floors: live.settled_window_floors,
                params: self.next_params,
                prices: self.next_prices,
                fullness: self.fullness_peaks(),
                usable_packages: self.usable_packages(self.current_epoch.next()),
                seeds: self.seeds.clone(),
            },
            network,
        )
    }

    /// The fullest dimension of each shard's mean, which is all its
    /// reshape predicate reads: a shard is too busy when any one of its
    /// caps is what binds it, so the window carries one figure per shard
    /// rather than the vector behind it.
    fn fullness_peaks(&self) -> BTreeMap<ShardId, u32> {
        self.fullness
            .iter()
            .map(|(shard, mean)| (*shard, mean.peak()))
            .collect()
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

    /// The window projection as state stands right now — what the next
    /// promotion freezes into [`Self::window`], and what the lookahead
    /// snapshot projects for the window it describes.
    ///
    /// One source for both, so the two writes of a window's entry cannot
    /// disagree, and a field added here is frozen and projected by
    /// construction rather than by remembering to touch both.
    #[must_use]
    pub fn live_window(&self) -> FrozenWindow {
        FrozenWindow {
            witness_bases: self.live_witness_bases(),
            split_pending: self.live_split_pending(),
            scheduled_terminals: self.live_scheduled_terminals(),
            settled_window_floors: self.live_settled_window_floors(),
            reshape_observers: self.live_reshape_observers(),
            reshape_keepers: self.live_reshape_keepers(),
        }
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

    /// Whether `shard`'s cut is scheduled but its reshape has not applied
    /// — its boundary already carries the terminal mark, yet its chain is
    /// still live in the trie and producing normally.
    ///
    /// The mark alone cannot answer this: it lands a window before the
    /// fold that applies the reshape, so between the two a terminal
    /// `boundary.terminal_epoch` describes a shard that has not stopped.
    /// Readers asking "has this chain terminated" must exclude the shards
    /// this returns `true` for. The reshape record's survival is the
    /// signal — the applying fold consumes it.
    #[must_use]
    pub fn terminal_scheduled_unapplied(&self, shard: ShardId) -> bool {
        let scheduled_merge = |parent: ShardId| {
            matches!(
                self.pending_reshapes.get(&parent),
                Some(r @ PendingReshape::Merge { .. }) if r.scheduled_terminal().is_some()
            )
        };
        matches!(
            self.pending_reshapes.get(&shard),
            Some(r @ PendingReshape::Split { .. }) if r.scheduled_terminal().is_some()
        ) || shard.parent().is_some_and(scheduled_merge)
    }

    /// Each terminating leaf's scheduled final window as state stands
    /// right now, keyed by the leaf that leaves the trie: a split's
    /// parent, or both of a merge's children. Empty until the readiness
    /// gate passes, since an admitted reshape carries no cut yet.
    ///
    /// The value the next promotion freezes into
    /// [`Self::terminal_epoch_window`], and what the lookahead snapshot
    /// projects — the two must agree, so both read this one source.
    #[must_use]
    pub fn live_scheduled_terminals(&self) -> BTreeMap<ShardId, Epoch> {
        let mut scheduled = BTreeMap::new();
        for (target, reshape) in &self.pending_reshapes {
            let Some(terminal) = reshape.scheduled_terminal() else {
                continue;
            };
            // A split's parent is the terminating leaf; a merge's are its
            // two children, which share the cut their parent forms on.
            match reshape {
                PendingReshape::Split { .. } => {
                    scheduled.insert(*target, terminal);
                }
                PendingReshape::Merge { .. } => {
                    for child in <[ShardId; 2]>::from(target.children()) {
                        scheduled.insert(child, terminal);
                    }
                }
            }
        }
        scheduled
    }

    /// Each terminating leaf's settled-transaction window floor as state stands
    /// right now: the start of the epoch its reshape was admitted (split)
    /// or paired (merge), backed off by [`RETENTION_HORIZON`] to cover a
    /// tick that finalized against the fence just after it armed but
    /// executed up to a full tick lifetime earlier. Sourced from
    /// `pending_reshapes` while the record lives and from the boundary
    /// stamp once the reshape executes (the coast). The value the next
    /// promotion freezes into [`Self::settled_window_floors`], and what
    /// the lookahead snapshot projects.
    #[must_use]
    pub fn live_settled_window_floors(&self) -> BTreeMap<ShardId, WeightedTimestamp> {
        let floor = |admitted: Epoch| {
            WeightedTimestamp::from_millis(
                admitted
                    .inner()
                    .saturating_mul(self.chain_config.epoch_duration_ms)
                    .saturating_sub(RETENTION_HORIZON.as_secs() * 1000),
            )
        };
        let mut floors: BTreeMap<ShardId, WeightedTimestamp> = self
            .boundaries
            .iter()
            .filter_map(|(shard, b)| b.reshape_admitted_epoch.map(|at| (*shard, floor(at))))
            .collect();
        for (target, reshape) in &self.pending_reshapes {
            match reshape {
                PendingReshape::Split { admitted_at, .. } => {
                    floors.insert(*target, floor(*admitted_at));
                }
                PendingReshape::Merge {
                    admitted_at: Some(at),
                    ..
                } => {
                    let (left, right) = target.children();
                    floors.insert(left, floor(*at));
                    floors.insert(right, floor(*at));
                }
                PendingReshape::Merge { .. } => {}
            }
        }
        floors
    }

    /// Each pending split's observer cohort (parent → observer → child
    /// sub-shard) as `pending_reshapes` stand right now — the value the
    /// next promotion freezes into [`Self::reshape_observers_window`], and
    /// what the lookahead snapshot projects for the window it describes.
    #[must_use]
    pub fn live_reshape_observers(&self) -> BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> {
        self.pending_reshapes
            .iter()
            .filter_map(|(target, reshape)| match reshape {
                PendingReshape::Split { cohort, .. } => Some((
                    *target,
                    cohort
                        .iter()
                        .map(|(id, seat)| {
                            (
                                *id,
                                ReshapeSeat {
                                    shard: seat.child,
                                    ready: seat.ready,
                                },
                            )
                        })
                        .collect(),
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
    pub fn live_reshape_keepers(&self) -> BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> {
        let mut keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> = BTreeMap::new();
        for (parent, reshape) in &self.pending_reshapes {
            if let PendingReshape::Merge { keepers: seats, .. } = reshape {
                for (validator, seat) in seats {
                    keepers.entry(seat.child).or_default().insert(
                        *validator,
                        ReshapeSeat {
                            shard: *parent,
                            ready: seat.ready,
                        },
                    );
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
            scheduled_terminals,
            settled_window_floors,
            params,
            prices,
            fullness,
            usable_packages,
            seeds,
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
                        witness_base: b.witness_base,
                        terminal_roots: b.terminal_roots,
                        handoff_complete: b.handoff_complete,
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
        .with_prices(prices)
        .with_fullness(fullness)
        .with_scheduled_terminals(scheduled_terminals)
        .with_settled_window_floors(settled_window_floors)
        .with_advanced(self.advanced.iter().copied().collect())
        .with_pending_recoveries(self.pending_recoveries.clone())
        .with_completed_recoveries(self.completed_recoveries.clone())
        .with_usable_packages(usable_packages)
        .with_seeds(seeds)
    }

    /// The packages a block governed by `epoch` may name: registered and
    /// past their maturity window, plus the genesis packages the registry
    /// is seeded with.
    ///
    /// Stated as the permission rather than the refusal, which is what
    /// makes the rule answerable from the registry alone. Its complement
    /// — immature, or never published at all — would otherwise have to be
    /// judged by an argument about which nodes happen to hold which
    /// metadata, and an invariant that needs that argument is one nobody
    /// can check locally.
    #[must_use]
    pub fn usable_packages(&self, epoch: Epoch) -> BTreeSet<Hash> {
        self.packages
            .iter()
            .filter(|(_, fact)| fact.usable_in(epoch))
            .map(|(package, _)| *package)
            .collect()
    }

    /// Active-duty validator pool: the [`Self::beacon_eligible`] serving
    /// set paired with pubkeys. Returned sorted by `ValidatorId`.
    ///
    /// This is the quorum substrate for epoch ratification:
    /// [`RatifyVote`](crate::RatifyVote)s are signed by members of this
    /// pool and assembled into a [`RatifyCert`](crate::RatifyCert)
    /// whose `signers` bitfield is positionally indexed against the same
    /// ordering.
    ///
    /// Ratification liveness rides on every pool member running a
    /// serving node, so membership is the same attested-serving rule the
    /// beacon committee draw trusts: `ready: true` on a live chain. The
    /// pending-anchor exclusion is what keeps a split from wedging the
    /// beacon: the execution fold flips the consumed observers `OnShard`,
    /// but their nodes only seat once the child's anchor seeds — folds
    /// *after* the execution, which this pool must ratify — so counting
    /// them before the seed would raise the quorum above the set of
    /// nodes that can vote. The parent halves, serving throughout, carry
    /// the pool across that window.
    ///
    /// Membership ⊆ shard-serving nodes is also load-bearing for
    /// delivery: candidate and ratify-vote gossip reaches a node
    /// through its hosted shards' global-topic fans, and shard-less
    /// pool followers drop ratify actions — a pool member serving no
    /// shard would silently lose its vote.
    #[must_use]
    pub fn derive_active_pool(&self) -> Vec<(ValidatorId, ConsensusPublicKey)> {
        self.beacon_eligible()
            .into_iter()
            .filter_map(|id| self.validators.get(&id).map(|r| (id, r.pubkey)))
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
    pub fn min_stake(&self) -> Stake {
        let ne = self.t_no_eject();
        let ad = self.admit_threshold();
        Stake::from_quanta(ne.quanta().min(ad.quanta()).max(MIN_STAKE_FLOOR.quanta()))
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
                    Some(pool.effective_stake().quanta() / active as u128)
                }
            })
            .min()
            .map_or(Stake::MAX, Stake::from_quanta)
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
            // A convicted pool's stake is impounded, not productive:
            // its offerings would price seats the network can never
            // fill (registration rejects convicted pools), silently
            // raising `min_stake` against every live pool.
            if pool.conviction.is_some() {
                continue;
            }
            let e = pool.effective_stake().quanta();
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
                (e / MIN_STAKE_FLOOR.quanta()) as usize
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
        Stake::from_quanta(offerings[target - 1])
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::public_key_from_u64_seed;

    use super::*;
    use crate::{
        EpochSeed, Hash, JailReason, PrincipalAddr, SeedLookup, SeedSource, TopologySnapshot,
    };

    fn validator_record(id: u64, pool: u32, status: ValidatorStatus) -> ValidatorRecord {
        ValidatorRecord {
            id: ValidatorId::new(id),
            pool: StakePoolId::new(pool),
            status,
            registered_at_epoch: Epoch::GENESIS,
            pubkey: public_key_from_u64_seed(id),
        }
    }

    fn empty_state() -> BeaconState {
        BeaconState::empty(BeaconChainConfig::default())
    }

    /// Both projections carry the ring the fold built, so a consumer
    /// resolving a past epoch reads it off whichever snapshot governs
    /// the block it is in. A seed is a fact about an epoch that already
    /// closed, so unlike the committee there is nothing to freeze a
    /// window ahead — the head and the lookahead answer alike.
    #[test]
    fn both_projections_carry_the_seed_window() {
        let mut state = empty_state();
        let seed = EpochSeed {
            randomness: Randomness::new([0x5A; 32]),
            source: SeedSource::Reveals,
        };
        state.seeds.record(Epoch::new(4), seed);
        state.current_epoch = Epoch::new(4);

        for snapshot in [
            state.derive_topology_snapshot(NetworkDefinition::simulator()),
            state.derive_next_topology_snapshot(NetworkDefinition::simulator()),
        ] {
            assert_eq!(snapshot.seed(Epoch::new(4)), SeedLookup::Seed(seed));
            assert_eq!(snapshot.seed(Epoch::new(5)), SeedLookup::NotYetCommitted);
        }
    }

    /// A snapshot nobody projected from a beacon state answers nothing,
    /// rather than answering zero: a caller that took a default seed for
    /// a real one would be drawing on a value no fold produced.
    #[test]
    fn an_unprojected_snapshot_holds_no_seed() {
        let snapshot = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        );
        assert_eq!(
            snapshot.seed(Epoch::GENESIS),
            SeedLookup::NotYetCommitted,
            "an empty ring is ahead of every epoch"
        );
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
                total_stake: Stake::from_quanta(u128::from(n_active) * MIN_STAKE_FLOOR.quanta()),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state
            .next_shard_committees
            .insert(shard, ShardCommittee { members });
        state
    }

    // ─── beacon_eligible ──────────────────────────────────────────────

    /// The recency period is `beacon_eligible / beacon_committee_size`,
    /// floored at one — the committee-turnover horizon the resample
    /// weight and the withholding jail both key off.
    #[test]
    fn beacon_recency_period_is_eligible_over_committee_size() {
        // Default committee size is BEACON_SIGNER_COUNT = 4.
        let mut state = single_pool_state(20);
        assert_eq!(state.beacon_eligible().len(), 20);
        assert_eq!(state.beacon_recency_period(), 5);

        // Fewer eligible than a committee still floors at one epoch.
        state = single_pool_state(2);
        assert_eq!(state.beacon_recency_period(), 1);
    }

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
            used: DeclaredWork::ZERO,
            blocks: 0,
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            cumulative_fees: 0,
            substate_bytes: 0,
            last_live_epoch: creation,
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
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

    // ─── halted_shards ────────────────────────────────────────────────

    /// Only a live shard whose miss count crossed the threshold flags:
    /// a fresh record, a count exactly at the threshold, a pending
    /// reshape (split target or merge child), a terminal coast, and a
    /// reshape placeholder all read as healthy or legitimately quiet.
    /// A genesis-born record that never produced is a halt.
    #[test]
    fn halted_shards_flags_persistently_missing_live_shards_only() {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(40);
        let over = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits u32") + 1;
        let boundary = |misses: u32| ShardBoundary {
            used: DeclaredWork::ZERO,
            blocks: 0,
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
            height: BlockHeight::new(5),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            cumulative_fees: 0,
            substate_bytes: 0,
            last_live_epoch: Epoch::new(1),
            consecutive_misses: misses,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        };

        let halted = ShardId::leaf(3, 0);
        state.boundaries.insert(halted, boundary(over));

        let healthy = ShardId::leaf(3, 1);
        state.boundaries.insert(healthy, boundary(0));

        let at_threshold = ShardId::leaf(3, 2);
        state.boundaries.insert(at_threshold, boundary(over - 1));

        let splitting = ShardId::leaf(3, 3);
        state.boundaries.insert(splitting, boundary(over));
        state.pending_reshapes.insert(
            splitting,
            PendingReshape::Split {
                last_asserted: Epoch::new(1),
                admitted_at: Epoch::new(1),
                cohort: BTreeMap::new(),
                cohort_seed: Randomness::ZERO,
                scheduled: None,
            },
        );

        let terminal = ShardId::leaf(3, 4);
        state.boundaries.insert(
            terminal,
            ShardBoundary {
                terminal_epoch: Some(Epoch::new(2)),
                ..boundary(over)
            },
        );

        let placeholder = ShardId::leaf(3, 5);
        state.boundaries.insert(
            placeholder,
            ShardBoundary {
                block_hash: BlockHash::ZERO,
                ..boundary(over)
            },
        );

        let genesis_born = ShardId::leaf(3, 6);
        state.boundaries.insert(
            genesis_born,
            ShardBoundary {
                block_hash: BlockHash::ZERO,
                last_live_epoch: Epoch::GENESIS,
                ..boundary(over)
            },
        );

        let merge_parent = ShardId::leaf(3, 7);
        let (left, right) = merge_parent.children();
        state.boundaries.insert(left, boundary(over));
        state.boundaries.insert(right, boundary(over));
        state.pending_reshapes.insert(
            merge_parent,
            PendingReshape::Merge {
                halves: BTreeMap::new(),
                keepers: BTreeMap::new(),
                admitted_at: None,
                scheduled_terminal: None,
            },
        );

        assert_eq!(
            state.halted_shards(),
            BTreeSet::from([halted, genesis_born]),
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
            released_cumulative: Stake::ZERO,
            conviction: None,
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
            released_cumulative: Stake::ZERO,
            conviction: None,
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
        state.window.witness_bases = state.live_witness_bases();
        let frozen = state.window.witness_bases.get(&shard).copied();

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
                witness_base: BeaconWitnessLeafCount::ZERO,
                cumulative_fees: 0,
                used: DeclaredWork::ZERO,
                blocks: 0,
                substate_bytes: 0,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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
                scheduled: None,
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
        state.window.reshape_observers = state.live_reshape_observers();
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
        state.window.reshape_observers = state.live_reshape_observers();
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

    /// A package registered in epoch `N` carries `usable_from = N + 2`,
    /// so it is held back for the whole of `N` and `N + 1`. The shortest
    /// wait it can draw — registration in the last instant of `N` — is
    /// still the whole of `N + 1`, which is the window every node
    /// fetches its bytes in.
    #[test]
    fn a_registered_package_matures_two_epochs_on() {
        let registered_at = Epoch::new(4);
        let fact = PackageFact {
            publisher: Address::from(PrincipalAddr::new([7u8; 31])),
            usable_from: registered_at.saturating_add(PACKAGE_MATURITY_EPOCHS),
        };
        assert!(!fact.usable_in(Epoch::new(4)), "not in its own epoch");
        assert!(!fact.usable_in(Epoch::new(5)), "not in the next one");
        assert!(fact.usable_in(Epoch::new(6)), "runs two epochs on");
        assert!(fact.usable_in(Epoch::new(600)), "and every epoch after");

        // A package the chain is born running waits for nothing: genesis
        // seeds it, and every node compiles it at boot.
        let born = PackageFact {
            publisher: Address::from(PrincipalAddr::new([8u8; 31])),
            usable_from: Epoch::GENESIS,
        };
        assert!(born.usable_in(Epoch::GENESIS), "runs from the first epoch");
    }

    /// The projection names what a block may run. A package still inside
    /// its window is absent, and so is one nobody ever registered — the
    /// two are refused alike, which is what spares the rule an argument
    /// about which nodes hold which metadata.
    #[test]
    fn only_the_usable_project_into_the_window() {
        let mut state = empty_state();
        let young = Hash::from_bytes(b"young");
        let old = Hash::from_bytes(b"old");
        let unpublished = Hash::from_bytes(b"unpublished");
        state.packages.insert(
            young,
            PackageFact {
                publisher: Address::from(PrincipalAddr::new([1u8; 31])),
                usable_from: Epoch::new(11),
            },
        );
        state.packages.insert(
            old,
            PackageFact {
                publisher: Address::from(PrincipalAddr::new([2u8; 31])),
                usable_from: Epoch::new(3),
            },
        );

        let usable = state.usable_packages(Epoch::new(10));
        assert!(usable.contains(&old), "long since matured");
        assert!(!usable.contains(&young), "still inside its window");
        assert!(!usable.contains(&unpublished), "never registered at all");
        assert!(
            state.usable_packages(Epoch::new(11)).contains(&young),
            "and it joins the set as its window closes"
        );
    }
}
