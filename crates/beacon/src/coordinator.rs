//! Top-level beacon FSM.
//!
//! [`BeaconCoordinator`] is the per-vnode state machine; it owns the
//! committed [`BeaconState`], the [`SpcDriver`](crate::spc_driver::SpcDriver)
//! consensus plane, and the wall-clock anchor that drives epoch-cadence
//! timers.
//!
//! Constructor is pure synchronous data assembly — the runner is
//! responsible for loading `(latest_block, latest_state)` from
//! [`BeaconChainReader::latest_committed`](hyperscale_storage::BeaconChainReader::latest_committed)
//! before invoking [`BeaconCoordinator::new`]. The same code path
//! handles fresh-genesis and warm-restart: the runner builds and
//! commits the genesis pair on an empty store, then loads it back via
//! the same `latest_committed()` call. When the loaded block is
//! genesis the constructor debug-asserts its
//! [`BeaconCert::Genesis`](hyperscale_types::BeaconCert) `config_hash`
//! matches `expected_config_hash` — a tripwire against booting a
//! validator off a chain initialised by a different operator TOML.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{
    Action, FetchAbandon, FetchRequest, KeepDelta, ObserveDelta, ParticipationChange, TimerId,
};
use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, BeaconCert, BeaconProposal, BeaconProposalVerifyContext,
    BeaconState, BlockHash, BlockHeight, Bls12381G1PublicKey, CandidateBeaconBlock,
    CandidateBeaconBlockVerifyError, CertifiedBeaconBlock, CertifiedBeaconBlockVerifyError,
    CertifiedBlockHeader, Epoch, GenesisConfigHash, JailReason, LeafIndex, LocalTimestamp,
    MAX_EQUIVOCATIONS_PER_PROPOSER, MAX_WITNESSES_PER_FETCH, NetworkDefinition, PcValueElement,
    PcVector, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3,
    PcVote3VerifyError, PcVoteEquivocation, PcVoteEquivocationContext, RATIFY_ROUND_TIMEOUT,
    RETENTION_HORIZON, RatifyCert, RatifyPhase, RatifyRound, RatifyVote, RatifyVoteRecord,
    RatifyVoteVerifyError, SKIP_TIMEOUT, SPC_INPUT_DWELL, SPC_VIEW_TIMEOUT, ShardCommittee,
    ShardId, ShardWitness, SlotEffects, SpcCert, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError,
    SpcNewCommitMsg, SpcNewCommitMsgVerifyError, SpcProposalObject, SpcProposalObjectVerifyError,
    SpcView, TopologySchedule, TopologySnapshot, ValidatorId, ValidatorStatus, Verifiable,
    Verified, Verify, WeightedTimestamp,
};
use tracing::{trace, warn};

use crate::commit_assembly::{AssemblyDecision, CommitAssembler};
use crate::equivocations::EquivocationObservations;
use crate::proposal_pool::BeaconProposalPool;
use crate::ratify::{RatifyEffect, RatifyTracker};
use crate::shard_source::ShardSourceTracker;
use crate::spc::SpcEffect;
use crate::spc_driver::SpcDriver;
use crate::state::{apply_epoch, apply_input_for};
use crate::verification::BeaconVerificationPipeline;
use crate::{boundary, rules};

/// How many times the view-1 input dwell re-arms while waiting for full
/// proposal coverage before giving up and feeding whatever is pooled.
///
/// The view-1 input is a positional vector — one slot per committee
/// member, the pooled proposal's hash or `BOTTOM` if absent — and the
/// inner PC runs prefix consensus over it. A vector that diverges across
/// honest nodes (different members pooled different proposal subsets at
/// feed time) collapses to a short or empty maximum-common-prefix: a
/// disagreement at slot `k` discards every slot from `k` on, so an
/// inconsistently-pooled low-slot proposal can drive the whole commit to
/// empty. Feeding only at full coverage makes honest nodes feed the same
/// vector. The cap bounds the wait: once it elapses, a still-missing
/// proposal is from a member no node holds, so every node feeds the same
/// partial vector and the epoch still makes progress. At
/// [`SPC_INPUT_DWELL`] per re-arm this is a few seconds — negligible
/// against the epoch, comfortably inside [`SPC_VIEW_TIMEOUT`].
const MAX_INPUT_DWELL_REARMS: u32 = 6;

/// Oldest epoch the topology schedule must retain — the minimum of the
/// consumer frontiers that still verify QC-bearing artifacts:
///
/// - the local shard chain's committee anchor (`local_frontier`, the
///   committed tip's parent-QC weighted timestamp): live votes/headers and
///   synced blocks all key their schedule lookups at or after it;
/// - each shard's last live boundary epoch, minus one window of slack (a
///   boundary block is signed by the committee at its *parent* QC's weighted
///   timestamp, which can land one window earlier): the next legitimate
///   boundary QC or remote header from a stalled shard is signed no earlier;
/// - the tx-artifact horizon (`now − RETENTION_HORIZON`): provisions and
///   execution certificates are provably terminal past it.
///
/// Clamped to `state.current_epoch` so the head entry always survives.
/// Anything attested below the floor is provably bogus or provably
/// terminal, so a schedule miss below it is rejectable, never deferrable.
///
/// Human-readable discriminator for a block's authenticating cert,
/// for diagnostics.
const fn cert_kind(cert: &BeaconCert) -> &'static str {
    match cert {
        BeaconCert::Genesis(_) => "genesis",
        BeaconCert::Normal { .. } => "normal",
        BeaconCert::Skip(_) => "skip",
    }
}

/// **Not consensus-critical**: the floor bounds a node-local cache; nodes
/// with different frontiers produce the same chain.
#[must_use]
pub fn retention_floor(
    state: &BeaconState,
    local_frontier: WeightedTimestamp,
    now: LocalTimestamp,
) -> Epoch {
    let windows = state.chain_config.epoch_windows();
    let local_chain = windows.epoch_for(local_frontier);
    let shard_boundaries = state
        .shard_committees
        .keys()
        .map(|shard| {
            state.boundaries.get(shard).map_or(Epoch::GENESIS, |b| {
                Epoch::new(b.last_live_epoch.inner().saturating_sub(1))
            })
        })
        // A reshape predecessor dropped from the live committees keeps a
        // lingering terminal boundary record so straggling observers can
        // snap-sync its anchor and the coasting predecessor can resolve its
        // own committee. Its schedule window must outlive the record, or the
        // floor rises the instant the successors advance — a beat before the
        // predecessor observes successor-live and stops coasting — and evicts
        // the window mid-handoff. Folding terminal records in holds the window
        // exactly as long as the record lives.
        .chain(
            state
                .boundaries
                .values()
                .filter(|b| b.terminal_epoch.is_some())
                .map(|b| Epoch::new(b.last_live_epoch.inner().saturating_sub(1))),
        )
        .min()
        .unwrap_or(Epoch::GENESIS);
    let horizon = windows.epoch_for(WeightedTimestamp::from_millis(
        now.as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000),
    ));
    local_chain
        .min(shard_boundaries)
        .min(horizon)
        .min(state.current_epoch)
}

/// Per-vnode beacon-chain coordinator.
///
/// Synchronous event-driven FSM. Mirrors `ShardCoordinator`'s public
/// shape: handlers take `&mut self` plus a per-call
/// `&TopologySnapshot` and return `Vec<Action>`. Multiple vnodes
/// share an `Arc<dyn BeaconStorage>` at the runner layer but each
/// holds an independent coordinator, so determinism is per-vnode.
pub struct BeaconCoordinator {
    state: BeaconState,

    /// Latest committed beacon block paired with its authenticating
    /// cert. Carried so SPC instance bootstrap and ratify anchor
    /// checks read `prev_block_hash` without a storage roundtrip.
    latest_block: Arc<Verified<CertifiedBeaconBlock>>,

    /// Beacon committee that governed the tip epoch, captured before
    /// its fold advanced the state. A competing block for the adopted
    /// epoch verifies against the sets that governed it, not the sets
    /// the fold derived from it — the current state's committee may
    /// have rotated. On a restart the constructor recovers this from
    /// the penultimate history state when one is loaded; otherwise the
    /// live state stands in until the next commit.
    tip_epoch_committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    /// Active pool that governed the tip epoch — the signer base for a
    /// competing block's ratify cert. Same capture discipline as
    /// `tip_epoch_committee`.
    tip_epoch_pool: Vec<(ValidatorId, Bls12381G1PublicKey)>,

    /// SPC consensus-plane driver: the optional current-epoch instance
    /// plus the PC-vote and SPC-message verification slot pools. Bare
    /// between bootstrap and the first epoch-boundary trigger, and again
    /// briefly between an epoch's commit and the next bootstrap.
    spc: SpcDriver,

    /// In-flight slot tracking for the async crypto checks the coordinator
    /// owns (block cert sigs + skip-request sigs). Dedup-only — the payload
    /// rides through the dispatch/result round-trip in the action and
    /// event themselves, not stashed here.
    verification: BeaconVerificationPipeline,

    /// Per-shard header records, validated-witness pool, and
    /// in-flight fetches; drives proposal-readiness and the
    /// witness drain.
    shard_source: ShardSourceTracker,

    /// Ratification state for the pending epoch at the current tip:
    /// rounds, own-vote registers, locks, pooled votes, and
    /// commit-cert assembly. Rebuilt on every adoption for the new
    /// `(anchor, epoch)`.
    ratify: RatifyTracker,

    /// The verified SPC candidate awaiting ratification, held so the
    /// commit certificate can pair with the block it names. First
    /// verified candidate wins; reset on every adoption. A replica
    /// whose cert names a hash it never held adopts from the
    /// assembler's certified-block broadcast instead.
    pending_candidate: Option<Arc<Verified<CandidateBeaconBlock>>>,

    /// Equivocation evidence the local vnode has observed but not
    /// yet proposed for inclusion.
    equivocations: EquivocationObservations,

    /// Per-epoch cache of committee members' `BeaconProposal`s.
    /// Scoped to the in-flight epoch (`state.current_epoch.next()`);
    /// reset on commit. Vnode-local — inbound fetch serving reads the
    /// driver's process-level cache, never this pool.
    proposal_pool: BeaconProposalPool,

    /// Committee members whose in-flight-epoch `BeaconProposal` this
    /// vnode has already run the witness-admission gate over, regardless
    /// of outcome. Bounds the per-epoch verification work to one
    /// evaluation per committee member so a peer flooding distinct
    /// forged proposals can't force unbounded BLS/merkle checks. Cleared
    /// on `adopt_block` alongside the proposal-pool reset.
    evaluated_proposers: BTreeSet<ValidatorId>,

    /// Commit-assembly sub-machine. Stashes SPC-decided epochs whose
    /// committed proposals reference a `BeaconProposal` the local pool
    /// hasn't observed, tracks the fetches that resolve them, and decides
    /// when assembly is ready. `adopt_block` advancing `current_epoch`
    /// past a stash evicts it via `prune_stale`, whose returned ids the
    /// coordinator turns into [`FetchAbandon::BeaconProposal`].
    commit_assembly: CommitAssembler,

    /// Per-epoch committee schedule. Its head is the current epoch's
    /// committee (refreshed on every `adopt_block` so consumers reading via
    /// `io_loop`'s `ArcSwap` see the post-`apply_epoch` placement immediately
    /// after commit); its `at` resolves any artifact's committee by weighted
    /// timestamp over the window from [`retention_floor`] through
    /// `current_epoch + 1`. The `+1` lookahead entry is finalized an epoch
    /// before its window opens. A node-local cache, not consensus-critical.
    topology_schedule: TopologySchedule,

    /// Committee anchor of the local shard's committed tip — its parent QC's
    /// weighted timestamp. The oldest anchor the local chain can still key a
    /// schedule lookup on; holds [`retention_floor`] open while the shard
    /// chain verifies blocks older than the beacon head (catch-up after
    /// downtime, resume after a stall). Seeded at construction from the
    /// recovered tip; advances on every local commit via
    /// [`on_local_block_committed`](Self::on_local_block_committed).
    local_frontier: WeightedTimestamp,

    me: ValidatorId,

    /// Shard the host vnode belongs to. Beacon is process-wide
    /// consensus, but the coordinator stamps fetch requests with the
    /// dispatching vnode's shard so the runner's network adapter has a
    /// committee handle for peer selection.
    local_shard: ShardId,

    /// Mixed into every signing helper's domain bytes; carried so
    /// per-epoch SPC instances and outbound canonical-bytes
    /// encoders don't re-thread it from the runner.
    network: NetworkDefinition,

    /// Local wall-clock time. Drives the epoch-cadence timers; never
    /// fed into deterministic consensus computations — use
    /// `state.current_epoch` or weighted timestamps for that.
    now: LocalTimestamp,

    /// How many times the view-1 input dwell has re-armed for the
    /// in-flight epoch while waiting for full proposal coverage. Reset
    /// to zero at each SPC bootstrap; capped at
    /// [`MAX_INPUT_DWELL_REARMS`]. The dwell waits for *every* committee
    /// member's proposal before feeding so honest nodes feed the same
    /// view-1 vector — a partial vector diverges across nodes and the
    /// inner PC's prefix consensus collapses it to an empty commit. The
    /// cap bounds the wait so a genuinely-absent member (whose proposal
    /// no node holds, so all feed the same partial vector) still lets the
    /// epoch make progress.
    input_dwell_rearms: u32,
}

impl BeaconCoordinator {
    /// Construct a coordinator from `latest_block` and a `history` of
    /// recently-committed states (newest last; `history.last()` becomes
    /// the live state). Each state seeds the topology schedule with its
    /// active and lookahead snapshots, so the coordinator boots able to
    /// verify cross-shard artifacts back across the loaded window.
    /// `local_frontier` is the local shard chain's recovered committee
    /// anchor (`RecoveredState::committee_anchor_ts`); it seeds the
    /// schedule's eviction floor and advances via
    /// [`on_local_block_committed`](Self::on_local_block_committed) as the
    /// chain commits. When `latest_block` is genesis, debug-asserts its cert's
    /// `config_hash` matches `expected_config_hash` — catches a runner
    /// that loaded a chain initialised by a different operator TOML than
    /// this process is configured for.
    ///
    /// # Panics
    ///
    /// Panics if `history` is empty. In debug builds, also panics if
    /// `latest_block.is_genesis()` and the cert's `config_hash` doesn't
    /// match `expected_config_hash`.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // identity + storage state both threaded explicitly
    pub fn new(
        latest_block: Arc<Verified<CertifiedBeaconBlock>>,
        history: Vec<BeaconState>,
        me: ValidatorId,
        local_shard: ShardId,
        local_frontier: WeightedTimestamp,
        network: NetworkDefinition,
        expected_config_hash: GenesisConfigHash,
    ) -> Self {
        const LATEST_STATE_EXPECT: &str = "history must carry at least the latest committed state";
        if let BeaconCert::Genesis(config_hash) = latest_block.cert() {
            debug_assert_eq!(
                *config_hash, expected_config_hash,
                "genesis block config_hash doesn't match operator config",
            );
        }
        let latest = history.last().expect(LATEST_STATE_EXPECT);
        let latest_epoch = latest.current_epoch;
        let epoch_duration_ms = latest.chain_config.epoch_duration_ms;
        // The head and the latest epoch's active committee are the same
        // snapshot; derive it once and let the schedule share the handle.
        // Seed every other loaded state's active committee under its own epoch
        // and its lookahead under the next, skipping anything that targets
        // `latest_epoch` so the shared head stays in place. Consecutive states
        // agree on that boundary entry (one's lookahead is the next's active),
        // so the skip drops only a redundant re-derivation.
        let head = Arc::new(latest.derive_topology_snapshot(network.clone()));
        let mut topology_schedule =
            TopologySchedule::new(epoch_duration_ms, latest_epoch, Arc::clone(&head));
        for state in &history {
            if state.current_epoch != latest_epoch {
                topology_schedule.insert(
                    state.current_epoch,
                    Arc::new(state.derive_topology_snapshot(network.clone())),
                );
            }
            let lookahead = state.current_epoch.next();
            if lookahead != latest_epoch {
                topology_schedule.insert(
                    lookahead,
                    Arc::new(state.derive_next_topology_snapshot(network.clone())),
                );
            }
        }
        // The tip epoch's signer sets come from the state *before* its
        // fold when the loaded history carries one; the live state
        // stands in otherwise (see the field docs).
        let tip_epoch_source = if history.len() >= 2 {
            &history[history.len() - 2]
        } else {
            latest
        };
        let tip_epoch_committee = tip_epoch_source.derive_beacon_committee();
        let tip_epoch_pool = tip_epoch_source.derive_active_pool();
        let state = history.into_iter().next_back().expect(LATEST_STATE_EXPECT);
        // The pending epoch's ratification runs over the pool the live
        // (post-fold) state derives — the signer base every candidate
        // outcome at this tip shares.
        let ratify = RatifyTracker::new(
            latest_block.block_hash(),
            state.current_epoch.next(),
            state.derive_active_pool(),
        );
        Self {
            state,
            latest_block,
            tip_epoch_committee,
            tip_epoch_pool,
            spc: SpcDriver::new(me),
            verification: BeaconVerificationPipeline::new(),
            shard_source: ShardSourceTracker::new(),
            ratify,
            pending_candidate: None,
            equivocations: EquivocationObservations::new(),
            proposal_pool: BeaconProposalPool::new(latest_epoch.next()),
            evaluated_proposers: BTreeSet::new(),
            commit_assembly: CommitAssembler::new(),
            local_shard,
            topology_schedule,
            local_frontier,
            me,
            network,
            now: LocalTimestamp::ZERO,
            input_dwell_rearms: 0,
        }
    }

    /// Install the durable ratification record a restart recovered —
    /// see [`RatifyTracker::install_recovered_record`]. Call once,
    /// right after construction, before any input is processed; a
    /// record for a different epoch than the pending ratification is
    /// ignored.
    pub fn install_recovered_ratify_record(&mut self, record: &RatifyVoteRecord) {
        self.ratify.install_recovered_record(record);
    }

    /// Whether the local validator sits on the current beacon
    /// committee. The runner gates committee-only event forwarding
    /// (PC votes, SPC messages) on this.
    #[must_use]
    pub fn is_on_committee(&self) -> bool {
        self.state.committee.contains(&self.me)
    }

    /// Runner calls this once before each batch of handler invocations
    /// so every handler in the batch reads a consistent `now`.
    pub const fn set_now(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Hash of the verified candidate held for the pending epoch, if
    /// any.
    #[must_use]
    pub fn pending_candidate_hash(&self) -> Option<BeaconBlockHash> {
        self.pending_candidate.as_ref().map(|c| c.block_hash())
    }

    /// Local shard block committed — advance the chain's committee anchor to
    /// the new tip's parent-QC weighted timestamp, the node-local frontier
    /// [`retention_floor`] keeps the schedule open for.
    pub const fn on_local_block_committed(&mut self, anchor_ts: WeightedTimestamp) {
        self.local_frontier = anchor_ts;
    }

    /// Schedule the first `BeaconCommitteeStart` timer so the upcoming
    /// epoch's SPC instance bootstraps. Subsequent epochs self-arm via
    /// `adopt_block`'s direct `bootstrap_spc_for_next_epoch` +
    /// `try_propose` call; this only covers the resume gap from a
    /// freshly-constructed or just-loaded coordinator.
    ///
    /// Fires at the next epoch's wall-clock boundary
    /// (`next_epoch × chain_config.epoch_duration`), or immediately if
    /// `now` is already past it. Tests that want fast beacon kickoff
    /// override `chain_config.epoch_duration_ms` in the genesis config.
    #[must_use]
    pub fn on_startup(&self) -> Vec<Action> {
        vec![
            Action::SetTimer {
                id: TimerId::BeaconCommitteeStart,
                duration: self.duration_until_next_epoch_boundary(),
            },
            Action::SetTimer {
                id: TimerId::BeaconRatifyTrigger,
                duration: self.duration_until_next_ratify_fire(),
            },
        ]
    }

    /// Wall-clock boundary of the upcoming epoch — the close of the current
    /// epoch's window. The beacon starts the next epoch's SPC only once `now`
    /// reaches this, so its synthetic per-epoch clock tracks wall-clock
    /// instead of racing ahead at SPC-round speed. The window's weighted-time
    /// cut is the same instant on this validator's local clock — the synthetic
    /// beacon clock is anchored to `epoch × epoch_duration_ms`.
    const fn next_epoch_boundary(&self) -> LocalTimestamp {
        let cut = self
            .state
            .chain_config
            .epoch_windows()
            .window_of(self.state.current_epoch)
            .end;
        LocalTimestamp::from_millis(cut.as_millis())
    }

    /// Wall-clock duration from `now` to [`Self::next_epoch_boundary`].
    /// Saturates to zero if `now` is already past the boundary.
    const fn duration_until_next_epoch_boundary(&self) -> Duration {
        Duration::from_millis(
            self.next_epoch_boundary()
                .as_millis()
                .saturating_sub(self.now.as_millis()),
        )
    }

    /// Whether the committee-start timer is due — i.e. wall-clock time has
    /// reached the upcoming epoch's boundary. Gates both the initial
    /// `BeaconCommitteeStart` timer and the per-commit self-perpetuation in
    /// [`Self::adopt_block`], so the beacon catches up to wall-clock and then
    /// paces to it rather than cascading ahead.
    #[must_use]
    pub const fn committee_start_due(&self, epoch_boundary: LocalTimestamp) -> bool {
        self.now.as_millis() >= epoch_boundary.as_millis()
    }

    /// How long the pool waits past an epoch's expected block time before
    /// a member prevotes the canonical skip hash.
    ///
    /// [`SKIP_TIMEOUT`] is sized for the 5-minute production epoch (a small
    /// fraction of it). Clamped into `[SPC_VIEW_TIMEOUT, SKIP_TIMEOUT]` against
    /// `epoch_duration`:
    ///
    /// - The upper clamp at the epoch keeps a genuinely dead epoch (no proposer
    ///   the committee can rally behind) carried within ~one epoch — inside the
    ///   schedule's `L=1` lookahead — at a faster sim epoch, instead of
    ///   cascading many epochs behind.
    /// - The lower clamp at [`SPC_VIEW_TIMEOUT`](hyperscale_types::SPC_VIEW_TIMEOUT)
    ///   keeps the skip above one SPC view change at every epoch length, so a
    ///   single down proposer rotates to the next proposer (a real block)
    ///   rather than skipping, and the skip never pre-empts a healthy commit at
    ///   an epoch shorter than the consensus floor.
    ///
    /// Consensus-critical, but `epoch_duration_ms` rides in the shared genesis
    /// config, so every validator derives the same instant.
    fn skip_timeout(&self) -> Duration {
        Duration::from_millis(self.state.chain_config.epoch_duration_ms)
            .clamp(SPC_VIEW_TIMEOUT, SKIP_TIMEOUT)
    }

    /// Whether the skip-trigger timer is due — i.e. wall-clock time
    /// has reached `expected_block_time + skip_timeout`. The
    /// runner combines this with its own "expected block hasn't
    /// arrived" + "local on active pool" checks before actually
    /// prevoting the skip hash.
    #[must_use]
    pub fn skip_trigger_due(&self, expected_block_time: LocalTimestamp) -> bool {
        self.now.as_millis() >= expected_block_time.plus(self.skip_timeout()).as_millis()
    }

    /// The ratify round the wall clock says the pool should be in:
    /// elapsed time past the skip deadline divided by the round
    /// timeout, starting from the round after [`RatifyRound::INITIAL`].
    /// Every pool member reads the same deadline off its own beacon
    /// fold, so members converge on one round despite timer jitter.
    fn wall_clock_ratify_round(&self) -> RatifyRound {
        let deadline = self
            .next_epoch_boundary()
            .plus(self.skip_timeout())
            .as_millis();
        let elapsed = self.now.as_millis().saturating_sub(deadline);
        let timeout_ms: u128 = RATIFY_ROUND_TIMEOUT.as_millis();
        let rounds = u32::try_from(u128::from(elapsed) / timeout_ms).unwrap_or(u32::MAX);
        RatifyRound::new(RatifyRound::INITIAL.inner().saturating_add(rounds))
    }

    /// Duration until the next ratify fire: the epoch's skip deadline,
    /// then each round boundary after it — the same shared schedule
    /// [`Self::wall_clock_ratify_round`] reads, so the timer fires at
    /// the instant the wall-clock round changes. Arming at boundaries
    /// rather than a fixed interval from the previous fire means every
    /// pool member enters a round at the same moment and its votes get
    /// the round's whole window to propagate. A member firing late in
    /// the window casts votes that complete its peers' polkas one round
    /// behind, where they are no longer precommittable — at exact pool
    /// quorum, one such member starves certificate assembly entirely.
    fn duration_until_next_ratify_fire(&self) -> Duration {
        let now = self.now.as_millis();
        let deadline = self
            .next_epoch_boundary()
            .plus(self.skip_timeout())
            .as_millis();
        if now < deadline {
            return Duration::from_millis(deadline - now);
        }
        let timeout_ms = u64::try_from(RATIFY_ROUND_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        let past_boundary = (now - deadline) % timeout_ms;
        Duration::from_millis(timeout_ms - past_boundary)
    }

    /// `TimerId::BeaconRatifyTrigger` fired. The first fire past the
    /// pending epoch's deadline makes the skip hash prevotable (the
    /// expected block didn't commit in time); each subsequent fire is a
    /// round timeout that re-prevotes per the tracker's lock rule. The
    /// timer re-arms at the next round boundary
    /// ([`Self::duration_until_next_ratify_fire`]) while the epoch is
    /// undecided.
    ///
    /// The deadline is re-validated at fire time because votes are
    /// built from the *current* tip and epoch: a fire armed against an
    /// older tip looks fresh once the chain advances, and voting on it
    /// would target an epoch whose window may not even have opened.
    /// Re-checking makes any stale or early fire harmless.
    pub fn on_beacon_ratify_timer(&mut self) -> Vec<Action> {
        if !self.skip_trigger_due(self.next_epoch_boundary()) {
            // An early fire must re-arm or this validator's skip
            // machinery dies with the timer chain: the initial arm can
            // land marginally before the deadline on a wall-clock
            // harness, and without a follow-up fire the epoch's skip
            // rounds never start here — starving the pool quorum that
            // an epoch stalled below SPC quorum needs to resume.
            // Re-arming at the boundary fires again at the deadline
            // itself, keeping this member's rounds in step with the
            // pool rather than a full round window late.
            return vec![Action::SetTimer {
                id: TimerId::BeaconRatifyTrigger,
                duration: self.duration_until_next_ratify_fire(),
            }];
        }
        if self.ratify.is_completed() {
            return Vec::new();
        }
        let effects = if self.ratify.deadline_passed() {
            self.ratify.on_round_timeout(self.wall_clock_ratify_round())
        } else {
            self.ratify.on_deadline()
        };
        let mut actions = self.lift_ratify_effects(effects);
        actions.push(Action::SetTimer {
            id: TimerId::BeaconRatifyTrigger,
            duration: self.duration_until_next_ratify_fire(),
        });
        actions
    }

    /// Lift the tracker's typed effects into actions: sign intents
    /// become signing dispatches (pool members only — the tracker
    /// tracks votes on every node, but only pool members contribute
    /// signatures), and an assembled commit certificate becomes the
    /// epoch's block.
    fn lift_ratify_effects(&mut self, effects: Vec<RatifyEffect>) -> Vec<Action> {
        let mut actions = Vec::new();
        for effect in effects {
            match effect {
                RatifyEffect::SignPrevote { round, block_hash } => {
                    actions.extend(self.ratify_sign_action(
                        round,
                        RatifyPhase::Prevote,
                        block_hash,
                    ));
                }
                RatifyEffect::SignPrecommit { round, block_hash } => {
                    actions.extend(self.ratify_sign_action(
                        round,
                        RatifyPhase::Precommit,
                        block_hash,
                    ));
                }
                RatifyEffect::CertAssembled { cert } => {
                    actions.extend(self.commit_ratified_block(*cert));
                }
            }
        }
        actions
    }

    fn ratify_sign_action(
        &self,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Option<Action> {
        if !self.ratify.pool_contains(self.me) {
            return None;
        }
        Some(Action::SignAndBroadcastRatifyVote {
            anchor: self.latest_block.block_hash(),
            epoch: self.state.current_epoch.next(),
            round,
            phase,
            block_hash,
        })
    }

    /// A peer's round-1 PC vote arrived. Gate, dedup, and dispatch the
    /// BLS check via the [`SpcDriver`]. Admission happens in
    /// [`Self::on_pc_vote1_verified`] when the result lands.
    pub fn on_pc_vote1_received(&mut self, view: SpcView, vote: PcVote1) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote1_received(view, vote, skip)
    }

    /// A peer's round-2 PC vote arrived.
    pub fn on_pc_vote2_received(&mut self, view: SpcView, vote: Box<PcVote2>) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote2_received(view, vote, skip)
    }

    /// A peer's round-3 PC vote arrived.
    pub fn on_pc_vote3_received(&mut self, view: SpcView, vote: Box<PcVote3>) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote3_received(view, vote, skip)
    }

    /// A peer's SPC `new-view` arrived. Gate on instance/skip-quorum,
    /// mark the slot in-flight, and dispatch the cert BLS check to the
    /// crypto pool. Admission happens in [`Self::on_spc_new_view_verified`]
    /// when the result lands.
    pub fn on_spc_new_view_received(
        &mut self,
        from: ValidatorId,
        proposal: Arc<Verifiable<SpcProposalObject>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_spc_new_view_received(from, proposal, skip)
    }

    /// A peer's SPC `new-commit` arrived.
    pub fn on_spc_new_commit_received(
        &mut self,
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_spc_new_commit_received(from, msg, skip)
    }

    /// A peer's SPC `empty-view` attestation arrived.
    pub fn on_unverified_spc_empty_view_received(
        &mut self,
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_unverified_spc_empty_view_received(msg, skip)
    }

    /// A locally-signed empty-view attestation arrived via the
    /// `Action::SignAndBroadcastEmptyView` self-loopback path — verified
    /// by construction, so it feeds the FSM directly.
    pub fn on_verified_spc_empty_view_received(
        &mut self,
        msg: Box<Verified<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_verified_spc_empty_view_received(msg, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifySpcNewView`] dispatch.
    pub fn on_spc_new_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_new_view_verified(epoch, from, view, result, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifySpcNewCommit`] dispatch.
    pub fn on_spc_new_commit_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_new_commit_verified(epoch, from, view, result, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifySpcEmptyView`] dispatch.
    pub fn on_spc_empty_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_empty_view_verified(epoch, from, view, result, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifyPcVote1`] dispatch.
    pub fn on_pc_vote1_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote1_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifyPcVote2`] dispatch.
    pub fn on_pc_vote2_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote2_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(effects)
    }

    /// Result of an [`Action::VerifyPcVote3`] dispatch.
    pub fn on_pc_vote3_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote3_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(effects)
    }

    /// A round-1 PC vote the coordinator received already verified — fed
    /// in via the local sign-and-emit path. Routes straight into the FSM.
    pub fn on_verified_pc_vote1_received(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote1>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_verified_pc_vote1_received(view, vote, skip);
        self.lift_from_spc(effects)
    }

    /// A round-2 PC vote the coordinator received already verified.
    pub fn on_verified_pc_vote2_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote2>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_verified_pc_vote2_received(view, vote, skip);
        self.lift_from_spc(effects)
    }

    /// A round-3 PC vote the coordinator received already verified.
    pub fn on_verified_pc_vote3_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote3>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_verified_pc_vote3_received(view, vote, skip);
        self.lift_from_spc(effects)
    }

    /// `TimerId::BeaconSpcView` fired. Route a synthesized `TimerExpired`
    /// into the SPC instance against its current view.
    pub fn on_beacon_spc_view_timer(&mut self) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_beacon_spc_view_timer(skip);
        self.lift_from_spc(effects)
    }

    /// A peer committee member's `BeaconProposal` arrived. Admit it
    /// to the pool gated on committee membership at `epoch`. The
    /// `IoLoop` has already authenticated `from` and verified the
    /// proposal's VRF reveal against `(network.id, epoch)` under
    /// `from`'s pubkey, so admission here is a pure pool insert.
    ///
    /// Once a quorum (`2f+1`) of committee proposals — including the
    /// local one, which arrives back via the action handler's
    /// feedback — is pooled, this is the fast-path trigger that feeds
    /// SPC's view-1 PC instance: `compute_view_one_input` reads the
    /// pool's view of committee proposals and `SpcEvent::Input` kicks
    /// the FSM into outbound traffic. Quorum rather than full
    /// coverage keeps one faulty or lagging member from pushing every
    /// epoch onto the dwell timer; requiring the local proposal keeps
    /// a fast peer wave from feeding an input that omits it. The
    /// post-bootstrap dwell ([`Self::on_spc_input_dwell_timer`])
    /// covers the rest.
    pub fn on_beacon_proposal_received(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    ) -> Vec<Action> {
        if !self.state.committee.contains(&from) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                "BeaconProposalReceived from non-committee sender — dropping",
            );
            return Vec::new();
        }
        // Witness-admission gate. A peer's proposal only enters the pool —
        // and so only feeds this vnode's PC vote — once every embedded
        // witness positively verifies against locally-available state; the
        // pooled copy carries the upgraded `Verified` markers downstream.
        // Because SPC commits a value only on a 2f+1 quorum, gating the
        // vote means ≥ f+1 honest verifiers stand behind every committed
        // proposal, so an unverifiable witness can never reach the
        // committed `PcVector`; `apply_epoch` trusts what commits. Own
        // proposals are verified by construction (built from verified
        // votes and validated-pool witnesses) and skip the gate. The
        // per-epoch dedup bounds the work to one evaluation per sender so
        // a peer flooding distinct forged proposals can't force unbounded
        // verification.
        let proposal = if from == self.me {
            proposal
        } else {
            if epoch != self.proposal_pool.epoch() {
                trace!(
                    ?from,
                    epoch = epoch.inner(),
                    pool_epoch = self.proposal_pool.epoch().inner(),
                    "BeaconProposalReceived for a non-inflight epoch — dropping",
                );
                return Vec::new();
            }
            if !self.evaluated_proposers.insert(from) {
                return Vec::new();
            }
            let Some(upgraded) = self.upgrade_proposal_equivocations(&proposal) else {
                trace!(
                    ?from,
                    epoch = epoch.inner(),
                    "BeaconProposalReceived carries unverifiable equivocation evidence — dropping",
                );
                return Vec::new();
            };
            if !boundary::proposal_boundary_qcs_admissible(
                &upgraded,
                &self.state,
                &self.shard_source,
                &self.topology_schedule,
                &self.network,
            ) {
                trace!(
                    ?from,
                    epoch = epoch.inner(),
                    "BeaconProposalReceived carries an unverifiable boundary QC — dropping",
                );
                return Vec::new();
            }
            Arc::new(upgraded)
        };
        if !self.proposal_pool.admit(from, epoch, proposal) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                pool_epoch = self.proposal_pool.epoch().inner(),
                "BeaconProposalReceived rejected — wrong epoch or duplicate sender",
            );
            return Vec::new();
        }
        if self.spc.should_feed_view_one_input(epoch) {
            let pooled = self
                .state
                .committee
                .iter()
                .filter(|member| self.proposal_pool.contains(**member))
                .count();
            // Feed the view-1 input only once every committee member's
            // proposal is pooled, so every honest node feeds the inner PC
            // the same positional vector. A partial vector diverges across
            // nodes and the prefix consensus collapses it (see
            // [`MAX_INPUT_DWELL_REARMS`]); the dwell handles a member whose
            // proposal never arrives.
            if pooled == self.state.committee.len() {
                return self.feed_view_one_input(epoch);
            }
        }
        Vec::new()
    }

    /// Verify the equivocation evidence embedded in `proposal` and
    /// return the proposal with each `Verifiable` marker upgraded in
    /// place, or `None` if any entry is unverifiable. An entry verifies
    /// when both BLS sigs check out under the named validator's pubkey
    /// (from `state.validators`); evidence naming an unknown validator
    /// is unverifiable. A forged sig can't be made to pass, so an honest
    /// node never votes for it. The upgraded markers ride the pooled
    /// proposal through to `apply_epoch`.
    fn upgrade_proposal_equivocations(
        &self,
        proposal: &Verified<BeaconProposal>,
    ) -> Option<Verified<BeaconProposal>> {
        let mut equivocations = Vec::with_capacity(proposal.equivocations().len());
        for ev in proposal.equivocations().iter() {
            let rec = self.state.validators.get(&ev.validator)?;
            let mut ev = ev.clone();
            ev.upgrade_in_place(&PcVoteEquivocationContext {
                network: &self.network,
                committee: &[(ev.validator, rec.pubkey)],
            })
            .ok()?;
            equivocations.push(ev);
        }
        proposal
            .clone()
            .with_verified_equivocations(equivocations.into())
            .ok()
    }

    /// Build view 1's local input vector from the current pool view and
    /// drive it into SPC. Caller gates on
    /// [`SpcDriver::should_feed_view_one_input`]; lifts the effects.
    fn feed_view_one_input(&mut self, epoch: Epoch) -> Vec<Action> {
        let input = self.compute_view_one_input(epoch);
        let effects = self.spc.feed_view_one_input(input);
        self.lift_from_spc(effects)
    }

    /// Build the PC input vector for view 1: one `PcValueElement` per
    /// committee position, the hashed proposal if we've seen it or
    /// [`PcValueElement::BOTTOM`] if not.
    fn compute_view_one_input(&self, epoch: Epoch) -> PcVector {
        let elements: Vec<PcValueElement> = self
            .state
            .committee
            .iter()
            .map(|id| {
                self.proposal_pool
                    .get(*id)
                    .map_or(PcValueElement::BOTTOM, |p| p.pc_element_hash(epoch))
            })
            .collect();
        PcVector::new(elements)
    }

    /// Local-proposal trigger: if the local validator is on the
    /// committee, an SPC instance is bootstrapped, and we haven't
    /// already proposed this epoch, emit
    /// [`Action::BuildAndBroadcastBeaconProposal`] so the action
    /// handler can VRF-sign and gossip. The signed proposal arrives
    /// back via `on_beacon_proposal_received` which feeds SPC's
    /// view-1 input.
    ///
    /// Proposal payload:
    /// - Per-shard boundary QCs from [`source_boundary_qcs`](Self::source_boundary_qcs),
    ///   each reported only for a shard whose witness chunk the proposer
    ///   can also supply (the witness-availability coupling).
    /// - Equivocations from [`drain_equivocations_for`](Self::drain_equivocations_for),
    ///   capped at [`MAX_EQUIVOCATIONS_PER_PROPOSER`] with overflow
    ///   re-recorded for the next epoch — each permanently jails its
    ///   target. Shard witnesses ride the boundary contributions, not the
    ///   proposal.
    pub fn try_propose(&mut self) -> Vec<Action> {
        if !self.spc.is_bootstrapped() {
            trace!("try_propose: no SPC instance — deferring");
            return Vec::new();
        }
        if !self.is_on_committee() {
            return Vec::new();
        }
        if self.proposal_pool.contains(self.me) {
            return Vec::new();
        }
        let epoch = self.proposal_pool.epoch();
        let recipients = self.spc_recipients();
        let boundary_qcs = boundary::source_boundary_qcs(&self.state, &self.shard_source);
        let equivocations = self.drain_equivocations_for();
        vec![Action::BuildAndBroadcastBeaconProposal {
            epoch,
            boundary_qcs,
            equivocations,
            recipients,
        }]
    }

    /// Drain observed equivocations for the next proposal, capped at
    /// [`MAX_EQUIVOCATIONS_PER_PROPOSER`]; overflow is re-recorded for a
    /// future epoch's drain rather than dropped.
    fn drain_equivocations_for(&mut self) -> Vec<PcVoteEquivocation> {
        let mut equivocations = self.equivocations.drain_for_proposal();
        for overflow in
            equivocations.split_off(equivocations.len().min(MAX_EQUIVOCATIONS_PER_PROPOSER))
        {
            self.equivocations.record_pc_equivocation(overflow);
        }
        equivocations
    }

    /// `TimerId::BeaconCommitteeStart` fired — the upcoming epoch's
    /// wall-clock boundary has been reached. If the local validator
    /// is on the next committee and no SPC instance is already
    /// running, bootstrap one and immediately invoke
    /// [`Self::try_propose`] so the local `BeaconProposal` enters
    /// the gossip + admission cycle.
    pub fn on_beacon_committee_start_timer(&mut self) -> Vec<Action> {
        if self.spc.is_bootstrapped() {
            trace!("BeaconCommitteeStart fired with SPC already running");
            return Vec::new();
        }
        if !self.is_on_committee() {
            trace!("BeaconCommitteeStart fired but local validator not on committee");
            return Vec::new();
        }
        let mut actions = self.bootstrap_spc_for_next_epoch();
        actions.extend(self.try_propose());
        actions
    }

    /// Stand up a fresh SPC instance for the upcoming epoch under the
    /// current beacon committee, derived from `state`.
    fn bootstrap_spc_for_next_epoch(&mut self) -> Vec<Action> {
        let committee = self.state.derive_beacon_committee();
        self.bootstrap_spc_with_committee(committee)
    }

    /// Stand up the per-epoch SPC instance for the next epoch from an
    /// explicit committee. The BFT-minimum gate (declining the bootstrap
    /// when the committee can't tolerate a fault, so the skip path carries
    /// the epoch) lives in [`SpcDriver::bootstrap`].
    ///
    /// Arms the proposal-collection dwell: members bootstrap
    /// near-simultaneously at the epoch boundary, so the view-1 PC
    /// input must wait for peers' proposals to arrive — divergent
    /// positional inputs collapse the prefix consensus. The
    /// full-coverage fast path in [`Self::on_beacon_proposal_received`]
    /// feeds the instant every proposal is pooled; the dwell re-arms to
    /// give a laggard time and only feeds a partial vector once
    /// [`MAX_INPUT_DWELL_REARMS`] elapse.
    fn bootstrap_spc_with_committee(
        &mut self,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Vec<Action> {
        self.spc
            .bootstrap(self.state.current_epoch.next(), committee);
        self.input_dwell_rearms = 0;
        vec![Action::SetTimer {
            id: TimerId::BeaconSpcInputDwell,
            duration: SPC_INPUT_DWELL,
        }]
    }

    /// `TimerId::BeaconSpcInputDwell` fired: the proposal-collection
    /// dwell elapsed. Feed the view-1 input once every committee
    /// member's proposal is pooled; otherwise re-arm the dwell to give a
    /// laggard more time, up to [`MAX_INPUT_DWELL_REARMS`] re-arms — only
    /// then feed whatever is pooled. Waiting for full coverage keeps
    /// honest nodes feeding the same positional vector; a partial vector
    /// diverges and the inner PC's prefix consensus collapses it to an
    /// empty commit. A no-op when the fast path already fed it, or when
    /// no instance is up (off-committee, or the epoch already adopted).
    pub fn on_spc_input_dwell_timer(&mut self) -> Vec<Action> {
        let epoch = self.state.current_epoch.next();
        if !self.spc.should_feed_view_one_input(epoch) {
            return Vec::new();
        }
        let pooled = self
            .state
            .committee
            .iter()
            .filter(|member| self.proposal_pool.contains(**member))
            .count();
        if pooled < self.state.committee.len() && self.input_dwell_rearms < MAX_INPUT_DWELL_REARMS {
            self.input_dwell_rearms += 1;
            return vec![Action::SetTimer {
                id: TimerId::BeaconSpcInputDwell,
                duration: SPC_INPUT_DWELL,
            }];
        }
        self.feed_view_one_input(epoch)
    }

    /// Whether the pending epoch is already decided — a ratification
    /// commit certificate assembled at the local tip. Further PC/SPC
    /// crypto for the epoch is moot.
    const fn ratify_settled_at_tip(&self) -> bool {
        self.ratify.is_completed()
    }

    /// A peer-aggregated [`BeaconBlock`] arrived via the beacon gossip
    /// topic. After structural checks, dispatch cert verification to
    /// the crypto pool and stash the block until the result lands; on
    /// success [`Self::on_beacon_block_verified`] hands the verified
    /// block off to [`Self::adopt_block`]. A block more than one epoch
    /// ahead of the local tip is dropped and triggers gap-fill sync
    /// ([`Action::StartBeaconBlockSync`]) to fetch the missing epochs in
    /// order.
    ///
    /// Cert verification uses `self.state.committee` for Normal blocks
    /// and the active pool for Skip blocks. Committee rotation across
    /// epochs means an off-committee observer whose state has fallen
    /// behind the actual signing committee will reject otherwise-valid
    /// blocks. Resolving that without `apply_epoch` is a state-sync
    /// problem handled elsewhere.
    pub fn on_beacon_block_received(
        &mut self,
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
    ) -> Vec<Action> {
        let epoch = block.epoch();
        let tip_epoch = self.latest_block.epoch();
        if epoch <= tip_epoch {
            if let Some(actions) = self.tip_competitor_verification(&block) {
                return actions;
            }
            trace!(
                epoch = epoch.inner(),
                "BeaconBlockReceived for past/current epoch — dropping",
            );
            return Vec::new();
        }
        let expected_epoch = tip_epoch.next();
        if epoch > expected_epoch {
            trace!(
                epoch = epoch.inner(),
                expected = expected_epoch.inner(),
                "BeaconBlockReceived for future epoch — triggering sync",
            );
            // Drop the unverified block and let gap-fill sync fetch the
            // missing epochs in order from storage-backed peers. The
            // claimed epoch is only a target hint — the runner's sync
            // backs off on epochs that don't exist, so a bogus far-future
            // epoch can't busy-loop the network.
            return vec![Action::StartBeaconBlockSync { target: epoch }];
        }

        if block.prev_block_hash() != self.latest_block.block_hash() {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with mismatched prev_block_hash — dropping",
            );
            return Vec::new();
        }
        // Structural checks pass. The ratify cert's own anchor/epoch
        // binding to the block is the pairing invariant, enforced at
        // wire decode.
        if matches!(block.cert(), BeaconCert::Genesis(_)) {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with Genesis cert past tip — dropping",
            );
            return Vec::new();
        }
        let committee = self.state.derive_beacon_committee();
        let active_pool = self.state.derive_active_pool();
        let equivocation_signers = self.equivocation_signers_for(block.block());
        self.dispatch_block_verification(block, committee, active_pool, equivocation_signers)
    }

    /// Dispatch verification for a block that competes with the adopted
    /// tip: same epoch, same parent, different hash. A validly certified
    /// competitor is self-proving evidence of two ratification commit
    /// certificates for one epoch — more than a third of the pool
    /// double-signed — and [`Self::on_beacon_block_verified`] halts on
    /// it: the divergence is detected loudly rather than carried
    /// silently. Returns `None` when `block` is not a tip competitor
    /// (the caller's ordinary drop/sync handling applies).
    ///
    /// Verification runs against the signer sets that governed the tip
    /// epoch (`tip_epoch_committee` / `tip_epoch_pool`), captured at
    /// adoption — the live state's sets are post-fold.
    fn tip_competitor_verification(
        &mut self,
        block: &Arc<Verifiable<CertifiedBeaconBlock>>,
    ) -> Option<Vec<Action>> {
        if block.epoch() != self.latest_block.epoch()
            || block.epoch() == Epoch::GENESIS
            || block.prev_block_hash() != self.latest_block.prev_block_hash()
            || block.block_hash() == self.latest_block.block_hash()
            || matches!(block.cert(), BeaconCert::Genesis(_))
        {
            return None;
        }
        warn!(
            epoch = block.epoch().inner(),
            competitor = ?block.block_hash(),
            adopted = ?self.latest_block.block_hash(),
            "BeaconBlock competes with the adopted tip — dispatching cert verification",
        );
        let equivocation_signers = self.equivocation_signers_for(block.block());
        Some(self.dispatch_block_verification(
            Arc::clone(block),
            self.tip_epoch_committee.clone(),
            self.tip_epoch_pool.clone(),
            equivocation_signers,
        ))
    }

    /// Apply a beacon block delivered by the runner's gap-fill sync.
    ///
    /// The runner's beacon `Sync` machine fetches one epoch at a time
    /// and only advances once the prior block commits, so a delivered
    /// block is always at `epoch == tip + 1`. It therefore flows through
    /// the identical structural-check + cert-verification + adoption path
    /// as a gossiped block — verification (and the committed-proposal
    /// binding) is not bypassed.
    pub fn on_beacon_block_sync_ready_to_apply(
        &mut self,
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
    ) -> Vec<Action> {
        self.on_beacon_block_received(block)
    }

    /// Pubkey lookup covering every validator referenced by
    /// `PcVoteEquivocation` in `block`'s committed proposals.
    /// Returns an empty `Vec` when the block carries no equivocations —
    /// the common path. Validators referenced by evidence but missing
    /// from `state.validators` are silently elided; the verifier rejects
    /// such evidence at admission via the pubkey-lookup miss.
    fn equivocation_signers_for(
        &self,
        block: &BeaconBlock,
    ) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        let mut signers: Vec<(ValidatorId, Bls12381G1PublicKey)> = Vec::new();
        let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
        for (_, proposal) in block.committed_proposals() {
            for ev in proposal.equivocations().iter() {
                if seen.insert(ev.validator)
                    && let Some(rec) = self.state.validators.get(&ev.validator)
                {
                    signers.push((ev.validator, rec.pubkey));
                }
            }
        }
        signers
    }

    /// Dispatch a block's cert + equivocation verification. Returns a
    /// single [`Action::VerifyBeaconBlock`] on a fresh slot, or an empty
    /// vector when the slot is already in flight or already verified —
    /// the in-flight slot's result drives admission for any duplicate.
    fn dispatch_block_verification(
        &mut self,
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        active_pool: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        equivocation_signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Vec<Action> {
        if !self.verification.mark_block_in_flight(block.block_hash()) {
            return Vec::new();
        }
        vec![Action::VerifyBeaconBlock {
            block,
            committee,
            active_pool,
            equivocation_signers,
        }]
    }

    /// A peer's [`RatifyVote`] arrived via gossip. Validate the
    /// non-crypto fields and dispatch BLS verification to the crypto
    /// pool. Admission to the [`RatifyTracker`] happens in
    /// [`Self::on_ratify_vote_verified`] once the result lands; polka
    /// reactions, cert assembly, and adoption follow from there.
    ///
    /// Synchronous validation (before dispatch):
    /// - Anchor must equal `latest_block.block_hash()`. Votes pinning
    ///   a different anchor are stale or for a chain head we haven't
    ///   seen.
    /// - `epoch` must equal `current_epoch.next()` — the in-flight
    ///   epoch.
    /// - Signer must sit in the active-duty pool
    ///   ([`derive_active_pool`]); off-pool votes can't contribute to
    ///   quorum so the BLS check is pointless.
    ///
    /// No deadline gate: prevotes for the candidate are the happy path
    /// *before* the deadline. A premature skip-hash vote is harmless —
    /// the local tracker pools it, but the local validator's own votes
    /// (and the polkas they enable) still pace to the local clock.
    ///
    /// Async (on the crypto pool):
    /// - BLS sig verifies against the canonical
    ///   [`ratify_vote_message`](hyperscale_types::ratify_vote_message)
    ///   under the signer's pubkey.
    pub fn on_unverified_ratify_vote_received(
        &mut self,
        vote: Arc<Verifiable<RatifyVote>>,
    ) -> Vec<Action> {
        let expected_epoch = self.state.current_epoch.next();
        // A vote ratifying an epoch past the in-flight one means committed
        // beacon blocks exist that this replica never received. A stalled
        // epoch produces no new block gossip, so these votes are the only
        // traffic that reveals the gap — trigger gap-fill sync toward the
        // vote's anchor epoch. The target is a hint (mirrors
        // `on_beacon_block_received`): sync backs off on epochs nobody
        // serves, so a bogus far-future claim can't busy-loop the network.
        if vote.epoch() > expected_epoch {
            return vec![Action::StartBeaconBlockSync {
                target: vote.epoch().saturating_sub(1),
            }];
        }
        if vote.anchor_hash() != self.latest_block.block_hash() {
            trace!(
                signer = ?vote.signer(),
                "RatifyVote at unknown anchor — dropping",
            );
            return Vec::new();
        }
        if vote.epoch() != expected_epoch {
            trace!(
                signer = ?vote.signer(),
                epoch = vote.epoch().inner(),
                expected = expected_epoch.inner(),
                "RatifyVote at unexpected epoch — dropping",
            );
            return Vec::new();
        }
        if !self.ratify.pool_contains(vote.signer()) {
            trace!(
                signer = ?vote.signer(),
                "RatifyVote signer absent from active pool — dropping",
            );
            return Vec::new();
        }

        let key = (
            vote.anchor_hash(),
            vote.epoch(),
            vote.round(),
            vote.phase(),
            vote.signer(),
        );
        if !self.verification.mark_ratify_vote_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifyRatifyVote {
            vote: Box::new(Arc::unwrap_or_clone(vote)),
            signers: self.state.derive_active_pool(),
        }]
    }

    /// A locally-signed [`RatifyVote`] arrived via the
    /// `Action::SignAndBroadcastRatifyVote` self-loopback path. The
    /// signing validator produced the BLS sig, so the vote is verified
    /// by construction — skip the verify dispatch and pool directly.
    pub fn on_verified_ratify_vote_received(
        &mut self,
        vote: Arc<Verified<RatifyVote>>,
    ) -> Vec<Action> {
        self.admit_verified_ratify_vote(Arc::unwrap_or_clone(vote))
    }

    /// Build the block the commit certificate names, adopt it via the
    /// shared adoption path, and emit a broadcast so peers converge.
    ///
    /// The skip hash rebuilds the canonical skip block from the cert's
    /// own fields; the candidate hash pairs the held verified
    /// candidate with the cert. A cert naming a hash this replica
    /// never held commits nothing locally — the assembling peers
    /// broadcast the certified block and adoption follows from its
    /// receipt.
    fn commit_ratified_block(&mut self, cert: Verified<RatifyCert>) -> Vec<Action> {
        let block_hash = cert.block_hash();
        let certified = if block_hash == self.ratify.skip_block_hash() {
            let block = BeaconBlock::skip(cert.epoch(), cert.anchor_hash());
            Verified::<CertifiedBeaconBlock>::from_committed_assembly(
                block,
                BeaconCert::Skip(cert.into_inner()),
            )
            .expect("skip block pairs with its ratify cert by construction")
        } else if self
            .pending_candidate
            .as_ref()
            .is_some_and(|c| c.block_hash() == block_hash)
        {
            let candidate = self.pending_candidate.take().expect("checked above");
            Verified::<CertifiedBeaconBlock>::from_ratified_candidate(
                Arc::unwrap_or_clone(candidate),
                cert,
            )
            .expect("candidate pairs with its ratify cert by construction")
        } else {
            warn!(
                block_hash = ?block_hash,
                "Ratify cert names a candidate this replica never held — awaiting \
                 the assembler's certified block broadcast",
            );
            return Vec::new();
        };
        let block_arc = Arc::new(certified);

        let mut actions = self.adopt_block(Arc::clone(&block_arc));
        actions.push(Action::BroadcastBeaconBlock { block: block_arc });
        actions
    }

    /// A previously-dispatched [`Action::VerifyBeaconBlock`] has
    /// returned. Clear the pipeline slot, and on the `Ok` arm adopt
    /// the verified block (unless the tip has since moved past it).
    /// Drops silently on the `Err` arm.
    ///
    /// Stale or duplicate results (slot wasn't in flight) are
    /// tolerated.
    ///
    /// # Panics
    ///
    /// Panics when the verified block competes with the adopted tip —
    /// same epoch, same parent, different hash. Every block carries a
    /// pool ratify cert, so two validly certified blocks for one epoch
    /// mean intersecting pool signers equivocated; there is no
    /// reconciliation between the blocks, so the replica halts with
    /// the evidence rather than continuing on a forked beacon chain.
    pub fn on_beacon_block_verified(
        &mut self,
        result: Result<Arc<Verified<CertifiedBeaconBlock>>, CertifiedBeaconBlockVerifyError>,
    ) -> Vec<Action> {
        let block = match result {
            Ok(b) => b,
            Err(err) => {
                warn!(%err, "BeaconBlock cert verification failed — dropping");
                return Vec::new();
            }
        };
        let block_hash = block.block_hash();
        // A validly certified block for the adopted epoch, extending the
        // same parent, with a different hash: the ratify quorums behind
        // the two certs intersect, so some pool signers equivocated.
        // There is no reconciliation — every fact the fold derives
        // (committees, schedule, pricing) diverges from here — so halt
        // with the evidence rather than keep operating on a forked
        // beacon chain.
        if block.epoch() == self.latest_block.epoch()
            && block.epoch() > Epoch::GENESIS
            && block.prev_block_hash() == self.latest_block.prev_block_hash()
            && block_hash != self.latest_block.block_hash()
        {
            panic!(
                "beacon dual commit detected: epoch {} carries two validly certified blocks — \
                 adopted {:?} ({} cert) and competitor {:?} ({} cert) both extend {:?}; \
                 halting rather than continuing on a forked beacon chain",
                block.epoch().inner(),
                self.latest_block.block_hash(),
                cert_kind(self.latest_block.cert()),
                block_hash,
                cert_kind(block.cert()),
                block.prev_block_hash(),
            );
        }
        // Idempotency: another path (local ratify cert assembly, an
        // earlier peer-broadcast adoption) may have already advanced
        // the tip at or past this block's epoch. Re-entering
        // `adopt_block` would trip `apply_epoch`'s regression guard.
        if block.epoch() <= self.state.current_epoch
            || block.prev_block_hash() != self.latest_block.block_hash()
        {
            trace!(
                block_epoch = block.epoch().inner(),
                tip_epoch = self.state.current_epoch.inner(),
                "Verified BeaconBlock no longer chains off the tip — dropping",
            );
            return Vec::new();
        }
        // The SPC cert authenticates `committed_proposals`, not the
        // `shard_contributions` projected from them. Re-derive the
        // canonical projection and require the block to match it, so a
        // Byzantine assembler's variant (fabricated, stale, extra, or
        // omitted contribution) can't fork the boundary fold off the
        // committed inputs.
        if !rules::contributions_well_formed(&self.state, block.block()) {
            warn!(
                epoch = block.epoch().inner(),
                "Verified BeaconBlock has malformed shard contributions — dropping",
            );
            self.verification.forget_block(block_hash);
            return Vec::new();
        }
        self.verification.forget_block(block_hash);
        self.adopt_block(block)
    }

    /// A previously-dispatched [`Action::VerifyRatifyVote`] has
    /// returned. Clears the `(anchor, epoch, round, phase, signer)`
    /// pipeline slot on both arms — the key fields ride back in the
    /// result event so a verification failure can't pin a signer's
    /// slot in-flight and block their later honest vote — and on
    /// success pools the vote in the [`RatifyTracker`].
    pub fn on_ratify_vote_verified(
        &mut self,
        anchor: BeaconBlockHash,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        signer: ValidatorId,
        result: Result<Verified<RatifyVote>, RatifyVoteVerifyError>,
    ) -> Vec<Action> {
        let key = (anchor, epoch, round, phase, signer);
        let vote = match result {
            Ok(v) => v,
            Err(err) => {
                self.verification.forget_ratify_vote(key);
                warn!(%err, "RatifyVote BLS verification failed — dropping");
                return Vec::new();
            }
        };
        self.verification.forget_ratify_vote(key);
        self.admit_verified_ratify_vote(vote)
    }

    /// A [`RatifyVote`] has passed BLS verification: pool it and lift
    /// whatever it completes — a polka into the local precommit, a
    /// precommit quorum into the epoch's commit certificate.
    fn admit_verified_ratify_vote(&mut self, vote: Verified<RatifyVote>) -> Vec<Action> {
        // Tip may have advanced since dispatch; re-check the anchor +
        // epoch before admission so a stale verified vote can't pool
        // against the wrong instance.
        if vote.anchor_hash() != self.latest_block.block_hash()
            || vote.epoch() != self.state.current_epoch.next()
        {
            trace!(
                signer = ?vote.signer(),
                "Verified RatifyVote no longer matches tip — dropping",
            );
            return Vec::new();
        }
        let effects = self.ratify.observe(vote);
        self.lift_ratify_effects(effects)
    }

    /// A shard-witness fetch response arrived. For each witness:
    /// look up the source-shard committed block's
    /// `beacon_witness_root` via the local
    /// [`ShardSourceTracker`](crate::ShardSourceTracker)
    /// header records, verify Merkle inclusion under that root, and
    /// admit to the validated pool. Witnesses that fail any check are
    /// dropped silently; the fetch protocol retries on its own cadence.
    ///
    /// Off-committee vnodes don't initiate fetches, so this handler
    /// no-ops there — the pool is empty by design for those nodes.
    pub fn on_shard_witnesses_received(
        &mut self,
        shard_id: ShardId,
        witnesses: Vec<Arc<ShardWitness>>,
    ) -> Vec<Action> {
        if !self.is_on_committee() {
            return Vec::new();
        }
        for witness in witnesses {
            if witness.proof.shard_id != shard_id {
                warn!(
                    expected = ?shard_id,
                    got = ?witness.proof.shard_id,
                    "ShardWitness shard_id mismatches enclosing fetch response — dropping",
                );
                continue;
            }
            let Some(header) = self
                .shard_source
                .verified_header_by_block_hash(shard_id, witness.proof.committed_block_hash)
            else {
                warn!(
                    shard = ?shard_id,
                    "ShardWitness committed_block_hash has no verified header yet — dropping",
                );
                continue;
            };
            match witness.verify(header.as_ref()) {
                Ok(verified) => {
                    self.shard_source.admit_witness(Arc::new(verified));
                }
                Err(err) => {
                    warn!(
                        shard = ?shard_id,
                        leaf = witness.proof.leaf_index.inner(),
                        %err,
                        "ShardWitness verification failed — dropping",
                    );
                }
            }
        }
        // Pull the next gap now that this batch landed — a chunk wider than
        // one fetch completes across responses without waiting for the
        // shard's next source header (a terminated shard sends none).
        self.fetch_witness_chunk(shard_id)
    }

    /// Record a verified source-shard header — a remote shard's via the
    /// remote-header path, or the local shard's from its own commit
    /// stream — and note any epoch-boundary crossing it makes visible.
    /// Local-shard intake is what makes the shard's own boundary QCs
    /// verifiable at proposal admission (and reportable by local
    /// proposers): `boundary_qc_admissible` resolves headers from this
    /// view, and a validator is never on the remote path for its own
    /// shard. Off-committee vnodes retain the header
    /// (their inbound `BeaconBlock` verifier needs it to check witness
    /// merkle paths) and emit nothing. On-committee vnodes additionally
    /// fetch the witness chunk of the shard's latest observed crossing via
    /// [`fetch_witness_chunk`](Self::fetch_witness_chunk) — the leaves
    /// `[prior, chunk_end)` the boundary fold will apply next, anchored to
    /// the boundary block, bounded to [`MAX_WITNESSES_PER_FETCH`] leaves
    /// per call so a large producer/consumer gap can't make one header do
    /// unbounded work.
    pub fn on_verified_source_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        self.shard_source
            .on_verified_source_header(Arc::clone(certified_header));
        self.shard_source.observe_crossing(
            certified_header.header().shard_id(),
            certified_header.header().height(),
            self.state.chain_config.epoch_duration_ms,
        );
        if !self.is_on_committee() {
            return Vec::new();
        }
        self.fetch_witness_chunk(certified_header.header().shard_id())
    }

    /// Fetch the lowest still-missing leaves of `shard`'s current witness
    /// chunk, anchored to its latest observed crossing's boundary block.
    ///
    /// The anchor is the boundary block `B` (not whichever header just
    /// arrived): a witness proves against `B`'s `beacon_witness_root`, and
    /// the chunk is the leaves `[prior, chunk_end)` the boundary fold will
    /// apply next (`prior` = the applied watermark). At most
    /// [`MAX_WITNESSES_PER_FETCH`] leaves per call, taken from where the
    /// held leaves end rather than a fixed offset from `prior`: the chunk
    /// folds (advancing `prior`) only once every leaf is in hand, so a
    /// chunk wider than one fetch is pulled across successive calls, each
    /// re-issue — next observation, fetch response, or commit — picking up
    /// the next gap.
    fn fetch_witness_chunk(&mut self, shard: ShardId) -> Vec<Action> {
        let (anchor, block_height, prior, chunk_end) = {
            let Some(crossing) = self.shard_source.latest_crossing(shard) else {
                return Vec::new();
            };
            let boundary_header = crossing.boundary_header();
            let (prior, chunk_end) =
                rules::witness_chunk_bounds(&self.state, shard, boundary_header);
            (
                crossing.canonical_qc().block_hash(),
                boundary_header.height(),
                prior,
                chunk_end,
            )
        };
        let leaves_to_fetch: Vec<LeafIndex> = self
            .shard_source
            .missing_chunk_leaves(shard, anchor, prior, chunk_end)
            .into_iter()
            .take(MAX_WITNESSES_PER_FETCH)
            .collect();
        if leaves_to_fetch.is_empty() {
            return Vec::new();
        }
        // Re-send even leaves already marked in flight: a response that
        // never landed leaves a leaf pinned, and a chunk only folds once
        // every leaf is held. The batch advances as held leaves drop out
        // of `missing_chunk_leaves` on each re-issue.
        for &leaf in &leaves_to_fetch {
            self.shard_source
                .register_pending_fetch(shard, block_height, anchor, leaf);
        }
        vec![Action::Fetch(FetchRequest::ShardWitnesses {
            source_shard: shard,
            block_height,
            committed_block_hash: anchor,
            leaf_indices: leaves_to_fetch,
            preferred: None,
            class: None,
        })]
    }

    /// Re-issue witness-chunk fetches for terminated shards whose terminal
    /// crossing hasn't folded yet.
    ///
    /// [`fetch_witness_chunk`](Self::fetch_witness_chunk) is otherwise driven
    /// by source-header observation, and a terminated shard emits no new
    /// header — so its terminal chunk would stall mid-fetch. Re-issuing it
    /// each commit advances the chunk (and re-sends any leaf whose response
    /// never landed); once it folds, the boundary advances its watermark and
    /// the terminal record drops, ending the re-drive. The fold seeds a
    /// split's children or composes a merge's parent.
    fn redrive_terminal_witness_fetches(&mut self) -> Vec<Action> {
        if !self.is_on_committee() {
            return Vec::new();
        }
        // Collected up front: the loop body borrows `self` mutably through
        // `fetch_witness_chunk`, so it can't hold the `boundaries` iterator.
        let terminals: Vec<ShardId> = self
            .state
            .boundaries
            .iter()
            .filter(|(_, b)| b.terminal_epoch.is_some())
            .map(|(shard, _)| *shard)
            .collect();
        let mut actions = Vec::new();
        for shard in terminals {
            actions.extend(self.fetch_witness_chunk(shard));
        }
        actions
    }

    /// Advance `self.state` / `self.latest_block` to `block` after
    /// running `apply_epoch` over its committed proposals. Resets
    /// per-epoch caches, bootstraps next epoch's SPC if local is on
    /// the new committee. Emits `CommitBeaconBlock` only — no
    /// broadcast (caller decides whether the local node is the
    /// originator).
    /// The pending epoch is settled: ratification restarts for the
    /// next one at the new tip, over the post-fold pool.
    fn restart_ratification(&mut self) {
        self.ratify = RatifyTracker::new(
            self.latest_block.block_hash(),
            self.state.current_epoch.next(),
            self.state.derive_active_pool(),
        );
        self.pending_candidate = None;
    }

    fn adopt_block(&mut self, block: Arc<Verified<CertifiedBeaconBlock>>) -> Vec<Action> {
        let was_on_committee = self.is_on_committee();
        // The sets governing the epoch being adopted, captured before
        // its fold advances them — a competing block for this epoch
        // verifies against these.
        self.tip_epoch_committee = self.state.derive_beacon_committee();
        self.tip_epoch_pool = self.state.derive_active_pool();
        let input = apply_input_for(&block);
        let effects = apply_epoch(&mut self.state, &self.network, block.epoch(), input);
        self.latest_block = Arc::clone(&block);
        self.spc.clear();
        self.restart_ratification();

        // Evidence for a validator the fold now holds permanently jailed
        // is dead weight in future proposals — the jail can't be upgraded
        // further — so drop it from the local buffer.
        let validators = &self.state.validators;
        self.equivocations.prune(|v| {
            matches!(
                validators.get(&v).map(|r| r.status),
                Some(ValidatorStatus::Jailed {
                    reason: JailReason::Equivocation,
                    ..
                })
            )
        });

        // Refresh the head and record the active snapshot for the just-applied
        // epoch plus the lookahead for the next, then drop entries every
        // consumer frontier has passed. The lookahead entry lets a shard
        // resolve its committee a full epoch before its window opens.
        let head = Arc::new(self.state.derive_topology_snapshot(self.network.clone()));
        let epoch = self.state.current_epoch;
        self.topology_schedule.set_head(Arc::clone(&head));
        self.topology_schedule.insert(epoch, head);
        self.topology_schedule.insert(
            epoch.next(),
            Arc::new(
                self.state
                    .derive_next_topology_snapshot(self.network.clone()),
            ),
        );
        self.topology_schedule.evict_below(retention_floor(
            &self.state,
            self.local_frontier,
            self.now,
        ));

        // Evict witnesses the boundary fold has now consumed — those below
        // each shard's advanced applied watermark
        // (`boundaries[shard].witness_leaf_count`) — and bound the
        // verified-header maps to their sliding window.
        let consumed: Vec<(ShardId, u64)> = self
            .state
            .boundaries
            .iter()
            .map(|(shard, boundary)| (*shard, boundary.witness_leaf_count.inner()))
            .collect();
        let mut abandoned_witness_ids: Vec<(ShardId, BlockHeight, BlockHash, LeafIndex)> =
            Vec::new();
        for (shard, watermark) in consumed {
            abandoned_witness_ids.extend(self.shard_source.evict_consumed(shard, watermark));
        }
        // A commit that rotates the local validator off the beacon
        // committee ends its witness-fetching duties: drop the pooled
        // chunks and release the in-flight fetches alongside the
        // consumed ones.
        if was_on_committee && !self.is_on_committee() {
            abandoned_witness_ids.extend(self.shard_source.evicted_from_committee());
        }
        self.shard_source.prune_stale_headers();

        let next_epoch = self.state.current_epoch.next();
        self.proposal_pool.reset(next_epoch);
        self.evaluated_proposers.clear();

        // TopologyChanged emits on every commit, whether or not the
        // committee actually changed.
        let mut actions = vec![
            Action::CommitBeaconBlock {
                block,
                state: Box::new(self.state.clone()),
            },
            Action::TopologyChanged {
                epoch: self.state.current_epoch,
                topology_snapshot: Arc::clone(self.topology_schedule.head()),
                routing_committees: Arc::new(self.topology_schedule.routing_committees()),
            },
            // Re-arm the skip-trigger timer against the new tip. Fires
            // `skip_timeout` after the upcoming epoch's boundary if no
            // commit lands by then.
            Action::SetTimer {
                id: TimerId::BeaconRatifyTrigger,
                duration: self.duration_until_next_ratify_fire(),
            },
        ];

        // A lookahead placement delta for the local validator means the
        // host must reconfigure physical participation before the next
        // window opens: bootstrap of a joined shard needs the lookahead
        // epoch (snap-sync + tail sync), and a left shard's drain is
        // scheduled from the window close. The delta exists at exactly
        // one commit — the next `apply_epoch` promotes the lookahead
        // into the active window and the two views agree again. Emitted
        // after `TopologyChanged` so the consumer reads a snapshot (and
        // snap-sync anchor) that already reflects this commit.
        if let Some(change) = self.participation_delta(&effects) {
            actions.push(Action::ReconfigureParticipation(change));
        }

        let abandoned_proposals = self.commit_assembly.prune_stale(self.state.current_epoch);
        if !abandoned_proposals.is_empty() {
            actions.push(Action::AbandonFetch(FetchAbandon::BeaconProposal {
                ids: abandoned_proposals,
            }));
        }
        // Release in-flight witness fetches the boundary fold just consumed
        // — their leaves are below the advanced watermark, so a future
        // contribution can't include them and the runner's slot should
        // free rather than pin on a payload the tracker would only evict.
        if !abandoned_witness_ids.is_empty() {
            actions.push(Action::AbandonFetch(FetchAbandon::ShardWitnesses {
                ids: abandoned_witness_ids,
            }));
        }
        actions.extend(self.redrive_terminal_witness_fetches());

        // Self-perpetuate the next epoch's SPC, but only once wall-clock has
        // reached its boundary. While the beacon is behind real time (catch-up
        // after a gap, or `now` already past the boundary) this fires straight
        // away and the chain cascades to catch up; once the synthetic epoch
        // clock reaches wall-clock it instead arms `BeaconCommitteeStart` for
        // the boundary, so the beacon paces to real time rather than racing
        // ahead at SPC-round speed.
        if self.is_on_committee() {
            if self.committee_start_due(self.next_epoch_boundary()) {
                actions.extend(self.bootstrap_spc_for_next_epoch());
                actions.extend(self.try_propose());
            } else {
                actions.push(Action::SetTimer {
                    id: TimerId::BeaconCommitteeStart,
                    duration: self.duration_until_next_epoch_boundary(),
                });
            }
        }

        actions
    }

    /// The local validator's placement delta between the active window
    /// (`shard_committees`) and the lookahead (`next_shard_committees`),
    /// or `None` when the two agree and no observer seat changed hands.
    /// The lookahead is final for its window — membership changes fold
    /// one epoch ahead — so a delta here is the earliest, and only,
    /// detection point. A validator sits on at most one shard per
    /// window (`ValidatorStatus::OnShard` is singular and `members ⇔
    /// status` is a fold invariant), so each view yields at most one
    /// placement.
    ///
    /// Observer seats are transport-only committee presence, never a
    /// member placement: membership held under an `Observing` status —
    /// or under a seat this epoch's fold just released — is excluded
    /// from both views, so a cohort draw surfaces as
    /// [`ObserveDelta::Begin`] rather than a join, the grow itself is
    /// silent, and a released seat surfaces as
    /// [`ObserveDelta::Abandon`] with no spurious leave (plus a genuine
    /// join when a pool draw immediately re-placed the released
    /// observer as a regular member). A split's execution moves the
    /// observer's lookahead membership onto its child, surfacing as the
    /// ordinary join/leave pair.
    fn participation_delta(&self, effects: &SlotEffects) -> Option<ParticipationChange> {
        let me = self.me;
        let placement = |committees: &BTreeMap<ShardId, ShardCommittee>| -> Option<ShardId> {
            committees
                .iter()
                .find(|(_, committee)| committee.members.contains(&me))
                .map(|(shard, _)| *shard)
                .filter(|shard| {
                    !matches!(
                        self.state.validators.get(&me).map(|r| r.status),
                        Some(ValidatorStatus::Observing { shard: s, .. }) if s == *shard
                    )
                })
        };
        let drawn = effects.observers_drawn.iter().find(|s| s.validator == me);
        let released = effects
            .observers_released
            .iter()
            .find(|s| s.validator == me);
        let current = placement(&self.state.shard_committees)
            .filter(|shard| released.is_none_or(|seat| seat.shard != *shard));
        let next = placement(&self.state.next_shard_committees);
        let observe = drawn
            .map(|seat| ObserveDelta::Begin {
                via: seat.shard,
                child: seat.child,
            })
            .or_else(|| {
                released.map(|seat| ObserveDelta::Abandon {
                    via: seat.shard,
                    child: seat.child,
                })
            });
        // A keeper is already a member of its child, so a draw or
        // abandon accompanies no placement change. `Begin` names the
        // sibling half the keeper must sync; the merge's execution
        // surfaces the keeper's move onto the parent as the join/leave
        // pair, never here.
        let keep = effects
            .keepers_drawn
            .iter()
            .find(|seat| seat.validator == me)
            .map(|seat| {
                let (left, right) = seat.parent.children();
                let sibling = if seat.child == left { right } else { left };
                KeepDelta::Begin {
                    parent: seat.parent,
                    sibling,
                }
            })
            .or_else(|| {
                effects
                    .keepers_released
                    .iter()
                    .find(|seat| seat.validator == me)
                    .map(|seat| KeepDelta::Abandon {
                        parent: seat.parent,
                    })
            });
        if current == next && observe.is_none() && keep.is_none() {
            return None;
        }
        let moved = current != next;
        Some(ParticipationChange {
            validator: me,
            join: next.filter(|_| moved),
            leave: current.filter(|_| moved),
            observe,
            keep,
            effective_epoch: self.state.current_epoch.next(),
        })
    }

    /// SPC has decided this epoch. When every committed-vector
    /// element resolves to a pooled proposal, assemble the block
    /// directly. Otherwise stash the cert + output keyed by `epoch`
    /// and emit one fetch per missing element via
    /// [`Self::fetch_missing_proposals`]; assembly resumes from
    /// [`Self::on_beacon_proposal_fetched`] once every awaited fetch
    /// lands. Concurrent stashes for different epochs are allowed —
    /// stale entries get evicted from `adopt_block` once
    /// `current_epoch` advances past them.
    fn on_spc_output_high(
        &mut self,
        epoch: Epoch,
        output: &PcVector,
        cert: Verified<SpcCert>,
        _recipients: &[ValidatorId],
    ) -> Vec<Action> {
        match self.commit_assembly.on_decided(
            epoch,
            output,
            cert,
            &self.proposal_pool,
            &self.state.committee,
        ) {
            AssemblyDecision::Assemble {
                committed, cert, ..
            } => self.assemble_and_broadcast_candidate(epoch, committed, *cert),
            AssemblyDecision::AwaitFetch { missing, .. } => {
                self.fetch_missing_proposals(epoch, &missing)
            }
            AssemblyDecision::Idle => Vec::new(),
        }
    }

    /// Emit one [`FetchRequest::BeaconProposal`] per missing committed
    /// proposal. The routing `shard` is the dispatching vnode's
    /// `local_shard` (peer selection rides the local committee);
    /// `preferred` rotates through the beacon committee so multiple
    /// missing proposals don't all target the same peer.
    fn fetch_missing_proposals(&self, epoch: Epoch, missing: &[ValidatorId]) -> Vec<Action> {
        let peers = self.spc_recipients();
        let local_shard = self.local_shard;
        missing
            .iter()
            .enumerate()
            .map(|(i, &validator)| {
                let preferred = peers.get(i % peers.len().max(1)).copied();
                Action::Fetch(FetchRequest::BeaconProposal {
                    shard: local_shard,
                    epoch,
                    validator,
                    preferred,
                    class: None,
                })
            })
            .collect()
    }

    /// Build the candidate block from `committed` + SPC `cert`, feed
    /// its hash to the ratification tracker as the prevotable value,
    /// and broadcast it to the pool. The SPC cert authenticates the
    /// content; commitment waits for the pool's ratify cert.
    ///
    /// Defers (emitting nothing) when a committed boundary's source
    /// header isn't synced locally: assembling an incomplete contribution
    /// set would diverge from a fully-synced peer's candidate, so the
    /// local node waits for that peer's gossiped candidate instead.
    fn assemble_and_broadcast_candidate(
        &mut self,
        epoch: Epoch,
        committed: Vec<(ValidatorId, Verified<BeaconProposal>)>,
        cert: Verified<SpcCert>,
    ) -> Vec<Action> {
        let Some(shard_contributions) =
            boundary::build_shard_contributions(&self.state, &self.shard_source, &committed)
        else {
            trace!(
                epoch = epoch.inner(),
                "Deferring candidate assembly — a committed boundary's source header isn't \
                 synced locally; awaiting a fully-synced peer's gossiped candidate",
            );
            return Vec::new();
        };
        let prev_block_hash = self.latest_block.block_hash();
        let candidate = Arc::new(Verified::<CandidateBeaconBlock>::assemble(
            epoch,
            prev_block_hash,
            committed,
            shard_contributions,
            cert,
        ));
        if self.pending_candidate.is_none() {
            self.pending_candidate = Some(Arc::clone(&candidate));
        }
        let effects = self.ratify.on_candidate(candidate.block_hash());
        let mut actions = self.lift_ratify_effects(effects);
        actions.push(Action::BroadcastBeaconCandidate { candidate });
        actions
    }

    /// A peer's [`CandidateBeaconBlock`] arrived via gossip. Gate the
    /// non-crypto fields and dispatch SPC-cert + equivocation
    /// verification; [`Self::on_beacon_candidate_verified`] feeds the
    /// tracker when the result lands. First verified candidate wins —
    /// a second distinct candidate (an equivocating committee) is
    /// ignored, and the pool cert arbitrates.
    pub fn on_beacon_candidate_received(
        &mut self,
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
    ) -> Vec<Action> {
        if candidate.prev_block_hash() != self.latest_block.block_hash()
            || candidate.epoch() != self.state.current_epoch.next()
        {
            trace!(
                epoch = candidate.epoch().inner(),
                "BeaconCandidate doesn't extend the local tip — dropping",
            );
            return Vec::new();
        }
        if self.pending_candidate.is_some() || self.ratify.candidate().is_some() {
            return Vec::new();
        }
        // The SPC cert authenticates `committed_proposals`, not the
        // `shard_contributions` projected from them. Re-derive the
        // canonical projection before dispatching verification, so a
        // Byzantine assembler's variant (fabricated, stale, extra, or
        // omitted contribution) never becomes the value honest pool
        // members prevote.
        if !rules::contributions_well_formed(&self.state, candidate.block()) {
            warn!(
                epoch = candidate.epoch().inner(),
                "BeaconCandidate has malformed shard contributions — dropping",
            );
            return Vec::new();
        }
        if !self
            .verification
            .mark_candidate_in_flight(candidate.block_hash())
        {
            return Vec::new();
        }
        let committee = self.state.derive_beacon_committee();
        let equivocation_signers = self.equivocation_signers_for(candidate.block());
        vec![Action::VerifyBeaconCandidate {
            candidate,
            committee,
            equivocation_signers,
        }]
    }

    /// A previously-dispatched [`Action::VerifyBeaconCandidate`] has
    /// returned. Clear the pipeline slot, and on the `Ok` arm hold the
    /// candidate for cert pairing and feed its hash to the tracker as
    /// the prevotable value. Drops silently on the `Err` arm.
    pub fn on_beacon_candidate_verified(
        &mut self,
        result: Result<Arc<Verified<CandidateBeaconBlock>>, CandidateBeaconBlockVerifyError>,
    ) -> Vec<Action> {
        let candidate = match result {
            Ok(c) => c,
            Err(err) => {
                warn!(%err, "BeaconCandidate verification failed — dropping");
                return Vec::new();
            }
        };
        self.verification.forget_candidate(candidate.block_hash());
        // Tip may have advanced since dispatch; a stale candidate no
        // longer names a prevotable value.
        if candidate.prev_block_hash() != self.latest_block.block_hash()
            || candidate.epoch() != self.state.current_epoch.next()
        {
            trace!(
                epoch = candidate.epoch().inner(),
                "Verified BeaconCandidate no longer extends the tip — dropping",
            );
            return Vec::new();
        }
        if self.pending_candidate.is_none() {
            self.pending_candidate = Some(Arc::clone(&candidate));
        }
        let effects = self.ratify.on_candidate(candidate.block_hash());
        self.lift_ratify_effects(effects)
    }

    /// Handle a [`ProtocolEvent::BeaconProposalFetched`] dispatch:
    /// verify the returned proposal under the named validator's
    /// pubkey, admit it to the pool, and resume the stashed assembly
    /// for `epoch` once every awaited fetch has resolved.
    ///
    /// Out-of-band responses — no stash for the named epoch, or
    /// validator not in the awaiting set — drop silently.
    ///
    /// Unlike the gossip path, this admission doesn't re-run the
    /// witness-admission gate: a fetch only ever resolves a proposal
    /// referenced by an already-committed `PcVector` element, so the
    /// embedded witnesses are threshold-vouched (≥ f+1 honest voters
    /// verified them before the value could commit). The committed-proposal
    /// decode pins the fetched bytes to that committed element by hash.
    ///
    /// [`ProtocolEvent::BeaconProposalFetched`]: hyperscale_core::ProtocolEvent::BeaconProposalFetched
    pub fn on_beacon_proposal_fetched(
        &mut self,
        epoch: Epoch,
        validator: ValidatorId,
        proposal: Option<Arc<Verifiable<BeaconProposal>>>,
    ) -> Vec<Action> {
        if !self.commit_assembly.is_awaiting(epoch, validator) {
            return Vec::new();
        }
        if let Some(proposal) = proposal {
            if let Some(record) = self.state.validators.get(&validator) {
                let ctx = BeaconProposalVerifyContext {
                    network: &self.network,
                    epoch,
                    sender_pk: record.pubkey,
                };
                match Arc::unwrap_or_clone(proposal).upgrade(&ctx) {
                    Ok(verified) => {
                        let _ = self
                            .proposal_pool
                            .admit(validator, epoch, Arc::new(verified));
                    }
                    Err((_, err)) => {
                        warn!(
                            ?validator,
                            epoch = epoch.inner(),
                            ?err,
                            "Fetched BeaconProposal failed VRF verification — dropping",
                        );
                    }
                }
            } else {
                warn!(
                    ?validator,
                    "Fetched proposal's validator is not in BeaconState — dropping",
                );
            }
        }
        match self.commit_assembly.on_proposal_resolved(
            epoch,
            validator,
            &self.proposal_pool,
            &self.state.committee,
        ) {
            AssemblyDecision::Assemble {
                committed, cert, ..
            } => self.assemble_and_broadcast_candidate(epoch, committed, *cert),
            AssemblyDecision::AwaitFetch { .. } | AssemblyDecision::Idle => Vec::new(),
        }
    }

    /// This coordinator's proposal pool — lets tests and sims run
    /// lookups without going through the network path.
    #[must_use]
    pub const fn proposal_pool(&self) -> &BeaconProposalPool {
        &self.proposal_pool
    }

    /// Beacon-committee members excluding the local validator —
    /// recipient list for outbound SPC traffic.
    fn spc_recipients(&self) -> Vec<ValidatorId> {
        self.state
            .committee
            .iter()
            .filter(|v| **v != self.me)
            .copied()
            .collect()
    }

    /// Lift effects produced by the [`SpcDriver`] into actions. Captures
    /// `epoch` + `recipients` before lifting because the `OutputHigh`
    /// arm's adoption clears the instance. A no-op for empty effects.
    fn lift_from_spc(&mut self, effects: Vec<SpcEffect>) -> Vec<Action> {
        if effects.is_empty() {
            return Vec::new();
        }
        let Some(epoch) = self.spc.epoch() else {
            return Vec::new();
        };
        let recipients = self.spc_recipients();
        self.lift_spc_effects(epoch, &recipients, effects)
    }

    /// Translate the sub-machine's local effect enum into beacon
    /// actions plus internal state mutations (equivocation pool,
    /// commit assembly).
    fn lift_spc_effects(
        &mut self,
        epoch: Epoch,
        recipients: &[ValidatorId],
        effects: Vec<SpcEffect>,
    ) -> Vec<Action> {
        let mut actions = Vec::with_capacity(effects.len());
        for effect in effects {
            match effect {
                SpcEffect::SignAndBroadcastPcVote1 { view, v_in } => {
                    actions.push(Action::SignAndBroadcastPcVote1 {
                        epoch,
                        view,
                        v_in,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastPcVote2 { view, qc1 } => {
                    actions.push(Action::SignAndBroadcastPcVote2 {
                        epoch,
                        view,
                        qc1,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastPcVote3 { view, qc2 } => {
                    actions.push(Action::SignAndBroadcastPcVote3 {
                        epoch,
                        view,
                        qc2,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastEmptyView { view, reported } => {
                    actions.push(Action::SignAndBroadcastEmptyView {
                        epoch,
                        view,
                        reported,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::BroadcastNewView { view, cert } => {
                    let proposal = Verified::<SpcProposalObject>::from_verified_cert(view, *cert);
                    actions.push(Action::BroadcastSpcNewView {
                        epoch,
                        proposal: Box::new(proposal),
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::BroadcastNewCommit { view, proof } => {
                    let msg = Verified::<SpcNewCommitMsg>::from_verified_proof(view, *proof);
                    actions.push(Action::BroadcastSpcNewCommit {
                        epoch,
                        msg: Box::new(msg),
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SetTimer { view: _, duration } => {
                    actions.push(Action::SetTimer {
                        id: TimerId::BeaconSpcView,
                        duration,
                    });
                }
                SpcEffect::Equivocation { view: _, evidence } => {
                    self.equivocations.record_pc_equivocation(*evidence);
                }
                SpcEffect::OutputHigh { value, cert } => {
                    actions.extend(self.on_spc_output_high(epoch, &value, *cert, recipients));
                }
            }
        }
        actions
    }
}

// Flat accessors; their names and return types are the documentation.
#[allow(missing_docs)]
impl BeaconCoordinator {
    #[must_use]
    pub const fn current_state(&self) -> &BeaconState {
        &self.state
    }

    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.state.current_epoch
    }

    #[must_use]
    pub const fn latest_block(&self) -> &Arc<Verified<CertifiedBeaconBlock>> {
        &self.latest_block
    }

    #[must_use]
    pub const fn network_definition(&self) -> &NetworkDefinition {
        &self.network
    }

    #[must_use]
    pub const fn me(&self) -> ValidatorId {
        self.me
    }

    #[must_use]
    pub const fn now(&self) -> LocalTimestamp {
        self.now
    }

    #[must_use]
    pub const fn current_topology_snapshot(&self) -> &Arc<TopologySnapshot> {
        self.topology_schedule.head()
    }

    /// The per-epoch committee schedule — the verification interface handed to
    /// shard and execution coordinators. They resolve an artifact's committee
    /// from its weighted timestamp ([`TopologySchedule::at`]) and the routing
    /// head ([`TopologySchedule::head`]) through it, so no consensus-layer type
    /// crosses into their verification paths.
    #[must_use]
    pub const fn topology_schedule(&self) -> &TopologySchedule {
        &self.topology_schedule
    }

    /// Number of crypto verifications dispatched but not yet resulted.
    /// Test introspection — production code shouldn't gate on this.
    #[must_use]
    pub fn verifications_in_flight(&self) -> usize {
        self.verification.in_flight_count() + self.spc.in_flight_count()
    }
}

impl std::fmt::Debug for BeaconCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconCoordinator")
            .field("current_epoch", &self.state.current_epoch)
            .field("latest_block_hash", &self.latest_block.block_hash())
            .field("me", &self.me)
            .field("spc_active", &self.spc.is_bootstrapped())
            .field("verifications_in_flight", &self.verifications_in_flight())
            .field("witness_chunks", &self.shard_source.total_chunk_len())
            .field("ratify_round", &self.ratify.round())
            .field("equivocations", &self.equivocations.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconBlock, BeaconBlockHash, BeaconChainConfig, BeaconGenesisConfig,
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, BlockHeight, Bls12381G1PrivateKey,
        Bls12381G1PublicKey, BoundedVec, CertificateRoot, CertifiedBlockHeader, ChainOrigin, Epoch,
        GenesisConfigHash, GenesisPool, GenesisValidator, Hash, InFlightCount, KeptSeat, LeafIndex,
        LocalReceiptRoot, MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR, NetworkDefinition,
        ObserverSeat, PcVector, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Randomness,
        Round, ShardBoundary, ShardCommittee, ShardEpochContribution, ShardId, ShardWitness,
        ShardWitnessPayload, ShardWitnessProof, SignerBitfield, SpcCert, SpcView, Stake,
        StakePoolId, StateRoot, TransactionRoot, ValidatorId, VrfProof, WeightedTimestamp,
        bls_keypair_from_seed, build_qc1, build_qc2, build_qc3, build_ratify_cert,
        compute_merkle_root_with_proof, genesis_config_hash, pc_context, sign_ratify_vote,
        sign_vote1, sign_vote2, sign_vote3, spc_context, zero_bls_signature,
    };

    use super::*;
    use crate::genesis::build_genesis_beacon_state;

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        keypair(seed).public_key()
    }

    /// 4 validators, all on the beacon committee, all placed on the ROOT
    /// genesis shard.
    fn sample_genesis() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let validators: Vec<GenesisValidator> = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committee: members,
            initial_randomness: Randomness::new([0xAB; 32]),
        }
    }

    /// The (block, state, `config_hash`) trio the runner would produce
    /// on an empty store: build genesis state, hash the config, wrap
    /// the genesis block.
    fn genesis_trio() -> (
        Arc<Verified<CertifiedBeaconBlock>>,
        BeaconState,
        GenesisConfigHash,
    ) {
        let config = sample_genesis();
        let state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config, &NetworkDefinition::simulator());
        let block = Verified::<CertifiedBeaconBlock>::genesis(config_hash);
        (Arc::new(block), state, config_hash)
    }

    fn new_coord(me: ValidatorId) -> BeaconCoordinator {
        let (block, state, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            block,
            vec![state],
            me,
            ShardId::ROOT,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            config_hash,
        )
    }

    /// Advance `coord`'s clock past the next epoch's skip deadline so
    /// skip-request intake and admission accept requests.
    fn pass_skip_deadline(coord: &mut BeaconCoordinator) {
        let state = coord.current_state();
        let boundary = state
            .chain_config
            .epoch_windows()
            .window_of(state.current_epoch)
            .end
            .as_millis();
        let timeout_ms: u64 = SKIP_TIMEOUT
            .as_millis()
            .try_into()
            .expect("SKIP_TIMEOUT fits in u64 millis");
        coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms));
    }

    fn fresh_coord() -> BeaconCoordinator {
        new_coord(ValidatorId::new(0))
    }

    // ─── boundary-QC contribution hardening ─────────────────────────────

    /// A verified source-shard header whose parent QC carries `pred_wt`,
    /// carrying `state_root`, `root` as its `beacon_witness_root`, and
    /// `leaf_count`. Only the fields the boundary projection and
    /// verification read carry meaning; the rest are zeroed.
    fn boundary_block_header_with_root(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        root: BeaconWitnessRoot,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(pred_wt),
        );
        let header = BlockHeader::new(
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            state_root,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            root,
            BeaconWitnessLeafCount::new(leaf_count),
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(pred_wt),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// A boundary header carrying a synthetic (witnessless) accumulator
    /// root — for tests that exercise the projection/binding logic and not
    /// the witness chunk.
    fn boundary_block_header(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        boundary_block_header_with_root(
            shard,
            height,
            pred_wt,
            state_root,
            BeaconWitnessRoot::from_raw(Hash::from_bytes(format!("bw-{height}").as_bytes())),
            leaf_count,
        )
    }

    /// A boundary header committing a real beacon-witness accumulator of
    /// `leaf_count` `StakeDeposit` leaves, plus the matching per-leaf
    /// witnesses (merkle-proven against the block's root, anchored to its
    /// hash). Seat the witnesses into a coordinator via
    /// [`BeaconCoordinator::on_shard_witnesses_received`] or embed them in a
    /// [`ShardEpochContribution`] to drive the witness-chunk fetch and fold.
    fn boundary_block_with_witnesses(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> (Arc<Verified<CertifiedBlockHeader>>, Vec<ShardWitness>) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200 + u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        let leaf_hashes: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        let root = if leaf_hashes.is_empty() {
            BeaconWitnessRoot::ZERO
        } else {
            BeaconWitnessRoot::from_raw(compute_merkle_root_with_proof(&leaf_hashes, 0).0)
        };
        let certified =
            boundary_block_header_with_root(shard, height, pred_wt, state_root, root, leaf_count);
        let block_hash = certified.block_hash();
        let witnesses = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let (_, siblings, _) = compute_merkle_root_with_proof(&leaf_hashes, i);
                ShardWitness {
                    payload,
                    proof: ShardWitnessProof {
                        shard_id: shard,
                        committed_block_hash: block_hash,
                        leaf_index: LeafIndex::new(i as u64),
                        siblings: siblings.into(),
                    },
                }
            })
            .collect();
        (certified, witnesses)
    }

    /// A verified header whose `parent_qc` names `parent_hash` at
    /// `parent_wt`. Chaining two (`C.parent_qc` naming `B`) lets the
    /// crossing detector recognise an epoch-boundary `(B, C)` pair.
    fn linked_block_header(
        shard: ShardId,
        height: u64,
        parent_hash: BlockHash,
        parent_wt: u64,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_wt),
        );
        let header = BlockHeader::new(
            shard,
            BlockHeight::new(height),
            parent_hash,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::from_raw(Hash::from_bytes(format!("bw-{height}").as_bytes())),
            BeaconWitnessLeafCount::new(leaf_count),
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            parent_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_wt),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// A structural QC naming `block_hash` at weighted timestamp `wt`.
    /// `build_shard_contributions` and `contributions_well_formed` project
    /// and bind cert-bound QCs without re-running BLS (the `2f+1` is the
    /// admission gate's job), so a structural QC suffices for them.
    fn qc_naming(block_hash: BlockHash, shard: ShardId, height: u64, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(wt),
        )
    }

    fn proposal_with_boundary(shard: ShardId, qc: QuorumCertificate) -> BeaconProposal {
        BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        )
    }

    /// The assembler defers (returns `None`, awaiting a synced peer's
    /// block) when it can't fully back a committed boundary QC locally —
    /// neither when the boundary block is unsynced nor when its witness
    /// chunk isn't in hand (the witness-availability coupling) — and seats
    /// the canonical projection, witnesses embedded, once both arrive.
    #[test]
    fn build_shard_contributions_defers_until_boundary_synced() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"unit-anchor"));
        let (b, witnesses) = boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(
            ValidatorId::new(0),
            Verified::new_unchecked_for_test(proposal_with_boundary(shard, qc)),
        )];

        // The boundary block isn't synced — defer rather than omit it.
        assert!(
            boundary::build_shard_contributions(&coord.state, &coord.shard_source, &committed)
                .is_none()
        );

        // Header synced but the witness chunk isn't in hand — still defer
        // (the coupling rule: a boundary is only reportable with its chunk).
        coord.on_verified_source_header(&b);
        assert!(
            boundary::build_shard_contributions(&coord.state, &coord.shard_source, &committed)
                .is_none()
        );

        // Once the witness chunk arrives, the contribution seats with it.
        coord.on_shard_witnesses_received(shard, witnesses.iter().cloned().map(Arc::new).collect());
        let built =
            boundary::build_shard_contributions(&coord.state, &coord.shard_source, &committed)
                .expect("contribution seats once the boundary block and chunk sync");
        assert_eq!(built.len(), 1);
        assert_eq!(built[&shard].boundary_header.hash(), b.block_hash());
        assert_eq!(built[&shard].witnesses.len(), 3);
    }

    /// `contributions_well_formed` accepts the canonical projection of the
    /// committed boundary QCs and rejects an incomplete, extra, or unbound
    /// contribution set — the Byzantine-variant gate on received blocks.
    #[test]
    fn contributions_well_formed_enforces_canonical_projection() {
        let coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let other = ShardId::leaf(1, 1);
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"wf-anchor"));
        let (b, witnesses) = boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(ValidatorId::new(0), proposal_with_boundary(shard, qc))];
        let contribution = ShardEpochContribution {
            boundary_header: b.header().clone(),
            witnesses: witnesses.into(),
        };
        let block_with = |contribs: BTreeMap<ShardId, ShardEpochContribution>| {
            BeaconBlock::new_with_contributions(
                Epoch::new(1),
                BeaconBlockHash::ZERO,
                committed.clone(),
                contribs,
            )
        };

        // Canonical projection — accepted.
        let good = block_with(std::iter::once((shard, contribution.clone())).collect());
        assert!(rules::contributions_well_formed(&coord.state, &good));

        // Omits the committed shard's contribution — rejected.
        assert!(!rules::contributions_well_formed(
            &coord.state,
            &block_with(BTreeMap::new())
        ));

        // Extra contribution for a shard with no committed QC — rejected.
        let mut extra: BTreeMap<ShardId, ShardEpochContribution> = BTreeMap::new();
        extra.insert(shard, contribution.clone());
        extra.insert(other, contribution);
        assert!(!rules::contributions_well_formed(
            &coord.state,
            &block_with(extra)
        ));

        // A contribution binding to no committed QC — rejected.
        let wrong = boundary_block_header(shard, 9, 299_000, StateRoot::ZERO, 3);
        let tampered = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: wrong.header().clone(),
                witnesses: BoundedVec::new(),
            },
        ))
        .collect();
        assert!(!rules::contributions_well_formed(
            &coord.state,
            &block_with(tampered)
        ));

        // Correctly bound, but a short witness chunk (the boundary commits
        // 3 leaves, the contribution carries none) — rejected on the
        // chunk-completeness check.
        let short = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b.header().clone(),
                witnesses: BoundedVec::new(),
            },
        ))
        .collect();
        assert!(!rules::contributions_well_formed(
            &coord.state,
            &block_with(short)
        ));
    }

    /// A gossiped candidate whose `shard_contributions` deviate from
    /// the canonical projection is dropped before verification is
    /// dispatched, so honest pool members never prevote a Byzantine
    /// assembler's variant. The canonical projection of the same
    /// content dispatches verification normally.
    #[test]
    fn malformed_candidate_drops_before_verification_dispatch() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"cand-anchor"));
        let (b, witnesses) = boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(ValidatorId::new(0), proposal_with_boundary(shard, qc))];
        let contribution = ShardEpochContribution {
            boundary_header: b.header().clone(),
            witnesses: witnesses.into(),
        };
        let epoch = coord.state.current_epoch.next();
        let prev = coord.latest_block.block_hash();

        // The cert content is irrelevant here — the contributions gate
        // runs before any crypto dispatch — but `SpcCert` has no
        // structural placeholder, so build a real one.
        let n = coord.state.committee.len();
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_signers: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let signer_positions: Vec<usize> = (0..n - (n - 1) / 3).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            epoch,
            &keys,
            &cert_signers,
            &signer_positions,
            &PcVector::empty(),
        );
        let candidate_with = |contribs: BTreeMap<ShardId, ShardEpochContribution>| {
            Arc::new(Verifiable::from(CandidateBeaconBlock::new(
                BeaconBlock::new_with_contributions(epoch, prev, committed.clone(), contribs),
                Box::new(cert.clone()),
            )))
        };

        // Omits the committed shard's contribution — dropped, nothing
        // dispatched, no prevotable value held.
        let actions = coord.on_beacon_candidate_received(candidate_with(BTreeMap::new()));
        assert!(
            actions.is_empty(),
            "malformed candidate must not dispatch verification: {actions:?}",
        );
        assert!(coord.pending_candidate_hash().is_none());

        // The canonical projection dispatches verification — the drop
        // above is the contributions gate, not an earlier check.
        let actions = coord.on_beacon_candidate_received(candidate_with(
            std::iter::once((shard, contribution)).collect(),
        ));
        assert!(
            matches!(actions.as_slice(), [Action::VerifyBeaconCandidate { .. }]),
            "canonical candidate dispatches verification: {actions:?}",
        );
    }

    /// Drive any beacon-verify actions in `actions` through to their
    /// result event, appending the post-verify actions in dispatch
    /// order. Mirrors the round-trip the production runner (and
    /// `CoordinatorSim`) perform; lets tests assert the
    /// synchronous-equivalent outcome without manually threading
    /// results back to the coordinator.
    fn complete_verifications(coord: &mut BeaconCoordinator, actions: Vec<Action>) -> Vec<Action> {
        use hyperscale_types::{
            CandidateVerifyContext, CertifiedBeaconBlockVerifyContext, RatifyVerifyContext,
        };

        let net = NetworkDefinition::simulator();
        let mut out = Vec::new();
        for action in actions {
            match action {
                Action::VerifyBeaconBlock {
                    block,
                    committee,
                    active_pool,
                    equivocation_signers,
                } => {
                    let result = Arc::unwrap_or_clone(block)
                        .upgrade(&CertifiedBeaconBlockVerifyContext {
                            network: &net,
                            committee: &committee,
                            active_pool: &active_pool,
                            equivocation_signers: &equivocation_signers,
                        })
                        .map(Arc::new)
                        .map_err(|(_, e)| e);
                    let post = coord.on_beacon_block_verified(result);
                    out.extend(complete_verifications(coord, post));
                }
                Action::VerifyBeaconCandidate {
                    candidate,
                    committee,
                    equivocation_signers,
                } => {
                    let result = Arc::unwrap_or_clone(candidate)
                        .upgrade(&CandidateVerifyContext {
                            network: &net,
                            committee: &committee,
                            equivocation_signers: &equivocation_signers,
                        })
                        .map(Arc::new)
                        .map_err(|(_, e)| e);
                    let post = coord.on_beacon_candidate_verified(result);
                    out.extend(complete_verifications(coord, post));
                }
                Action::VerifyRatifyVote { vote, signers } => {
                    let anchor = vote.anchor_hash();
                    let epoch = vote.epoch();
                    let round = vote.round();
                    let phase = vote.phase();
                    let signer = vote.signer();
                    let result = (*vote)
                        .upgrade(&RatifyVerifyContext {
                            network: &net,
                            active_pool: &signers,
                        })
                        .map_err(|(_, e)| e);
                    let post =
                        coord.on_ratify_vote_verified(anchor, epoch, round, phase, signer, result);
                    out.extend(complete_verifications(coord, post));
                }
                other => out.push(other),
            }
        }
        out
    }

    #[test]
    fn new_from_genesis_pair_resumes_at_genesis_epoch() {
        let coord = fresh_coord();
        assert_eq!(coord.current_epoch(), Epoch::GENESIS);
        assert!(coord.is_on_committee());
        assert_eq!(coord.now(), LocalTimestamp::ZERO);
    }

    #[test]
    fn new_carries_latest_block() {
        let (block, state, config_hash) = genesis_trio();
        let block_hash = block.block_hash();
        let coord = BeaconCoordinator::new(
            Arc::clone(&block),
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            config_hash,
        );
        assert_eq!(coord.latest_block().block_hash(), block_hash);
    }

    #[test]
    fn new_resumes_at_loaded_state_epoch() {
        // Warm-restart: the runner loads a committed `(block, state)` from
        // storage past genesis and hands it to `new()`. The coordinator must
        // resume at the loaded state's epoch, not fall back to genesis.
        let (block, mut state, config_hash) = genesis_trio();
        state.current_epoch = Epoch::new(7);
        let coord = BeaconCoordinator::new(
            block,
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            config_hash,
        );
        assert_eq!(coord.current_epoch(), Epoch::new(7));
    }

    #[test]
    fn off_committee_validator_reports_not_on_committee() {
        let coord = new_coord(ValidatorId::new(99));
        assert!(!coord.is_on_committee());
    }

    #[test]
    fn set_now_advances_local_clock() {
        let mut coord = fresh_coord();
        let t = LocalTimestamp::from_millis(123_456);
        coord.set_now(t);
        assert_eq!(coord.now(), t);
    }

    #[test]
    #[should_panic(expected = "genesis block config_hash doesn't match operator config")]
    #[cfg(debug_assertions)]
    fn debug_assertion_catches_runner_loading_mismatched_genesis() {
        use hyperscale_types::Hash;
        let (_block, state, _config_hash) = genesis_trio();
        let mismatched_block = Verified::<CertifiedBeaconBlock>::genesis(
            GenesisConfigHash::from_raw(Hash::from_bytes(b"other-config")),
        );
        let _coord = BeaconCoordinator::new(
            Arc::new(mismatched_block),
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            GenesisConfigHash::ZERO,
        );
    }

    #[test]
    fn committee_start_due_fires_at_or_after_boundary() {
        let mut coord = fresh_coord();
        let boundary = LocalTimestamp::from_millis(10_000);
        coord.set_now(LocalTimestamp::from_millis(9_999));
        assert!(!coord.committee_start_due(boundary));
        coord.set_now(LocalTimestamp::from_millis(10_000));
        assert!(coord.committee_start_due(boundary));
        coord.set_now(LocalTimestamp::from_millis(10_001));
        assert!(coord.committee_start_due(boundary));
    }

    #[test]
    fn skip_trigger_due_fires_one_timeout_past_expected() {
        let mut coord = fresh_coord();
        let expected = LocalTimestamp::from_millis(100_000);
        let timeout_ms: u64 = SKIP_TIMEOUT
            .as_millis()
            .try_into()
            .expect("SKIP_TIMEOUT fits in u64 millis");

        coord.set_now(LocalTimestamp::from_millis(100_000 + timeout_ms - 1));
        assert!(!coord.skip_trigger_due(expected));
        coord.set_now(LocalTimestamp::from_millis(100_000 + timeout_ms));
        assert!(coord.skip_trigger_due(expected));
    }

    /// The ratify-timer fire re-validates the deadline against the
    /// *current* next epoch. A fire before that deadline — a re-armed
    /// timer racing an adoption — must vote nothing: the vote it would
    /// sign anchors at the current tip and names the current next
    /// epoch, so nothing downstream could tell it was stale. Past the
    /// deadline, the fire prevotes the skip hash and re-arms for the
    /// next round; a second fire advances the round and re-prevotes
    /// per the lock rule.
    #[test]
    fn ratify_timer_paces_to_the_deadline_then_rounds() {
        let mut coord = fresh_coord();
        let boundary = coord.current_state().chain_config.epoch_duration_ms;
        let timeout_ms: u64 = SKIP_TIMEOUT
            .as_millis()
            .try_into()
            .expect("SKIP_TIMEOUT fits in u64 millis");
        let skip_hash = coord.ratify.skip_block_hash();

        coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms - 1));
        let actions = coord.on_beacon_ratify_timer();
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastRatifyVote { .. })),
            "an early fire must not vote; got {actions:?}",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer {
                    id: TimerId::BeaconRatifyTrigger,
                    ..
                }
            )),
            "an early fire must re-arm — a dead timer chain kills the \
             validator's skip machinery; got {actions:?}",
        );

        coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms));
        let actions = coord.on_beacon_ratify_timer();
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SignAndBroadcastRatifyVote { epoch, phase: RatifyPhase::Prevote, block_hash, .. }
                    if epoch.inner() == 1 && *block_hash == skip_hash
            )),
            "a fire past the deadline must prevote the skip hash; got {actions:?}",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer {
                    id: TimerId::BeaconRatifyTrigger,
                    ..
                }
            )),
            "the timer must re-arm for the next round; got {actions:?}",
        );
        assert_eq!(coord.ratify.round(), RatifyRound::INITIAL);

        // A second fire is a round timeout: the round advances, and the
        // unlocked tracker re-prevotes skip (still no candidate).
        let actions = coord.on_beacon_ratify_timer();
        assert_eq!(coord.ratify.round(), RatifyRound::new(2));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SignAndBroadcastRatifyVote { round, phase: RatifyPhase::Prevote, block_hash, .. }
                    if *round == RatifyRound::new(2) && *block_hash == skip_hash
            )),
            "a round timeout must re-prevote in the new round; got {actions:?}",
        );
    }

    #[test]
    fn coordinator_owns_state_independently_from_input() {
        let coord = fresh_coord();
        let snapshot = coord.current_state().clone();
        assert_eq!(coord.current_state(), &snapshot);
        assert_eq!(coord.current_state().miss_counters, BTreeMap::new());
    }

    #[test]
    fn on_pc_vote_received_drops_when_no_spc_instance() {
        use hyperscale_types::{Bls12381G2Signature, PcVote1};
        let mut coord = fresh_coord();
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        );
        let actions = coord.on_pc_vote1_received(SpcView::new(1), vote);
        assert!(actions.is_empty());
    }

    /// A PC vote whose claimed signer is outside the committee is dropped
    /// before the BLS dispatch, so it can't mint a verification slot.
    #[test]
    fn pc_vote_from_non_committee_signer_dropped_before_dispatch() {
        use hyperscale_types::{Bls12381G2Signature, PcVote1};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        // The committee is validators 0..4; 9 is not a member.
        let vote = PcVote1::new(
            ValidatorId::new(9),
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        );
        let actions = coord.on_pc_vote1_received(SpcView::new(1), vote);
        assert!(actions.is_empty());
        assert_eq!(coord.verifications_in_flight(), 0);
    }

    /// A PC vote for a view far outside `[current, current +
    /// MAX_PENDING_EMPTY_VIEW_AHEAD]` is dropped before dispatch.
    #[test]
    fn pc_vote_for_out_of_window_view_dropped_before_dispatch() {
        use hyperscale_types::{Bls12381G2Signature, PcVote1};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        // current_view is 1; the window is [1, 5], so view 6 is out.
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        );
        let actions = coord.on_pc_vote1_received(SpcView::new(6), vote);
        assert!(actions.is_empty());
        assert_eq!(coord.verifications_in_flight(), 0);
    }

    /// A committee signer's vote within the view window passes the gate
    /// and dispatches a verification (one in-flight slot).
    #[test]
    fn pc_vote_from_committee_in_window_dispatches_verification() {
        use hyperscale_types::{Bls12381G2Signature, PcVote1};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        );
        let actions = coord.on_pc_vote1_received(SpcView::new(1), vote);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::VerifyPcVote1 { .. }));
        assert_eq!(coord.verifications_in_flight(), 1);
    }

    #[test]
    fn on_beacon_spc_view_timer_drops_when_no_spc_instance() {
        let mut coord = fresh_coord();
        assert!(coord.on_beacon_spc_view_timer().is_empty());
    }

    #[test]
    fn committee_start_bootstraps_spc_for_on_committee_local() {
        let mut coord = fresh_coord();
        assert!(!coord.spc.is_bootstrapped());
        let actions = coord.on_beacon_committee_start_timer();
        assert_eq!(coord.spc.epoch(), Some(Epoch::GENESIS.next()));
        assert_eq!(coord.spc.current_view(), Some(SpcView::new(1)));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildAndBroadcastBeaconProposal { .. })),
            "expected BuildAndBroadcastBeaconProposal in {actions:?}",
        );
    }

    /// A beacon-eligible set that resampled below the BFT minimum
    /// (`n < MIN_BEACON_COMMITTEE_SIZE`) must not bootstrap an SPC instance —
    /// `PcInstance::new` would panic on it. The coordinator declines and
    /// leaves `spc` cleared so the skip path can carry the epoch.
    #[test]
    fn bootstrap_below_bft_minimum_declines_without_panicking() {
        let mut coord = fresh_coord();
        let undersized: Vec<(ValidatorId, Bls12381G1PublicKey)> = (0u64
            ..(MIN_BEACON_COMMITTEE_SIZE as u64 - 1))
            .map(|i| (ValidatorId::new(i), pubkey(i)))
            .collect();
        coord.bootstrap_spc_with_committee(undersized);
        assert!(!coord.spc.is_bootstrapped());
    }

    /// A committee exactly at the BFT minimum bootstraps normally.
    #[test]
    fn bootstrap_at_bft_minimum_creates_instance() {
        let mut coord = fresh_coord();
        let committee: Vec<(ValidatorId, Bls12381G1PublicKey)> = (0u64..MIN_BEACON_COMMITTEE_SIZE
            as u64)
            .map(|i| (ValidatorId::new(i), pubkey(i)))
            .collect();
        coord.bootstrap_spc_with_committee(committee);
        assert!(coord.spc.is_bootstrapped());
    }

    /// Two skip requests from the same signer at the same anchor/epoch
    /// but with different signature bytes collapse to one verification
    /// slot: the slot key is `(anchor, epoch, round, phase, signer)`,
    /// not the encoded-vote hash, so a forged-sig flood can't mint
    /// extra in-flight BLS checks.
    #[test]
    fn ratify_vote_verification_keys_on_signer_not_signature() {
        use hyperscale_types::Bls12381G2Signature;
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1); // a peer on the active pool
        let skip_hash = coord.ratify.skip_block_hash();

        let vote = |sig_byte: u8| {
            Arc::new(Verifiable::from(RatifyVote::new(
                anchor,
                epoch,
                RatifyRound::INITIAL,
                RatifyPhase::Prevote,
                skip_hash,
                signer,
                Bls12381G2Signature([sig_byte; 96]),
            )))
        };

        // First vote dispatches one verification.
        let first = coord.on_unverified_ratify_vote_received(vote(0));
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Action::VerifyRatifyVote { .. }));
        assert_eq!(coord.verifications_in_flight(), 1);

        // Same tuple, different signature — deduped before dispatch.
        let second = coord.on_unverified_ratify_vote_received(vote(1));
        assert!(second.is_empty());
        assert_eq!(coord.verifications_in_flight(), 1);
    }

    /// A ratify vote that fails BLS verification releases its slot, so
    /// a later vote for the same tuple re-dispatches. Without clearing
    /// on the failure arm, a forged vote could pin a signer's slot
    /// in-flight and block their honest vote from ever being verified.
    #[test]
    fn failed_ratify_vote_verification_releases_slot() {
        use hyperscale_types::Bls12381G2Signature;
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1);
        let skip_hash = coord.ratify.skip_block_hash();

        let forged = Arc::new(Verifiable::from(RatifyVote::new(
            anchor,
            epoch,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
            signer,
            Bls12381G2Signature([0u8; 96]), // garbage sig — fails BLS verify
        )));
        let dispatched = coord.on_unverified_ratify_vote_received(forged);
        assert_eq!(coord.verifications_in_flight(), 1);

        // Drive the (failing) verification to completion — the slot clears.
        let _ = complete_verifications(&mut coord, dispatched);
        assert_eq!(coord.verifications_in_flight(), 0);

        // A fresh vote for the same tuple re-dispatches rather than
        // being deduped against a pinned slot.
        let retry = Arc::new(Verifiable::from(RatifyVote::new(
            anchor,
            epoch,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
            signer,
            Bls12381G2Signature([2u8; 96]),
        )));
        let redispatched = coord.on_unverified_ratify_vote_received(retry);
        assert_eq!(redispatched.len(), 1);
        assert!(matches!(redispatched[0], Action::VerifyRatifyVote { .. }));
    }

    #[test]
    fn committee_start_no_op_when_off_committee() {
        let mut coord = new_coord(ValidatorId::new(99));
        let actions = coord.on_beacon_committee_start_timer();
        assert!(actions.is_empty());
        assert!(!coord.spc.is_bootstrapped());
    }

    #[test]
    fn committee_start_is_idempotent() {
        let mut coord = fresh_coord();
        coord.on_beacon_committee_start_timer();
        let spc_view_first = coord.spc.current_view();
        coord.on_beacon_committee_start_timer();
        let spc_view_second = coord.spc.current_view();
        assert_eq!(spc_view_first, spc_view_second);
    }

    fn sample_proposal(seed: u8) -> Arc<Verified<BeaconProposal>> {
        use hyperscale_types::VrfProof;
        Arc::new(Verified::new_unchecked_for_test(BeaconProposal::vrf_only(
            VrfProof::new([seed; 96]),
        )))
    }

    #[test]
    fn on_proposal_received_admits_in_flight_epoch_from_committee_member() {
        let mut coord = fresh_coord();
        let from = ValidatorId::new(1);
        let in_flight = Epoch::GENESIS.next();
        let actions = coord.on_beacon_proposal_received(from, in_flight, sample_proposal(0xAB));
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.contains(from));
    }

    #[test]
    fn on_proposal_received_drops_non_committee_sender() {
        let mut coord = fresh_coord();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(99),
            Epoch::GENESIS.next(),
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.is_empty());
    }

    #[test]
    fn on_proposal_received_drops_wrong_epoch() {
        let mut coord = fresh_coord();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(1),
            Epoch::GENESIS,
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.is_empty());
    }

    #[test]
    fn try_propose_emits_build_action_after_bootstrap() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let actions = coord.try_propose();
        let in_flight = Epoch::GENESIS.next();
        let [
            Action::BuildAndBroadcastBeaconProposal {
                epoch,
                boundary_qcs,
                equivocations,
                recipients,
            },
        ] = actions.as_slice()
        else {
            panic!("expected BuildAndBroadcastBeaconProposal, got {actions:?}");
        };
        assert_eq!(*epoch, in_flight);
        // No source-shard headers observed in this fixture, so the
        // proposer reports no crossings.
        assert!(boundary_qcs.is_empty());
        assert!(equivocations.is_empty());
        // Three peers in the n=4 committee (self filtered out).
        assert_eq!(recipients.len(), 3);
        assert!(!recipients.contains(&coord.me));
    }

    #[test]
    fn try_propose_is_no_op_without_spc() {
        let mut coord = fresh_coord();
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn try_propose_is_no_op_off_committee() {
        let mut coord = new_coord(ValidatorId::new(99));
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn try_propose_idempotent_after_own_proposal_in_pool() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let first = coord.try_propose();
        assert!(!first.is_empty());
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(coord.try_propose().is_empty());
    }

    fn proposal_equivocations(actions: &[Action]) -> &[PcVoteEquivocation] {
        match actions {
            [Action::BuildAndBroadcastBeaconProposal { equivocations, .. }] => {
                equivocations.as_slice()
            }
            other => panic!("expected single BuildAndBroadcastBeaconProposal, got {other:?}"),
        }
    }

    #[test]
    fn try_propose_drains_buffered_equivocations_into_witnesses() {
        use hyperscale_types::{Bls12381G2Signature, PcVoteEquivocation, PcVoteRound};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();

        let evidence = PcVoteEquivocation {
            validator: ValidatorId::new(2),
            epoch: Epoch::new(1),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::empty(),
            sig_a: Bls12381G2Signature([0x11; 96]),
            value_b: PcVector::empty(),
            sig_b: Bls12381G2Signature([0x22; 96]),
        };
        assert!(coord.equivocations.record_pc_equivocation(evidence));

        let actions = coord.try_propose();
        let equivocations = proposal_equivocations(&actions);
        assert_eq!(equivocations.len(), 1);
        assert_eq!(equivocations[0].validator, ValidatorId::new(2));
        assert!(coord.equivocations.is_empty());
    }

    /// The view-1 input feeds only once *every* committee member's
    /// proposal is pooled — members bootstrap near-simultaneously, so a
    /// partial-coverage feed hands PC a positional vector that diverges
    /// across nodes and the prefix consensus collapses it. A laggard tail
    /// is covered by the dwell timer, not by feeding an incomplete set.
    #[test]
    fn full_proposal_coverage_feeds_spc_view_one_input() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();

        let mut fed_at = None;
        let mut admitted = 0usize;
        let mut peers = committee.iter().filter(|&&v| v != me);
        // Own proposal first, then peers until the feed triggers — the
        // trigger is full coverage of the committee.
        let mut next = Some(me);
        while let Some(member) = next {
            let actions = coord.on_beacon_proposal_received(
                member,
                in_flight,
                sample_proposal(u8::try_from(admitted).unwrap_or(0)),
            );
            admitted += 1;
            if actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastPcVote1 { .. }))
            {
                fed_at = Some(admitted);
                break;
            }
            assert!(
                !coord.spc.view_one_input_fed(),
                "fed without emitting vote1",
            );
            next = peers.next().copied();
        }
        assert_eq!(
            fed_at,
            Some(n),
            "the feed must trigger at exactly full committee coverage",
        );
        assert!(coord.spc.view_one_input_fed());
    }

    /// With the pool short of full coverage, the dwell timer re-arms
    /// (giving a laggard more time) up to `MAX_INPUT_DWELL_REARMS` times,
    /// then feeds whatever is pooled — covering a committee member that
    /// never delivers. A second fire after feeding is a no-op.
    #[test]
    fn input_dwell_timer_rearms_then_feeds_from_partial_pool() {
        let mut coord = fresh_coord();
        let actions = coord.bootstrap_spc_for_next_epoch();
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer {
                    id: TimerId::BeaconSpcInputDwell,
                    ..
                }
            )),
            "bootstrap arms the proposal-collection dwell",
        );
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        let actions = coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(actions.is_empty(), "own proposal alone doesn't kick PC");
        assert!(!coord.spc.view_one_input_fed());

        // Each fire below full coverage re-arms rather than feeding.
        for _ in 0..MAX_INPUT_DWELL_REARMS {
            let actions = coord.on_spc_input_dwell_timer();
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::SetTimer {
                        id: TimerId::BeaconSpcInputDwell,
                        ..
                    }
                )),
                "incomplete coverage re-arms the dwell: {actions:?}",
            );
            assert!(!coord.spc.view_one_input_fed());
        }

        // Re-arm budget exhausted — feed the partial pool.
        let actions = coord.on_spc_input_dwell_timer();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastPcVote1 { .. })),
            "expected SignAndBroadcastPcVote1 in {actions:?}",
        );
        assert!(coord.spc.view_one_input_fed());
        assert!(coord.on_spc_input_dwell_timer().is_empty());
    }

    /// Drive `signer_positions` of `committee`'s keys through one
    /// round each of PC voting to assemble a real `Direct` SPC cert
    /// for `(epoch, prev_view)`.
    fn build_direct_cert(
        prev_view: SpcView,
        epoch: Epoch,
        keys: &[Bls12381G1PrivateKey],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
        signer_positions: &[usize],
        v_in: &PcVector,
    ) -> SpcCert {
        let net = NetworkDefinition::simulator();
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, prev_view);
        let v1s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote1(&keys[i], committee[i].0, &net, &pc_ctx, v_in.clone()))
            .collect();
        let v1_refs: Vec<&_> = v1s.iter().collect();
        let qc1 = build_qc1(&v1_refs, committee);
        let v2s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote2(&keys[i], committee[i].0, &net, &pc_ctx, qc1.clone()))
            .collect();
        let v2_refs: Vec<&_> = v2s.iter().collect();
        let qc2 = build_qc2(&v2_refs, committee);
        let v3s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote3(&keys[i], committee[i].0, &net, &pc_ctx, qc2.clone()))
            .collect();
        let v3_refs: Vec<&_> = v3s.iter().collect();
        let qc3 = build_qc3(&v3_refs, committee);
        let value = qc3.x_pe().clone();
        SpcCert::Direct {
            prev_view,
            value,
            proof: qc3.into(),
        }
    }

    /// Pool-signed commit certificate for `block`: a precommit quorum
    /// over its hash at round 1, signed by every active-pool member's
    /// fixture key.
    fn ratify_cert_for_block(coord: &BeaconCoordinator, block: &BeaconBlock) -> RatifyCert {
        let pool = coord.state.derive_active_pool();
        let net = NetworkDefinition::simulator();
        let votes: Vec<RatifyVote> = pool
            .iter()
            .map(|(id, _)| {
                sign_ratify_vote(
                    &keypair(id.inner()),
                    *id,
                    &net,
                    block.prev_block_hash(),
                    block.epoch(),
                    RatifyRound::INITIAL,
                    RatifyPhase::Precommit,
                    block.block_hash(),
                )
            })
            .collect();
        build_ratify_cert(&votes, &pool).expect("full pool meets quorum")
    }

    /// Build a peer `BeaconBlock` at `epoch` that verifies under
    /// `coord`'s state: an SPC proposal cert from the committee quorum
    /// plus a pool-signed ratify cert over the block's hash.
    fn valid_block_at(
        coord: &BeaconCoordinator,
        epoch: Epoch,
        prev_hash: BeaconBlockHash,
    ) -> Arc<Verifiable<CertifiedBeaconBlock>> {
        let n = coord.state.committee.len();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            epoch,
            &keys,
            &committee,
            &signer_positions,
            &PcVector::empty(),
        );
        let block = BeaconBlock::new(epoch, prev_hash, Vec::new());
        let ratify = ratify_cert_for_block(coord, &block);
        Arc::new(Verifiable::from(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Normal {
                spc: Box::new(cert),
                ratify,
            },
        )))
    }

    /// Like `valid_block_at`, but carrying one committed proposal (a
    /// bare abstention from the position-0 proposer), with the cert
    /// built over the matching element vector. A proposal-less block is
    /// bit-identical to the epoch's skip block — the cert discriminator
    /// rides outside the block hash — so a *diverging* SPC block needs
    /// content.
    fn valid_nonempty_block_at(
        coord: &BeaconCoordinator,
        epoch: Epoch,
        prev_hash: BeaconBlockHash,
    ) -> Arc<Verifiable<CertifiedBeaconBlock>> {
        let n = coord.state.committee.len();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let signer_positions: Vec<usize> = (0..q).collect();
        let proposal = BeaconProposal::new(
            std::iter::once((ShardId::ROOT, None)).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let mut elements = vec![PcValueElement::BOTTOM; n];
        elements[0] = proposal.pc_element_hash(epoch);
        let cert = build_direct_cert(
            SpcView::new(1),
            epoch,
            &keys,
            &committee,
            &signer_positions,
            &PcVector::new(elements),
        );
        let block = BeaconBlock::new(epoch, prev_hash, vec![(committee[0].0, proposal)]);
        let ratify = ratify_cert_for_block(coord, &block);
        Arc::new(Verifiable::from(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Normal {
                spc: Box::new(cert),
                ratify,
            },
        )))
    }

    #[test]
    fn on_beacon_block_received_drops_past_epoch() {
        let mut coord = fresh_coord();
        // A genesis-shaped block at the genesis tip is past-epoch from the
        // tip's perspective. `on_beacon_block_received` should drop it
        // before even inspecting the cert.
        let _prev = coord.latest_block.block_hash();
        let block = Arc::new(Verifiable::from(CertifiedBeaconBlock::genesis(
            GenesisConfigHash::ZERO,
        )));
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_triggers_sync_for_future_epoch() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(5), prev);
        let actions = coord.on_beacon_block_received(block);
        // A block more than one epoch ahead drops and triggers gap-fill
        // sync up to its claimed epoch; the tip doesn't move.
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::StartBeaconBlockSync { target } if target == Epoch::new(5)
        ));
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_drops_wrong_prev_hash() {
        let mut coord = fresh_coord();
        let block = valid_block_at(&coord, Epoch::new(1), BeaconBlockHash::ZERO);
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
    }

    /// Sign one pool member's ratify vote for the pending epoch at
    /// `coord`'s tip.
    fn signed_ratify_vote(
        coord: &BeaconCoordinator,
        signer: u64,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Arc<Verified<RatifyVote>> {
        Arc::new(Verified::<RatifyVote>::sign_local(
            &keypair(signer),
            ValidatorId::new(signer),
            &NetworkDefinition::simulator(),
            coord.latest_block.block_hash(),
            coord.state.current_epoch.next(),
            round,
            phase,
            block_hash,
        ))
    }

    /// Drive `coord` through the skip outcome for the pending epoch:
    /// deadline passed, one verified precommit for the skip hash per
    /// pool member, cert assembly, adoption. Returns the broadcast
    /// skip block.
    fn adopt_skip_block(coord: &mut BeaconCoordinator) -> Arc<Verified<CertifiedBeaconBlock>> {
        pass_skip_deadline(coord);
        let skip_hash = coord.ratify.skip_block_hash();
        let mut adopted = None;
        for i in 0..4u64 {
            let vote = signed_ratify_vote(
                coord,
                i,
                RatifyRound::INITIAL,
                RatifyPhase::Precommit,
                skip_hash,
            );
            let actions = coord.on_verified_ratify_vote_received(vote);
            for action in actions {
                if let Action::BroadcastBeaconBlock { block } = action {
                    adopted = Some(block);
                }
            }
        }
        adopted.expect("pool precommit quorum assembles and adopts the skip block")
    }

    /// Both commit paths assemble for one epoch from honest inputs
    /// alone under asymmetric delivery: one replica adopts the SPC
    /// block, another the skip block, and their chains diverge. On
    /// first contact — the skip block verifying against the SPC
    /// adopter's tip — the replica halts instead of carrying the fork.
    #[test]
    #[should_panic(expected = "beacon dual commit detected")]
    fn normal_and_skip_paths_diverge_then_halt_on_contact() {
        // Replica A commits epoch 1 via the SPC path.
        let mut coord_a = new_coord(ValidatorId::new(0));
        let ed = coord_a.state.chain_config.epoch_duration_ms;
        coord_a.set_now(LocalTimestamp::from_millis(2 * ed));
        let genesis_tip = coord_a.latest_block.block_hash();
        let normal = valid_nonempty_block_at(&coord_a, Epoch::new(1), genesis_tip);
        let dispatched = coord_a.on_beacon_block_received(Arc::clone(&normal));
        let _ = complete_verifications(&mut coord_a, dispatched);
        assert_eq!(coord_a.current_epoch(), Epoch::new(1));

        // Replica B, cut off from the block, skips epoch 1 with the
        // pool quorum.
        let mut coord_b = new_coord(ValidatorId::new(1));
        let skip_block = adopt_skip_block(&mut coord_b);
        assert_eq!(coord_b.current_epoch(), Epoch::new(1));

        // The fork: same epoch, same parent, different blocks.
        assert_ne!(
            coord_a.latest_block.block_hash(),
            coord_b.latest_block.block_hash(),
        );

        // Contact: the skip block reaches A. Its cert is dispatched for
        // verification against the pool that governed epoch 1, and the
        // verified competitor halts the replica.
        let competitor = Arc::new(Verifiable::from(
            Arc::unwrap_or_clone(skip_block).into_inner(),
        ));
        let dispatched = coord_a.on_beacon_block_received(competitor);
        assert!(
            dispatched
                .iter()
                .any(|a| matches!(a, Action::VerifyBeaconBlock { .. })),
            "a tip competitor must be verified, not silently dropped",
        );
        let _ = complete_verifications(&mut coord_a, dispatched);
    }

    /// The reverse contact direction: a replica on the skip branch
    /// verifies the SPC block for the epoch it skipped and halts.
    #[test]
    #[should_panic(expected = "beacon dual commit detected")]
    fn verified_normal_competitor_on_skip_tip_halts() {
        let mut coord = fresh_coord();
        let genesis_tip = coord.latest_block.block_hash();
        // Built against the genesis-time committee — the set the tip
        // epoch's competitor verification uses.
        let normal = valid_nonempty_block_at(&coord, Epoch::new(1), genesis_tip);

        let _ = adopt_skip_block(&mut coord);
        assert_eq!(coord.current_epoch(), Epoch::new(1));

        let dispatched = coord.on_beacon_block_received(normal);
        assert!(
            dispatched
                .iter()
                .any(|a| matches!(a, Action::VerifyBeaconBlock { .. })),
        );
        let _ = complete_verifications(&mut coord, dispatched);
    }

    /// Committing an epoch resets ratification for the next one:
    /// pooled votes at the prior tip don't survive into the new
    /// instance — otherwise every epoch that saw votes before
    /// committing would leak them into the next epoch's counting.
    #[test]
    fn commit_resets_ratification_for_the_new_epoch() {
        let mut coord = fresh_coord();
        let genesis_tip = coord.latest_block.block_hash();
        // A vote pooled at the genesis tip for the in-flight epoch.
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = signed_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        let _ = coord.on_verified_ratify_vote_received(vote);
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            1
        );

        // Commit epoch 1 normally (a valid peer block chaining off genesis).
        let block = valid_block_at(&coord, Epoch::new(1), genesis_tip);
        let dispatched = coord.on_beacon_block_received(block);
        let _ = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.current_epoch(), Epoch::new(1));
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0,
            "the new epoch's tracker starts empty",
        );
    }

    #[test]
    fn on_beacon_block_received_dispatches_then_adopts_valid_peer_block() {
        let mut coord = fresh_coord();
        // Wall-clock past the boundary of the epoch *after* the one we adopt,
        // so the self-perpetuation gate is in catch-up mode and bootstraps the
        // next epoch's SPC.
        let ed = coord.state.chain_config.epoch_duration_ms;
        coord.set_now(LocalTimestamp::from_millis(2 * ed));
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let block_hash = block.block_hash();
        let dispatched = coord.on_beacon_block_received(Arc::clone(&block));

        // Cert verification is offloaded — the immediate handler emits
        // exactly one `VerifyBeaconBlock` action.
        let [Action::VerifyBeaconBlock { .. }] = dispatched.as_slice() else {
            panic!("expected single VerifyBeaconBlock, got {dispatched:?}");
        };
        assert!(coord.verification.is_block_in_flight(block_hash));

        let actions = complete_verifications(&mut coord, dispatched);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {actions:?}",
        );
        // Adoption skips re-broadcast — peer is disseminating.
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
            "adoption path should not re-broadcast",
        );
        assert_eq!(coord.state.current_epoch, Epoch::new(1));
        assert_eq!(coord.latest_block.block_hash(), block_hash);
        assert!(!coord.verification.is_block_in_flight(block_hash));
        assert!(
            coord.spc.is_bootstrapped(),
            "next epoch's SPC should bootstrap"
        );
    }

    /// The beacon paces epoch production to wall-clock instead of racing ahead
    /// at SPC-round speed. After committing an epoch while still caught up to
    /// real time, an on-committee node leaves SPC idle and arms
    /// `BeaconCommitteeStart` for the next boundary; once wall-clock reaches it
    /// and the timer fires, SPC bootstraps. Without this the beacon's synthetic
    /// per-epoch clock (`epoch × epoch_duration_ms`) outruns the shards'
    /// weighted-time past the schedule's retention window and wedges them.
    #[test]
    fn adopt_paces_next_epoch_to_wall_clock_then_resumes_at_boundary() {
        let mut coord = fresh_coord();
        // `fresh_coord` is at now = 0, before any epoch boundary.
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(Arc::clone(&block));
        let actions = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.state.current_epoch, Epoch::new(1));
        assert!(
            !coord.spc.is_bootstrapped(),
            "caught up to wall-clock: must not bootstrap the next epoch's SPC early",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer {
                    id: TimerId::BeaconCommitteeStart,
                    ..
                }
            )),
            "must arm BeaconCommitteeStart for the boundary, got {actions:?}",
        );

        // Wall-clock reaches the boundary and the timer fires: SPC bootstraps.
        coord.set_now(coord.next_epoch_boundary());
        coord.on_beacon_committee_start_timer();
        assert!(
            coord.spc.is_bootstrapped(),
            "the armed BeaconCommitteeStart must bootstrap SPC once its boundary arrives",
        );
    }

    #[test]
    fn off_committee_observer_adopts_valid_peer_block() {
        let mut observer = new_coord(ValidatorId::new(99));
        let prev = observer.latest_block.block_hash();
        let block = valid_block_at(&observer, Epoch::new(1), prev);
        let block_hash = block.block_hash();

        let dispatched = observer.on_beacon_block_received(Arc::clone(&block));
        let actions = complete_verifications(&mut observer, dispatched);
        // Off-committee observers still advance state via apply_epoch.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {actions:?}",
        );
        assert_eq!(observer.current_epoch(), Epoch::new(1));
        assert_eq!(observer.latest_block().block_hash(), block_hash);
        // Off-committee, so no SPC bootstrap for the next epoch.
        assert!(!observer.spc.is_bootstrapped());
    }

    /// Off-committee observers stay in sync across multiple epochs:
    /// each block chains off the previous adopted block's hash, and
    /// state keeps advancing. The committee derives from `self.state`
    /// at each call, so a stale observer can verify every successor
    /// block as long as it adopted the predecessor.
    #[test]
    fn off_committee_observer_chain_tracks_across_multiple_epochs() {
        let mut observer = new_coord(ValidatorId::new(99));

        for epoch in 1u64..=3 {
            let prev = observer.latest_block.block_hash();
            let block = valid_block_at(&observer, Epoch::new(epoch), prev);
            let block_hash = block.block_hash();
            let dispatched = observer.on_beacon_block_received(Arc::clone(&block));
            let actions = complete_verifications(&mut observer, dispatched);
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
                "epoch {epoch}: expected CommitBeaconBlock in {actions:?}",
            );
            assert_eq!(observer.current_epoch(), Epoch::new(epoch));
            assert_eq!(observer.latest_block().block_hash(), block_hash);
        }
        assert!(!observer.spc.is_bootstrapped());
    }

    /// Adoption prunes buffered equivocation evidence for validators the
    /// fold now holds permanently jailed — their jail can't be upgraded
    /// further, so re-proposing the evidence would only waste block
    /// space. Evidence for other validators stays buffered.
    #[test]
    fn adopt_prunes_evidence_for_permanently_jailed_validators() {
        use hyperscale_types::{Bls12381G2Signature, PcVoteRound};
        let mut coord = fresh_coord();
        let evidence = |v: u64| PcVoteEquivocation {
            validator: ValidatorId::new(v),
            epoch: Epoch::new(1),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::empty(),
            sig_a: Bls12381G2Signature([0x11; 96]),
            value_b: PcVector::empty(),
            sig_b: Bls12381G2Signature([0x22; 96]),
        };
        assert!(coord.equivocations.record_pc_equivocation(evidence(1)));
        assert!(coord.equivocations.record_pc_equivocation(evidence(2)));
        // Validator 1's jail is already permanent by the time the next
        // block applies.
        coord
            .state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Equivocation,
        };

        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(block);
        let _ = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.current_epoch(), Epoch::new(1));
        assert!(!coord.equivocations.contains(ValidatorId::new(1)));
        assert!(coord.equivocations.contains(ValidatorId::new(2)));
    }

    /// A commit that rotates the local validator off the beacon
    /// committee drops the pooled witness chunks and releases in-flight
    /// witness fetches as `FetchAbandon::ShardWitnesses`, so the
    /// runner's fetch slots don't pin on payloads an off-committee vnode
    /// no longer wants.
    #[test]
    fn adopt_releases_witness_state_when_local_falls_off_committee() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let anchor = BlockHash::from_raw(Hash::from_bytes(b"witness-anchor"));
        let height = BlockHeight::new(5);
        let leaf = LeafIndex::new(0);
        assert!(
            coord
                .shard_source
                .register_pending_fetch(shard, height, anchor, leaf)
        );

        // Jail the local validator so the post-apply resample drops it
        // from the beacon committee.
        coord.state.validators.get_mut(&coord.me).unwrap().status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };

        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(block);
        let actions = complete_verifications(&mut coord, dispatched);

        assert!(!coord.is_on_committee());
        assert!(!coord.shard_source.is_pending_fetch(shard, anchor, leaf));
        let abandoned = actions.iter().any(|a| {
            matches!(
                a,
                Action::AbandonFetch(FetchAbandon::ShardWitnesses { ids })
                    if ids.contains(&(shard, height, anchor, leaf))
            )
        });
        assert!(
            abandoned,
            "expected FetchAbandon::ShardWitnesses naming the in-flight fetch, got {actions:?}",
        );
    }

    /// A committed element whose digest diverges from the locally-pooled
    /// proposal — the fingerprint of a proposer that equivocated its
    /// proposal across the committee — must not assemble and adopt a
    /// block locally. Such a block omits the committed position, fails
    /// the committed-proposal binding every verifier runs, and would fork
    /// this node off the canonical chain. The decode defers to a fetch
    /// instead, leaving the tip unmoved until the canonical block arrives
    /// via gossip.
    #[test]
    fn output_high_defers_when_committed_proposal_diverges_from_pool() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();

        // Pool a proposal for every committee member, then commit a value
        // whose element at position 1 carries a different variant's digest
        // — what a peer that admitted the proposer's other equivocated
        // proposal would have committed.
        let divergent_pos = 1;
        let mut elements = Vec::with_capacity(n);
        for (pos, id) in committee.iter().enumerate() {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            let committed_hash = if pos == divergent_pos {
                sample_proposal(0xFF).pc_element_hash(in_flight)
            } else {
                p.pc_element_hash(in_flight)
            };
            elements.push(committed_hash);
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            in_flight,
            &keys,
            &cert_committee,
            &signer_positions,
            &PcVector::empty(),
        );

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );

        // The divergent position can't be reconstructed locally, so the
        // node fetches it rather than adopting a fork: no commit, tip
        // unmoved, and a BeaconProposal fetch for the divergent proposer.
        let kinds: Vec<&str> = actions.iter().map(Action::type_name).collect();
        assert!(
            !kinds.contains(&"CommitBeaconBlock"),
            "must not adopt a block omitting a committed position, got {kinds:?}",
        );
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
        let fetches_divergent = actions.iter().any(|a| {
            matches!(
                a,
                Action::Fetch(FetchRequest::BeaconProposal { validator, .. })
                    if *validator == committee[divergent_pos]
            )
        });
        assert!(
            fetches_divergent,
            "expected a BeaconProposal fetch for the divergent proposer, got {kinds:?}",
        );
    }

    /// `on_spc_output_high` broadcasts a candidate and prevotes its
    /// hash: the SPC cert authenticates the content, but nothing
    /// commits until the pool's ratify cert assembles — no
    /// `CommitBeaconBlock`, no epoch advance.
    #[test]
    fn output_high_broadcasts_candidate_and_prevotes() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        // Construct a verifying cert the way the SPC FSM would produce
        // it — same machinery `valid_block_at` uses.
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            in_flight,
            &keys,
            &cert_committee,
            &signer_positions,
            &PcVector::empty(),
        );

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );

        // The SPC cert authenticates the content only: OutputHigh
        // produces the candidate broadcast plus the local prevote for
        // its hash — commitment waits for the pool.
        let kinds: Vec<&str> = actions.iter().map(Action::type_name).collect();
        assert!(
            !kinds.contains(&"CommitBeaconBlock"),
            "nothing commits before the ratify cert, got {kinds:?}",
        );
        assert!(
            kinds.contains(&"BroadcastBeaconCandidate"),
            "expected BroadcastBeaconCandidate in {kinds:?}",
        );
        let candidate_hash = coord
            .ratify
            .candidate()
            .expect("the assembled candidate's hash feeds the tracker");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SignAndBroadcastRatifyVote { phase: RatifyPhase::Prevote, block_hash, .. }
                    if *block_hash == candidate_hash
            )),
            "expected a prevote for the candidate's hash in {actions:?}",
        );
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS, "no adoption");
    }

    /// Ratifying the candidate commits it: once a precommit quorum for
    /// the candidate's hash pools, the coordinator pairs the held
    /// candidate with the cert, adopts, and broadcasts the certified
    /// block.
    #[test]
    fn precommit_quorum_over_candidate_commits_the_normal_block() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            in_flight,
            &keys,
            &cert_committee,
            &signer_positions,
            &PcVector::empty(),
        );
        let recipients = coord.spc_recipients();
        let _ = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );
        let candidate_hash = coord.ratify.candidate().expect("candidate held");

        let mut emitted: Vec<Action> = Vec::new();
        for i in 0..u64::try_from(n).unwrap() {
            let vote = signed_ratify_vote(
                &coord,
                i,
                RatifyRound::INITIAL,
                RatifyPhase::Precommit,
                candidate_hash,
            );
            emitted.extend(coord.on_verified_ratify_vote_received(vote));
        }

        assert_eq!(coord.state.current_epoch, in_flight);
        assert_eq!(coord.latest_block.epoch(), in_flight);
        assert!(matches!(
            coord.latest_block.cert(),
            BeaconCert::Normal { .. }
        ));
        let kinds: Vec<&str> = emitted.iter().map(Action::type_name).collect();
        assert!(
            kinds.contains(&"CommitBeaconBlock") && kinds.contains(&"BroadcastBeaconBlock"),
            "expected commit + broadcast after ratification, got {kinds:?}",
        );
    }

    /// Wrap a signed ratify vote for the wire receive shape.
    fn wire_ratify_vote(
        coord: &BeaconCoordinator,
        signer: u64,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Arc<Verifiable<RatifyVote>> {
        let vote = signed_ratify_vote(coord, signer, round, phase, block_hash);
        Arc::new(Verifiable::from(Arc::unwrap_or_clone(vote).into_inner()))
    }

    /// Ratify votes carry no deadline gate: a candidate prevote before
    /// the epoch's skip deadline is the happy path, so the wire intake
    /// dispatches its verification straight away. The clock discipline
    /// lives in the local validator's own votes, not in what it pools.
    #[test]
    fn pre_deadline_prevotes_dispatch_verification() {
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        // Clock at genesis: the deadline (boundary + SKIP_TIMEOUT) is
        // far in the future.
        let wire = wire_ratify_vote(
            &coord,
            1,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        assert!(
            coord
                .on_unverified_ratify_vote_received(wire)
                .iter()
                .any(|a| matches!(a, Action::VerifyRatifyVote { .. })),
            "a pre-deadline vote must still be delegated for verification",
        );
    }

    #[test]
    fn on_ratify_vote_drops_at_wrong_anchor() {
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = signed_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        // Re-sign against a foreign anchor: zero hash isn't the tip.
        let foreign = Arc::new(Verifiable::from(RatifyVote::new(
            BeaconBlockHash::ZERO,
            vote.epoch(),
            vote.round(),
            vote.phase(),
            vote.block_hash(),
            vote.signer(),
            vote.sig(),
        )));
        let actions = coord.on_unverified_ratify_vote_received(foreign);
        assert!(actions.is_empty());
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_triggers_sync_for_future_epoch() {
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = signed_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        let future_epoch = Arc::new(Verifiable::from(RatifyVote::new(
            vote.anchor_hash(),
            Epoch::new(99),
            vote.round(),
            vote.phase(),
            vote.block_hash(),
            vote.signer(),
            vote.sig(),
        )));
        let actions = coord.on_unverified_ratify_vote_received(future_epoch);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::StartBeaconBlockSync { target } if *target == Epoch::new(98)
            )),
            "a vote ratifying a future epoch reveals missing beacon blocks \
             and must trigger gap-fill sync toward its anchor epoch; got {actions:?}",
        );
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_at_stale_epoch() {
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = signed_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        let stale_epoch = Arc::new(Verifiable::from(RatifyVote::new(
            vote.anchor_hash(),
            Epoch::GENESIS,
            vote.round(),
            vote.phase(),
            vote.block_hash(),
            vote.signer(),
            vote.sig(),
        )));
        let actions = coord.on_unverified_ratify_vote_received(stale_epoch);
        assert!(actions.is_empty());
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_non_pool_signer() {
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = wire_ratify_vote(
            &coord,
            99,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        let actions = coord.on_unverified_ratify_vote_received(vote);
        assert!(actions.is_empty());
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_invalid_sig_via_async_result() {
        use hyperscale_types::Bls12381G2Signature;
        let mut coord = fresh_coord();
        let skip_hash = coord.ratify.skip_block_hash();
        // Signer 0 is in the pool, but sig is all-zeros — verification
        // returns false on the result path.
        let vote = Arc::new(Verifiable::from(RatifyVote::new(
            coord.latest_block.block_hash(),
            coord.state.current_epoch.next(),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
            ValidatorId::new(0),
            Bls12381G2Signature([0u8; 96]),
        )));
        let dispatched = coord.on_unverified_ratify_vote_received(vote);
        // Synchronous validation passes (signer in pool, anchor + epoch
        // match) — so a verify action is dispatched.
        let [Action::VerifyRatifyVote { .. }] = dispatched.as_slice() else {
            panic!("expected single VerifyRatifyVote, got {dispatched:?}");
        };
        let actions = complete_verifications(&mut coord, dispatched);
        assert!(actions.is_empty(), "invalid sig should drop on result");
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_admits_valid_vote_below_quorum() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let skip_hash = coord.ratify.skip_block_hash();
        let vote = wire_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Precommit,
            skip_hash,
        );
        let dispatched = coord.on_unverified_ratify_vote_received(vote);
        let actions = complete_verifications(&mut coord, dispatched);
        assert!(actions.is_empty());
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Precommit),
            1,
            "vote must land in the tracker after verification",
        );
        // n=4 → quorum is ⌈8/3⌉+1 = 4. One sig is below.
        assert!(
            coord.spc.is_bootstrapped(),
            "SPC still running below quorum"
        );
    }

    /// A precommit quorum for the skip hash at the local tip builds +
    /// adopts the skip block, broadcasts it, advances the epoch
    /// counter, and clears the SPC instance for the abandoned epoch
    /// (the next epoch's SPC bootstraps on adoption since the local
    /// node remains on the committee).
    #[test]
    fn precommit_quorum_assembles_cert_and_adopts_skip_block() {
        let mut coord = fresh_coord();
        pass_skip_deadline(&mut coord);
        coord.bootstrap_spc_for_next_epoch();
        let anchor = coord.latest_block.block_hash();
        let epoch_to_skip = coord.state.current_epoch.next();
        let skip_hash = coord.ratify.skip_block_hash();
        let n = coord.state.committee.len();

        let votes: Vec<_> = (0..u64::try_from(n).unwrap())
            .map(|i| {
                wire_ratify_vote(
                    &coord,
                    i,
                    RatifyRound::INITIAL,
                    RatifyPhase::Precommit,
                    skip_hash,
                )
            })
            .collect();
        let mut emitted: Vec<Action> = Vec::new();
        for vote in votes {
            let dispatched = coord.on_unverified_ratify_vote_received(vote);
            emitted.extend(complete_verifications(&mut coord, dispatched));
        }

        // Adoption happened: epoch advanced past the skipped one.
        assert_eq!(coord.state.current_epoch, epoch_to_skip);
        // Tip now points at the Skip block, committed by a ratify cert
        // naming the previous tip as anchor.
        let BeaconCert::Skip(cert) = coord.latest_block.cert() else {
            panic!("expected a Skip cert at the tip");
        };
        assert_eq!(cert.anchor_hash(), anchor);
        assert_eq!(cert.epoch(), epoch_to_skip);
        assert_eq!(cert.block_hash(), skip_hash);
        // Broadcast emitted for peers.
        assert!(
            emitted
                .iter()
                .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
            "expected BroadcastBeaconBlock in {emitted:?}",
        );
        // Commit emitted alongside.
        assert!(
            emitted
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {emitted:?}",
        );
        // Ratification restarted for the new pending epoch.
        assert_eq!(
            coord
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Precommit),
            0
        );
    }

    /// A late duplicate vote against the pre-adoption anchor is
    /// dropped by the anchor-mismatch check — the adoption path's
    /// `apply_epoch` regression check would panic if the coordinator
    /// tried to re-adopt.
    #[test]
    fn duplicate_vote_after_adoption_is_noop() {
        let mut coord = fresh_coord();
        pass_skip_deadline(&mut coord);
        coord.bootstrap_spc_for_next_epoch();
        let skip_hash = coord.ratify.skip_block_hash();
        let n = coord.state.committee.len();

        let stale = wire_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Precommit,
            skip_hash,
        );
        for i in 0..u64::try_from(n).unwrap() {
            let vote = wire_ratify_vote(
                &coord,
                i,
                RatifyRound::INITIAL,
                RatifyPhase::Precommit,
                skip_hash,
            );
            let dispatched = coord.on_unverified_ratify_vote_received(vote);
            let _ = complete_verifications(&mut coord, dispatched);
        }
        // The tip's anchor has moved on.
        let actions = coord.on_unverified_ratify_vote_received(stale);
        assert!(actions.is_empty(), "stale anchor must be a no-op");
    }

    /// A commit certificate for a candidate this replica never held
    /// settles the epoch without adopting (the assembler's broadcast
    /// delivers the block); until it arrives, the SPC dispatch gate
    /// drops further SPC events for the already-decided epoch.
    #[test]
    fn dispatch_spc_event_gated_once_epoch_settles() {
        use hyperscale_types::Hash;
        let mut coord = fresh_coord();
        pass_skip_deadline(&mut coord);
        coord.bootstrap_spc_for_next_epoch();
        let n = coord.state.committee.len();
        // A candidate hash the local replica never verified.
        let unheld = BeaconBlockHash::from_raw(Hash::from_bytes(b"unheld-candidate"));

        for i in 0..u64::try_from(n).unwrap() {
            let vote = signed_ratify_vote(
                &coord,
                i,
                RatifyRound::INITIAL,
                RatifyPhase::Precommit,
                unheld,
            );
            let _ = coord.on_verified_ratify_vote_received(vote);
        }
        assert!(coord.ratify.is_completed(), "the epoch is decided");
        assert_eq!(
            coord.state.current_epoch,
            Epoch::GENESIS,
            "nothing adopted without the block",
        );

        // SPC dispatch is now gated — the view timer drops without
        // dispatching into the FSM (no broadcast actions).
        let actions = coord.on_beacon_spc_view_timer();
        assert!(actions.is_empty(), "gated dispatch must emit no actions");
        // The SPC instance stays Some — gate is query-based, not
        // state-based.
        assert!(coord.spc.is_bootstrapped());
    }

    /// Build a (witness, source-shard verified header) pair where the
    /// witness's Merkle proof verifies under the header's
    /// `beacon_witness_root`. `total_leaves` controls the accumulator
    /// size; `leaf_index` picks which slot belongs to our witness.
    fn make_verifiable_witness_and_header(
        shard: ShardId,
        height: u64,
        leaf_index: u64,
        total_leaves: u64,
    ) -> (Arc<ShardWitness>, Arc<Verified<CertifiedBlockHeader>>) {
        use hyperscale_types::{
            BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
            CertificateRoot, Hash, InFlightCount, LeafIndex, LocalReceiptRoot, ProposerTimestamp,
            ProvisionsRoot, QuorumCertificate, Round, ShardWitnessPayload, ShardWitnessProof,
            SignerBitfield, StateRoot, TransactionRoot, WeightedTimestamp,
            compute_merkle_root_with_proof, zero_bls_signature,
        };
        let payload = ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(0),
            amount: Stake::from_whole_tokens(1),
        };
        let our_leaf = payload.leaf_hash();
        let mut leaves: Vec<Hash> = (0..total_leaves)
            .map(|i| Hash::from_bytes(format!("leaf-{i}").as_bytes()))
            .collect();
        let leaf_idx_usize = usize::try_from(leaf_index).unwrap();
        leaves[leaf_idx_usize] = our_leaf;
        let (root, siblings, _) = compute_merkle_root_with_proof(&leaves, leaf_idx_usize);
        let beacon_root = BeaconWitnessRoot::from_raw(root);

        let parent_qc = QuorumCertificate::genesis(shard, ChainOrigin::ROOT);
        let parent_block_hash = BlockHash::ZERO;
        let header = BlockHeader::new(
            shard,
            BlockHeight::new(height),
            parent_block_hash,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            beacon_root,
            BeaconWitnessLeafCount::new(total_leaves),
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            parent_block_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(1_000),
        );
        let certified_header = Arc::new(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(header, qc),
        ));

        let proof = ShardWitnessProof {
            shard_id: shard,
            committed_block_hash: block_hash,
            leaf_index: LeafIndex::new(leaf_index),
            siblings: siblings.into(),
        };
        let witness = Arc::new(ShardWitness { payload, proof });
        (witness, certified_header)
    }

    /// An observed crossing whose boundary block holds far more
    /// accumulator leaves than the beacon has applied enqueues at most
    /// `MAX_WITNESSES_PER_FETCH` leaves per call — the chunk fetch is a
    /// bounded window `[prior, prior + MAX)` anchored to the boundary
    /// block, not the full applied/boundary gap. The remainder is picked
    /// up on later observations as the watermark advances.
    #[test]
    fn on_verified_source_header_caps_leaf_fetch_window() {
        use hyperscale_types::{MAX_WITNESSES_PER_FETCH, ShardId};
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);

        // A `(B, C)` crossing of the epoch-1 cut: `B`'s predecessor sits
        // at wt 1 (≤ the 300_000 ms cut) and `B`'s own wt is 300_001 (past
        // it), with a large accumulator at `B`.
        let total_leaves = u64::try_from(MAX_WITNESSES_PER_FETCH + 50).unwrap();
        let b = linked_block_header(shard, 5, BlockHash::ZERO, 1, total_leaves);
        let c = linked_block_header(shard, 6, b.block_hash(), 300_001, total_leaves);
        coord.on_verified_source_header(&b);
        let actions = coord.on_verified_source_header(&c);

        let leaf_indices = actions
            .iter()
            .find_map(|a| match a {
                Action::Fetch(FetchRequest::ShardWitnesses { leaf_indices, .. }) => {
                    Some(leaf_indices)
                }
                _ => None,
            })
            .expect("expected a ShardWitnesses fetch");
        assert_eq!(leaf_indices.len(), MAX_WITNESSES_PER_FETCH);
        // Contiguous 0-based window `[0, MAX)` from the applied watermark.
        assert_eq!(leaf_indices.first().copied(), Some(LeafIndex::new(0)));
        assert_eq!(
            leaf_indices.last().copied(),
            Some(LeafIndex::new(MAX_WITNESSES_PER_FETCH as u64 - 1)),
        );
    }

    #[test]
    fn on_shard_witnesses_received_admits_valid_witness() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let (witness, header) = make_verifiable_witness_and_header(shard, 1, 2, 4);
        coord
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        let actions = coord.on_shard_witnesses_received(shard, vec![Arc::clone(&witness)]);
        assert!(actions.is_empty());
        assert_eq!(coord.shard_source.total_chunk_len(), 1);
    }

    #[test]
    fn on_shard_witnesses_received_drops_mismatched_shard_id() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let other = ShardId::leaf(1, 1);
        let (witness, header) = make_verifiable_witness_and_header(shard, 1, 2, 4);
        coord
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        // Witness is for `shard` but envelope claims `other`.
        let actions = coord.on_shard_witnesses_received(other, vec![witness]);
        assert!(actions.is_empty());
        assert_eq!(coord.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn on_shard_witnesses_received_drops_unknown_committed_block() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        // Build a witness pointing at a block hash that no header
        // record exists for (we never call on_verified_source_header).
        let (witness, _header) = make_verifiable_witness_and_header(shard, 1, 0, 1);

        let actions = coord.on_shard_witnesses_received(shard, vec![witness]);
        assert!(actions.is_empty());
        assert_eq!(coord.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn on_shard_witnesses_received_drops_bad_merkle_proof() {
        use hyperscale_types::{LeafIndex, ShardId};
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let (witness, header) = make_verifiable_witness_and_header(shard, 1, 2, 4);
        coord
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        // Tamper with the witness's leaf_index so the path no longer
        // reconstructs the committed root.
        let mut tampered_proof = witness.proof.clone();
        tampered_proof.leaf_index = LeafIndex::new(0);
        let bad = Arc::new(ShardWitness {
            payload: witness.payload.clone(),
            proof: tampered_proof,
        });
        let actions = coord.on_shard_witnesses_received(shard, vec![bad]);
        assert!(actions.is_empty());
        assert_eq!(coord.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn on_shard_witnesses_received_off_committee_drops_all() {
        use hyperscale_types::ShardId;
        // Validator 99 isn't on the committee.
        let mut observer = new_coord(ValidatorId::new(99));
        let shard = ShardId::leaf(1, 0);
        let (witness, header) = make_verifiable_witness_and_header(shard, 1, 0, 1);
        observer
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        let actions = observer.on_shard_witnesses_received(shard, vec![witness]);
        assert!(actions.is_empty());
        // Pool stays empty — off-committee never admits witnesses.
        assert_eq!(observer.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn current_topology_snapshot_reflects_genesis_state() {
        let coord = fresh_coord();
        let snap = coord.current_topology_snapshot();
        // 4 validators all on the ROOT genesis shard.
        assert_eq!(snap.num_shards(), 1);
        assert_eq!(snap.committee_for_shard(ShardId::ROOT).len(), 4);
    }

    // ─── topology schedule + resolver ────────────────────────────────────

    /// A state at `epoch` whose ROOT genesis-shard committee (active and
    /// lookahead) holds `size` members, so snapshots derived for different
    /// epochs are distinguishable by committee size.
    fn state_at(epoch: u64, size: u64) -> BeaconState {
        let mut s = build_genesis_beacon_state(&sample_genesis());
        s.current_epoch = Epoch::new(epoch);
        let committee = ShardCommittee {
            members: (0..size).map(ValidatorId::new).collect(),
        };
        s.shard_committees.insert(ShardId::ROOT, committee.clone());
        s.next_shard_committees.insert(ShardId::ROOT, committee);
        s.shard_consensus_members = s.ready_consensus_members(&s.shard_committees);
        s
    }

    fn coord_from_history(history: Vec<BeaconState>) -> BeaconCoordinator {
        let (block, _genesis_state, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            block,
            history,
            ValidatorId::new(0),
            ShardId::ROOT,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            config_hash,
        )
    }

    /// The schedule resolves each loaded window plus the one-epoch
    /// lookahead, keyed correctly to its committee, and returns `None`
    /// past the lookahead or below the loaded history. The head is the
    /// newest active window.
    #[test]
    fn topology_schedule_resolves_active_lookahead_and_none_beyond() {
        let coord = coord_from_history(vec![state_at(1, 4), state_at(2, 3), state_at(3, 2)]);
        let ed = coord.current_state().chain_config.epoch_duration_ms;
        let shard = ShardId::ROOT;
        let len_at = |window: u64| {
            coord
                .topology_schedule()
                .at(WeightedTimestamp::from_millis(window * ed))
                .map(|t| t.committee_for_shard(shard).len())
        };
        assert_eq!(len_at(1), Some(4)); // active for epoch 1
        assert_eq!(len_at(2), Some(3)); // epoch 2
        assert_eq!(len_at(3), Some(2)); // epoch 3 (newest active)
        assert_eq!(len_at(4), Some(2)); // epoch 3's lookahead
        assert_eq!(len_at(5), None); // beyond the lookahead
        assert_eq!(len_at(0), None); // below the loaded history
        assert_eq!(
            coord
                .current_topology_snapshot()
                .committee_for_shard(shard)
                .len(),
            2
        );
    }

    /// Construction retains every loaded state — the runner bounds what it
    /// loads via [`retention_floor`], and `adopt_block` trims forward from
    /// there as the consumer frontiers advance.
    #[test]
    fn construction_retains_the_full_loaded_history() {
        let history: Vec<BeaconState> = (0..=8).map(|e| state_at(e, 4)).collect();
        let coord = coord_from_history(history);
        let ed = coord.current_state().chain_config.epoch_duration_ms;
        let resolves = |window: u64| {
            coord
                .topology_schedule()
                .at(WeightedTimestamp::from_millis(window * ed))
                .is_some()
        };
        assert!(resolves(0), "oldest loaded epoch retained");
        assert!(resolves(8), "newest epoch retained");
    }

    fn boundary_live_at(epoch: u64) -> ShardBoundary {
        ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            last_live_epoch: Epoch::new(epoch),
            consecutive_misses: 0,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
            reshape_admitted_epoch: None,
        }
    }

    fn boundary_terminal_at(epoch: u64) -> ShardBoundary {
        ShardBoundary {
            terminal_epoch: Some(Epoch::new(epoch)),
            ..boundary_live_at(epoch)
        }
    }

    /// Each consumer frontier can become the floor: the lagging one wins.
    #[test]
    fn retention_floor_is_the_minimum_consumer_frontier() {
        let shard = ShardId::ROOT;
        let mut state = state_at(1000, 4);
        state.boundaries.insert(shard, boundary_live_at(999));
        let ed = state.chain_config.epoch_duration_ms;
        let wt = |epoch: u64| WeightedTimestamp::from_millis(epoch * ed);
        let local_now = |epoch: u64| LocalTimestamp::from_millis(epoch * ed);

        // A lagging local shard chain holds the floor at its anchor.
        assert_eq!(
            retention_floor(&state, wt(5), local_now(1000)),
            Epoch::new(5)
        );

        // A stalled shard's boundary holds the floor one window before its
        // last live epoch.
        state.boundaries.insert(shard, boundary_live_at(7));
        assert_eq!(
            retention_floor(&state, wt(1000), local_now(1000)),
            Epoch::new(6)
        );

        // A shard with no boundary record yet pins the floor at genesis.
        state.boundaries.remove(&shard);
        assert_eq!(
            retention_floor(&state, wt(1000), local_now(1000)),
            Epoch::GENESIS
        );
    }

    /// With every chain frontier at the head, the tx-artifact horizon
    /// (`now − RETENTION_HORIZON`) is the floor.
    #[test]
    fn retention_floor_defaults_to_the_artifact_horizon() {
        let shard = ShardId::ROOT;
        let mut state = state_at(1000, 4);
        state.boundaries.insert(shard, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let now_ms = 1000 * ed;
        let floor = retention_floor(
            &state,
            WeightedTimestamp::from_millis(now_ms),
            LocalTimestamp::from_millis(now_ms),
        );
        let horizon = Epoch::new(now_ms.saturating_sub(RETENTION_HORIZON.as_secs() * 1000) / ed);
        assert_eq!(floor, horizon);
        assert!(floor < Epoch::new(1000), "horizon trails the head");
    }

    /// A reshape predecessor's terminal boundary record holds the floor at its
    /// last live epoch even after it leaves the live committees — its schedule
    /// window must outlive the record so straggling observers can snap-sync its
    /// anchor and the coasting predecessor can resolve its own committee through
    /// the beacon-fold lag before it observes its successors live.
    #[test]
    fn retention_floor_holds_a_terminal_predecessors_window() {
        let mut state = state_at(1000, 4);
        state
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let head = WeightedTimestamp::from_millis(1000 * ed);
        let now = LocalTimestamp::from_millis(1000 * ed);

        let without = retention_floor(&state, head, now);

        // A dropped predecessor — not in the live committees — with a terminal
        // record last live at epoch 100 pins the floor to 99, below the
        // artifact horizon that would otherwise bind.
        let predecessor = ShardId::leaf(2, 0);
        assert!(!state.shard_committees.contains_key(&predecessor));
        state
            .boundaries
            .insert(predecessor, boundary_terminal_at(100));
        let with = retention_floor(&state, head, now);

        assert!(with < without, "the terminal record lowers the floor");
        assert_eq!(
            with,
            Epoch::new(99),
            "to its last live epoch minus a window"
        );
    }

    #[test]
    fn adopt_block_refreshes_topology_snapshot_and_emits_topology_changed() {
        let mut coord = fresh_coord();
        let pre_snap = Arc::clone(coord.current_topology_snapshot());

        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            in_flight,
            &keys,
            &cert_committee,
            &signer_positions,
            &PcVector::empty(),
        );

        let recipients = coord.spc_recipients();
        let _ = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );
        // Ratify the candidate: adoption (and the topology refresh)
        // happens at the pool's commit certificate.
        let candidate_hash = coord.ratify.candidate().expect("candidate held");
        let mut actions: Vec<Action> = Vec::new();
        for i in 0..u64::try_from(n).unwrap() {
            let vote = signed_ratify_vote(
                &coord,
                i,
                RatifyRound::INITIAL,
                RatifyPhase::Precommit,
                candidate_hash,
            );
            actions.extend(coord.on_verified_ratify_vote_received(vote));
        }

        let topology_changed: Vec<&Action> = actions
            .iter()
            .filter(|a| matches!(a, Action::TopologyChanged { .. }))
            .collect();
        assert_eq!(
            topology_changed.len(),
            1,
            "expected exactly one TopologyChanged per commit, got {}",
            topology_changed.len(),
        );

        // Cached snapshot was rebuilt — Arc pointer differs from the
        // pre-commit one (both Arcs wrap freshly-derived snapshots).
        let post_snap = Arc::clone(coord.current_topology_snapshot());
        assert!(!Arc::ptr_eq(&pre_snap, &post_snap));
    }

    // ─── participation delta detection ───────────────────────────────────

    /// Genesis seeds identical active and lookahead committees, so a
    /// fresh coordinator detects no placement delta.
    #[test]
    fn participation_delta_none_when_views_agree() {
        let coord = fresh_coord();
        assert_eq!(coord.participation_delta(&SlotEffects::default()), None);
    }

    /// A lookahead that moves the local validator from the ROOT shard to
    /// a sibling yields exactly that join/leave pair, effective at the
    /// next epoch's window.
    #[test]
    fn participation_delta_detects_relocation() {
        let mut coord = fresh_coord();
        let from = ShardId::ROOT;
        let to = ShardId::leaf(1, 1);
        let me = coord.me;

        let mut moved = coord.state.next_shard_committees[&from].clone();
        moved.members.retain(|&v| v != me);
        coord.state.next_shard_committees.insert(from, moved);
        coord
            .state
            .next_shard_committees
            .insert(to, ShardCommittee { members: vec![me] });

        let change = coord
            .participation_delta(&SlotEffects::default())
            .expect("relocation produces a delta");
        assert_eq!(change.validator, me);
        assert_eq!(change.join, Some(to));
        assert_eq!(change.leave, Some(from));
        assert_eq!(change.effective_epoch, coord.state.current_epoch.next());

        // Promotion makes the views agree again — the delta is gone, so
        // the action fires at exactly one commit.
        coord.state.shard_committees = coord.state.next_shard_committees.clone();
        assert_eq!(coord.participation_delta(&SlotEffects::default()), None);
    }

    /// Another validator's move is invisible to this coordinator — the
    /// delta is strictly about the local validator's placement.
    #[test]
    fn participation_delta_ignores_other_validators() {
        let mut coord = fresh_coord();
        let from = ShardId::ROOT;
        let to = ShardId::leaf(1, 1);
        let other = ValidatorId::new(3);

        let mut moved = coord.state.next_shard_committees[&from].clone();
        moved.members.retain(|&v| v != other);
        coord.state.next_shard_committees.insert(from, moved);
        coord.state.next_shard_committees.insert(
            to,
            ShardCommittee {
                members: vec![other],
            },
        );

        assert_eq!(coord.participation_delta(&SlotEffects::default()), None);
    }

    /// Drop `me` from a committee view's members.
    fn remove_me(committees: &mut BTreeMap<ShardId, ShardCommittee>, me: ValidatorId) {
        for committee in committees.values_mut() {
            committee.members.retain(|&v| v != me);
        }
    }

    fn seat(me: ValidatorId, via: ShardId, child: ShardId) -> ObserverSeat {
        ObserverSeat {
            validator: me,
            shard: via,
            child,
        }
    }

    /// A cohort draw surfaces as `ObserveDelta::Begin`, never as a
    /// member join — the observer's lookahead membership is
    /// transport-only.
    #[test]
    fn participation_delta_reads_a_cohort_draw_as_observe_begin() {
        let mut coord = fresh_coord();
        let me = coord.me;
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-fold admission state: drawn from the pool into the
        // lookahead committee under an Observing status.
        remove_me(&mut coord.state.shard_committees, me);
        remove_me(&mut coord.state.next_shard_committees, me);
        coord
            .state
            .next_shard_committees
            .get_mut(&via)
            .unwrap()
            .members
            .push(me);
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::Observing {
            shard: via,
            placed_at_epoch: coord.state.current_epoch,
        };
        let mut effects = SlotEffects::default();
        effects.observers_drawn.push(seat(me, via, child));

        let change = coord
            .participation_delta(&effects)
            .expect("a draw produces a delta");
        assert_eq!(change.join, None);
        assert_eq!(change.leave, None);
        assert_eq!(change.observe, Some(ObserveDelta::Begin { via, child }));
        assert_eq!(change.effective_epoch, coord.state.current_epoch.next());

        // The grow itself is silent: once promotion carries the
        // observer into the active committee, neither view reads the
        // seat as a placement.
        coord
            .state
            .shard_committees
            .get_mut(&via)
            .unwrap()
            .members
            .push(me);
        assert_eq!(coord.participation_delta(&SlotEffects::default()), None);
    }

    /// A released seat surfaces as `ObserveDelta::Abandon` with no
    /// spurious leave — and with a genuine join when a pool draw
    /// immediately re-placed the released observer as a regular member
    /// of the same shard.
    #[test]
    fn participation_delta_reads_a_released_seat_as_abandon() {
        let mut coord = fresh_coord();
        let me = coord.me;
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-fold cancel state: back in the pool, out of the
        // lookahead committee; the active window still carries the
        // seat-kind membership.
        remove_me(&mut coord.state.next_shard_committees, me);
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::Pooled;
        let mut effects = SlotEffects::default();
        effects.observers_released.push(seat(me, via, child));

        let change = coord
            .participation_delta(&effects)
            .expect("a release produces a delta");
        assert_eq!(change.join, None);
        assert_eq!(change.leave, None);
        assert_eq!(change.observe, Some(ObserveDelta::Abandon { via, child }));

        // Same fold, but a pool draw re-placed the released observer on
        // the same shard as a regular member: the join must fire even
        // though both windows show membership of the same shard.
        coord
            .state
            .next_shard_committees
            .get_mut(&via)
            .unwrap()
            .members
            .push(me);
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: via,
            ready: false,
            placed_at_epoch: coord.state.current_epoch,
        };
        let change = coord
            .participation_delta(&effects)
            .expect("the redraw produces a delta");
        assert_eq!(change.join, Some(via));
        assert_eq!(change.leave, None);
        assert_eq!(change.observe, Some(ObserveDelta::Abandon { via, child }));
    }

    /// A split's execution moves the observer's lookahead membership
    /// onto its child — the ordinary join/leave pair, no observe delta.
    #[test]
    fn participation_delta_reads_execution_as_the_member_flip() {
        let mut coord = fresh_coord();
        let me = coord.me;
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-execution state: the lookahead replaced the parent with
        // its children; the observer landed on its child as a member.
        coord.state.next_shard_committees.remove(&via);
        coord
            .state
            .next_shard_committees
            .insert(child, ShardCommittee { members: vec![me] });
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: child,
            ready: true,
            placed_at_epoch: coord.state.current_epoch,
        };

        let change = coord
            .participation_delta(&SlotEffects::default())
            .expect("execution produces the flip");
        assert_eq!(change.join, Some(child));
        assert_eq!(change.leave, Some(via));
        assert_eq!(change.observe, None);
    }

    /// A keeper draw surfaces as `KeepDelta::Begin` with the sibling half
    /// to sync — never a placement change, since the keeper is already a
    /// member of its child.
    #[test]
    fn participation_delta_reads_a_keeper_draw_as_keep_begin() {
        let coord = fresh_coord();
        let me = coord.me;
        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;
        let sibling = ShardId::leaf(1, 1);

        let mut effects = SlotEffects::default();
        effects.keepers_drawn.push(KeptSeat {
            validator: me,
            parent,
            child,
        });

        let change = coord
            .participation_delta(&effects)
            .expect("a keeper draw produces a delta");
        assert_eq!(change.join, None);
        assert_eq!(change.leave, None);
        assert_eq!(change.observe, None);
        assert_eq!(change.keep, Some(KeepDelta::Begin { parent, sibling }));
    }

    /// A released keeper seat surfaces as `KeepDelta::Abandon` with no
    /// placement change — the keeper stays an ordinary member.
    #[test]
    fn participation_delta_reads_a_released_keeper_as_keep_abandon() {
        let coord = fresh_coord();
        let me = coord.me;
        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;

        let mut effects = SlotEffects::default();
        effects.keepers_released.push(KeptSeat {
            validator: me,
            parent,
            child,
        });

        let change = coord
            .participation_delta(&effects)
            .expect("a keeper release produces a delta");
        assert_eq!(change.join, None);
        assert_eq!(change.leave, None);
        assert_eq!(change.keep, Some(KeepDelta::Abandon { parent }));
    }

    /// A merge's execution moves the keeper from its child onto the
    /// reformed parent — the ordinary join/leave pair, no keep delta (the
    /// supervisor's keeper duty supplies the merged store).
    #[test]
    fn participation_delta_reads_merge_execution_as_the_member_flip() {
        let mut coord = fresh_coord();
        let me = coord.me;
        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;

        // Pre-merge state: me is a member of the child shard (the split
        // state this merge reverses), in both windows.
        let on_child = ShardCommittee { members: vec![me] };
        coord.state.shard_committees = std::iter::once((child, on_child.clone())).collect();
        coord.state.next_shard_committees = std::iter::once((child, on_child)).collect();
        coord.state.shard_consensus_members = coord
            .state
            .ready_consensus_members(&coord.state.shard_committees);
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: child,
            ready: true,
            placed_at_epoch: coord.state.current_epoch,
        };

        // Post-execution lookahead: the children collapsed into the
        // parent; me landed on it as a member.
        coord.state.next_shard_committees.remove(&child);
        coord
            .state
            .next_shard_committees
            .insert(parent, ShardCommittee { members: vec![me] });
        coord.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: parent,
            ready: true,
            placed_at_epoch: coord.state.current_epoch,
        };

        let change = coord
            .participation_delta(&SlotEffects::default())
            .expect("execution produces the flip");
        assert_eq!(change.join, Some(parent));
        assert_eq!(change.leave, Some(child));
        assert_eq!(change.keep, None);
    }
}
