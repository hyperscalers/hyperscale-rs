//! Top-level beacon FSM.
//!
//! [`BeaconCoordinator`] is the per-vnode state machine; it owns the
//! committed [`BeaconState`], the optional current-epoch
//! [`SpcInstance`], and the wall-clock anchor that drives
//! epoch-cadence timers.
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

use hyperscale_core::{Action, FetchAbandon, FetchRequest, TimerId};
use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, BeaconCert, BeaconProposal, BeaconProposalVerifyContext,
    BeaconState, BlockHash, BlockHeader, BlockHeight, Bls12381G1PublicKey, CertifiedBeaconBlock,
    CertifiedBeaconBlockVerifyError, CertifiedBlockHeader, EPOCH_DURATION, Epoch,
    GenesisConfigHash, LeafIndex, LocalTimestamp, MAX_EQUIVOCATIONS_PER_PROPOSER,
    MAX_WITNESSES_PER_FETCH, MIN_BEACON_COMMITTEE_SIZE, NetworkDefinition, PcQc3, PcValueElement,
    PcVector, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3,
    PcVote3VerifyError, PcVoteEquivocation, PcVoteEquivocationContext, PcVoteRound, QcContext,
    QuorumCertificate, RETENTION_HORIZON, SKIP_TIMEOUT, SPC_VIEW_TIMEOUT, ShardEpochContribution,
    ShardId, ShardWitness, SkipEpochCert, SkipRequest, SkipRequestVerifyError, SpcCert,
    SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError, SpcNewCommitMsg, SpcNewCommitMsgVerifyError,
    SpcProposalObject, SpcProposalObjectVerifyError, SpcView, TopologySchedule, TopologySnapshot,
    ValidatorId, Verifiable, Verified, Verify,
};
use tracing::{trace, warn};

use crate::commit_assembly::{AssemblyDecision, CommitAssembler};
use crate::equivocations::EquivocationObservations;
use crate::proposal_pool::BeaconProposalPool;
use crate::shard_source::ShardSourceTracker;
use crate::skip_tracker::SkipTracker;
use crate::spc::{MAX_PENDING_EMPTY_VIEW_AHEAD, SpcEffect, SpcEvent, SpcInstance};
use crate::state::{
    apply_epoch, apply_input_for, chunk_bounds, contribution_chunk_valid, epoch_boundary_below,
};
use crate::verification::{BeaconVerificationPipeline, SpcMsgKind};

/// Depth of the coordinator's queryable committee-history window.
///
/// Sized to cover the oldest cross-shard artifact any consumer would
/// still verify (`RETENTION_HORIZON` worth of epochs) plus headroom for
/// the lookahead neighbour and the integer-division floor.
///
/// **Not consensus-critical**: a node with a smaller value still
/// produces the same chain, it just can't answer some historical
/// topology queries. A node-local cache bound, not a protocol parameter.
/// Exposed so the runner loads exactly this many states from storage at
/// boot to seed the schedule's restart history.
pub const TOPOLOGY_SCHEDULE_RETENTION_EPOCHS: u64 =
    RETENTION_HORIZON.as_secs() / EPOCH_DURATION.as_secs() + 2;

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
    /// cert. Carried so SPC instance bootstrap and skip-cert anchor
    /// checks read `prev_block_hash` without a storage roundtrip.
    latest_block: Arc<Verified<CertifiedBeaconBlock>>,

    /// `None` between bootstrap and the first epoch-boundary
    /// trigger, and again briefly between an epoch's commit and the
    /// next instance's bootstrap.
    spc: Option<SpcInstance>,

    /// In-flight and verified slot tracking for async crypto checks
    /// (block cert sigs + skip-request sigs). Dedup-only — the payload
    /// rides through the dispatch/result round-trip in the action and
    /// event themselves, not stashed here.
    verification: BeaconVerificationPipeline,

    /// Per-shard header records, validated-witness pool, and
    /// in-flight fetches; drives proposal-readiness and the
    /// witness drain.
    shard_source: ShardSourceTracker,

    /// Buckets observed [`SkipRequest`]s and aggregates them into a
    /// [`SkipEpochCert`](hyperscale_types::SkipEpochCert) once
    /// ⌈2M/3⌉ + 1 active-pool quorum lands.
    skip_tracker: SkipTracker,

    /// Equivocation evidence the local vnode has observed but not
    /// yet proposed for inclusion.
    equivocations: EquivocationObservations,

    /// Per-epoch cache of committee members' `BeaconProposal`s.
    /// Scoped to the in-flight epoch (`state.current_epoch.next()`);
    /// reset on commit. Shared with the `GetBeaconProposalRequest`
    /// network responder and with every co-hosted vnode's
    /// `BeaconCoordinator` — single `Arc` per host.
    proposal_pool: Arc<BeaconProposalPool>,

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
    /// timestamp over the window `[current_epoch −
    /// TOPOLOGY_SCHEDULE_RETENTION_EPOCHS, current_epoch + 1]`. The `+1`
    /// lookahead entry is finalized an epoch before its window opens. A
    /// node-local cache, not consensus-critical.
    topology: TopologySchedule,

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
}

impl BeaconCoordinator {
    /// Construct a coordinator from `latest_block` and a `history` of
    /// recently-committed states (newest last; `history.last()` becomes
    /// the live state). Each state seeds the topology schedule with its
    /// active and lookahead snapshots, so the coordinator boots able to
    /// verify cross-shard artifacts back across the loaded window. When
    /// `latest_block` is genesis, debug-asserts its cert's `config_hash`
    /// matches `expected_config_hash` — catches a runner that loaded a
    /// chain initialised by a different operator TOML than this process
    /// is configured for.
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
        network: NetworkDefinition,
        expected_config_hash: GenesisConfigHash,
        proposal_pool: Arc<BeaconProposalPool>,
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
        let mut topology = TopologySchedule::new(
            epoch_duration_ms,
            TOPOLOGY_SCHEDULE_RETENTION_EPOCHS,
            latest_epoch,
            Arc::clone(&head),
        );
        for state in &history {
            if state.current_epoch != latest_epoch {
                topology.insert(
                    state.current_epoch,
                    Arc::new(state.derive_topology_snapshot(network.clone())),
                );
            }
            let lookahead = state.current_epoch.next();
            if lookahead != latest_epoch {
                topology.insert(
                    lookahead,
                    Arc::new(state.derive_next_topology_snapshot(network.clone())),
                );
            }
        }
        let state = history.into_iter().next_back().expect(LATEST_STATE_EXPECT);
        // Bound the schedule to the retention window in case the caller loaded
        // more states than we keep; `adopt_block` holds the same bound forward.
        topology.evict_before(state.current_epoch);
        Self {
            state,
            latest_block,
            spc: None,
            verification: BeaconVerificationPipeline::new(),
            shard_source: ShardSourceTracker::new(),
            skip_tracker: SkipTracker::new(),
            equivocations: EquivocationObservations::new(),
            proposal_pool,
            evaluated_proposers: BTreeSet::new(),
            commit_assembly: CommitAssembler::new(),
            local_shard,
            topology,
            me,
            network,
            now: LocalTimestamp::ZERO,
        }
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
                id: TimerId::BeaconSkipTrigger,
                duration: self
                    .duration_until_next_epoch_boundary()
                    .saturating_add(SKIP_TIMEOUT),
            },
        ]
    }

    /// Wall-clock boundary of the upcoming epoch —
    /// `next_epoch × chain_config.epoch_duration_ms`. The beacon starts the
    /// next epoch's SPC only once `now` reaches this, so its synthetic
    /// per-epoch clock (`epoch × epoch_duration_ms`) tracks wall-clock instead
    /// of racing ahead at SPC-round speed.
    const fn next_epoch_boundary(&self) -> LocalTimestamp {
        LocalTimestamp::from_millis(
            self.state
                .current_epoch
                .next()
                .inner()
                .saturating_mul(self.state.chain_config.epoch_duration_ms),
        )
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

    /// Whether the skip-trigger timer is due — i.e. wall-clock time
    /// has reached `expected_block_time + SKIP_TIMEOUT`. The
    /// runner combines this with its own "expected block hasn't
    /// arrived" + "local on active pool" checks before actually
    /// broadcasting a [`SkipRequest`](hyperscale_types::SkipRequest).
    #[must_use]
    pub fn skip_trigger_due(&self, expected_block_time: LocalTimestamp) -> bool {
        self.now.as_millis() >= expected_block_time.plus(SKIP_TIMEOUT).as_millis()
    }

    /// `TimerId::BeaconSkipTrigger` fired — the next epoch's expected
    /// block hasn't committed within `SKIP_TIMEOUT` of its boundary.
    /// If the local validator sits on the active pool, sign and
    /// broadcast a [`SkipRequest`] for the next epoch at the current
    /// tip; otherwise no-op.
    ///
    /// The action handler signs the request (the coordinator has no
    /// key) and emits the loopback into `on_verified_skip_request_received`.
    pub fn on_beacon_skip_timer(&self) -> Vec<Action> {
        let local_on_active_pool = self
            .state
            .derive_active_pool()
            .iter()
            .any(|(id, _)| *id == self.me);
        if !local_on_active_pool {
            trace!("BeaconSkipTrigger fired but local validator not on active pool");
            return Vec::new();
        }
        vec![Action::BroadcastSkipRequest {
            epoch_to_skip: self.state.current_epoch.next(),
            anchor: self.latest_block.block_hash(),
        }]
    }

    /// A peer's round-1 PC vote arrived. Gate on instance/skip-quorum,
    /// mark the slot in-flight, and dispatch the BLS check to the
    /// crypto pool. Admission happens in [`Self::on_pc_vote1_verified`]
    /// when the result lands.
    pub fn on_pc_vote1_received(&mut self, view: SpcView, vote: PcVote1) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.spc_admission_ctx(validator, view, "PcVote") else {
            return Vec::new();
        };
        let key = (epoch, view, validator, PcVoteRound::Vote1);
        if !self.verification.mark_pc_vote_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifyPcVote1 {
            epoch,
            view,
            vote: Verifiable::from(vote),
            committee,
        }]
    }

    /// A peer's round-2 PC vote arrived.
    pub fn on_pc_vote2_received(&mut self, view: SpcView, vote: Box<PcVote2>) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.spc_admission_ctx(validator, view, "PcVote") else {
            return Vec::new();
        };
        let key = (epoch, view, validator, PcVoteRound::Vote2);
        if !self.verification.mark_pc_vote_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifyPcVote2 {
            epoch,
            view,
            vote: Box::new(Verifiable::from(*vote)),
            committee,
        }]
    }

    /// A peer's round-3 PC vote arrived.
    pub fn on_pc_vote3_received(&mut self, view: SpcView, vote: Box<PcVote3>) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.spc_admission_ctx(validator, view, "PcVote") else {
            return Vec::new();
        };
        let key = (epoch, view, validator, PcVoteRound::Vote3);
        if !self.verification.mark_pc_vote_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifyPcVote3 {
            epoch,
            view,
            vote: Box::new(Verifiable::from(*vote)),
            committee,
        }]
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
        let view = proposal.view;
        let Some((epoch, committee)) = self.spc_admission_ctx(from, view, "NewView") else {
            return Vec::new();
        };
        let key = (epoch, view, from, SpcMsgKind::NewView);
        if !self.verification.mark_spc_msg_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifySpcNewView {
            epoch,
            from,
            proposal: Box::new(Arc::unwrap_or_clone(proposal)),
            committee,
        }]
    }

    /// A peer's SPC `new-commit` arrived. Gate on instance/skip-quorum,
    /// mark the slot in-flight, and dispatch the embedded QC3's BLS check
    /// to the crypto pool. Admission happens in
    /// [`Self::on_spc_new_commit_verified`] when the result lands.
    pub fn on_spc_new_commit_received(
        &mut self,
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    ) -> Vec<Action> {
        let view = msg.view;
        let Some((epoch, committee)) = self.spc_admission_ctx(from, view, "NewCommit") else {
            return Vec::new();
        };
        let key = (epoch, view, from, SpcMsgKind::NewCommit);
        if !self.verification.mark_spc_msg_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifySpcNewCommit {
            epoch,
            from,
            msg: Box::new(Arc::unwrap_or_clone(msg)),
            committee,
        }]
    }

    /// A peer's SPC `empty-view` attestation arrived. Gate on
    /// instance/skip-quorum, mark the slot in-flight (keyed by the
    /// embedded signer), and dispatch the BLS check to the crypto pool.
    /// Admission happens in [`Self::on_spc_empty_view_verified`] when
    /// the result lands.
    pub fn on_unverified_spc_empty_view_received(
        &mut self,
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let signer = msg.signer;
        let view = msg.view;
        let Some((epoch, committee)) = self.spc_admission_ctx(signer, view, "EmptyView") else {
            return Vec::new();
        };
        let key = (epoch, view, signer, SpcMsgKind::EmptyView);
        if !self.verification.mark_spc_msg_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifySpcEmptyView {
            epoch,
            msg: Box::new(Arc::unwrap_or_clone(msg)),
            committee,
        }]
    }

    /// A locally-signed empty-view attestation arrived via the
    /// `Action::SignAndBroadcastEmptyView` self-loopback path. The
    /// signing-key holder produced the BLS sig over a verified high
    /// triple, so the message is verified by construction — feed it
    /// directly into the SPC sub-machine without the verify round-trip.
    pub fn on_verified_spc_empty_view_received(
        &mut self,
        msg: Box<Verified<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let signer = msg.signer;
        if self
            .spc_admission_ctx(signer, msg.view, "VerifiedEmptyView")
            .is_none()
        {
            return Vec::new();
        }
        self.dispatch_spc_event(signer, SpcEvent::EmptyViewVerified(msg))
    }

    /// Common gating for the SPC receive entries: returns the
    /// `(epoch, committee)` pair if the message is admissible, else logs
    /// and returns `None`. Four gates, all cheap and applied before the
    /// BLS dispatch so a flood can't mint verification slots:
    ///
    /// 1. The local SPC instance is bootstrapped.
    /// 2. Skip-quorum hasn't been reached at the local tip.
    /// 3. `signer` (the claimed vote/message signer, which keys the
    ///    verification slot) is a current committee member — a
    ///    non-committee signer can't contribute to consensus.
    /// 4. `view` is within `[current_view, current_view +
    ///    MAX_PENDING_EMPTY_VIEW_AHEAD]` — the window the FSM can act on.
    ///
    /// Gates 3 and 4 bound the `(signer, view)` slot key to
    /// `committee_size × window`, so a peer flooding fabricated signers
    /// or views can't grow the in-flight verification pools without
    /// bound.
    fn spc_admission_ctx(
        &self,
        signer: ValidatorId,
        view: SpcView,
        kind: &'static str,
    ) -> Option<(Epoch, Vec<(ValidatorId, Bls12381G1PublicKey)>)> {
        let Some(spc) = self.spc.as_ref() else {
            trace!(
                ?signer,
                kind, "SPC message received but no SPC instance bootstrapped",
            );
            return None;
        };
        if self.skip_quorum_at_tip() {
            trace!(
                ?signer,
                kind, "SPC message received but skip-quorum reached at local tip — dropping",
            );
            return None;
        }
        if !spc.committee().iter().any(|(id, _)| *id == signer) {
            trace!(
                ?signer,
                kind, "SPC message from non-committee signer — dropping before dispatch",
            );
            return None;
        }
        let current = spc.current_view().inner();
        if view.inner() < current
            || view.inner() > current.saturating_add(MAX_PENDING_EMPTY_VIEW_AHEAD)
        {
            trace!(
                view = view.inner(),
                current,
                kind,
                "SPC message view outside the actionable window — dropping before dispatch",
            );
            return None;
        }
        Some((spc.epoch(), spc.committee().to_vec()))
    }

    /// Result of an [`Action::VerifySpcNewView`] dispatch. The view is
    /// extracted from the unverified payload at dispatch time and
    /// carried back here so the slot can be cleared on both arms.
    pub fn on_spc_new_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
    ) -> Vec<Action> {
        let key = (epoch, view, from, SpcMsgKind::NewView);
        let proposal = match result {
            Ok(p) => p,
            Err(err) => {
                self.verification.forget_spc_msg(key);
                warn!(
                    ?from,
                    epoch = epoch.inner(),
                    view = view.inner(),
                    %err,
                    "SPC NewView cert verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.verification.forget_spc_msg(key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        let cert = Verified::<SpcCert>::from_verified_proposal_object(proposal);
        self.dispatch_spc_event(
            from,
            SpcEvent::NewViewVerified {
                from,
                view,
                cert: Box::new(cert),
            },
        )
    }

    /// Result of an [`Action::VerifySpcNewCommit`] dispatch.
    pub fn on_spc_new_commit_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
    ) -> Vec<Action> {
        let key = (epoch, view, from, SpcMsgKind::NewCommit);
        let msg = match result {
            Ok(m) => m,
            Err(err) => {
                self.verification.forget_spc_msg(key);
                warn!(
                    ?from,
                    epoch = epoch.inner(),
                    view = view.inner(),
                    %err,
                    "SPC NewCommit QC3 verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.verification.forget_spc_msg(key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        let value = msg.value.clone();
        let proof = Verified::<PcQc3>::from_verified_new_commit(msg);
        self.dispatch_spc_event(
            from,
            SpcEvent::NewCommitVerified {
                view,
                value,
                proof: Box::new(proof),
            },
        )
    }

    /// Result of an [`Action::VerifySpcEmptyView`] dispatch.
    pub fn on_spc_empty_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
    ) -> Vec<Action> {
        let key = (epoch, view, from, SpcMsgKind::EmptyView);
        let msg = match result {
            Ok(m) => m,
            Err(err) => {
                self.verification.forget_spc_msg(key);
                warn!(
                    ?from,
                    epoch = epoch.inner(),
                    view = view.inner(),
                    %err,
                    "SPC EmptyView verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.verification.forget_spc_msg(key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(from, SpcEvent::EmptyViewVerified(Box::new(msg)))
    }

    /// Result of an [`Action::VerifyPcVote1`] dispatch. Clears the
    /// pipeline slot, routes the verified vote through
    /// `SpcEvent::PcVoteVerified`, drops on verify failure. Stale
    /// results (instance gone, epoch advanced, skip-quorum reached) are
    /// tolerated by the inner `dispatch_spc_event` gating.
    pub fn on_pc_vote1_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
    ) -> Vec<Action> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote1);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-1 BLS verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote1);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(
            self.me,
            SpcEvent::PcVote1Verified {
                view,
                vote: verified,
            },
        )
    }

    /// Result of an [`Action::VerifyPcVote2`] dispatch.
    pub fn on_pc_vote2_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
    ) -> Vec<Action> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote2);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-2 BLS verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote2);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(
            self.me,
            SpcEvent::PcVote2Verified {
                view,
                vote: Box::new(verified),
            },
        )
    }

    /// Result of an [`Action::VerifyPcVote3`] dispatch.
    pub fn on_pc_vote3_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
    ) -> Vec<Action> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote3);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-3 BLS verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote3);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(
            self.me,
            SpcEvent::PcVote3Verified {
                view,
                vote: Box::new(verified),
            },
        )
    }

    /// A round-1 PC vote that the coordinator received already
    /// verified — fed in via the local sign-and-emit handler (or by a
    /// colocated peer's local-dispatch fast path). Skips the verify
    /// dispatch and routes straight to the SPC sub-machine.
    pub fn on_verified_pc_vote1_received(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote1>,
    ) -> Vec<Action> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.spc_admission_ctx(signer, view, "PcVote") else {
            return Vec::new();
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote1);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(self.me, SpcEvent::PcVote1Verified { view, vote })
    }

    /// A round-2 PC vote that the coordinator received already verified.
    pub fn on_verified_pc_vote2_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote2>>,
    ) -> Vec<Action> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.spc_admission_ctx(signer, view, "PcVote") else {
            return Vec::new();
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote2);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(self.me, SpcEvent::PcVote2Verified { view, vote })
    }

    /// A round-3 PC vote that the coordinator received already verified.
    pub fn on_verified_pc_vote3_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote3>>,
    ) -> Vec<Action> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.spc_admission_ctx(signer, view, "PcVote") else {
            return Vec::new();
        };
        self.clear_pc_vote_slot(epoch, view, signer, PcVoteRound::Vote3);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch_spc_event(self.me, SpcEvent::PcVote3Verified { view, vote })
    }

    /// Shared slot-clear helper used by all three per-round PC vote
    /// verify-result handlers. The signer is extracted from the
    /// unverified payload at dispatch time and carried back in the
    /// result event, so the slot can be cleared on both arms.
    fn clear_pc_vote_slot(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        round: PcVoteRound,
    ) {
        self.verification
            .forget_pc_vote((epoch, view, signer, round));
    }

    /// `TimerId::BeaconSpcView` fired. Route a synthesized
    /// `TimerExpired` into SPC against its current view — the FSM's
    /// stale-view guard no-ops if the view has already advanced.
    pub fn on_beacon_spc_view_timer(&mut self) -> Vec<Action> {
        let Some(spc) = self.spc.as_ref() else {
            trace!("BeaconSpcViewTimer fired but no SPC instance bootstrapped");
            return Vec::new();
        };
        let view = spc.current_view();
        self.dispatch_spc_event(self.me, SpcEvent::TimerExpired { view })
    }

    /// A peer committee member's `BeaconProposal` arrived. Admit it
    /// to the pool gated on committee membership at `epoch`. The
    /// `IoLoop` has already authenticated `from` and verified the
    /// proposal's VRF reveal against `(network.id, epoch)` under
    /// `from`'s pubkey, so admission here is a pure pool insert.
    ///
    /// When the local validator's own proposal arrives back via the
    /// action handler's feedback, this is also the trigger that
    /// feeds SPC's view-1 PC instance — `compute_view_one_input`
    /// reads the pool's current view of committee proposals and
    /// `SpcEvent::Input` kicks the FSM into outbound traffic.
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
            let Some(upgraded) = self.upgrade_proposal_witnesses(&proposal) else {
                trace!(
                    ?from,
                    epoch = epoch.inner(),
                    "BeaconProposalReceived carries an unverifiable witness — dropping",
                );
                return Vec::new();
            };
            if !self.boundary_qcs_admissible(&upgraded) {
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
        if from == self.me && self.should_feed_view_one_input(epoch) {
            return self.feed_view_one_input(epoch);
        }
        Vec::new()
    }

    /// Verify every observation embedded in `proposal` against
    /// locally-available state and return the proposal with each
    /// `Verifiable` marker upgraded in place, or `None` if any is
    /// unverifiable. Each list runs its own element type's `Verify`:
    /// - equivocation evidence — both BLS sigs verify under the named
    ///   validator's pubkey (from `state.validators`); evidence naming an
    ///   unknown validator is unverifiable.
    /// - shard witness — the merkle path reaches the source-shard
    ///   header's `beacon_witness_root`; a witness whose source header
    ///   hasn't synced yet is unverifiable.
    ///
    /// A forged observation fails regardless of header availability (a bad
    /// merkle path can't be made to verify, a forged sig can't pass), so
    /// an honest node never votes for it. A genuine-but-unsynced shard
    /// witness merely abstains until the header lands — the proposer
    /// re-includes the still-unconsumed witness next epoch. The upgraded
    /// markers ride the pooled proposal through to `apply_epoch`.
    fn upgrade_proposal_witnesses(
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

    /// Whether every boundary QC a peer proposes is admissible. A `Some`
    /// entry must name a boundary block this node has synced, that block's
    /// canonical QC must be a genuine `2f+1` of the governing shard
    /// committee, and the block must be a real epoch-boundary crossing.
    /// Unverifiable entries make the whole proposal inadmissible — this
    /// vnode abstains, exactly as it does for an unverifiable witness, and
    /// the one-honest-reporter rule covers a crossing this node hasn't yet
    /// seen. Gating the vote keeps forged QCs out of the committed set: a
    /// committed boundary QC carries `≥ f+1` honest verifiers, so the fold
    /// trusts what commits.
    fn boundary_qcs_admissible(&self, proposal: &Verified<BeaconProposal>) -> bool {
        proposal.boundary_qcs().iter().all(|(shard, opt)| {
            opt.as_ref()
                .is_none_or(|qc| self.boundary_qc_admissible(*shard, qc.as_unverified()))
        })
    }

    /// Whether a single peer-proposed boundary QC clears admission: the
    /// local node holds the boundary block, the QC authenticates as a
    /// genuine `2f+1` of the governing shard committee, and the block is a
    /// real epoch-boundary crossing.
    fn boundary_qc_admissible(&self, shard: ShardId, qc: &QuorumCertificate) -> bool {
        let Some(header) = self.boundary_header_for(shard, qc.block_hash()) else {
            return false;
        };
        self.boundary_qc_authentic(shard, header, qc) && self.is_boundary_crossing(header, qc)
    }

    /// Whether `boundary_header` is the first block across the epoch cut
    /// `qc` attests: its predecessor sits at or before the largest epoch
    /// boundary below the block's own weighted timestamp (`qc.wt`). Pure
    /// over the chain's epoch duration — the fold applies the same test.
    fn is_boundary_crossing(&self, boundary_header: &BlockHeader, qc: &QuorumCertificate) -> bool {
        let dur = self.state.chain_config.epoch_duration_ms;
        let Some(cut) = epoch_boundary_below(qc.weighted_timestamp().as_millis(), dur) else {
            return false;
        };
        boundary_header.parent_qc().weighted_timestamp().as_millis() <= cut
    }

    /// The locally-held header for `block_hash` in `shard`: a retained
    /// epoch-boundary crossing first (kept past header pruning), then the
    /// sliding header window. `None` when the node hasn't synced the block.
    fn boundary_header_for(&self, shard: ShardId, block_hash: BlockHash) -> Option<&BlockHeader> {
        if let Some(crossing) = self.shard_source.crossing_by_block_hash(shard, block_hash) {
            return Some(crossing.boundary_header());
        }
        self.shard_source
            .find_header_by_block_hash(shard, block_hash)
            .map(|h| h.header())
    }

    /// Whether `qc` is a genuine `2f+1` quorum of the committee that
    /// governed `boundary_header`, and commits exactly that block.
    ///
    /// The committee is resolved at the boundary block's parent-QC
    /// weighted timestamp — the window the block was produced in — through
    /// the [`TopologySchedule`], which retains historical committees the
    /// live `BeaconState` no longer holds (a tracked crossing can lag the
    /// tip by up to a few epochs). `None` resolution (the epoch fell out
    /// of the retention window) fails closed.
    fn boundary_qc_authentic(
        &self,
        shard: ShardId,
        boundary_header: &BlockHeader,
        qc: &QuorumCertificate,
    ) -> bool {
        if qc.block_hash() != boundary_header.hash() {
            return false;
        }
        let Some(snapshot) = self
            .topology
            .at(boundary_header.parent_qc().weighted_timestamp())
        else {
            return false;
        };
        let committee = snapshot.committee_for_shard(shard);
        if committee.is_empty() {
            return false;
        }
        let mut public_keys = Vec::with_capacity(committee.len());
        for id in committee {
            let Some(pk) = snapshot.public_key(*id) else {
                return false;
            };
            public_keys.push(pk);
        }
        qc.verify(&QcContext {
            network: &self.network,
            public_keys: &public_keys,
            quorum_threshold: snapshot.quorum_threshold_for_shard(shard),
        })
        .is_ok()
    }

    /// Whether the current SPC instance is ready to receive its
    /// view-1 `Input`: instance exists, drives `epoch`, and hasn't
    /// been fed already.
    fn should_feed_view_one_input(&self, epoch: Epoch) -> bool {
        self.spc
            .as_ref()
            .is_some_and(|spc| spc.epoch() == epoch && !spc.view_one_input_fed())
    }

    /// Build view 1's local input vector from the current pool view
    /// and drive it into SPC. Lifts the resulting effects.
    fn feed_view_one_input(&mut self, epoch: Epoch) -> Vec<Action> {
        let input = self.compute_view_one_input(epoch);
        let recipients = self.spc_recipients();
        let spc = self.spc.as_mut().expect("checked by should_feed");
        let effects = spc.handle(SpcEvent::Input(input));
        self.lift_spc_effects(epoch, &recipients, effects)
    }

    /// Build the PC input vector for view 1: one `PcValueElement` per
    /// committee position, the hashed proposal if we've seen it or
    /// `PcValueElement::ZERO` (`HASH_BOTTOM`) if not.
    fn compute_view_one_input(&self, epoch: Epoch) -> PcVector {
        let elements: Vec<PcValueElement> = self
            .state
            .committee
            .iter()
            .map(|id| {
                self.proposal_pool
                    .get(*id)
                    .map_or(PcValueElement::ZERO, |p| p.pc_element_hash(epoch))
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
        if self.spc.is_none() {
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
        let boundary_qcs = self.source_boundary_qcs();
        let equivocations = self.drain_equivocations_for();
        vec![Action::BuildAndBroadcastBeaconProposal {
            epoch,
            boundary_qcs,
            equivocations,
            recipients,
        }]
    }

    /// Source this proposer's per-shard boundary QCs: each active shard's
    /// most recently observed epoch-boundary crossing **whose witness
    /// chunk is in hand**.
    ///
    /// The witness-availability coupling: a shard is reported only if the
    /// local node holds the chunk `[prior, chunk_end)` anchored to that
    /// crossing's boundary block, so a committed boundary QC always implies
    /// its witnesses are assemblable. Shards with no observed crossing — or
    /// an observed crossing whose chunk hasn't fetched yet — are absent;
    /// one honest reporter is enough to mark a shard live, so partial
    /// coverage is fine.
    fn source_boundary_qcs(&self) -> BTreeMap<ShardId, Option<QuorumCertificate>> {
        self.state
            .shard_committees
            .keys()
            .filter_map(|shard| {
                let crossing = self.shard_source.latest_crossing(*shard)?;
                let qc = crossing.canonical_qc();
                let (prior, chunk_end) =
                    self.witness_chunk_bounds(*shard, crossing.boundary_header());
                // Coupling: only report a shard whose chunk we can supply.
                self.shard_source
                    .witness_chunk(*shard, qc.block_hash(), prior, chunk_end)?;
                Some((*shard, Some(qc.clone())))
            })
            .collect()
    }

    /// The witness chunk bounds for `shard` against `boundary_header`:
    /// reads the applied watermark from `state.boundaries` and the
    /// boundary's accumulator count from the header, then derives the
    /// range via [`chunk_bounds`].
    fn witness_chunk_bounds(&self, shard: ShardId, boundary_header: &BlockHeader) -> (u64, u64) {
        let prior = self
            .state
            .boundaries
            .get(&shard)
            .map_or(0, |b| b.witness_leaf_count.inner());
        chunk_bounds(prior, boundary_header.beacon_witness_leaf_count().inner())
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
        if self.spc.is_some() {
            trace!("BeaconCommitteeStart fired with SPC already running");
            return Vec::new();
        }
        if !self.is_on_committee() {
            trace!("BeaconCommitteeStart fired but local validator not on committee");
            return Vec::new();
        }
        self.bootstrap_spc_for_next_epoch();
        self.try_propose()
    }

    /// Stand up a fresh [`SpcInstance`] for the upcoming epoch under
    /// the current `state.committee`. Skips validators absent from
    /// `state.validators` — a structurally impossible state for an
    /// on-chain committee, so the skip is defensive rather than
    /// expected.
    fn bootstrap_spc_for_next_epoch(&mut self) {
        let committee = self.state.derive_beacon_committee();
        self.bootstrap_spc_with_committee(committee);
    }

    /// Stand up the per-epoch [`SpcInstance`] from an explicit committee.
    ///
    /// Declines (leaves `self.spc` cleared) when `committee.len() <
    /// MIN_BEACON_COMMITTEE_SIZE`: a committee that can't tolerate a single
    /// Byzantine fault must not run PC. Rather than panic in
    /// [`PcInstance::new`], the coordinator skips the bootstrap and lets
    /// the skip path carry the epoch — the ready on-shard set has
    /// collapsed below the BFT floor, an operator-visible degradation
    /// the chain recovers from once enough validators ready up. The
    /// assertion in `PcInstance::new` stays as a tripwire for a
    /// genuinely impossible caller.
    fn bootstrap_spc_with_committee(&mut self, committee: Vec<(ValidatorId, Bls12381G1PublicKey)>) {
        let next_epoch = self.state.current_epoch.next();
        if committee.len() < MIN_BEACON_COMMITTEE_SIZE {
            warn!(
                committee_size = committee.len(),
                min_committee_size = MIN_BEACON_COMMITTEE_SIZE,
                epoch = next_epoch.inner(),
                "Beacon-eligible set below the BFT minimum — declining SPC bootstrap. \
                 The epoch advances via the skip path; normal blocks resume once the \
                 ready on-shard set recovers.",
            );
            self.spc = None;
            return;
        }
        self.spc = Some(SpcInstance::new(
            next_epoch,
            committee,
            self.me,
            SPC_VIEW_TIMEOUT,
        ));
    }

    /// Drive `event` through the current `SpcInstance` and lift the
    /// resulting effects. The `from` argument is logged on the
    /// not-bootstrapped path so dropped messages are attributable.
    ///
    /// Skip-quorum gate: if the local node has already observed the
    /// ⌈2M/3⌉ + 1 active-pool quorum to skip
    /// `current_epoch.next()` at the local tip, drop the event
    /// without dispatching. The SPC instance for the abandoned epoch
    /// can't reach `n - f` once the pool has committed to skipping;
    /// continued dispatch would just produce wasted work and admit
    /// equivocation patterns the per-FSM detector doesn't catch.
    /// Query-based, not state-based — `self.spc` stays `Some` until
    /// ordinary `adopt_block` teardown clears it.
    fn dispatch_spc_event(&mut self, from: ValidatorId, event: SpcEvent) -> Vec<Action> {
        if self.spc.is_none() {
            trace!(?from, "SPC event received but no SPC instance bootstrapped");
            return Vec::new();
        }
        if self.skip_quorum_at_tip() {
            trace!(
                ?from,
                "SPC event received but skip-quorum reached at local tip — dropping",
            );
            return Vec::new();
        }
        let recipients = self.spc_recipients();
        let spc = self.spc.as_mut().expect("checked is_none above");
        let epoch = spc.epoch();
        let effects = spc.handle(event);
        self.lift_spc_effects(epoch, &recipients, effects)
    }

    /// Whether the skip tracker has accumulated quorum to abandon
    /// `current_epoch.next()` at the local tip's anchor.
    fn skip_quorum_at_tip(&self) -> bool {
        let active_pool_size = self.state.derive_active_pool().len();
        self.skip_tracker.quorum_reached(
            self.latest_block.block_hash(),
            self.state.current_epoch.next(),
            active_pool_size,
        )
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
        // Structural checks pass. Skip blocks carry an extra anchor +
        // epoch gate beyond the cert-type → signer-pool dispatch.
        if let BeaconCert::Skip(skip_cert) = block.cert()
            && (skip_cert.anchor_hash() != self.latest_block.block_hash()
                || skip_cert.epoch_to_skip() != epoch)
        {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived Skip cert anchor/epoch mismatch — dropping",
            );
            return Vec::new();
        }
        let Some(signers) = self.state.signer_pool_for(&block) else {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with Genesis cert past tip — dropping",
            );
            return Vec::new();
        };
        let equivocation_signers = self.equivocation_signers_for(&block);
        self.dispatch_block_verification(block, signers, equivocation_signers)
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
        block: &CertifiedBeaconBlock,
    ) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        let mut signers: Vec<(ValidatorId, Bls12381G1PublicKey)> = Vec::new();
        let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
        for (_, proposal) in block.block().committed_proposals() {
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
        signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        equivocation_signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Vec<Action> {
        if !self.verification.mark_block_in_flight(block.block_hash()) {
            return Vec::new();
        }
        vec![Action::VerifyBeaconBlock {
            block,
            signers,
            equivocation_signers,
        }]
    }

    /// A peer's [`SkipRequest`] arrived via gossip. Validate the
    /// non-crypto fields and dispatch BLS verification to the crypto
    /// pool. Admission to the [`SkipTracker`] happens in
    /// [`Self::on_skip_request_verified`] once the result lands;
    /// quorum assembly + adoption follow from there.
    ///
    /// Synchronous validation (before dispatch):
    /// - Anchor must equal `latest_block.block_hash()`. Requests
    ///   pinning a different anchor are stale or for a chain head we
    ///   haven't seen.
    /// - `epoch_to_skip` must equal `current_epoch.next()` — the
    ///   in-flight epoch.
    /// - Signer must sit in the active-duty pool
    ///   ([`derive_active_pool`]); off-pool requests can't contribute
    ///   to quorum so the BLS check is pointless.
    ///
    /// Async (on the crypto pool):
    /// - BLS sig verifies against the canonical
    ///   [`skip_request_message`](hyperscale_types::skip_request_message)
    ///   under the signer's pubkey.
    pub fn on_unverified_skip_request_received(
        &mut self,
        request: Arc<Verifiable<SkipRequest>>,
    ) -> Vec<Action> {
        if request.anchor_hash() != self.latest_block.block_hash() {
            trace!(
                signer = ?request.signer(),
                "SkipRequest at unknown anchor — dropping",
            );
            return Vec::new();
        }
        let expected_epoch = self.state.current_epoch.next();
        if request.epoch_to_skip() != expected_epoch {
            trace!(
                signer = ?request.signer(),
                epoch_to_skip = request.epoch_to_skip().inner(),
                expected = expected_epoch.inner(),
                "SkipRequest at unexpected epoch — dropping",
            );
            return Vec::new();
        }

        let active_pool = self.state.derive_active_pool();
        if !active_pool.iter().any(|(id, _)| *id == request.signer()) {
            trace!(
                signer = ?request.signer(),
                "SkipRequest signer absent from active pool — dropping",
            );
            return Vec::new();
        }

        let key = (
            request.anchor_hash(),
            request.epoch_to_skip(),
            request.signer(),
        );
        if !self.verification.mark_skip_request_in_flight(key) {
            return Vec::new();
        }
        vec![Action::VerifySkipRequest {
            request: Box::new(Arc::unwrap_or_clone(request)),
            signers: active_pool,
        }]
    }

    /// A locally-signed [`SkipRequest`] arrived via the
    /// `Action::BroadcastSkipRequest` self-loopback path. The signing
    /// validator produced the BLS sig, so the request is verified by
    /// construction — skip the verify dispatch and admit directly.
    pub fn on_verified_skip_request_received(
        &mut self,
        request: Arc<Verified<SkipRequest>>,
    ) -> Vec<Action> {
        self.admit_verified_skip_request(Arc::unwrap_or_clone(request))
    }

    /// A peer-assembled [`SkipEpochCert`](hyperscale_types::SkipEpochCert)
    /// arrived via gossip. Validate the non-crypto fields and dispatch
    /// BLS aggregate verification to the crypto pool. On a verified
    /// result, [`Self::on_beacon_block_verified`] builds and adopts the
    /// skip block (idempotent: ignored if the local tip has already
    /// advanced past the cert's epoch).
    pub fn on_skip_cert_received(&mut self, cert: Arc<Verifiable<SkipEpochCert>>) -> Vec<Action> {
        if cert.anchor_hash() != self.latest_block.block_hash() {
            trace!("SkipCert at unknown anchor — dropping");
            return Vec::new();
        }
        let expected_epoch = self.state.current_epoch.next();
        if cert.epoch_to_skip() != expected_epoch {
            trace!(
                epoch_to_skip = cert.epoch_to_skip().inner(),
                expected = expected_epoch.inner(),
                "SkipCert at unexpected epoch — dropping",
            );
            return Vec::new();
        }
        let active_pool = self.state.derive_active_pool();
        let anchor = self.latest_block.block_hash();
        let raw_cert = Arc::unwrap_or_clone(cert).into_unverified();
        let block = BeaconBlock::skip(expected_epoch, anchor);
        let certified = CertifiedBeaconBlock::new_unchecked(block, BeaconCert::Skip(raw_cert));
        let block_arc = Arc::new(Verifiable::from(certified));
        // Skip blocks carry no `committed_proposals`, so the equivocation
        // lookup is necessarily empty.
        self.dispatch_block_verification(block_arc, active_pool, Vec::new())
    }

    /// Build the skip block paired with `cert`, adopt it via the
    /// shared adoption path, and emit a broadcast so peers converge.
    fn commit_skip_block(&mut self, cert: Verified<SkipEpochCert>) -> Vec<Action> {
        let anchor = self.latest_block.block_hash();
        let raw_cert = cert.into_inner();
        let epoch_to_skip = raw_cert.epoch_to_skip();
        let block = BeaconBlock::skip(epoch_to_skip, anchor);
        let certified = Verified::<CertifiedBeaconBlock>::from_committed_assembly(
            block,
            BeaconCert::Skip(raw_cert),
        )
        .expect("skip block pairs with skip cert by construction");
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
        // Idempotency: another path (local skip-quorum assembly, an
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
        if !self.contributions_well_formed(block.block()) {
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

    /// A previously-dispatched [`Action::VerifySkipRequest`] has
    /// returned. Clears the `(anchor, epoch_to_skip, signer)` pipeline
    /// slot on both arms — the key fields ride back in the result event
    /// so a verification failure can't pin a signer's slot in-flight and
    /// block their later honest request — and on success admits the
    /// request to the [`SkipTracker`].
    pub fn on_skip_request_verified(
        &mut self,
        anchor: BeaconBlockHash,
        epoch_to_skip: Epoch,
        signer: ValidatorId,
        result: Result<Verified<SkipRequest>, SkipRequestVerifyError>,
    ) -> Vec<Action> {
        let key = (anchor, epoch_to_skip, signer);
        let request = match result {
            Ok(r) => r,
            Err(err) => {
                self.verification.forget_skip_request(key);
                warn!(%err, "SkipRequest BLS verification failed — dropping");
                return Vec::new();
            }
        };
        self.verification.forget_skip_request(key);
        self.admit_verified_skip_request(request)
    }

    /// A [`SkipRequest`] has passed BLS verification: admit it to the
    /// tracker, and if the local tip now sits at a skip-quorum, assemble
    /// the cert, build the skip block, adopt locally, and broadcast.
    fn admit_verified_skip_request(&mut self, request: Verified<SkipRequest>) -> Vec<Action> {
        // Tip may have advanced since dispatch; re-check the anchor +
        // epoch before admission so a stale verified request can't push
        // into the wrong bucket.
        let anchor = self.latest_block.block_hash();
        let expected_epoch = self.state.current_epoch.next();
        if request.anchor_hash() != anchor || request.epoch_to_skip() != expected_epoch {
            trace!(
                signer = ?request.signer(),
                "Verified SkipRequest no longer matches tip — dropping",
            );
            return Vec::new();
        }
        if !self.skip_tracker.observe(request) {
            return Vec::new();
        }
        let active_pool = self.state.derive_active_pool();
        if !self
            .skip_tracker
            .quorum_reached(anchor, expected_epoch, active_pool.len())
        {
            return Vec::new();
        }
        let Some(cert) = self
            .skip_tracker
            .try_assemble(anchor, expected_epoch, &active_pool)
        else {
            warn!("SkipTracker quorum reached but try_assemble returned None");
            return Vec::new();
        };
        self.commit_skip_block(cert)
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
        Vec::new()
    }

    /// Record a verified source-shard header and note any epoch-boundary
    /// crossing it makes visible. Off-committee vnodes retain the header
    /// (their inbound `BeaconBlock` verifier needs it to check witness
    /// merkle paths) and emit nothing. On-committee vnodes additionally
    /// fetch the witness chunk of the shard's latest observed crossing via
    /// [`fetch_witness_chunk`](Self::fetch_witness_chunk) — the leaves
    /// `[prior, chunk_end)` the boundary fold will apply next, anchored to
    /// the boundary block, bounded to [`MAX_WITNESSES_PER_FETCH`] leaves
    /// per call so a large producer/consumer gap can't make one header do
    /// unbounded work.
    pub fn on_verified_remote_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        self.shard_source
            .on_verified_remote_header(Arc::clone(certified_header));
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

    /// Fetch the missing leaves of `shard`'s current witness chunk,
    /// anchored to its latest observed crossing's boundary block.
    ///
    /// The anchor is the boundary block `B` (not whichever header just
    /// arrived): a witness proves against `B`'s `beacon_witness_root`, and
    /// the chunk is the leaves `[prior, chunk_end)` the boundary fold will
    /// apply next (`prior` = the applied watermark). Bounded to
    /// [`MAX_WITNESSES_PER_FETCH`] leaves per call; later commits advance
    /// the watermark and the next observation re-issues for the rest.
    fn fetch_witness_chunk(&mut self, shard: ShardId) -> Vec<Action> {
        let (anchor, block_height, prior, chunk_end) = {
            let Some(crossing) = self.shard_source.latest_crossing(shard) else {
                return Vec::new();
            };
            let boundary_header = crossing.boundary_header();
            let (prior, chunk_end) = self.witness_chunk_bounds(shard, boundary_header);
            (
                crossing.canonical_qc().block_hash(),
                boundary_header.height(),
                prior,
                chunk_end,
            )
        };
        let window_end = chunk_end.min(prior.saturating_add(MAX_WITNESSES_PER_FETCH as u64));
        let mut leaves_to_fetch: Vec<LeafIndex> = Vec::new();
        let mut leaf = prior;
        while leaf < window_end {
            let li = LeafIndex::new(leaf);
            if self
                .shard_source
                .register_pending_fetch(shard, block_height, anchor, li)
            {
                leaves_to_fetch.push(li);
            }
            leaf = leaf.saturating_add(1);
        }
        if leaves_to_fetch.is_empty() {
            return Vec::new();
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

    /// Advance `self.state` / `self.latest_block` to `block` after
    /// running `apply_epoch` over its committed proposals. Resets
    /// per-epoch caches, bootstraps next epoch's SPC if local is on
    /// the new committee. Emits `CommitBeaconBlock` only — no
    /// broadcast (caller decides whether the local node is the
    /// originator).
    fn adopt_block(&mut self, block: Arc<Verified<CertifiedBeaconBlock>>) -> Vec<Action> {
        // The anchor we're committing past. Its skip-request buckets are
        // stale on any commit path once the tip advances, so drop them
        // here.
        let prior_tip = self.latest_block.block_hash();
        let mut new_state = self.state.clone();
        let input = apply_input_for(&block);
        apply_epoch(&mut new_state, &self.network, block.epoch(), input);
        self.state = new_state;
        self.latest_block = Arc::clone(&block);
        self.spc = None;
        self.skip_tracker.forget_anchor(prior_tip);

        // Refresh the head and record the active snapshot for the just-applied
        // epoch plus the lookahead for the next, then drop entries that fell
        // out of the retention window. The lookahead entry lets a shard
        // resolve its committee a full epoch before its window opens.
        let head = Arc::new(self.state.derive_topology_snapshot(self.network.clone()));
        let epoch = self.state.current_epoch;
        self.topology.set_head(Arc::clone(&head));
        self.topology.insert(epoch, head);
        self.topology.insert(
            epoch.next(),
            Arc::new(
                self.state
                    .derive_next_topology_snapshot(self.network.clone()),
            ),
        );
        self.topology.evict_before(epoch);

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
                topology_snapshot: Arc::clone(self.topology.head()),
            },
            // Re-arm the skip-trigger timer against the new tip. Fires
            // `SKIP_TIMEOUT` after the upcoming epoch's boundary if no
            // commit lands by then.
            Action::SetTimer {
                id: TimerId::BeaconSkipTrigger,
                duration: self
                    .duration_until_next_epoch_boundary()
                    .saturating_add(SKIP_TIMEOUT),
            },
        ];

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

        // Self-perpetuate the next epoch's SPC, but only once wall-clock has
        // reached its boundary. While the beacon is behind real time (catch-up
        // after a gap, or `now` already past the boundary) this fires straight
        // away and the chain cascades to catch up; once the synthetic epoch
        // clock reaches wall-clock it instead arms `BeaconCommitteeStart` for
        // the boundary, so the beacon paces to real time rather than racing
        // ahead at SPC-round speed.
        if self.is_on_committee() {
            if self.committee_start_due(self.next_epoch_boundary()) {
                self.bootstrap_spc_for_next_epoch();
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

    /// SPC has decided this epoch. When every committed-vector
    /// element resolves to a pooled proposal, assemble the block
    /// directly. Otherwise stash the cert + output keyed by `epoch`
    /// and emit one `Action::Fetch(FetchRequest::BeaconProposal { … })`
    /// per missing element; assembly resumes from
    /// [`Self::on_beacon_proposal_fetched`] once every awaited fetch
    /// lands. Concurrent stashes for different epochs are allowed —
    /// stale entries get evicted from `adopt_block` once
    /// `current_epoch` advances past them. The fetch's routing
    /// `shard` is the dispatching vnode's `local_shard` (peer
    /// selection rides the local committee); `preferred` rotates
    /// through the beacon committee so multiple missing proposals
    /// don't all target the same peer.
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
            } => self.assemble_and_adopt(epoch, committed, *cert),
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

    /// Build the certified block from `committed` + SPC `cert`, route
    /// it through the shared adoption path, and emit the gossip
    /// broadcast.
    ///
    /// Defers (emitting nothing) when a committed boundary's source
    /// header isn't synced locally: assembling an incomplete contribution
    /// set would diverge from a fully-synced peer's block, so the local
    /// node waits for that peer's gossiped block instead.
    fn assemble_and_adopt(
        &mut self,
        epoch: Epoch,
        committed: Vec<(ValidatorId, Verified<BeaconProposal>)>,
        cert: Verified<SpcCert>,
    ) -> Vec<Action> {
        let Some(shard_contributions) = self.build_shard_contributions(&committed) else {
            trace!(
                epoch = epoch.inner(),
                "Deferring beacon assembly — a committed boundary's source header isn't synced \
                 locally; awaiting a fully-synced peer's gossiped block",
            );
            return Vec::new();
        };
        let prev_block_hash = self.latest_block.block_hash();
        let certified = Verified::<CertifiedBeaconBlock>::assemble(
            epoch,
            prev_block_hash,
            committed,
            shard_contributions,
            cert,
        )
        .expect("Normal beacon block pairs with SPC cert by construction");
        let block_arc = Arc::new(certified);

        let mut actions = self.adopt_block(Arc::clone(&block_arc));
        actions.push(Action::BroadcastBeaconBlock { block: block_arc });
        actions
    }

    /// Assemble this epoch's per-shard boundary contributions — the
    /// canonical projection of the committed proposals' boundary QCs.
    ///
    /// Per shard, [`canonical_boundary_qcs`] selects the highest-weighted
    /// committed QC, and this seats the header for the block it names,
    /// pulled from the local crossing tracker or header window. Every
    /// committed boundary QC is a genuine `2f+1` crossing (enforced at
    /// proposal admission), so the projection is a pure function of the
    /// cert-bound committed proposals — every honest assembler that can
    /// back it builds the byte-identical map.
    ///
    /// Returns `None` to **defer** when a committed boundary's source
    /// header isn't held locally: a block that omitted that shard would
    /// diverge from a fully-synced peer's, so the local node waits for the
    /// peer's gossiped block rather than assemble an incomplete one.
    fn build_shard_contributions(
        &self,
        committed: &[(ValidatorId, Verified<BeaconProposal>)],
    ) -> Option<BTreeMap<ShardId, ShardEpochContribution>> {
        let canonical = canonical_boundary_qcs(committed.iter().map(|(_, p)| &**p));
        let mut contributions = BTreeMap::new();
        for (shard, qc) in canonical {
            let boundary_header = self.boundary_header_for(shard, qc.block_hash())?.clone();
            let (prior, chunk_end) = self.witness_chunk_bounds(shard, &boundary_header);
            // Defer the whole block if the chunk isn't in hand — a
            // fully-synced peer will assemble and gossip it.
            let witnesses =
                self.shard_source
                    .witness_chunk(shard, qc.block_hash(), prior, chunk_end)?;
            contributions.insert(
                shard,
                ShardEpochContribution {
                    boundary_header,
                    witnesses: witnesses.into(),
                },
            );
        }
        Some(contributions)
    }

    /// Whether `block`'s shard contributions are the faithful canonical
    /// projection of its cert-bound committed boundary QCs: exactly one
    /// contribution per shard that has a committed QC, each binding by hash
    /// to that shard's highest-weighted committed QC, forming a genuine
    /// epoch-boundary crossing, and carrying exactly the witness chunk
    /// `[prior, chunk_end)` (merkle-proven against the boundary root).
    /// Deterministic — a pure function of the committed proposals, the
    /// contributions, and the parent `BeaconState` watermark, with no
    /// topology lookup — so every honest node reaches the same verdict on
    /// the same block and a Byzantine assembler's variant (a fabricated,
    /// stale, extra, omitted, or short-witnessed contribution) is rejected
    /// identically everywhere.
    fn contributions_well_formed(&self, block: &BeaconBlock) -> bool {
        let canonical = canonical_boundary_qcs(block.committed_proposals().iter().map(|(_, p)| p));
        let contributions = block.shard_contributions();
        if contributions.len() != canonical.len() {
            return false;
        }
        canonical.into_iter().all(|(shard, qc)| {
            contributions.get(&shard).is_some_and(|contribution| {
                let header = &contribution.boundary_header;
                if header.hash() != qc.block_hash() || !self.is_boundary_crossing(header, qc) {
                    return false;
                }
                let (prior, chunk_end) = self.witness_chunk_bounds(shard, header);
                contribution_chunk_valid(header, &contribution.witnesses, prior, chunk_end)
            })
        })
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
            } => self.assemble_and_adopt(epoch, committed, *cert),
            AssemblyDecision::AwaitFetch { .. } | AssemblyDecision::Idle => Vec::new(),
        }
    }

    /// Shared handle to this coordinator's proposal pool. Lets the
    /// host hand the same `Arc` to the network-worker responder at
    /// `crates/node/src/shard_io/fetch/beacon_proposal_serve.rs` and
    /// lets tests run lookups without going through the network path.
    #[must_use]
    pub const fn proposal_pool(&self) -> &Arc<BeaconProposalPool> {
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
                SpcEffect::BroadcastNewCommit {
                    view,
                    value: _,
                    proof,
                } => {
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
        self.topology.head()
    }

    /// The per-epoch committee schedule — the verification interface handed to
    /// shard and execution coordinators. They resolve an artifact's committee
    /// from its weighted timestamp ([`TopologySchedule::at`]) and the routing
    /// head ([`TopologySchedule::head`]) through it, so no consensus-layer type
    /// crosses into their verification paths.
    #[must_use]
    pub const fn topology_schedule(&self) -> &TopologySchedule {
        &self.topology
    }

    /// Number of crypto verifications dispatched but not yet resulted.
    /// Test introspection — production code shouldn't gate on this.
    #[must_use]
    pub fn verifications_in_flight(&self) -> usize {
        self.verification.in_flight_count()
    }
}

/// Per-shard canonical boundary QC across a committed proposal set: the
/// entry with the highest `(weighted_timestamp, block_hash)`, breaking
/// ties on the hash so the choice is total and identical on every node.
///
/// Pure over the cert-bound committed proposals — the shared selection the
/// assembler projects into `shard_contributions` and the receiver
/// re-derives to validate one. Every committed boundary QC is a genuine
/// crossing (enforced at proposal admission), so the highest-timestamp
/// pick can't be inflated by a forged entry.
fn canonical_boundary_qcs<'a>(
    proposals: impl Iterator<Item = &'a BeaconProposal>,
) -> BTreeMap<ShardId, &'a QuorumCertificate> {
    let mut canonical: BTreeMap<ShardId, &QuorumCertificate> = BTreeMap::new();
    for proposal in proposals {
        for (shard, opt) in proposal.boundary_qcs().iter() {
            let Some(qc) = opt.as_ref().map(Verifiable::as_unverified) else {
                continue;
            };
            canonical
                .entry(*shard)
                .and_modify(|cur| {
                    if (qc.weighted_timestamp().as_millis(), qc.block_hash())
                        > (cur.weighted_timestamp().as_millis(), cur.block_hash())
                    {
                        *cur = qc;
                    }
                })
                .or_insert(qc);
        }
    }
    canonical
}

impl std::fmt::Debug for BeaconCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconCoordinator")
            .field("current_epoch", &self.state.current_epoch)
            .field("latest_block_hash", &self.latest_block.block_hash())
            .field("me", &self.me)
            .field("spc_active", &self.spc.is_some())
            .field(
                "verifications_in_flight",
                &self.verification.in_flight_count(),
            )
            .field("witness_chunks", &self.shard_source.total_chunk_len())
            .field("skip_buckets", &self.skip_tracker.bucket_count())
            .field("equivocations", &self.equivocations.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconBlock, BeaconBlockHash, BeaconChainConfig, BeaconGenesisConfig,
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeight, Bls12381G1PrivateKey,
        Bls12381G1PublicKey, BoundedVec, CertificateRoot, CertifiedBlockHeader, Epoch,
        GenesisConfigHash, GenesisPool, GenesisValidator, Hash, InFlightCount, LeafIndex,
        LocalReceiptRoot, MIN_STAKE_FLOOR, NetworkDefinition, PcVector, ProposerTimestamp,
        ProvisionsRoot, Randomness, Round, ShardCommittee, ShardEpochContribution, ShardId,
        ShardWitness, ShardWitnessPayload, ShardWitnessProof, SignerBitfield, SpcCert, SpcView,
        Stake, StakePoolId, StateRoot, TransactionRoot, ValidatorId, VrfProof, WeightedTimestamp,
        bls_keypair_from_seed, build_qc1, build_qc2, build_qc3, compute_merkle_root_with_proof,
        genesis_config_hash, pc_context, sign_vote1, sign_vote2, sign_vote3, spc_context,
        zero_bls_signature,
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

    /// 4 validators, all on the beacon committee, all placed on shard 0.
    fn sample_genesis() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let shard = ShardId::leaf(1, 0);
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
            initial_shard_committees: std::iter::once((shard, members)).collect(),
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
        let pool = Arc::new(BeaconProposalPool::new(state.current_epoch.next()));
        BeaconCoordinator::new(
            block,
            vec![state],
            me,
            ShardId::leaf(1, 0),
            NetworkDefinition::simulator(),
            config_hash,
            pool,
        )
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
        assert!(coord.build_shard_contributions(&committed).is_none());

        // Header synced but the witness chunk isn't in hand — still defer
        // (the coupling rule: a boundary is only reportable with its chunk).
        coord.on_verified_remote_header(&b);
        assert!(coord.build_shard_contributions(&committed).is_none());

        // Once the witness chunk arrives, the contribution seats with it.
        coord.on_shard_witnesses_received(shard, witnesses.iter().cloned().map(Arc::new).collect());
        let built = coord
            .build_shard_contributions(&committed)
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
        assert!(coord.contributions_well_formed(&good));

        // Omits the committed shard's contribution — rejected.
        assert!(!coord.contributions_well_formed(&block_with(BTreeMap::new())));

        // Extra contribution for a shard with no committed QC — rejected.
        let mut extra: BTreeMap<ShardId, ShardEpochContribution> = BTreeMap::new();
        extra.insert(shard, contribution.clone());
        extra.insert(other, contribution);
        assert!(!coord.contributions_well_formed(&block_with(extra)));

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
        assert!(!coord.contributions_well_formed(&block_with(tampered)));

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
        assert!(!coord.contributions_well_formed(&block_with(short)));
    }

    /// Drive any beacon-verify actions in `actions` through to their
    /// result event, appending the post-verify actions in dispatch
    /// order. Mirrors the round-trip the production runner (and
    /// `CoordinatorSim`) perform; lets tests assert the
    /// synchronous-equivalent outcome without manually threading
    /// results back to the coordinator.
    fn complete_verifications(coord: &mut BeaconCoordinator, actions: Vec<Action>) -> Vec<Action> {
        use hyperscale_types::{CertifiedBeaconBlockVerifyContext, SkipVerifyContext};

        let net = NetworkDefinition::simulator();
        let mut out = Vec::new();
        for action in actions {
            match action {
                Action::VerifyBeaconBlock {
                    block,
                    signers,
                    equivocation_signers,
                } => {
                    let result = Arc::unwrap_or_clone(block)
                        .upgrade(&CertifiedBeaconBlockVerifyContext {
                            network: &net,
                            signers: &signers,
                            equivocation_signers: &equivocation_signers,
                        })
                        .map(Arc::new)
                        .map_err(|(_, e)| e);
                    let post = coord.on_beacon_block_verified(result);
                    out.extend(complete_verifications(coord, post));
                }
                Action::VerifySkipRequest { request, signers } => {
                    let anchor = request.anchor_hash();
                    let epoch_to_skip = request.epoch_to_skip();
                    let signer = request.signer();
                    let result = (*request)
                        .upgrade(&SkipVerifyContext {
                            network: &net,
                            active_pool: &signers,
                        })
                        .map_err(|(_, e)| e);
                    let post =
                        coord.on_skip_request_verified(anchor, epoch_to_skip, signer, result);
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
        let pool = Arc::new(BeaconProposalPool::new(state.current_epoch.next()));
        let coord = BeaconCoordinator::new(
            Arc::clone(&block),
            vec![state],
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            NetworkDefinition::simulator(),
            config_hash,
            pool,
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
        let pool = Arc::new(BeaconProposalPool::new(state.current_epoch.next()));
        let coord = BeaconCoordinator::new(
            block,
            vec![state],
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            NetworkDefinition::simulator(),
            config_hash,
            pool,
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
        let pool = Arc::new(BeaconProposalPool::new(state.current_epoch.next()));
        let _coord = BeaconCoordinator::new(
            Arc::new(mismatched_block),
            vec![state],
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            NetworkDefinition::simulator(),
            GenesisConfigHash::ZERO,
            pool,
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
        assert_eq!(coord.verification.in_flight_count(), 0);
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
        assert_eq!(coord.verification.in_flight_count(), 0);
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
        assert_eq!(coord.verification.in_flight_count(), 1);
    }

    #[test]
    fn on_beacon_spc_view_timer_drops_when_no_spc_instance() {
        let mut coord = fresh_coord();
        assert!(coord.on_beacon_spc_view_timer().is_empty());
    }

    #[test]
    fn committee_start_bootstraps_spc_for_on_committee_local() {
        let mut coord = fresh_coord();
        assert!(coord.spc.is_none());
        let actions = coord.on_beacon_committee_start_timer();
        let spc = coord.spc.as_ref().expect("SPC bootstrapped");
        assert_eq!(spc.epoch(), Epoch::GENESIS.next());
        assert_eq!(spc.current_view(), SpcView::new(1));
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
        assert!(coord.spc.is_none());
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
        assert!(coord.spc.is_some());
    }

    /// Two skip requests from the same signer at the same anchor/epoch
    /// but with different signature bytes collapse to one verification
    /// slot: the slot key is `(anchor, epoch_to_skip, signer)`, not the
    /// encoded-request hash, so a forged-sig flood can't mint extra
    /// in-flight BLS checks.
    #[test]
    fn skip_request_verification_keys_on_signer_not_signature() {
        use hyperscale_types::{Bls12381G2Signature, SkipRequest};
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1); // a peer on the active pool

        let req = |sig_byte: u8| {
            Arc::new(Verifiable::from(SkipRequest::new(
                anchor,
                epoch,
                signer,
                Bls12381G2Signature([sig_byte; 96]),
            )))
        };

        // First request dispatches one verification.
        let first = coord.on_unverified_skip_request_received(req(0));
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Action::VerifySkipRequest { .. }));
        assert_eq!(coord.verification.in_flight_count(), 1);

        // Same triple, different signature — deduped before dispatch.
        let second = coord.on_unverified_skip_request_received(req(1));
        assert!(second.is_empty());
        assert_eq!(coord.verification.in_flight_count(), 1);
    }

    /// A skip request that fails BLS verification releases its slot, so
    /// a later request for the same `(anchor, epoch, signer)` triple
    /// re-dispatches. Without clearing on the failure arm, a forged
    /// request could pin a signer's slot in-flight and block their
    /// honest request from ever being verified.
    #[test]
    fn failed_skip_request_verification_releases_slot() {
        use hyperscale_types::{Bls12381G2Signature, SkipRequest};
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1);

        let forged = Arc::new(Verifiable::from(SkipRequest::new(
            anchor,
            epoch,
            signer,
            Bls12381G2Signature([0u8; 96]), // garbage sig — fails BLS verify
        )));
        let dispatched = coord.on_unverified_skip_request_received(forged);
        assert_eq!(coord.verification.in_flight_count(), 1);

        // Drive the (failing) verification to completion — the slot clears.
        let _ = complete_verifications(&mut coord, dispatched);
        assert_eq!(coord.verification.in_flight_count(), 0);

        // A fresh request for the same triple re-dispatches rather than
        // being deduped against a pinned slot.
        let retry = Arc::new(Verifiable::from(SkipRequest::new(
            anchor,
            epoch,
            signer,
            Bls12381G2Signature([2u8; 96]),
        )));
        let redispatched = coord.on_unverified_skip_request_received(retry);
        assert_eq!(redispatched.len(), 1);
        assert!(matches!(redispatched[0], Action::VerifySkipRequest { .. }));
    }

    #[test]
    fn committee_start_no_op_when_off_committee() {
        let mut coord = new_coord(ValidatorId::new(99));
        let actions = coord.on_beacon_committee_start_timer();
        assert!(actions.is_empty());
        assert!(coord.spc.is_none());
    }

    #[test]
    fn committee_start_is_idempotent() {
        let mut coord = fresh_coord();
        coord.on_beacon_committee_start_timer();
        let spc_view_first = coord.spc.as_ref().unwrap().current_view();
        coord.on_beacon_committee_start_timer();
        let spc_view_second = coord.spc.as_ref().unwrap().current_view();
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

    #[test]
    fn own_proposal_feedback_feeds_spc_view_one_input() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        assert!(!coord.spc.as_ref().unwrap().view_one_input_fed());
        let actions = coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastPcVote1 { .. })),
            "expected SignAndBroadcastPcVote1 in {actions:?}",
        );
        assert!(coord.spc.as_ref().unwrap().view_one_input_fed());
    }

    #[test]
    fn peer_proposal_does_not_trigger_view_one_input_feed() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(1),
            Epoch::GENESIS.next(),
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty(), "peer proposal alone doesn't kick PC");
        assert!(!coord.spc.as_ref().unwrap().view_one_input_fed());
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
    ) -> SpcCert {
        let net = NetworkDefinition::simulator();
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, prev_view);
        let v_in = PcVector::empty();
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

    /// Build a peer `BeaconBlock` at `epoch` that verifies under
    /// `coord`'s state. `signer_positions` selects which committee
    /// members contribute to the cert (default `n - f` for honest
    /// quorum).
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
        let cert = build_direct_cert(SpcView::new(1), epoch, &keys, &committee, &signer_positions);
        let block = BeaconBlock::new(epoch, prev_hash, Vec::new());
        Arc::new(Verifiable::from(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Normal(Box::new(cert)),
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

    /// Committing an epoch *normally* forgets the prior tip's
    /// skip-request buckets, not just the skip-commit path — otherwise a
    /// bucket leaks for every epoch that saw a skip request before
    /// committing normally.
    #[test]
    fn normal_commit_forgets_prior_tip_skip_buckets() {
        use hyperscale_types::SkipRequest;
        let mut coord = fresh_coord();
        let genesis_tip = coord.latest_block.block_hash();
        // A skip request observed at the genesis tip for the in-flight
        // epoch.
        let req = Verified::<SkipRequest>::sign_local(
            &keypair(0),
            ValidatorId::new(0),
            &NetworkDefinition::simulator(),
            genesis_tip,
            Epoch::new(1),
        );
        assert!(coord.skip_tracker.observe(req));
        assert_eq!(coord.skip_tracker.bucket_count(), 1);

        // Commit epoch 1 normally (a valid peer block chaining off genesis).
        let block = valid_block_at(&coord, Epoch::new(1), genesis_tip);
        let dispatched = coord.on_beacon_block_received(block);
        let _ = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.current_epoch(), Epoch::new(1));
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
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
        assert!(coord.spc.is_some(), "next epoch's SPC should bootstrap");
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
            coord.spc.is_none(),
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
            coord.spc.is_some(),
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
        assert!(observer.spc.is_none());
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
        assert!(observer.spc.is_none());
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

    /// `on_spc_output_high` commits and broadcasts directly: the SPC cert
    /// authenticates the block, so the decision yields `CommitBeaconBlock`
    /// then `BroadcastBeaconBlock` with no header-signature round in between.
    #[test]
    fn output_high_emits_commit_and_broadcast_directly() {
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
        );

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );

        // The SPC cert authenticates the block, so OutputHigh produces
        // Commit + TopologyChanged + Broadcast directly. (The next-epoch
        // BuildAndBroadcastBeaconProposal also tails on since the genesis
        // committee doesn't rotate.)
        let kinds: Vec<&str> = actions.iter().map(Action::type_name).collect();
        assert!(
            kinds.starts_with(&["CommitBeaconBlock", "TopologyChanged"]),
            "expected commit-then-topology prefix, got {kinds:?}",
        );
        assert!(
            kinds.contains(&"BroadcastBeaconBlock"),
            "expected BroadcastBeaconBlock in {kinds:?}",
        );
        assert_eq!(coord.state.current_epoch, in_flight);
        assert_eq!(coord.latest_block.epoch(), in_flight);
    }

    /// Build a real skip request signed by validator `seed`'s key,
    /// wrapped for the `on_unverified_skip_request_received` receive
    /// shape.
    fn signed_skip_request(
        seed: u64,
        validator: ValidatorId,
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
    ) -> Arc<Verifiable<SkipRequest>> {
        use hyperscale_types::sign_skip_request;
        let sk = keypair(seed);
        let net = NetworkDefinition::simulator();
        let raw = sign_skip_request(&sk, validator, &net, anchor_hash, epoch_to_skip);
        Arc::new(Verifiable::from(raw))
    }

    #[test]
    fn on_skip_request_drops_at_wrong_anchor() {
        let mut coord = fresh_coord();
        // Wrong anchor: zero hash isn't the local tip.
        let req = signed_skip_request(
            0,
            ValidatorId::new(0),
            BeaconBlockHash::ZERO,
            coord.state.current_epoch.next(),
        );
        let actions = coord.on_unverified_skip_request_received(req);
        assert!(actions.is_empty());
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
    }

    #[test]
    fn on_skip_request_drops_at_wrong_epoch() {
        let mut coord = fresh_coord();
        // Right anchor, wrong epoch_to_skip (we expect current.next()).
        let req = signed_skip_request(
            0,
            ValidatorId::new(0),
            coord.latest_block.block_hash(),
            Epoch::new(99),
        );
        let actions = coord.on_unverified_skip_request_received(req);
        assert!(actions.is_empty());
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
    }

    #[test]
    fn on_skip_request_drops_non_pool_signer() {
        let mut coord = fresh_coord();
        let req = signed_skip_request(
            99,
            ValidatorId::new(99),
            coord.latest_block.block_hash(),
            coord.state.current_epoch.next(),
        );
        let actions = coord.on_unverified_skip_request_received(req);
        assert!(actions.is_empty());
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
    }

    #[test]
    fn on_skip_request_drops_invalid_sig_via_async_result() {
        use hyperscale_types::Bls12381G2Signature;
        let mut coord = fresh_coord();
        // Signer 0 is in the pool, but sig is all-zeros — verification
        // returns false on the result path.
        let req = Arc::new(Verifiable::from(SkipRequest::new(
            coord.latest_block.block_hash(),
            coord.state.current_epoch.next(),
            ValidatorId::new(0),
            Bls12381G2Signature([0u8; 96]),
        )));
        let dispatched = coord.on_unverified_skip_request_received(req);
        // Synchronous validation passes (signer in pool, anchor + epoch
        // match) — so a verify action is dispatched.
        let [Action::VerifySkipRequest { .. }] = dispatched.as_slice() else {
            panic!("expected single VerifySkipRequest, got {dispatched:?}");
        };
        let actions = complete_verifications(&mut coord, dispatched);
        assert!(actions.is_empty(), "invalid sig should drop on result");
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
    }

    #[test]
    fn on_skip_request_admits_valid_request_below_quorum() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let anchor = coord.latest_block.block_hash();
        let epoch_to_skip = coord.state.current_epoch.next();
        let req = signed_skip_request(0, ValidatorId::new(0), anchor, epoch_to_skip);
        let dispatched = coord.on_unverified_skip_request_received(req);
        let actions = complete_verifications(&mut coord, dispatched);
        assert!(actions.is_empty());
        assert_eq!(
            coord.skip_tracker.signer_count(anchor, epoch_to_skip),
            1,
            "request must land in the tracker after verification",
        );
        // n=4 → quorum is ⌈8/3⌉+1 = 4. One sig is below.
        assert!(coord.spc.is_some(), "SPC still running below quorum");
    }

    /// Reaching skip-quorum at the local tip builds + adopts the skip
    /// block, broadcasts it, advances the epoch counter, and clears
    /// the SPC instance for the abandoned epoch (the next epoch's SPC
    /// bootstraps on adoption since the local node remains on the
    /// committee).
    #[test]
    fn on_skip_request_assembles_cert_and_adopts_skip_block_on_quorum() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let anchor = coord.latest_block.block_hash();
        let epoch_to_skip = coord.state.current_epoch.next();
        let n = coord.state.committee.len();

        let mut emitted: Vec<Action> = Vec::new();
        for i in 0..u64::try_from(n).unwrap() {
            let req = signed_skip_request(i, ValidatorId::new(i), anchor, epoch_to_skip);
            let dispatched = coord.on_unverified_skip_request_received(req);
            emitted.extend(complete_verifications(&mut coord, dispatched));
        }

        // Adoption happened: epoch advanced past the skipped one.
        assert_eq!(coord.state.current_epoch, epoch_to_skip);
        // Tip now points at the Skip block.
        assert!(matches!(coord.latest_block.cert(), BeaconCert::Skip(_)));
        // Skip cert anchored at the previous tip's hash.
        if let BeaconCert::Skip(cert) = coord.latest_block.cert() {
            assert_eq!(cert.anchor_hash(), anchor);
            assert_eq!(cert.epoch_to_skip(), epoch_to_skip);
        }
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
        // Tracker bucket cleared after adoption.
        assert_eq!(coord.skip_tracker.bucket_count(), 0);
    }

    /// Two assemblies at the same quorum — e.g. a duplicate
    /// re-observation that re-hits quorum — must be idempotent: the
    /// adoption path's `apply_epoch` regression check would panic if
    /// the coordinator tried to re-adopt the skip block.
    #[test]
    fn on_skip_request_duplicate_after_adoption_is_noop() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let anchor = coord.latest_block.block_hash();
        let epoch_to_skip = coord.state.current_epoch.next();
        let n = coord.state.committee.len();

        for i in 0..u64::try_from(n).unwrap() {
            let req = signed_skip_request(i, ValidatorId::new(i), anchor, epoch_to_skip);
            let dispatched = coord.on_unverified_skip_request_received(req);
            let _ = complete_verifications(&mut coord, dispatched);
        }
        // The tip's anchor has moved on. A late duplicate against the
        // old anchor is dropped by the anchor-mismatch check.
        let stale = signed_skip_request(0, ValidatorId::new(0), anchor, epoch_to_skip);
        let actions = coord.on_unverified_skip_request_received(stale);
        assert!(actions.is_empty(), "stale anchor must be a no-op");
    }

    /// Once the skip-quorum is reached at the local tip, the SPC
    /// dispatch gate drops further SPC events for the abandoned
    /// epoch.
    #[test]
    fn dispatch_spc_event_gated_by_skip_quorum() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let anchor = coord.latest_block.block_hash();
        let epoch_to_skip = coord.state.current_epoch.next();
        let n = coord.state.committee.len();
        // Observe quorum-1 requests so the tracker holds quorum-many
        // entries but we observe them without triggering the adoption
        // path. To do that, observe one fewer than required, then
        // separately bump the tracker via `observe` to cross quorum
        // without re-driving adoption — this is what the gate is for.
        for i in 0..u64::try_from(n - 1).unwrap() {
            let req = signed_skip_request(i, ValidatorId::new(i), anchor, epoch_to_skip);
            let dispatched = coord.on_unverified_skip_request_received(req);
            let _ = complete_verifications(&mut coord, dispatched);
        }
        // Push the last request directly into the tracker, bypassing
        // the adoption-on-quorum branch — simulates the gate firing
        // between observation and the next dispatch.
        let last_idx = u64::try_from(n - 1).unwrap();
        let last_sk = keypair(last_idx);
        let last_req = Verified::<SkipRequest>::sign_local(
            &last_sk,
            ValidatorId::new(last_idx),
            &NetworkDefinition::simulator(),
            anchor,
            epoch_to_skip,
        );
        coord.skip_tracker.observe(last_req);
        assert!(coord.skip_quorum_at_tip());

        // SPC dispatch is now gated — events drop without dispatching
        // into the FSM (state unchanged, no broadcast actions).
        let from = ValidatorId::new(0);
        let actions = coord.dispatch_spc_event(
            from,
            SpcEvent::TimerExpired {
                view: SpcView::new(1),
            },
        );
        assert!(actions.is_empty(), "gated dispatch must emit no actions");
        // The SPC instance stays Some — gate is query-based, not
        // state-based.
        assert!(coord.spc.is_some());
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

        let parent_qc = QuorumCertificate::genesis(shard);
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
    fn on_verified_remote_header_caps_leaf_fetch_window() {
        use hyperscale_types::{MAX_WITNESSES_PER_FETCH, ShardId};
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);

        // A `(B, C)` crossing of the epoch-1 cut: `B`'s predecessor sits
        // at wt 1 (≤ the 300_000 ms cut) and `B`'s own wt is 300_001 (past
        // it), with a large accumulator at `B`.
        let total_leaves = u64::try_from(MAX_WITNESSES_PER_FETCH + 50).unwrap();
        let b = linked_block_header(shard, 5, BlockHash::ZERO, 1, total_leaves);
        let c = linked_block_header(shard, 6, b.block_hash(), 300_001, total_leaves);
        coord.on_verified_remote_header(&b);
        let actions = coord.on_verified_remote_header(&c);

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
            .on_verified_remote_header(Arc::clone(&header));

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
            .on_verified_remote_header(Arc::clone(&header));

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
        // record exists for (we never call on_verified_remote_header).
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
            .on_verified_remote_header(Arc::clone(&header));

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
            .on_verified_remote_header(Arc::clone(&header));

        let actions = observer.on_shard_witnesses_received(shard, vec![witness]);
        assert!(actions.is_empty());
        // Pool stays empty — off-committee never admits witnesses.
        assert_eq!(observer.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn current_topology_snapshot_reflects_genesis_state() {
        let coord = fresh_coord();
        let snap = coord.current_topology_snapshot();
        // 4 validators all on shard 0.
        assert_eq!(snap.num_shards(), 1);
        assert_eq!(snap.committee_for_shard(ShardId::leaf(1, 0)).len(), 4);
    }

    // ─── topology schedule + resolver ────────────────────────────────────

    /// A state at `epoch` whose shard-0 committee (active and lookahead)
    /// holds `size` members, so snapshots derived for different epochs
    /// are distinguishable by committee size.
    fn state_at(epoch: u64, size: u64) -> BeaconState {
        let mut s = build_genesis_beacon_state(&sample_genesis());
        s.current_epoch = Epoch::new(epoch);
        let committee = ShardCommittee {
            members: (0..size).map(ValidatorId::new).collect(),
        };
        s.shard_committees
            .insert(ShardId::leaf(1, 0), committee.clone());
        s.next_shard_committees
            .insert(ShardId::leaf(1, 0), committee);
        s
    }

    fn coord_from_history(history: Vec<BeaconState>) -> BeaconCoordinator {
        let (block, _genesis_state, config_hash) = genesis_trio();
        let next_epoch = history
            .last()
            .expect("non-empty history")
            .current_epoch
            .next();
        BeaconCoordinator::new(
            block,
            history,
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            NetworkDefinition::simulator(),
            config_hash,
            Arc::new(BeaconProposalPool::new(next_epoch)),
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
        let shard = ShardId::leaf(1, 0);
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

    /// A history longer than the retention window is bounded at
    /// construction — the oldest epochs drop out, the newest stay.
    #[test]
    fn schedule_evicts_history_beyond_retention() {
        let newest = TOPOLOGY_SCHEDULE_RETENTION_EPOCHS + 3;
        let history: Vec<BeaconState> = (0..=newest).map(|e| state_at(e, 4)).collect();
        let coord = coord_from_history(history);
        let ed = coord.current_state().chain_config.epoch_duration_ms;
        let resolves = |window: u64| {
            coord
                .topology_schedule()
                .at(WeightedTimestamp::from_millis(window * ed))
                .is_some()
        };
        assert!(!resolves(0), "epoch 0 should be evicted past retention");
        assert!(resolves(newest), "newest epoch retained");
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
        );

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(
            in_flight,
            &output,
            Verified::new_unchecked_for_test(cert),
            &recipients,
        );

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
}
