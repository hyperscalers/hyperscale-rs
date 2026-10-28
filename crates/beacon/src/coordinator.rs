//! Top-level beacon FSM.
//!
//! [`BeaconCoordinator`] is one identity's beacon state machine: a
//! [`BeaconFold`] that follows the chain — the committed [`BeaconState`],
//! the topology schedule and the wall-clock anchor that drives
//! epoch-cadence timers — and that identity's one [`BeaconParticipant`],
//! which runs its SPC, ratification and proposal duty. A host drives one
//! fold and a participant per identity on its beacon loop; this pairing is
//! the single-identity shape the crate's harnesses drive.
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

use std::borrow::Borrow;
use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    BeaconBlockHash, BeaconProposal, BeaconState, BlockHash, BlockHeight, CandidateBeaconBlock,
    CandidateBeaconBlockVerifyError, CertifiedBeaconBlock, CertifiedBeaconBlockVerifyError,
    CertifiedBlockHeader, ConsensusPublicKey, Epoch, GenesisConfigHash, Hash, LeafIndex,
    LocalTimestamp, NetworkDefinition, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError,
    PcVote3, PcVote3VerifyError, RETENTION_HORIZON, RatifyPhase, RatifyRound, RatifyVote,
    RatifyVoteRecord, RatifyVoteVerifyError, ShardForkProof, ShardId, ShardVoteEquivocation,
    ShardWitnessPayload, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError, SpcNewCommitMsg,
    SpcNewCommitMsgVerifyError, SpcProposalObject, SpcProposalObjectVerifyError, SpcView,
    TopologySchedule, TopologySnapshot, ValidatorId, Verifiable, Verified, Verifier,
    WeightedTimestamp,
};

use crate::fold::{Adopted, BeaconFold, ChainRegistration};
use crate::participant::{BeaconParticipant, ParticipantStep};
use crate::proposal_pool::BeaconProposalPool;

/// The topology schedule a coordinator resumed over `history` holds,
/// `history` running oldest to newest and ending at the latest committed
/// state.
///
/// # Panics
///
/// Panics if `history` is empty.
#[must_use]
pub fn resumed_schedule<B: Borrow<BeaconState>>(
    history: &[B],
    network: &NetworkDefinition,
) -> TopologySchedule {
    let latest = history
        .last()
        .expect("history must carry at least the latest committed state")
        .borrow();
    let latest_epoch = latest.current_epoch;
    // The head and the latest epoch's active committee are the same
    // snapshot; derive it once and let the schedule share the handle.
    // Seed every other loaded state's active committee under its own epoch
    // and its lookahead under the next, oldest first so each window's
    // projection is kept as the fold before it published it, then
    // reinstate the head so the latest epoch shares its handle.
    let head = Arc::new(latest.derive_topology_snapshot(network.clone()));
    let mut schedule = TopologySchedule::new(
        latest.chain_config.epoch_windows(),
        latest_epoch,
        Arc::clone(&head),
    );
    for state in history.iter().map(Borrow::borrow) {
        if state.current_epoch != latest_epoch {
            schedule.insert(
                state.current_epoch,
                Arc::new(state.derive_topology_snapshot(network.clone())),
            );
        }
        schedule.insert_lookahead(
            state.current_epoch.next(),
            Arc::new(state.derive_next_topology_snapshot(network.clone())),
        );
    }
    schedule.insert(latest_epoch, head);
    schedule
}

/// Re-insert into `schedule` the windows `history` carries below its
/// oldest retained epoch.
///
/// `history` runs oldest to newest. Eviction
/// is only the absence of entries below the oldest, so a window evicted
/// here resolves again once a state that projected it is reloaded.
/// Retained windows are left as they are.
pub fn widen_schedule<B: Borrow<BeaconState>>(
    schedule: &mut TopologySchedule,
    history: &[B],
    network: &NetworkDefinition,
) {
    let Some((oldest, _)) = schedule.retained_epochs() else {
        return;
    };
    for state in history.iter().map(Borrow::borrow) {
        let epoch = state.current_epoch;
        if epoch >= oldest {
            break;
        }
        if epoch.next() < oldest {
            schedule.insert_lookahead(
                epoch.next(),
                Arc::new(state.derive_next_topology_snapshot(network.clone())),
            );
        }
        schedule.insert(
            epoch,
            Arc::new(state.derive_topology_snapshot(network.clone())),
        );
    }
}

/// Oldest epoch the topology schedule must retain — the minimum of the
/// consumer frontiers that still verify QC-bearing artifacts:
///
/// - the oldest committee anchor over the registered shard chains whose
///   terminal latch is unset (`local_committee_anchor`): a committed tip is
///   signed by the committee its *parent* anchors, so this trails the tip's
///   own anchor by one commit. Live votes/headers and synced blocks all key
///   their schedule lookups at or after it. `None` when no such chain is
///   registered — a vnode that runs no shard chain, or one whose chain has
///   latched past its terminal — which keys no lookup of its own, so the
///   term drops out;
/// - each shard's last live boundary epoch, minus one window of slack (a
///   boundary block is signed by the committee at its *parent* QC's weighted
///   timestamp, which can land one window earlier): the next legitimate
///   boundary QC or remote header from a stalled shard is signed no earlier;
/// - each lingering terminal record's cut and each settled-window floor,
///   minus the same slack: the evidence those records still name resolves
///   its signing committee there;
/// - the tx-artifact horizon (`now − RETENTION_HORIZON`): provisions and
///   execution certificates are provably terminal past it.
///
/// Clamped to `state.current_epoch` so the head entry always survives.
/// Anything attested below the floor is provably bogus or provably
/// terminal, so a schedule miss below it is rejectable, never deferrable.
///
/// **Not consensus-critical**: the floor bounds a node-local cache; nodes
/// with different frontiers produce the same chain.
#[must_use]
pub fn retention_floor(
    state: &BeaconState,
    local_committee_anchor: Option<WeightedTimestamp>,
    now: LocalTimestamp,
) -> Epoch {
    let windows = state.chain_config.epoch_windows();
    let local_chain = local_committee_anchor.map(|anchor| windows.epoch_for(anchor));
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
        // snap-sync its anchor and the still-seated predecessor can resolve
        // its own committee. Its schedule window must outlive the record, or
        // the floor rises the instant the successors advance — a beat before
        // the predecessor observes successor-live and dissolves — and evicts
        // the window mid-handoff.
        //
        // A terminal record pins the cut's own window: the shard leaves
        // the trie at its cut, so that window is the newest whose trie
        // carries the shard at all, and dropping it would stop resolving
        // the terminal — and with it a settled set — while its roots sat
        // in a record still held. The window below absorbs the same
        // signing slack as a live boundary's.
        .chain(
            state
                .boundaries
                .values()
                .filter_map(|b| b.terminal_epoch)
                .map(|terminal| Epoch::new(terminal.inner().saturating_sub(1))),
        )
        // And each settled-window floor pins the windows the settled
        // evidence reaches back to. A departed shard's set names every
        // settlement from that floor to its cut, and each named
        // certificate resolves its signing committee at its own vote
        // anchor — the committing block's window, which can sit several
        // epochs before the cut. Pinning only the cut's window would let
        // a survivor acquire the set, fetch the certificate, and then
        // drop it unverifiable: the committee that signed it evicted
        // while the evidence it authenticates was still readable. One
        // derivation with the serve and the terminal proposer
        // (`live_settled_window_floors`), so the schedule never stops
        // resolving what the attested window can still name.
        .chain(
            state
                .live_settled_window_floors()
                .into_values()
                .map(|floor| Epoch::new(windows.epoch_for(floor).inner().saturating_sub(1))),
        )
        .min()
        .unwrap_or(Epoch::GENESIS);
    let horizon = windows.epoch_for(WeightedTimestamp::from_millis(
        now.as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000),
    ));
    let floor = shard_boundaries.min(horizon).min(state.current_epoch);
    local_chain.map_or(floor, |local| local.min(floor))
}

/// The local shard chain's committed frontier, as the anchors its tip
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalChainAnchors {
    /// Committee anchor of the committed tip — the anchor its *parent*
    /// carried. The oldest anchor the local chain can still key a schedule
    /// lookup on; holds [`retention_floor`] open while the shard chain
    /// verifies blocks older than the beacon head (catch-up after downtime,
    /// resume after a stall).
    pub committee: WeightedTimestamp,

    /// The committed tip's *own* anchor, one hop newer than
    /// [`Self::committee`] — held so the next commit can shift it into
    /// place. A block's committee anchors on its parent, so the anchor a
    /// commit reports governs the block after it, and only becomes the
    /// retained floor once that block commits.
    ///
    /// Kept rather than derived: consecutive blocks' anchors sit an
    /// unbounded number of windows apart when the chain stalls between them
    /// (a QC aggregated after a view-change gap dates far past its parent's),
    /// so no fixed slack subtracted from the frontier bounds it.
    pub block: WeightedTimestamp,
}

impl LocalChainAnchors {
    /// The frontier of a chain that has committed nothing past genesis.
    pub const GENESIS: Self = Self {
        committee: WeightedTimestamp::ZERO,
        block: WeightedTimestamp::ZERO,
    };
}

/// One identity's beacon-chain coordinator: a [`BeaconFold`] and the
/// identity's [`BeaconParticipant`], driven together.
///
/// Synchronous event-driven FSM. Mirrors `ShardCoordinator`'s public
/// shape: handlers take `&mut self` and return `Vec<Action>`. A block a
/// participant handler certifies is adopted into the fold before the
/// handler returns, and the participant then settles the epoch it
/// decided.
pub struct BeaconCoordinator {
    fold: BeaconFold,
    participant: BeaconParticipant,
    /// The vnode's shard chain as the fold tracks it, or `None` for a
    /// coordinator whose vnode runs no shard chain.
    local_chain: Option<ChainRegistration>,
}

impl BeaconCoordinator {
    /// Construct a coordinator from `latest_block` and a `history` of
    /// recently-committed states (newest last; `history.last()` becomes
    /// the live state). Each state seeds the topology schedule with its
    /// active and lookahead snapshots, so the coordinator boots able to
    /// verify cross-shard artifacts back across the loaded window.
    /// `local_chain` is the local shard chain's recovered frontier and
    /// committed height (`RecoveredState::committee_anchor_wt`,
    /// `block_anchor_wt` and `committed_height`), or `None` for a vnode
    /// that runs no shard chain; it seeds the schedule's eviction floor
    /// and advances via
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
        verifier: Arc<dyn Verifier>,
        latest_block: Arc<Verified<CertifiedBeaconBlock>>,
        history: Vec<BeaconState>,
        me: ValidatorId,
        local_shard: ShardId,
        local_chain: Option<(LocalChainAnchors, BlockHeight)>,
        network: NetworkDefinition,
        expected_config_hash: GenesisConfigHash,
    ) -> Self {
        let mut fold = BeaconFold::new(
            verifier,
            latest_block,
            history,
            network,
            expected_config_hash,
        );
        let local_chain =
            local_chain.map(|(anchors, height)| fold.register_chain(local_shard, anchors, height));
        let participant = BeaconParticipant::new(&fold, me);
        let fetches = fold.set_host_on_committee(participant.is_on_committee(&fold));
        debug_assert!(
            fetches.is_empty(),
            "a fresh fold holds no crossing to fetch a witness for",
        );
        Self {
            fold,
            participant,
            local_chain,
        }
    }

    /// Run a participant handler, adopting the block it certified.
    fn drive<S: Into<ParticipantStep>>(
        &mut self,
        handler: impl FnOnce(&mut BeaconParticipant, &BeaconFold) -> S,
    ) -> Vec<Action> {
        let step: ParticipantStep = handler(&mut self.participant, &self.fold).into();
        let mut actions = step.actions;
        if let Some(block) = step.certified {
            actions.extend(self.adopt(block));
        }
        actions
    }

    fn adopt(&mut self, block: Arc<Verified<CertifiedBeaconBlock>>) -> Vec<Action> {
        self.fold
            .adopt(block)
            .map_or_else(Vec::new, |adopted| self.settle(adopted))
    }

    /// Follow an adoption through: the committee flag the fold's witness
    /// duty reads, the terminal witness re-drive, and the participant's
    /// half of the epoch it settled.
    fn settle(&mut self, adopted: Adopted) -> Vec<Action> {
        let mut actions = adopted.actions;
        let on_committee = self.participant.is_on_committee(&self.fold);
        actions.extend(self.fold.set_host_on_committee(on_committee));
        actions.extend(self.fold.redrive_terminal_witness_fetches());
        let effects = adopted.effects;
        actions.extend(self.drive(|p, fold| p.on_adopted(fold, &effects)));
        actions
    }

    /// Install the durable ratification record a restart recovered —
    /// see [`RatifyTracker::install_recovered_record`]. Call once,
    /// right after construction, before any input is processed; a
    /// record for a different epoch than the pending ratification is
    /// ignored.
    ///
    /// [`RatifyTracker::install_recovered_record`]: crate::ratify::RatifyTracker::install_recovered_record
    pub fn install_recovered_ratify_record(&mut self, record: &RatifyVoteRecord) {
        self.participant
            .install_recovered_ratify_record(&self.fold, record);
    }

    /// Runner calls this once before each batch of handler invocations
    /// so every handler in the batch reads a consistent `now`.
    pub const fn set_now(&mut self, now: LocalTimestamp) {
        self.fold.now = now;
    }

    /// Hash of the verified candidate held for the pending epoch, if
    /// any.
    #[must_use]
    pub fn pending_candidate_hash(&self) -> Option<BeaconBlockHash> {
        self.participant.pending_candidate_hash()
    }

    /// Local shard block committed: record its header, fetch its witness
    /// chunk while on the committee, and shift the local chain's anchors
    /// a hop, once per committed height — see
    /// [`BeaconFold::on_local_block_committed`]. Releases the proposals
    /// the header completes.
    pub fn on_local_block_committed(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let mut actions = match self.local_chain {
            Some(token) => self.fold.on_local_block_committed(token, certified_header),
            None => self.fold.on_source_header(certified_header),
        };
        actions.extend(self.drive(BeaconParticipant::on_source_header));
        actions
    }

    /// Schedule the first `BeaconCommitteeStart` timer so the upcoming
    /// epoch's SPC instance bootstraps. Subsequent epochs self-arm on
    /// adoption; this only covers the resume gap from a
    /// freshly-constructed or just-loaded coordinator.
    #[must_use]
    pub fn on_startup(&self) -> Vec<Action> {
        self.fold.on_startup()
    }

    /// `TimerId::BeaconRatifyTrigger` fired.
    pub fn on_beacon_ratify_timer(&mut self) -> Vec<Action> {
        self.drive(BeaconParticipant::on_beacon_ratify_timer)
    }

    /// A peer's round-1 PC vote arrived.
    pub fn on_pc_vote1_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: PcVote1,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_pc_vote1_received(epoch, view, vote))
    }

    /// A peer's round-2 PC vote arrived.
    pub fn on_pc_vote2_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<PcVote2>,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_pc_vote2_received(epoch, view, vote))
    }

    /// A peer's round-3 PC vote arrived.
    pub fn on_pc_vote3_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<PcVote3>,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_pc_vote3_received(epoch, view, vote))
    }

    /// A peer's SPC `new-view` arrived.
    pub fn on_spc_new_view_received(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        proposal: Arc<Verifiable<SpcProposalObject>>,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_spc_new_view_received(epoch, from, proposal))
    }

    /// A peer's SPC `new-commit` arrived.
    pub fn on_spc_new_commit_received(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_spc_new_commit_received(epoch, from, msg))
    }

    /// A peer's SPC `empty-view` attestation arrived.
    pub fn on_unverified_spc_empty_view_received(
        &mut self,
        epoch: Epoch,
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        self.drive(|p, _| p.on_unverified_spc_empty_view_received(epoch, msg))
    }

    /// A locally-signed empty-view attestation arrived via the
    /// self-loopback path.
    pub fn on_verified_spc_empty_view_received(
        &mut self,
        epoch: Epoch,
        msg: Box<Verified<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_verified_spc_empty_view_received(fold, epoch, msg))
    }

    /// Result of an [`Action::VerifySpcNewView`] dispatch.
    pub fn on_spc_new_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_spc_new_view_verified(fold, epoch, from, view, result))
    }

    /// Result of an [`Action::VerifySpcNewCommit`] dispatch.
    pub fn on_spc_new_commit_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_spc_new_commit_verified(fold, epoch, from, view, result))
    }

    /// Result of an [`Action::VerifySpcEmptyView`] dispatch.
    pub fn on_spc_empty_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_spc_empty_view_verified(fold, epoch, from, view, result))
    }

    /// Result of an [`Action::VerifyPcVote1`] dispatch.
    pub fn on_pc_vote1_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_pc_vote1_verified(fold, epoch, view, signer, result))
    }

    /// Result of an [`Action::VerifyPcVote2`] dispatch.
    pub fn on_pc_vote2_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_pc_vote2_verified(fold, epoch, view, signer, result))
    }

    /// Result of an [`Action::VerifyPcVote3`] dispatch.
    pub fn on_pc_vote3_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_pc_vote3_verified(fold, epoch, view, signer, result))
    }

    /// A round-1 PC vote received already verified.
    pub fn on_verified_pc_vote1_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Verified<PcVote1>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_verified_pc_vote1_received(fold, epoch, view, vote))
    }

    /// A round-2 PC vote received already verified.
    pub fn on_verified_pc_vote2_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<Verified<PcVote2>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_verified_pc_vote2_received(fold, epoch, view, vote))
    }

    /// A round-3 PC vote received already verified.
    pub fn on_verified_pc_vote3_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<Verified<PcVote3>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_verified_pc_vote3_received(fold, epoch, view, vote))
    }

    /// `TimerId::BeaconSpcView` fired.
    pub fn on_beacon_spc_view_timer(&mut self) -> Vec<Action> {
        self.drive(BeaconParticipant::on_beacon_spc_view_timer)
    }

    /// A peer committee member's `BeaconProposal` arrived.
    pub fn on_beacon_proposal_received(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_beacon_proposal_received(fold, from, epoch, proposal))
    }

    /// Buffer a verified shard fork proof for the next proposal.
    pub fn observe_fork_proof(&mut self, proof: ShardForkProof) {
        self.participant.observe_fork_proof(&self.fold, proof);
    }

    /// Buffer a verified shard double-vote pair for the next proposal;
    /// `true` on first sight.
    pub fn observe_vote_equivocation(&mut self, evidence: ShardVoteEquivocation) -> bool {
        self.participant.observe_vote_equivocation(evidence)
    }

    /// The registered pubkey for `validator` — see
    /// [`BeaconFold::validator_pubkey`].
    #[must_use]
    pub fn validator_pubkey(&self, validator: ValidatorId) -> Option<ConsensusPublicKey> {
        self.fold.validator_pubkey(validator)
    }

    /// `TimerId::BeaconCommitteeStart` fired.
    pub fn on_beacon_committee_start_timer(&mut self) -> Vec<Action> {
        self.drive(BeaconParticipant::on_beacon_committee_start_timer)
    }

    /// A source block's commit is proven — the remote-header path's
    /// answer to a commit-proof ask, or its own proof of a block it
    /// followed. A block this member asked for is held for admission, and
    /// the proposals awaiting it are released.
    pub fn on_commit_proven_source_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        if !self
            .fold
            .admit_proven_for(certified_header, [&self.participant])
        {
            return Vec::new();
        }
        self.drive(BeaconParticipant::on_source_header)
    }

    /// `TimerId::BeaconSpcInputDwell` fired.
    pub fn on_spc_input_dwell_timer(&mut self) -> Vec<Action> {
        self.drive(BeaconParticipant::on_spc_input_dwell_timer)
    }

    /// A peer-aggregated beacon block arrived via gossip — see
    /// [`BeaconFold::on_beacon_block_received`].
    pub fn on_beacon_block_received(
        &mut self,
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
    ) -> Vec<Action> {
        self.fold.on_beacon_block_received(block)
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
        self.fold.on_beacon_block_received(block)
    }

    /// A peer's [`RatifyVote`] arrived via gossip.
    ///
    /// [`RatifyVote`]: hyperscale_types::RatifyVote
    pub fn on_unverified_ratify_vote_received(
        &mut self,
        vote: Arc<Verifiable<RatifyVote>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_unverified_ratify_vote_received(fold, vote))
    }

    /// A locally-signed ratify vote arrived via the self-loopback path.
    pub fn on_verified_ratify_vote_received(
        &mut self,
        vote: Arc<Verified<RatifyVote>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_verified_ratify_vote_received(fold, vote))
    }

    /// A previously-dispatched [`Action::VerifyBeaconBlock`] has
    /// returned — see [`BeaconFold::on_beacon_block_verified`].
    ///
    /// # Panics
    ///
    /// Panics when the verified block competes with the adopted tip.
    pub fn on_beacon_block_verified(
        &mut self,
        result: Result<Arc<Verified<CertifiedBeaconBlock>>, CertifiedBeaconBlockVerifyError>,
    ) -> Vec<Action> {
        self.fold
            .on_beacon_block_verified(result)
            .map_or_else(Vec::new, |adopted| self.settle(adopted))
    }

    /// A previously-dispatched [`Action::VerifyRatifyVote`] has
    /// returned.
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
        self.drive(|p, fold| p.on_ratify_vote_verified(fold, key, result))
    }

    /// A shard-witness chunk arrived — see
    /// [`BeaconFold::on_shard_witnesses_received`].
    pub fn on_shard_witnesses_received(
        &mut self,
        shard_id: ShardId,
        anchor: BlockHash,
        lo: LeafIndex,
        payloads: Vec<ShardWitnessPayload>,
        range_proof: Vec<Hash>,
    ) -> Option<Vec<Action>> {
        self.fold
            .on_shard_witnesses_received(shard_id, anchor, lo, payloads, range_proof)
    }

    /// Record a verified remote source-shard header, fetch its witness
    /// chunk while on the committee, and release the proposals it
    /// completes.
    pub fn on_verified_source_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let mut actions = self.fold.on_source_header(certified_header);
        actions.extend(self.drive(BeaconParticipant::on_source_header));
        actions
    }

    /// Record a local block's header the moment it certifies, ahead of
    /// its commit, and release the proposals it completes. A member's own
    /// shard answers no commit-proof ask, so the headers its chain
    /// certifies are the only thing that arrives for it, and they arrive
    /// no later than a remote observer's: a remote shard learns a header
    /// from its proposer's commit, which follows the certification of the
    /// block above it.
    pub fn on_certified_local_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        if let Some(token) = self.local_chain {
            self.fold.on_certified_local_header(token, certified_header);
        }
        self.drive(BeaconParticipant::on_source_header)
    }

    /// A peer's candidate block arrived via gossip.
    pub fn on_beacon_candidate_received(
        &mut self,
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_beacon_candidate_received(fold, candidate))
    }

    /// A previously-dispatched [`Action::VerifyBeaconCandidate`] has
    /// returned.
    pub fn on_beacon_candidate_verified(
        &mut self,
        result: Result<Arc<Verified<CandidateBeaconBlock>>, CandidateBeaconBlockVerifyError>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_beacon_candidate_verified(fold, result))
    }

    /// A fetched beacon proposal arrived.
    pub fn on_beacon_proposal_fetched(
        &mut self,
        epoch: Epoch,
        validator: ValidatorId,
        proposal: Arc<Verifiable<BeaconProposal>>,
    ) -> Vec<Action> {
        self.drive(|p, fold| p.on_beacon_proposal_fetched(fold, epoch, validator, proposal))
    }

    /// This coordinator's proposal pool — lets tests and sims run
    /// lookups without going through the network path.
    #[must_use]
    pub const fn proposal_pool(&self) -> &BeaconProposalPool {
        self.participant.proposal_pool()
    }
}

// Flat accessors; their names and return types are the documentation.
#[allow(missing_docs)]
impl BeaconCoordinator {
    #[must_use]
    pub const fn current_state(&self) -> &BeaconState {
        &self.fold.state
    }

    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.fold.state.current_epoch
    }

    #[must_use]
    pub const fn latest_block(&self) -> &Arc<Verified<CertifiedBeaconBlock>> {
        &self.fold.latest_block
    }

    /// Scheme verifier shared with callers that build verify contexts
    /// outside the coordinator.
    #[must_use]
    pub fn verifier(&self) -> &Arc<dyn Verifier> {
        &self.fold.verifier
    }

    #[must_use]
    pub const fn network_definition(&self) -> &NetworkDefinition {
        &self.fold.network
    }

    #[must_use]
    pub const fn me(&self) -> ValidatorId {
        self.participant.me()
    }

    #[must_use]
    pub const fn now(&self) -> LocalTimestamp {
        self.fold.now
    }

    #[must_use]
    pub const fn current_topology_snapshot(&self) -> &Arc<TopologySnapshot> {
        self.fold.current_topology_snapshot()
    }

    /// The per-epoch committee schedule — the verification interface handed to
    /// shard and execution coordinators. They resolve an artifact's committee
    /// from its weighted timestamp ([`TopologySchedule::at`]) and the routing
    /// head ([`TopologySchedule::head`]) through it, so no consensus-layer type
    /// crosses into their verification paths.
    #[must_use]
    pub const fn topology_schedule(&self) -> &TopologySchedule {
        &self.fold.topology_schedule
    }

    /// Number of crypto verifications dispatched but not yet resulted.
    /// Test introspection — production code shouldn't gate on this.
    #[must_use]
    pub fn verifications_in_flight(&self) -> usize {
        self.fold.verification.in_flight_count()
            + self.participant.verification.in_flight_count()
            + self.participant.spc.in_flight_count()
    }
}

impl std::fmt::Debug for BeaconCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconCoordinator")
            .field("current_epoch", &self.fold.state.current_epoch)
            .field("latest_block_hash", &self.fold.latest_block.block_hash())
            .field("me", &self.participant.me())
            .field("spc_active", &self.participant.spc.is_bootstrapped())
            .field("verifications_in_flight", &self.verifications_in_flight())
            .field("witness_chunks", &self.fold.shard_source.total_chunk_len())
            .field("ratify_round", &self.participant.ratify.round())
            .field("equivocations", &self.participant.equivocations.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use hyperscale_core::{
        BeaconFetchIds, FetchIds, FetchRequest, KeepDelta, ObserveDelta, ParticipationChange,
        TimerId,
    };
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::test_pool;
    use hyperscale_types::{
        AggregateSignature, BeaconBlock, BeaconBlockHash, BeaconCert, BeaconChainConfig,
        BeaconGenesisConfig, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader,
        BlockHeaderParts, BlockHeight, CertifiedBlockHeader, ChainOrigin, ConsensusPublicKey,
        ConsensusSignature, DeclaredWork, Epoch, GenesisConfigHash, GenesisPool, GenesisValidator,
        Hash, JailReason, KeptSeat, LeafIndex, MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR,
        NetworkDefinition, ObserverSeat, PcScope, PcValueElement, PcVector, PcVoteEquivocation,
        QuorumCertificate, RATIFY_ROUND_TIMEOUT, Randomness, RatifyCert, Round, SKIP_TIMEOUT,
        ShardBoundary, ShardCommittee, ShardEpochContribution, ShardId, ShardWitnessPayload,
        Signer, SignerBitfield, SlotEffects, SpcCert, SpcView, Stake, StateRoot, Unpublished,
        ValidatorId, ValidatorStatus, VrfProof, WeightedTimestamp, build_qc1, build_qc2, build_qc3,
        build_ratify_cert, compute_merkle_root, compute_range_proof, genesis_config_hash,
        sign_ratify_vote, sign_vote1, sign_vote2, sign_vote3,
    };

    use super::*;
    use crate::participant::MAX_INPUT_DWELL_REARMS;
    use crate::shard_source::ChunkFetchId;
    use crate::{boundary, rules};

    /// Reach the participant's and the fold's internals the way the
    /// coordinator's own handlers do.
    impl BeaconCoordinator {
        fn bootstrap_spc_for_next_epoch(&mut self) -> Vec<Action> {
            self.drive(BeaconParticipant::bootstrap_spc_for_next_epoch)
        }

        fn bootstrap_spc_with_committee(
            &mut self,
            committee: Vec<(ValidatorId, ConsensusPublicKey)>,
        ) -> Vec<Action> {
            self.drive(|p, fold| p.bootstrap_spc_with_committee(fold, committee))
        }

        fn try_propose(&mut self) -> Vec<Action> {
            self.drive(BeaconParticipant::try_propose)
        }

        fn on_spc_output_high(
            &mut self,
            epoch: Epoch,
            output: &PcVector,
            cert: Verified<SpcCert>,
            recipients: &[ValidatorId],
        ) -> Vec<Action> {
            self.drive(|p, fold| p.on_spc_output_high(fold, epoch, output, cert, recipients))
        }

        fn participation_delta(&self, effects: &SlotEffects) -> Option<ParticipationChange> {
            self.participant.participation_delta(&self.fold, effects)
        }

        fn spc_recipients(&self) -> Vec<ValidatorId> {
            self.participant.spc_recipients(&self.fold)
        }

        fn is_on_committee(&self) -> bool {
            self.participant.is_on_committee(&self.fold)
        }

        fn committee_start_due(&self, epoch_boundary: LocalTimestamp) -> bool {
            self.fold.committee_start_due(epoch_boundary)
        }

        fn skip_trigger_due(&self, expected_block_time: LocalTimestamp) -> bool {
            self.fold.skip_trigger_due(expected_block_time)
        }

        fn next_epoch_boundary(&self) -> LocalTimestamp {
            self.fold.next_epoch_boundary()
        }

        fn fetch_witness_chunk(&mut self, shard: ShardId) -> Vec<Action> {
            self.fold.fetch_witness_chunk(shard)
        }

        fn prune_folded_evidence(&mut self) {
            self.participant.prune_folded_evidence(&self.fold);
        }

        fn retire_departed_sources(&mut self) -> Vec<ChunkFetchId> {
            self.fold.retire_departed_sources()
        }

        fn local_anchors(&self) -> Option<LocalChainAnchors> {
            self.local_chain
                .map(|token| self.fold.hosted[&token].anchors)
        }

        /// Commit the local chain's next block, whose own anchor is
        /// `block_anchor`.
        fn commit_local(&mut self, block_anchor: WeightedTimestamp) -> Vec<Action> {
            let token = self.local_chain.expect("a local chain");
            let height = self.fold.hosted[&token].height.inner() + 1;
            let header = boundary_block_header(
                ShardId::ROOT,
                height,
                block_anchor.as_millis(),
                StateRoot::ZERO,
                0,
            );
            self.on_local_block_committed(&header)
        }
    }
    use crate::genesis::build_genesis_beacon_state;
    use crate::state::test_fixtures::{genesis_boundary, keypair, pubkey};

    /// 4 validators, all on the beacon committee, all placed on the ROOT
    /// genesis shard.
    fn sample_genesis() -> BeaconGenesisConfig {
        let pool_id = test_pool(0);
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
                total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
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
        let config_hash = genesis_config_hash(&config, &NetworkDefinition::simulator(), &[]);
        let block = Verified::<CertifiedBeaconBlock>::genesis(config_hash);
        (Arc::new(block), state, config_hash)
    }

    fn new_coord(me: ValidatorId) -> BeaconCoordinator {
        let (block, state, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            block,
            vec![state],
            me,
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(pred_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: parent_qc.into(),
            round: Round::new(height),
            state_root,
            beacon_witness_root: root,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
            ..Default::default()
        });
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
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
    /// `leaf_count` `StakeDeposit` leaves, plus the chunk covering the
    /// whole window: its payloads and the range proof lifting them to the
    /// block's root. Seat the chunk into a coordinator via
    /// [`BeaconCoordinator::on_shard_witnesses_received`] or embed it in a
    /// [`ShardEpochContribution`] to drive the witness-chunk fetch and fold.
    ///
    /// The window base is zero and the run spans it, so the proof is empty
    /// — the full-width case the assembler hits in steady state.
    fn boundary_block_with_witnesses(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> (
        Arc<Verified<CertifiedBlockHeader>>,
        Vec<ShardWitnessPayload>,
        Vec<Hash>,
    ) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: test_pool(200 + u32::try_from(i).unwrap_or(u32::MAX)),
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
            BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes))
        };
        let certified =
            boundary_block_header_with_root(shard, height, pred_wt, state_root, root, leaf_count);
        let range_proof = compute_range_proof(&leaf_hashes, 0, leaf_hashes.len());
        (certified, payloads, range_proof)
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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            round: Round::new(height),
            beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(
                format!("bw-{height}").as_bytes(),
            )),
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
            ..Default::default()
        });
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            parent_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_wt),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// A structural QC naming `block_hash` at weighted timestamp `wt`.
    /// `build_shard_contributions` and `contributions_well_formed` project
    /// and bind cert-bound QCs without re-running verification (the `2f+1` is the
    /// admission gate's job), so a structural QC suffices for them.
    fn qc_naming(block_hash: BlockHash, shard: ShardId, height: u64, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt),
        )
    }

    fn proposal_with_boundary(shard: ShardId, qc: QuorumCertificate) -> BeaconProposal {
        BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
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
        let (b, payloads, range_proof) =
            boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(
            ValidatorId::new(0),
            Verified::new_unchecked_for_test(proposal_with_boundary(shard, qc)),
        )];

        // The boundary block isn't synced — defer rather than omit it.
        assert!(
            boundary::build_shard_contributions(
                &coord.fold.state,
                &coord.fold.shard_source,
                &committed
            )
            .is_none()
        );

        // Header synced but the witness chunk isn't in hand — still defer
        // (the coupling rule: a boundary is only reportable with its chunk).
        coord.on_verified_source_header(&b);
        assert!(
            boundary::build_shard_contributions(
                &coord.fold.state,
                &coord.fold.shard_source,
                &committed
            )
            .is_none()
        );

        // Once the witness chunk arrives, the contribution seats with it.
        coord.on_shard_witnesses_received(
            shard,
            b.block_hash(),
            LeafIndex::new(0),
            payloads,
            range_proof,
        );
        let built = boundary::build_shard_contributions(
            &coord.fold.state,
            &coord.fold.shard_source,
            &committed,
        )
        .expect("contribution seats once the boundary block and chunk sync");
        assert_eq!(built.len(), 1);
        assert_eq!(built[&shard].boundary_header.hash(), b.block_hash());
        assert_eq!(built[&shard].payloads.len(), 3);
    }

    /// The proposer stops sourcing a live shard's crossing once the fold
    /// has consumed it — anchor recorded, chunk drained. Re-sourcing it
    /// masks a halted shard as live (the re-fold keeps resetting its miss
    /// counter) and, once the crossing's window ages below the schedule
    /// floor, forces every verifier to abstain on any proposal carrying
    /// it. A partially drained chunk keeps sourcing — the backlog still
    /// has leaves to deliver.
    #[test]
    fn source_boundary_qcs_skips_a_folded_live_crossing() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"folded-anchor"));
        let (b, payloads, range_proof) =
            boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        coord.fold.state.shard_committees.insert(
            shard,
            ShardCommittee {
                members: vec![ValidatorId::new(0)],
            },
        );
        // A `(B, C)` pair whose successor QC lands past the epoch cut, and
        // the block that commits `C`, so the tracker records `b` as a
        // genuine crossing.
        let c = linked_block_header(shard, 6, b.block_hash(), 301_000, 3);
        let d = linked_block_header(shard, 7, c.block_hash(), 301_000, 3);
        coord.on_verified_source_header(&b);
        coord.on_verified_source_header(&c);
        coord.on_verified_source_header(&d);
        coord.on_shard_witnesses_received(
            shard,
            b.block_hash(),
            LeafIndex::new(0),
            payloads.clone(),
            range_proof,
        );
        let boundary = |applied: u64| ShardBoundary {
            boundary_qc: None,
            state_root: anchor,
            block_hash: b.block_hash(),
            height: BlockHeight::new(5),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::new(applied),
            witness_base: BeaconWitnessLeafCount::ZERO,
            cumulative_fees: 0,
            used: DeclaredWork::ZERO,
            blocks: 0,
            substate_bytes: 0,
            formed: Epoch::GENESIS,
            last_live_epoch: Epoch::new(1),
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_settled_txs: None,
            reshape_admitted_epoch: None,
        };

        // Unfolded: the crossing is fresh news, so it sources.
        let sourced = boundary::source_boundary_qcs(&coord.fold.state, &coord.fold.shard_source);
        assert!(sourced.contains_key(&shard), "a fresh crossing sources");

        // Folded with backlog left: the shard keeps sourcing once the
        // remaining run is in hand. The watermark only ever lands on a
        // chunk boundary, so the tail is a chunk in its own right.
        coord.fold.state.boundaries.insert(shard, boundary(1));
        let leaves: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        coord.on_shard_witnesses_received(
            shard,
            b.block_hash(),
            LeafIndex::new(1),
            payloads[1..].to_vec(),
            compute_range_proof(&leaves, 1, 3),
        );
        let sourced = boundary::source_boundary_qcs(&coord.fold.state, &coord.fold.shard_source);
        assert!(
            sourced.contains_key(&shard),
            "an undrained backlog keeps sourcing",
        );

        // Fully folded: nothing new to report, so the shard is absent.
        coord.fold.state.boundaries.insert(shard, boundary(3));
        let sourced = boundary::source_boundary_qcs(&coord.fold.state, &coord.fold.shard_source);
        assert!(
            !sourced.contains_key(&shard),
            "a fully folded live crossing must stop sourcing",
        );
    }

    /// `contributions_well_formed` accepts the canonical projection of the
    /// committed boundary QCs and rejects an incomplete, extra, or unbound
    /// contribution set — the Byzantine-variant gate on received blocks.
    #[test]
    fn contributions_well_formed_enforces_canonical_projection() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        let other = ShardId::leaf(1, 1);
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"wf-anchor"));
        let (b, payloads, range_proof) =
            boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(ValidatorId::new(0), proposal_with_boundary(shard, qc))];
        let contribution = ShardEpochContribution {
            boundary_header: b.header().clone(),
            payloads: Capped::new(payloads).expect("a list written out in a test"),
            range_proof: Capped::new(range_proof).expect("a list written out in a test"),
        };
        let block_with = |contribs: BTreeMap<ShardId, ShardEpochContribution>| {
            BeaconBlock::new_with_contributions(
                Epoch::new(1),
                BeaconBlockHash::ZERO,
                Capped::new(committed.clone()).expect("a list written out in a test"),
                Capped::new(contribs).expect("a list written out in a test"),
            )
        };

        // Canonical projection — accepted.
        let good = block_with(std::iter::once((shard, contribution.clone())).collect());
        assert!(rules::contributions_well_formed(&coord.fold.state, &good));

        // Omits the committed shard's contribution — rejected.
        assert!(!rules::contributions_well_formed(
            &coord.fold.state,
            &block_with(BTreeMap::new())
        ));

        // Extra contribution for a shard with no committed QC — rejected.
        let mut extra: BTreeMap<ShardId, ShardEpochContribution> = BTreeMap::new();
        extra.insert(shard, contribution.clone());
        extra.insert(other, contribution);
        assert!(!rules::contributions_well_formed(
            &coord.fold.state,
            &block_with(extra)
        ));

        // A contribution binding to no committed QC — rejected.
        let wrong = boundary_block_header(shard, 9, 299_000, StateRoot::ZERO, 3);
        let tampered = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: wrong.header().clone(),
                payloads: Capped::empty(),
                range_proof: Capped::empty(),
            },
        ))
        .collect();
        assert!(!rules::contributions_well_formed(
            &coord.fold.state,
            &block_with(tampered)
        ));

        // Correctly bound, but a short witness chunk (the boundary commits
        // 3 leaves, the contribution carries none) — rejected on the
        // chunk-completeness check.
        let short = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b.header().clone(),
                payloads: Capped::empty(),
                range_proof: Capped::empty(),
            },
        ))
        .collect();
        assert!(!rules::contributions_well_formed(
            &coord.fold.state,
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
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"cand-anchor"));
        let (b, payloads, range_proof) =
            boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let qc = qc_naming(b.block_hash(), shard, 5, 301_000);
        let committed = vec![(ValidatorId::new(0), proposal_with_boundary(shard, qc))];
        let contribution = ShardEpochContribution {
            boundary_header: b.header().clone(),
            payloads: Capped::new(payloads).expect("a list written out in a test"),
            range_proof: Capped::new(range_proof).expect("a list written out in a test"),
        };
        let epoch = coord.fold.state.current_epoch.next();
        let prev = coord.fold.latest_block.block_hash();

        // The cert content is irrelevant here — the contributions gate
        // runs before any crypto dispatch — but `SpcCert` has no
        // structural placeholder, so build a real one.
        let n = coord.fold.state.committee.len();
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_signers: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
                BeaconBlock::new_with_contributions(
                    epoch,
                    prev,
                    Capped::new(committed.clone()).expect("a list written out in a test"),
                    Capped::new(contribs).expect("a map written out in a test"),
                ),
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
                            verifier: &BlsVerifier,
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
                            verifier: &BlsVerifier,
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
                            verifier: &BlsVerifier,
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
            Arc::new(BlsVerifier),
            Arc::clone(&block),
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
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
            Arc::new(BlsVerifier),
            block,
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
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
            Arc::new(BlsVerifier),
            Arc::new(mismatched_block),
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
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
        let skip_hash = coord.participant.ratify.skip_block_hash();

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
        assert_eq!(coord.participant.ratify.round(), RatifyRound::INITIAL);

        // A round fire that lands before the round boundary on this
        // member's clock enters no round: the round is the wall clock's,
        // and the re-arm at the boundary is the fire that enters it.
        let round_ms: u64 = RATIFY_ROUND_TIMEOUT
            .as_millis()
            .try_into()
            .expect("RATIFY_ROUND_TIMEOUT fits in u64 millis");
        let round_two = boundary + timeout_ms + round_ms;
        coord.set_now(LocalTimestamp::from_millis(round_two - 1));
        let actions = coord.on_beacon_ratify_timer();
        assert_eq!(coord.participant.ratify.round(), RatifyRound::INITIAL);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SetTimer {
                    id: TimerId::BeaconRatifyTrigger,
                    duration,
                } if *duration == Duration::from_millis(1)
            )),
            "an early round fire must re-arm at the boundary; got {actions:?}",
        );

        // The fire at the boundary is a round timeout: the round
        // advances, and the unlocked tracker re-prevotes skip (still no
        // candidate). A second fire at the same instant enters nothing.
        coord.set_now(LocalTimestamp::from_millis(round_two));
        let actions = coord.on_beacon_ratify_timer();
        assert_eq!(coord.participant.ratify.round(), RatifyRound::new(2));
        let _ = coord.on_beacon_ratify_timer();
        assert_eq!(coord.participant.ratify.round(), RatifyRound::new(2));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SignAndBroadcastRatifyVote { round, phase: RatifyPhase::Prevote, block_hash, .. }
                    if *round == RatifyRound::new(2) && *block_hash == skip_hash
            )),
            "a round timeout must re-prevote in the new round; got {actions:?}",
        );
    }

    /// A replica that missed the pending epoch's block gossip sees only
    /// its deadline pass. The fire past it asks peers for that epoch,
    /// since a chain that has moved on sends nothing that would reveal
    /// the gap until its next epoch's traffic. An early fire asks for
    /// nothing: the block may still be on its way.
    #[test]
    fn ratify_timer_past_the_deadline_asks_peers_for_the_pending_epoch() {
        let mut coord = fresh_coord();
        let boundary = coord.current_state().chain_config.epoch_duration_ms;
        let timeout_ms: u64 = SKIP_TIMEOUT
            .as_millis()
            .try_into()
            .expect("SKIP_TIMEOUT fits in u64 millis");
        let pending = coord.current_state().current_epoch.next();
        let asks = |actions: &[Action]| {
            actions
                .iter()
                .any(|a| matches!(a, Action::StartBeaconBlockSync { target } if *target == pending))
        };

        coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms - 1));
        let actions = coord.on_beacon_ratify_timer();
        assert!(
            !asks(&actions),
            "an early fire must not sync; got {actions:?}"
        );

        coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms));
        let actions = coord.on_beacon_ratify_timer();
        assert!(
            asks(&actions),
            "a fire past the deadline must ask peers for the pending epoch; got {actions:?}",
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
        use hyperscale_types::PcVote1;
        let mut coord = fresh_coord();
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            Capped::from_array([ConsensusSignature::new([0u8; 96])]),
        );
        let actions = coord.on_pc_vote1_received(
            coord.current_state().current_epoch.next(),
            SpcView::new(1),
            vote,
        );
        assert!(actions.is_empty());
    }

    /// A PC vote whose claimed signer is outside the committee is dropped
    /// before the verify dispatch, so it can't mint a verification slot.
    #[test]
    fn pc_vote_from_non_committee_signer_dropped_before_dispatch() {
        use hyperscale_types::PcVote1;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        // The committee is validators 0..4; 9 is not a member.
        let vote = PcVote1::new(
            ValidatorId::new(9),
            PcVector::empty(),
            Capped::from_array([ConsensusSignature::new([0u8; 96])]),
        );
        let actions = coord.on_pc_vote1_received(
            coord.current_state().current_epoch.next(),
            SpcView::new(1),
            vote,
        );
        assert!(actions.is_empty());
        assert_eq!(coord.verifications_in_flight(), 0);
    }

    /// A PC vote for a view far outside `[current, current +
    /// MAX_PENDING_EMPTY_VIEW_AHEAD]` is dropped before dispatch.
    #[test]
    fn pc_vote_for_out_of_window_view_dropped_before_dispatch() {
        use hyperscale_types::PcVote1;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        // current_view is 1; the window is [1, 5], so view 6 is out.
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            Capped::from_array([ConsensusSignature::new([0u8; 96])]),
        );
        let actions = coord.on_pc_vote1_received(
            coord.current_state().current_epoch.next(),
            SpcView::new(6),
            vote,
        );
        assert!(actions.is_empty());
        assert_eq!(coord.verifications_in_flight(), 0);
    }

    /// A committee signer's vote within the view window passes the gate
    /// and dispatches a verification (one in-flight slot).
    #[test]
    fn pc_vote_from_committee_in_window_dispatches_verification() {
        use hyperscale_types::PcVote1;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let vote = PcVote1::new(
            ValidatorId::new(1),
            PcVector::empty(),
            Capped::from_array([ConsensusSignature::new([0u8; 96])]),
        );
        let actions = coord.on_pc_vote1_received(
            coord.current_state().current_epoch.next(),
            SpcView::new(1),
            vote,
        );
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
        assert!(!coord.participant.spc.is_bootstrapped());
        let actions = coord.on_beacon_committee_start_timer();
        assert_eq!(coord.participant.spc.epoch(), Some(Epoch::GENESIS.next()));
        assert_eq!(coord.participant.spc.current_view(), Some(SpcView::new(1)));
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
        let undersized: Vec<(ValidatorId, ConsensusPublicKey)> =
            (0u64..(MIN_BEACON_COMMITTEE_SIZE as u64 - 1))
                .map(|i| (ValidatorId::new(i), pubkey(i)))
                .collect();
        coord.bootstrap_spc_with_committee(undersized);
        assert!(!coord.participant.spc.is_bootstrapped());
    }

    /// A committee exactly at the BFT minimum bootstraps normally.
    #[test]
    fn bootstrap_at_bft_minimum_creates_instance() {
        let mut coord = fresh_coord();
        let committee: Vec<(ValidatorId, ConsensusPublicKey)> = (0u64..MIN_BEACON_COMMITTEE_SIZE
            as u64)
            .map(|i| (ValidatorId::new(i), pubkey(i)))
            .collect();
        coord.bootstrap_spc_with_committee(committee);
        assert!(coord.participant.spc.is_bootstrapped());
    }

    /// Two skip requests from the same signer at the same anchor/epoch
    /// but with different signature bytes collapse to one verification
    /// slot: the slot key is `(anchor, epoch, round, phase, signer)`,
    /// not the encoded-vote hash, so a forged-sig flood can't mint
    /// extra in-flight signature checks.
    #[test]
    fn ratify_vote_verification_keys_on_signer_not_signature() {
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1); // a peer on the active pool
        let skip_hash = coord.participant.ratify.skip_block_hash();

        let vote = |sig_byte: u8| {
            Arc::new(Verifiable::from(RatifyVote::new(
                anchor,
                epoch,
                RatifyRound::INITIAL,
                RatifyPhase::Prevote,
                skip_hash,
                signer,
                ConsensusSignature::new([sig_byte; 96]),
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

    /// A ratify vote that fails signature verification releases its slot, so
    /// a later vote for the same tuple re-dispatches. Without clearing
    /// on the failure arm, a forged vote could pin a signer's slot
    /// in-flight and block their honest vote from ever being verified.
    #[test]
    fn failed_ratify_vote_verification_releases_slot() {
        let mut coord = fresh_coord();
        let anchor = coord.latest_block().block_hash();
        let epoch = coord.current_epoch().next();
        let signer = ValidatorId::new(1);
        let skip_hash = coord.participant.ratify.skip_block_hash();

        let forged = Arc::new(Verifiable::from(RatifyVote::new(
            anchor,
            epoch,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
            signer,
            ConsensusSignature::new([0u8; 96]), // garbage sig — fails verification
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
            ConsensusSignature::new([2u8; 96]),
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
        assert!(!coord.participant.spc.is_bootstrapped());
    }

    #[test]
    fn committee_start_is_idempotent() {
        let mut coord = fresh_coord();
        coord.on_beacon_committee_start_timer();
        let spc_view_first = coord.participant.spc.current_view();
        coord.on_beacon_committee_start_timer();
        let spc_view_second = coord.participant.spc.current_view();
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
        assert!(coord.participant.proposal_pool.contains(from));
    }

    /// A verified fork proof observed from the shard layer drains into the
    /// next proposal the coordinator builds.
    #[test]
    fn observed_fork_proof_drains_into_the_next_proposal() {
        use hyperscale_types::BlockHeight;
        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};

        let mut coord = fresh_coord();
        let committee = TestCommittee::new(4, 1);
        coord.observe_fork_proof(shard_fork_proof(
            &committee,
            ShardId::ROOT,
            BlockHeight::new(5),
        ));
        coord.bootstrap_spc_for_next_epoch();

        let actions = coord.try_propose();
        let [Action::BuildAndBroadcastBeaconProposal { fork_proofs, .. }] = actions.as_slice()
        else {
            panic!("expected BuildAndBroadcastBeaconProposal, got {actions:?}");
        };
        assert!(fork_proofs.contains_key(&ShardId::ROOT));
    }

    /// A peer proposal carrying a fork proof that doesn't verify against the
    /// local schedule is inadmissible — the vnode abstains rather than pool
    /// it and fold garbage.
    #[test]
    fn proposal_with_an_unverifiable_fork_proof_is_dropped() {
        use std::collections::BTreeMap;

        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};
        use hyperscale_types::{BlockHeight, ShardForkProof, VrfProof};

        let mut coord = fresh_coord();
        let from = ValidatorId::new(1);
        // Signed by a committee unrelated to the genesis schedule, so the
        // QCs fail to authenticate against the resolved committee.
        let committee = TestCommittee::new(4, 999);
        let proof = shard_fork_proof(&committee, ShardId::ROOT, BlockHeight::new(5));
        let fork_proofs: BTreeMap<ShardId, ShardForkProof> =
            std::iter::once((ShardId::ROOT, proof)).collect();
        let proposal = Arc::new(Verified::new_unchecked_for_test(BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            fork_proofs,
            Vec::new(),
            VrfProof::ZERO,
        )));

        let actions = coord.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal);
        assert!(actions.is_empty());
        assert!(!coord.participant.proposal_pool.contains(from));
    }

    /// A fork proof keyed under a shard other than its own is inadmissible
    /// even when the proof itself verifies: the map key is unauthenticated
    /// framing, and trusting it would let one genuine equivocation nominate
    /// every keyed shard for recovery. The correctly keyed control proves
    /// the rejection is the key check, not verification.
    #[test]
    fn proposal_with_a_rekeyed_fork_proof_is_dropped() {
        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};
        use hyperscale_types::{BlockHeight, ShardForkProof, VrfProof};

        // Genesis committee backed by the TestCommittee's keys, so a proof
        // it signs resolves and verifies against the coordinator's schedule.
        let committee = TestCommittee::new(4, 1);
        let pool_id = test_pool(0);
        let validators: Vec<GenesisValidator> = (0usize..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i as u64),
                pool: pool_id,
                pubkey: *committee.public_key(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        let config = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committee: members,
            initial_randomness: Randomness::new([0xAB; 32]),
        };
        let state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config, &NetworkDefinition::simulator(), &[]);
        let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
        let mut coord = BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            block,
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
            NetworkDefinition::simulator(),
            config_hash,
        );

        let from = ValidatorId::new(1);
        let proof = shard_fork_proof(&committee, ShardId::ROOT, BlockHeight::new(5));
        let proposal = |key: ShardId| {
            let fork_proofs: BTreeMap<ShardId, ShardForkProof> =
                std::iter::once((key, proof.clone())).collect();
            Arc::new(Verified::new_unchecked_for_test(BeaconProposal::new(
                BTreeMap::new(),
                Vec::new(),
                fork_proofs,
                Vec::new(),
                VrfProof::ZERO,
            )))
        };

        // Control: keyed under its own shard, the proposal pools.
        coord.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal(ShardId::ROOT));
        assert!(coord.participant.proposal_pool.contains(from));

        // Re-keyed under a foreign shard: dropped.
        let mut coord2 = {
            let state = build_genesis_beacon_state(&config);
            let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
            BeaconCoordinator::new(
                Arc::new(BlsVerifier),
                block,
                vec![state],
                ValidatorId::new(0),
                ShardId::ROOT,
                Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
                NetworkDefinition::simulator(),
                config_hash,
            )
        };
        coord2.on_beacon_proposal_received(
            from,
            Epoch::GENESIS.next(),
            proposal(ShardId::leaf(1, 0)),
        );
        assert!(!coord2.participant.proposal_pool.contains(from));
    }

    /// A coordinator at genesis whose root committee holds `pubkeys` in
    /// seat order, so a proof the holders of those keys sign resolves
    /// and verifies against the coordinator's schedule.
    fn coord_seating(pubkeys: [ConsensusPublicKey; 4]) -> BeaconCoordinator {
        let pool_id = test_pool(0);
        let validators: Vec<GenesisValidator> = (0u64..4)
            .zip(pubkeys)
            .map(|(id, pubkey)| GenesisValidator {
                id: ValidatorId::new(id),
                pool: pool_id,
                pubkey,
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        let config = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committee: members,
            initial_randomness: Randomness::new([0xAB; 32]),
        };
        let state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config, &NetworkDefinition::simulator(), &[]);
        let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
        BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            block,
            vec![state],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
            NetworkDefinition::simulator(),
            config_hash,
        )
    }

    /// A proposal naming the member's own shard boundary awaits that
    /// shard's certified headers, which are the only thing that arrives
    /// for it. Certified headers up to the boundary's child leave it
    /// awaiting while the child's commit is unproven; the block that
    /// commits the child releases it into the pool. None of it fetches a
    /// witness chunk, which the local store serves only once a block
    /// commits.
    #[test]
    fn certified_local_headers_release_a_proposal_naming_the_own_shard_boundary() {
        use hyperscale_types::test_utils::TestCommittee;
        use hyperscale_types::{BlockVote, ProposerTimestamp};

        let committee = TestCommittee::new(4, 1);
        let mut coord = coord_seating([0, 1, 2, 3].map(|seat| *committee.public_key(seat)));
        let shard = ShardId::ROOT;
        let cut = coord.fold.state.chain_config.epoch_duration_ms;
        let network = NetworkDefinition::simulator();

        let header = |height: u64, parent_qc: &QuorumCertificate| {
            BlockHeader::new(BlockHeaderParts {
                shard_id: shard,
                height: BlockHeight::new(height),
                parent_block_hash: parent_qc.block_hash(),
                parent_qc: parent_qc.clone().into(),
                round: Round::new(height),
                beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(b"bw")),
                beacon_witness_leaf_count: BeaconWitnessLeafCount::new(3),
                ..Default::default()
            })
        };
        let qc_over = |header: &BlockHeader, wt: u64| {
            let votes: Vec<(usize, Verified<BlockVote>)> = (0..3)
                .map(|seat| {
                    let vote = BlockVote::new(
                        &network,
                        header.hash(),
                        header.parent_block_hash(),
                        shard,
                        header.height(),
                        header.round(),
                        ValidatorId::new(seat as u64),
                        committee.signer(seat).as_ref(),
                        ProposerTimestamp::from_millis(wt),
                    )
                    .expect("vote signs");
                    (seat, Verified::new_unchecked_for_test(vote))
                })
                .collect();
            Verified::<QuorumCertificate>::from_verified_votes(
                &BlsVerifier,
                header.hash(),
                shard,
                header.height(),
                header.round(),
                header.parent_block_hash(),
                header.parent_qc().weighted_timestamp(),
                &votes,
            )
            .expect("aggregates over a quorum")
            .into_inner()
        };
        let certified = |header: &BlockHeader, qc: &QuorumCertificate| {
            Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
                header.clone(),
                qc.clone(),
            )))
        };

        // `B` anchors short of the cut and is certified past it; `C`
        // embeds that certificate and `D` commits `C`.
        let below = qc_naming(BlockHash::ZERO, shard, 3, cut - 2);
        let a = header(4, &below);
        let a_qc = qc_over(&a, cut - 1);
        let b = header(5, &a_qc);
        let b_qc = qc_over(&b, cut + 1);
        let c = header(6, &b_qc);
        let c_qc = qc_over(&c, cut + 2);
        let d = header(7, &c_qc);
        let d_qc = qc_over(&d, cut + 3);

        let from = ValidatorId::new(1);
        let proposal = Arc::new(Verified::new_unchecked_for_test(proposal_with_boundary(
            shard,
            b_qc.clone(),
        )));
        let mut actions = coord.on_certified_local_header(&certified(&a, &a_qc));
        actions.extend(coord.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal));
        actions.extend(coord.on_certified_local_header(&certified(&b, &b_qc)));
        actions.extend(coord.on_certified_local_header(&certified(&c, &c_qc)));
        assert!(
            coord.participant.awaiting_boundaries.contains_key(&from)
                && !coord.participant.proposal_pool.contains(from),
            "a boundary whose dating child is only certified leaves the proposal awaiting",
        );

        actions.extend(coord.on_certified_local_header(&certified(&d, &d_qc)));
        assert!(
            coord.participant.awaiting_boundaries.is_empty()
                && coord.participant.proposal_pool.contains(from),
            "the block that commits the dating child releases the proposal into the pool",
        );
        assert!(
            !actions.iter().any(|action| matches!(
                action,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(_)),
                    ..
                })
            )),
            "certification fetches no witness chunk: {actions:?}",
        );
    }

    /// Two participants share a fold, and only one asked for the commit
    /// proof a proposal it awaits needs. The proof is held for admission
    /// because one participant asked, and the asker's awaiting proposal is
    /// released into its pool once the proof lands. A proof no
    /// participant asked for is not held.
    #[test]
    #[allow(clippy::too_many_lines)] // one certified chain built and walked end to end
    fn a_commit_proof_one_participant_asked_for_releases_its_awaiting_proposal() {
        use hyperscale_core::ProtocolEvent;
        use hyperscale_types::test_utils::TestCommittee;
        use hyperscale_types::{BlockVote, ProposerTimestamp};

        let committee = TestCommittee::new(4, 1);
        let mut coord = coord_seating([0, 1, 2, 3].map(|seat| *committee.public_key(seat)));
        let shard = ShardId::ROOT;
        let cut = coord.fold.state.chain_config.epoch_duration_ms;
        let network = NetworkDefinition::simulator();

        let header = |height: u64, parent_qc: &QuorumCertificate| {
            BlockHeader::new(BlockHeaderParts {
                shard_id: shard,
                height: BlockHeight::new(height),
                parent_block_hash: parent_qc.block_hash(),
                parent_qc: parent_qc.clone().into(),
                round: Round::new(height),
                beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(b"bw")),
                beacon_witness_leaf_count: BeaconWitnessLeafCount::new(3),
                ..Default::default()
            })
        };
        let qc_over = |header: &BlockHeader, wt: u64| {
            let votes: Vec<(usize, Verified<BlockVote>)> = (0..3)
                .map(|seat| {
                    let vote = BlockVote::new(
                        &network,
                        header.hash(),
                        header.parent_block_hash(),
                        shard,
                        header.height(),
                        header.round(),
                        ValidatorId::new(seat as u64),
                        committee.signer(seat).as_ref(),
                        ProposerTimestamp::from_millis(wt),
                    )
                    .expect("vote signs");
                    (seat, Verified::new_unchecked_for_test(vote))
                })
                .collect();
            Verified::<QuorumCertificate>::from_verified_votes(
                &BlsVerifier,
                header.hash(),
                shard,
                header.height(),
                header.round(),
                header.parent_block_hash(),
                header.parent_qc().weighted_timestamp(),
                &votes,
            )
            .expect("aggregates over a quorum")
            .into_inner()
        };
        let certified = |header: &BlockHeader, qc: &QuorumCertificate| {
            Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
                header.clone(),
                qc.clone(),
            )))
        };

        // `B` anchors short of the cut and is certified past it; `C`
        // embeds that certificate and `D` commits `C`.
        let below = qc_naming(BlockHash::ZERO, shard, 3, cut - 2);
        let a = header(4, &below);
        let a_qc = qc_over(&a, cut - 1);
        let b = header(5, &a_qc);
        let b_qc = qc_over(&b, cut + 1);
        let c = header(6, &b_qc);
        let c_qc = qc_over(&c, cut + 2);
        let d = header(7, &c_qc);
        let d_qc = qc_over(&d, cut + 3);

        let from = ValidatorId::new(1);
        let proposal = Arc::new(Verified::new_unchecked_for_test(proposal_with_boundary(
            shard,
            b_qc.clone(),
        )));
        let mut actions = coord.on_certified_local_header(&certified(&a, &a_qc));
        actions.extend(coord.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal));
        actions.extend(coord.on_certified_local_header(&certified(&b, &b_qc)));
        actions.extend(coord.on_certified_local_header(&certified(&c, &c_qc)));
        assert!(
            coord.participant.awaiting_boundaries.contains_key(&from),
            "the boundary's dating child is only certified, so the proposal awaits",
        );
        let asked: Vec<(ShardId, BlockHeight)> = actions
            .iter()
            .filter_map(|action| match action {
                Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard,
                    block_height,
                }) => Some((*source_shard, *block_height)),
                _ => None,
            })
            .collect();
        assert!(!asked.is_empty(), "the awaiting proposal asks for a proof");

        let bystander = BeaconParticipant::new(&coord.fold, ValidatorId::new(2));
        let proofs = [
            certified(&b, &b_qc),
            certified(&c, &c_qc),
            certified(&d, &d_qc),
        ];
        let (asked_for, unasked): (Vec<_>, Vec<_>) = proofs
            .iter()
            .partition(|proof| asked.contains(&(proof.shard_id(), proof.height())));
        assert!(
            !coord
                .fold
                .admit_proven_for(unasked[0], [&bystander, &coord.participant]),
            "a proof no participant asked for is not held",
        );
        assert!(
            !coord.fold.admit_proven_for(asked_for[0], [&bystander]),
            "the bystander asked for nothing",
        );
        for proof in asked_for {
            assert!(
                coord
                    .fold
                    .admit_proven_for(proof, [&bystander, &coord.participant]),
                "one participant's ask holds the proof",
            );
        }
        let _ = coord.participant.on_source_header(&coord.fold);
        assert!(
            coord.participant.awaiting_boundaries.is_empty()
                && coord.participant.proposal_pool.contains(from),
            "the proven commit releases the asker's proposal into its pool",
        );
    }

    /// A genuine fork proof against a shard the lookahead no longer
    /// seats is inadmissible, though it verifies: the schedule still
    /// resolves the committee of the window its QCs were signed in. The
    /// seated control proves the rejection is the seating check, not
    /// verification. The same proof observed locally is not buffered, so
    /// the coordinator's own proposal carries none.
    #[test]
    fn proposal_with_a_fork_proof_against_an_unseated_shard_is_dropped() {
        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};
        use hyperscale_types::{BlockHeight, ShardForkProof, VrfProof};

        let committee = TestCommittee::new(4, 1);
        let pubkeys = [0, 1, 2, 3].map(|seat| *committee.public_key(seat));
        let from = ValidatorId::new(1);
        let proof = shard_fork_proof(&committee, ShardId::ROOT, BlockHeight::new(5));
        let proposal = || {
            let fork_proofs: BTreeMap<ShardId, ShardForkProof> =
                std::iter::once((ShardId::ROOT, proof.clone())).collect();
            Arc::new(Verified::new_unchecked_for_test(BeaconProposal::new(
                BTreeMap::new(),
                Vec::new(),
                fork_proofs,
                Vec::new(),
                VrfProof::ZERO,
            )))
        };
        // The root's split has applied: its children hold the lookahead
        // and the root is in its last window.
        let unseat = |coord: &mut BeaconCoordinator| {
            let members = coord
                .fold
                .state
                .next_shard_committees
                .remove(&ShardId::ROOT)
                .expect("the genesis committee");
            for child in <[ShardId; 2]>::from(ShardId::ROOT.children()) {
                coord
                    .fold
                    .state
                    .next_shard_committees
                    .insert(child, members.clone());
            }
        };

        let mut seated = coord_seating(pubkeys);
        seated.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal());
        assert!(seated.participant.proposal_pool.contains(from));

        let mut unseated = coord_seating(pubkeys);
        unseat(&mut unseated);
        assert_eq!(
            proof.verify(&BlsVerifier, &unseated.fold.topology_schedule),
            Ok(()),
        );
        unseated.on_beacon_proposal_received(from, Epoch::GENESIS.next(), proposal());
        assert!(!unseated.participant.proposal_pool.contains(from));

        unseated.observe_fork_proof(proof.clone());
        assert!(unseated.participant.fork_proofs.is_empty());

        let mut departing = coord_seating(pubkeys);
        departing.observe_fork_proof(proof.clone());
        assert!(departing.participant.fork_proofs.contains(ShardId::ROOT));
        unseat(&mut departing);
        departing.prune_folded_evidence();
        assert!(departing.participant.fork_proofs.is_empty());
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
        assert!(coord.participant.proposal_pool.is_empty());
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
        assert!(coord.participant.proposal_pool.is_empty());
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
                fork_proofs,
                vote_equivocations: _,
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
        assert!(fork_proofs.is_empty());
        // Three peers in the n=4 committee (self filtered out).
        assert_eq!(recipients.len(), 3);
        assert!(!recipients.contains(&coord.me()));
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
        let me = coord.me();
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
        use hyperscale_types::{PcVoteEquivocation, PcVoteRound};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();

        let evidence = PcVoteEquivocation {
            validator: ValidatorId::new(2),
            epoch: Epoch::new(1),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::empty(),
            sig_a: ConsensusSignature::new([0x11; 96]),
            value_b: PcVector::empty(),
            sig_b: ConsensusSignature::new([0x22; 96]),
        };
        assert!(
            coord
                .participant
                .equivocations
                .record_pc_equivocation(evidence)
        );

        let actions = coord.try_propose();
        let equivocations = proposal_equivocations(&actions);
        assert_eq!(equivocations.len(), 1);
        assert_eq!(equivocations[0].validator, ValidatorId::new(2));
        assert!(coord.participant.equivocations.is_empty());
    }

    /// The signed proposal pools only when its build returns, so a second
    /// trigger in between must not build again: the durable register
    /// refuses the second body, and the evidence drained into it would be
    /// gone.
    #[test]
    fn a_second_try_propose_while_a_proposal_is_in_flight_drains_no_evidence() {
        use hyperscale_types::{PcVoteEquivocation, PcVoteRound};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let evidence = |validator: u64| PcVoteEquivocation {
            validator: ValidatorId::new(validator),
            epoch: Epoch::new(1),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::empty(),
            sig_a: ConsensusSignature::new([0x11; 96]),
            value_b: PcVector::empty(),
            sig_b: ConsensusSignature::new([0x22; 96]),
        };
        assert!(
            coord
                .participant
                .equivocations
                .record_pc_equivocation(evidence(2))
        );
        assert_eq!(proposal_equivocations(&coord.try_propose()).len(), 1);

        assert!(
            coord
                .participant
                .equivocations
                .record_pc_equivocation(evidence(3))
        );
        assert!(
            coord.try_propose().is_empty(),
            "no second build while the first is in flight"
        );
        assert!(
            coord
                .participant
                .equivocations
                .contains(ValidatorId::new(3)),
            "the evidence observed meanwhile stays buffered for a later proposal"
        );
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
        let me = coord.me();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.fold.state.committee.clone();
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
                !coord.participant.spc.view_one_input_fed(),
                "fed without emitting vote1",
            );
            next = peers.next().copied();
        }
        assert_eq!(
            fed_at,
            Some(n),
            "the feed must trigger at exactly full committee coverage",
        );
        assert!(coord.participant.spc.view_one_input_fed());
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
        let me = coord.me();
        let in_flight = Epoch::GENESIS.next();
        let actions = coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(actions.is_empty(), "own proposal alone doesn't kick PC");
        assert!(!coord.participant.spc.view_one_input_fed());

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
            assert!(!coord.participant.spc.view_one_input_fed());
        }

        // Re-arm budget exhausted — feed the partial pool.
        let actions = coord.on_spc_input_dwell_timer();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastPcVote1 { .. })),
            "expected SignAndBroadcastPcVote1 in {actions:?}",
        );
        assert!(coord.participant.spc.view_one_input_fed());
        assert!(coord.on_spc_input_dwell_timer().is_empty());
    }

    /// The dwell asks each missing proposal of its author, the one peer
    /// that holds it whoever else missed its gossip. A peer that lost the
    /// gossip too answers empty, and an ask pinned to it would be put to
    /// it again on every retry.
    #[test]
    fn input_dwell_asks_each_missing_proposal_of_its_author() {
        let mut coord = fresh_coord();
        let _ = coord.bootstrap_spc_for_next_epoch();
        let me = coord.me();
        let in_flight = Epoch::GENESIS.next();
        let _ = coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        let peers: Vec<ValidatorId> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .filter(|member| *member != me)
            .collect();
        let _ = coord.on_beacon_proposal_received(peers[0], in_flight, sample_proposal(0xCD));
        assert!(coord.participant.proposal_pool.contains(peers[0]));

        let actions = coord.on_spc_input_dwell_timer();
        let asks: Vec<(ValidatorId, Option<ValidatorId>)> = actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Proposals(ids)),
                    preferred,
                    ..
                }) => Some((ids[0].1, *preferred)),
                _ => None,
            })
            .collect();
        assert_eq!(
            asks,
            peers[1..]
                .iter()
                .map(|&member| (member, Some(member)))
                .collect::<Vec<_>>(),
        );
    }

    /// Drive `signer_positions` of `committee`'s keys through one
    /// round each of PC voting to assemble a real `Direct` SPC cert
    /// for `(epoch, prev_view)`.
    fn build_direct_cert(
        prev_view: SpcView,
        epoch: Epoch,
        keys: &[BlsSigner],
        committee: &[(ValidatorId, ConsensusPublicKey)],
        signer_positions: &[usize],
        v_in: &PcVector,
    ) -> SpcCert {
        let net = NetworkDefinition::simulator();
        let pc_ctx = PcScope {
            epoch,
            view: prev_view,
        };
        let v1s: Vec<_> = signer_positions
            .iter()
            .map(|&i| {
                sign_vote1(&keys[i], committee[i].0, &net, pc_ctx, v_in.clone()).expect("sign")
            })
            .collect();
        let v1_refs: Vec<&_> = v1s.iter().collect();
        let qc1 = build_qc1(&BlsVerifier, &v1_refs, committee);
        let v2s: Vec<_> = signer_positions
            .iter()
            .map(|&i| {
                sign_vote2(&keys[i], committee[i].0, &net, pc_ctx, qc1.clone()).expect("sign")
            })
            .collect();
        let v2_refs: Vec<&_> = v2s.iter().collect();
        let qc2 = build_qc2(&BlsVerifier, &v2_refs, committee);
        let v3s: Vec<_> = signer_positions
            .iter()
            .map(|&i| {
                sign_vote3(&keys[i], committee[i].0, &net, pc_ctx, qc2.clone()).expect("sign")
            })
            .collect();
        let v3_refs: Vec<&_> = v3s.iter().collect();
        let qc3 = build_qc3(&BlsVerifier, &v3_refs, committee);
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
        let pool = coord.fold.state.derive_active_pool();
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
                .expect("sign")
            })
            .collect();
        build_ratify_cert(&BlsVerifier, &votes, &pool).expect("full pool meets quorum")
    }

    /// Build a peer `BeaconBlock` at `epoch` that verifies under
    /// `coord`'s state: an SPC proposal cert from the committee quorum
    /// plus a pool-signed ratify cert over the block's hash.
    fn valid_block_at(
        coord: &BeaconCoordinator,
        epoch: Epoch,
        prev_hash: BeaconBlockHash,
    ) -> Arc<Verifiable<CertifiedBeaconBlock>> {
        let n = coord.fold.state.committee.len();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let committee: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
        let block = BeaconBlock::new(epoch, prev_hash, Capped::empty());
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
        let n = coord.fold.state.committee.len();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let committee: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
            .collect();
        let signer_positions: Vec<usize> = (0..q).collect();
        let proposal = BeaconProposal::new(
            std::iter::once((ShardId::ROOT, None)).collect(),
            Vec::new(),
            BTreeMap::new(),
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
        let block = BeaconBlock::new(
            epoch,
            prev_hash,
            Capped::from_array([(committee[0].0, proposal)]),
        );
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
        let _prev = coord.fold.latest_block.block_hash();
        let block = Arc::new(Verifiable::from(CertifiedBeaconBlock::genesis(
            GenesisConfigHash::ZERO,
        )));
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert_eq!(coord.fold.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_triggers_sync_for_future_epoch() {
        let mut coord = fresh_coord();
        let prev = coord.fold.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(5), prev);
        let actions = coord.on_beacon_block_received(block);
        // A block more than one epoch ahead drops and triggers gap-fill
        // sync up to its claimed epoch; the tip doesn't move.
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::StartBeaconBlockSync { target } if target == Epoch::new(5)
        ));
        assert_eq!(coord.fold.state.current_epoch, Epoch::GENESIS);
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
        Arc::new(
            Verified::<RatifyVote>::sign_local(
                &keypair(signer),
                ValidatorId::new(signer),
                &NetworkDefinition::simulator(),
                coord.fold.latest_block.block_hash(),
                coord.fold.state.current_epoch.next(),
                round,
                phase,
                block_hash,
            )
            .expect("sign"),
        )
    }

    /// Drive `coord` through the skip outcome for the pending epoch:
    /// deadline passed, one verified precommit for the skip hash per
    /// pool member, cert assembly, adoption. Returns the broadcast
    /// skip block.
    fn adopt_skip_block(coord: &mut BeaconCoordinator) -> Arc<Verified<CertifiedBeaconBlock>> {
        pass_skip_deadline(coord);
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
        let ed = coord_a.fold.state.chain_config.epoch_duration_ms;
        coord_a.set_now(LocalTimestamp::from_millis(2 * ed));
        let genesis_tip = coord_a.fold.latest_block.block_hash();
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
            coord_a.fold.latest_block.block_hash(),
            coord_b.fold.latest_block.block_hash(),
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
        let genesis_tip = coord.fold.latest_block.block_hash();
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
        let genesis_tip = coord.fold.latest_block.block_hash();
        // A vote pooled at the genesis tip for the in-flight epoch.
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                .participant
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
                .participant
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
        let ed = coord.fold.state.chain_config.epoch_duration_ms;
        coord.set_now(LocalTimestamp::from_millis(2 * ed));
        let prev = coord.fold.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let block_hash = block.block_hash();
        let dispatched = coord.on_beacon_block_received(Arc::clone(&block));

        // Cert verification is offloaded — the immediate handler emits
        // exactly one `VerifyBeaconBlock` action.
        let [Action::VerifyBeaconBlock { .. }] = dispatched.as_slice() else {
            panic!("expected single VerifyBeaconBlock, got {dispatched:?}");
        };
        assert!(coord.fold.verification.is_block_in_flight(block_hash));

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
        assert_eq!(coord.fold.state.current_epoch, Epoch::new(1));
        assert_eq!(coord.fold.latest_block.block_hash(), block_hash);
        assert!(!coord.fold.verification.is_block_in_flight(block_hash));
        assert!(
            coord.participant.spc.is_bootstrapped(),
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
        let prev = coord.fold.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(Arc::clone(&block));
        let actions = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.fold.state.current_epoch, Epoch::new(1));
        assert!(
            !coord.participant.spc.is_bootstrapped(),
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
            coord.participant.spc.is_bootstrapped(),
            "the armed BeaconCommitteeStart must bootstrap SPC once its boundary arrives",
        );
    }

    #[test]
    fn off_committee_observer_adopts_valid_peer_block() {
        let mut observer = new_coord(ValidatorId::new(99));
        let prev = observer.fold.latest_block.block_hash();
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
        assert!(!observer.participant.spc.is_bootstrapped());
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
            let prev = observer.fold.latest_block.block_hash();
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
        assert!(!observer.participant.spc.is_bootstrapped());
    }

    /// Adoption prunes buffered equivocation evidence for validators the
    /// fold now holds revoked — no further punishment exists
    /// further, so re-proposing the evidence would only waste block
    /// space. Evidence for other validators stays buffered.
    #[test]
    fn adopt_prunes_evidence_for_revoked_validators() {
        use hyperscale_types::PcVoteRound;
        let mut coord = fresh_coord();
        let evidence = |v: u64| PcVoteEquivocation {
            validator: ValidatorId::new(v),
            epoch: Epoch::new(1),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::empty(),
            sig_a: ConsensusSignature::new([0x11; 96]),
            value_b: PcVector::empty(),
            sig_b: ConsensusSignature::new([0x22; 96]),
        };
        assert!(
            coord
                .participant
                .equivocations
                .record_pc_equivocation(evidence(1))
        );
        assert!(
            coord
                .participant
                .equivocations
                .record_pc_equivocation(evidence(2))
        );
        // Validator 1's jail is already permanent by the time the next
        // block applies.
        coord
            .fold
            .state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::Revoked {
            at_epoch: Epoch::GENESIS,
        };

        let prev = coord.fold.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(block);
        let _ = complete_verifications(&mut coord, dispatched);

        assert_eq!(coord.current_epoch(), Epoch::new(1));
        assert!(
            !coord
                .participant
                .equivocations
                .contains(ValidatorId::new(1))
        );
        assert!(
            coord
                .participant
                .equivocations
                .contains(ValidatorId::new(2))
        );
    }

    /// A commit that rotates the local validator off the beacon
    /// committee drops the pooled witness chunks and releases in-flight
    /// witness fetches as `BeaconFetchIds::Witnesses`, so the
    /// runner's fetch slots don't pin on payloads an off-committee vnode
    /// no longer wants.
    #[test]
    fn adopt_releases_witness_state_when_local_falls_off_committee() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let anchor = BlockHash::from_raw(Hash::from_bytes(b"witness-anchor"));
        let height = BlockHeight::new(5);
        coord
            .fold
            .shard_source
            .register_pending_fetch(shard, height, anchor, 0, 2);

        // Jail the local validator so the post-apply resample drops it
        // from the beacon committee.
        coord
            .fold
            .state
            .validators
            .get_mut(&coord.me())
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };

        let prev = coord.fold.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let dispatched = coord.on_beacon_block_received(block);
        let actions = complete_verifications(&mut coord, dispatched);

        assert!(!coord.is_on_committee());
        assert!(
            !coord
                .fold
                .shard_source
                .is_pending_fetch(shard, anchor, 0, 2)
        );
        let abandoned = actions.iter().any(|a| {
            matches!(
                a,
                Action::AbandonFetch(FetchIds::Beacon(BeaconFetchIds::Witnesses(ids)))
                    if ids.contains(&(shard, height, anchor, LeafIndex::new(0), LeafIndex::new(2)))
            )
        });
        assert!(
            abandoned,
            "expected BeaconFetchIds::Witnesses naming the in-flight fetch, got {actions:?}",
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
        let committee = coord.fold.state.committee.clone();
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
            coord.participant.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
        assert_eq!(coord.fold.state.current_epoch, Epoch::GENESIS);
        let fetches_divergent = actions.iter().any(|a| {
            matches!(
                a,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Proposals(wanted)),
                    ..
                })
                    if wanted
                        .iter()
                        .any(|(_, validator)| *validator == committee[divergent_pos])
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
        let committee = coord.fold.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.participant.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        // Construct a verifying cert the way the SPC FSM would produce
        // it — same machinery `valid_block_at` uses.
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
            .participant
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
        assert_eq!(
            coord.fold.state.current_epoch,
            Epoch::GENESIS,
            "no adoption"
        );
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
        let committee = coord.fold.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.participant.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
        let candidate_hash = coord
            .participant
            .ratify
            .candidate()
            .expect("candidate held");

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

        assert_eq!(coord.fold.state.current_epoch, in_flight);
        assert_eq!(coord.fold.latest_block.epoch(), in_flight);
        assert!(matches!(
            coord.fold.latest_block.cert(),
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
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_triggers_sync_for_future_epoch() {
        let mut coord = fresh_coord();
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                Action::StartBeaconBlockSync { target, .. } if *target == Epoch::new(98)
            )),
            "a vote ratifying a future epoch reveals missing beacon blocks \
             and must trigger gap-fill sync toward its anchor epoch; got {actions:?}",
        );
        assert_eq!(
            coord
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_at_stale_epoch() {
        let mut coord = fresh_coord();
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_non_pool_signer() {
        let mut coord = fresh_coord();
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_drops_invalid_sig_via_async_result() {
        let mut coord = fresh_coord();
        let skip_hash = coord.participant.ratify.skip_block_hash();
        // Signer 0 is in the pool, but sig is all-zeros — verification
        // returns false on the result path.
        let vote = Arc::new(Verifiable::from(RatifyVote::new(
            coord.fold.latest_block.block_hash(),
            coord.fold.state.current_epoch.next(),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
            ValidatorId::new(0),
            ConsensusSignature::new([0u8; 96]),
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
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            0
        );
    }

    #[test]
    fn on_ratify_vote_admits_valid_vote_below_quorum() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let skip_hash = coord.participant.ratify.skip_block_hash();
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
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Precommit),
            1,
            "vote must land in the tracker after verification",
        );
        // n=4 → quorum is ⌈8/3⌉+1 = 4. One sig is below.
        assert!(
            coord.participant.spc.is_bootstrapped(),
            "SPC still running below quorum"
        );
    }

    /// A vote whose slot the tracker already filled — the common case
    /// for a vote re-sent in a peer's proof — is dropped before its
    /// signature is checked.
    #[test]
    fn a_pooled_ratify_vote_is_not_verified_again() {
        let mut coord = fresh_coord();
        let skip_hash = coord.participant.ratify.skip_block_hash();
        let vote = wire_ratify_vote(
            &coord,
            0,
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            skip_hash,
        );
        let resent = Arc::clone(&vote);
        let dispatched = coord.on_unverified_ratify_vote_received(vote);
        let _ = complete_verifications(&mut coord, dispatched);
        assert_eq!(
            coord
                .participant
                .ratify
                .vote_count(RatifyRound::INITIAL, RatifyPhase::Prevote),
            1,
        );

        assert!(coord.on_unverified_ratify_vote_received(resent).is_empty());
        assert_eq!(coord.verifications_in_flight(), 0);
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
        let anchor = coord.fold.latest_block.block_hash();
        let epoch_to_skip = coord.fold.state.current_epoch.next();
        let skip_hash = coord.participant.ratify.skip_block_hash();
        let n = coord.fold.state.committee.len();

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
        assert_eq!(coord.fold.state.current_epoch, epoch_to_skip);
        // Tip now points at the Skip block, committed by a ratify cert
        // naming the previous tip as anchor.
        let BeaconCert::Skip(cert) = coord.fold.latest_block.cert() else {
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
                .participant
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
        let skip_hash = coord.participant.ratify.skip_block_hash();
        let n = coord.fold.state.committee.len();

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
        let n = coord.fold.state.committee.len();
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
        assert!(
            coord.participant.ratify.is_completed(),
            "the epoch is decided"
        );
        assert_eq!(
            coord.fold.state.current_epoch,
            Epoch::GENESIS,
            "nothing adopted without the block",
        );

        // SPC dispatch is now gated — the view timer drops without
        // dispatching into the FSM (no broadcast actions).
        let actions = coord.on_beacon_spc_view_timer();
        assert!(actions.is_empty(), "gated dispatch must emit no actions");
        // The SPC instance stays Some — gate is query-based, not
        // state-based.
        assert!(coord.participant.spc.is_bootstrapped());
    }

    /// Build a (chunk, source-shard verified header) pair where the
    /// chunk's range proof verifies under the header's
    /// `beacon_witness_root`. `total_leaves` sizes the accumulator; the
    /// chunk covers `[lo, hi)` of it.
    fn make_verifiable_chunk_and_header(
        shard: ShardId,
        height: u64,
        lo: u64,
        hi: u64,
        total_leaves: u64,
    ) -> (
        Vec<ShardWitnessPayload>,
        Vec<Hash>,
        Arc<Verified<CertifiedBlockHeader>>,
    ) {
        let payloads: Vec<ShardWitnessPayload> = (lo..hi)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: test_pool(u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        let mut leaves: Vec<Hash> = (0..total_leaves)
            .map(|i| Hash::from_bytes(format!("leaf-{i}").as_bytes()))
            .collect();
        let (lo_i, hi_i) = (usize::try_from(lo).unwrap(), usize::try_from(hi).unwrap());
        for (offset, payload) in payloads.iter().enumerate() {
            leaves[lo_i + offset] = payload.leaf_hash();
        }
        let beacon_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaves));
        let range_proof = compute_range_proof(&leaves, lo_i, hi_i);

        let parent_qc = QuorumCertificate::genesis(shard, ChainOrigin::ROOT);
        let parent_block_hash = BlockHash::ZERO;
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash,
            parent_qc: parent_qc.into(),
            beacon_witness_root: beacon_root,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(total_leaves),
            ..Default::default()
        });
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            BlockHeight::new(height),
            parent_block_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        let certified_header = Arc::new(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(header, qc),
        ));
        (payloads, range_proof, certified_header)
    }

    /// An observed crossing enqueues the whole chunk `[prior, chunk_end)`
    /// as one fetch, capped by `chunk_bounds` at the fold's per-epoch
    /// budget. The run is the unit the range proof covers, so it is never
    /// split across requests.
    #[test]
    fn on_verified_source_header_requests_the_whole_chunk() {
        use hyperscale_types::{MAX_WITNESSES_PER_SHARD, ShardId};
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());

        // A `(B, C)` crossing of the epoch-1 cut: `B`'s predecessor sits
        // at wt 1 (≤ the 300_000 ms cut) and `B`'s own wt is 300_001 (past
        // it), with an accumulator wider than the per-epoch fold budget.
        // `D` commits `C`, which is what lets `C` date `B`.
        let total_leaves = u64::try_from(MAX_WITNESSES_PER_SHARD + 50).unwrap();
        let b = linked_block_header(shard, 5, BlockHash::ZERO, 1, total_leaves);
        let c = linked_block_header(shard, 6, b.block_hash(), 300_001, total_leaves);
        let d = linked_block_header(shard, 7, c.block_hash(), 300_001, total_leaves);
        coord.on_verified_source_header(&b);
        assert!(
            coord.on_verified_source_header(&c).is_empty(),
            "a crossing dated by an uncommitted child asks for nothing",
        );
        let actions = coord.on_verified_source_header(&d);

        let (lo, hi) = actions
            .iter()
            .find_map(|a| match a {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(runs)),
                    ..
                }) => runs.first().map(|(_, _, _, lo, hi)| (*lo, *hi)),
                _ => None,
            })
            .expect("expected a ShardWitnesses fetch");
        // `[0, MAX_WITNESSES_PER_SHARD)` from the applied watermark — the
        // cap binds, the remainder follows once the watermark advances.
        assert_eq!(lo, LeafIndex::new(0));
        assert_eq!(hi, LeafIndex::new(MAX_WITNESSES_PER_SHARD as u64));
    }

    /// A fold whose host gains its first committee participant mid-epoch
    /// fetches the witness chunk of a crossing it already holds: no
    /// further header need arrive to ask for it.
    #[test]
    fn a_participant_added_mid_epoch_on_the_committee_starts_witness_fetches() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        let _ = coord.fold.set_host_on_committee(false);
        let b = linked_block_header(shard, 5, BlockHash::ZERO, 1, 3);
        let c = linked_block_header(shard, 6, b.block_hash(), 300_001, 3);
        let d = linked_block_header(shard, 7, c.block_hash(), 300_001, 3);
        for header in [&b, &c, &d] {
            assert!(
                coord.fold.on_source_header(header).is_empty(),
                "off the committee the fold asks for no witness",
            );
        }
        let asked = coord.fold.set_host_on_committee(true);
        assert!(
            asked.iter().any(|action| matches!(
                action,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(runs)),
                    ..
                }) if runs.iter().any(|run| run.0 == shard)
            )),
            "joining the committee asks for the held crossing's chunk: {asked:?}",
        );
    }

    /// A pooled run is not asked for again until the fold moves past it.
    /// Every landed response re-drives the fetch, so re-asking a held run
    /// feeds itself: a host that serves the source shard answers from its
    /// own store at once, and the loop never yields.
    #[test]
    fn a_pooled_witness_run_is_not_fetched_again() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        let b = linked_block_header(shard, 5, BlockHash::ZERO, 1, 3);
        let c = linked_block_header(shard, 6, b.block_hash(), 300_001, 3);
        let d = linked_block_header(shard, 7, c.block_hash(), 300_001, 3);
        coord.on_verified_source_header(&b);
        coord.on_verified_source_header(&c);
        let asked = |actions: &[Action]| {
            actions.iter().find_map(|a| match a {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(runs)),
                    ..
                }) => runs.first().copied(),
                _ => None,
            })
        };
        let (_, _, anchor, lo, hi) = asked(&coord.on_verified_source_header(&d))
            .expect("an observed crossing asks for its run");
        assert_eq!((lo, hi), (LeafIndex::new(0), LeafIndex::new(3)));

        coord.fold.shard_source.admit_chunk(
            shard,
            anchor,
            lo.inner(),
            (0..3)
                .map(|i| ShardWitnessPayload::StakeDeposit {
                    pool_id: test_pool(i),
                    amount: Stake::from_whole_tokens(1),
                })
                .collect(),
            Vec::new(),
        );

        assert_eq!(asked(&coord.fetch_witness_chunk(shard)), None);
        assert_eq!(asked(&coord.on_verified_source_header(&c)), None);
    }

    #[test]
    fn on_shard_witnesses_received_admits_valid_chunk() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let (payloads, range_proof, header) = make_verifiable_chunk_and_header(shard, 1, 1, 3, 4);
        coord
            .fold
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        let actions = coord.on_shard_witnesses_received(
            shard,
            header.block_hash(),
            LeafIndex::new(1),
            payloads,
            range_proof,
        );
        assert!(actions.is_some_and(|actions| actions.is_empty()));
        assert_eq!(coord.fold.shard_source.total_chunk_len(), 2);
    }

    #[test]
    fn on_shard_witnesses_received_drops_unknown_anchor() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        // The anchor's header was never seated locally.
        let (payloads, range_proof, header) = make_verifiable_chunk_and_header(shard, 1, 0, 1, 1);

        let actions = coord.on_shard_witnesses_received(
            shard,
            header.block_hash(),
            LeafIndex::new(0),
            payloads,
            range_proof,
        );
        assert!(actions.is_none(), "a chunk on an unheld anchor is refused");
        assert_eq!(coord.fold.shard_source.total_chunk_len(), 0);
    }

    /// A chunk delivered at the wrong offset recomputes to a different
    /// root and is dropped — the range's position is what the proof
    /// commits to, so a misplaced run can't slip in.
    #[test]
    fn on_shard_witnesses_received_drops_chunk_at_wrong_offset() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let (payloads, range_proof, header) = make_verifiable_chunk_and_header(shard, 1, 1, 3, 4);
        coord
            .fold
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        let actions = coord.on_shard_witnesses_received(
            shard,
            header.block_hash(),
            LeafIndex::new(2),
            payloads,
            range_proof,
        );
        assert!(actions.is_none(), "a misplaced chunk is refused");
        assert_eq!(coord.fold.shard_source.total_chunk_len(), 0);
    }

    /// A chunk that fails its root check while its crossing stays the one
    /// to fetch asks for nothing: the fetch that delivered it decides
    /// when the run is asked again, and a run this host serves itself
    /// would otherwise be re-asked and refused without end.
    #[test]
    fn a_refused_chunk_of_the_current_crossing_asks_nothing_itself() {
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        coord
            .fold
            .state
            .boundaries
            .insert(shard, genesis_boundary());
        coord.fold.state.shard_committees.insert(
            shard,
            ShardCommittee {
                members: vec![ValidatorId::new(0)],
            },
        );
        let anchor = StateRoot::from_raw(Hash::from_bytes(b"refused-anchor"));
        let (b, mut payloads, range_proof) =
            boundary_block_with_witnesses(shard, 5, 299_000, anchor, 3);
        let c = linked_block_header(shard, 6, b.block_hash(), 301_000, 3);
        let d = linked_block_header(shard, 7, c.block_hash(), 301_000, 3);
        let asked = |actions: &[Action]| {
            actions.iter().any(|a| {
                matches!(
                    a,
                    Action::Fetch(FetchRequest::Ask {
                        ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(_)),
                        ..
                    })
                )
            })
        };
        coord.on_verified_source_header(&b);
        coord.on_verified_source_header(&c);
        let asked_first = coord.on_verified_source_header(&d);
        assert!(
            asked(&asked_first),
            "the crossing's chunk is asked: {asked_first:?}"
        );

        payloads[0] = ShardWitnessPayload::StakeDeposit {
            pool_id: test_pool(999),
            amount: Stake::from_whole_tokens(7),
        };
        let refused = coord.on_shard_witnesses_received(
            shard,
            b.block_hash(),
            LeafIndex::new(0),
            payloads,
            range_proof,
        );
        assert!(refused.is_none(), "{refused:?}");
        assert!(
            asked(&coord.fetch_witness_chunk(shard)),
            "the run is still the one to fetch"
        );
    }

    /// A mutated payload breaks the recomputed root, so the whole chunk is
    /// dropped rather than partially admitted.
    #[test]
    fn on_shard_witnesses_received_drops_mutated_payload() {
        use hyperscale_types::ShardId;
        let mut coord = fresh_coord();
        let shard = ShardId::leaf(1, 0);
        let (mut payloads, range_proof, header) =
            make_verifiable_chunk_and_header(shard, 1, 1, 3, 4);
        coord
            .fold
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        payloads[0] = ShardWitnessPayload::StakeDeposit {
            pool_id: test_pool(999),
            amount: Stake::from_whole_tokens(7),
        };
        let actions = coord.on_shard_witnesses_received(
            shard,
            header.block_hash(),
            LeafIndex::new(1),
            payloads,
            range_proof,
        );
        assert!(actions.is_none(), "a mutated chunk is refused");
        assert_eq!(coord.fold.shard_source.total_chunk_len(), 0);
    }

    #[test]
    fn on_shard_witnesses_received_off_committee_drops_all() {
        use hyperscale_types::ShardId;
        // Validator 99 isn't on the committee.
        let mut observer = new_coord(ValidatorId::new(99));
        let shard = ShardId::leaf(1, 0);
        let (payloads, range_proof, header) = make_verifiable_chunk_and_header(shard, 1, 0, 1, 1);
        observer
            .fold
            .shard_source
            .on_verified_source_header(Arc::clone(&header));

        let actions = observer.on_shard_witnesses_received(
            shard,
            header.block_hash(),
            LeafIndex::new(0),
            payloads,
            range_proof,
        );
        assert!(actions.is_some_and(|actions| actions.is_empty()));
        // Pool stays empty — off-committee never admits chunks.
        assert_eq!(observer.fold.shard_source.total_chunk_len(), 0);
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
    /// A shard that dissolved at a reshape sends no further source
    /// header, and nothing else sheds a shard from the tracker: its
    /// header window, its crossings and its chunks are held for the life
    /// of the process. The handoff evidence window is what ends one, and
    /// a shard the schedule states nothing about is untouched.
    #[test]
    fn a_departed_shards_source_tracking_goes_when_its_evidence_window_closes() {
        let departed = ShardId::leaf(1, 1);
        let live = ShardId::leaf(1, 0);

        let coord_with = |handoff_complete: Option<Epoch>| {
            let mut state = state_at(1, 4);
            let mut terminal = boundary_live_at(1);
            // A zeroed hash is the genesis placeholder, which does not
            // project into the snapshot the schedule reads.
            terminal.block_hash = BlockHash::from_raw(Hash::from_bytes(b"terminal"));
            terminal.terminal_epoch = Some(Epoch::new(1));
            terminal.handoff_complete = handoff_complete;
            state.boundaries.insert(departed, terminal);
            state.boundaries.insert(live, boundary_live_at(1));
            let mut coord = coord_from_history(vec![state], Some(LocalChainAnchors::GENESIS));
            for shard in [departed, live] {
                coord
                    .fold
                    .shard_source
                    .on_verified_source_header(boundary_block_header(
                        shard,
                        5,
                        1_000,
                        StateRoot::ZERO,
                        4,
                    ));
                coord.fold.shard_source.register_pending_fetch(
                    shard,
                    BlockHeight::new(5),
                    BlockHash::ZERO,
                    0,
                    4,
                );
            }
            coord
        };
        let holds = |coord: &BeaconCoordinator, shard: ShardId| {
            coord
                .fold
                .shard_source
                .header(shard, BlockHeight::new(5))
                .is_some()
        };

        // Unstamped: the window is open, the terminal is still being
        // sourced, and nothing is retired.
        let mut open = coord_with(None);
        open.commit_local(WeightedTimestamp::from_millis(u64::MAX / 2));
        assert!(open.retire_departed_sources().is_empty());
        assert!(holds(&open, departed), "an open window holds");

        let mut coord = coord_with(Some(Epoch::new(1)));
        let expiry = coord
            .topology_schedule()
            .handoff_evidence_expiry(departed)
            .expect("the stamp fixes an expiry");

        coord.commit_local(expiry);
        assert!(coord.retire_departed_sources().is_empty());
        assert!(holds(&coord, departed), "at the expiry it holds");

        coord.commit_local(expiry.plus(Duration::from_millis(1)));
        let abandoned = coord.retire_departed_sources();

        assert!(!holds(&coord, departed), "past it the headers go");
        assert_eq!(
            abandoned,
            vec![(
                departed,
                BlockHeight::new(5),
                BlockHash::ZERO,
                LeafIndex::new(0),
                LeafIndex::new(4),
            )],
            "and the chunk fetch it was holding is handed back to be cancelled",
        );
        assert!(
            holds(&coord, live),
            "a shard with no departure record keeps everything"
        );
        assert!(
            coord
                .fold
                .shard_source
                .is_pending_fetch(live, BlockHash::ZERO, 0, 4)
        );
    }

    /// A host's fold follows every chain the host runs. A hosted replica
    /// still syncing far behind holds its own anchors back, and the
    /// departed-source clock reads the newest anchor over the chains, so
    /// the lagging one does not freeze the retirement of a departed
    /// shard's source tracking.
    #[test]
    fn a_lagging_hosted_replica_does_not_freeze_its_shards_source_window() {
        let departed = ShardId::leaf(1, 1);
        let mut state = state_at(1, 4);
        let mut terminal = boundary_live_at(1);
        terminal.block_hash = BlockHash::from_raw(Hash::from_bytes(b"terminal"));
        terminal.terminal_epoch = Some(Epoch::new(1));
        terminal.handoff_complete = Some(Epoch::new(1));
        state.boundaries.insert(departed, terminal);
        let mut coord = coord_from_history(vec![state], Some(LocalChainAnchors::GENESIS));
        let lagging = coord.fold.register_chain(
            ShardId::leaf(1, 0),
            LocalChainAnchors {
                committee: WeightedTimestamp::from_millis(1),
                block: WeightedTimestamp::from_millis(1),
            },
            BlockHeight::new(1),
        );
        coord
            .fold
            .shard_source
            .on_verified_source_header(boundary_block_header(
                departed,
                5,
                1_000,
                StateRoot::ZERO,
                4,
            ));
        let expiry = coord
            .topology_schedule()
            .handoff_evidence_expiry(departed)
            .expect("the stamp fixes an expiry");

        coord.commit_local(expiry.plus(Duration::from_millis(1)));
        assert!(
            coord.fold.hosted[&lagging].anchors.block < expiry,
            "the lagging chain is still behind the expiry",
        );
        let _ = coord.retire_departed_sources();
        assert!(
            coord
                .fold
                .shard_source
                .header(departed, BlockHeight::new(5))
                .is_none(),
            "the live chain's anchor retires the departed shard's tracking",
        );
    }

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

    fn coord_from_history(
        history: Vec<BeaconState>,
        local_chain: Option<LocalChainAnchors>,
    ) -> BeaconCoordinator {
        let (block, _genesis_state, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            block,
            history,
            ValidatorId::new(0),
            ShardId::ROOT,
            local_chain.map(|anchors| (anchors, BlockHeight::GENESIS)),
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
        let coord = coord_from_history(
            vec![state_at(1, 4), state_at(2, 3), state_at(3, 2)],
            Some(LocalChainAnchors::GENESIS),
        );
        let ed = coord.current_state().chain_config.epoch_duration_ms;
        let shard = ShardId::ROOT;
        let len_at = |window: u64| {
            coord
                .topology_schedule()
                .at_for_shard(shard, WeightedTimestamp::from_millis(window * ed))
                .map(|(t, _)| t.committee_for_shard(shard).len())
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

    /// A coordinator at genesis holds the genesis window as published,
    /// since no fold projected it. One resumed past genesis holds each
    /// window the states it loaded projected, and leaves the window of
    /// its oldest loaded state unpublished: the state that projected it
    /// is not in hand, and the frozen window is not that projection.
    #[test]
    fn a_schedule_at_genesis_and_one_resumed_hold_their_first_published_window() {
        let genesis = fresh_coord();
        let ed = genesis.current_state().chain_config.epoch_duration_ms;
        let published = |coord: &BeaconCoordinator, epoch: u64| {
            coord
                .topology_schedule()
                .recovery_as_published(ShardId::ROOT, WeightedTimestamp::from_millis(epoch * ed))
        };
        assert_eq!(published(&genesis, 0), Ok(None));
        assert_eq!(published(&genesis, 1), Ok(None));
        assert_eq!(published(&genesis, 2), Err(Unpublished));

        let tip = valid_block_at(&genesis, Epoch::new(3), genesis.latest_block().block_hash());
        let tip = Arc::new(Verified::new_unchecked_for_test(
            tip.as_unverified().clone(),
        ));
        let (_, _, config_hash) = genesis_trio();
        let resumed = BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            tip,
            vec![state_at(2, 4), state_at(3, 4)],
            ValidatorId::new(0),
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
            NetworkDefinition::simulator(),
            config_hash,
        );
        assert!(
            resumed
                .topology_schedule()
                .at(WeightedTimestamp::from_millis(2 * ed))
                .is_some(),
            "the oldest loaded window is held frozen"
        );
        assert_eq!(published(&resumed, 2), Err(Unpublished));
        assert_eq!(published(&resumed, 3), Ok(None));
        assert_eq!(published(&resumed, 4), Ok(None));
    }

    /// Construction retains every loaded state — the runner bounds what it
    /// loads via [`retention_floor`], and `adopt_block` trims forward from
    /// there as the consumer frontiers advance.
    #[test]
    fn construction_retains_the_full_loaded_history() {
        let history: Vec<BeaconState> = (0..=8).map(|e| state_at(e, 4)).collect();
        let coord = coord_from_history(history, Some(LocalChainAnchors::GENESIS));
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
            boundary_qc: None,
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
            formed: Epoch::GENESIS,
            last_live_epoch: Epoch::new(epoch),
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_settled_txs: None,
            reshape_admitted_epoch: None,
        }
    }

    fn boundary_terminal_at(epoch: u64) -> ShardBoundary {
        ShardBoundary {
            boundary_qc: None,
            terminal_epoch: Some(Epoch::new(epoch)),
            handoff_complete: None,
            ..boundary_live_at(epoch)
        }
    }

    #[test]
    fn the_retained_anchor_trails_the_committed_tips_own_anchor() {
        // The shard resolves its committed tip's committee from the tip's
        // *parent* anchor, so the floor has to sit there and not at the tip's
        // own — otherwise the window that verifies the parent QC over the tip
        // is evictable. A fixed slack cannot stand in for the real value:
        // consecutive anchors sit an unbounded number of windows apart when
        // the chain stalls between the two blocks, as it does here.
        let mut coord = new_coord(ValidatorId::new(0));
        let anchor = |ms: u64| WeightedTimestamp::from_millis(ms);

        coord.commit_local(anchor(1_000));
        coord.commit_local(anchor(9_000));
        assert_eq!(
            coord.local_anchors().map(|chain| chain.committee),
            Some(anchor(1_000)),
            "committing a block past a long stall retains the anchor its parent carried, not the \
             one it dates itself by",
        );

        coord.commit_local(anchor(9_500));
        assert_eq!(
            coord.local_anchors().map(|chain| chain.committee),
            Some(anchor(9_000))
        );
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
            retention_floor(&state, Some(wt(5)), local_now(1000)),
            Epoch::new(5)
        );

        // A stalled shard's boundary holds the floor one window before its
        // last live epoch.
        state.boundaries.insert(shard, boundary_live_at(7));
        assert_eq!(
            retention_floor(&state, Some(wt(1000)), local_now(1000)),
            Epoch::new(6)
        );

        // A shard with no boundary record yet pins the floor at genesis.
        state.boundaries.remove(&shard);
        assert_eq!(
            retention_floor(&state, Some(wt(1000)), local_now(1000)),
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
            Some(WeightedTimestamp::from_millis(now_ms)),
            LocalTimestamp::from_millis(now_ms),
        );
        let horizon = Epoch::new(now_ms.saturating_sub(RETENTION_HORIZON.as_secs() * 1000) / ed);
        assert_eq!(floor, horizon);
        assert!(floor < Epoch::new(1000), "horizon trails the head");
    }

    /// The window a terminal record exists to project must outlive the
    /// record.
    ///
    /// A terminal contribution folds two epochs after the cut it closes, so
    /// the record's `last_live_epoch` sits above the last window whose trie
    /// carried the shard. Pinning the floor to `last_live - 1` therefore
    /// evicts exactly that window, and the shard stops resolving through
    /// `terminal_cut_wt` and `at_for_shard` — while the record itself is
    /// still held, carrying the `settled_txs_root` a survivor came for.
    #[test]
    fn a_terminal_records_window_outlives_the_fold_that_delivered_it() {
        let mut state = state_at(1000, 4);
        state
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let head = WeightedTimestamp::from_millis(1000 * ed);
        let now = LocalTimestamp::from_millis(1000 * ed);

        // The cut closed epoch 100; the contribution carrying its roots
        // folded at 102, which is what the record's last live epoch reads.
        let predecessor = ShardId::leaf(2, 0);
        state.boundaries.insert(
            predecessor,
            ShardBoundary {
                boundary_qc: None,
                terminal_epoch: Some(Epoch::new(100)),
                handoff_complete: None,
                ..boundary_live_at(102)
            },
        );

        assert!(
            retention_floor(&state, Some(head), now) <= Epoch::new(100),
            "the floor must retain the window whose trie last carried the shard",
        );
    }

    /// A reshape predecessor's terminal boundary record holds the floor at its
    /// cut even after it leaves the live committees — its schedule window must
    /// outlive the record so straggling observers can snap-sync its anchor and
    /// the still-seated predecessor can resolve its own committee through the
    /// beacon-fold lag before it observes its successors live.
    #[test]
    fn retention_floor_holds_a_terminal_predecessors_window() {
        let mut state = state_at(1000, 4);
        state
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let head = WeightedTimestamp::from_millis(1000 * ed);
        let now = LocalTimestamp::from_millis(1000 * ed);

        let without = retention_floor(&state, Some(head), now);

        // A dropped predecessor — not in the live committees — terminating at
        // epoch 100 pins the floor to 99, below the artifact horizon that
        // would otherwise bind.
        let predecessor = ShardId::leaf(2, 0);
        assert!(!state.shard_committees.contains_key(&predecessor));
        state
            .boundaries
            .insert(predecessor, boundary_terminal_at(100));
        let with = retention_floor(&state, Some(head), now);

        assert!(with < without, "the terminal record lowers the floor");
        assert_eq!(with, Epoch::new(99), "to its terminal cut minus a window");
    }

    /// The retention floor pins the window a settled-window floor reaches
    /// back to across Skip folds: the admission epoch, which a stall does
    /// not move, so the certificates the attested window can still name
    /// keep resolving their signing committees.
    #[test]
    fn retention_floor_holds_the_admission_window_across_skips() {
        use hyperscale_types::{Admission, PendingReshape, RETENTION_HORIZON};

        use crate::state::test_fixtures::net;
        use crate::state::{ApplyEpochInput, apply_epoch};

        let mut state = state_at(1000, 4);
        state
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let admitted = Epoch::new(995);
        state.pending_reshapes.insert(
            ShardId::ROOT,
            PendingReshape::Split {
                last_asserted: Epoch::new(1000),
                admitted: Admission::new(admitted),
                cohort: BTreeMap::new(),
                cohort_seed: state.randomness,
                scheduled: None,
                quiet: false,
            },
        );
        for _ in 0..2 {
            let next = state.current_epoch.next();
            apply_epoch(
                &BlsVerifier,
                &mut state,
                &net(),
                next,
                ApplyEpochInput::Skip,
            );
        }
        assert!(
            state.pending_reshapes.contains_key(&ShardId::ROOT),
            "the skips defer the readiness deadline, so the split stands",
        );

        let head_ms = state.current_epoch.inner() * ed;
        let floor = retention_floor(
            &state,
            Some(WeightedTimestamp::from_millis(head_ms)),
            LocalTimestamp::from_millis(head_ms),
        );
        let admission_window =
            state
                .chain_config
                .epoch_windows()
                .epoch_for(WeightedTimestamp::from_millis(
                    admitted.inner() * ed - RETENTION_HORIZON.as_secs() * 1000,
                ));
        assert!(
            floor <= Epoch::new(admission_window.inner() - 1),
            "the floor {floor:?} must sit at or below the admission's window {admission_window:?} \
             minus one, two skips later",
        );
    }

    /// A host running no shard chain keys no schedule lookup at a local
    /// anchor, so its floor is the other frontiers' — here the artifact
    /// horizon — and never genesis.
    #[test]
    fn retention_floor_without_a_local_chain_is_not_pinned_at_genesis() {
        let mut state = state_at(1000, 4);
        state
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        let ed = state.chain_config.epoch_duration_ms;
        let now_ms = 1000 * ed;
        let horizon = Epoch::new(now_ms.saturating_sub(RETENTION_HORIZON.as_secs() * 1000) / ed);
        assert!(horizon > Epoch::GENESIS);

        assert_eq!(
            retention_floor(&state, None, LocalTimestamp::from_millis(now_ms)),
            horizon,
        );
    }

    /// A coordinator with no local chain sheds the windows every frontier
    /// has passed as it adopts blocks, while one whose local chain has
    /// committed nothing past genesis keeps them for that chain.
    #[test]
    fn a_coordinator_with_no_local_chain_evicts_passed_windows() {
        let history = || {
            [1, 1000]
                .map(|epoch| {
                    let mut state = state_at(epoch, 4);
                    state
                        .boundaries
                        .insert(ShardId::ROOT, boundary_live_at(1000));
                    state
                })
                .to_vec()
        };
        let resolves_window_one = |coord: &BeaconCoordinator| {
            let ed = coord.current_state().chain_config.epoch_duration_ms;
            coord
                .topology_schedule()
                .at(WeightedTimestamp::from_millis(ed))
                .is_some()
        };

        let mut follower = coord_from_history(history(), None);
        let mut seated = coord_from_history(history(), Some(LocalChainAnchors::GENESIS));
        assert!(resolves_window_one(&follower) && resolves_window_one(&seated));

        adopt_skip_block(&mut follower);
        adopt_skip_block(&mut seated);

        assert!(
            !resolves_window_one(&follower),
            "a window no frontier reaches is evicted"
        );
        assert!(
            resolves_window_one(&seated),
            "a local chain at genesis keeps it"
        );
    }

    /// Count the adoptions `actions` record.
    fn commits(actions: &[Action]) -> usize {
        actions
            .iter()
            .filter(|action| matches!(action, Action::CommitBeaconBlock { .. }))
            .count()
    }

    /// Every path that certifies an epoch reaches the fold, and only the
    /// first folds it: a second copy of the block, whichever path brings
    /// it, adopts nothing.
    #[test]
    fn the_fold_adopts_an_epoch_once_whichever_path_certified_it() {
        // The participant certifies first, and the gossiped copy follows.
        let mut certifier = fresh_coord();
        pass_skip_deadline(&mut certifier);
        let skip_hash = certifier.participant.ratify.skip_block_hash();
        let precommits: Vec<_> = (0..4u64)
            .map(|i| {
                signed_ratify_vote(
                    &certifier,
                    i,
                    RatifyRound::INITIAL,
                    RatifyPhase::Precommit,
                    skip_hash,
                )
            })
            .collect();
        let mut emitted = Vec::new();
        for vote in &precommits {
            emitted.extend(certifier.on_verified_ratify_vote_received(Arc::clone(vote)));
        }
        assert_eq!(commits(&emitted), 1, "the certifying participant adopts");
        let block = emitted
            .iter()
            .find_map(|action| match action {
                Action::BroadcastBeaconBlock { block } => Some(Arc::clone(block)),
                _ => None,
            })
            .expect("the certified block is broadcast");
        let epoch = certifier.current_epoch();
        assert_eq!(epoch, block.epoch());
        assert!(
            certifier
                .on_beacon_block_verified(Ok(Arc::clone(&block)))
                .is_empty(),
            "the gossiped copy adopts nothing",
        );
        assert!(
            certifier.fold.adopt(Arc::clone(&block)).is_none(),
            "nor does the fold itself on a second copy",
        );
        assert_eq!(certifier.current_epoch(), epoch);

        // The gossiped copy lands first, and the participant's own quorum
        // completes after it.
        let mut follower = fresh_coord();
        pass_skip_deadline(&mut follower);
        assert_eq!(
            commits(&follower.on_beacon_block_verified(Ok(block))),
            1,
            "the gossiped copy adopts",
        );
        let mut emitted = Vec::new();
        for vote in precommits {
            emitted.extend(follower.on_verified_ratify_vote_received(vote));
        }
        assert_eq!(
            commits(&emitted),
            0,
            "the participant's quorum adopts nothing"
        );
        assert_eq!(follower.current_epoch(), epoch);
    }

    /// Each committed height shifts a hosted chain's anchors once,
    /// however many times it is reported.
    #[test]
    fn a_repeated_local_commit_report_does_not_shift_the_anchors() {
        let mut coord = new_coord(ValidatorId::new(0));
        let committed = |height: u64, anchor_ms: u64| {
            boundary_block_header(ShardId::ROOT, height, anchor_ms, StateRoot::ZERO, 0)
        };
        let anchor = |ms: u64| WeightedTimestamp::from_millis(ms);

        coord.on_local_block_committed(&committed(1, 1_000));
        coord.on_local_block_committed(&committed(2, 2_000));
        coord.on_local_block_committed(&committed(2, 2_000));
        coord.on_local_block_committed(&committed(1, 1_000));
        assert_eq!(
            coord.local_anchors(),
            Some(LocalChainAnchors {
                committee: anchor(1_000),
                block: anchor(2_000),
            }),
            "a height at or below the chain's own moves nothing",
        );

        coord.on_local_block_committed(&committed(3, 3_000));
        assert_eq!(
            coord.local_anchors(),
            Some(LocalChainAnchors {
                committee: anchor(2_000),
                block: anchor(3_000),
            }),
        );
    }

    /// A certified local header reported twice is recorded once: the
    /// second report of its block keeps the copy first held. Neither
    /// report fetches a witness chunk; the committed header does that.
    #[test]
    fn a_certified_local_header_reported_twice_is_recorded_once() {
        let mut coord = fresh_coord();
        let first = boundary_block_header(ShardId::ROOT, 4, 1_000, StateRoot::ZERO, 0);
        let second = boundary_block_header(ShardId::ROOT, 4, 1_000, StateRoot::ZERO, 0);
        assert_eq!(first.block_hash(), second.block_hash());
        assert!(!Arc::ptr_eq(&first, &second));

        assert!(coord.on_certified_local_header(&first).is_empty());
        assert!(coord.on_certified_local_header(&second).is_empty());
        let held = coord
            .fold
            .shard_source
            .header(ShardId::ROOT, BlockHeight::new(4))
            .expect("held");
        assert!(
            Arc::ptr_eq(held, &first),
            "the second report records nothing"
        );
    }

    /// Reloading the states an evicted window was projected from brings
    /// the window back, and leaves the retained ones as they were.
    #[test]
    fn widening_a_schedule_resolves_an_evicted_window_again() {
        let network = NetworkDefinition::simulator();
        let history: Vec<BeaconState> = (1..=6).map(|e| state_at(e, 4)).collect();
        let mut schedule = resumed_schedule(&history, &network);
        let ed = history[0].chain_config.epoch_duration_ms;
        let at = |schedule: &TopologySchedule, epoch: u64| {
            schedule
                .at_for_shard(ShardId::ROOT, WeightedTimestamp::from_millis(epoch * ed))
                .map(|(snapshot, _)| Arc::clone(snapshot))
        };
        let retained = at(&schedule, 5);

        schedule.evict_below(Epoch::new(4));
        assert!(at(&schedule, 2).is_none(), "evicted");

        widen_schedule(&mut schedule, &history, &network);
        assert!(at(&schedule, 2).is_some(), "widened back");
        assert!(at(&schedule, 1).is_some());
        assert_eq!(
            schedule.retained_epochs().map(|(oldest, _)| oldest),
            Some(Epoch::new(1)),
        );
        assert!(
            at(&schedule, 5)
                .zip(retained)
                .is_some_and(|(now, before)| Arc::ptr_eq(&now, &before)),
            "a retained window is not rewritten",
        );
    }

    /// The states a merge of `child` into `ROOT` leaves: window 1 runs
    /// `ROOT`'s two children, and window 1000 runs `ROOT` alone, so
    /// `child`'s terminal window is 1.
    fn merged_history(child: ShardId) -> Vec<BeaconState> {
        let mut before = state_at(1, 4);
        let committee = before
            .shard_committees
            .remove(&ShardId::ROOT)
            .expect("root");
        let (left, right) = ShardId::ROOT.children();
        assert!(child == left || child == right);
        before.shard_committees = BTreeMap::from([(left, committee.clone()), (right, committee)]);
        before.next_shard_committees = before.shard_committees.clone();
        before.shard_consensus_members = before.ready_consensus_members(&before.shard_committees);
        let mut after = state_at(1000, 4);
        after
            .boundaries
            .insert(ShardId::ROOT, boundary_live_at(1000));
        vec![before, after]
    }

    fn coord_hosting(child: ShardId, anchors: LocalChainAnchors) -> BeaconCoordinator {
        let (block, _, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            block,
            merged_history(child),
            ValidatorId::new(0),
            child,
            Some((anchors, BlockHeight::GENESIS)),
            NetworkDefinition::simulator(),
            config_hash,
        )
    }

    fn holds_window(coord: &BeaconCoordinator, epoch: u64) -> bool {
        let ed = coord.current_state().chain_config.epoch_duration_ms;
        coord
            .topology_schedule()
            .at(WeightedTimestamp::from_millis(epoch * ed))
            .is_some()
    }

    /// A hosted chain that committed past its terminal reads nothing from
    /// the windows before it: its terminal record pins what its evidence
    /// names, so its own committee anchor stops flooring the schedule.
    #[test]
    fn a_hosted_chain_that_committed_its_terminal_does_not_hold_the_retention_floor() {
        let (child, _) = ShardId::ROOT.children();
        let ed = state_at(1, 4).chain_config.epoch_duration_ms;
        let in_window = |epoch: u64| WeightedTimestamp::from_millis(epoch * ed + 1);
        let mut coord = coord_hosting(
            child,
            LocalChainAnchors {
                committee: in_window(1),
                block: in_window(1),
            },
        );
        coord.on_local_block_committed(&boundary_block_header(
            child,
            1,
            in_window(1000).as_millis(),
            StateRoot::ZERO,
            0,
        ));
        let token = coord.local_chain.expect("hosted");
        assert!(coord.fold.hosted[&token].terminal_committed);
        assert_eq!(
            coord.local_anchors().map(|anchors| anchors.committee),
            Some(in_window(1)),
            "the chain's committee anchor still names window 1",
        );

        adopt_skip_block(&mut coord);
        assert!(
            !holds_window(&coord, 1),
            "a chain past its terminal holds no window open"
        );
    }

    /// A predecessor whose replica is still committing its last live
    /// blocks after the cut keeps every window its walk reads: its block
    /// anchor is not past its terminal, so nothing latches.
    #[test]
    fn a_lagging_predecessor_keeps_its_windows_after_the_cut() {
        let (child, _) = ShardId::ROOT.children();
        let ed = state_at(1, 4).chain_config.epoch_duration_ms;
        let in_window = |epoch: u64| WeightedTimestamp::from_millis(epoch * ed + 1);
        let mut coord = coord_hosting(
            child,
            LocalChainAnchors {
                committee: in_window(1),
                block: in_window(1),
            },
        );
        coord.on_local_block_committed(&boundary_block_header(
            child,
            1,
            in_window(1).as_millis() + 1,
            StateRoot::ZERO,
            0,
        ));
        adopt_skip_block(&mut coord);
        adopt_skip_block(&mut coord);
        let token = coord.local_chain.expect("hosted");
        assert!(!coord.fold.hosted[&token].terminal_committed);
        assert!(
            holds_window(&coord, 1),
            "the window the lagging chain still verifies under stays"
        );
    }

    #[test]
    fn adopt_block_refreshes_topology_snapshot_and_emits_topology_changed() {
        let mut coord = fresh_coord();
        let pre_snap = Arc::clone(coord.current_topology_snapshot());

        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.fold.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.participant.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .fold
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(BlsSigner::public_key))
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
        let candidate_hash = coord
            .participant
            .ratify
            .candidate()
            .expect("candidate held");
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
        let me = coord.me();

        let mut moved = coord.fold.state.next_shard_committees[&from].clone();
        moved.members.retain(|&v| v != me);
        coord.fold.state.next_shard_committees.insert(from, moved);
        coord
            .fold
            .state
            .next_shard_committees
            .insert(to, ShardCommittee { members: vec![me] });

        let change = coord
            .participation_delta(&SlotEffects::default())
            .expect("relocation produces a delta");
        assert_eq!(change.validator, me);
        assert_eq!(change.join, Some(to));
        assert_eq!(change.leave, Some(from));
        assert_eq!(
            change.effective_epoch,
            coord.fold.state.current_epoch.next()
        );

        // Promotion makes the views agree again — the delta is gone, so
        // the action fires at exactly one commit.
        coord.fold.state.shard_committees = coord.fold.state.next_shard_committees.clone();
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

        let mut moved = coord.fold.state.next_shard_committees[&from].clone();
        moved.members.retain(|&v| v != other);
        coord.fold.state.next_shard_committees.insert(from, moved);
        coord.fold.state.next_shard_committees.insert(
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
        let me = coord.me();
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-fold admission state: drawn from the pool into the
        // lookahead committee under an Observing status.
        remove_me(&mut coord.fold.state.shard_committees, me);
        remove_me(&mut coord.fold.state.next_shard_committees, me);
        coord
            .fold
            .state
            .next_shard_committees
            .get_mut(&via)
            .unwrap()
            .members
            .push(me);
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::Observing {
            shard: via,
            placed_at_epoch: coord.fold.state.current_epoch,
        };
        let mut effects = SlotEffects::default();
        effects.observers_drawn.push(seat(me, via, child));

        let change = coord
            .participation_delta(&effects)
            .expect("a draw produces a delta");
        assert_eq!(change.join, None);
        assert_eq!(change.leave, None);
        assert_eq!(change.observe, Some(ObserveDelta::Begin { via, child }));
        assert_eq!(
            change.effective_epoch,
            coord.fold.state.current_epoch.next()
        );

        // The grow itself is silent: once promotion carries the
        // observer into the active committee, neither view reads the
        // seat as a placement.
        coord
            .fold
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
        let me = coord.me();
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-fold cancel state: back in the pool, out of the
        // lookahead committee; the active window still carries the
        // seat-kind membership.
        remove_me(&mut coord.fold.state.next_shard_committees, me);
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::Pooled;
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
            .fold
            .state
            .next_shard_committees
            .get_mut(&via)
            .unwrap()
            .members
            .push(me);
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: via,
            ready: false,
            placed_at_epoch: coord.fold.state.current_epoch,
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
        let me = coord.me();
        let via = ShardId::ROOT;
        let (child, _) = via.children();

        // Post-execution state: the lookahead replaced the parent with
        // its children; the observer landed on its child as a member.
        coord.fold.state.next_shard_committees.remove(&via);
        coord
            .fold
            .state
            .next_shard_committees
            .insert(child, ShardCommittee { members: vec![me] });
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: child,
            ready: true,
            placed_at_epoch: coord.fold.state.current_epoch,
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
        let me = coord.me();
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
        let me = coord.me();
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
        let me = coord.me();
        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;

        // Pre-merge state: me is a member of the child shard (the split
        // state this merge reverses), in both windows.
        let on_child = ShardCommittee { members: vec![me] };
        coord.fold.state.shard_committees = std::iter::once((child, on_child.clone())).collect();
        coord.fold.state.next_shard_committees = std::iter::once((child, on_child)).collect();
        coord.fold.state.shard_consensus_members = coord
            .fold
            .state
            .ready_consensus_members(&coord.fold.state.shard_committees);
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: child,
            ready: true,
            placed_at_epoch: coord.fold.state.current_epoch,
        };

        // Post-execution lookahead: the children collapsed into the
        // parent; me landed on it as a member.
        coord.fold.state.next_shard_committees.remove(&child);
        coord
            .fold
            .state
            .next_shard_committees
            .insert(parent, ShardCommittee { members: vec![me] });
        coord.fold.state.validators.get_mut(&me).unwrap().status = ValidatorStatus::OnShard {
            shard: parent,
            ready: true,
            placed_at_epoch: coord.fold.state.current_epoch,
        };

        let change = coord
            .participation_delta(&SlotEffects::default())
            .expect("execution produces the flip");
        assert_eq!(change.join, Some(parent));
        assert_eq!(change.leave, Some(child));
        assert_eq!(change.keep, None);
    }
}
