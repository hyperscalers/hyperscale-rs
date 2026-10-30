//! One validator identity's beacon consensus duty.
//!
//! [`BeaconParticipant`] runs a validator's SPC, ratification and
//! proposal duty against the [`BeaconFold`] it is driven with: every
//! handler reads the fold and returns what the participant does. A
//! handler that pools a ratify vote can complete the epoch's commit
//! certificate, so it returns a [`ParticipantStep`] carrying the
//! certified block, and the driver adopts it into the fold before
//! running [`BeaconParticipant::on_adopted`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{
    Action, BeaconFetchIds, FetchIds, FetchRequest, KeepDelta, ObserveDelta, ParticipationChange,
    ProtocolEvent, TimerId,
};
use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, BeaconCert, BeaconProposal, BlockHeight, CandidateBeaconBlock,
    CandidateBeaconBlockVerifyError, CertifiedBeaconBlock, ConsensusPublicKey, Epoch,
    MAX_EQUIVOCATIONS_PER_PROPOSER, PcValueElement, PcVector, PcVote1, PcVote1VerifyError, PcVote2,
    PcVote2VerifyError, PcVote3, PcVote3VerifyError, PcVoteEquivocation, RatifyCert, RatifyPhase,
    RatifyRound, RatifyVote, RatifyVoteRecord, RatifyVoteVerifyError, RecoveryCause,
    SPC_INPUT_DWELL, ShardCommittee, ShardForkProof, ShardId, ShardVoteEquivocation, SlotEffects,
    SpcCert, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError, SpcNewCommitMsg,
    SpcNewCommitMsgVerifyError, SpcProposalObject, SpcProposalObjectVerifyError, SpcView,
    ValidatorId, ValidatorStatus, Verifiable, Verified,
};
use tracing::{debug, error, trace, warn};

use crate::boundary;
use crate::commit_assembly::{AssemblyDecision, CommitAssembler};
use crate::equivocations::EquivocationObservations;
use crate::fold::{BeaconFold, CandidateKeys};
use crate::fork_observations::ForkProofObservations;
use crate::proposal_pool::BeaconProposalPool;
use crate::ratify::{RatifyEffect, RatifyTracker};
use crate::spc::SpcEffect;
use crate::spc_driver::SpcDriver;
use crate::verification::{BeaconVerificationPipeline, RatifyVoteSlotKey};
use crate::vote_equivocation_observations::VoteEquivocationObservations;

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
/// vector. The cap bounds the wait so a member whose proposal no node
/// holds cannot stall the epoch: every node then feeds the same partial
/// vector and the epoch still makes progress. That agreement rests on the
/// dwell outlasting a fetch of anything a peer does hold. Where it does
/// not — the asks lost on channels that heal partway through the dwell —
/// members feed the differing subsets their fetches recovered, and the
/// commit truncates at the first slot they disagree on, to empty when
/// that is slot 0. At [`SPC_INPUT_DWELL`] per re-arm the wait is a few
/// seconds — negligible against the epoch, comfortably inside
/// [`SPC_VIEW_TIMEOUT`](hyperscale_types::SPC_VIEW_TIMEOUT).
pub const MAX_INPUT_DWELL_REARMS: u32 = 6;

/// The longest a member waits for the committee's inputs to an SPC view
/// before feeding whatever it holds: view 1's dwell with every re-arm, and
/// the same bound on a view ≥ 2's proposal objects. A silent member costs
/// an epoch this, not a view timeout.
pub const MAX_INPUT_WAIT: Duration = SPC_INPUT_DWELL.saturating_mul(MAX_INPUT_DWELL_REARMS + 1);

/// Candidates held for epochs past the pending one. One committee
/// certifies one candidate per epoch; the cap bounds what a sender can
/// make a member hold before it can verify any of them. A full buffer
/// gives way to a nearer epoch, so a sender filling it with epochs far
/// ahead holds no slot past the next real candidate.
const MAX_EARLY_CANDIDATES: usize = 4;

/// What one participant handler produced: its actions, and the block a
/// ratification commit certificate it assembled certified, which the
/// driver adopts into the fold.
#[derive(Default)]
#[must_use]
#[allow(missing_docs)] // the struct doc names both fields
pub struct ParticipantStep {
    pub actions: Vec<Action>,
    pub certified: Option<Verified<CertifiedBeaconBlock>>,
}

impl From<Vec<Action>> for ParticipantStep {
    fn from(actions: Vec<Action>) -> Self {
        Self {
            actions,
            certified: None,
        }
    }
}

/// What a participant made of a peer's proposal. Ordered by how much
/// it says about the proposer, so co-hosted participants' judgements of
/// one copy combine by their maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProposalAdmission {
    /// Nothing here judged the proposal: it is for another epoch or from
    /// outside the committee, its proposer was judged already, or it
    /// rests on state this member does not hold, now or yet.
    Abstained,
    /// The pool took it.
    Admitted,
    /// Its evidence is false by its own bytes under keys every member
    /// resolves alike, so no honest proposer sends it.
    Refuted,
}

/// One validator's beacon consensus duty.
pub struct BeaconParticipant {
    me: ValidatorId,

    /// SPC consensus-plane driver: the optional current-epoch instance
    /// plus the PC-vote and SPC-message verification slot pools. Bare
    /// between bootstrap and the first epoch-boundary trigger, and again
    /// briefly between an epoch's commit and the next bootstrap.
    pub(crate) spc: SpcDriver,

    /// In-flight candidate and ratify-vote signature checks. Dedup-only,
    /// as the fold's block slots are.
    pub(crate) verification: BeaconVerificationPipeline,

    /// Ratification state for the pending epoch at the current tip:
    /// rounds, own-vote registers, locks, pooled votes, and
    /// commit-cert assembly. Rebuilt on every adoption for the new
    /// `(anchor, epoch)`.
    pub(crate) ratify: RatifyTracker,

    /// The verified SPC candidate awaiting ratification, held so the
    /// commit certificate can pair with the block it names. First
    /// verified candidate wins; reset on every adoption. A replica
    /// whose cert names a hash it never held adopts from the
    /// assembler's certified-block broadcast instead.
    pending_candidate: Option<Verified<CandidateBeaconBlock>>,

    /// Candidates the pool prevoted that this member never received and
    /// has asked a prevoter for, as `(epoch, block_hash)`. One ask per
    /// candidate; the asks are abandoned when the epoch settles.
    candidate_asks: BTreeSet<(Epoch, BeaconBlockHash)>,

    /// Candidates for epochs past the pending one, which extend a block
    /// this member has yet to adopt. A member behind its pool, by one
    /// block or several, receives the pool's candidate before the blocks
    /// it builds on, and the gossip is sent once: dropped here, the
    /// member can prevote only skip until a later round's prevotes lead
    /// it to fetch the candidate, and a pool short of the members that
    /// hold it concedes the epoch. Replayed on every adoption until the
    /// block they extend is the tip; unverified until then, so capped at
    /// [`MAX_EARLY_CANDIDATES`]. Keyed by epoch first, so the last entry
    /// is the furthest ahead.
    early_candidates: BTreeMap<(Epoch, BeaconBlockHash), Verifiable<CandidateBeaconBlock>>,

    /// Equivocation evidence the local vnode has observed but not
    /// yet proposed for inclusion.
    pub(crate) equivocations: EquivocationObservations,

    /// Shard fork proofs the local vnode has verified but not yet
    /// carried into a proposal. Fed from the shard layer's fork
    /// detection; drained into the next proposal so the fold can stamp a
    /// fork-caused `ShardRecovery`.
    pub(crate) fork_proofs: ForkProofObservations,
    /// Locally verified shard double-vote pairs awaiting a proposal
    /// slot — the gossip-fed recovery lane for evidence whose holders
    /// left the source committee.
    vote_equivocations_observed: VoteEquivocationObservations,

    /// Per-epoch cache of committee members' `BeaconProposal`s.
    /// Scoped to the in-flight epoch (`state.current_epoch.next()`);
    /// reset on commit. Participant-local — inbound fetch serving reads the
    /// driver's process-level cache, never this pool.
    pub(crate) proposal_pool: BeaconProposalPool,

    /// The pool epoch this participant last emitted its own proposal
    /// build for. The signed proposal pools only once its build returns,
    /// so this is what keeps a second build — and a second drain of the
    /// buffered evidence — from going out while the first is in flight.
    proposed: Option<Epoch>,

    /// Committee members whose in-flight-epoch `BeaconProposal` this
    /// vnode has already run the witness-admission gate over, regardless
    /// of outcome. Bounds the per-epoch verification work to one
    /// evaluation per committee member so a peer flooding distinct
    /// forged proposals can't force unbounded signature/merkle checks.
    /// The input dwell's ask for a member's proposal releases that
    /// member's slot: a refusal judges the copy this vnode was handed,
    /// which need not be the one its peers pooled, and the answer to the
    /// ask is evaluated afresh. An abstention for want of a boundary's
    /// blocks is released by the header that ends it
    /// ([`Self::release_awaited_proposals`]). The
    /// dwell asks at most once per re-arm, so the work stays bounded by
    /// [`MAX_INPUT_DWELL_REARMS`] per member. Cleared on adoption
    /// alongside the proposal-pool reset.
    evaluated_proposers: BTreeSet<ValidatorId>,

    /// Committee members whose in-flight-epoch proposal the input dwell
    /// has asked peers for. A proposal lost on gossip still reaches
    /// every member that fetches it, so a member absent from the fed
    /// vector is one no reachable peer holds: the absence the
    /// withholding jail reads is a choice, not a dropped message.
    /// Released at feed and on epoch advance.
    dwell_fetches: BTreeSet<ValidatorId>,

    /// In-flight-epoch proposals this member abstained on only for want
    /// of a block that decides a boundary they name
    /// ([`boundary::awaited_boundaries`]) — keyed by proposer. The member
    /// asks the shard to prove each block, and every source header that
    /// arrives, proven on an ask or followed, re-evaluates the proposals
    /// it completes. Asked and re-evaluated only until the view-1 input
    /// is fed, the window the input dwell holds open; cleared on epoch
    /// advance.
    pub(crate) awaiting_boundaries: BTreeMap<ValidatorId, Verified<BeaconProposal>>,

    /// Blocks asked for this epoch, as `(shard, height)`: one ask per
    /// block. A chain commits one block per height, so the proven answer
    /// at an asked height is the block the ask was for.
    boundary_asks: BTreeSet<(ShardId, BlockHeight)>,

    /// Commit-assembly sub-machine. Stashes SPC-decided epochs whose
    /// committed proposals reference a `BeaconProposal` the local pool
    /// hasn't observed, tracks the fetches that resolve them, and decides
    /// when assembly is ready. An adoption advancing `current_epoch`
    /// past a stash evicts it via `prune_stale`, whose returned ids the
    /// participant turns into [`BeaconFetchIds::Proposals`].
    commit_assembly: CommitAssembler,

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

    /// The last `(pending epoch, overdue epoch count)` the park watchdog
    /// logged for, so a parked beacon reports once per epoch of parked
    /// time instead of once per ratify-timer fire.
    park_logged: Option<(Epoch, u64)>,
}

impl BeaconParticipant {
    /// A participant for `me` at `fold`'s tip, with no proposal, vote or
    /// candidate in hand.
    #[must_use]
    pub fn new(fold: &BeaconFold, me: ValidatorId) -> Self {
        // The pending epoch's ratification runs over the pool the live
        // (post-fold) state derives — the signer base every candidate
        // outcome at this tip shares.
        let ratify = RatifyTracker::new(
            Arc::clone(&fold.verifier),
            fold.latest_block.block_hash(),
            fold.state.current_epoch.next(),
            fold.state.derive_active_pool(),
        );
        Self {
            me,
            spc: SpcDriver::new(Arc::clone(&fold.verifier), me),
            verification: BeaconVerificationPipeline::new(),
            ratify,
            pending_candidate: None,
            candidate_asks: BTreeSet::new(),
            early_candidates: BTreeMap::new(),
            equivocations: EquivocationObservations::new(),
            fork_proofs: ForkProofObservations::new(),
            vote_equivocations_observed: VoteEquivocationObservations::new(),
            proposal_pool: BeaconProposalPool::new(fold.state.current_epoch.next()),
            proposed: None,
            evaluated_proposers: BTreeSet::new(),
            dwell_fetches: BTreeSet::new(),
            awaiting_boundaries: BTreeMap::new(),
            boundary_asks: BTreeSet::new(),
            commit_assembly: CommitAssembler::new(),
            input_dwell_rearms: 0,
            park_logged: None,
        }
    }

    #[must_use]
    pub(crate) const fn me(&self) -> ValidatorId {
        self.me
    }

    /// Install the durable ratification record a restart recovered —
    /// see [`RatifyTracker::install_recovered_record`]. Call once,
    /// right after construction, before any input is processed; a
    /// record for a different epoch than the pending ratification is
    /// ignored.
    pub fn install_recovered_ratify_record(
        &mut self,
        fold: &BeaconFold,
        record: &RatifyVoteRecord,
    ) {
        self.ratify.install_recovered_record(record, &fold.network);
    }

    /// Whether the local validator sits on the current beacon
    /// committee. The runner gates committee-only event forwarding
    /// (PC votes, SPC messages) on this.
    #[must_use]
    pub fn is_on_committee(&self, fold: &BeaconFold) -> bool {
        fold.state.committee.contains(&self.me)
    }

    /// Hash of the verified candidate held for the pending epoch, if
    /// any.
    #[must_use]
    pub(crate) fn pending_candidate_hash(&self) -> Option<BeaconBlockHash> {
        self.pending_candidate.as_ref().map(|c| c.block_hash())
    }

    /// `TimerId::BeaconRatifyTrigger` fired. The first fire past the
    /// pending epoch's deadline makes the skip hash prevotable (the
    /// expected block didn't commit in time); each subsequent fire is a
    /// round timeout that re-prevotes per the tracker's lock rule. The
    /// timer re-arms at the next round boundary
    /// ([`BeaconFold::duration_until_next_ratify_fire`]) while the epoch is
    /// undecided. Each fire past the deadline also asks peers for the
    /// pending epoch's block: a replica that missed its gossip sees the
    /// same overdue deadline, and a chain that has moved on sends it
    /// nothing else until the next epoch's traffic, which a slow or
    /// stalled epoch withholds.
    ///
    /// The deadline is re-validated at fire time because votes are
    /// built from the *current* tip and epoch: a fire armed against an
    /// older tip looks fresh once the chain advances, and voting on it
    /// would target an epoch whose window may not even have opened.
    /// Re-checking makes any stale or early fire harmless.
    pub fn on_beacon_ratify_timer(&mut self, fold: &BeaconFold) -> Vec<Action> {
        self.park_watchdog(fold);
        if !fold.skip_trigger_due(fold.next_epoch_boundary()) {
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
                duration: fold.duration_until_next_ratify_fire(),
            }];
        }
        if self.ratify.is_completed() {
            return Vec::new();
        }
        let effects = if self.ratify.deadline_passed() {
            self.ratify.on_round_timeout(fold.wall_clock_ratify_round())
        } else {
            self.ratify.on_deadline()
        };
        let mut actions = self.lift_ratify_effects(fold, effects);
        actions.push(Action::StartBeaconBlockSync {
            target: fold.state.current_epoch.next(),
        });
        actions.push(Action::SetTimer {
            id: TimerId::BeaconRatifyTrigger,
            duration: fold.duration_until_next_ratify_fire(),
        });
        actions
    }

    /// The beacon park watchdog: when wall-clock has run a full epoch
    /// duration past the pending epoch's boundary with no commit, log the
    /// machine state a diagnosis needs — once per epoch of parked time,
    /// keyed off the ratify timer's own re-arm loop so no extra timer
    /// exists to die with the thing it watches. A parked beacon is
    /// otherwise silent: every wait state defers politely, and the first
    /// loud symptom is a distant downstream assert or a stalled schedule.
    fn park_watchdog(&mut self, fold: &BeaconFold) {
        let epoch_duration_ms = fold.state.chain_config.epoch_duration_ms;
        let overdue_ms = fold
            .now
            .as_millis()
            .saturating_sub(fold.next_epoch_boundary().as_millis());
        if epoch_duration_ms == 0 || overdue_ms <= epoch_duration_ms {
            self.park_logged = None;
            return;
        }
        let pending = fold.state.current_epoch.next();
        let overdue_epochs = overdue_ms / epoch_duration_ms;
        if self.park_logged == Some((pending, overdue_epochs)) {
            return;
        }
        self.park_logged = Some((pending, overdue_epochs));
        let round = self.ratify.round();
        error!(
            pending_epoch = pending.inner(),
            overdue_epochs,
            spc_bootstrapped = self.spc.is_bootstrapped(),
            spc_view = ?self.spc.current_view().map(SpcView::inner),
            spc_input_fed = self.spc.view_one_input_fed(),
            candidate = ?self.pending_candidate_hash(),
            ratify_round = round.inner(),
            ratify_completed = self.ratify.is_completed(),
            prevotes = ?self.ratify.tallies(round, RatifyPhase::Prevote),
            precommits = ?self.ratify.tallies(round, RatifyPhase::Precommit),
            "beacon parked: no epoch commit a full epoch past its boundary"
        );
    }

    /// Lift the tracker's sign intents into signing dispatches, for pool
    /// members only: the tracker tracks votes on every node, but only
    /// pool members contribute signatures.
    fn lift_ratify_effects(&self, fold: &BeaconFold, effects: Vec<RatifyEffect>) -> Vec<Action> {
        let mut actions = Vec::new();
        for effect in effects {
            match effect {
                RatifyEffect::SignPrevote {
                    round,
                    block_hash,
                    proof,
                } => {
                    actions.extend(self.ratify_sign_action(
                        fold,
                        round,
                        RatifyPhase::Prevote,
                        block_hash,
                        proof,
                    ));
                }
                RatifyEffect::SignPrecommit {
                    round,
                    block_hash,
                    polka,
                } => {
                    actions.extend(self.ratify_sign_action(
                        fold,
                        round,
                        RatifyPhase::Precommit,
                        block_hash,
                        polka,
                    ));
                }
            }
        }
        actions
    }

    fn ratify_sign_action(
        &self,
        fold: &BeaconFold,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
        proof: Vec<Verified<RatifyVote>>,
    ) -> Option<Action> {
        if !self.ratify.pool_contains(self.me) {
            return None;
        }
        Some(Action::SignAndBroadcastRatifyVote {
            anchor: fold.latest_block.block_hash(),
            epoch: fold.state.current_epoch.next(),
            round,
            phase,
            block_hash,
            proof,
        })
    }

    /// A peer's round-1 PC vote arrived. Gate, dedup, and dispatch the
    /// signature check via the [`SpcDriver`]. Admission happens in
    /// [`Self::on_pc_vote1_verified`] when the result lands.
    pub fn on_pc_vote1_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: PcVote1,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote1_received(epoch, view, vote, skip)
    }

    /// A peer's round-2 PC vote arrived.
    pub fn on_pc_vote2_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<PcVote2>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote2_received(epoch, view, vote, skip)
    }

    /// A peer's round-3 PC vote arrived.
    pub fn on_pc_vote3_received(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        vote: Box<PcVote3>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_pc_vote3_received(epoch, view, vote, skip)
    }

    /// A peer's SPC `new-view` arrived. Gate on instance/skip-quorum,
    /// mark the slot in-flight, and dispatch the cert signature check to the
    /// crypto pool. Admission happens in [`Self::on_spc_new_view_verified`]
    /// when the result lands.
    pub fn on_spc_new_view_received(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        proposal: Arc<Verifiable<SpcProposalObject>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc
            .on_spc_new_view_received(epoch, from, proposal, skip)
    }

    /// A peer's SPC `new-commit` arrived.
    pub fn on_spc_new_commit_received(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc.on_spc_new_commit_received(epoch, from, msg, skip)
    }

    /// A peer's SPC `empty-view` attestation arrived.
    pub fn on_unverified_spc_empty_view_received(
        &mut self,
        epoch: Epoch,
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        self.spc
            .on_unverified_spc_empty_view_received(epoch, msg, skip)
    }

    /// A locally-signed empty-view attestation arrived via the
    /// `Action::SignAndBroadcastEmptyView` self-loopback path — verified
    /// by construction, so it feeds the FSM directly.
    pub fn on_verified_spc_empty_view_received(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        msg: Box<Verified<SpcEmptyViewMsg>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_verified_spc_empty_view_received(epoch, msg, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifySpcNewView`] dispatch.
    pub fn on_spc_new_view_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_new_view_verified(epoch, from, view, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifySpcNewCommit`] dispatch.
    pub fn on_spc_new_commit_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_new_commit_verified(epoch, from, view, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifySpcEmptyView`] dispatch.
    pub fn on_spc_empty_view_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_spc_empty_view_verified(epoch, from, view, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifyPcVote1`] dispatch.
    pub fn on_pc_vote1_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote1_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifyPcVote2`] dispatch.
    pub fn on_pc_vote2_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote2_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// Result of an [`Action::VerifyPcVote3`] dispatch.
    pub fn on_pc_vote3_verified(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_pc_vote3_verified(epoch, view, signer, result, skip);
        self.lift_from_spc(fold, effects)
    }

    /// A round-1 PC vote received already verified — fed
    /// in via the local sign-and-emit path. Routes straight into the FSM.
    pub fn on_verified_pc_vote1_received(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        vote: Verified<PcVote1>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_verified_pc_vote1_received(epoch, view, vote, skip);
        self.lift_from_spc(fold, effects)
    }

    /// A round-2 PC vote received already verified.
    pub fn on_verified_pc_vote2_received(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        vote: Box<Verified<PcVote2>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_verified_pc_vote2_received(epoch, view, vote, skip);
        self.lift_from_spc(fold, effects)
    }

    /// A round-3 PC vote received already verified.
    pub fn on_verified_pc_vote3_received(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        view: SpcView,
        vote: Box<Verified<PcVote3>>,
    ) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self
            .spc
            .on_verified_pc_vote3_received(epoch, view, vote, skip);
        self.lift_from_spc(fold, effects)
    }

    /// `TimerId::BeaconSpcView` fired. Route a synthesized `TimerExpired`
    /// into the SPC instance against its current view.
    pub fn on_beacon_spc_view_timer(&mut self, fold: &BeaconFold) -> Vec<Action> {
        let skip = self.ratify_settled_at_tip();
        let effects = self.spc.on_beacon_spc_view_timer(skip);
        self.lift_from_spc(fold, effects)
    }

    /// A peer committee member's `BeaconProposal` arrived. Admit it
    /// to the pool gated on committee membership at `epoch`. The
    /// `IoLoop` has already authenticated `from` and verified the
    /// proposal's VRF reveal against `(network.id, epoch)` under
    /// `from`'s pubkey; what remains is the evidence it carries.
    ///
    /// Once every committee member's proposal — the local one included,
    /// which arrives back via the action handler's feedback — is pooled,
    /// this feeds SPC's view-1 PC instance: `compute_view_one_input`
    /// reads the pool's view of committee proposals and
    /// `SpcEvent::Input` kicks the FSM into outbound traffic. The
    /// post-bootstrap dwell ([`Self::on_spc_input_dwell_timer`]) feeds
    /// a partial vector when a member's proposal never arrives.
    pub fn on_beacon_proposal_received(
        &mut self,
        fold: &BeaconFold,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Verified<BeaconProposal>,
    ) -> (ProposalAdmission, Vec<Action>) {
        if !fold.state.committee.contains(&from) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                "BeaconProposalReceived from non-committee sender — dropping",
            );
            return (ProposalAdmission::Abstained, Vec::new());
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
                return (ProposalAdmission::Abstained, Vec::new());
            }
            if !self.evaluated_proposers.insert(from) {
                return (ProposalAdmission::Abstained, Vec::new());
            }
            let upgraded = fold
                .upgrade_proposal_equivocations(&proposal)
                .and_then(|upgraded| fold.upgrade_proposal_vote_equivocations(&upgraded))
                .and_then(|upgraded| fold.fork_proofs_admissible(&upgraded).map(|()| upgraded));
            let upgraded = match upgraded {
                Ok(upgraded) => upgraded,
                Err(admission) => {
                    trace!(
                        ?from,
                        epoch = epoch.inner(),
                        ?admission,
                        "BeaconProposalReceived carries unverifiable evidence — dropping",
                    );
                    return (admission, Vec::new());
                }
            };
            // A boundary is judged against this member's view of the
            // shard's chain, which an honest proposer's may lead or trail,
            // so an inadmissible one never refutes the proposal.
            if !boundary::proposal_boundary_qcs_admissible(
                fold.verifier.as_ref(),
                &upgraded,
                &fold.state,
                &fold.shard_source,
                &fold.topology_schedule,
                &fold.network,
                fold.now,
            ) {
                let awaited = boundary::awaited_boundaries(&upgraded, &fold.shard_source);
                if !awaited.is_empty() && self.asks_for_boundaries(fold) {
                    return (
                        ProposalAdmission::Abstained,
                        self.await_boundaries(from, upgraded, &awaited),
                    );
                }
                trace!(
                    ?from,
                    epoch = epoch.inner(),
                    "BeaconProposalReceived carries an unverifiable boundary QC — dropping",
                );
                return (ProposalAdmission::Abstained, Vec::new());
            }
            upgraded
        };
        if !self.proposal_pool.admit(from, epoch, proposal) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                pool_epoch = self.proposal_pool.epoch().inner(),
                "BeaconProposalReceived rejected — wrong epoch or duplicate sender",
            );
            return (ProposalAdmission::Abstained, Vec::new());
        }
        if self.spc.should_feed_view_one_input(epoch) {
            let pooled = fold
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
            if pooled == fold.state.committee.len() {
                return (
                    ProposalAdmission::Admitted,
                    self.feed_view_one_input(fold, epoch),
                );
            }
        }
        (ProposalAdmission::Admitted, Vec::new())
    }

    /// Build view 1's local input vector from the current pool view and
    /// drive it into SPC. Caller gates on
    /// [`SpcDriver::should_feed_view_one_input`]; lifts the effects.
    fn feed_view_one_input(&mut self, fold: &BeaconFold, epoch: Epoch) -> Vec<Action> {
        let input = self.compute_view_one_input(fold, epoch);
        let effects = self.spc.feed_view_one_input(input);
        let mut actions: Vec<Action> = self.release_dwell_fetches().into_iter().collect();
        actions.extend(self.lift_from_spc(fold, effects));
        actions
    }

    /// Abandon the dwell's outstanding proposal fetches once the input
    /// no longer reads them. A fetch commit assembly also awaits stays
    /// live: the committed vector needs its answer.
    fn release_dwell_fetches(&mut self) -> Option<Action> {
        let epoch = self.proposal_pool.epoch();
        let released: Vec<(Epoch, ValidatorId)> = std::mem::take(&mut self.dwell_fetches)
            .into_iter()
            .filter(|validator| !self.commit_assembly.is_awaiting(epoch, *validator))
            .map(|validator| (epoch, validator))
            .collect();
        (!released.is_empty())
            .then(|| Action::AbandonFetch(FetchIds::Beacon(BeaconFetchIds::Proposals(released))))
    }

    /// Build the PC input vector for view 1: one `PcValueElement` per
    /// committee position, the hashed proposal if we've seen it or
    /// [`PcValueElement::BOTTOM`] if not.
    fn compute_view_one_input(&self, fold: &BeaconFold, epoch: Epoch) -> PcVector {
        let elements: Vec<PcValueElement> = fold
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
    /// One build per epoch: the signed proposal pools only when it
    /// returns, so a second build in the meantime would drain the
    /// buffered evidence into a proposal the durable register refuses.
    ///
    /// Proposal payload:
    /// - Per-shard boundary QCs from [`source_boundary_qcs`](crate::boundary::source_boundary_qcs),
    ///   each reported only for a shard whose witness chunk the proposer
    ///   can also supply (the witness-availability coupling).
    /// - Equivocations from [`drain_equivocations_for`](Self::drain_equivocations_for),
    ///   capped at [`MAX_EQUIVOCATIONS_PER_PROPOSER`] with overflow
    ///   re-recorded for the next epoch — each permanently revokes its
    ///   target. Shard witnesses ride the boundary contributions, not the
    ///   proposal.
    pub(crate) fn try_propose(&mut self, fold: &BeaconFold) -> Vec<Action> {
        if !self.spc.is_bootstrapped() {
            trace!("try_propose: no SPC instance — deferring");
            return Vec::new();
        }
        if !self.is_on_committee(fold) {
            return Vec::new();
        }
        let epoch = self.proposal_pool.epoch();
        if self.proposal_pool.contains(self.me) || self.proposed == Some(epoch) {
            return Vec::new();
        }
        self.proposed = Some(epoch);
        let recipients = self.spc_recipients(fold);
        let boundary_qcs = boundary::source_boundary_qcs(&fold.state, &fold.shard_source);
        let equivocations = self.drain_equivocations_for();
        let fork_proofs = self.fork_proofs.drain_for_proposal();
        let vote_equivocations = self.drain_vote_equivocations_for();
        vec![Action::BuildAndBroadcastBeaconProposal {
            epoch,
            boundary_qcs,
            equivocations,
            fork_proofs,
            vote_equivocations,
            recipients,
        }]
    }

    /// Buffer a verified shard fork proof so the next proposal carries it
    /// into the fold. The proof is already verified by the shard layer
    /// (assembled locally from verified headers, or checked off-thread on
    /// gossip receipt); first-wins per shard, so a repeat for an
    /// already-buffered shard is dropped.
    ///
    /// A proof against a shard the lookahead does not seat is not
    /// buffered: no fold registers it, and a proposal carrying it is
    /// inadmissible.
    pub fn observe_fork_proof(&mut self, fold: &BeaconFold, proof: ShardForkProof) {
        if fold
            .state
            .next_shard_committees
            .contains_key(&proof.shard())
        {
            self.fork_proofs.observe(proof);
        }
    }

    /// Buffer a verified shard double-vote pair so the next proposal
    /// carries it into the fold. Verified by the shard layer (vote-keeper
    /// detection, or checked off-thread on gossip receipt); first-wins
    /// per accused validator.
    pub fn observe_vote_equivocation(&mut self, evidence: ShardVoteEquivocation) -> bool {
        self.vote_equivocations_observed.record(evidence)
    }

    /// Drain observed shard double-vote pairs for the next proposal,
    /// capped like the PC lane; overflow is re-recorded for a future
    /// epoch's drain rather than dropped.
    fn drain_vote_equivocations_for(&mut self) -> Vec<ShardVoteEquivocation> {
        let mut pairs = self.vote_equivocations_observed.drain_for_proposal();
        for overflow in pairs.split_off(pairs.len().min(MAX_EQUIVOCATIONS_PER_PROPOSER)) {
            self.vote_equivocations_observed.retain_overflow(overflow);
        }
        pairs
    }

    /// Drain observed equivocations for the next proposal, capped at
    /// [`MAX_EQUIVOCATIONS_PER_PROPOSER`]; overflow is re-recorded for a
    /// future epoch's drain rather than dropped.
    fn drain_equivocations_for(&mut self) -> Vec<PcVoteEquivocation> {
        let mut equivocations = self.equivocations.drain_for_proposal();
        for overflow in
            equivocations.split_off(equivocations.len().min(MAX_EQUIVOCATIONS_PER_PROPOSER))
        {
            self.equivocations.retain_overflow(overflow);
        }
        equivocations
    }

    /// `TimerId::BeaconCommitteeStart` fired — the upcoming epoch's
    /// wall-clock boundary has been reached. If the local validator
    /// is on the next committee and no SPC instance is already
    /// running, bootstrap one and immediately invoke
    /// [`Self::try_propose`] so the local `BeaconProposal` enters
    /// the gossip + admission cycle.
    pub fn on_beacon_committee_start_timer(&mut self, fold: &BeaconFold) -> Vec<Action> {
        if self.spc.is_bootstrapped() {
            trace!("BeaconCommitteeStart fired with SPC already running");
            return Vec::new();
        }
        if !self.is_on_committee(fold) {
            trace!("BeaconCommitteeStart fired but local validator not on committee");
            return Vec::new();
        }
        let mut actions = self.bootstrap_spc_for_next_epoch(fold);
        actions.extend(self.try_propose(fold));
        actions
    }

    /// Stand up a fresh SPC instance for the upcoming epoch under the
    /// current beacon committee, derived from `state`.
    pub(crate) fn bootstrap_spc_for_next_epoch(&mut self, fold: &BeaconFold) -> Vec<Action> {
        let committee = fold.state.derive_beacon_committee();
        self.bootstrap_spc_with_committee(fold, committee)
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
    pub(crate) fn bootstrap_spc_with_committee(
        &mut self,
        fold: &BeaconFold,
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    ) -> Vec<Action> {
        self.spc
            .bootstrap(fold.state.current_epoch.next(), committee);
        self.input_dwell_rearms = 0;
        vec![Action::SetTimer {
            id: TimerId::BeaconSpcInputDwell,
            duration: SPC_INPUT_DWELL,
        }]
    }

    /// Open proposal admission for the epoch after the new tip: an empty
    /// pool, every proposer's dedup slot free, and no boundary block
    /// awaited for the epoch just settled.
    fn reset_proposal_admission(&mut self, fold: &BeaconFold) {
        self.proposal_pool.reset(fold.state.current_epoch.next());
        self.evaluated_proposers.clear();
        self.awaiting_boundaries.clear();
        self.boundary_asks.clear();
    }

    /// Whether an abstention for want of a boundary block still warrants
    /// asking for it: the local member is on the committee and has not
    /// fed its view-1 input, so a proposal admitted now still reaches the
    /// input the withholding sweep reads.
    fn asks_for_boundaries(&self, fold: &BeaconFold) -> bool {
        self.is_on_committee(fold) && !self.spc.view_one_input_fed()
    }

    /// Hold `proposal` against the blocks its boundaries await, and ask
    /// each block's shard to prove it. The shard's headers are QC-verified
    /// on arrival and a commit proof is the round-contiguous two-chain
    /// above the block, so the answer is unforgeable; a source header
    /// that completes the proposal re-evaluates it in
    /// [`Self::release_awaited_proposals`].
    fn await_boundaries(
        &mut self,
        from: ValidatorId,
        proposal: Verified<BeaconProposal>,
        awaited: &[(ShardId, BlockHeight)],
    ) -> Vec<Action> {
        debug!(
            ?from,
            awaited = awaited.len(),
            "Abstained on a proposal for want of a block that decides its boundary — asking its shard",
        );
        self.awaiting_boundaries.insert(from, proposal);
        self.ask_for_boundaries(awaited)
    }

    /// Ask each of `awaited`'s shards to prove its block, once per block
    /// per epoch.
    fn ask_for_boundaries(&mut self, awaited: &[(ShardId, BlockHeight)]) -> Vec<Action> {
        awaited
            .iter()
            .filter(|ask| self.boundary_asks.insert(**ask))
            .map(|&(source_shard, block_height)| {
                Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard,
                    block_height,
                })
            })
            .collect()
    }

    /// Whether this member asked, this epoch, for the block `shard`
    /// commits at `height`. A chain commits one block per height, so a
    /// commit proof at an asked height answers the ask, and the fold
    /// holds it for admission.
    #[must_use]
    pub fn asked(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.boundary_asks.contains(&(shard, height))
    }

    /// The fold recorded or admitted a source header: release the
    /// proposals it completes, while this member is on the committee and
    /// its view-1 input is unfed.
    pub fn on_source_header(&mut self, fold: &BeaconFold) -> Vec<Action> {
        self.release_awaited_proposals(fold)
    }

    /// Judge the awaiting proposals against the source headers now held.
    /// One that awaits nothing further is evaluated afresh, its dedup slot
    /// released. One that a held header lets name a further block — the
    /// child of a boundary just proven, or its parent — asks for it. The
    /// work is bounded by the headers that arrive: each call re-evaluates
    /// a proposal at most once, and a proposal that abstains again awaits
    /// again.
    fn release_awaited_proposals(&mut self, fold: &BeaconFold) -> Vec<Action> {
        if self.awaiting_boundaries.is_empty() || !self.asks_for_boundaries(fold) {
            return Vec::new();
        }
        let awaiting: Vec<(ValidatorId, Vec<(ShardId, BlockHeight)>)> = self
            .awaiting_boundaries
            .iter()
            .map(|(from, proposal)| {
                (
                    *from,
                    boundary::awaited_boundaries(proposal, &fold.shard_source),
                )
            })
            .collect();
        let epoch = fold.state.current_epoch.next();
        let mut actions = Vec::new();
        for (from, awaited) in awaiting {
            if !awaited.is_empty() {
                actions.extend(self.ask_for_boundaries(&awaited));
                continue;
            }
            let Some(proposal) = self.awaiting_boundaries.remove(&from) else {
                continue;
            };
            self.evaluated_proposers.remove(&from);
            actions.extend(
                self.on_beacon_proposal_received(fold, from, epoch, proposal)
                    .1,
            );
        }
        actions
    }

    /// `TimerId::BeaconSpcInputDwell` fired: the proposal-collection
    /// dwell elapsed. Feed the view-1 input once every committee
    /// member's proposal is pooled; otherwise ask peers for each missing
    /// proposal and re-arm the dwell to give a laggard more time, up to
    /// [`MAX_INPUT_DWELL_REARMS`] re-arms — only then feed whatever is
    /// pooled. Waiting for full coverage keeps
    /// honest nodes feeding the same positional vector; a partial vector
    /// diverges and the inner PC's prefix consensus collapses it to an
    /// empty commit. A no-op when the fast path already fed it, or when
    /// no instance is up (off-committee, or the epoch already adopted).
    pub fn on_spc_input_dwell_timer(&mut self, fold: &BeaconFold) -> Vec<Action> {
        let epoch = fold.state.current_epoch.next();
        if !self.spc.should_feed_view_one_input(epoch) {
            return Vec::new();
        }
        let pooled = fold
            .state
            .committee
            .iter()
            .filter(|member| self.proposal_pool.contains(**member))
            .count();
        if pooled < fold.state.committee.len() && self.input_dwell_rearms < MAX_INPUT_DWELL_REARMS {
            self.input_dwell_rearms += 1;
            let missing: Vec<ValidatorId> = fold
                .state
                .committee
                .iter()
                .filter(|member| {
                    **member != self.me
                        && !self.proposal_pool.contains(**member)
                        && !self.dwell_fetches.contains(member)
                })
                .copied()
                .collect();
            for member in &missing {
                self.evaluated_proposers.remove(member);
            }
            self.dwell_fetches.extend(missing.iter().copied());
            let mut actions = Self::fetch_missing_proposals(fold, epoch, &missing);
            actions.push(Action::SetTimer {
                id: TimerId::BeaconSpcInputDwell,
                duration: SPC_INPUT_DWELL,
            });
            return actions;
        }
        self.feed_view_one_input(fold, epoch)
    }

    /// Whether the pending epoch is already decided — a ratification
    /// commit certificate assembled at the local tip. Further PC/SPC
    /// crypto for the epoch is moot.
    const fn ratify_settled_at_tip(&self) -> bool {
        self.ratify.is_completed()
    }

    /// A peer's [`RatifyVote`] arrived via gossip. Validate the
    /// non-crypto fields and dispatch signature verification to the crypto
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
    ///   quorum so the signature check is pointless.
    /// - The signer's `(round, phase)` slot must still be free in the
    ///   tracker; slots are first-wins.
    ///
    /// No deadline gate: prevotes for the candidate are the happy path
    /// *before* the deadline. A premature skip-hash vote is harmless —
    /// the local tracker pools it, but the local validator's own votes
    /// (and the polkas they enable) still pace to the local clock.
    ///
    /// Async (on the crypto pool):
    /// - signature verifies against the canonical
    ///   [`RatifyVoteMessage`](hyperscale_types::RatifyVoteMessage)
    ///   under the signer's pubkey.
    ///
    /// [`derive_active_pool`]: hyperscale_types::BeaconState::derive_active_pool
    pub fn on_unverified_ratify_vote_received(
        &mut self,
        fold: &BeaconFold,
        vote: Arc<Verifiable<RatifyVote>>,
    ) -> Vec<Action> {
        let expected_epoch = fold.state.current_epoch.next();
        // Ahead of every other check, because the only one this vote is
        // held to before its signature is checked is pool membership, and
        // the far-future arm below skips the two that a vote naming an
        // epoch we do not hold cannot pass.
        if !self.ratify.pool_contains(vote.signer()) {
            trace!(
                signer = ?vote.signer(),
                "RatifyVote signer absent from active pool — dropping",
            );
            return Vec::new();
        }
        // A vote ratifying an epoch past the in-flight one means committed
        // beacon blocks exist that this replica never received. A stalled
        // epoch produces no new block gossip, so these votes are the only
        // traffic that reveals the gap — trigger gap-fill sync toward the
        // vote's anchor epoch. The target is a hint (mirrors
        // `on_beacon_block_received`), and the signature behind it is not
        // checked, so what bounds a bogus claim is that an unreachable
        // target stops being one: the sync engine reads a sustained
        // not-found at the height above its own as the tip.
        if vote.epoch() > expected_epoch {
            return vec![Action::StartBeaconBlockSync {
                target: vote.epoch().saturating_sub(1),
            }];
        }
        if vote.anchor_hash() != fold.latest_block.block_hash() {
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
        // Every prevote's proof re-sends votes most of the pool already
        // holds; a taken slot cannot pool a second vote, so its
        // signature is not worth checking.
        if self
            .ratify
            .has_pooled(vote.round(), vote.phase(), vote.signer())
        {
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
            signers: fold.state.derive_active_pool(),
        }]
    }

    /// A locally-signed [`RatifyVote`] arrived via the
    /// `Action::SignAndBroadcastRatifyVote` self-loopback path. The
    /// signing validator produced the signature, so the vote is verified
    /// by construction — skip the verify dispatch and pool directly.
    pub fn on_verified_ratify_vote_received(
        &mut self,
        fold: &BeaconFold,
        vote: Arc<Verified<RatifyVote>>,
    ) -> ParticipantStep {
        self.admit_verified_ratify_vote(fold, Arc::unwrap_or_clone(vote))
    }

    /// Build the block the commit certificate names, for the driver to
    /// adopt and broadcast so peers converge.
    ///
    /// The skip hash rebuilds the canonical skip block from the cert's
    /// own fields; the candidate hash pairs the held verified
    /// candidate with the cert. A cert naming a hash this replica
    /// never held commits nothing locally — the assembling peers
    /// broadcast the certified block and adoption follows from its
    /// receipt.
    fn commit_ratified_block(
        &mut self,
        cert: Verified<RatifyCert>,
    ) -> Option<Verified<CertifiedBeaconBlock>> {
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
            Verified::<CertifiedBeaconBlock>::from_ratified_candidate(candidate, cert)
                .expect("candidate pairs with its ratify cert by construction")
        } else {
            warn!(
                block_hash = ?block_hash,
                "Ratify cert names a candidate this replica never held — awaiting \
                 the assembler's certified block broadcast",
            );
            return None;
        };
        Some(certified)
    }

    /// A previously-dispatched [`Action::VerifyRatifyVote`] has
    /// returned. Clears the `(anchor, epoch, round, phase, signer)`
    /// pipeline slot on both arms — the key fields ride back in the
    /// result event so a verification failure can't pin a signer's
    /// slot in-flight and block their later honest vote — and on
    /// success pools the vote in the [`RatifyTracker`].
    pub fn on_ratify_vote_verified(
        &mut self,
        fold: &BeaconFold,
        key: RatifyVoteSlotKey,
        result: Result<Verified<RatifyVote>, RatifyVoteVerifyError>,
    ) -> ParticipantStep {
        let vote = match result {
            Ok(v) => v,
            Err(err) => {
                self.verification.forget_ratify_vote(key);
                warn!(%err, "RatifyVote signature verification failed — dropping");
                return ParticipantStep::default();
            }
        };
        self.verification.forget_ratify_vote(key);
        self.admit_verified_ratify_vote(fold, vote)
    }

    /// A [`RatifyVote`] has passed signature verification: pool it and lift
    /// whatever it completes — a polka into the local precommit, a
    /// precommit quorum into the epoch's commit certificate.
    fn admit_verified_ratify_vote(
        &mut self,
        fold: &BeaconFold,
        vote: Verified<RatifyVote>,
    ) -> ParticipantStep {
        // Tip may have advanced since dispatch; re-check the anchor +
        // epoch before admission so a stale verified vote can't pool
        // against the wrong instance.
        if vote.anchor_hash() != fold.latest_block.block_hash()
            || vote.epoch() != fold.state.current_epoch.next()
        {
            trace!(
                signer = ?vote.signer(),
                "Verified RatifyVote no longer matches tip — dropping",
            );
            return ParticipantStep::default();
        }
        let observed = self.ratify.observe(vote);
        let mut actions = self.lift_ratify_effects(fold, observed.effects);
        let certified = observed
            .cert
            .and_then(|cert| self.commit_ratified_block(*cert));
        if let Some(block) = &certified {
            actions.push(Action::BroadcastBeaconBlock {
                block: block.clone(),
            });
        }
        actions.extend(self.ask_for_prevoted_candidates(fold));
        ParticipantStep { actions, certified }
    }

    /// Ask for every candidate the pool prevoted that this member does
    /// not hold, once each. Without the candidate a member can prevote
    /// only the skip hash, and members locked on either value never
    /// leave it for the other without a newer polka: a pool split
    /// between members that hold the candidate and members that missed
    /// it on gossip never reaches a quorum. The ask goes to a member
    /// that prevoted it — before any polka an honest prevoter verified
    /// the candidate, so it holds a copy — over that member's shard; the
    /// answer enters as a gossiped candidate does. Once a polka forms
    /// the tracker follows it without the block.
    fn ask_for_prevoted_candidates(&mut self, fold: &BeaconFold) -> Vec<Action> {
        if self.ratify.is_completed()
            || self.ratify.candidate().is_some()
            || self.pending_candidate.is_some()
        {
            return Vec::new();
        }
        let epoch = fold.state.current_epoch.next();
        let mut actions = Vec::new();
        for (block_hash, voters) in self.ratify.unheld_prevoted_candidates() {
            if self.candidate_asks.contains(&(epoch, block_hash)) {
                continue;
            }
            let Some((voter, shard)) =
                voters
                    .iter()
                    .find_map(|voter| match fold.state.validators.get(voter)?.status {
                        ValidatorStatus::OnShard { shard, .. } => Some((*voter, shard)),
                        _ => None,
                    })
            else {
                continue;
            };
            self.candidate_asks.insert((epoch, block_hash));
            actions.push(Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::Beacon(BeaconFetchIds::Candidates(vec![(epoch, block_hash)])),
                shard,
                preferred: Some(voter),
                class: None,
            }));
        }
        actions
    }

    /// The pending epoch is settled: ratification restarts for the
    /// next one at the new tip, over the post-fold pool.
    fn restart_ratification(&mut self, fold: &BeaconFold) {
        self.ratify = RatifyTracker::new(
            Arc::clone(&fold.verifier),
            fold.latest_block.block_hash(),
            fold.state.current_epoch.next(),
            fold.state.derive_active_pool(),
        );
        self.pending_candidate = None;
    }

    /// Drop locally buffered evidence the fold has consumed. Equivocations
    /// for a validator whose key is already revoked are dead weight — no
    /// further punishment exists. A fork proof the fold has registered —
    /// as the durable flag or a stamped fork-caused recovery — has done
    /// its job: the beacon's own state retries the re-draw from there, so
    /// re-proposing the proof only wastes proposal space. A fork proof
    /// against a shard the lookahead does not seat registers at no fold
    /// and is inadmissible in a proposal, so it is dropped too. Anything
    /// else still in flight rode a proposal this fold discarded (a Skip epoch
    /// drops every member's drained copy at once); restore it for the
    /// next build.
    ///
    /// All three buffers, because a drain is not a delivery for any of
    /// them: evidence taken for a proposal that never folds and not
    /// restored is gone from this node for good.
    pub(crate) fn prune_folded_evidence(&mut self, fold: &BeaconFold) {
        let validators = &fold.state.validators;
        self.equivocations.prune(|v| {
            matches!(
                validators.get(&v).map(|r| r.status),
                Some(ValidatorStatus::Revoked { .. })
            )
        });
        self.vote_equivocations_observed.prune(|v| {
            matches!(
                validators.get(&v).map(|r| r.status),
                Some(ValidatorStatus::Revoked { .. })
            )
        });
        let pending = &fold.state.pending_recoveries;
        let flagged = &fold.state.fork_flagged;
        let seated = &fold.state.next_shard_committees;
        self.fork_proofs.prune(|shard| {
            flagged.contains_key(&shard)
                || !seated.contains_key(&shard)
                || pending
                    .get(&shard)
                    .is_some_and(|r| r.cause == RecoveryCause::Fork)
        });
        self.equivocations.restore_undelivered();
        self.vote_equivocations_observed.restore_undelivered();
        self.fork_proofs.restore_undelivered();
    }

    /// The fold adopted a block: settle the epoch it decided and open the
    /// next one. Resets the per-epoch caches, restarts ratification at the
    /// new tip, releases the fetches the settled epoch no longer reads,
    /// reports the local validator's placement delta, and bootstraps the
    /// next epoch's SPC when the local validator sits on the new
    /// committee.
    pub fn on_adopted(&mut self, fold: &BeaconFold, effects: &SlotEffects) -> Vec<Action> {
        self.spc.clear();
        let abandoned_candidates: Vec<(Epoch, BeaconBlockHash)> =
            std::mem::take(&mut self.candidate_asks)
                .into_iter()
                .collect();
        self.restart_ratification(fold);
        self.prune_folded_evidence(fold);
        let released_dwell_fetches = self.release_dwell_fetches();
        self.reset_proposal_admission(fold);

        let mut actions = vec![
            // Re-arm the skip-trigger timer against the new tip. Fires
            // `skip_timeout` after the upcoming epoch's boundary if no
            // commit lands by then.
            Action::SetTimer {
                id: TimerId::BeaconRatifyTrigger,
                duration: fold.duration_until_next_ratify_fire(),
            },
        ];

        // A lookahead placement delta for the local validator means the
        // host must reconfigure physical participation before the next
        // window opens: bootstrap of a joined shard needs the lookahead
        // epoch (snap-sync + tail sync), and a left shard's drain is
        // scheduled from the window close. The delta exists at exactly
        // one commit — the next `apply_epoch` promotes the lookahead
        // into the active window and the two views agree again. The
        // driver runs this after the fold's `TopologyChanged`, so the
        // consumer reads a snapshot (and snap-sync anchor) that already
        // reflects this commit.
        if let Some(change) = self.participation_delta(fold, effects) {
            actions.push(Action::ReconfigureParticipation(change));
        }

        let abandoned_proposals = self.commit_assembly.prune_stale(fold.state.current_epoch);
        if !abandoned_proposals.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::Beacon(
                BeaconFetchIds::Proposals(abandoned_proposals),
            )));
        }
        actions.extend(released_dwell_fetches);
        if !abandoned_candidates.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::Beacon(
                BeaconFetchIds::Candidates(abandoned_candidates),
            )));
        }

        // Self-perpetuate the next epoch's SPC, but only once wall-clock has
        // reached its boundary. While the beacon is behind real time (catch-up
        // after a gap, or `now` already past the boundary) this fires straight
        // away and the chain cascades to catch up; once the synthetic epoch
        // clock reaches wall-clock it instead arms `BeaconCommitteeStart` for
        // the boundary, so the beacon paces to real time rather than racing
        // ahead at SPC-round speed.
        if self.is_on_committee(fold) {
            if fold.committee_start_due(fold.next_epoch_boundary()) {
                actions.extend(self.bootstrap_spc_for_next_epoch(fold));
                actions.extend(self.try_propose(fold));
            } else {
                actions.push(Action::SetTimer {
                    id: TimerId::BeaconCommitteeStart,
                    duration: fold.duration_until_next_epoch_boundary(),
                });
            }
        }

        actions.extend(self.replay_early_candidates(fold));

        actions
    }

    /// Re-admit the candidates held ahead of the tip. One for the epoch
    /// the new tip makes pending is admitted, or dropped if it extends a
    /// different block than the one adopted; one still further ahead is
    /// held again.
    fn replay_early_candidates(&mut self, fold: &BeaconFold) -> Vec<Action> {
        std::mem::take(&mut self.early_candidates)
            .into_values()
            .flat_map(|candidate| self.on_beacon_candidate_received(fold, candidate))
            .collect()
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
    pub(crate) fn participation_delta(
        &self,
        fold: &BeaconFold,
        effects: &SlotEffects,
    ) -> Option<ParticipationChange> {
        let me = self.me;
        let placement =
            |committees: &BTreeMap<ShardId, ShardCommittee>| self.placement(fold, committees);
        let drawn = effects.observers_drawn.iter().find(|s| s.validator == me);
        let released = effects
            .observers_released
            .iter()
            .find(|s| s.validator == me);
        let current = placement(&fold.state.shard_committees)
            .filter(|shard| released.is_none_or(|seat| seat.shard != *shard));
        let next = placement(&fold.state.next_shard_committees);
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
            effective_epoch: fold.state.current_epoch.next(),
        })
    }

    /// The shard `committees` seat this participant on as a member, unless
    /// that seat is the one it observes.
    fn placement(
        &self,
        fold: &BeaconFold,
        committees: &BTreeMap<ShardId, ShardCommittee>,
    ) -> Option<ShardId> {
        let me = self.me;
        committees
            .iter()
            .find(|(_, committee)| committee.members.contains(&me))
            .map(|(shard, _)| *shard)
            .filter(|shard| {
                !matches!(
                    fold.state.validators.get(&me).map(|r| r.status),
                    Some(ValidatorStatus::Observing { shard: s, .. }) if s == *shard
                )
            })
    }

    /// SPC has decided this epoch. When every committed-vector
    /// element resolves to a pooled proposal, assemble the block
    /// directly. Otherwise stash the cert + output keyed by `epoch`
    /// and emit one fetch per missing element via
    /// [`Self::fetch_missing_proposals`]; assembly resumes from
    /// [`Self::on_beacon_proposal_fetched`] once every awaited fetch
    /// lands. Concurrent stashes for different epochs are allowed —
    /// stale entries get evicted on adoption once
    /// `current_epoch` advances past them.
    pub(crate) fn on_spc_output_high(
        &mut self,
        fold: &BeaconFold,
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
            &fold.state.committee,
        ) {
            AssemblyDecision::Assemble {
                committed, cert, ..
            } => self.assemble_and_broadcast_candidate(fold, epoch, committed, *cert),
            AssemblyDecision::AwaitFetch { missing, .. } => {
                Self::fetch_missing_proposals(fold, epoch, &missing)
            }
            AssemblyDecision::Idle => Vec::new(),
        }
    }

    /// Emit one [`FetchRequest::Ask`] of beacon proposals per missing committed
    /// proposal, routed to the shard `fold` places its author on. Each ask
    /// prefers the author: it caches what it signs before gossiping it,
    /// so an honest author holds the proposal whoever else missed it. The
    /// author is only the first ask: a failed answer drops the
    /// preference, so an author that answers some members "not held"
    /// cannot keep them from the peers its gossip did reach. An author on
    /// no shard names the root, and the asker's driver picks a live
    /// committee for it.
    fn fetch_missing_proposals(
        fold: &BeaconFold,
        epoch: Epoch,
        missing: &[ValidatorId],
    ) -> Vec<Action> {
        missing
            .iter()
            .map(|&validator| {
                let shard = match fold.state.validators.get(&validator).map(|v| v.status) {
                    Some(ValidatorStatus::OnShard { shard, .. }) => shard,
                    _ => ShardId::ROOT,
                };
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Beacon(BeaconFetchIds::Proposals(vec![(epoch, validator)])),
                    shard,
                    preferred: Some(validator),
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
        fold: &BeaconFold,
        epoch: Epoch,
        committed: Vec<(ValidatorId, Verified<BeaconProposal>)>,
        cert: Verified<SpcCert>,
    ) -> Vec<Action> {
        let Some(shard_contributions) =
            boundary::build_shard_contributions(&fold.state, &fold.shard_source, &committed)
        else {
            // `build_shard_contributions` names the shard and artifact it
            // waited for; this line anchors the defer to the epoch. Bounded
            // to the SPC decide plus one resume per fetched proposal.
            warn!(
                epoch = epoch.inner(),
                "deferring candidate assembly — awaiting a fully-synced peer's \
                 gossiped candidate",
            );
            return Vec::new();
        };
        let prev_block_hash = fold.latest_block.block_hash();
        let candidate = Verified::<CandidateBeaconBlock>::assemble(
            epoch,
            prev_block_hash,
            committed,
            shard_contributions,
            cert,
        );
        if self.pending_candidate.is_none() {
            self.pending_candidate = Some(candidate.clone());
        }
        let effects = self.ratify.on_candidate(candidate.block_hash());
        let mut actions = self.lift_ratify_effects(fold, effects);
        actions.push(Action::BroadcastBeaconCandidate { candidate });
        actions
    }

    /// A peer's [`CandidateBeaconBlock`] arrived via gossip. Gate the
    /// fields no signature covers ([`BeaconFold::candidate_keys`]) and
    /// dispatch SPC-cert + equivocation verification;
    /// [`Self::on_beacon_candidate_verified`] feeds the tracker when the
    /// result lands. First verified candidate wins — a second distinct
    /// candidate (an equivocating committee) is ignored, and the pool
    /// cert arbitrates. A candidate for an epoch past the pending one
    /// waits in `early_candidates` for the block it extends.
    pub fn on_beacon_candidate_received(
        &mut self,
        fold: &BeaconFold,
        candidate: Verifiable<CandidateBeaconBlock>,
    ) -> Vec<Action> {
        if candidate.epoch() > fold.state.current_epoch.next() {
            self.hold_early_candidate(candidate);
            return Vec::new();
        }
        if self.holds_a_candidate() {
            return Vec::new();
        }
        let Some(CandidateKeys {
            committee,
            equivocation_signers,
        }) = fold.candidate_keys(&candidate)
        else {
            return Vec::new();
        };
        if !self
            .verification
            .mark_candidate_in_flight(candidate.block_hash())
        {
            return Vec::new();
        }
        vec![Action::VerifyBeaconCandidate {
            candidate,
            committee,
            equivocation_signers,
        }]
    }

    /// A candidate this participant asked for, checked and verified on
    /// the host's beacon loop. It enters as a gossiped candidate's
    /// verified result does, unless one is already held.
    pub fn on_beacon_candidate_fetched(
        &mut self,
        fold: &BeaconFold,
        candidate: Verified<CandidateBeaconBlock>,
    ) -> Vec<Action> {
        if self.holds_a_candidate() {
            return Vec::new();
        }
        self.hold_verified_candidate(fold, candidate)
    }

    const fn holds_a_candidate(&self) -> bool {
        self.pending_candidate.is_some() || self.ratify.candidate().is_some()
    }

    /// Hold a candidate for an epoch past the pending one. At the cap it
    /// displaces the furthest-ahead entry when its own epoch is nearer,
    /// and is dropped otherwise.
    fn hold_early_candidate(&mut self, candidate: Verifiable<CandidateBeaconBlock>) {
        let key = (candidate.epoch(), candidate.block_hash());
        if self.early_candidates.contains_key(&key) {
            return;
        }
        if self.early_candidates.len() >= MAX_EARLY_CANDIDATES {
            let Some(&(furthest, _)) = self.early_candidates.keys().next_back() else {
                return;
            };
            if key.0 >= furthest {
                return;
            }
            self.early_candidates.pop_last();
        }
        self.early_candidates.insert(key, candidate);
    }

    /// A previously-dispatched [`Action::VerifyBeaconCandidate`] has
    /// returned. Clear `block_hash`'s pipeline slot on both arms, so a
    /// copy that failed leaves the hash open to another copy's check,
    /// and on the `Ok` arm hold the candidate for cert pairing and feed
    /// its hash to the tracker as the prevotable value.
    pub fn on_beacon_candidate_verified(
        &mut self,
        fold: &BeaconFold,
        block_hash: BeaconBlockHash,
        result: Result<Verified<CandidateBeaconBlock>, CandidateBeaconBlockVerifyError>,
    ) -> Vec<Action> {
        self.verification.forget_candidate(block_hash);
        let candidate = match result {
            Ok(c) => c,
            Err(err) => {
                warn!(%err, "BeaconCandidate verification failed — dropping");
                return Vec::new();
            }
        };
        self.hold_verified_candidate(fold, candidate)
    }

    /// Hold a verified candidate for cert pairing and feed its hash to
    /// the tracker as the prevotable value.
    fn hold_verified_candidate(
        &mut self,
        fold: &BeaconFold,
        candidate: Verified<CandidateBeaconBlock>,
    ) -> Vec<Action> {
        // Tip may have advanced since dispatch; a stale candidate no
        // longer names a prevotable value.
        if candidate.prev_block_hash() != fold.latest_block.block_hash()
            || candidate.epoch() != fold.state.current_epoch.next()
        {
            trace!(
                epoch = candidate.epoch().inner(),
                "Verified BeaconCandidate no longer extends the tip — dropping",
            );
            return Vec::new();
        }
        let block_hash = candidate.block_hash();
        if self.pending_candidate.is_none() {
            self.pending_candidate = Some(candidate);
        }
        let effects = self.ratify.on_candidate(block_hash);
        self.lift_ratify_effects(fold, effects)
    }

    /// A fetched proposal, already VRF-verified under the named
    /// validator's pubkey ([`BeaconFold::verify_fetched_proposal`]):
    /// hand it to whichever consumer asked.
    ///
    /// A proposal commit assembly awaits is admitted straight to the
    /// pool, and the stashed assembly for `epoch` resumes once every
    /// awaited fetch has resolved. That admission skips the
    /// witness-admission gate: it only ever resolves a proposal an
    /// already-committed `PcVector` element references, so the embedded
    /// witnesses are threshold-vouched (≥ f+1 honest voters verified them
    /// before the value could commit), and the committed-proposal decode
    /// pins the fetched bytes to that element by hash.
    ///
    /// A proposal the input dwell asked for is not yet vouched for by
    /// anyone, so it enters through [`Self::on_beacon_proposal_received`]
    /// exactly as a gossiped copy would.
    ///
    /// Out-of-band responses drop silently.
    pub fn on_beacon_proposal_fetched(
        &mut self,
        fold: &BeaconFold,
        epoch: Epoch,
        validator: ValidatorId,
        proposal: Verified<BeaconProposal>,
    ) -> Vec<Action> {
        if !self.commit_assembly.is_awaiting(epoch, validator) {
            if epoch != self.proposal_pool.epoch() || !self.dwell_fetches.remove(&validator) {
                return Vec::new();
            }
            return self
                .on_beacon_proposal_received(fold, validator, epoch, proposal)
                .1;
        }
        let _ = self.proposal_pool.admit(validator, epoch, proposal);
        match self.commit_assembly.on_proposal_resolved(
            epoch,
            validator,
            &self.proposal_pool,
            &fold.state.committee,
        ) {
            AssemblyDecision::Assemble {
                committed, cert, ..
            } => self.assemble_and_broadcast_candidate(fold, epoch, committed, *cert),
            AssemblyDecision::AwaitFetch { .. } | AssemblyDecision::Idle => Vec::new(),
        }
    }

    /// Feed this participant one beacon consensus event: a peer's message,
    /// the outcome of a check it dispatched, or one of its timers. Every
    /// other event is dropped with a warning.
    pub fn on_event(&mut self, fold: &BeaconFold, event: ProtocolEvent) -> ParticipantStep {
        match event {
            ProtocolEvent::UnverifiedRatifyVoteReceived { vote } => {
                self.on_unverified_ratify_vote_received(fold, vote).into()
            }
            ProtocolEvent::VerifiedRatifyVoteReceived { vote } => {
                self.on_verified_ratify_vote_received(fold, vote)
            }
            ProtocolEvent::BeaconProposalReceived {
                from,
                epoch,
                proposal,
            } => self
                .on_beacon_proposal_received(fold, from, epoch, proposal)
                .1
                .into(),
            ProtocolEvent::BeaconCandidateReceived { candidate } => {
                self.on_beacon_candidate_received(fold, candidate).into()
            }
            ProtocolEvent::BeaconCandidateVerified { block_hash, result } => self
                .on_beacon_candidate_verified(fold, block_hash, result)
                .into(),
            ProtocolEvent::RatifyVoteVerified {
                anchor,
                epoch,
                round,
                phase,
                signer,
                result,
            } => {
                let key = (anchor, epoch, round, phase, signer);
                self.on_ratify_vote_verified(fold, key, result)
            }
            ProtocolEvent::BeaconCommitteeStartTimer => {
                self.on_beacon_committee_start_timer(fold).into()
            }
            ProtocolEvent::BeaconRatifyTimer => self.on_beacon_ratify_timer(fold).into(),
            ProtocolEvent::BeaconSpcViewTimer => self.on_beacon_spc_view_timer(fold).into(),
            ProtocolEvent::BeaconSpcInputDwellTimer => self.on_spc_input_dwell_timer(fold).into(),
            other => self.on_spc_event(fold, other),
        }
    }

    /// The SPC plane's share of [`Self::on_event`]: PC votes and SPC
    /// messages as they arrive, and the checks they dispatched.
    fn on_spc_event(&mut self, fold: &BeaconFold, event: ProtocolEvent) -> ParticipantStep {
        match event {
            ProtocolEvent::UnverifiedPcVote1Received { epoch, view, vote } => {
                self.on_pc_vote1_received(epoch, view, vote).into()
            }
            ProtocolEvent::UnverifiedPcVote2Received { epoch, view, vote } => {
                self.on_pc_vote2_received(epoch, view, vote).into()
            }
            ProtocolEvent::UnverifiedPcVote3Received { epoch, view, vote } => {
                self.on_pc_vote3_received(epoch, view, vote).into()
            }
            ProtocolEvent::VerifiedPcVote1Received { epoch, view, vote } => self
                .on_verified_pc_vote1_received(fold, epoch, view, vote)
                .into(),
            ProtocolEvent::VerifiedPcVote2Received { epoch, view, vote } => self
                .on_verified_pc_vote2_received(fold, epoch, view, vote)
                .into(),
            ProtocolEvent::VerifiedPcVote3Received { epoch, view, vote } => self
                .on_verified_pc_vote3_received(fold, epoch, view, vote)
                .into(),
            ProtocolEvent::SpcNewViewReceived {
                epoch,
                from,
                proposal,
            } => self.on_spc_new_view_received(epoch, from, proposal).into(),
            ProtocolEvent::SpcNewCommitReceived { epoch, from, msg } => {
                self.on_spc_new_commit_received(epoch, from, msg).into()
            }
            ProtocolEvent::UnverifiedSpcEmptyViewReceived { epoch, msg } => self
                .on_unverified_spc_empty_view_received(epoch, msg)
                .into(),
            ProtocolEvent::VerifiedSpcEmptyViewReceived { epoch, msg } => self
                .on_verified_spc_empty_view_received(fold, epoch, msg)
                .into(),
            ProtocolEvent::PcVote1Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .on_pc_vote1_verified(fold, epoch, view, signer, result)
                .into(),
            ProtocolEvent::PcVote2Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .on_pc_vote2_verified(fold, epoch, view, signer, result)
                .into(),
            ProtocolEvent::PcVote3Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .on_pc_vote3_verified(fold, epoch, view, signer, result)
                .into(),
            ProtocolEvent::SpcNewViewVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .on_spc_new_view_verified(fold, epoch, from, view, result)
                .into(),
            ProtocolEvent::SpcNewCommitVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .on_spc_new_commit_verified(fold, epoch, from, view, result)
                .into(),
            ProtocolEvent::SpcEmptyViewVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .on_spc_empty_view_verified(fold, epoch, from, view, result)
                .into(),
            other => {
                warn!(
                    event = other.type_name(),
                    "event no participant handles — dropping"
                );
                ParticipantStep::default()
            }
        }
    }

    /// This participant's proposal pool — lets tests and sims run
    /// lookups without going through the network path.
    #[must_use]
    pub const fn proposal_pool(&self) -> &BeaconProposalPool {
        &self.proposal_pool
    }

    /// Beacon-committee members excluding the local validator —
    /// recipient list for outbound SPC traffic.
    pub(crate) fn spc_recipients(&self, fold: &BeaconFold) -> Vec<ValidatorId> {
        fold.state
            .committee
            .iter()
            .filter(|v| **v != self.me)
            .copied()
            .collect()
    }

    /// Lift effects produced by the [`SpcDriver`] into actions. Captures
    /// `epoch` + `recipients` before lifting because the `OutputHigh`
    /// arm's adoption clears the instance. A no-op for empty effects.
    fn lift_from_spc(&mut self, fold: &BeaconFold, effects: Vec<SpcEffect>) -> Vec<Action> {
        if effects.is_empty() {
            return Vec::new();
        }
        let Some(epoch) = self.spc.epoch() else {
            return Vec::new();
        };
        let recipients = self.spc_recipients(fold);
        self.lift_spc_effects(fold, epoch, &recipients, effects)
    }

    /// Translate the sub-machine's local effect enum into beacon
    /// actions plus internal state mutations (equivocation pool,
    /// commit assembly).
    fn lift_spc_effects(
        &mut self,
        fold: &BeaconFold,
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
                    actions.extend(self.on_spc_output_high(fold, epoch, &value, *cert, recipients));
                }
            }
        }
        actions
    }
}
