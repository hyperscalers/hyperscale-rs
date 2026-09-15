//! SPC consensus-plane driver.
//!
//! [`SpcDriver`] wraps the per-epoch [`SpcInstance`] and the in-flight
//! verification slots for the consensus messages that feed it — PC votes
//! and SPC `new-view` / `new-commit` / `empty-view` messages. It owns the
//! ingress gating (admission window + committee membership + skip-quorum),
//! the async-verify slot dedup, and the dispatch of verified events into
//! the FSM.
//!
//! It does **not** lift effects to actions or touch sibling sub-machines:
//! ingress methods return mature [`Action`]s (the verify dispatch);
//! instance-driving methods return [`SpcEffect`]s for the coordinator to
//! lift (the coordinator stamps `epoch`/`recipients` and routes the
//! decided output into commit assembly + the equivocation pool). The
//! skip-quorum verdict is computed by the coordinator and passed in — the
//! driver never reads the skip tracker or chain state.

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    ConsensusPublicKey, Epoch, MIN_BEACON_COMMITTEE_SIZE, PcQc3, PcVector, PcVote1,
    PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3, PcVote3VerifyError, PcVoteRound,
    SPC_VIEW_TIMEOUT, SpcCert, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError, SpcNewCommitMsg,
    SpcNewCommitMsgVerifyError, SpcProposalObject, SpcProposalObjectVerifyError, SpcView,
    ValidatorId, Verifiable, Verified, Verifier,
};
use tracing::{trace, warn};

use crate::spc::{MAX_PENDING_EMPTY_VIEW_AHEAD, SpcEffect, SpcEvent, SpcInstance};
use crate::verification::VerificationSlots;

/// Slot key for a pending PC-vote verification.
///
/// Per-`(epoch, view, signer, round)` because a Byzantine signer may
/// dispatch divergent votes at the same round within a view; each gets
/// its own slot so the post-verify equivocation check sees both.
pub(crate) type PcVoteSlotKey = (Epoch, SpcView, ValidatorId, PcVoteRound);

/// Which SPC message kind a verification slot refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SpcMsgKind {
    /// `NewView` cert verification.
    NewView,
    /// `NewCommit` embedded QC3 verification.
    NewCommit,
    /// `EmptyView` sig + embedded QC3 verification.
    EmptyView,
}

/// Slot key for a pending SPC message verification.
pub(crate) type SpcMsgSlotKey = (Epoch, SpcView, ValidatorId, SpcMsgKind);

/// Per-vnode SPC driver: the optional current-epoch [`SpcInstance`] plus
/// the PC-vote and SPC-message verification slot pools.
pub(crate) struct SpcDriver {
    /// Scheme verifier handed to each bootstrapped [`SpcInstance`].
    verifier: Arc<dyn Verifier>,
    /// `None` between bootstrap and the first epoch-boundary trigger, and
    /// again briefly between an epoch's commit and the next bootstrap.
    spc: Option<SpcInstance>,
    pc_votes: VerificationSlots<PcVoteSlotKey>,
    spc_msgs: VerificationSlots<SpcMsgSlotKey>,
    me: ValidatorId,
}

impl SpcDriver {
    /// A driver with no instance bootstrapped.
    #[must_use]
    pub(crate) fn new(verifier: Arc<dyn Verifier>, me: ValidatorId) -> Self {
        Self {
            verifier,
            spc: None,
            pc_votes: VerificationSlots::default(),
            spc_msgs: VerificationSlots::default(),
            me,
        }
    }

    /// Whether an SPC instance is currently bootstrapped.
    #[must_use]
    pub(crate) const fn is_bootstrapped(&self) -> bool {
        self.spc.is_some()
    }

    /// The current instance's epoch, or `None` when not bootstrapped.
    #[must_use]
    pub(crate) fn epoch(&self) -> Option<Epoch> {
        self.spc.as_ref().map(SpcInstance::epoch)
    }

    /// The current instance's view, or `None` when not bootstrapped.
    #[must_use]
    pub(crate) fn current_view(&self) -> Option<SpcView> {
        self.spc.as_ref().map(SpcInstance::current_view)
    }

    /// Whether the current instance has been fed its view-1 input.
    #[must_use]
    pub(crate) fn view_one_input_fed(&self) -> bool {
        self.spc
            .as_ref()
            .is_some_and(SpcInstance::view_one_input_fed)
    }

    /// Count of dispatched-but-unresolved PC-vote + SPC-message
    /// verifications.
    #[must_use]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.pc_votes.len() + self.spc_msgs.len()
    }

    /// Tear down the instance after a commit. The slot pools are left
    /// intact — stale results clear their own slots on arrival.
    pub(crate) fn clear(&mut self) {
        self.spc = None;
    }

    /// Stand up the per-epoch [`SpcInstance`] from an explicit committee.
    ///
    /// Declines (leaves the instance cleared) when `committee.len() <
    /// MIN_BEACON_COMMITTEE_SIZE`: a committee that can't tolerate a single
    /// Byzantine fault must not run PC. Rather than panic in
    /// [`PcInstance::new`](crate::pc), the driver skips the bootstrap and
    /// lets the skip path carry the epoch — the ready on-shard set has
    /// collapsed below the BFT floor, an operator-visible degradation the
    /// chain recovers from once enough validators ready up.
    pub(crate) fn bootstrap(
        &mut self,
        next_epoch: Epoch,
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    ) {
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
            Arc::clone(&self.verifier),
            next_epoch,
            committee,
            self.me,
            SPC_VIEW_TIMEOUT,
        ));
    }

    /// Whether the current instance is ready to receive its view-1
    /// `Input`: instance exists, drives `epoch`, and hasn't been fed.
    #[must_use]
    pub(crate) fn should_feed_view_one_input(&self, epoch: Epoch) -> bool {
        self.spc
            .as_ref()
            .is_some_and(|spc| spc.epoch() == epoch && !spc.view_one_input_fed())
    }

    /// Feed view 1's local input vector into the instance. Caller gates on
    /// [`Self::should_feed_view_one_input`]. Not skip-quorum gated — the
    /// input is the local node's entry into the round, independent of
    /// the skip path.
    pub(crate) fn feed_view_one_input(&mut self, input: PcVector) -> Vec<SpcEffect> {
        let Some(spc) = self.spc.as_mut() else {
            return Vec::new();
        };
        spc.handle(SpcEvent::Input(input))
    }

    /// A peer's round-1 PC vote arrived. Gate on instance/skip-quorum,
    /// mark the slot in-flight, and dispatch the signature check. Admission
    /// happens in [`Self::on_pc_vote1_verified`] when the result lands.
    pub(crate) fn on_pc_vote1_received(
        &mut self,
        view: SpcView,
        vote: PcVote1,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.admission_ctx(validator, view, "PcVote", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .pc_votes
            .mark_in_flight((epoch, view, validator, PcVoteRound::Vote1))
        {
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
    pub(crate) fn on_pc_vote2_received(
        &mut self,
        view: SpcView,
        vote: Box<PcVote2>,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.admission_ctx(validator, view, "PcVote", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .pc_votes
            .mark_in_flight((epoch, view, validator, PcVoteRound::Vote2))
        {
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
    pub(crate) fn on_pc_vote3_received(
        &mut self,
        view: SpcView,
        vote: Box<PcVote3>,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let validator = vote.validator();
        let Some((epoch, committee)) = self.admission_ctx(validator, view, "PcVote", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .pc_votes
            .mark_in_flight((epoch, view, validator, PcVoteRound::Vote3))
        {
            return Vec::new();
        }
        vec![Action::VerifyPcVote3 {
            epoch,
            view,
            vote: Box::new(Verifiable::from(*vote)),
            committee,
        }]
    }

    /// A peer's SPC `new-view` arrived. Gate, mark the slot in-flight, and
    /// dispatch the cert signature check.
    pub(crate) fn on_spc_new_view_received(
        &mut self,
        from: ValidatorId,
        proposal: Arc<Verifiable<SpcProposalObject>>,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let view = proposal.view;
        let Some((epoch, committee)) = self.admission_ctx(from, view, "NewView", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .spc_msgs
            .mark_in_flight((epoch, view, from, SpcMsgKind::NewView))
        {
            return Vec::new();
        }
        vec![Action::VerifySpcNewView {
            epoch,
            from,
            proposal: Box::new(Arc::unwrap_or_clone(proposal)),
            committee,
        }]
    }

    /// A peer's SPC `new-commit` arrived. Gate, mark the slot in-flight,
    /// and dispatch the embedded QC3's signature check.
    pub(crate) fn on_spc_new_commit_received(
        &mut self,
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let view = msg.view;
        let Some((epoch, committee)) = self.admission_ctx(from, view, "NewCommit", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .spc_msgs
            .mark_in_flight((epoch, view, from, SpcMsgKind::NewCommit))
        {
            return Vec::new();
        }
        vec![Action::VerifySpcNewCommit {
            epoch,
            from,
            msg: Box::new(Arc::unwrap_or_clone(msg)),
            committee,
        }]
    }

    /// A peer's SPC `empty-view` attestation arrived. Gate, mark the slot
    /// in-flight (keyed by the embedded signer), and dispatch the
    /// check.
    pub(crate) fn on_unverified_spc_empty_view_received(
        &mut self,
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
        skip_quorum: bool,
    ) -> Vec<Action> {
        let signer = msg.signer;
        let view = msg.view;
        let Some((epoch, committee)) = self.admission_ctx(signer, view, "EmptyView", skip_quorum)
        else {
            return Vec::new();
        };
        if !self
            .spc_msgs
            .mark_in_flight((epoch, view, signer, SpcMsgKind::EmptyView))
        {
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
    /// signing-key holder produced the signature over a verified high
    /// triple, so the message is verified by construction — feed it
    /// directly into the FSM without the verify round-trip.
    pub(crate) fn on_verified_spc_empty_view_received(
        &mut self,
        msg: Box<Verified<SpcEmptyViewMsg>>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let signer = msg.signer;
        if self
            .admission_ctx(signer, msg.view, "VerifiedEmptyView", skip_quorum)
            .is_none()
        {
            return Vec::new();
        }
        self.dispatch(signer, SpcEvent::EmptyViewVerified(msg), skip_quorum)
    }

    /// Result of an [`Action::VerifySpcNewView`] dispatch. The view rode
    /// back from the unverified payload so the slot clears on both arms.
    pub(crate) fn on_spc_new_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let key = (epoch, view, from, SpcMsgKind::NewView);
        let proposal = match result {
            Ok(p) => p,
            Err(err) => {
                self.spc_msgs.clear(&key);
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
        self.spc_msgs.clear(&key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        let cert = Verified::<SpcCert>::from_verified_proposal_object(proposal);
        self.dispatch(
            from,
            SpcEvent::NewViewVerified {
                from,
                view,
                cert: Box::new(cert),
            },
            skip_quorum,
        )
    }

    /// Result of an [`Action::VerifySpcNewCommit`] dispatch.
    pub(crate) fn on_spc_new_commit_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let key = (epoch, view, from, SpcMsgKind::NewCommit);
        let msg = match result {
            Ok(m) => m,
            Err(err) => {
                self.spc_msgs.clear(&key);
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
        self.spc_msgs.clear(&key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        let value = msg.value.clone();
        let proof = Verified::<PcQc3>::from_verified_new_commit(msg);
        self.dispatch(
            from,
            SpcEvent::NewCommitVerified {
                view,
                value,
                proof: Box::new(proof),
            },
            skip_quorum,
        )
    }

    /// Result of an [`Action::VerifySpcEmptyView`] dispatch.
    pub(crate) fn on_spc_empty_view_verified(
        &mut self,
        epoch: Epoch,
        from: ValidatorId,
        view: SpcView,
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let key = (epoch, view, from, SpcMsgKind::EmptyView);
        let msg = match result {
            Ok(m) => m,
            Err(err) => {
                self.spc_msgs.clear(&key);
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
        self.spc_msgs.clear(&key);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            from,
            SpcEvent::EmptyViewVerified(Box::new(msg)),
            skip_quorum,
        )
    }

    /// Result of an [`Action::VerifyPcVote1`] dispatch. Clears the slot,
    /// routes the verified vote into the FSM, drops on verify failure.
    pub(crate) fn on_pc_vote1_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote1);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-1 signature verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote1);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote1Verified {
                view,
                vote: verified,
            },
            skip_quorum,
        )
    }

    /// Result of an [`Action::VerifyPcVote2`] dispatch.
    pub(crate) fn on_pc_vote2_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote2);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-2 signature verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote2);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote2Verified {
                view,
                vote: Box::new(verified),
            },
            skip_quorum,
        )
    }

    /// Result of an [`Action::VerifyPcVote3`] dispatch.
    pub(crate) fn on_pc_vote3_verified(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let verified = match result {
            Ok(v) => v,
            Err(err) => {
                self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote3);
                warn!(
                    epoch = epoch.inner(),
                    view = view.inner(),
                    ?signer,
                    ?err,
                    "PC vote-3 signature verification failed — dropping",
                );
                return Vec::new();
            }
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote3);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote3Verified {
                view,
                vote: Box::new(verified),
            },
            skip_quorum,
        )
    }

    /// A round-1 PC vote the coordinator received already verified — fed
    /// in via the local sign-and-emit path. Skips the verify dispatch and
    /// routes straight into the FSM.
    pub(crate) fn on_verified_pc_vote1_received(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote1>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.admission_ctx(signer, view, "PcVote", skip_quorum) else {
            return Vec::new();
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote1);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote1Verified { view, vote },
            skip_quorum,
        )
    }

    /// A round-2 PC vote the coordinator received already verified.
    pub(crate) fn on_verified_pc_vote2_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote2>>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.admission_ctx(signer, view, "PcVote", skip_quorum) else {
            return Vec::new();
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote2);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote2Verified { view, vote },
            skip_quorum,
        )
    }

    /// A round-3 PC vote the coordinator received already verified.
    pub(crate) fn on_verified_pc_vote3_received(
        &mut self,
        view: SpcView,
        vote: Box<Verified<PcVote3>>,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let signer = vote.validator();
        let Some((epoch, _)) = self.admission_ctx(signer, view, "PcVote", skip_quorum) else {
            return Vec::new();
        };
        self.clear_pc_vote(epoch, view, signer, PcVoteRound::Vote3);
        if self.spc.as_ref().is_some_and(|s| s.epoch() != epoch) {
            return Vec::new();
        }
        self.dispatch(
            self.me,
            SpcEvent::PcVote3Verified { view, vote },
            skip_quorum,
        )
    }

    /// `TimerId::BeaconSpcView` fired. Route a synthesized `TimerExpired`
    /// into the FSM against its current view — the stale-view guard no-ops
    /// if the view has already advanced.
    pub(crate) fn on_beacon_spc_view_timer(&mut self, skip_quorum: bool) -> Vec<SpcEffect> {
        let Some(spc) = self.spc.as_ref() else {
            trace!("BeaconSpcViewTimer fired but no SPC instance bootstrapped");
            return Vec::new();
        };
        let view = spc.current_view();
        self.dispatch(self.me, SpcEvent::TimerExpired { view }, skip_quorum)
    }

    /// Common gating for the receive entries: returns `(epoch, committee)`
    /// if admissible, else logs and returns `None`. Four gates, all cheap
    /// and applied before the verify dispatch so a flood can't mint slots:
    ///
    /// 1. The local SPC instance is bootstrapped.
    /// 2. Skip-quorum hasn't been reached at the local tip (`skip_quorum`).
    /// 3. `signer` (which keys the verification slot) is a current
    ///    committee member.
    /// 4. `view` is within `[current_view, current_view +
    ///    MAX_PENDING_EMPTY_VIEW_AHEAD]`.
    ///
    /// Gates 3 and 4 bound the `(signer, view)` slot key to
    /// `committee_size × window`.
    fn admission_ctx(
        &self,
        signer: ValidatorId,
        view: SpcView,
        kind: &'static str,
        skip_quorum: bool,
    ) -> Option<(Epoch, Vec<(ValidatorId, ConsensusPublicKey)>)> {
        let Some(spc) = self.spc.as_ref() else {
            trace!(
                ?signer,
                kind, "SPC message received but no SPC instance bootstrapped",
            );
            return None;
        };
        if skip_quorum {
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

    /// Drive `event` through the instance and return its effects. Drops
    /// without dispatching when not bootstrapped or when skip-quorum has
    /// been reached at the local tip — the abandoned epoch's instance
    /// can't reach `n - f` once the pool commits to skipping. Query-based,
    /// not state-based: the instance stays `Some` until ordinary teardown.
    fn dispatch(
        &mut self,
        from: ValidatorId,
        event: SpcEvent,
        skip_quorum: bool,
    ) -> Vec<SpcEffect> {
        let Some(spc) = self.spc.as_mut() else {
            trace!(?from, "SPC event received but no SPC instance bootstrapped");
            return Vec::new();
        };
        if skip_quorum {
            trace!(
                ?from,
                "SPC event received but skip-quorum reached at local tip — dropping",
            );
            return Vec::new();
        }
        spc.handle(event)
    }

    fn clear_pc_vote(
        &mut self,
        epoch: Epoch,
        view: SpcView,
        signer: ValidatorId,
        round: PcVoteRound,
    ) {
        self.pc_votes.clear(&(epoch, view, signer, round));
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_types::{
        NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcScope, PcValueElement, Signer, sign_vote1,
    };

    use super::*;

    /// Epoch the test instance is bootstrapped at; the admission gate
    /// echoes it back on every dispatched `Action`.
    const EPOCH: u64 = 7;

    /// Deterministic BLS key for validator index `i`.
    fn bls_sk(i: u64) -> BlsSigner {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        BlsSigner::from_seed(&bytes)
    }

    /// An `n`-member committee with ids `0..n` and matching deterministic
    /// keys, in the shape `bootstrap` consumes.
    fn committee(n: u64) -> Vec<(ValidatorId, ConsensusPublicKey)> {
        (0..n)
            .map(|i| (ValidatorId::new(i), bls_sk(i).public_key()))
            .collect()
    }

    /// A driver bootstrapped at [`EPOCH`] under a BFT-minimum committee,
    /// with the local validator at id 0. Its instance starts at view 1.
    fn bootstrapped() -> SpcDriver {
        let mut driver = SpcDriver::new(Arc::new(BlsVerifier), ValidatorId::new(0));
        driver.bootstrap(
            Epoch::new(EPOCH),
            committee(MIN_BEACON_COMMITTEE_SIZE as u64),
        );
        driver
    }

    /// A round-1 PC vote from validator `i` carrying `view`. Only the
    /// signer id and the passed-in view matter to the admission gate —
    /// the signature isn't checked until the async dispatch resolves.
    fn vote1(i: u64, view: u32) -> PcVote1 {
        let ctx = PcScope {
            epoch: Epoch::new(EPOCH),
            view: SpcView::new(view),
        };
        let v_in = PcVector::new((0..3).map(|b| PcValueElement::new([b; PC_VALUE_ELEMENT_BYTES])));
        sign_vote1(
            &bls_sk(i),
            ValidatorId::new(i),
            &NetworkDefinition::simulator(),
            ctx,
            v_in,
        )
        .expect("sign")
    }

    /// Assert `actions` is exactly one `VerifyPcVote1` carrying the
    /// instance epoch, the expected `view`, and the full committee.
    fn assert_dispatches(actions: &[Action], view: u32) {
        assert_eq!(actions.len(), 1, "expected exactly one verify dispatch");
        match &actions[0] {
            Action::VerifyPcVote1 {
                epoch,
                view: v,
                committee,
                ..
            } => {
                assert_eq!(epoch.inner(), EPOCH);
                assert_eq!(v.inner(), view);
                assert_eq!(committee.len(), MIN_BEACON_COMMITTEE_SIZE);
            }
            _ => panic!("expected Action::VerifyPcVote1"),
        }
    }

    #[test]
    fn admissible_pc_vote_dispatches_verification() {
        let mut driver = bootstrapped();
        let actions = driver.on_pc_vote1_received(SpcView::new(1), vote1(1, 1), false);
        assert_dispatches(&actions, 1);
    }

    #[test]
    fn pc_vote_admitted_at_window_upper_edge() {
        let mut driver = bootstrapped();
        let edge = 1 + MAX_PENDING_EMPTY_VIEW_AHEAD;
        let actions = driver.on_pc_vote1_received(SpcView::new(edge), vote1(1, edge), false);
        assert_dispatches(&actions, edge);
    }

    #[test]
    fn pc_vote_dropped_when_no_instance_bootstrapped() {
        let mut driver = SpcDriver::new(Arc::new(BlsVerifier), ValidatorId::new(0));
        let actions = driver.on_pc_vote1_received(SpcView::new(1), vote1(1, 1), false);
        assert!(actions.is_empty());
    }

    #[test]
    fn pc_vote_dropped_once_skip_quorum_reached() {
        let mut driver = bootstrapped();
        let actions = driver.on_pc_vote1_received(SpcView::new(1), vote1(1, 1), true);
        assert!(actions.is_empty());
    }

    #[test]
    fn pc_vote_from_non_committee_signer_dropped() {
        let mut driver = bootstrapped();
        // Id 99 sits outside the `0..MIN_BEACON_COMMITTEE_SIZE` committee.
        let actions = driver.on_pc_vote1_received(SpcView::new(1), vote1(99, 1), false);
        assert!(actions.is_empty());
    }

    #[test]
    fn pc_vote_below_current_view_dropped() {
        let mut driver = bootstrapped();
        assert_eq!(driver.current_view(), Some(SpcView::new(1)));
        let actions = driver.on_pc_vote1_received(SpcView::new(0), vote1(1, 0), false);
        assert!(actions.is_empty());
    }

    #[test]
    fn pc_vote_beyond_window_dropped() {
        let mut driver = bootstrapped();
        let beyond = 1 + MAX_PENDING_EMPTY_VIEW_AHEAD + 1;
        let actions = driver.on_pc_vote1_received(SpcView::new(beyond), vote1(1, beyond), false);
        assert!(actions.is_empty());
    }

    #[test]
    fn duplicate_in_flight_pc_vote_not_redispatched() {
        let mut driver = bootstrapped();
        let first = driver.on_pc_vote1_received(SpcView::new(1), vote1(1, 1), false);
        assert_eq!(first.len(), 1);
        // Same (epoch, view, signer, round) slot is still in flight.
        let second = driver.on_pc_vote1_received(SpcView::new(1), vote1(1, 1), false);
        assert!(second.is_empty());
    }
}
