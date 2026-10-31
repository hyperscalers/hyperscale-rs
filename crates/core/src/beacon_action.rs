//! What the host's beacon loop runs: its fold's and its participants'
//! actions.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    BeaconBlockHash, BeaconState, BlockHeight, CandidateBeaconBlock, CertifiedBeaconBlock,
    ConsensusPublicKey, Epoch, MessageClass, PcQc1, PcQc2, PcVector, PcVote1, PcVote2, PcVote3,
    PcVoteEquivocation, QuorumCertificate, RatifyPhase, RatifyRound, RatifyVote, ShardForkProof,
    ShardId, ShardVoteEquivocation, SpcEmptyViewMsg, SpcHighTriple, SpcNewCommitMsg,
    SpcProposalObject, SpcView, TopologySchedule, ValidatorId, Verifiable, Verified,
};

use crate::{BeaconFetchIds, ParticipationChange, TimerId};

/// An action the beacon fold or one of the host's beacon participants
/// emits, for the beacon loop that drives them.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum BeaconAction {
    /// A participant's delegated work, run on the consensus dispatch
    /// pool under that participant's signer and release gate.
    Participant(ParticipantAction),

    /// The fold's check of a beacon block's certificates. Result returns
    /// via [`crate::ProtocolEvent::BeaconBlockVerified`].
    VerifyBeaconBlock(BeaconBlockCheck),

    /// Persist a committed beacon block + its resulting `BeaconState`
    /// to `BeaconStorage`. Both writes go in one atomic batch.
    CommitBeaconBlock {
        /// Certified committed block.
        block: Verified<CertifiedBeaconBlock>,
        /// State the block advances to. Boxed to bound enum size.
        state: Box<BeaconState>,
    },

    /// Propagate the folded topology to every loop on the host and the
    /// network layer.
    ///
    /// Emitted by the fold on every beacon commit. The host publishes the
    /// schedule's head as its shared topology snapshot, keys fetch
    /// routing on the schedule's terminal-clamped committees, and hands
    /// the schedule to each shard loop.
    TopologyChanged {
        /// Beacon epoch the schedule was folded at. The host's one fold
        /// emits it once per adopted block, so the epochs published only
        /// rise.
        epoch: Epoch,
        /// The beacon's window schedule as of this fold: the head, the
        /// retained windows and the lookahead, one clone per epoch.
        schedule: Arc<TopologySchedule>,
    },

    /// The lookahead committees move a local validator onto or off
    /// a shard at the next window — surface the delta to the runner so
    /// it can reconfigure physical participation (open storage and
    /// bootstrap a joined shard, schedule a left shard's drain).
    ReconfigureParticipation(ParticipationChange),

    /// Request the runner to start (or raise the target of) beacon-chain
    /// gap-fill sync.
    ///
    /// Emitted when a committed beacon block is observed more than one
    /// epoch ahead of the fold's tip. The beacon loop's `Sync` machine
    /// fetches the missing blocks epoch by epoch and feeds each back as
    /// `ProtocolEvent::BeaconBlockSyncReadyToApply`.
    StartBeaconBlockSync {
        /// The epoch to sync the beacon chain up to.
        target: Epoch,
    },

    /// Set a timer to fire after a duration, owned by the emitter.
    SetTimer {
        /// Timer slot to set; replaces any previous timer with the same id.
        id: TimerId,
        /// How long until the timer fires.
        duration: Duration,
    },

    /// Cancel a previously set timer.
    CancelTimer {
        /// Timer slot to cancel.
        id: TimerId,
    },

    /// Ask `shard`'s committee for `ids` on the emitter's behalf.
    Fetch {
        /// What to fetch.
        ids: BeaconFetchIds,
        /// Committee whose members serve the request.
        shard: ShardId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Overrides the wire type's static class; `None` keeps it.
        class: Option<MessageClass>,
    },

    /// The emitter no longer wants `ids`. An id another owner on the
    /// loop still asks for stays in flight.
    AbandonFetch(BeaconFetchIds),

    /// Ask `source_shard` to prove the block it committed at
    /// `block_height`. The beacon loop routes the ask to a shard loop on
    /// the host that follows `source_shard`'s headers.
    AskCommitProof {
        /// Shard whose commit is to be proved.
        source_shard: ShardId,
        /// Height of the block to prove.
        block_height: BlockHeight,
    },
}

impl BeaconAction {
    /// The action type name for telemetry: a participant's work by its
    /// own name.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Participant(action) => action.into(),
            other => other.into(),
        }
    }
}

impl ParticipantAction {
    /// The action type name for telemetry.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }
}

/// What the fold's check of a beacon block reads.
///
/// The check covers the certificates authenticating the block — the pool
/// ratify cert on every non-genesis block, plus the SPC proposal cert on a
/// Normal block — **and** every `PcVoteEquivocation` carried in the
/// block's committed proposals.
#[derive(Debug, Clone)]
pub struct BeaconBlockCheck {
    /// Block whose certs + embedded equivocation witnesses are being
    /// verified. A `Verifiable::Verified` wrapper short-circuits
    /// dispatch. Carried back through the result event so the fold
    /// doesn't have to stash it separately.
    pub block: Verifiable<CertifiedBeaconBlock>,
    /// Beacon committee for the block's epoch — the SPC cert's signer
    /// base. Positional ordering matches the cert's bitfields.
    pub committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    /// Active validator pool at the anchor's epoch — the ratify cert's
    /// signer base. Positional ordering matches the cert's bitfield.
    pub active_pool: Vec<(ValidatorId, ConsensusPublicKey)>,
    /// Pubkeys for the validators referenced by embedded
    /// `PcVoteEquivocation` evidence. Empty when the block carries no
    /// equivocations. Lookup-shape, order doesn't matter.
    pub equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
}

/// A beacon participant's delegated work: signatures, broadcasts and
/// peer item checks, run off the beacon loop's thread under the
/// participant's signer. Outcomes return to that participant.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ParticipantAction {
    /// Sign a PC round-1 vote over `v_in` and broadcast it to the SPC
    /// committee. Handler reconstructs the canonical signing bytes
    /// from `(epoch, view, v_in)`, signs with the local signer,
    /// broadcasts the wire-form vote, and feeds the signed vote back
    /// to the state machine via `ProtocolEvent::PcVoteReceived` with
    /// `from = local validator`.
    SignAndBroadcastPcVote1 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Local input vector being signed as `v_in`.
        v_in: PcVector,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a PC round-2 vote derived from `qc1` and broadcast it.
    SignAndBroadcastPcVote2 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Source round-1 QC; `v2.x == qc1.x` is enforced at the
        /// signer.
        qc1: Box<Verified<PcQc1>>,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a PC round-3 vote derived from `qc2` and broadcast it.
    SignAndBroadcastPcVote3 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Source round-2 QC; `v3.x_p == qc2.x_p` is enforced at the
        /// signer.
        qc2: Box<Verified<PcQc2>>,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign an SPC empty-view attestation and broadcast it. Feeds the
    /// signed message back to the state machine via
    /// `ProtocolEvent::VerifiedSpcEmptyViewReceived`.
    SignAndBroadcastEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// View this empty-view attestation skips.
        view: SpcView,
        /// Local max high triple reported in the attestation, carried
        /// verified-by-construction from the FSM's
        /// [`Verified<SpcHighTriple>`] pool.
        reported: Box<Verified<SpcHighTriple>>,
        /// SPC committee members the message ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-view` notification to the SPC committee — the
    /// cert is already aggregated, no signing happens at the handler.
    BroadcastSpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Proposal object pairing the view with its backing cert,
        /// carried verified-by-construction from the FSM.
        proposal: Box<Verified<SpcProposalObject>>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-commit` notification — the embedded `proof`
    /// is a `PcQc3` that self-authenticates the committed value.
    BroadcastSpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Committed-low message, carried verified-by-construction
        /// from the FSM's inner-PC QC3.
        msg: Box<Verified<SpcNewCommitMsg>>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a VRF reveal, build a `BeaconProposal` carrying the
    /// proposer's `boundary_qcs` and equivocation evidence, and unicast
    /// it to the rest of the beacon committee. Handler feeds the signed
    /// proposal back to the state machine via
    /// `ProtocolEvent::BeaconProposalReceived` with `from = local
    /// validator` so the same admission path peer proposals use also
    /// admits our own.
    BuildAndBroadcastBeaconProposal {
        /// Epoch this proposal targets; bound into the VRF reveal's
        /// signing context.
        epoch: Epoch,
        /// Per-shard canonical boundary QCs this proposer observed (only
        /// shards whose witness chunk it can supply), or `None` for an
        /// active shard whose crossing it hasn't yet seen.
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        /// Equivocation evidence to embed. Raw — built locally from
        /// verified PC votes.
        equivocations: Vec<PcVoteEquivocation>,
        /// Fork proofs to embed, one per forked shard. Raw — drained from
        /// the local observation buffer of verified proofs.
        fork_proofs: BTreeMap<ShardId, ShardForkProof>,
        /// Shard double-vote pairs to embed. Raw — drained from the
        /// local observation buffer of verified pairs.
        vote_equivocations: Vec<ShardVoteEquivocation>,
        /// Beacon-committee members the proposal ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a finalized beacon block (post-SPC commit) over the
    /// beacon gossip topic.
    BroadcastBeaconBlock {
        /// Certified block to broadcast.
        block: Verified<CertifiedBeaconBlock>,
    },

    /// Sign and broadcast a [`RatifyVote`] globally. The action handler
    /// signs the vote using the runner-held signer (the coordinator
    /// has no signing material), broadcasts the result over the global
    /// beacon-ratify topic, and loops the verified vote back to the
    /// state machine so the local ratification tracker pools its own
    /// contribution. Quorum aggregation happens off-chain inside the
    /// tracker.
    SignAndBroadcastRatifyVote {
        /// Anchor block hash the vote rides against (the latest
        /// committed beacon block at the dispatching coordinator).
        anchor: BeaconBlockHash,
        /// Epoch whose block the vote ratifies. Must be
        /// `current_epoch.next()` at the local tip — older or further
        /// epochs are rejected at admission.
        epoch: Epoch,
        /// Ratification round the vote is cast in.
        round: RatifyRound,
        /// Prevote or precommit.
        phase: RatifyPhase,
        /// Hash of the block the vote names — the verified candidate's
        /// or the canonical skip block's.
        block_hash: BeaconBlockHash,
        /// Peers' verified votes proving the polka behind the vote. A
        /// prevote's is the newest polka the tracker has evidence of,
        /// broadcast alongside it so a polka whose votes were lost still
        /// reaches the pool. A precommit's is the prevote quorum it
        /// locks on, persisted with its slot rather than broadcast, so
        /// a restarted member's lock still carries its proof.
        proof: Vec<Verified<RatifyVote>>,
    },

    /// Verify a single-signer [`RatifyVote`] signature. The result
    /// returns to the state machine carrying the typed verified handle
    /// on success.
    VerifyRatifyVote {
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        vote: Box<Verifiable<RatifyVote>>,
        /// Active validator pool used to look up the signer's pubkey.
        signers: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Broadcast an SPC-certified [`CandidateBeaconBlock`] over the
    /// beacon gossip topic for pool ratification. The candidate is
    /// self-authenticating (its SPC cert rides along); no signing
    /// needed.
    BroadcastBeaconCandidate {
        /// Candidate to broadcast.
        candidate: Verified<CandidateBeaconBlock>,
    },

    /// Verify a [`CandidateBeaconBlock`]: its SPC proposal cert against
    /// the epoch's committee, every `PcVoteEquivocation` carried in its
    /// committed proposals, and the proposal-to-cert content binding.
    /// The result returns to the state machine carrying the candidate
    /// back.
    VerifyBeaconCandidate {
        /// Candidate whose cert + embedded equivocation witnesses are
        /// being verified. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        candidate: Verifiable<CandidateBeaconBlock>,
        /// Beacon committee for the candidate's epoch, in positional
        /// order matching the SPC cert's signer bitfields.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `PcVoteEquivocation` evidence. Empty when the candidate
        /// carries no equivocations.
        equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-1 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`crate::ProtocolEvent::PcVote1Verified`] carrying the
    /// typed verified handle on success.
    VerifyPcVote1 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch.
        vote: Verifiable<PcVote1>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-2 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`crate::ProtocolEvent::PcVote2Verified`].
    VerifyPcVote2 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch; the embedded round-1 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote2>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-3 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`crate::ProtocolEvent::PcVote3Verified`].
    VerifyPcVote3 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch; the embedded round-2 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote3>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify an SPC `NewView` proposal object. Result returns via
    /// [`crate::ProtocolEvent::SpcNewViewVerified`] carrying the typed
    /// verified handle on success.
    VerifySpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Sender of the `NewView` (carried back through the result event).
        from: ValidatorId,
        /// Proposal object to verify. A `Verifiable::Verified`
        /// wrapper short-circuits the dispatch.
        proposal: Box<Verifiable<SpcProposalObject>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify an SPC `NewCommit` message. Result returns via
    /// [`crate::ProtocolEvent::SpcNewCommitVerified`].
    VerifySpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Wire-level sender — carried back through the result so the
        /// coordinator can clear its per-`(epoch, view, sender)`
        /// pipeline slot. `NewCommit` is self-authenticating via the
        /// embedded `proof`, so this label is dedup metadata only.
        from: ValidatorId,
        /// New-commit message to verify. A `Verifiable::Verified`
        /// wrapper short-circuits dispatch; the embedded QC3 marker
        /// shortcuts its sub-check.
        msg: Box<Verifiable<SpcNewCommitMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify an empty-view attestation (sig + embedded reported QC3).
    /// Result returns via [`crate::ProtocolEvent::SpcEmptyViewVerified`].
    VerifySpcEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Attestation to verify. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        msg: Box<Verifiable<SpcEmptyViewMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },
}
