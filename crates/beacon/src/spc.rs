//! Strong Prefix Consensus FSM.
//!
//! SPC drives one epoch through a sequence of views. Each view runs an
//! inner PC instance under `pc_context(spc_context(epoch), view)`; the
//! inner PC is leaderless (every committee member broadcasts their
//! `v_in`), but view *entry* is leader-driven — the cyclic-shifted
//! first party in the view's ranking proposes an [`SpcProposalObject`]
//! authorising entry.
//!
//! When a view fails (its proposer is silent or Byzantine), `f+1`
//! committee members exchange [`SpcEmptyViewMsg`]s reporting their
//! latest verifiable high triple, and `f+1` such messages aggregate
//! into an indirect [`SpcCert`] that skips ahead to the next view
//! while pinning that view's *parent triple* to a specific
//! [`SpcHighTriple`] — the one the max-reported skip signer attested
//! to. The next leader's identity falls out of the ranking; what the
//! cert constrains is what they're allowed to extend from.
//!
//! Pure verifiers, signers, and the indirect-cert aggregator live in
//! [`hyperscale_types::beacon::spc`]; this module owns the stateful
//! FSM (inner-PC sub-machines, observed proposal-object table,
//! per-view scheduling).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use blake3::Hasher;
use hyperscale_types::{
    Bls12381G1PublicKey, Epoch, MAX_VOTE_VECTOR_LEN, PC_VALUE_ELEMENT_BYTES, PcQc1, PcQc2, PcQc3,
    PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation, SpcCert,
    SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcView, ValidatorId, Verified,
    byzantine_threshold,
};

use crate::pc::{PcEffect, PcEvent, PcInstance};

/// Cyclic-shift offset for view `view` in an SPC instance with `n`
/// parties. Views 1 and 2 use the input ranking (offset 0); from view
/// 3 the ranking left-shifts by `view - 2 mod n` each step.
#[must_use]
pub const fn rank_shift_for_view(view: SpcView, n: usize) -> usize {
    let v = view.inner();
    if v <= 2 { 0 } else { (v as usize - 2) % n }
}

// ─── Proposal-object hashing ───────────────────────────────────────────────

/// Canonical bytes for an [`SpcProposalObject`] — the preimage of
/// [`hash_proposal_object`]. Layout: `domain || view (4 LE) || cert
/// (SBOR)`. Not signed; consumed only by the proposal-hash → input-
/// vector pipeline.
fn proposal_object_message(po: &SpcProposalObject) -> Vec<u8> {
    const DOMAIN: &[u8] = b"hyperscale-spc-proposal-object-v1";
    let mut buf = Vec::with_capacity(DOMAIN.len() + 4 + 256);
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&po.view.to_le_bytes());
    buf.extend_from_slice(&po.cert.encode_bytes());
    buf
}

/// Blake3-hash a proposal object into a `PcValueElement` suitable for
/// the inner-PC input vector at the next view.
/// [`PcValueElement::from_digest`] keeps the result off the
/// [`PcValueElement::BOTTOM`] "no proposal object" sentinel.
fn hash_proposal_object(po: &SpcProposalObject) -> PcValueElement {
    const COLLISION_DOMAIN: &[u8] = b"hyperscale-spc-proposal-bottom-collision-v1";
    let bytes = proposal_object_message(po);
    let mut raw = [0u8; PC_VALUE_ELEMENT_BYTES];
    raw.copy_from_slice(Hasher::new().update(&bytes).finalize().as_bytes());
    PcValueElement::from_digest(raw, COLLISION_DOMAIN)
}

/// `Parent(view, value)` — walk a value vector's first non-bottom
/// element to its proposal-object preimage, returning the cert's
/// parent `(view, value)` alongside the verified cert that proves it.
/// Used by [`commit`] to chain back to view 1; on reaching view 1 the
/// returned cert is what authenticates the committed beacon block.
///
/// `view = 1` has no parent (returns `None`).
fn parent_of(
    view: SpcView,
    value: &PcVector,
    proposals: &BTreeMap<PcValueElement, Verified<SpcProposalObject>>,
) -> Option<(SpcView, PcVector, Verified<SpcCert>)> {
    if view.inner() == 1 {
        return None;
    }
    for el in value.iter() {
        if *el != PcValueElement::BOTTOM
            && let Some(po) = proposals.get(el)
        {
            let (parent_view, parent_value) = match &po.cert {
                SpcCert::Direct {
                    prev_view, value, ..
                } => (*prev_view, value.clone()),
                SpcCert::Indirect {
                    target_view,
                    target_value,
                    ..
                } => (*target_view, target_value.clone()),
            };
            return Some((parent_view, parent_value, po.verified_cert()));
        }
    }
    None
}

/// `HasParent(view, value)`: view 1 always has a parent (the genesis
/// boundary); view ≥ 2 needs the first non-bottom hash in `value` to
/// reference a known proposal object.
fn has_parent(
    view: SpcView,
    value: &PcVector,
    proposals: &BTreeMap<PcValueElement, Verified<SpcProposalObject>>,
) -> bool {
    view.inner() == 1 || parent_of(view, value, proposals).is_some()
}

// ─── FSM ───────────────────────────────────────────────────────────────────

/// What [`SpcInstance::handle`] tells its parent.
///
/// Sub-machine-local — the parent (the `BeaconCoordinator`) drains
/// these and lifts them into either internal state mutations or
/// further effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpcEffect {
    /// Sign a round-1 inner-PC vote over `v_in` (under `view`'s PC
    /// context) and broadcast it to the SPC committee.
    SignAndBroadcastPcVote1 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Input vector to be signed as `v_in`.
        v_in: PcVector,
    },
    /// Sign a round-2 inner-PC vote derived from `qc1` and broadcast.
    SignAndBroadcastPcVote2 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Source round-1 QC the round-2 vote is built from.
        qc1: Box<Verified<PcQc1>>,
    },
    /// Sign a round-3 inner-PC vote derived from `qc2` and broadcast.
    SignAndBroadcastPcVote3 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Source round-2 QC the round-3 vote is built from.
        qc2: Box<Verified<PcQc2>>,
    },
    /// Broadcast a `new-view` to peers — we just entered `view` under
    /// `cert`.
    BroadcastNewView {
        /// View this notification authorises entry to.
        view: SpcView,
        /// Cert backing the authorisation.
        cert: Box<Verified<SpcCert>>,
    },
    /// Broadcast a `new-commit` to peers — `view`'s inner PC produced
    /// the (low, proof) pair, anchoring the commit walk. The committed
    /// low rides as `proof.x_pp`; the wire message is built from the
    /// proof alone. Emitted only for `view ≥ 2`; view 1's low is
    /// computed but not broadcast, since peers learn view-1's QC3 from
    /// view-2's direct cert.
    BroadcastNewCommit {
        /// View whose inner PC produced this commit.
        view: SpcView,
        /// PC round-3 cert anchoring the committed low as `proof.x_pp`.
        proof: Box<Verified<PcQc3>>,
    },
    /// Pass-through of an inner-PC equivocation, tagged with the SPC
    /// view so the parent can reconstruct the inner PC context.
    Equivocation {
        /// SPC view the inner PC instance belonged to.
        view: SpcView,
        /// Slim wire-form evidence of the double-sign.
        evidence: Box<PcVoteEquivocation>,
    },
    /// Sign an empty-view attestation reporting `reported` as our
    /// max high triple and broadcast it — we produced a high output
    /// at `view` but our local table can't resolve its parent, so
    /// we fall back to the view-change path. The signed message
    /// lands back on the FSM via the same `SpcEvent::EmptyViewVerified`
    /// path peer messages use.
    SignAndBroadcastEmptyView {
        /// View this empty-view attestation skips.
        view: SpcView,
        /// Our locally-known max high triple at the time of emission.
        /// Boxed to keep [`SpcEffect`] compact — `SpcHighTriple`
        /// embeds a full `PcQc3`.
        reported: Box<Verified<SpcHighTriple>>,
    },
    /// Schedule a view-timeout timer. The parent fires
    /// [`SpcEvent::TimerExpired`] when it elapses.
    SetTimer {
        /// View this timer is scoped to.
        view: SpcView,
        /// How long to wait before firing.
        duration: Duration,
    },
    /// Agreed high output — terminal effect for this SPC instance.
    /// `cert` is the cert the commit walk resolved to view 1's high
    /// (a `Direct` with `prev_view == 1`, or an `Indirect` carrying it
    /// forward with `target_view == 1`); it authenticates the resulting
    /// beacon block. `cert.committed_value() == value` by construction,
    /// so a remote verifier can bind the block's committed proposals to
    /// it.
    OutputHigh {
        /// Committed high vector.
        value: PcVector,
        /// Authenticating cert.
        cert: Box<Verified<SpcCert>>,
    },
}

/// Events [`SpcInstance::handle`] consumes.
///
/// Peer messages flow in as `*Verified` variants carrying `Verified<T>`
/// — the marker is produced by the BLS dispatch through the crypto pool
/// and threaded through the coordinator into the FSM. There is no
/// unverified admission path; the type system forbids passing an
/// unverified message into `handle`.
#[derive(Debug, Clone)]
pub enum SpcEvent {
    /// The local validator's input vector for view 1.
    Input(PcVector),
    /// A BLS-verified inner-PC round-1 vote, tagged with the SPC view
    /// it belongs to. Routed to the right view's `PcInstance::handle`.
    PcVote1Verified {
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// The verified vote.
        vote: Verified<PcVote1>,
    },
    /// A BLS-verified inner-PC round-2 vote.
    PcVote2Verified {
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// The verified vote.
        vote: Box<Verified<PcVote2>>,
    },
    /// A BLS-verified inner-PC round-3 vote.
    PcVote3Verified {
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// The verified vote.
        vote: Box<Verified<PcVote3>>,
    },
    /// BLS-verified `new-view` from a peer entering `view` under `cert`.
    ///
    /// `from` is the transport-level sender id. `NewView` isn't
    /// sender-signed (the cert authenticates the parent claim
    /// cryptographically), so `from` only determines which validator's
    /// proposal-object epoch this `NewView` fills. Two distinct valid
    /// certs from the same `from` are valid relays, not equivocation —
    /// last-write-wins.
    NewViewVerified {
        /// Validator that relayed this notification.
        from: ValidatorId,
        /// View the peer entered.
        view: SpcView,
        /// Cert backing the entry.
        cert: Box<Verified<SpcCert>>,
    },
    /// BLS-verified `new-commit` from a peer. Self-authenticating via
    /// the embedded `proof`; sender label isn't load-bearing.
    NewCommitVerified {
        /// View whose inner PC produced this commit.
        view: SpcView,
        /// Committed low value.
        value: PcVector,
        /// PC round-3 cert anchoring `value` as `proof.x_pp`.
        proof: Box<Verified<PcQc3>>,
    },
    /// BLS-verified `empty-view` attestation from a peer.
    EmptyViewVerified(Box<Verified<SpcEmptyViewMsg>>),
    /// Timer for `view` fired — its leader's grace period elapsed.
    /// Drives `RunVPC(view)` even on a partial proposal-object
    /// buffer so a silent leader can't stall the view indefinitely.
    TimerExpired {
        /// View whose timer fired.
        view: SpcView,
    },
}

/// Per-view local state owned by [`SpcInstance`].
struct ViewState {
    vpc: PcInstance,
    proposal_objects: BTreeMap<ValidatorId, Verified<SpcProposalObject>>,
    vpc_input_fed: bool,
    /// `Q_i,w` — empty-view messages collected for this view,
    /// indexed by signer. At `f + 1` we form the indirect cert.
    empty_views: BTreeMap<ValidatorId, Verified<SpcEmptyViewMsg>>,
    /// Latched once we've assembled and broadcast an indirect cert
    /// from this view's empty-views.
    indirect_cert_built: bool,
    /// Whether we've broadcast our own empty-view for this view.
    empty_view_broadcast: bool,
}

impl ViewState {
    fn new(
        epoch: Epoch,
        view: SpcView,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Self {
        Self {
            vpc: PcInstance::new(epoch, view, committee),
            proposal_objects: BTreeMap::new(),
            vpc_input_fed: false,
            empty_views: BTreeMap::new(),
            indirect_cert_built: false,
            empty_view_broadcast: false,
        }
    }
}

/// Bound on `pending_empty_views` memory: at most
/// `MAX_PENDING_EMPTY_VIEW_AHEAD × n` entries. Beyond this we drop —
/// the message is far enough ahead of `current_view` that catching
/// up via state-sync is the right move.
///
/// Also the forward edge of the coordinator's pre-verification view
/// window (see `BeaconCoordinator::spc_admission_ctx`): a message for a
/// view beyond `current + MAX_PENDING_EMPTY_VIEW_AHEAD` is one the FSM
/// wouldn't act on, so it's dropped before the BLS dispatch.
pub(crate) const MAX_PENDING_EMPTY_VIEW_AHEAD: u32 = 4;

/// One SPC FSM instance, scoped to a single epoch.
///
/// Owns one inner PC instance per view it enters. The
/// `BeaconCoordinator` drives one `SpcInstance` per epoch. Handles
/// both the happy path (view 1 input → view 2 cert → commit) and
/// view-change (empty-view attestations → indirect cert → skip
/// ahead).
pub struct SpcInstance {
    epoch: Epoch,
    committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    me: ValidatorId,
    view_timeout: Duration,

    current_view: SpcView,
    views: BTreeMap<SpcView, ViewState>,
    proposals_by_hash: BTreeMap<PcValueElement, Verified<SpcProposalObject>>,
    new_commit_broadcast: BTreeSet<SpcView>,
    max_high: Option<Verified<SpcHighTriple>>,

    /// Empty-view messages we've sig-/Qc3-validated but couldn't admit
    /// yet because `has_parent` failed at receipt. Keyed by `msg.view`
    /// then sender. Re-scanned after every `enter_view` so a missing-
    /// parent message that arrives ahead of its parent proposal-object
    /// still counts toward the `f + 1` indirect-cert threshold once
    /// the gap closes.
    pending_empty_views: BTreeMap<SpcView, BTreeMap<ValidatorId, Verified<SpcEmptyViewMsg>>>,

    high_output: Option<PcVector>,
}

impl SpcInstance {
    /// Construct a fresh SPC instance for `epoch`. Creates the view-1
    /// `PcInstance` eagerly.
    ///
    /// `view_timeout` is the duration the parent (the
    /// `BeaconCoordinator`) is asked to wait between `SetTimer { view }`
    /// and `TimerExpired { view }` firing — the `2Δ` cap on a view's
    /// leader-proposal grace period before participants exchange
    /// empty-views and skip ahead.
    ///
    /// # Panics
    ///
    /// Panics if `committee.len() < 4` (inherited from `PcInstance`).
    /// Panics if `committee.len() > MAX_VOTE_VECTOR_LEN`: every view's
    /// input is an `n`-element [`PcVector`], whose constructor rejects
    /// more than `MAX_VOTE_VECTOR_LEN` entries, so a larger committee
    /// would otherwise panic deep in `compute_view_input`. Asserting
    /// here fails fast with an attributable message. Genesis caps
    /// `beacon_committee_size` at the same bound, so a validated config
    /// can't reach this.
    #[must_use]
    pub fn new(
        epoch: Epoch,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        me: ValidatorId,
        view_timeout: Duration,
    ) -> Self {
        assert!(
            committee.len() <= MAX_VOTE_VECTOR_LEN,
            "SPC committee ({}) exceeds MAX_VOTE_VECTOR_LEN ({MAX_VOTE_VECTOR_LEN}); \
             view-input vectors can't hold it",
            committee.len(),
        );
        let mut views = BTreeMap::new();
        views.insert(
            SpcView::new(1),
            ViewState::new(epoch, SpcView::new(1), committee.clone()),
        );
        Self {
            epoch,
            committee,
            me,
            view_timeout,
            current_view: SpcView::new(1),
            views,
            proposals_by_hash: BTreeMap::new(),
            new_commit_broadcast: BTreeSet::new(),
            max_high: None,
            pending_empty_views: BTreeMap::new(),
            high_output: None,
        }
    }

    /// Epoch this SPC instance drives consensus for.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Highest view this instance has entered.
    #[must_use]
    pub const fn current_view(&self) -> SpcView {
        self.current_view
    }

    /// Beacon committee driving this instance, positional order matching
    /// every embedded signer bitfield.
    #[must_use]
    pub fn committee(&self) -> &[(ValidatorId, Bls12381G1PublicKey)] {
        &self.committee
    }

    /// Whether view 1's inner PC has been fed its `Input`. Coordinator
    /// reads this to gate the local-proposal arrival path: once the
    /// input is fed the PC FSM has started its round-trips and a
    /// second feed would be a no-op anyway.
    #[must_use]
    pub fn view_one_input_fed(&self) -> bool {
        self.views
            .get(&SpcView::new(1))
            .is_some_and(|v| v.vpc_input_fed)
    }

    /// Latched high output, if any. The commit walk surfaces this on
    /// reaching the view-1 ancestor.
    #[must_use]
    pub const fn high_output(&self) -> Option<&PcVector> {
        self.high_output.as_ref()
    }

    /// Process one event; returns the resulting effects, possibly
    /// empty.
    pub fn handle(&mut self, event: SpcEvent) -> Vec<SpcEffect> {
        match event {
            SpcEvent::Input(v) => self.on_input(v),
            SpcEvent::PcVote1Verified { view, vote } => self.on_pc_vote1_verified(view, vote),
            SpcEvent::PcVote2Verified { view, vote } => self.on_pc_vote2_verified(view, *vote),
            SpcEvent::PcVote3Verified { view, vote } => self.on_pc_vote3_verified(view, *vote),
            SpcEvent::NewViewVerified { from, view, cert } => {
                self.on_new_view_verified(from, view, *cert)
            }
            SpcEvent::NewCommitVerified { view, value, proof } => {
                self.on_new_commit_verified(view, &value, *proof)
            }
            SpcEvent::EmptyViewVerified(msg) => self.on_empty_view_verified(*msg),
            SpcEvent::TimerExpired { view } => self.on_timer_expired(view),
        }
    }

    /// Route a verified PC round-1 vote into the right view's inner PC
    /// instance. Drop on a view the local FSM hasn't entered.
    pub(crate) fn on_pc_vote1_verified(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote1>,
    ) -> Vec<SpcEffect> {
        let Some(view_state) = self.views.get_mut(&view) else {
            return vec![];
        };
        let pc_effects = view_state.vpc.on_vote1_verified(vote);
        self.translate_pc_effects(view, pc_effects)
    }

    /// Route a verified PC round-2 vote into the right view's inner PC
    /// instance.
    pub(crate) fn on_pc_vote2_verified(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote2>,
    ) -> Vec<SpcEffect> {
        let Some(view_state) = self.views.get_mut(&view) else {
            return vec![];
        };
        let pc_effects = view_state.vpc.on_vote2_verified(vote);
        self.translate_pc_effects(view, pc_effects)
    }

    /// Route a verified PC round-3 vote into the right view's inner PC
    /// instance.
    pub(crate) fn on_pc_vote3_verified(
        &mut self,
        view: SpcView,
        vote: Verified<PcVote3>,
    ) -> Vec<SpcEffect> {
        let Some(view_state) = self.views.get_mut(&view) else {
            return vec![];
        };
        let pc_effects = view_state.vpc.on_vote3_verified(vote);
        self.translate_pc_effects(view, pc_effects)
    }

    fn on_input(&mut self, v: PcVector) -> Vec<SpcEffect> {
        let view_state = self.views.get_mut(&SpcView::new(1)).expect("view 1 exists");
        if view_state.vpc_input_fed {
            return vec![];
        }
        view_state.vpc_input_fed = true;
        let pc_effects = view_state.vpc.handle(PcEvent::Input(v));
        self.translate_pc_effects(SpcView::new(1), pc_effects)
    }

    fn translate_pc_effects(&mut self, view: SpcView, pc_effects: Vec<PcEffect>) -> Vec<SpcEffect> {
        let mut out = vec![];
        for effect in pc_effects {
            match effect {
                PcEffect::SignAndBroadcastVote1 { v_in } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote1 { view, v_in });
                }
                PcEffect::SignAndBroadcastVote2 { qc1 } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote2 { view, qc1 });
                }
                PcEffect::SignAndBroadcastVote3 { qc2 } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote3 { view, qc2 });
                }
                PcEffect::EquivocationObserved(ev) => {
                    out.push(SpcEffect::Equivocation { view, evidence: ev });
                }
                PcEffect::Decided(qc3) => {
                    let low = qc3.x_pp().clone();
                    let high = qc3.x_pe().clone();
                    out.extend(self.on_vpc_output_low(view, &low, (*qc3).clone()));
                    out.extend(self.on_vpc_output_high(view, &high, *qc3));
                }
            }
        }
        out
    }

    fn on_vpc_output_low(
        &mut self,
        view: SpcView,
        low: &PcVector,
        proof: Verified<PcQc3>,
    ) -> Vec<SpcEffect> {
        // View 1's PC low is the paper's `v_low` — Upper Bound only, no
        // Agreement across honest parties. Nothing in the FSM acts on it,
        // and peers learn the view-1 QC3 from view-2's NewView (which
        // embeds it in the direct cert), so the broadcast would be
        // redundant. Skip the new-commit / commit() path entirely at
        // view 1; OutputHigh drives epoch finalisation through the
        // parent walk at view ≥ 2.
        if view.inner() == 1 {
            return vec![];
        }
        let mut out = vec![];
        if self.new_commit_broadcast.insert(view) {
            out.push(SpcEffect::BroadcastNewCommit {
                view,
                proof: Box::new(proof),
            });
            // `commit` walks the parent chain back toward view 1.
            out.extend(self.commit(view, low));
        }
        out
    }

    fn on_vpc_output_high(
        &mut self,
        view: SpcView,
        high: &PcVector,
        proof: Verified<PcQc3>,
    ) -> Vec<SpcEffect> {
        if self.high_output.is_some() {
            return vec![];
        }
        let mut out = vec![];
        if has_parent(view, high, &self.proposals_by_hash) {
            let triple = Verified::<SpcHighTriple>::from_verified_proof(view, proof.clone());
            self.update_max_high(triple);
            let Some(next_raw) = view.inner().checked_add(1) else {
                // u32 view counter saturated; honest execution never
                // reaches anywhere near this.
                return out;
            };
            let next = SpcView::new(next_raw);
            let cert = Verified::<SpcCert>::from_qc3_attestation(view, proof);
            // Self-process: enter view+1 and broadcast. `from = me`
            // because we're the relay for our own proposal-object.
            out.extend(self.enter_view(self.me, next, cert.clone()));
            out.push(SpcEffect::BroadcastNewView {
                view: next,
                cert: Box::new(cert),
            });
        } else {
            // Empty-view path: our high has no known parent. Emit a
            // sign-and-broadcast intent reporting our current
            // `max_high`; the signed message lands back on the FSM
            // via `SpcEvent::EmptyViewVerified` and gets pooled toward
            // the `f + 1` indirect-cert quorum the same way peer
            // attestations are.
            let reported = self.max_high.clone();
            let should_broadcast = self
                .views
                .get(&view)
                .is_some_and(|vs| !vs.empty_view_broadcast);
            if let Some(reported) = reported
                && should_broadcast
            {
                if let Some(vs) = self.views.get_mut(&view) {
                    vs.empty_view_broadcast = true;
                }
                out.push(SpcEffect::SignAndBroadcastEmptyView {
                    view,
                    reported: Box::new(reported),
                });
            }
        }
        out
    }

    /// Admit a verified `NewView`. The type system guarantees the
    /// embedded cert is well-formed; this entry runs the FSM-level
    /// `has_parent` / view-entry logic.
    fn on_new_view_verified(
        &mut self,
        from: ValidatorId,
        view: SpcView,
        cert: Verified<SpcCert>,
    ) -> Vec<SpcEffect> {
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        // The cert's parent claim has to resolve in our local
        // `proposals_by_hash` — the FSM-level gate beyond crypto.
        let (prev_view, parent_value) = match cert.as_ref() {
            SpcCert::Direct {
                prev_view, value, ..
            } => (*prev_view, value.clone()),
            SpcCert::Indirect {
                target_view,
                target_value,
                ..
            } => (*target_view, target_value.clone()),
        };
        if !has_parent(prev_view, &parent_value, &self.proposals_by_hash) {
            return vec![];
        }
        self.enter_view(from, view, cert)
    }

    /// Admit a verified `NewCommit`. The embedded QC3 was checked at
    /// the verify boundary.
    fn on_new_commit_verified(
        &mut self,
        view: SpcView,
        value: &PcVector,
        proof: Verified<PcQc3>,
    ) -> Vec<SpcEffect> {
        // View-1 new-commits carry no information the local FSM acts on
        // — peers learn view 1 from view-2 NewView, which embeds the
        // view-1 QC3 in its direct cert. Defensive drop; honest peers
        // stop emitting view-1 new-commits, so this only fires on
        // misbehaving or out-of-date peers.
        if view.inner() == 1 {
            return vec![];
        }
        // FSM-level binding between the committed `value` and the
        // cert's low. The crypto pool checked the QC3 signature; this
        // method enforces the structural identity.
        if proof.x_pp() != value {
            return vec![];
        }
        let mut out = vec![];
        if self.new_commit_broadcast.insert(view) {
            out.push(SpcEffect::BroadcastNewCommit {
                view,
                proof: Box::new(proof),
            });
        }
        out.extend(self.commit(view, value));
        out
    }

    fn enter_view(
        &mut self,
        from: ValidatorId,
        view: SpcView,
        cert: Verified<SpcCert>,
    ) -> Vec<SpcEffect> {
        if self.high_output.is_some() {
            return vec![];
        }
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        let entered_new = view.inner() > self.current_view.inner();
        let mut out = vec![];
        if entered_new {
            self.current_view = view;
            // Start the view-timeout timer for view ≥ 2. View 1 is
            // never entered via this path (it's eager at
            // construction), so this branch only fires for views
            // that just got authorised by a cert.
            if view.inner() > 1 {
                out.push(SpcEffect::SetTimer {
                    view,
                    duration: self.view_timeout,
                });
            }
        }

        self.update_max_high(Verified::<SpcHighTriple>::from_verified_cert(&cert));

        let po = Verified::<SpcProposalObject>::from_verified_cert(view, cert);
        let h = hash_proposal_object(po.as_ref());
        self.proposals_by_hash.insert(h, po.clone());
        let view_state = self
            .views
            .entry(view)
            .or_insert_with(|| ViewState::new(self.epoch, view, self.committee.clone()));
        // Last-write-wins on `(view, sender)` for proposal objects.
        // The cert authenticates the parent claim, so two distinct
        // valid certs from the "same sender" are valid relays, not
        // equivocation.
        view_state.proposal_objects.insert(from, po);

        // Kick the inner PC once we have all `n` proposal objects
        // (view ≥ 2; view 1 takes the application input directly).
        let n = self.committee.len();
        let ready =
            view.inner() > 1 && !view_state.vpc_input_fed && view_state.proposal_objects.len() == n;
        if ready {
            view_state.vpc_input_fed = true;
            let input = self.compute_view_input(view);
            let view_state = self.views.get_mut(&view).expect("present");
            let pc_effects = view_state.vpc.handle(PcEvent::Input(input));
            out.extend(self.translate_pc_effects(view, pc_effects));
        }
        // `proposals_by_hash` just gained an entry, so previously-
        // buffered empty-views may now pass their `has_parent` check.
        out.extend(self.rescan_pending_empty_views());
        out
    }

    /// Admit a verified `EmptyView` attestation. The embedded
    /// reported-triple QC3 was checked at the verify boundary.
    fn on_empty_view_verified(&mut self, msg: Verified<SpcEmptyViewMsg>) -> Vec<SpcEffect> {
        self.process_empty_view(msg)
    }

    /// Forces `RunVPC(view)` on timer expiry even with a partial
    /// proposal-object buffer. Idempotent if VPC already fired.
    fn on_timer_expired(&mut self, view: SpcView) -> Vec<SpcEffect> {
        if view.inner() <= 1 {
            return vec![];
        }
        let Some(view_state) = self.views.get_mut(&view) else {
            return vec![];
        };
        if view_state.vpc_input_fed {
            return vec![];
        }
        view_state.vpc_input_fed = true;
        let input = self.compute_view_input(view);
        let view_state = self.views.get_mut(&view).expect("present");
        let pc_effects = view_state.vpc.handle(PcEvent::Input(input));
        self.translate_pc_effects(view, pc_effects)
    }

    /// Add a verified empty-view to `Q_i,w`, and on reaching `f + 1`
    /// distinct signers build an indirect cert and advance.
    fn process_empty_view(&mut self, msg: Verified<SpcEmptyViewMsg>) -> Vec<SpcEffect> {
        let view = msg.view;
        let signer = msg.signer;
        let reported_view = msg.reported.view;
        let reported_value = msg.reported.value.clone();
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        // Paper requires `w > w_h` — empty-view must skip ahead of
        // the reported high triple's view.
        if view.inner() <= reported_view.inner() {
            return vec![];
        }
        if !has_parent(reported_view, &reported_value, &self.proposals_by_hash) {
            // Parent ProposalObject hasn't arrived yet. Buffer the
            // empty-view; `rescan_pending_empty_views` retries it
            // after every `enter_view`.
            self.buffer_pending_empty_view(msg);
            return vec![];
        }

        self.update_max_high(Verified::<SpcHighTriple>::from_verified_empty_view(&msg));

        let view_state = self
            .views
            .entry(view)
            .or_insert_with(|| ViewState::new(self.epoch, view, self.committee.clone()));
        if view_state.indirect_cert_built {
            return vec![];
        }
        if view_state.empty_views.contains_key(&signer) {
            return vec![];
        }
        view_state.empty_views.insert(signer, msg);

        let n = self.committee.len();
        let threshold = byzantine_threshold(n) + 1;
        if view_state.empty_views.len() < threshold {
            return vec![];
        }
        // Quorum reached — build the indirect cert and enter the
        // next view.
        view_state.indirect_cert_built = true;
        let msgs: Vec<&Verified<SpcEmptyViewMsg>> = view_state.empty_views.values().collect();
        let Some(cert) = Verified::<SpcCert>::from_skip_reports(view, &msgs, &self.committee)
        else {
            // Shouldn't happen — the threshold check above guarantees
            // non-empty input and `view + 1` overflow is the only
            // other failure mode (only at u32 saturation).
            return vec![];
        };
        let Some(next_raw) = view.inner().checked_add(1) else {
            return vec![];
        };
        let next = SpcView::new(next_raw);
        // `from = me` because we're the relay for this indirect-cert
        // assembly we just built ourselves.
        let mut out = self.enter_view(self.me, next, cert.clone());
        out.push(SpcEffect::BroadcastNewView {
            view: next,
            cert: Box::new(cert),
        });
        out
    }

    fn buffer_pending_empty_view(&mut self, msg: Verified<SpcEmptyViewMsg>) {
        let current = self.current_view.inner();
        let view = msg.view.inner();
        if view < current || view > current + MAX_PENDING_EMPTY_VIEW_AHEAD {
            return;
        }
        let bucket = self.pending_empty_views.entry(msg.view).or_default();
        bucket.entry(msg.signer).or_insert(msg);
    }

    /// Drain `pending_empty_views` and re-attempt each entry. Every
    /// `proposals_by_hash` insert must follow with a call here —
    /// `has_parent` flips from false to true when the value's first
    /// non-bottom hash gains a preimage, and entries waiting on that
    /// would otherwise stall.
    fn rescan_pending_empty_views(&mut self) -> Vec<SpcEffect> {
        let current = self.current_view;
        self.pending_empty_views
            .retain(|v, _| v.inner() >= current.inner());
        let pending = std::mem::take(&mut self.pending_empty_views);
        let mut out = vec![];
        for (_view, by_sender) in pending {
            for (_sender, msg) in by_sender {
                out.extend(self.process_empty_view(msg));
            }
        }
        out
    }

    fn commit(&mut self, view: SpcView, value: &PcVector) -> Vec<SpcEffect> {
        let mut out = vec![];
        // View-1 commit is a no-op locally: `v_low` is computed by PC
        // but the FSM doesn't act on it. The view-1 high is what view-2
        // entry consumes via the direct cert path in on_vpc_output_high.
        if view.inner() == 1 {
            return out;
        }
        if let Some((parent_view, parent_value, parent_cert)) =
            parent_of(view, value, &self.proposals_by_hash)
        {
            if parent_view.inner() == 1 {
                if self.high_output.is_none() {
                    self.high_output = Some(parent_value.clone());
                    // The authenticating cert is the one the walk just
                    // resolved to `(1, parent_value)` — so
                    // `cert.committed_value() == parent_value == value`
                    // holds by construction, which is what lets a remote
                    // verifier bind a block's committed proposals to its
                    // cert.
                    out.push(SpcEffect::OutputHigh {
                        value: parent_value,
                        cert: Box::new(parent_cert),
                    });
                    // Instance is done: free the proposal table.
                    self.proposals_by_hash.clear();
                }
            } else if parent_view.inner() > 1 {
                out.extend(self.commit(parent_view, &parent_value));
            }
        }
        out
    }

    fn update_max_high(&mut self, triple: Verified<SpcHighTriple>) {
        let beats = self.max_high.as_ref().is_none_or(|c| triple.view > c.view);
        if beats {
            self.max_high = Some(triple);
        }
    }

    fn compute_view_input(&self, view: SpcView) -> PcVector {
        let view_state = self.views.get(&view).expect("view present");
        let n = self.committee.len();
        let shifts = rank_shift_for_view(view, n);
        // Cyclically shifted ranking: `committee[i + shifts mod n]`.
        let elements: Vec<PcValueElement> = (0..n)
            .map(|i| {
                let validator = self.committee[(i + shifts) % n].0;
                view_state
                    .proposal_objects
                    .get(&validator)
                    .map_or(PcValueElement::BOTTOM, |po| {
                        hash_proposal_object(po.as_ref())
                    })
            })
            .collect();
        PcVector::new(elements)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        Bls12381G1PrivateKey, Bls12381G2Signature, Epoch, NetworkDefinition, PcQc2, PcQc3,
        PcSignerLengths, PcVote1, PcXpProof, SignerBitfield, bls_keypair_from_seed,
        generate_bls_keypair, spc_context,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn dummy_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            generate_bls_keypair().sign_v1(b"unused"),
        )
    }

    /// `rank_shift_for_view` pins views 1 and 2 to offset 0 and
    /// shifts by `view - 2 mod n` from view 3 onward.
    #[test]
    fn rank_shift_layout_is_pinned() {
        let n = 4;
        assert_eq!(rank_shift_for_view(SpcView::new(1), n), 0);
        assert_eq!(rank_shift_for_view(SpcView::new(2), n), 0);
        assert_eq!(rank_shift_for_view(SpcView::new(3), n), 1);
        assert_eq!(rank_shift_for_view(SpcView::new(4), n), 2);
        assert_eq!(rank_shift_for_view(SpcView::new(5), n), 3);
        assert_eq!(rank_shift_for_view(SpcView::new(6), n), 0); // wraps
    }

    // ─── FSM tests ─────────────────────────────────────────────────────

    fn fsm_committee(
        n: usize,
    ) -> (
        Vec<Arc<Bls12381G1PrivateKey>>,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&seed);
            members.push((ValidatorId::new(i as u64), sk.public_key()));
            sks.push(Arc::new(sk));
        }
        (sks, members)
    }

    fn fsm_instance(idx: usize) -> SpcInstance {
        let (_, members) = fsm_committee(4);
        SpcInstance::new(
            Epoch::new(1),
            members.clone(),
            members[idx].0,
            Duration::from_millis(100),
        )
    }

    /// Fresh `SpcInstance` constructs with view 1 as current and no
    /// high output latched.
    #[test]
    fn spc_instance_initial_state() {
        let fsm = fsm_instance(0);
        assert_eq!(fsm.current_view(), SpcView::new(1));
        assert!(fsm.high_output().is_none());
    }

    /// Feeding `Input` at view 1 emits exactly one
    /// `SignAndBroadcastPcVote1` at the local view — the inner PC
    /// surfaces a sign intent as its first effect.
    #[test]
    fn spc_input_emits_vote1_sign_intent() {
        let mut fsm = fsm_instance(0);
        let v = PcVector::new(std::iter::once(PcValueElement::new([7u8; 32])));
        let effects = fsm.handle(SpcEvent::Input(v.clone()));
        assert_eq!(effects.len(), 1);
        let SpcEffect::SignAndBroadcastPcVote1 { view, v_in } = &effects[0] else {
            panic!("expected SignAndBroadcastPcVote1, got {:?}", effects[0]);
        };
        assert_eq!(*view, SpcView::new(1));
        assert_eq!(*v_in, v);
    }

    /// Subsequent `Input` events at view 1 are idempotent — already
    /// fed.
    #[test]
    fn spc_input_idempotent_at_view_one() {
        let mut fsm = fsm_instance(0);
        let v = PcVector::new(std::iter::once(PcValueElement::new([1u8; 32])));
        let _ = fsm.handle(SpcEvent::Input(v.clone()));
        let second = fsm.handle(SpcEvent::Input(v));
        assert!(second.is_empty());
    }

    /// A PC vote for an unknown view is dropped — no buffering, no
    /// effects.
    #[test]
    fn spc_pc_vote_for_unknown_view_dropped() {
        let mut fsm = fsm_instance(0);
        let (_sks, members) = fsm_committee(4);
        // Build a stub Vote1 from peer 1 under view 99 (we've only
        // entered view 1).
        let dummy = Verified::<PcVote1>::new_unchecked_for_test(PcVote1::new(
            members[1].0,
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        ));
        let effects = fsm.on_pc_vote1_verified(SpcView::new(99), dummy);
        assert!(effects.is_empty());
    }

    /// `parent_of(view 1, _)` returns `None` — view 1 has no parent.
    /// `has_parent(view 1, _)` returns `true` — the genesis boundary.
    #[test]
    fn parent_helpers_at_view_one() {
        let proposals = BTreeMap::new();
        assert!(parent_of(SpcView::new(1), &PcVector::empty(), &proposals).is_none());
        assert!(has_parent(SpcView::new(1), &PcVector::empty(), &proposals));
    }

    /// `parent_of(view N, _)` returns the cert's parent triple when
    /// the value's first non-bottom hash resolves to a proposal
    /// object in the table.
    #[test]
    fn parent_of_resolves_first_non_bottom_hash() {
        let parent_value = PcVector::new(std::iter::once(PcValueElement::new([0xAB; 32])));
        let cert = SpcCert::Direct {
            prev_view: SpcView::new(2),
            value: parent_value.clone(),
            proof: dummy_pc_qc3().into(),
        };
        let po = SpcProposalObject {
            view: SpcView::new(3),
            cert,
        };
        let h = hash_proposal_object(&po);
        let mut proposals = BTreeMap::new();
        proposals.insert(h, Verified::<SpcProposalObject>::new_unchecked_for_test(po));

        // Search vector: [BOTTOM, h] — second element resolves.
        let search = PcVector::new([PcValueElement::BOTTOM, h]);
        let (parent_view, resolved_value, resolved_cert) =
            parent_of(SpcView::new(3), &search, &proposals).expect("resolves");
        assert_eq!(parent_view, SpcView::new(2));
        assert_eq!(resolved_value, parent_value);
        // The lifted cert is exactly the proposal object's cert, so its
        // committed value matches the resolved parent value.
        assert_eq!(resolved_cert.committed_value(), &parent_value);
    }

    /// `hash_proposal_object` is deterministic + never returns
    /// [`PcValueElement::BOTTOM`] (bottom-collision avoidance gives full
    /// collision resistance against the sentinel).
    #[test]
    fn hash_proposal_object_deterministic_and_avoids_bottom() {
        let po = SpcProposalObject {
            view: SpcView::new(2),
            cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: PcVector::empty(),
                proof: dummy_pc_qc3().into(),
            },
        };
        let h1 = hash_proposal_object(&po);
        let h2 = hash_proposal_object(&po);
        assert_eq!(h1, h2);
        assert_ne!(h1, PcValueElement::BOTTOM);
    }

    /// `TimerExpired` for view ≤ 1 is a no-op — view 1 has no timer
    /// (input drives it directly).
    #[test]
    fn timer_expiry_at_view_one_is_noop() {
        let mut fsm = fsm_instance(0);
        let effects = fsm.handle(SpcEvent::TimerExpired {
            view: SpcView::new(1),
        });
        assert!(effects.is_empty());
    }

    /// `TimerExpired` for an unknown view is a no-op.
    #[test]
    fn timer_expiry_for_unknown_view_is_noop() {
        let mut fsm = fsm_instance(0);
        let effects = fsm.handle(SpcEvent::TimerExpired {
            view: SpcView::new(42),
        });
        assert!(effects.is_empty());
    }

    /// `EmptyView` whose `view <= reported.view` is rejected — paper
    /// requires `w > w_h` so the skip statement points strictly
    /// forward.
    #[test]
    fn empty_view_with_non_progressing_reported_view_rejected() {
        let mut fsm = fsm_instance(0);
        let (sks, members) = fsm_committee(4);
        let spc_ctx = spc_context(Epoch::new(1));
        let reported = SpcHighTriple {
            view: SpcView::new(5),
            value: PcVector::empty(),
            proof: dummy_pc_qc3().into(),
        };
        // View 3 < reported view 5 — rejected.
        let msg = Verified::<SpcEmptyViewMsg>::sign_local(
            &sks[1],
            members[1].0,
            &net(),
            &spc_ctx,
            SpcView::new(3),
            Verified::<SpcHighTriple>::new_unchecked_for_test(reported),
        );
        let effects = fsm.handle(SpcEvent::EmptyViewVerified(Box::new(msg)));
        assert!(effects.is_empty());
    }
}
