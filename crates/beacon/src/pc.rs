//! Prefix Consensus inner-consensus FSM.
//!
//! One [`PcInstance`] drives one `(epoch, view)` of PC through three
//! rounds of voting and emits effects the parent (SPC) drains into
//! `BeaconCoordinator` actions. The vote / QC wire types and their
//! verify / sign / build helpers live in [`hyperscale_types::beacon::pc`].

use std::collections::BTreeMap;

use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, Epoch, PcQc1, PcQc2, PcQc3, PcVector, PcVote1,
    PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound, SpcView, ValidatorId, Verified,
};

/// What `PcInstance::handle` tells its parent.
///
/// Sub-machine-local — the parent (SPC) drains these and lifts them
/// into either internal state mutations or further effects bubbling
/// up to the `BeaconCoordinator`.
///
/// Signing happens off the state-machine thread: the FSM emits
/// `SignAndBroadcastVote*` carrying the unsigned input the signer
/// needs (vector for round 1, QC for rounds 2/3), and accepts the
/// resulting signed vote back via `PcEvent::Vote*Received` on the
/// same path peer votes use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcEffect {
    /// Sign a round-1 vote over `v_in` and broadcast it to the
    /// committee.
    SignAndBroadcastVote1 {
        /// The local input vector to be signed as `v_in`.
        v_in: PcVector,
    },
    /// Sign a round-2 vote over `qc1.x()` and broadcast it.
    SignAndBroadcastVote2 {
        /// Source QC; `v2.x == qc1.x` is enforced at the signer.
        qc1: Box<Verified<PcQc1>>,
    },
    /// Sign a round-3 vote over `qc2.x_p()` and broadcast it.
    SignAndBroadcastVote3 {
        /// Source QC; `v3.x_p == qc2.x_p` is enforced at the signer.
        qc2: Box<Verified<PcQc2>>,
    },
    /// Slim wire-form evidence that a peer double-signed at the same
    /// `(epoch, view, round)`. The parent assembles this into beacon
    /// witnesses for inclusion in a future beacon proposal.
    EquivocationObserved(Box<PcVoteEquivocation>),
    /// Round-3 quorum reached — terminal cert ready. The parent reads
    /// the certified low (`qc3.x_pp`) and high (`qc3.x_pe`) out of
    /// the embedded QC.
    Decided(Box<Verified<PcQc3>>),
}

/// Events `PcInstance::handle` consumes.
///
/// Peer votes flow in as `Vote*Verified` after the
/// [`BeaconCoordinator`](crate::coordinator::BeaconCoordinator) has
/// dispatched the BLS check to the crypto pool and received the
/// `valid=true` result. There is no `*Received` admission path — the
/// type system forbids passing an unverified vote into `handle`.
#[derive(Debug, Clone)]
pub enum PcEvent {
    /// The local validator's input vector. Idempotent: subsequent
    /// inputs after the first are dropped.
    Input(PcVector),
    /// A BLS-verified round-1 vote, ready for admission to the pool.
    Vote1Verified(Verified<PcVote1>),
    /// A BLS-verified round-2 vote.
    Vote2Verified(Box<Verified<PcVote2>>),
    /// A BLS-verified round-3 vote.
    Vote3Verified(Box<Verified<PcVote3>>),
}

/// One inner-PC FSM instance, scoped to a single `(epoch, view)`.
///
/// SPC owns one `PcInstance` per view it drives; the
/// `BeaconCoordinator` owns one `SpcInstance` per epoch. The FSM is
/// synchronous — every event-handler invocation returns the full set
/// of effects that follow, and the parent drains them.
pub struct PcInstance {
    epoch: Epoch,
    view: SpcView,
    committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,

    vote1_pool: BTreeMap<ValidatorId, Verified<PcVote1>>,
    vote2_pool: BTreeMap<ValidatorId, Verified<PcVote2>>,
    vote3_pool: BTreeMap<ValidatorId, Verified<PcVote3>>,

    input: Option<PcVector>,
    sent_vote2: bool,
    sent_vote3: bool,
    decided: bool,
}

/// Byzantine fault threshold for a committee of size `n` — classic
/// BFT `f = (n - 1) / 3`. Committees too small to tolerate any faults
/// (`n < 4`) return `0`.
const fn byzantine_threshold(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

impl PcInstance {
    /// Construct a fresh PC instance for `(epoch, view)`.
    ///
    /// # Panics
    ///
    /// Panics if `committee.len() < 4` — PC requires `n >= 3f + 1`
    /// and `f = (n - 1) / 3`, which collapses to `n >= 4`.
    #[must_use]
    pub fn new(
        epoch: Epoch,
        view: SpcView,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Self {
        assert!(
            committee.len() >= 4,
            "PC requires n >= 4 (3f + 1 with f = 1); got n = {}",
            committee.len()
        );
        Self {
            epoch,
            view,
            committee,
            vote1_pool: BTreeMap::new(),
            vote2_pool: BTreeMap::new(),
            vote3_pool: BTreeMap::new(),
            input: None,
            sent_vote2: false,
            sent_vote3: false,
            decided: false,
        }
    }

    /// Whether the local validator's input has been set.
    #[must_use]
    pub const fn has_input(&self) -> bool {
        self.input.is_some()
    }

    /// Whether the FSM has emitted a `Decided` effect (round-3 quorum
    /// reached at least once).
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        self.decided
    }

    /// Process one event; returns the resulting effects, possibly
    /// empty.
    pub fn handle(&mut self, event: PcEvent) -> Vec<PcEffect> {
        match event {
            PcEvent::Input(v) => self.on_input(v),
            PcEvent::Vote1Verified(v) => self.on_vote1_verified(v),
            PcEvent::Vote2Verified(v) => self.on_vote2_verified(*v),
            PcEvent::Vote3Verified(v) => self.on_vote3_verified(*v),
        }
    }

    const fn quorum(&self) -> usize {
        let n = self.committee.len();
        n - byzantine_threshold(n)
    }

    fn on_input(&mut self, v: PcVector) -> Vec<PcEffect> {
        if self.input.is_some() {
            return vec![];
        }
        self.input = Some(v.clone());
        let mut effects = vec![PcEffect::SignAndBroadcastVote1 { v_in: v }];
        effects.extend(self.maybe_advance_to_round2());
        effects
    }

    /// Admit a BLS-verified round-1 vote. The type system guarantees
    /// the sig check has cleared; this entry runs the pool /
    /// equivocation logic.
    pub(crate) fn on_vote1_verified(&mut self, v1: Verified<PcVote1>) -> Vec<PcEffect> {
        let from = v1.validator();
        if let Some(existing) = self.vote1_pool.get(&from) {
            if existing.v_in() == v1.v_in() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote1,
                    existing.v_in().clone(),
                    prefix_top_sig(existing.as_ref()),
                    v1.v_in().clone(),
                    prefix_top_sig(v1.as_ref()),
                ),
            ))];
        }
        self.vote1_pool.insert(from, v1);
        self.maybe_advance_to_round2()
    }

    /// Admit a BLS-verified round-2 vote.
    pub(crate) fn on_vote2_verified(&mut self, v2: Verified<PcVote2>) -> Vec<PcEffect> {
        let from = v2.validator();
        if let Some(existing) = self.vote2_pool.get(&from) {
            // Vote2's signed payload is `x` — different `qc1` aggregations
            // are honest re-aggregations, not equivocation.
            if existing.x() == v2.x() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote2,
                    existing.x().clone(),
                    vote2_top_sig(existing.as_ref()),
                    v2.x().clone(),
                    vote2_top_sig(v2.as_ref()),
                ),
            ))];
        }
        self.vote2_pool.insert(from, v2);
        self.maybe_advance_to_round3()
    }

    /// Admit a BLS-verified round-3 vote.
    pub(crate) fn on_vote3_verified(&mut self, v3: Verified<PcVote3>) -> Vec<PcEffect> {
        let from = v3.validator();
        if let Some(existing) = self.vote3_pool.get(&from) {
            // Vote3's signed payload is `x_p` — different `qc2`s are
            // honest re-aggregations, not equivocation.
            if existing.x_p() == v3.x_p() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote3,
                    existing.x_p().clone(),
                    existing.sig_xp(),
                    v3.x_p().clone(),
                    v3.sig_xp(),
                ),
            ))];
        }
        self.vote3_pool.insert(from, v3);
        self.maybe_finalize()
    }

    fn maybe_advance_to_round2(&mut self) -> Vec<PcEffect> {
        if self.sent_vote2 || self.vote1_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let vote1s: Vec<&Verified<PcVote1>> = self.vote1_pool.values().take(q).collect();
        let qc1 = Verified::<PcQc1>::from_verified_votes(&vote1s, &self.committee);
        self.sent_vote2 = true;
        let mut effects = vec![PcEffect::SignAndBroadcastVote2 { qc1: Box::new(qc1) }];
        effects.extend(self.maybe_advance_to_round3());
        effects
    }

    fn maybe_advance_to_round3(&mut self) -> Vec<PcEffect> {
        if self.sent_vote3 || self.vote2_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let vote2s: Vec<&Verified<PcVote2>> = self.vote2_pool.values().take(q).collect();
        let qc2 = Verified::<PcQc2>::from_verified_votes(&vote2s, &self.committee);
        self.sent_vote3 = true;
        let mut effects = vec![PcEffect::SignAndBroadcastVote3 { qc2: Box::new(qc2) }];
        effects.extend(self.maybe_finalize());
        effects
    }

    fn maybe_finalize(&mut self) -> Vec<PcEffect> {
        if self.decided || self.vote3_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let vote3s: Vec<&Verified<PcVote3>> = self.vote3_pool.values().take(q).collect();
        let qc3 = Verified::<PcQc3>::from_verified_votes(&vote3s, &self.committee);
        self.decided = true;
        vec![PcEffect::Decided(Box::new(qc3))]
    }

    const fn equivocation_wire(
        &self,
        equivocator: ValidatorId,
        round: PcVoteRound,
        value_a: PcVector,
        sig_a: Bls12381G2Signature,
        value_b: PcVector,
        sig_b: Bls12381G2Signature,
    ) -> PcVoteEquivocation {
        PcVoteEquivocation {
            validator: equivocator,
            epoch: self.epoch,
            view: self.view,
            round,
            value_a,
            sig_a,
            value_b,
            sig_b,
        }
    }
}

/// Pull the round-1 vote's "primary" sig — the sig over the full
/// `v_in` vector, sitting at `prefix_sigs[v_in.len()]`. This is the
/// sig the slim wire form carries.
fn prefix_top_sig(v: &PcVote1) -> Bls12381G2Signature {
    v.prefix_sigs()[v.v_in().len()]
}

/// Pull the round-2 vote's "primary" sig — the sig over the full
/// `x` vector at `prefix_sigs[x.len()]`.
fn vote2_top_sig(v: &PcVote2) -> Bls12381G2Signature {
    v.prefix_sigs()[v.x().len()]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        Bls12381G1PrivateKey, Epoch, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcValueElement,
        PcVector, PcVoteRound, SpcView, bls_keypair_from_seed, pc_context, spc_context,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn elem(b: u8) -> PcValueElement {
        PcValueElement::new([b; PC_VALUE_ELEMENT_BYTES])
    }

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
            let pk = sk.public_key();
            members.push((ValidatorId::new(i as u64), pk));
            sks.push(Arc::new(sk));
        }
        (sks, members)
    }

    fn fsm_instance() -> PcInstance {
        let (_, members) = fsm_committee(4);
        PcInstance::new(Epoch::new(1), SpcView::new(0), members)
    }

    /// `PcInstance::new` panics when the committee is too small for
    /// any BFT (`n < 4`). Enforces the `n >= 3f + 1` precondition at
    /// construction so the FSM never enters a state where `quorum()`
    /// is undefined.
    #[test]
    #[should_panic(expected = "PC requires n >= 4")]
    fn pc_instance_rejects_undersized_committee() {
        let (_, members) = fsm_committee(3);
        let _ = PcInstance::new(Epoch::new(1), SpcView::new(0), members);
    }

    /// First `Input` event emits a sign-and-broadcast intent for
    /// round 1. Subsequent inputs are idempotent.
    #[test]
    fn pc_input_emits_single_sign_intent_then_idempotent() {
        let mut fsm = fsm_instance();
        let v = PcVector::new(std::iter::once(elem(7)));
        let effects = fsm.handle(PcEvent::Input(v.clone()));
        assert_eq!(effects.len(), 1);
        let PcEffect::SignAndBroadcastVote1 { v_in } = &effects[0] else {
            panic!("expected SignAndBroadcastVote1, got {:?}", effects[0]);
        };
        assert_eq!(*v_in, v);
        assert!(fsm.has_input());

        // Second input — already set, no effects.
        let effects2 = fsm.handle(PcEvent::Input(v));
        assert!(effects2.is_empty());
    }

    /// Two distinct round-1 votes from the same peer (different
    /// `v_in`) trigger `EquivocationObserved`. Both sides individually
    /// verify; the FSM's pool collision is what surfaces it.
    #[test]
    fn pc_observes_round1_equivocation() {
        let (sks, members) = fsm_committee(4);
        let mut fsm = PcInstance::new(Epoch::new(1), SpcView::new(0), members.clone());

        // Two distinct v_ins signed by validator 1 (the equivocator).
        let pc_ctx_bytes = pc_context(&spc_context(Epoch::new(1)), SpcView::new(0));
        let v_a = PcVector::new(std::iter::once(elem(1)));
        let v_b = PcVector::new(std::iter::once(elem(2)));
        let vote_a =
            Verified::<PcVote1>::sign_local(&sks[1], members[1].0, &net(), &pc_ctx_bytes, v_a);
        let vote_b =
            Verified::<PcVote1>::sign_local(&sks[1], members[1].0, &net(), &pc_ctx_bytes, v_b);

        let effects_a = fsm.handle(PcEvent::Vote1Verified(vote_a));
        assert!(effects_a.is_empty(), "first vote pools without effect");
        let effects_b = fsm.handle(PcEvent::Vote1Verified(vote_b));
        let [PcEffect::EquivocationObserved(ev)] = effects_b.as_slice() else {
            panic!("expected EquivocationObserved, got {effects_b:?}");
        };
        assert_eq!(ev.validator, members[1].0);
        assert_eq!(ev.round, PcVoteRound::Vote1);
    }
}
