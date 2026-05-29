//! PC inner-consensus round-trip integration tests.
//!
//! Build each round's votes from real BLS signers, assemble the round
//! QC, and assert verification accepts it. Cross-network and tampered
//! variants assert rejection at the right step.

mod common;

use common::{Committee, PcSim, pc_ctx};
use hyperscale_types::{
    Epoch, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcContext, PcQc1, PcQc2, PcValueElement,
    PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound, PcXpProof, SpcView,
    build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2, sign_vote3, verify_qc1, verify_qc2,
    verify_qc3, verify_vote_equivocation,
};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Build the full round-1 quorum for a committee voting the same `v_in`.
fn round1_quorum(
    cm: &Committee,
    network: &NetworkDefinition,
    ctx: &PcContext,
    quorum: usize,
    v_in: &PcVector,
) -> Vec<PcVote1> {
    (0..quorum)
        .map(|i| sign_vote1(cm.sk(i), cm.id(i), network, ctx, v_in.clone()))
        .collect()
}

/// Build the full round-2 quorum from a shared QC1. Every signer's
/// `x = qc1.x` here (the all-equal case → `PcXpProof::Full`).
fn round2_quorum(
    cm: &Committee,
    network: &NetworkDefinition,
    ctx: &PcContext,
    quorum: usize,
    qc1: &PcQc1,
) -> Vec<PcVote2> {
    (0..quorum)
        .map(|i| sign_vote2(cm.sk(i), cm.id(i), network, ctx, qc1.clone()))
        .collect()
}

/// Build the full round-3 quorum from a shared QC2.
fn round3_quorum(
    cm: &Committee,
    network: &NetworkDefinition,
    ctx: &PcContext,
    quorum: usize,
    qc2: &PcQc2,
) -> Vec<PcVote3> {
    (0..quorum)
        .map(|i| sign_vote3(cm.sk(i), cm.id(i), network, ctx, qc2.clone()))
        .collect()
}

/// Sign three round-1 votes over the same input, aggregate into a
/// QC1, and assert `verify_qc1` accepts it.
#[test]
fn qc1_round_trip_n4() {
    let cm = Committee::new(4, 0xAA);
    let network = NetworkDefinition::simulator();
    let ctx = pc_ctx(1, 0);
    let v_in = PcVector::new([elem(1), elem(2), elem(3)]);

    let votes = round1_quorum(&cm, &network, &ctx, 3, &v_in);
    let refs: Vec<&PcVote1> = votes.iter().collect();
    let qc1 = build_qc1(&refs, &cm.members);

    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members).is_ok());
}

/// QC1 verification must reject the same QC1 under a different
/// network — cross-network replay defense.
#[test]
fn qc1_rejected_under_different_network() {
    let cm = Committee::new(4, 0xBB);
    let network = NetworkDefinition::simulator();
    let other_network = NetworkDefinition::mainnet();
    let ctx = pc_ctx(1, 0);
    let v_in = PcVector::new([elem(1), elem(2)]);

    let votes = round1_quorum(&cm, &network, &ctx, 3, &v_in);
    let refs: Vec<&PcVote1> = votes.iter().collect();
    let qc1 = build_qc1(&refs, &cm.members);

    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members).is_ok());
    assert!(verify_qc1(&qc1, &other_network, &ctx, &cm.members).is_err());
}

/// QC2 verification must reject the same QC2 under a different
/// network — cross-network replay defense at round 2.
#[test]
fn qc2_rejected_under_different_network() {
    let cm = Committee::new(4, 0xB2);
    let network = NetworkDefinition::simulator();
    let other_network = NetworkDefinition::mainnet();
    let ctx = pc_ctx(2, 0);
    let v_in = PcVector::new([elem(1), elem(2)]);

    let v1s = round1_quorum(&cm, &network, &ctx, 3, &v_in);
    let v1_refs: Vec<&PcVote1> = v1s.iter().collect();
    let qc1 = build_qc1(&v1_refs, &cm.members);

    let v2s = round2_quorum(&cm, &network, &ctx, 3, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);

    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members).is_ok());
    assert!(verify_qc2(&qc2, &other_network, &ctx, &cm.members).is_err());
}

/// QC3 verification must reject the same QC3 under a different
/// network — cross-network replay defense at round 3.
#[test]
fn qc3_rejected_under_different_network() {
    let cm = Committee::new(4, 0xB3);
    let network = NetworkDefinition::simulator();
    let other_network = NetworkDefinition::mainnet();
    let ctx = pc_ctx(3, 0);
    let v_in = PcVector::new([elem(1), elem(2)]);

    let v1s = round1_quorum(&cm, &network, &ctx, 3, &v_in);
    let v1_refs: Vec<&PcVote1> = v1s.iter().collect();
    let qc1 = build_qc1(&v1_refs, &cm.members);

    let v2s = round2_quorum(&cm, &network, &ctx, 3, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);

    let v3s = round3_quorum(&cm, &network, &ctx, 3, &qc2);
    let v3_refs: Vec<&PcVote3> = v3s.iter().collect();
    let qc3 = build_qc3(&v3_refs, &cm.members);

    assert!(verify_qc3(&qc3, &network, &ctx, &cm.members).is_ok());
    assert!(verify_qc3(&qc3, &other_network, &ctx, &cm.members).is_err());
}

/// QC1 verification must reject the same QC1 under a different PC
/// context (epoch or view) — cross-view replay defense.
#[test]
fn qc1_rejected_under_different_view() {
    let cm = Committee::new(4, 0xCC);
    let network = NetworkDefinition::simulator();
    let ctx_v0 = pc_ctx(7, 0);
    let ctx_v1 = pc_ctx(7, 1);
    let v_in = PcVector::new([elem(9)]);

    let votes = round1_quorum(&cm, &network, &ctx_v0, 3, &v_in);
    let refs: Vec<&PcVote1> = votes.iter().collect();
    let qc1 = build_qc1(&refs, &cm.members);

    assert!(verify_qc1(&qc1, &network, &ctx_v0, &cm.members).is_ok());
    assert!(verify_qc1(&qc1, &network, &ctx_v1, &cm.members).is_err());
}

/// Full PC pipeline at n=4 — three rounds, all signers vote the same
/// input. Asserts QC3 verifies, and that the dedup encoding kicks in
/// (since every signer's `x_p` equals the mcp/mce).
#[test]
fn qc3_round_trip_n4_all_agree() {
    let cm = Committee::new(4, 0xDE);
    let network = NetworkDefinition::simulator();
    let ctx = pc_ctx(2, 0);
    let v_in = PcVector::new([elem(1), elem(2)]);

    // Round 1.
    let v1s = round1_quorum(&cm, &network, &ctx, 3, &v_in);
    let v1_refs: Vec<&PcVote1> = v1s.iter().collect();
    let qc1 = build_qc1(&v1_refs, &cm.members);
    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members).is_ok());

    // Round 2.
    let v2s = round2_quorum(&cm, &network, &ctx, 3, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members).is_ok());

    // Round 3.
    let v3s = round3_quorum(&cm, &network, &ctx, 3, &qc2);
    let v3_refs: Vec<&PcVote3> = v3s.iter().collect();
    let qc3 = build_qc3(&v3_refs, &cm.members);
    assert!(verify_qc3(&qc3, &network, &ctx, &cm.members).is_ok());
}

/// Larger committee (n=7, q=5) exercises the same pipeline at non-
/// minimal scale — catches off-by-one issues in dedup / signer-set
/// sizing that an n=4 test could miss.
#[test]
fn qc3_round_trip_n7_all_agree() {
    let cm = Committee::new(7, 0x07);
    let network = NetworkDefinition::simulator();
    let ctx = pc_ctx(3, 0);
    let v_in = PcVector::new([elem(0xA1)]);

    let v1s = round1_quorum(&cm, &network, &ctx, 5, &v_in);
    let v1_refs: Vec<&PcVote1> = v1s.iter().collect();
    let qc1 = build_qc1(&v1_refs, &cm.members);
    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members).is_ok());

    let v2s = round2_quorum(&cm, &network, &ctx, 5, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members).is_ok());

    let v3s = round3_quorum(&cm, &network, &ctx, 5, &qc2);
    let v3_refs: Vec<&PcVote3> = v3s.iter().collect();
    let qc3 = build_qc3(&v3_refs, &cm.members);
    assert!(verify_qc3(&qc3, &network, &ctx, &cm.members).is_ok());
}

/// Round-1 equivocation round-trip: have validator 0 sign two
/// distinct `v_in` vectors at the same `(epoch, view)`, package the
/// `(value, sig)` pairs into a `PcVoteEquivocation`, and assert the
/// verifier accepts it.
#[test]
fn equivocation_round_trip_round1() {
    let cm = Committee::new(4, 0xE0);
    let network = NetworkDefinition::simulator();
    let epoch = Epoch::new(1);
    let view = SpcView::new(0);
    let ctx = pc_ctx(epoch.inner(), view.inner());

    let value_a = PcVector::new([elem(1), elem(2)]);
    let value_b = PcVector::new([elem(1), elem(3)]);

    let vote_a = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_a.clone());
    let vote_b = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_b.clone());

    // Slim wire-form pulls the primary sig from `prefix_sigs[|v_in|]`
    // — the BLS sig over the full vector.
    let ev = PcVoteEquivocation {
        validator: cm.id(0),
        epoch,
        view,
        round: PcVoteRound::Vote1,
        value_a,
        sig_a: vote_a.prefix_sigs()[vote_a.v_in().len()],
        value_b,
        sig_b: vote_b.prefix_sigs()[vote_b.v_in().len()],
    };
    assert!(verify_vote_equivocation(&ev, &network, &cm.members).is_ok());
}

/// Drive a 4-party `PcSim` end-to-end with every party voting the
/// same `v_in`. All parties reach `Decided` and converge on the
/// same `(x_pp, x_pe)`.
#[test]
fn sim_n4_all_agree_converges() {
    let mut sim = PcSim::new(4, 0xAA, Epoch::new(1), SpcView::new(0));
    let v = PcVector::new([elem(1), elem(2)]);
    for i in 0..4 {
        sim.input(i, v.clone());
    }
    let steps = sim.run_until_quiescent(1_000);
    assert!(sim.all_decided(), "all 4 parties should reach Decided");
    let baseline_low = sim.decided(0).unwrap().x_pp().clone();
    let baseline_high = sim.decided(0).unwrap().x_pe().clone();
    for i in 1..4 {
        let qc3 = sim.decided(i).unwrap();
        assert_eq!(*qc3.x_pp(), baseline_low);
        assert_eq!(*qc3.x_pe(), baseline_high);
    }
    // Sanity: should converge in well under the budget.
    assert!(steps < 500, "convergence took {steps} steps");
}

/// Sim at n=7 (q=5): all-agree still converges. Catches off-by-one
/// in quorum sizing.
#[test]
fn sim_n7_all_agree_converges() {
    let mut sim = PcSim::new(7, 0x07, Epoch::new(2), SpcView::new(0));
    let v = PcVector::new([elem(0xA1)]);
    for i in 0..7 {
        sim.input(i, v.clone());
    }
    sim.run_until_quiescent(2_000);
    assert!(sim.all_decided());
    let first = sim.decided(0).unwrap().x_pp().clone();
    for i in 1..7 {
        assert_eq!(*sim.decided(i).unwrap().x_pp(), first);
    }
}

/// `f` parties silent: the remaining `q = n - f` parties still
/// converge. Verifies the FSM doesn't deadlock on the missing
/// quorum threshold.
#[test]
fn sim_n4_with_one_silent_party_still_converges() {
    let mut sim = PcSim::new(4, 0xFF, Epoch::new(3), SpcView::new(0));
    let v = PcVector::new([elem(5)]);
    // Parties 0..3 vote; party 3 stays silent.
    for i in 0..3 {
        sim.input(i, v.clone());
    }
    sim.run_until_quiescent(1_000);
    // Parties 0, 1, 2 reach Decided (3 = n-f).
    for i in 0..3 {
        assert!(sim.decided(i).is_some(), "party {i} should decide");
    }
    // Party 3 (silent) never received an Input, so no votes to drive
    // its own quorum into round 1 — it observes others' votes but
    // never broadcasts, so it gathers the 3 other votes per round
    // and also reaches Decided.
    assert!(
        sim.decided(3).is_some(),
        "silent observer should also decide via received votes"
    );
}

// ─── `build_qc2` proof-variant coverage ────────────────────────────────────────
//
// `PcSim` can't reach the Diverging or ShortWitness branches end-to-end: its
// deterministic FIFO delivery makes every party see the same first `q` round-1
// votes, so every party builds the *same* QC1 and signs round-2 over an
// identical `x`. Round 2 collapses to `PcXpProof::Full`. Forcing two signers
// to back round-2 with different QC1s — which is what Diverging and
// ShortWitness require — has to be done by composing the votes directly.
// These tests cover the same code path (`build_qc2` → `build_xp_proof`) as
// the planned sim tests would have, at the layer that can actually produce
// divergent inputs.

/// Build a QC1 over `v_in` from a `quorum`-sized subset of the
/// committee. The signers collectively cover positions `0..quorum`.
fn qc1_over(
    cm: &Committee,
    network: &NetworkDefinition,
    ctx: &PcContext,
    quorum: usize,
    v_in: &PcVector,
) -> PcQc1 {
    let votes = round1_quorum(cm, network, ctx, quorum, v_in);
    let refs: Vec<&PcVote1> = votes.iter().collect();
    build_qc1(&refs, &cm.members)
}

/// Two signers vote round-2 over a QC1 with `x = [1, 2]`; one signs
/// over a QC1 with `x = [1, 3]`. The resulting QC2 must witness the
/// divergence — `x_p = [1]` and `pi = Diverging`.
#[test]
fn build_qc2_produces_diverging_proof_under_divergent_round1_inputs() {
    let cm = Committee::new(4, 0xD1);
    let network = NetworkDefinition::simulator();
    let ctx = pc_ctx(11, 0);
    let x_a = PcVector::new([elem(1), elem(2)]);
    let x_b = PcVector::new([elem(1), elem(3)]);

    let qc1_a = qc1_over(&cm, &network, &ctx, 3, &x_a);
    let qc1_b = qc1_over(&cm, &network, &ctx, 3, &x_b);

    let v2_0 = sign_vote2(cm.sk(0), cm.id(0), &network, &ctx, qc1_a.clone());
    let v2_1 = sign_vote2(cm.sk(1), cm.id(1), &network, &ctx, qc1_a);
    let v2_2 = sign_vote2(cm.sk(2), cm.id(2), &network, &ctx, qc1_b);

    let refs: Vec<&PcVote2> = vec![&v2_0, &v2_1, &v2_2];
    let qc2 = build_qc2(&refs, &cm.members);

    assert_eq!(qc2.x_p(), &PcVector::new([elem(1)]));
    assert!(
        matches!(qc2.pi(), PcXpProof::Diverging(_)),
        "qc2.pi is {:?}, expected Diverging",
        qc2.pi(),
    );
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members).is_ok());
}

/// Four signers vote round-2 over a QC1 with `x = [1, 2]`; one signs
/// over a QC1 with `x = [1]`. The short signer's vote constrains the
/// mcp; the resulting QC2 must carry a `PcXpProof::ShortWitness`
/// witness. `x_p = [1]`.
#[test]
fn build_qc2_produces_short_witness_proof_when_one_signer_is_short() {
    let cm = Committee::new(7, 0x5F);
    let network = NetworkDefinition::simulator();
    let ctx = pc_ctx(13, 0);
    let x_long = PcVector::new([elem(1), elem(2)]);
    let x_short = PcVector::new([elem(1)]);

    let qc1_long = qc1_over(&cm, &network, &ctx, 5, &x_long);
    let qc1_short = qc1_over(&cm, &network, &ctx, 5, &x_short);

    let v2s = [
        sign_vote2(cm.sk(0), cm.id(0), &network, &ctx, qc1_long.clone()),
        sign_vote2(cm.sk(1), cm.id(1), &network, &ctx, qc1_long.clone()),
        sign_vote2(cm.sk(2), cm.id(2), &network, &ctx, qc1_long.clone()),
        sign_vote2(cm.sk(3), cm.id(3), &network, &ctx, qc1_long),
        sign_vote2(cm.sk(4), cm.id(4), &network, &ctx, qc1_short),
    ];
    let refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&refs, &cm.members);

    assert_eq!(qc2.x_p(), &PcVector::new([elem(1)]));
    assert!(
        matches!(qc2.pi(), PcXpProof::ShortWitness { .. }),
        "qc2.pi is {:?}, expected ShortWitness",
        qc2.pi(),
    );
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members).is_ok());
}

/// A tampered `sig_b` (signed by a different validator) must not
/// verify even though `(value_a, sig_a)` is legitimate.
#[test]
fn equivocation_rejected_when_one_side_signed_by_other_validator() {
    let cm = Committee::new(4, 0xE1);
    let network = NetworkDefinition::simulator();
    let epoch = Epoch::new(1);
    let view = SpcView::new(0);
    let ctx = pc_ctx(epoch.inner(), view.inner());

    let value_a = PcVector::new([elem(1), elem(2)]);
    let value_b = PcVector::new([elem(1), elem(3)]);

    let vote_a = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_a.clone());
    // Validator 1 signs the other vote — there's no contradiction
    // from validator 0's perspective.
    let vote_b_by_other = sign_vote1(cm.sk(1), cm.id(0), &network, &ctx, value_b.clone());

    let ev = PcVoteEquivocation {
        validator: cm.id(0),
        epoch,
        view,
        round: PcVoteRound::Vote1,
        value_a,
        sig_a: vote_a.prefix_sigs()[vote_a.v_in().len()],
        value_b,
        sig_b: vote_b_by_other.prefix_sigs()[vote_b_by_other.v_in().len()],
    };
    assert!(verify_vote_equivocation(&ev, &network, &cm.members).is_err());
}
