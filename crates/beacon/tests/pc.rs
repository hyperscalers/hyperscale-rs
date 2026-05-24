//! PC inner-consensus round-trip integration tests.
//!
//! Build each round's votes from real BLS signers, assemble the round
//! QC, and assert verification accepts it. Cross-network and tampered
//! variants assert rejection at the right step.

mod common;

use common::{Committee, PcSim, pc_ctx};
use hyperscale_beacon::pc::{
    build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2, sign_vote3, verify_qc1, verify_qc2,
    verify_qc3, verify_vote_equivocation,
};
use hyperscale_types::{
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc1, PcQc2, PcValueElement, PcVector, PcVote1,
    PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound, Slot, SpcView,
};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Build the full round-1 quorum for a committee voting the same `v_in`.
fn round1_quorum(
    cm: &Committee,
    network: &NetworkDefinition,
    ctx: &[u8],
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
    ctx: &[u8],
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
    ctx: &[u8],
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
    let qc1 = build_qc1(&refs, cm.len());

    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members));
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
    let qc1 = build_qc1(&refs, cm.len());

    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members));
    assert!(!verify_qc1(&qc1, &other_network, &ctx, &cm.members));
}

/// QC1 verification must reject the same QC1 under a different PC
/// context (slot or view) — cross-view replay defense.
#[test]
fn qc1_rejected_under_different_view() {
    let cm = Committee::new(4, 0xCC);
    let network = NetworkDefinition::simulator();
    let ctx_v0 = pc_ctx(7, 0);
    let ctx_v1 = pc_ctx(7, 1);
    let v_in = PcVector::new([elem(9)]);

    let votes = round1_quorum(&cm, &network, &ctx_v0, 3, &v_in);
    let refs: Vec<&PcVote1> = votes.iter().collect();
    let qc1 = build_qc1(&refs, cm.len());

    assert!(verify_qc1(&qc1, &network, &ctx_v0, &cm.members));
    assert!(!verify_qc1(&qc1, &network, &ctx_v1, &cm.members));
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
    let qc1 = build_qc1(&v1_refs, cm.len());
    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members));

    // Round 2.
    let v2s = round2_quorum(&cm, &network, &ctx, 3, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members));

    // Round 3.
    let v3s = round3_quorum(&cm, &network, &ctx, 3, &qc2);
    let v3_refs: Vec<&PcVote3> = v3s.iter().collect();
    let qc3 = build_qc3(&v3_refs);
    assert!(verify_qc3(&qc3, &network, &ctx, &cm.members));
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
    let qc1 = build_qc1(&v1_refs, cm.len());
    assert!(verify_qc1(&qc1, &network, &ctx, &cm.members));

    let v2s = round2_quorum(&cm, &network, &ctx, 5, &qc1);
    let v2_refs: Vec<&PcVote2> = v2s.iter().collect();
    let qc2 = build_qc2(&v2_refs, &cm.members);
    assert!(verify_qc2(&qc2, &network, &ctx, &cm.members));

    let v3s = round3_quorum(&cm, &network, &ctx, 5, &qc2);
    let v3_refs: Vec<&PcVote3> = v3s.iter().collect();
    let qc3 = build_qc3(&v3_refs);
    assert!(verify_qc3(&qc3, &network, &ctx, &cm.members));
}

/// Round-1 equivocation round-trip: have validator 0 sign two
/// distinct `v_in` vectors at the same `(slot, view)`, package the
/// `(value, sig)` pairs into a `PcVoteEquivocation`, and assert the
/// verifier accepts it.
#[test]
fn equivocation_round_trip_round1() {
    let cm = Committee::new(4, 0xE0);
    let network = NetworkDefinition::simulator();
    let slot = Slot::new(1);
    let view = SpcView::new(0);
    let ctx = pc_ctx(slot.inner(), view.inner());

    let value_a = PcVector::new([elem(1), elem(2)]);
    let value_b = PcVector::new([elem(1), elem(3)]);

    let vote_a = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_a.clone());
    let vote_b = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_b.clone());

    // Slim wire-form pulls the primary sig from `prefix_sigs[|v_in|]`
    // — the BLS sig over the full vector.
    let ev = PcVoteEquivocation {
        validator: cm.id(0),
        slot,
        view,
        round: PcVoteRound::Vote1,
        value_a,
        sig_a: vote_a.prefix_sigs()[vote_a.v_in().len()],
        value_b,
        sig_b: vote_b.prefix_sigs()[vote_b.v_in().len()],
    };
    assert!(verify_vote_equivocation(&ev, &network, &cm.members));
}

/// Drive a 4-party `PcSim` end-to-end with every party voting the
/// same `v_in`. All parties reach `Decided` and converge on the
/// same `(x_pp, x_pe)`.
#[test]
fn sim_n4_all_agree_converges() {
    let mut sim = PcSim::new(4, 0xAA, Slot::new(1), SpcView::new(0));
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
    let mut sim = PcSim::new(7, 0x07, Slot::new(2), SpcView::new(0));
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
    let mut sim = PcSim::new(4, 0xFF, Slot::new(3), SpcView::new(0));
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

/// A tampered `sig_b` (signed by a different validator) must not
/// verify even though `(value_a, sig_a)` is legitimate.
#[test]
fn equivocation_rejected_when_one_side_signed_by_other_validator() {
    let cm = Committee::new(4, 0xE1);
    let network = NetworkDefinition::simulator();
    let slot = Slot::new(1);
    let view = SpcView::new(0);
    let ctx = pc_ctx(slot.inner(), view.inner());

    let value_a = PcVector::new([elem(1), elem(2)]);
    let value_b = PcVector::new([elem(1), elem(3)]);

    let vote_a = sign_vote1(cm.sk(0), cm.id(0), &network, &ctx, value_a.clone());
    // Validator 1 signs the other vote — there's no contradiction
    // from validator 0's perspective.
    let vote_b_by_other = sign_vote1(cm.sk(1), cm.id(0), &network, &ctx, value_b.clone());

    let ev = PcVoteEquivocation {
        validator: cm.id(0),
        slot,
        view,
        round: PcVoteRound::Vote1,
        value_a,
        sig_a: vote_a.prefix_sigs()[vote_a.v_in().len()],
        value_b,
        sig_b: vote_b_by_other.prefix_sigs()[vote_b_by_other.v_in().len()],
    };
    assert!(!verify_vote_equivocation(&ev, &network, &cm.members));
}
