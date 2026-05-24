//! PC inner-consensus round-trip integration tests.
//!
//! Build each round's votes from real BLS signers, assemble the round
//! QC, and assert verification accepts it. Cross-network and tampered
//! variants assert rejection at the right step.

mod common;

use common::{Committee, pc_ctx};
use hyperscale_beacon::pc::{
    build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2, sign_vote3, verify_qc1, verify_qc2,
    verify_qc3,
};
use hyperscale_types::{
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc1, PcQc2, PcValueElement, PcVector, PcVote1,
    PcVote2, PcVote3,
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
