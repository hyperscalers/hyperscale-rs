//! SPC sign + build + verify round-trip integration tests.
//!
//! Use PC's `PcSim` to harvest a real round-3 cert that can stand in
//! as the `proof` inside `SpcHighTriple` and `SpcCert::Direct`. Then
//! exercise the SPC sign/build/verify paths against that cert.

mod common;

use std::time::Duration;

use common::{PcSim, SpcSim};
use hyperscale_types::{
    Epoch, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc3, PcValueElement, PcVector, SpcCert,
    SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcView, build_indirect_cert,
    sign_empty_view_msg, spc_context, verify_block_cert, verify_cert, verify_empty_view_msg,
    verify_proposal_object,
};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Drive a 4-party PC sim and return party 0's terminal QC3 along
/// with the sim itself (caller borrows committee + keys from it).
fn harvest_real_qc3(seed: u64, view: u32, value: &PcVector) -> (PcSim, PcQc3) {
    // Run PC under the epoch the SPC test will use; view here means the
    // PC's `view`, which becomes the SpcHighTriple's `view`.
    let mut sim = PcSim::new(4, seed, Epoch::new(1), SpcView::new(view));
    for i in 0..4 {
        sim.input(i, value.clone());
    }
    sim.run_until_quiescent(1_000);
    let qc3 = sim.decided(0).expect("PC converges").clone();
    (sim, qc3)
}

/// Full direct-cert round-trip: harvest a real PC `Qc3`, wrap it in
/// `SpcCert::Direct`, and verify it accepts.
#[test]
fn direct_cert_round_trip() {
    let network = NetworkDefinition::simulator();
    let epoch = Epoch::new(1);
    let spc_ctx = spc_context(epoch);
    let value = PcVector::new([elem(1), elem(2)]);
    let (sim, qc3) = harvest_real_qc3(0xD1, 3, &value);

    // SpcCert::Direct for entering view = prev_view + 1 = 4.
    let cert = SpcCert::Direct {
        prev_view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3.into(),
    };

    assert!(verify_cert(
        &cert,
        SpcView::new(4),
        &network,
        &spc_ctx,
        &sim.members
    ));
    // And the same cert wrapped in a proposal object.
    let po = SpcProposalObject {
        view: SpcView::new(4),
        cert,
    };
    assert!(verify_proposal_object(
        &po,
        &network,
        &spc_ctx,
        &sim.members
    ));
}

/// Full indirect-cert round-trip: harvest a real `Qc3`, have 2 of
/// the 4 parties sign empty-view messages reporting that triple,
/// build an indirect cert, and verify it accepts.
#[test]
fn indirect_cert_round_trip() {
    let network = NetworkDefinition::simulator();
    let epoch = Epoch::new(1);
    let spc_ctx = spc_context(epoch);
    let value = PcVector::new([elem(7)]);
    let (sim, qc3) = harvest_real_qc3(0xD2, 3, &value);

    let reported = SpcHighTriple {
        view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3.into(),
    };
    let empty_view = SpcView::new(5);
    let entering_view = SpcView::new(6);

    // f+1 = 2 signers attest that view 5 was empty.
    let signers = sim.sks_for_indices(&[0, 1]);
    let msgs: Vec<SpcEmptyViewMsg> = signers
        .iter()
        .map(|(sk, validator)| {
            sign_empty_view_msg(
                sk,
                *validator,
                &network,
                &spc_ctx,
                empty_view,
                reported.clone(),
            )
        })
        .collect();

    // Each empty-view msg must individually verify.
    for m in &msgs {
        assert!(verify_empty_view_msg(m, &network, &spc_ctx, &sim.members));
    }

    let cert = build_indirect_cert(empty_view, &msgs, &sim.members).expect("build succeeds");
    assert!(verify_cert(
        &cert,
        entering_view,
        &network,
        &spc_ctx,
        &sim.members
    ));
}

/// Adversarial: swap an indirect cert's `target_value` for a
/// different valid PC `Qc3` at the same view. The skip-sigs were
/// over the *real* value's hash, so the verifier's
/// `target_value_hash` binding check rejects.
#[test]
fn indirect_cert_with_swapped_target_value_rejected() {
    let network = NetworkDefinition::simulator();
    let epoch = Epoch::new(1);
    let spc_ctx = spc_context(epoch);

    // Two different high triples at the same SPC view 3 — two sim
    // runs with different inputs yield distinct QC3s.
    let value_a = PcVector::new([elem(1)]);
    let value_b = PcVector::new([elem(2)]);
    let (sim, qc3_a) = harvest_real_qc3(0xD3, 3, &value_a);
    let (_sim_b, qc3_b) = harvest_real_qc3(0xD4, 3, &value_b);

    let reported_a = SpcHighTriple {
        view: SpcView::new(3),
        value: qc3_a.x_pe().clone(),
        proof: qc3_a.into(),
    };
    let empty_view = SpcView::new(5);
    let entering_view = SpcView::new(6);

    // Sign empty-view msgs reporting `reported_a`.
    let signers = sim.sks_for_indices(&[0, 1]);
    let msgs: Vec<SpcEmptyViewMsg> = signers
        .iter()
        .map(|(sk, validator)| {
            sign_empty_view_msg(
                sk,
                *validator,
                &network,
                &spc_ctx,
                empty_view,
                reported_a.clone(),
            )
        })
        .collect();
    let real_cert = build_indirect_cert(empty_view, &msgs, &sim.members).expect("build succeeds");

    // Swap target_value/target_proof for triple_b's data, keeping
    // the (skip_reports over value_a's hash + aggregate sig) intact.
    let SpcCert::Indirect {
        for_view,
        target_view,
        skip_reports,
        skip_aggregate_sig,
        ..
    } = real_cert
    else {
        panic!("expected Indirect");
    };
    let forged = SpcCert::Indirect {
        for_view,
        target_view,
        target_value: qc3_b.x_pe().clone(),
        target_proof: qc3_b.into(),
        skip_reports,
        skip_aggregate_sig,
    };
    assert!(
        !verify_cert(&forged, entering_view, &network, &spc_ctx, &sim.members),
        "cert with swapped target_value must fail the value-hash binding gate",
    );
}

// ─── SpcSim — multi-party FSM convergence ─────────────────────────────────

/// Drive a 4-party `SpcSim` with every party feeding the same input
/// vector to view 1. All parties' view 1 PC converges, they all
/// enter view 2 via direct cert, view 2's PC converges, and the
/// commit walk back to view 1 latches `OutputHigh` on every party.
#[test]
fn sim_n4_honest_path_converges_on_high() {
    let mut sim = SpcSim::new(4, 0xA0, Epoch::new(1), Duration::from_mins(1));
    let v = PcVector::new([elem(1), elem(2)]);
    for i in 0..4 {
        sim.input(i, v.clone());
    }
    sim.run_until_quiescent(10_000);
    assert!(
        sim.all_decided(),
        "all 4 parties should latch OutputHigh on the happy path",
    );
    // Agreement (Theorem A.9): every party's high output is identical.
    let baseline = sim.output(0).unwrap().clone();
    for i in 1..4 {
        assert_eq!(*sim.output(i).unwrap(), baseline);
    }
}

/// Same at n=7 (q=5, f=2) — catches sizing assumptions baked into
/// n=4.
#[test]
fn sim_n7_honest_path_converges_on_high() {
    let mut sim = SpcSim::new(7, 0xA1, Epoch::new(2), Duration::from_mins(1));
    let v = PcVector::new(std::iter::once(elem(0x5A)));
    for i in 0..7 {
        sim.input(i, v.clone());
    }
    sim.run_until_quiescent(20_000);
    assert!(sim.all_decided());
    let baseline = sim.output(0).unwrap().clone();
    for i in 1..7 {
        assert_eq!(*sim.output(i).unwrap(), baseline);
    }
}

// ─── Cross-network signature rejection ────────────────────────────────────────

/// A signed empty-view message must reject under a different
/// `NetworkDefinition` — the network byte feeds into the embedded
/// `PcQc3`'s signing context and the empty-view's own skip-statement
/// signature.
#[test]
fn spc_empty_view_rejected_under_different_network() {
    let network = NetworkDefinition::simulator();
    let other_network = NetworkDefinition::mainnet();
    let epoch = Epoch::new(1);
    let spc_ctx = spc_context(epoch);
    let value = PcVector::new([elem(7)]);
    let (sim, qc3) = harvest_real_qc3(0xE0, 3, &value);

    let reported = SpcHighTriple {
        view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3.into(),
    };
    let empty_view = SpcView::new(5);
    let (sk, validator) = sim.sks_for_indices(&[0]).into_iter().next().unwrap();
    let msg = sign_empty_view_msg(&sk, validator, &network, &spc_ctx, empty_view, reported);

    assert!(verify_empty_view_msg(
        &msg,
        &network,
        &spc_ctx,
        &sim.members
    ));
    assert!(!verify_empty_view_msg(
        &msg,
        &other_network,
        &spc_ctx,
        &sim.members
    ));
}

/// A beacon-block `SpcCert::Direct` must reject under a different
/// `NetworkDefinition` — the embedded `PcQc3`'s prefix sigs and round-2
/// aggregate are bound to the signer's `(network, pc_ctx)` pair.
#[test]
fn spc_block_cert_rejected_under_different_network() {
    let network = NetworkDefinition::simulator();
    let other_network = NetworkDefinition::mainnet();
    let epoch = Epoch::new(1);
    let spc_ctx = spc_context(epoch);
    let value = PcVector::new([elem(3), elem(5)]);
    let (sim, qc3) = harvest_real_qc3(0xE1, 3, &value);

    let cert = SpcCert::Direct {
        prev_view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3.into(),
    };
    assert!(verify_block_cert(&cert, &network, &spc_ctx, &sim.members));
    assert!(!verify_block_cert(
        &cert,
        &other_network,
        &spc_ctx,
        &sim.members
    ));
}
