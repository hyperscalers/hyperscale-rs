//! SPC sign + build + verify round-trip integration tests.
//!
//! Use PC's `PcSim` to harvest a real round-3 cert that can stand in
//! as the `proof` inside `SpcHighTriple` and `SpcCert::Direct`. Then
//! exercise the SPC sign/build/verify paths against that cert.

mod common;

use common::PcSim;
use hyperscale_beacon::spc::{
    build_indirect_cert, sign_empty_view_msg, verify_cert, verify_empty_view_msg,
    verify_proposal_object,
};
use hyperscale_types::{
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc3, PcValueElement, PcVector, Slot, SpcCert,
    SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcView, spc_context,
};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Drive a 4-party PC sim and return party 0's terminal QC3 along
/// with the sim itself (caller borrows committee + keys from it).
fn harvest_real_qc3(seed: u64, view: u32, value: &PcVector) -> (PcSim, PcQc3) {
    // Run PC under the slot the SPC test will use; view here means the
    // PC's `view`, which becomes the SpcHighTriple's `view`.
    let mut sim = PcSim::new(4, seed, Slot::new(1), SpcView::new(view));
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
    let slot = Slot::new(1);
    let spc_ctx = spc_context(slot);
    let value = PcVector::new([elem(1), elem(2)]);
    let (sim, qc3) = harvest_real_qc3(0xD1, 3, &value);

    // SpcCert::Direct for entering view = prev_view + 1 = 4.
    let cert = SpcCert::Direct {
        prev_view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3,
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
    let slot = Slot::new(1);
    let spc_ctx = spc_context(slot);
    let value = PcVector::new([elem(7)]);
    let (sim, qc3) = harvest_real_qc3(0xD2, 3, &value);

    let reported = SpcHighTriple {
        view: SpcView::new(3),
        value: qc3.x_pe().clone(),
        proof: qc3,
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

    let cert = build_indirect_cert(empty_view, &msgs).expect("build succeeds");
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
    let slot = Slot::new(1);
    let spc_ctx = spc_context(slot);

    // Two different high triples at the same SPC view 3 — two sim
    // runs with different inputs yield distinct QC3s.
    let value_a = PcVector::new([elem(1)]);
    let value_b = PcVector::new([elem(2)]);
    let (sim, qc3_a) = harvest_real_qc3(0xD3, 3, &value_a);
    let (_sim_b, qc3_b) = harvest_real_qc3(0xD4, 3, &value_b);

    let reported_a = SpcHighTriple {
        view: SpcView::new(3),
        value: qc3_a.x_pe().clone(),
        proof: qc3_a,
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
    let real_cert = build_indirect_cert(empty_view, &msgs).expect("build succeeds");

    // Swap target_value/target_proof for triple_b's data, keeping
    // the (skip_sigs over value_a's hash) intact.
    let SpcCert::Indirect {
        for_view,
        target_view,
        skip_sigs,
        ..
    } = real_cert
    else {
        panic!("expected Indirect");
    };
    let forged = SpcCert::Indirect {
        for_view,
        target_view,
        target_value: qc3_b.x_pe().clone(),
        target_proof: qc3_b,
        skip_sigs,
    };
    assert!(
        !verify_cert(&forged, entering_view, &network, &spc_ctx, &sim.members),
        "cert with swapped target_value must fail the value-hash binding gate",
    );
}
