//! `verify_qc3` rejects forged QC3s with prover-chosen `x_pp` /
//! `x_pe` endpoints, even when the embedded round-2 QCs and the
//! aggregate signature are real.
//!
//! Harvest a legitimate QC3 by driving [`PcSim`] to consensus, then
//! construct a tampered [`PcQc3`] swapping in a bogus endpoint —
//! `verify_qc3` must reject it because the endpoint-claim against
//! `qc2_xpp` / `qc2_xpe` no longer holds.

mod common;

use common::{PcSim, pc_ctx};
use hyperscale_types::{
    Epoch, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc3, PcValueElement, PcVector, SpcView,
    Verifiable, verify_qc3,
};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Drive a 4-party `PcSim` to consensus with every party voting
/// `unanimous_input`, then return party 0's terminal QC3.
fn harvest_real_qc3(seed: u64, epoch: Epoch, unanimous_input: &PcVector) -> (PcSim, PcQc3) {
    let mut sim = PcSim::new(4, seed, epoch, SpcView::new(0));
    for i in 0..4 {
        sim.input(i, unanimous_input.clone());
    }
    sim.run_until_quiescent(1_000);
    let qc3 = sim
        .decided(0)
        .expect("PC consensus should converge")
        .clone();
    (sim, qc3)
}

/// A forged QC3 claiming `x_pp = []` despite the signers' real `x_p`
/// values being non-empty must be rejected — the embedded
/// `qc2_xpp.x_p` no longer matches the claimed endpoint.
#[test]
fn forge_qc3_with_empty_xpp_is_rejected() {
    let network = NetworkDefinition::simulator();
    let real_input = PcVector::new([elem(42), elem(42), elem(42)]);
    let (sim, real) = harvest_real_qc3(0xA1, Epoch::new(1), &real_input);

    // Sanity: the real QC3 verifies and its x_pp matches the input.
    assert_eq!(real.x_pp().as_slice(), &[elem(42), elem(42), elem(42)]);
    assert!(verify_qc3(&real, &network, &pc_ctx(1, 0), &sim.members).is_ok());

    // Forge: swap in an empty x_pp while keeping the rest.
    let real_x_pe = real.x_pe().clone();
    let real_qc2_xpe = real.qc2_xpe().clone();
    let forged = PcQc3::new(
        PcVector::empty(),
        real.qc2_xpp().clone(),
        Some(real_x_pe),
        Some(Verifiable::from(real_qc2_xpe)),
        real.all_signers().clone(),
        real.signer_lengths().clone(),
        real.agg_sig(),
    );

    assert!(
        verify_qc3(&forged, &network, &pc_ctx(1, 0), &sim.members).is_err(),
        "forged QC3 with x_pp=[] but real signers' x_p non-empty must be rejected",
    );
}

/// A forged QC3 extending `x_pe` past the real round-3 quorum's
/// `mce(x_p_i)` must be rejected — the embedded `qc2_xpe.x_p` no
/// longer matches the claimed endpoint.
#[test]
fn forge_qc3_with_extended_xpe_is_rejected() {
    let network = NetworkDefinition::simulator();
    let real_input = PcVector::new([elem(7), elem(7)]);
    let (sim, real) = harvest_real_qc3(0xA2, Epoch::new(2), &real_input);

    // Forge: append a phantom element to x_pe.
    let real_x_pe = real.x_pe().clone();
    let mut extended: Vec<PcValueElement> = real_x_pe.iter().copied().collect();
    extended.push(elem(0xEF));
    let extended_x_pe = PcVector::new(extended);

    let forged = PcQc3::new(
        real.x_pp().clone(),
        real.qc2_xpp().clone(),
        Some(extended_x_pe),
        Some(Verifiable::from(real.qc2_xpe().clone())),
        real.all_signers().clone(),
        real.signer_lengths().clone(),
        real.agg_sig(),
    );

    assert!(
        verify_qc3(&forged, &network, &pc_ctx(2, 0), &sim.members).is_err(),
        "forged QC3 with x_pe extended past real mce must be rejected",
    );
}
