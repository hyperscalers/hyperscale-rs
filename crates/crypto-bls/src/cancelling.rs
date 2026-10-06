//! Signature pairs that cancel in their sum, for adversarial test suites.

use blst::{
    BLST_ERROR, blst_p2, blst_p2_add, blst_p2_affine, blst_p2_cneg, blst_p2_compress,
    blst_p2_from_affine, blst_p2_uncompress,
};
use hyperscale_crypto::ConsensusSignature;

/// Decompress a signature to a G2 point.
fn g2(s: &ConsensusSignature) -> blst_p2 {
    // SAFETY: `affine` and `point` are valid zero-initialised blst structs
    // and the signature is 96 bytes, the exact width `blst_p2_uncompress`
    // reads.
    unsafe {
        let mut affine = blst_p2_affine::default();
        assert_eq!(
            blst_p2_uncompress(&raw mut affine, s.as_bytes().as_ptr()),
            BLST_ERROR::BLST_SUCCESS,
            "a cancelling pair is built from valid signatures"
        );
        let mut point = blst_p2::default();
        blst_p2_from_affine(&raw mut point, &raw const affine);
        point
    }
}

/// `(a + delta, b - delta)` for valid signatures `a`, `b` and `delta`.
///
/// Both stay in the G2 subgroup and their sum is `a + b`, so every check
/// of the sum alone still passes, while neither verifies on its own.
///
/// # Panics
///
/// Panics if any input is not a valid compressed G2 point.
#[must_use]
pub fn cancelling_pair(
    a: &ConsensusSignature,
    b: &ConsensusSignature,
    delta: &ConsensusSignature,
) -> (ConsensusSignature, ConsensusSignature) {
    let (a, b, delta) = (g2(a), g2(b), g2(delta));
    let mut neg_delta = delta;
    let mut shifted_a = blst_p2::default();
    let mut shifted_b = blst_p2::default();
    let mut out_a = [0u8; 96];
    let mut out_b = [0u8; 96];
    // SAFETY: all pointers reference valid, initialised blst structs; both
    // outputs are 96 bytes, the exact width `blst_p2_compress` writes.
    unsafe {
        blst_p2_add(&raw mut shifted_a, &raw const a, &raw const delta);
        blst_p2_cneg(&raw mut neg_delta, true);
        blst_p2_add(&raw mut shifted_b, &raw const b, &raw const neg_delta);
        blst_p2_compress(out_a.as_mut_ptr(), &raw const shifted_a);
        blst_p2_compress(out_b.as_mut_ptr(), &raw const shifted_b);
    }
    (
        ConsensusSignature::new(out_a),
        ConsensusSignature::new(out_b),
    )
}
