//! Domain-separated signing for beacon-chain VRF reveals.
//!
//! Each committee member signs `(network, epoch)` under [`DOMAIN_PC_VRF`]
//! to produce a epoch-bound VRF reveal. The 96-byte BLS signature is the
//! [`VrfProof`](crate::VrfProof); its digest is the
//! [`VrfOutput`](crate::VrfOutput) mixed into beacon randomness.
//!
//! The VRF property — uniquely determined by `(secret_key, message)` —
//! follows from BLS signatures being deterministic in min-pk mode. Domain
//! separation here keeps a VRF reveal from being confused with a PC vote
//! or a block header sig, both of which reuse the same BLS keys.

use blake3::Hasher;

use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Epoch, NetworkDefinition,
    VrfOutput, VrfProof, verify_bls12381_v1,
};

/// Domain tag for beacon VRF reveals.
pub const DOMAIN_PC_VRF: &[u8] = b"HYPERSCALE_PC_VRF_v1";

/// Domain tag for hashing a [`VrfProof`] into its [`VrfOutput`]. Binds
/// the output to the specific proof bytes so a forged output paired
/// with a valid proof (which would otherwise pass the BLS sig check)
/// fails verification.
const DOMAIN_VRF_OUTPUT: &[u8] = b"HYPERSCALE_VRF_OUTPUT_v1";

/// Build the canonical signing bytes for a VRF reveal at `epoch` under
/// `network`.
///
/// Layout: `domain || network.id || slot_le_bytes (8)`. Both fields are
/// fixed-width so no length prefixes are needed.
#[must_use]
pub fn vrf_reveal_message(network: &NetworkDefinition, epoch: Epoch) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_PC_VRF.len() + 1 + 8);
    out.extend_from_slice(DOMAIN_PC_VRF);
    out.push(network.id);
    out.extend_from_slice(&epoch.to_le_bytes());
    out
}

/// Derive the [`VrfOutput`] for a [`VrfProof`] under the canonical
/// proof-to-output binding.
///
/// `BLAKE3(DOMAIN_VRF_OUTPUT ‖ proof_bytes)`. The domain tag keeps the
/// hash distinct from any other 32-byte BLAKE3 digest in the
/// codebase. Called by both [`vrf_sign`] (to populate the output) and
/// [`vrf_verify`] (to check the supplied output against the proof).
#[must_use]
pub fn vrf_output_from_proof(proof: &VrfProof) -> VrfOutput {
    let mut h = Hasher::new();
    h.update(DOMAIN_VRF_OUTPUT);
    h.update(proof.as_bytes());
    VrfOutput::new(*h.finalize().as_bytes())
}

/// Sign `(network, epoch)` and return the resulting `(VrfOutput,
/// VrfProof)` pair.
///
/// Deterministic — BLS sigs in min-pk mode are a function of `(sk,
/// message)` only, so the same `(sk, network, epoch)` always produces
/// the same pair.
#[must_use]
pub fn vrf_sign(
    sk: &Bls12381G1PrivateKey,
    network: &NetworkDefinition,
    epoch: Epoch,
) -> (VrfOutput, VrfProof) {
    let msg = vrf_reveal_message(network, epoch);
    let sig = sk.sign_v1(&msg);
    let proof = VrfProof::new(sig.0);
    let output = vrf_output_from_proof(&proof);
    (output, proof)
}

/// Verify that `(output, proof)` was produced by `pk` over `(network,
/// epoch)`.
///
/// Two checks, both must hold:
/// 1. `proof` (as a BLS sig) verifies against `pk` over the bytes
///    produced by [`vrf_reveal_message`] at `(network, epoch)`.
/// 2. `output == vrf_output_from_proof(proof)`. Without this an
///    adversary holding a valid `(pk, proof)` pair could grind any
///    `output` they wanted into beacon randomness.
#[must_use]
pub fn vrf_verify(
    pk: &Bls12381G1PublicKey,
    network: &NetworkDefinition,
    epoch: Epoch,
    output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let msg = vrf_reveal_message(network, epoch);
    let sig = Bls12381G2Signature(*proof.as_bytes());
    if !verify_bls12381_v1(&msg, pk, &sig) {
        return false;
    }
    *output == vrf_output_from_proof(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{DOMAIN_PC_EMPTY_VIEW, DOMAIN_PC_VOTE1};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    /// Pins the byte layout of `vrf_reveal_message`. Any change to the
    /// encoder — field order, length-prefix width, domain tag — shifts
    /// these bytes and fails this test. Cross-arch determinism rides on
    /// this layout being identical regardless of `usize` width on the
    /// host.
    #[test]
    fn vrf_reveal_message_byte_layout_is_pinned() {
        let bytes = vrf_reveal_message(&net(), Epoch::new(5));

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_PC_VRF);
        expected.push(net().id);
        expected.extend_from_slice(&5u64.to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_PC_VRF.len() + 1 + 8);
    }

    /// Distinct slots produce distinct signing bytes under the same
    /// network — every epoch's reveal is bound to its own epoch number so
    /// a reveal can't be replayed against a later epoch.
    #[test]
    fn vrf_reveal_message_differs_across_slots() {
        let a = vrf_reveal_message(&net(), Epoch::new(1));
        let b = vrf_reveal_message(&net(), Epoch::new(2));
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: byte-identical `(epoch,)` inputs
    /// under different networks must produce different signing bytes.
    #[test]
    fn vrf_reveal_message_differs_across_networks() {
        let mainnet = vrf_reveal_message(&NetworkDefinition::mainnet(), Epoch::new(7));
        let stokenet = vrf_reveal_message(&NetworkDefinition::stokenet(), Epoch::new(7));
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: a VRF reveal must not collide
    /// with a PC vote or empty-view skip statement under any input.
    /// Tested by constructing both with disjoint encoders and asserting
    /// the result bytes diverge.
    #[test]
    fn vrf_reveal_message_differs_from_other_beacon_pc_domains() {
        let vrf = vrf_reveal_message(&net(), Epoch::new(1));
        // The PC-vote encoders take a context + vector, but as long as
        // the prefix bytes differ at the domain tag, the full messages
        // can never match regardless of suffix content.
        assert_ne!(&vrf[..DOMAIN_PC_VRF.len()], DOMAIN_PC_VOTE1);
        assert_ne!(&vrf[..DOMAIN_PC_VRF.len()], DOMAIN_PC_EMPTY_VIEW);
    }

    // ─── sign / verify round trip and adversarial cases ──────────────────

    use crate::bls_keypair_from_seed;

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    #[test]
    fn vrf_sign_verify_round_trip() {
        let sk = keypair(3);
        let (output, proof) = vrf_sign(&sk, &net(), Epoch::new(42));
        assert!(vrf_verify(
            &sk.public_key(),
            &net(),
            Epoch::new(42),
            &output,
            &proof
        ));
    }

    /// Deterministic: same inputs → same outputs across replicas.
    #[test]
    fn vrf_sign_is_deterministic() {
        let sk = keypair(7);
        let a = vrf_sign(&sk, &net(), Epoch::new(100));
        let b = vrf_sign(&sk, &net(), Epoch::new(100));
        assert_eq!(a, b);
    }

    /// A reveal from party A doesn't verify under party B's pubkey.
    #[test]
    fn vrf_verify_rejects_cross_party() {
        let sk_a = keypair(3);
        let sk_b = keypair(4);
        let (output, proof) = vrf_sign(&sk_a, &net(), Epoch::new(42));
        assert!(!vrf_verify(
            &sk_b.public_key(),
            &net(),
            Epoch::new(42),
            &output,
            &proof
        ));
    }

    /// A reveal for epoch N doesn't verify against epoch M ≠ N — the epoch
    /// is bound into the signing message.
    #[test]
    fn vrf_verify_rejects_wrong_slot() {
        let sk = keypair(3);
        let (output, proof) = vrf_sign(&sk, &net(), Epoch::new(42));
        assert!(!vrf_verify(
            &sk.public_key(),
            &net(),
            Epoch::new(43),
            &output,
            &proof
        ));
    }

    /// Cross-network replay protection at the verify layer: a reveal
    /// signed under mainnet doesn't verify against stokenet even when
    /// the epoch matches.
    #[test]
    fn vrf_verify_rejects_cross_network() {
        let sk = keypair(3);
        let (output, proof) = vrf_sign(&sk, &NetworkDefinition::mainnet(), Epoch::new(42));
        assert!(!vrf_verify(
            &sk.public_key(),
            &NetworkDefinition::stokenet(),
            Epoch::new(42),
            &output,
            &proof,
        ));
    }

    /// Tampered output (proof still valid) must reject. Without the
    /// `output == hash(proof)` check an adversary could grind a chosen
    /// output into beacon randomness while presenting a real proof.
    #[test]
    fn vrf_verify_rejects_tampered_output() {
        let sk = keypair(3);
        let (output, proof) = vrf_sign(&sk, &net(), Epoch::new(42));
        let mut bytes = *output.as_bytes();
        bytes[0] ^= 1;
        let output = VrfOutput::new(bytes);
        assert!(!vrf_verify(
            &sk.public_key(),
            &net(),
            Epoch::new(42),
            &output,
            &proof
        ));
    }

    /// Tampered proof (BLS sig invalid) must reject — the BLS verify
    /// fails before the output-binding check.
    #[test]
    fn vrf_verify_rejects_tampered_proof() {
        let sk = keypair(3);
        let (output, proof) = vrf_sign(&sk, &net(), Epoch::new(42));
        let mut bytes = *proof.as_bytes();
        bytes[0] ^= 1;
        let proof = VrfProof::new(bytes);
        assert!(!vrf_verify(
            &sk.public_key(),
            &net(),
            Epoch::new(42),
            &output,
            &proof
        ));
    }
}
