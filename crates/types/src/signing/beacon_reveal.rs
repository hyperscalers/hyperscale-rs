//! Signing message for beacon-chain VRF reveals.
//!
//! Each committee member signs the epoch, under the network context, to
//! produce an epoch-bound VRF reveal. The 96-byte signature is the
//! [`VrfProof`](crate::VrfProof); its digest is the
//! [`VrfOutput`](crate::VrfOutput) mixed into beacon randomness.
//!
//! The VRF property — uniquely determined by `(secret_key, message)` —
//! follows from signatures being deterministic in min-pk mode. The
//! signing domain keeps a VRF reveal from being confused with a PC vote
//! or a block header sig, both of which reuse the same consensus keys.

pub use hyperscale_crypto::vrf_output_from_proof;
use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::{NetworkId, signed_bytes};
use crate::{ConsensusPublicKey, Epoch, NetworkDefinition, VrfProof};

/// What a VRF reveal covers: the epoch, under the network.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-beacon-reveal-v1", signing_context = NetworkId)]
pub struct BeaconRevealMessage {
    /// The epoch whose randomness the reveal contributes to.
    pub(crate) epoch: Epoch,
}

/// Sign `(network, epoch)` and return the VRF proof. The output is
/// [`vrf_output_from_proof`] of the result — a pure function of the
/// proof, never stored separately.
///
/// Deterministic — [`Signer::vrf_sign`] guarantees the proof is a
/// function of `(key, message)` only, so the same `(signer, network,
/// epoch)` always produces the same proof.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn beacon_reveal_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    epoch: Epoch,
) -> Result<VrfProof, SignError> {
    let msg = signed_bytes(&BeaconRevealMessage { epoch }, network);
    signer.vrf_sign(&msg)
}

/// Verify that `proof` was produced by `pk` over `(network, epoch)`.
///
/// The VRF output is a pure function of the proof
/// ([`vrf_output_from_proof`]), so there is nothing to grind and only one
/// check: the proof, as a signature, verifies against `pk` over the
/// reveal message at `(network, epoch)`.
#[must_use]
pub fn beacon_reveal_verify(
    verifier: &dyn Verifier,
    pk: &ConsensusPublicKey,
    network: &NetworkDefinition,
    epoch: Epoch,
    proof: &VrfProof,
) -> bool {
    let msg = signed_bytes(&BeaconRevealMessage { epoch }, network);
    verifier.verify_vrf(pk, &msg, proof)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed};

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn vrf_sign_verify_round_trip() {
        let signer = signer_from_u64_seed(3);
        let proof = beacon_reveal_sign(&signer, &net(), Epoch::new(42)).expect("sign");
        assert!(beacon_reveal_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            Epoch::new(42),
            &proof
        ));
    }

    /// Deterministic: same inputs → same proof across replicas.
    #[test]
    fn vrf_sign_is_deterministic() {
        let signer = signer_from_u64_seed(7);
        let a = beacon_reveal_sign(&signer, &net(), Epoch::new(100)).expect("sign");
        let b = beacon_reveal_sign(&signer, &net(), Epoch::new(100)).expect("sign");
        assert_eq!(a, b);
    }

    /// A reveal for epoch N doesn't verify against epoch M ≠ N — the
    /// epoch is bound into the signing message.
    #[test]
    fn vrf_verify_rejects_wrong_epoch() {
        let signer = signer_from_u64_seed(3);
        let proof = beacon_reveal_sign(&signer, &net(), Epoch::new(42)).expect("sign");
        assert!(!beacon_reveal_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            Epoch::new(43),
            &proof
        ));
    }
}
