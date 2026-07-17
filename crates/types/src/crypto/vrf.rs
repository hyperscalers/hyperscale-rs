//! Verifiable Random Function (VRF) outputs and proofs.
//!
//! Beacon-chain proposals carry per-slot VRF reveals: every committee
//! member's `(secret_key, slot, network.id)` triple deterministically
//! produces a `(VrfOutput, VrfProof)` pair, and the proof is verifiable
//! by anyone holding the signer's pubkey. The outputs are mixed into
//! the beacon's randomness for committee resampling.
//!
//! The proof is a compressed BLS12-381 signature; the output is the
//! 32-byte digest of that signature. Both are distinct newtypes (rather
//! than aliases for [`Bls12381G2Signature`](super::Bls12381G2Signature)
//! or [`Hash`](crate::Hash)) so the type system catches accidental
//! conflation with block-vote signatures or general-purpose hashes at
//! every call site.

use sbor::prelude::*;

/// Wire length of a `VrfOutput` in bytes.
pub const VRF_OUTPUT_BYTES: usize = 32;

/// Wire length of a `VrfProof` in bytes (compressed BLS12-381 signature).
pub const VRF_PROOF_BYTES: usize = 96;

/// Wire length of a [`Randomness`] in bytes.
pub const RANDOMNESS_BYTES: usize = 32;

/// 32-byte VRF output. Hash-of-the-proof; mixed into beacon randomness.
///
/// Distinct from [`Hash`](crate::Hash) at the type level — a VRF output
/// is the digest of a specific VRF signature under a specific
/// `(secret_key, slot, network.id)` binding, not a free-floating 32-byte
/// hash. Type confusion between the two would silently break randomness
/// derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct VrfOutput([u8; VRF_OUTPUT_BYTES]);

impl VrfOutput {
    /// All-zero VRF output — used as a placeholder where no VRF reveal
    /// is present (e.g. genesis randomness seed before any committee
    /// has signed).
    pub const ZERO: Self = Self([0u8; VRF_OUTPUT_BYTES]);

    /// Build a `VrfOutput` from a raw 32-byte digest. The
    /// proof-to-output binding lives in
    /// [`vrf_output_from_proof`](crate::vrf_output_from_proof); this
    /// constructor takes the digest directly for wire deserialisation
    /// and adversarial test setup.
    #[must_use]
    pub const fn new(bytes: [u8; VRF_OUTPUT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VRF_OUTPUT_BYTES] {
        &self.0
    }
}

/// 96-byte VRF proof — a compressed BLS12-381 signature over the
/// `(network.id, slot)` VRF message under the signer's secret key.
///
/// Verifiable by anyone holding the signer's compressed pubkey. The
/// proof's digest is the corresponding [`VrfOutput`]; the
/// pair-binding lives in the verification function (in the beacon
/// crate), not at the type level.
///
/// Distinct from [`Bls12381G2Signature`](super::Bls12381G2Signature)
/// at the type level — VRF proofs and block-vote signatures share the
/// same compressed-signature shape but sign under different domain
/// tags and verify against different message constructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct VrfProof([u8; VRF_PROOF_BYTES]);

impl VrfProof {
    /// All-zero VRF proof — used as a placeholder (genesis block has
    /// no signing committee yet, so it carries a sentinel).
    pub const ZERO: Self = Self([0u8; VRF_PROOF_BYTES]);

    /// Build a `VrfProof` from a raw 96-byte compressed BLS signature.
    /// Honest construction goes through [`vrf_sign`](crate::vrf_sign);
    /// this constructor takes the bytes directly for wire deserialisation
    /// and adversarial test setup.
    #[must_use]
    pub const fn new(bytes: [u8; VRF_PROOF_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VRF_PROOF_BYTES] {
        &self.0
    }
}

/// 32-byte beacon randomness.
///
/// BLAKE3 digest of the prior randomness concatenated with each slot's
/// accepted [`VrfOutput`]s. Seeds committee sampling and pool draws on
/// the beacon, and feeds per-shard randomness derivations downstream.
///
/// Distinct from [`Hash`](crate::Hash) and [`VrfOutput`] at the type
/// level: this is the running beacon seed, not a free-floating digest
/// or a per-slot VRF output. The type forces call sites to be explicit
/// about which 32-byte input the PRNG seed actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct Randomness([u8; RANDOMNESS_BYTES]);

impl Randomness {
    /// All-zero randomness — bootstrap value used as the genesis seed
    /// before any VRF reveal has been folded in.
    pub const ZERO: Self = Self([0u8; RANDOMNESS_BYTES]);

    /// Build a `Randomness` from a raw 32-byte digest.
    #[must_use]
    pub const fn new(bytes: [u8; RANDOMNESS_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RANDOMNESS_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_output_sbor_round_trip() {
        let original = VrfOutput::new([0xAB; VRF_OUTPUT_BYTES]);
        let bytes = basic_encode(&original).unwrap();
        let decoded: VrfOutput = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vrf_proof_sbor_round_trip() {
        let original = VrfProof::new([0xCD; VRF_PROOF_BYTES]);
        let bytes = basic_encode(&original).unwrap();
        let decoded: VrfProof = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn zero_sentinels() {
        assert_eq!(VrfOutput::ZERO.as_bytes(), &[0u8; VRF_OUTPUT_BYTES]);
        assert_eq!(VrfProof::ZERO.as_bytes(), &[0u8; VRF_PROOF_BYTES]);
        assert_eq!(Randomness::ZERO.as_bytes(), &[0u8; RANDOMNESS_BYTES]);
    }

    #[test]
    fn randomness_sbor_round_trip() {
        let original = Randomness::new([0x42; RANDOMNESS_BYTES]);
        let bytes = basic_encode(&original).unwrap();
        let decoded: Randomness = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn sbor_encoding_is_transparent_to_inner_bytes() {
        let raw: [u8; VRF_OUTPUT_BYTES] = [0xAB; VRF_OUTPUT_BYTES];
        let wrapped = VrfOutput::new(raw);
        let raw_bytes = basic_encode(&raw).unwrap();
        let wrapped_bytes = basic_encode(&wrapped).unwrap();
        assert_eq!(
            raw_bytes, wrapped_bytes,
            "#[sbor(transparent)] must make newtype encoding byte-identical to inner array"
        );
    }
}
