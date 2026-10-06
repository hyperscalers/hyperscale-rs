//! Role newtypes for consensus key and signature material.
//!
//! Each type names the *role* the bytes play in the protocol, not the
//! scheme that produced them. They are opaque byte containers: nothing
//! outside a scheme impl crate may assume curve structure (a mock
//! signature need not be a valid G2 point). Widths match the current
//! scheme's compressed encodings so wire encodings stay byte-identical.

use hyperscale_hbor::Hbor;

/// Wire length of a [`ConsensusPublicKey`] in bytes.
pub const CONSENSUS_PUBLIC_KEY_BYTES: usize = 48;

/// Wire length of a [`ConsensusSignature`] in bytes.
pub const CONSENSUS_SIGNATURE_BYTES: usize = 96;

/// Wire length of an [`AggregateSignature`] in bytes.
pub const AGGREGATE_SIGNATURE_BYTES: usize = 96;

/// A validator's consensus public key.
///
/// Identifies a validator for vote, timeout, proposal, and possession
/// proof verification. Only scheme impl crates interpret the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Hbor)]
#[hbor(transparent)]
pub struct ConsensusPublicKey([u8; CONSENSUS_PUBLIC_KEY_BYTES]);

impl ConsensusPublicKey {
    /// All-zero placeholder key — never a real validator's key.
    pub const ZERO: Self = Self([0u8; CONSENSUS_PUBLIC_KEY_BYTES]);

    /// Build from raw bytes. Honest key material comes from a scheme
    /// impl crate; this constructor exists for wire deserialisation and
    /// adversarial test setup.
    #[must_use]
    pub const fn new(bytes: [u8; CONSENSUS_PUBLIC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONSENSUS_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// A single validator's signature over a consensus message.
///
/// Carried by block votes, timeouts, proposer signatures, ready signals,
/// possession proofs, and signed network envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
#[hbor(transparent)]
pub struct ConsensusSignature([u8; CONSENSUS_SIGNATURE_BYTES]);

impl ConsensusSignature {
    /// All-zero placeholder signature — used where a sentinel is
    /// structural (genesis artifacts) and never verified.
    pub const ZERO: Self = Self([0u8; CONSENSUS_SIGNATURE_BYTES]);

    /// Build from raw bytes. Honest construction goes through
    /// [`Signer::sign`](crate::Signer::sign); this constructor exists
    /// for wire deserialisation and adversarial test setup.
    #[must_use]
    pub const fn new(bytes: [u8; CONSENSUS_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONSENSUS_SIGNATURE_BYTES] {
        &self.0
    }
}

/// A [`ConsensusSignature`] the scheme has already validated.
///
/// Holds when the signature got a positive answer from
/// [`Verifier::verify`](crate::Verifier::verify) or
/// [`Verifier::verify_each`](crate::Verifier::verify_each) or a `true`
/// verdict from [`Verifier::batch_verify`](crate::Verifier::batch_verify),
/// or came straight from [`Signer::sign`](crate::Signer::sign). Those are the
/// checks that run the scheme-level validation
/// [`Verifier::aggregate`](crate::Verifier::aggregate) repeats on every
/// input, so [`Verifier::aggregate_verified`](crate::Verifier::aggregate_verified)
/// can skip it.
///
/// Not a wire type: a value arriving off the wire is a
/// [`ConsensusSignature`] until one of those checks passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSignature(ConsensusSignature);

impl VerifiedSignature {
    /// Wrap `signature` without checking it. The caller asserts it passed
    /// one of the checks named on the type; production callers make that
    /// assertion only where the signature is read off a value whose own
    /// type witnesses the check.
    #[must_use]
    pub const fn new_unchecked(signature: ConsensusSignature) -> Self {
        Self(signature)
    }

    /// The signature itself.
    #[must_use]
    pub const fn signature(&self) -> ConsensusSignature {
        self.0
    }
}

/// A multi-signer aggregate over one or more consensus messages.
///
/// Carried by quorum certificates, beacon PC/SPC certificates, ratify
/// certificates, and execution certificates. The signer set travels
/// beside it (as a bitfield or positional bundle), never inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
#[hbor(transparent)]
pub struct AggregateSignature([u8; AGGREGATE_SIGNATURE_BYTES]);

impl AggregateSignature {
    /// All-zero placeholder aggregate — genesis QCs carry it and it is
    /// never verified.
    pub const ZERO: Self = Self([0u8; AGGREGATE_SIGNATURE_BYTES]);

    /// Build from raw bytes. Honest construction goes through
    /// [`Verifier::aggregate`](crate::Verifier::aggregate); this
    /// constructor exists for wire deserialisation and adversarial test
    /// setup.
    #[must_use]
    pub const fn new(bytes: [u8; AGGREGATE_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AGGREGATE_SIGNATURE_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn hbor_encoding_is_transparent_to_inner_bytes() {
        let raw = [0xABu8; CONSENSUS_PUBLIC_KEY_BYTES];
        let raw_bytes = hbor_to_vec(&raw).unwrap();
        let wrapped_bytes = hbor_to_vec(&ConsensusPublicKey::new(raw)).unwrap();
        assert_eq!(
            raw_bytes, wrapped_bytes,
            "#[hbor(transparent)] must make newtype encoding byte-identical to inner array"
        );
    }

    #[test]
    fn hbor_round_trips() {
        let key = ConsensusPublicKey::new([0x11; CONSENSUS_PUBLIC_KEY_BYTES]);
        let sig = ConsensusSignature::new([0x22; CONSENSUS_SIGNATURE_BYTES]);
        let agg = AggregateSignature::new([0x33; AGGREGATE_SIGNATURE_BYTES]);
        assert_eq!(
            hbor_from_slice::<ConsensusPublicKey>(&hbor_to_vec(&key).unwrap()).unwrap(),
            key
        );
        assert_eq!(
            hbor_from_slice::<ConsensusSignature>(&hbor_to_vec(&sig).unwrap()).unwrap(),
            sig
        );
        assert_eq!(
            hbor_from_slice::<AggregateSignature>(&hbor_to_vec(&agg).unwrap()).unwrap(),
            agg
        );
    }

    #[test]
    fn zero_sentinels() {
        assert_eq!(
            ConsensusPublicKey::ZERO.as_bytes(),
            &[0u8; CONSENSUS_PUBLIC_KEY_BYTES]
        );
        assert_eq!(
            ConsensusSignature::ZERO.as_bytes(),
            &[0u8; CONSENSUS_SIGNATURE_BYTES]
        );
        assert_eq!(
            AggregateSignature::ZERO.as_bytes(),
            &[0u8; AGGREGATE_SIGNATURE_BYTES]
        );
    }
}
