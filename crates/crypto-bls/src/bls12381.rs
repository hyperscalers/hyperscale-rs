//! BLS12-381 min-pk primitives: keys, signatures, and verification.
//!
//! Min-pk means public keys are G1 (48 bytes) and signatures G2 (96
//! bytes) — the trade that keeps the aggregated public key small, which
//! is what a committee bitfield resolves to.
//!
//! Signing and hashing-to-curve use the proof-of-possession ciphersuite
//! ([`CIPHERSUITE`]). That suffix is what makes it sound to aggregate
//! keys that were never checked against each other in a rogue-key sense
//! — validator registration proves possession of every key separately,
//! and the ciphersuite records which regime the signature was made
//! under.

use blst::BLST_ERROR;
use blst::min_pk::{
    AggregatePublicKey, AggregateSignature, PublicKey as BlstPublicKey, SecretKey,
    Signature as BlstSignature,
};

/// The proof-of-possession ciphersuite every signature here is made and
/// verified under. Signing and verifying must name the identical string
/// or verification fails, so it lives in one place.
pub(crate) const CIPHERSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS12-381 G1 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; Self::LENGTH]);

impl PublicKey {
    /// Byte length of a compressed G1 point.
    pub(crate) const LENGTH: usize = 48;

    /// Sum `keys` into the single key their signatures aggregate under.
    ///
    /// `validate` runs the G1 subgroup check on every input. Callers pass
    /// `false` only where the keys are already possession-proven — a
    /// registered topology key or genesis config — because
    /// that is exactly what forecloses the rogue-key construction the
    /// check would otherwise be defending against, and it is a per-key
    /// cost on a hot path.
    #[must_use]
    pub(crate) fn aggregate(keys: &[Self], validate: bool) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }
        let parsed: Option<Vec<BlstPublicKey>> = keys
            .iter()
            .map(|k| BlstPublicKey::from_bytes(&k.0).ok())
            .collect();
        let parsed = parsed?;
        let refs: Vec<&BlstPublicKey> = parsed.iter().collect();
        AggregatePublicKey::aggregate(&refs, validate)
            .ok()
            .map(|agg| Self(agg.to_public_key().to_bytes()))
    }
}

/// A BLS12-381 G2 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Signature(pub [u8; Self::LENGTH]);

impl Signature {
    /// Byte length of a compressed G2 point.
    pub(crate) const LENGTH: usize = 96;

    /// Sum `signatures` into the aggregate that verifies against the
    /// summed public key.
    ///
    /// `validate` group-checks every input; one malformed signature then
    /// refuses the whole aggregate rather than producing a value that
    /// cannot verify.
    #[must_use]
    pub(crate) fn aggregate(signatures: &[Self], validate: bool) -> Option<Self> {
        if signatures.is_empty() {
            return None;
        }
        let serialized: Vec<&[u8]> = signatures.iter().map(|s| s.0.as_slice()).collect();
        AggregateSignature::aggregate_serialized(&serialized, validate)
            .ok()
            .map(|agg| Self(agg.to_signature().to_bytes()))
    }
}

/// A BLS12-381 signing key.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Byte length of a serialized scalar.
    pub(crate) const LENGTH: usize = 32;

    /// Derive a key from 32 bytes of input keying material.
    ///
    /// Goes through blst's `key_gen`, which hashes the input to a valid
    /// scalar — so any 32 bytes work, including a test seed that is not
    /// itself a valid scalar.
    ///
    /// # Panics
    ///
    /// Cannot panic: `key_gen` succeeds for any input of this length.
    #[must_use]
    pub(crate) fn from_ikm(ikm: &[u8; Self::LENGTH]) -> Self {
        Self(SecretKey::key_gen(ikm, &[]).expect("key_gen accepts any 32-byte ikm"))
    }

    /// Rebuild a key from its serialized scalar.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the bytes are not a valid scalar.
    #[allow(clippy::result_unit_err)] // one failure mode; nothing to name
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ()> {
        SecretKey::from_bytes(slice).map(Self).map_err(|_| ())
    }

    /// The public key this key signs under.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk().to_bytes())
    }

    /// Sign `message`.
    #[must_use]
    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, CIPHERSUITE, &[]).to_bytes())
    }

    /// The key's serialized scalar.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// Whether `signature` is `public_key`'s signature over `message`.
///
/// Both points are group-checked, and malformed bytes are a refusal
/// rather than a panic, so peer-supplied values reach this directly.
#[must_use]
pub(crate) fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> bool {
    let (Ok(sig), Ok(pk)) = (
        BlstSignature::from_bytes(&signature.0),
        BlstPublicKey::from_bytes(&public_key.0),
    ) else {
        return false;
    };
    sig.verify(true, message, CIPHERSUITE, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

/// Whether `signature` is the aggregate of each key's signature over its
/// own message — the distinct-message aggregate check.
#[must_use]
pub(crate) fn aggregate_verify(pairs: &[(PublicKey, Vec<u8>)], signature: &Signature) -> bool {
    let Ok(sig) = BlstSignature::from_bytes(&signature.0) else {
        return false;
    };
    let Some(keys): Option<Vec<BlstPublicKey>> = pairs
        .iter()
        .map(|(pk, _)| BlstPublicKey::from_bytes(&pk.0).ok())
        .collect()
    else {
        return false;
    };
    let key_refs: Vec<&BlstPublicKey> = keys.iter().collect();
    let messages: Vec<&[u8]> = pairs.iter().map(|(_, msg)| msg.as_slice()).collect();
    sig.aggregate_verify(true, &messages, CIPHERSUITE, &key_refs, true) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from_ikm(&[seed; 32])
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let k = key(3);
        let sig = k.sign(b"message");
        assert!(verify(b"message", &k.public_key(), &sig));
        assert!(!verify(b"other", &k.public_key(), &sig));
        assert!(!verify(b"message", &key(4).public_key(), &sig));
    }

    #[test]
    fn keys_are_deterministic_in_their_ikm() {
        assert_eq!(key(9).public_key(), key(9).public_key());
        assert_eq!(key(9).sign(b"m"), key(9).sign(b"m"));
        assert_ne!(key(9).public_key(), key(10).public_key());
    }

    /// The whole point of min-pk aggregation: N signatures over one
    /// message collapse to one signature checked against one summed key.
    #[test]
    fn same_message_signatures_aggregate_under_the_summed_key() {
        let keys: Vec<PrivateKey> = (1..=4).map(key).collect();
        let sigs: Vec<Signature> = keys.iter().map(|k| k.sign(b"shared")).collect();
        let pks: Vec<PublicKey> = keys.iter().map(PrivateKey::public_key).collect();

        let agg_sig = Signature::aggregate(&sigs, true).expect("four valid signatures");
        let agg_pk = PublicKey::aggregate(&pks, true).expect("four valid keys");
        assert!(verify(b"shared", &agg_pk, &agg_sig));

        // A subset's summed key does not verify the full aggregate.
        let partial = PublicKey::aggregate(&pks[..3], true).expect("three valid keys");
        assert!(!verify(b"shared", &partial, &agg_sig));
    }

    #[test]
    fn distinct_message_signatures_aggregate_verify() {
        let keys: Vec<PrivateKey> = (1..=3).map(key).collect();
        let pairs: Vec<(PublicKey, Vec<u8>)> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    k.public_key(),
                    vec![u8::try_from(i).expect("three keys"); 8],
                )
            })
            .collect();
        let sigs: Vec<Signature> = keys
            .iter()
            .zip(&pairs)
            .map(|(k, (_, msg))| k.sign(msg))
            .collect();
        let agg = Signature::aggregate(&sigs, true).expect("three valid signatures");
        assert!(aggregate_verify(&pairs, &agg));

        // Reordering whole pairs is not a change — each key still claims
        // its own message. Swapping the *messages* between two keys is,
        // and must refuse.
        let mut reordered = pairs.clone();
        reordered.swap(0, 1);
        assert!(aggregate_verify(&reordered, &agg));

        let mut crossed = pairs;
        let first = crossed[0].1.clone();
        crossed[0].1 = crossed[1].1.clone();
        crossed[1].1 = first;
        assert!(!aggregate_verify(&crossed, &agg));
    }

    /// Peer-supplied bytes reach every entry point, so malformed input
    /// must refuse rather than panic.
    #[test]
    fn malformed_inputs_refuse() {
        let k = key(1);
        let sig = k.sign(b"m");
        assert!(!verify(b"m", &PublicKey([0u8; 48]), &sig));
        assert!(!verify(b"m", &k.public_key(), &Signature([0xFF; 96])));
        assert!(PublicKey::aggregate(&[], true).is_none());
        assert!(Signature::aggregate(&[], true).is_none());
        assert!(PublicKey::aggregate(&[PublicKey([0u8; 48])], true).is_none());
        assert!(Signature::aggregate(&[Signature([0xFF; 96])], true).is_none());
        assert!(!aggregate_verify(
            &[(PublicKey([0u8; 48]), b"m".to_vec())],
            &sig
        ));
    }
}
