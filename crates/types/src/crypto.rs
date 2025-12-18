//! Cryptographic key pairs and signatures.
//!
//! Supports:
//! - ED25519: Fast signing for general use
//! - BLS12-381: Signature aggregation for consensus efficiency

use sbor::prelude::*;
use std::fmt;

/// Supported key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub enum KeyType {
    /// ED25519 - Fast, widely supported.
    Ed25519,
    /// BLS12-381 - Supports signature aggregation.
    Bls12381,
}

/// A cryptographic key pair for signing.
#[derive(Clone)]
pub enum KeyPair {
    /// ED25519 key pair.
    Ed25519(ed25519_dalek::SigningKey),
    /// BLS12-381 key pair.
    Bls12381(blst::min_pk::SecretKey),
}

impl KeyPair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate_ed25519() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        KeyPair::Ed25519(signing_key)
    }

    /// Generate a new random BLS12-381 keypair.
    pub fn generate_bls() -> Self {
        let mut ikm = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ikm);
        let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        KeyPair::Bls12381(sk)
    }

    /// Generate a keypair from a seed (for testing/simulation).
    pub fn from_seed(key_type: KeyType, seed: &[u8; 32]) -> Self {
        match key_type {
            KeyType::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
                KeyPair::Ed25519(signing_key)
            }
            KeyType::Bls12381 => {
                let sk = blst::min_pk::SecretKey::key_gen(seed, &[]).unwrap();
                KeyPair::Bls12381(sk)
            }
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            KeyPair::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                let sig = signing_key.sign(message);
                Signature::Ed25519(sig.to_bytes().to_vec())
            }
            KeyPair::Bls12381(sk) => {
                let sig = sk.sign(message, &[], &[]);
                Signature::Bls12381(sig.to_bytes().to_vec())
            }
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(signing_key) => {
                PublicKey::Ed25519(signing_key.verifying_key().to_bytes())
            }
            KeyPair::Bls12381(sk) => PublicKey::Bls12381(sk.sk_to_pk().to_bytes().to_vec()),
        }
    }
}

/// A public key for signature verification.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub enum PublicKey {
    /// ED25519 public key (32 bytes).
    Ed25519([u8; 32]),
    /// BLS12-381 public key (48 bytes compressed).
    Bls12381(Vec<u8>),
}

impl PublicKey {
    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (self, signature) {
            (PublicKey::Ed25519(pk_bytes), Signature::Ed25519(sig_bytes)) => {
                use ed25519_dalek::Verifier;
                let pk = match ed25519_dalek::VerifyingKey::from_bytes(pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };
                if sig_bytes.len() != 64 {
                    return false;
                }
                let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => return false,
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
                pk.verify(message, &sig).is_ok()
            }
            (PublicKey::Bls12381(pk_bytes), Signature::Bls12381(sig_bytes)) => {
                let pk = match blst::min_pk::PublicKey::from_bytes(pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };
                let sig = match blst::min_pk::Signature::from_bytes(sig_bytes) {
                    Ok(sig) => sig,
                    Err(_) => return false,
                };
                sig.verify(true, message, &[], &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
            }
            _ => false, // Mismatched types
        }
    }

    /// Batch verify multiple Ed25519 signatures.
    ///
    /// This uses the ed25519-dalek batch verification which is significantly faster
    /// than verifying signatures one at a time (roughly 2x speedup for batches of 64+).
    ///
    /// Returns `true` only if ALL signatures are valid. If any signature is invalid,
    /// returns `false` without indicating which one failed.
    ///
    /// All inputs must be Ed25519 keys/signatures. Returns `false` if any are BLS.
    pub fn batch_verify_ed25519(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[PublicKey],
    ) -> bool {
        if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
            return false;
        }
        if messages.is_empty() {
            return true;
        }

        // Convert to ed25519-dalek types
        let mut dalek_sigs = Vec::with_capacity(signatures.len());
        let mut dalek_pks = Vec::with_capacity(pubkeys.len());

        for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
            match (sig, pk) {
                (Signature::Ed25519(sig_bytes), PublicKey::Ed25519(pk_bytes)) => {
                    if sig_bytes.len() != 64 {
                        return false;
                    }
                    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
                        Ok(arr) => arr,
                        Err(_) => return false,
                    };
                    dalek_sigs.push(ed25519_dalek::Signature::from_bytes(&sig_array));

                    match ed25519_dalek::VerifyingKey::from_bytes(pk_bytes) {
                        Ok(vk) => dalek_pks.push(vk),
                        Err(_) => return false,
                    }
                }
                _ => return false, // Mixed types or BLS
            }
        }

        // Use batch verification
        ed25519_dalek::verify_batch(messages, &dalek_sigs, &dalek_pks).is_ok()
    }

    /// Batch verify multiple BLS signatures over the SAME message.
    ///
    /// This is optimized for the common consensus case where multiple validators
    /// sign the same block hash. Instead of verifying N signatures individually,
    /// we aggregate all signatures and public keys, then do a single pairing check.
    ///
    /// Returns `true` only if ALL signatures are valid.
    ///
    /// All inputs must be BLS keys/signatures. Returns `false` if any are Ed25519.
    pub fn batch_verify_bls_same_message(
        message: &[u8],
        signatures: &[Signature],
        pubkeys: &[PublicKey],
    ) -> bool {
        if signatures.len() != pubkeys.len() {
            return false;
        }
        if signatures.is_empty() {
            return true;
        }

        // For same-message verification, we can aggregate both signatures and keys
        // and do a single verification: e(agg_sig, G2) == e(agg_pk, H(msg))
        let agg_sig = match Signature::aggregate_bls(signatures) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let agg_pk = match PublicKey::aggregate_bls(pubkeys) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        agg_pk.verify(message, &agg_sig)
    }

    /// Batch verify multiple BLS signatures over DIFFERENT messages.
    ///
    /// Uses blst's `verify_multiple_aggregate_signatures` for efficient batch verification.
    /// This uses random linear combination to verify all signatures in ~2 pairing operations
    /// instead of N individual verifications (~1-2ms each).
    ///
    /// Returns `true` only if ALL signatures are valid. If any is invalid, returns `false`.
    /// For identifying which signatures failed, use individual verification as fallback.
    ///
    /// All inputs must be BLS keys/signatures. Returns `false` if any are Ed25519.
    pub fn batch_verify_bls_different_messages_all_or_nothing(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[PublicKey],
    ) -> bool {
        if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
            return false;
        }
        if messages.is_empty() {
            return true;
        }

        // Convert to blst types
        let mut bls_sigs = Vec::with_capacity(signatures.len());
        let mut bls_pks = Vec::with_capacity(pubkeys.len());

        for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
            match (sig, pk) {
                (Signature::Bls12381(sig_bytes), PublicKey::Bls12381(pk_bytes)) => {
                    let sig = match blst::min_pk::Signature::from_bytes(sig_bytes) {
                        Ok(s) => s,
                        Err(_) => return false,
                    };
                    let pk = match blst::min_pk::PublicKey::from_bytes(pk_bytes) {
                        Ok(p) => p,
                        Err(_) => return false,
                    };
                    bls_sigs.push(sig);
                    bls_pks.push(pk);
                }
                _ => return false, // Mixed types or Ed25519
            }
        }

        // Generate random scalars for the linear combination.
        // Using 64 bits of randomness provides 2^-64 probability of false positive.
        // We seed a fast PRNG (ChaCha) from OsRng once, then generate all scalars from it.
        // This avoids N system calls to OsRng which can be slow.
        use rand::SeedableRng;
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let mut rng = rand::rngs::StdRng::from_seed(seed);

        let mut rands = Vec::with_capacity(signatures.len());
        for _ in 0..signatures.len() {
            let mut rand_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut rand_bytes);
            let mut scalar = blst::blst_scalar::default();
            unsafe {
                blst::blst_scalar_from_bendian(&mut scalar, rand_bytes.as_ptr());
            }
            rands.push(scalar);
        }

        // Build reference slices for the blst API
        let sig_refs: Vec<&blst::min_pk::Signature> = bls_sigs.iter().collect();
        let pk_refs: Vec<&blst::min_pk::PublicKey> = bls_pks.iter().collect();

        // Use blst's batch verification with random linear combination.
        // This verifies: ∏ e(r_i * sig_i, G2) == ∏ e(r_i * pk_i, H(msg_i))
        // in ~2 pairings instead of N.
        let result = blst::min_pk::Signature::verify_multiple_aggregate_signatures(
            messages,
            &[], // DST - empty since we don't use domain separation in signing
            &pk_refs,
            false, // pks_validate - already validated above
            &sig_refs,
            true, // sigs_groupcheck - verify signatures are in the group
            &rands,
            64, // rand_bits - 64 bits of randomness
        );

        result == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// Batch verify multiple BLS signatures over DIFFERENT messages.
    ///
    /// Returns a Vec of bools indicating which signatures are valid.
    /// Uses batch verification first (fast path), then falls back to individual
    /// verification only if the batch fails (to identify which ones failed).
    pub fn batch_verify_bls_different_messages(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[PublicKey],
    ) -> Vec<bool> {
        if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
            return vec![false; signatures.len().max(messages.len()).max(pubkeys.len())];
        }
        if messages.is_empty() {
            return vec![];
        }

        // Fast path: try batch verification first
        if Self::batch_verify_bls_different_messages_all_or_nothing(messages, signatures, pubkeys) {
            return vec![true; signatures.len()];
        }

        // Slow path: batch failed, verify individually to find failures
        messages
            .iter()
            .zip(signatures.iter())
            .zip(pubkeys.iter())
            .map(|((msg, sig), pk)| pk.verify(msg, sig))
            .collect()
    }

    /// Aggregate multiple BLS public keys.
    pub fn aggregate_bls(pubkeys: &[PublicKey]) -> Result<Self, AggregateError> {
        if pubkeys.is_empty() {
            return Err(AggregateError::Empty);
        }

        let bls_pks: Vec<_> = pubkeys
            .iter()
            .filter_map(|pk| match pk {
                PublicKey::Bls12381(bytes) => blst::min_pk::PublicKey::from_bytes(bytes).ok(),
                _ => None,
            })
            .collect();

        if bls_pks.len() != pubkeys.len() {
            return Err(AggregateError::MixedTypes);
        }

        let refs: Vec<&blst::min_pk::PublicKey> = bls_pks.iter().collect();
        let agg = blst::min_pk::AggregatePublicKey::aggregate(&refs, false)
            .map_err(|_| AggregateError::AggregationFailed)?;

        Ok(PublicKey::Bls12381(agg.to_public_key().to_bytes().to_vec()))
    }

    /// Get the raw bytes of this public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(bytes) => bytes.as_slice(),
            PublicKey::Bls12381(bytes) => bytes.as_slice(),
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKey::Ed25519(bytes) => {
                write!(f, "PublicKey::Ed25519({})", hex::encode(bytes))
            }
            PublicKey::Bls12381(bytes) => {
                let hex = hex::encode(bytes);
                write!(
                    f,
                    "PublicKey::Bls12381({}..{})",
                    &hex[..8],
                    &hex[hex.len() - 8..]
                )
            }
        }
    }
}

/// A cryptographic signature.
#[derive(Clone, PartialEq, Eq, BasicSbor)]
pub enum Signature {
    /// ED25519 signature (64 bytes).
    Ed25519(Vec<u8>),
    /// BLS12-381 signature (96 bytes compressed).
    Bls12381(Vec<u8>),
}

impl Signature {
    /// Create a zero/placeholder signature for testing.
    pub fn zero() -> Self {
        Signature::Ed25519(vec![0u8; 64])
    }

    /// Get signature as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(bytes) => bytes.to_vec(),
            Signature::Bls12381(bytes) => bytes.clone(),
        }
    }

    /// Get signature as byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Signature::Ed25519(bytes) => bytes.as_slice(),
            Signature::Bls12381(bytes) => bytes.as_slice(),
        }
    }

    /// Aggregate multiple BLS signatures.
    pub fn aggregate_bls(signatures: &[Signature]) -> Result<Self, AggregateError> {
        if signatures.is_empty() {
            return Err(AggregateError::Empty);
        }

        let bls_sigs: Vec<_> = signatures
            .iter()
            .filter_map(|s| match s {
                Signature::Bls12381(bytes) => blst::min_pk::Signature::from_bytes(bytes).ok(),
                _ => None,
            })
            .collect();

        if bls_sigs.len() != signatures.len() {
            return Err(AggregateError::MixedTypes);
        }

        let refs: Vec<&blst::min_pk::Signature> = bls_sigs.iter().collect();
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, true)
            .map_err(|_| AggregateError::AggregationFailed)?;

        Ok(Signature::Bls12381(agg.to_signature().to_bytes().to_vec()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signature::Ed25519(bytes) => {
                write!(f, "Signature::Ed25519({}..)", &hex::encode(bytes)[..16])
            }
            Signature::Bls12381(bytes) => {
                let hex = hex::encode(bytes);
                write!(f, "Signature::Bls12381({}..)", &hex[..16])
            }
        }
    }
}

/// Errors that can occur during aggregation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AggregateError {
    /// Empty list provided.
    #[error("Cannot aggregate empty list")]
    Empty,

    /// Mixed key/signature types.
    #[error("Cannot aggregate mixed types (ED25519 and BLS)")]
    MixedTypes,

    /// Aggregation operation failed.
    #[error("Aggregation failed")]
    AggregationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = KeyPair::generate_ed25519();
        let message = b"test message";

        let signature = keypair.sign(message);
        let pubkey = keypair.public_key();

        assert!(pubkey.verify(message, &signature));
    }

    #[test]
    fn test_ed25519_verify_fails_wrong_message() {
        let keypair = KeyPair::generate_ed25519();
        let message = b"test message";
        let wrong = b"wrong message";

        let signature = keypair.sign(message);
        let pubkey = keypair.public_key();

        assert!(!pubkey.verify(wrong, &signature));
    }

    #[test]
    fn test_bls_sign_verify() {
        let keypair = KeyPair::generate_bls();
        let message = b"test message";

        let signature = keypair.sign(message);
        let pubkey = keypair.public_key();

        assert!(pubkey.verify(message, &signature));
    }

    #[test]
    fn test_bls_aggregate_signatures() {
        let message = b"block hash";

        let keypair1 = KeyPair::generate_bls();
        let keypair2 = KeyPair::generate_bls();
        let keypair3 = KeyPair::generate_bls();

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        let sig3 = keypair3.sign(message);

        let agg_sig = Signature::aggregate_bls(&[sig1, sig2, sig3]).unwrap();

        let pubkeys = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];
        let agg_pubkey = PublicKey::aggregate_bls(&pubkeys).unwrap();

        assert!(agg_pubkey.verify(message, &agg_sig));
    }

    #[test]
    fn test_hyperscale_keypair_from_seed() {
        let seed = [42u8; 32];

        let kp1 = KeyPair::from_seed(KeyType::Ed25519, &seed);
        let kp2 = KeyPair::from_seed(KeyType::Ed25519, &seed);

        let msg = b"test";
        assert_eq!(kp1.sign(msg).to_bytes(), kp2.sign(msg).to_bytes());
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_batch_verify_ed25519() {
        let kp1 = KeyPair::generate_ed25519();
        let kp2 = KeyPair::generate_ed25519();
        let kp3 = KeyPair::generate_ed25519();

        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(msg2);
        let sig3 = kp3.sign(msg3);

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        assert!(PublicKey::batch_verify_ed25519(
            &messages,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_ed25519_fails_with_bad_signature() {
        let kp1 = KeyPair::generate_ed25519();
        let kp2 = KeyPair::generate_ed25519();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(b"wrong message"); // Sign wrong message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!PublicKey::batch_verify_ed25519(
            &messages,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_ed25519_empty() {
        let messages: Vec<&[u8]> = vec![];
        let signatures: Vec<Signature> = vec![];
        let pubkeys: Vec<PublicKey> = vec![];

        assert!(PublicKey::batch_verify_ed25519(
            &messages,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_bls_same_message() {
        let message = b"consensus block hash";

        let kp1 = KeyPair::generate_bls();
        let kp2 = KeyPair::generate_bls();
        let kp3 = KeyPair::generate_bls();

        let sig1 = kp1.sign(message);
        let sig2 = kp2.sign(message);
        let sig3 = kp3.sign(message);

        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        assert!(PublicKey::batch_verify_bls_same_message(
            message,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_bls_same_message_fails_with_bad_signature() {
        let message = b"consensus block hash";

        let kp1 = KeyPair::generate_bls();
        let kp2 = KeyPair::generate_bls();

        let sig1 = kp1.sign(message);
        let sig2 = kp2.sign(b"different message"); // Wrong message

        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!PublicKey::batch_verify_bls_same_message(
            message,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_bls_different_messages() {
        let kp1 = KeyPair::generate_bls();
        let kp2 = KeyPair::generate_bls();
        let kp3 = KeyPair::generate_bls();

        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(msg2);
        let sig3 = kp3.sign(msg3);

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let results =
            PublicKey::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);
        assert_eq!(results, vec![true, true, true]);
    }

    #[test]
    fn test_batch_verify_bls_different_messages_partial_failure() {
        let kp1 = KeyPair::generate_bls();
        let kp2 = KeyPair::generate_bls();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(b"wrong"); // Wrong message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        let results =
            PublicKey::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);
        assert_eq!(results, vec![true, false]);
    }
}
