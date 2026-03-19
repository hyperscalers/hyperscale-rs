//! Framework-owned BLS12-381 cryptographic types.
//!
//! These types replace the `radix_common::crypto` BLS re-exports with framework-owned
//! newtypes backed directly by the `blst` crate. The wire format is identical
//! (`#[sbor(transparent)]` over raw byte arrays), so no storage migration is needed.

use std::fmt;
use std::str::FromStr;

use hyperscale_codec as sbor;

use blst::min_pk;

/// BLS12-381 ciphersuite for signatures (hash-to-curve DST).
///
/// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
pub const BLS12381_CIPHERSUITE_V1: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// ── Error type ──────────────────────────────────────────────────────

/// Unified error type for BLS operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlsError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("no keys/signatures provided")]
    EmptyInput,
}

// ── Public Key ──────────────────────────────────────────────────────

/// BLS12-381 G1 public key (48 bytes, compressed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, sbor::prelude::BasicSbor)]
#[sbor(transparent)]
pub struct Bls12381G1PublicKey(pub [u8; Self::LENGTH]);

impl Bls12381G1PublicKey {
    pub const LENGTH: usize = 48;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Aggregate multiple public keys into one.
    pub fn aggregate(keys: &[Self], validate: bool) -> Result<Self, BlsError> {
        if keys.is_empty() {
            return Err(BlsError::EmptyInput);
        }
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.0.as_slice()).collect();
        let agg = min_pk::AggregatePublicKey::aggregate_serialized(&refs, validate)
            .map_err(|e| BlsError::InvalidPublicKey(format!("{e:?}")))?;
        Ok(Self(agg.to_public_key().to_bytes()))
    }
}

impl fmt::Display for Bls12381G1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Bls12381G1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Bls12381G1PublicKey {
    type Err = BlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| BlsError::InvalidHex(e.to_string()))?;
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Bls12381G1PublicKey {
    type Error = BlsError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; Self::LENGTH] = slice.try_into().map_err(|_| BlsError::InvalidLength {
            expected: Self::LENGTH,
            actual: slice.len(),
        })?;
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for Bls12381G1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<Self> for Bls12381G1PublicKey {
    fn as_ref(&self) -> &Self {
        self
    }
}

// ── Signature ───────────────────────────────────────────────────────

/// BLS12-381 G2 signature (96 bytes, compressed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, sbor::prelude::BasicSbor)]
#[sbor(transparent)]
pub struct Bls12381G2Signature(pub [u8; Self::LENGTH]);

impl Bls12381G2Signature {
    pub const LENGTH: usize = 96;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Aggregate multiple signatures into one.
    pub fn aggregate(sigs: &[Self], validate: bool) -> Result<Self, BlsError> {
        if sigs.is_empty() {
            return Err(BlsError::EmptyInput);
        }
        let refs: Vec<&[u8]> = sigs.iter().map(|s| s.0.as_slice()).collect();
        let agg = min_pk::AggregateSignature::aggregate_serialized(&refs, validate)
            .map_err(|e| BlsError::InvalidSignature(format!("{e:?}")))?;
        Ok(Self(agg.to_signature().to_bytes()))
    }
}

impl fmt::Display for Bls12381G2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Bls12381G2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Bls12381G2Signature {
    type Err = BlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| BlsError::InvalidHex(e.to_string()))?;
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Bls12381G2Signature {
    type Error = BlsError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; Self::LENGTH] = slice.try_into().map_err(|_| BlsError::InvalidLength {
            expected: Self::LENGTH,
            actual: slice.len(),
        })?;
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for Bls12381G2Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<Self> for Bls12381G2Signature {
    fn as_ref(&self) -> &Self {
        self
    }
}

// ── Private Key ─────────────────────────────────────────────────────

/// BLS12-381 G1 private key (not serializable).
pub struct Bls12381G1PrivateKey(min_pk::SecretKey);

impl Bls12381G1PrivateKey {
    pub const LENGTH: usize = 32;

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Bls12381G1PublicKey {
        Bls12381G1PublicKey(self.0.sk_to_pk().to_bytes())
    }

    /// Sign a message using BLS12-381 with the v1 ciphersuite.
    pub fn sign_v1(&self, message: &[u8]) -> Bls12381G2Signature {
        let signature = self
            .0
            .sign(message, BLS12381_CIPHERSUITE_V1, &[])
            .to_bytes();
        Bls12381G2Signature(signature)
    }

    /// Deserialize a private key from raw bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != Self::LENGTH {
            return Err(BlsError::InvalidLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }
        let sk = min_pk::SecretKey::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidPublicKey(format!("{e:?}")))?;
        Ok(Self(sk))
    }

    /// Serialize the private key to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

// ── Standalone functions ────────────────────────────────────────────

/// Verify a BLS12-381 signature.
pub fn verify_bls12381_v1(
    message: &[u8],
    public_key: &Bls12381G1PublicKey,
    signature: &Bls12381G2Signature,
) -> bool {
    let sig = match min_pk::Signature::from_bytes(&signature.0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = match min_pk::PublicKey::from_bytes(&public_key.0) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let result = sig.verify(true, message, BLS12381_CIPHERSUITE_V1, &[], &pk, true);
    result == blst::BLST_ERROR::BLST_SUCCESS
}

/// Generate a BLS12-381 keypair from a 32-byte seed (deterministic).
pub fn bls_keypair_from_seed(seed: &[u8; 32]) -> Bls12381G1PrivateKey {
    let blst_sk = min_pk::SecretKey::key_gen(seed, &[]).expect("key_gen should not fail");
    Bls12381G1PrivateKey(blst_sk)
}

/// Generate a random BLS12-381 keypair.
pub fn generate_bls_keypair() -> Bls12381G1PrivateKey {
    let mut ikm = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ikm);
    bls_keypair_from_seed(&ikm)
}

/// Create a zero/placeholder BLS signature for testing.
pub fn zero_bls_signature() -> Bls12381G2Signature {
    Bls12381G2Signature([0u8; 96])
}

// ── Batch verification ──────────────────────────────────────────────

/// Batch verify multiple BLS signatures over the SAME message.
///
/// Aggregates all signatures and public keys, then does a single pairing check.
pub fn batch_verify_bls_same_message(
    message: &[u8],
    signatures: &[Bls12381G2Signature],
    pubkeys: &[Bls12381G1PublicKey],
) -> bool {
    if signatures.len() != pubkeys.len() {
        return false;
    }
    if signatures.is_empty() {
        return true;
    }

    let agg_sig = match Bls12381G2Signature::aggregate(signatures, true) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let agg_pk = match Bls12381G1PublicKey::aggregate(pubkeys, false) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    verify_bls12381_v1(message, &agg_pk, &agg_sig)
}

/// Batch verify multiple BLS signatures over DIFFERENT messages (all-or-nothing).
///
/// Uses blst's `verify_multiple_aggregate_signatures` for efficient batch verification
/// with random linear combination (~2 pairing operations instead of N).
pub fn batch_verify_bls_different_messages_all_or_nothing(
    messages: &[&[u8]],
    signatures: &[Bls12381G2Signature],
    pubkeys: &[Bls12381G1PublicKey],
) -> bool {
    if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
        return false;
    }
    if messages.is_empty() {
        return true;
    }

    let mut bls_sigs = Vec::with_capacity(signatures.len());
    let mut bls_pks = Vec::with_capacity(pubkeys.len());

    for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
        let sig = match min_pk::Signature::from_bytes(&sig.0) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pk = match min_pk::PublicKey::from_bytes(&pk.0) {
            Ok(p) => p,
            Err(_) => return false,
        };
        bls_sigs.push(sig);
        bls_pks.push(pk);
    }

    // Generate random scalars for the linear combination
    use rand::SeedableRng;
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let mut rands = Vec::with_capacity(signatures.len());
    for _ in 0..signatures.len() {
        let mut rand_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut rand_bytes);
        let mut scalar = blst::blst_scalar::default();
        // SAFETY: `scalar` is a valid `blst_scalar` (zero-initialised above) and
        // `rand_bytes` is a 32-byte array whose pointer is valid for 32 bytes.
        // `blst_scalar_from_bendian` reads exactly 32 bytes from the pointer.
        unsafe {
            blst::blst_scalar_from_bendian(&mut scalar, rand_bytes.as_ptr());
        }
        rands.push(scalar);
    }

    let sig_refs: Vec<&min_pk::Signature> = bls_sigs.iter().collect();
    let pk_refs: Vec<&min_pk::PublicKey> = bls_pks.iter().collect();

    let result = min_pk::Signature::verify_multiple_aggregate_signatures(
        messages,
        BLS12381_CIPHERSUITE_V1,
        &pk_refs,
        false,
        &sig_refs,
        true,
        &rands,
        64,
    );

    result == blst::BLST_ERROR::BLST_SUCCESS
}

/// Batch verify multiple BLS signatures over DIFFERENT messages.
///
/// Returns a `Vec<bool>` indicating which signatures are valid.
/// Uses batch verification first (fast path), then falls back to individual
/// verification only if the batch fails.
pub fn batch_verify_bls_different_messages(
    messages: &[&[u8]],
    signatures: &[Bls12381G2Signature],
    pubkeys: &[Bls12381G1PublicKey],
) -> Vec<bool> {
    if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
        return vec![false; signatures.len().max(messages.len()).max(pubkeys.len())];
    }
    if messages.is_empty() {
        return vec![];
    }

    // Fast path: try batch verification first
    if batch_verify_bls_different_messages_all_or_nothing(messages, signatures, pubkeys) {
        return vec![true; signatures.len()];
    }

    // Slow path: batch failed, verify individually to find failures
    messages
        .iter()
        .zip(signatures.iter())
        .zip(pubkeys.iter())
        .map(|((msg, sig), pk)| verify_bls12381_v1(msg, pk, sig))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let kp = generate_bls_keypair();
        let msg = b"test message";
        let sig = kp.sign_v1(msg);
        assert!(verify_bls12381_v1(msg, &kp.public_key(), &sig));
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = generate_bls_keypair();
        let sig = kp.sign_v1(b"correct");
        assert!(!verify_bls12381_v1(b"wrong", &kp.public_key(), &sig));
    }

    #[test]
    fn test_aggregate_signatures() {
        let msg = b"block hash";
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();

        let agg_sig =
            Bls12381G2Signature::aggregate(&[kp1.sign_v1(msg), kp2.sign_v1(msg)], true).unwrap();
        let agg_pk =
            Bls12381G1PublicKey::aggregate(&[kp1.public_key(), kp2.public_key()], true).unwrap();

        assert!(verify_bls12381_v1(msg, &agg_pk, &agg_sig));
    }

    #[test]
    fn test_keypair_from_seed_deterministic() {
        let seed = [42u8; 32];
        let kp1 = bls_keypair_from_seed(&seed);
        let kp2 = bls_keypair_from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_keypair_from_seed_different_seeds() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        assert_ne!(
            bls_keypair_from_seed(&seed1).public_key(),
            bls_keypair_from_seed(&seed2).public_key()
        );
    }

    #[test]
    fn test_private_key_roundtrip() {
        let kp = generate_bls_keypair();
        let bytes = kp.to_bytes();
        let kp2 = Bls12381G1PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn test_public_key_display_fromstr() {
        let kp = generate_bls_keypair();
        let pk = kp.public_key();
        let s = pk.to_string();
        let pk2: Bls12381G1PublicKey = s.parse().unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_signature_display_fromstr() {
        let kp = generate_bls_keypair();
        let sig = kp.sign_v1(b"msg");
        let s = sig.to_string();
        let sig2: Bls12381G2Signature = s.parse().unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_public_key_try_from_slice() {
        let kp = generate_bls_keypair();
        let pk = kp.public_key();
        let pk2 = Bls12381G1PublicKey::try_from(pk.0.as_slice()).unwrap();
        assert_eq!(pk, pk2);

        // Wrong length
        assert!(Bls12381G1PublicKey::try_from([0u8; 10].as_slice()).is_err());
    }

    #[test]
    fn test_zero_signature() {
        let sig = zero_bls_signature();
        assert_eq!(sig.0, [0u8; 96]);
    }

    #[test]
    fn test_sbor_roundtrip_public_key() {
        let kp = generate_bls_keypair();
        let pk = kp.public_key();
        let encoded = sbor::prelude::basic_encode(&pk).unwrap();
        let decoded: Bls12381G1PublicKey = sbor::prelude::basic_decode(&encoded).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_signature() {
        let kp = generate_bls_keypair();
        let sig = kp.sign_v1(b"msg");
        let encoded = sbor::prelude::basic_encode(&sig).unwrap();
        let decoded: Bls12381G2Signature = sbor::prelude::basic_decode(&encoded).unwrap();
        assert_eq!(sig, decoded);
    }
}
