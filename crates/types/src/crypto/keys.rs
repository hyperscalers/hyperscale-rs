//! Key generation, deterministic seeding, and zero-signature placeholders.

use radix_common::crypto::{
    Bls12381G1PrivateKey, Bls12381G2Signature, Ed25519PrivateKey, Ed25519Signature,
};
use rand::Rng;

/// Generate a new random Ed25519 keypair.
///
/// # Panics
///
/// Cannot panic: any 32 bytes form a valid Ed25519 private key.
#[must_use]
pub fn generate_ed25519_keypair() -> Ed25519PrivateKey {
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    Ed25519PrivateKey::from_bytes(&secret).expect("valid key bytes")
}

/// Generate a new random BLS12-381 keypair.
///
/// Uses a random 32-byte seed with blst's `key_gen` for proper key derivation.
#[must_use]
pub fn generate_bls_keypair() -> Bls12381G1PrivateKey {
    let mut ikm = [0u8; 32];
    rand::rng().fill_bytes(&mut ikm);
    bls_keypair_from_seed(&ikm)
}

/// Generate an Ed25519 keypair from a seed (deterministic, for testing/simulation).
///
/// # Panics
///
/// Cannot panic: any 32 bytes form a valid Ed25519 private key.
#[must_use]
pub fn ed25519_keypair_from_seed(seed: &[u8; 32]) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(seed).expect("valid seed bytes")
}

/// Generate a BLS12-381 keypair from a seed (deterministic, for testing/simulation).
///
/// Uses blst's `key_gen` which hashes the full seed to derive a valid BLS scalar.
/// This is the proper way to deterministically generate BLS keys from arbitrary seeds.
///
/// # Panics
///
/// Cannot panic: `blst::min_pk::SecretKey::key_gen` succeeds for any 32-byte seed.
#[must_use]
pub fn bls_keypair_from_seed(seed: &[u8; 32]) -> Bls12381G1PrivateKey {
    // Use blst's key_gen which properly hashes the seed to derive a valid scalar
    let blst_sk = blst::min_pk::SecretKey::key_gen(seed, &[]).expect("key_gen should not fail");

    // Convert to radix-common type
    // blst secret key is a 32-byte scalar in big-endian format
    let sk_bytes = blst_sk.to_bytes();
    Bls12381G1PrivateKey::from_bytes(&sk_bytes).expect("valid BLS scalar bytes")
}

/// Create a zero/placeholder Ed25519 signature for testing.
#[must_use]
pub const fn zero_ed25519_signature() -> Ed25519Signature {
    Ed25519Signature([0u8; 64])
}

/// Create a zero/placeholder BLS signature for testing.
#[must_use]
pub const fn zero_bls_signature() -> Bls12381G2Signature {
    Bls12381G2Signature([0u8; 96])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_from_seed() {
        let seed = [42u8; 32];

        let kp1 = ed25519_keypair_from_seed(&seed);
        let kp2 = ed25519_keypair_from_seed(&seed);

        let msg = b"test";
        assert_eq!(kp1.sign(msg).0, kp2.sign(msg).0);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_bls_keypair_from_seed() {
        // Same seed should produce same key
        let seed = [42u8; 32];
        let kp1 = bls_keypair_from_seed(&seed);
        let kp2 = bls_keypair_from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());

        // Different seeds should produce different keys
        let mut seed2 = [0u8; 32];
        seed2[31] = 1; // Only differ in last byte
        let kp3 = bls_keypair_from_seed(&seed2);
        assert_ne!(kp1.public_key(), kp3.public_key());

        // Seeds with zeros in first 8 bytes but different later should still differ
        // (This was the bug: only first 8 bytes were used)
        let mut seed_a = [0u8; 32];
        seed_a[30] = 0x30; // "09" at end (like validator 0)
        seed_a[31] = 0x39;

        let mut seed_b = [0u8; 32];
        seed_b[30] = 0x30; // "0:" at end (like validator 1)
        seed_b[31] = 0x3a;

        let kp_a = bls_keypair_from_seed(&seed_a);
        let kp_b = bls_keypair_from_seed(&seed_b);
        assert_ne!(
            kp_a.public_key(),
            kp_b.public_key(),
            "Keys should differ even when first 8 bytes are identical"
        );
    }
}
