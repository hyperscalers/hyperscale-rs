//! Deterministic PeerId derivation from validator public keys.

use hyperscale_types::Bls12381G1PublicKey;
use libp2p::{identity, PeerId as Libp2pPeerId};

/// Domain separator for deriving libp2p identity from validator public key.
const LIBP2P_IDENTITY_DOMAIN: &[u8] = b"hyperscale-libp2p-identity-v1:";

/// Derive a libp2p Ed25519 keypair deterministically from a validator's public key.
///
/// This ensures that each validator's PeerId is deterministic and can be computed
/// by other validators from the known public key. This enables peer validation
/// at the network layer.
///
/// The derivation:
/// 1. Hash the public key bytes with a domain separator
/// 2. Use the hash as a seed to derive an Ed25519 keypair
///
/// IMPORTANT: The derivation is based on the PUBLIC key, not the secret key.
/// This allows other validators to compute any validator's PeerId from their
/// known public key.
pub fn derive_libp2p_keypair(public_key: &Bls12381G1PublicKey) -> identity::Keypair {
    use sha2::{Digest, Sha256};

    let public_bytes = public_key.to_vec();

    // Domain-separated hash to derive a seed
    let mut hasher = Sha256::new();
    hasher.update(LIBP2P_IDENTITY_DOMAIN);
    hasher.update(public_bytes);
    let derived_seed: [u8; 32] = hasher.finalize().into();

    // Create an Ed25519 keypair from the derived seed using libp2p's SecretKey type
    let secret_key = identity::ed25519::SecretKey::try_from_bytes(derived_seed)
        .expect("valid ed25519 secret key from derived seed");

    identity::Keypair::from(identity::ed25519::Keypair::from(secret_key))
}

/// Compute the libp2p PeerId for a validator from their signing public key.
///
/// This is a convenience wrapper around `derive_libp2p_keypair` that returns
/// just the PeerId.
pub fn compute_peer_id_for_validator(public_key: &Bls12381G1PublicKey) -> Libp2pPeerId {
    derive_libp2p_keypair(public_key).public().to_peer_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key(seed: u8) -> Bls12381G1PublicKey {
        let mut bytes = [0u8; Bls12381G1PublicKey::LENGTH];
        bytes[0] = seed;
        bytes[1] = seed.wrapping_mul(7);
        Bls12381G1PublicKey(bytes)
    }

    #[test]
    fn test_derive_keypair_deterministic() {
        let key = make_test_key(1);
        let peer_id_1 = derive_libp2p_keypair(&key).public().to_peer_id();
        let peer_id_2 = derive_libp2p_keypair(&key).public().to_peer_id();
        assert_eq!(peer_id_1, peer_id_2);
    }

    #[test]
    fn test_derive_keypair_different_keys_differ() {
        let key_a = make_test_key(1);
        let key_b = make_test_key(2);
        let peer_a = derive_libp2p_keypair(&key_a).public().to_peer_id();
        let peer_b = derive_libp2p_keypair(&key_b).public().to_peer_id();
        assert_ne!(peer_a, peer_b);
    }

    #[test]
    fn test_compute_peer_id_matches_derivation() {
        let key = make_test_key(42);
        let from_compute = compute_peer_id_for_validator(&key);
        let from_derive = derive_libp2p_keypair(&key).public().to_peer_id();
        assert_eq!(from_compute, from_derive);
    }

    #[test]
    fn test_derive_produces_valid_ed25519() {
        let key = make_test_key(99);
        let keypair = derive_libp2p_keypair(&key);
        // Should be an Ed25519 key — verify we can get a PeerId from it
        let peer_id = keypair.public().to_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }
}
