//! Simple tool to generate validator keys and print public keys.
//!
//! Usage:
//!   keygen <seed_hex>      - Print BLS public key for given 32-byte seed (hex)
//!   keygen --generate      - Generate new random BLS keypair and print

use hyperscale_types::{KeyPair, KeyType, PublicKey};
use sha2::{Digest, Sha256};
use std::env;

const LIBP2P_IDENTITY_DOMAIN: &[u8] = b"hyperscale-libp2p-identity-v1:";

/// Derive a libp2p Ed25519 keypair deterministically from a validator's public key.
fn derive_libp2p_keypair(public_key: &PublicKey) -> libp2p::identity::Keypair {
    let public_bytes = public_key.as_bytes();

    // Domain-separated hash to derive a seed
    let mut hasher = Sha256::new();
    hasher.update(LIBP2P_IDENTITY_DOMAIN);
    hasher.update(public_bytes);
    let derived_seed: [u8; 32] = hasher.finalize().into();

    // Create an Ed25519 keypair from the derived seed using libp2p's SecretKey type
    let secret_key = libp2p::identity::ed25519::SecretKey::try_from_bytes(derived_seed)
        .expect("valid ed25519 secret key from derived seed");

    libp2p::identity::Keypair::from(libp2p::identity::ed25519::Keypair::from(secret_key))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: keygen <seed_hex> | keygen --generate");
        std::process::exit(1);
    }

    if args[1] == "--generate" {
        // Generate random BLS keypair
        let keypair = KeyPair::generate_bls();
        let public_key = keypair.public_key();

        if let PublicKey::Bls12381(bytes) = public_key {
            println!("{}", hex::encode(bytes));
        }
    } else {
        // Derive BLS keypair from seed
        let seed_hex = &args[1];
        let seed_bytes = hex::decode(seed_hex).expect("Invalid hex seed");

        if seed_bytes.len() != 32 {
            eprintln!("Seed must be 32 bytes (64 hex chars)");
            std::process::exit(1);
        }

        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let keypair = KeyPair::from_seed(KeyType::Bls12381, &seed);
        let public_key = keypair.public_key();
        
        // Derive PeerId
        let libp2p_keypair = derive_libp2p_keypair(&public_key);
        let peer_id = libp2p::PeerId::from_public_key(&libp2p_keypair.public());

        // Print: public_key_hex peer_id_string
        if let PublicKey::Bls12381(bytes) = public_key {
            println!("{} {}", hex::encode(bytes), peer_id.to_base58());
        }
    }
}
