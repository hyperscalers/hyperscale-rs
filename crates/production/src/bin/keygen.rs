//! Simple tool to generate validator keys and print public keys.
//!
//! Usage:
//!   keygen <seed_hex>      - Print BLS public key for given 32-byte seed (hex)
//!   keygen --generate      - Generate new random BLS keypair and print

use hyperscale_types::{KeyPair, KeyType, PublicKey};
use std::env;

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

        // Just print the public key (for script consumption)
        if let PublicKey::Bls12381(bytes) = public_key {
            println!("{}", hex::encode(bytes));
        }
    }
}
