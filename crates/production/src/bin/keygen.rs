//! Simple tool to generate validator keys and print public keys.
//!
//! Usage:
//!   `keygen <seed_hex>`             - Print BLS public key for given 32-byte seed (hex)
//!   `keygen --generate`             - Generate new random BLS keypair and print
//!   `keygen --network-key <path>`   - Print the endpoint id of the network key at
//!                                     `path`, generating the key there if absent

use std::env;
use std::path::Path;

use hex::{decode, encode};
use hyperscale_crypto_bls::{bls_keypair_from_seed, generate_bls_keypair};
use hyperscale_network_iroh::load_or_generate_secret_key;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: keygen <seed_hex> | keygen --generate | keygen --network-key <path>");
        std::process::exit(1);
    }

    if args[1] == "--network-key" {
        let Some(path) = args.get(2) else {
            eprintln!("Usage: keygen --network-key <path>");
            std::process::exit(1);
        };
        match load_or_generate_secret_key(Path::new(path)) {
            Ok(key) => println!("{}", key.public()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } else if args[1] == "--generate" {
        // Generate random BLS keypair
        let keypair = generate_bls_keypair();
        let public_key = keypair.public_key();
        let bytes = public_key.0;
        println!("{}", encode(bytes));
    } else {
        // Derive BLS keypair from seed
        let seed_hex = &args[1];
        let seed_bytes = decode(seed_hex).expect("Invalid hex seed");

        if seed_bytes.len() != 32 {
            eprintln!("Seed must be 32 bytes (64 hex chars)");
            std::process::exit(1);
        }

        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let keypair = bls_keypair_from_seed(&seed);
        let public_key = keypair.public_key();

        // Print BLS public key hex
        let bytes = public_key.0;
        println!("{}", encode(bytes));
    }
}
