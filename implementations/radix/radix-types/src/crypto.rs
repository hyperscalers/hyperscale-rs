//! Ed25519 cryptographic types and helpers.
//!
//! Re-exported from `radix_common::crypto`.

pub use radix_common::crypto::{
    verify_ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};

/// Generate a new random Ed25519 keypair.
pub fn generate_ed25519_keypair() -> Ed25519PrivateKey {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()).expect("valid key bytes")
}

/// Generate an Ed25519 keypair from a seed (deterministic, for testing/simulation).
pub fn ed25519_keypair_from_seed(seed: &[u8; 32]) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(seed).expect("valid seed bytes")
}

/// Create a zero/placeholder Ed25519 signature for testing.
pub fn zero_ed25519_signature() -> Ed25519Signature {
    Ed25519Signature([0u8; 64])
}

/// Batch verify multiple Ed25519 signatures.
pub fn batch_verify_ed25519(
    messages: &[&[u8]],
    signatures: &[Ed25519Signature],
    pubkeys: &[Ed25519PublicKey],
) -> bool {
    if messages.len() != signatures.len() || signatures.len() != pubkeys.len() {
        return false;
    }
    if messages.is_empty() {
        return true;
    }

    let mut dalek_sigs = Vec::with_capacity(signatures.len());
    let mut dalek_pks = Vec::with_capacity(pubkeys.len());

    for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
        dalek_sigs.push(ed25519_dalek::Signature::from_bytes(&sig.0));

        match ed25519_dalek::VerifyingKey::from_bytes(&pk.0) {
            Ok(vk) => dalek_pks.push(vk),
            Err(_) => return false,
        }
    }

    ed25519_dalek::verify_batch(messages, &dalek_sigs, &dalek_pks).is_ok()
}
