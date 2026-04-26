//! Batch verification helpers for Ed25519 and BLS12-381 signatures.

use radix_common::crypto::{
    BLS12381_CIPHERSITE_V1, Bls12381G1PublicKey, Bls12381G2Signature, Ed25519PublicKey,
    Ed25519Signature, verify_bls12381_v1,
};
use rand::{Rng, SeedableRng};

/// Batch verify multiple Ed25519 signatures.
///
/// This uses the ed25519-dalek batch verification which is significantly faster
/// than verifying signatures one at a time (roughly 2x speedup for batches of 64+).
///
/// Returns `true` only if ALL signatures are valid. If any signature is invalid,
/// returns `false` without indicating which one failed.
#[must_use]
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

    // Convert to ed25519-dalek types
    let mut dalek_sigs = Vec::with_capacity(signatures.len());
    let mut dalek_pks = Vec::with_capacity(pubkeys.len());

    for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
        dalek_sigs.push(ed25519_dalek::Signature::from_bytes(&sig.0));

        match ed25519_dalek::VerifyingKey::from_bytes(&pk.0) {
            Ok(vk) => dalek_pks.push(vk),
            Err(_) => return false,
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
#[must_use]
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

    // Aggregate signatures (validate to catch malformed sigs)
    let Ok(agg_sig) = Bls12381G2Signature::aggregate(signatures, true) else {
        return false;
    };

    // Aggregate public keys (skip validation - keys come from trusted topology)
    let Ok(agg_pk) = Bls12381G1PublicKey::aggregate(pubkeys, false) else {
        return false;
    };

    // Single verification of aggregated sig against aggregated key
    verify_bls12381_v1(message, &agg_pk, &agg_sig)
}

/// Batch verify multiple BLS signatures over DIFFERENT messages (all-or-nothing).
///
/// Uses blst's `verify_multiple_aggregate_signatures` for efficient batch verification.
/// This uses random linear combination to verify all signatures in ~2 pairing operations
/// instead of N individual verifications.
///
/// Returns `true` only if ALL signatures are valid. If any is invalid, returns `false`.
#[must_use]
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

    // Convert to blst types
    let mut bls_sigs = Vec::with_capacity(signatures.len());
    let mut bls_pks = Vec::with_capacity(pubkeys.len());

    for (sig, pk) in signatures.iter().zip(pubkeys.iter()) {
        let Ok(sig) = blst::min_pk::Signature::from_bytes(&sig.0) else {
            return false;
        };
        let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk.0) else {
            return false;
        };
        bls_sigs.push(sig);
        bls_pks.push(pk);
    }

    // Generate random scalars for the linear combination
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let mut rands = Vec::with_capacity(signatures.len());
    for _ in 0..signatures.len() {
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let mut scalar = blst::blst_scalar::default();
        // SAFETY: `scalar` is a valid `blst_scalar` (zero-initialised above) and
        // `rand_bytes` is a 32-byte array whose pointer is valid for 32 bytes.
        // `blst_scalar_from_bendian` reads exactly 32 bytes from the pointer.
        unsafe {
            blst::blst_scalar_from_bendian(&raw mut scalar, rand_bytes.as_ptr());
        }
        rands.push(scalar);
    }

    // Build reference slices for the blst API
    let sig_refs: Vec<&blst::min_pk::Signature> = bls_sigs.iter().collect();
    let pk_refs: Vec<&blst::min_pk::PublicKey> = bls_pks.iter().collect();

    // Use blst's batch verification with random linear combination
    let result = blst::min_pk::Signature::verify_multiple_aggregate_signatures(
        messages,
        BLS12381_CIPHERSITE_V1, // DST must match sign_v1/verify_bls12381_v1
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
#[must_use]
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
    use crate::{generate_bls_keypair, generate_ed25519_keypair, verify_ed25519};

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = generate_ed25519_keypair();
        let message = b"test message";

        let signature = keypair.sign(message);
        let pubkey = keypair.public_key();

        assert!(verify_ed25519(message, &pubkey, &signature));
    }

    #[test]
    fn test_ed25519_verify_fails_wrong_message() {
        let keypair = generate_ed25519_keypair();
        let message = b"test message";
        let wrong = b"wrong message";

        let signature = keypair.sign(message);
        let pubkey = keypair.public_key();

        assert!(!verify_ed25519(wrong, &pubkey, &signature));
    }

    #[test]
    fn test_bls_sign_verify() {
        let keypair = generate_bls_keypair();
        let message = b"test message";

        let signature = keypair.sign_v1(message);
        let pubkey = keypair.public_key();

        assert!(verify_bls12381_v1(message, &pubkey, &signature));
    }

    #[test]
    fn test_bls_aggregate_signatures() {
        let message = b"block hash";

        let keypair1 = generate_bls_keypair();
        let keypair2 = generate_bls_keypair();
        let keypair3 = generate_bls_keypair();

        let sig1 = keypair1.sign_v1(message);
        let sig2 = keypair2.sign_v1(message);
        let sig3 = keypair3.sign_v1(message);

        let agg_sig = Bls12381G2Signature::aggregate(&[sig1, sig2, sig3], true).unwrap();

        let pubkeys = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];
        let agg_pubkey = Bls12381G1PublicKey::aggregate(&pubkeys, true).unwrap();

        assert!(verify_bls12381_v1(message, &agg_pubkey, &agg_sig));
    }

    #[test]
    fn test_batch_verify_ed25519() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();
        let kp3 = generate_ed25519_keypair();

        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(msg2);
        let sig3 = kp3.sign(msg3);

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        assert!(batch_verify_ed25519(&messages, &signatures, &pubkeys));
    }

    #[test]
    fn test_batch_verify_ed25519_fails_with_bad_signature() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(b"wrong message"); // Sign wrong message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!batch_verify_ed25519(&messages, &signatures, &pubkeys));
    }

    #[test]
    fn test_batch_verify_ed25519_empty() {
        let messages: Vec<&[u8]> = vec![];
        let signatures: Vec<Ed25519Signature> = vec![];
        let pubkeys: Vec<Ed25519PublicKey> = vec![];

        assert!(batch_verify_ed25519(&messages, &signatures, &pubkeys));
    }

    #[test]
    fn test_batch_verify_bls_same_message() {
        let message = b"consensus block hash";

        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();
        let kp3 = generate_bls_keypair();

        let sig1 = kp1.sign_v1(message);
        let sig2 = kp2.sign_v1(message);
        let sig3 = kp3.sign_v1(message);

        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        assert!(batch_verify_bls_same_message(
            message,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_bls_same_message_fails_with_bad_signature() {
        let message = b"consensus block hash";

        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();

        let sig1 = kp1.sign_v1(message);
        let sig2 = kp2.sign_v1(b"different message"); // Wrong message

        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!batch_verify_bls_same_message(
            message,
            &signatures,
            &pubkeys
        ));
    }

    #[test]
    fn test_batch_verify_bls_different_messages() {
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();
        let kp3 = generate_bls_keypair();

        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = kp1.sign_v1(msg1);
        let sig2 = kp2.sign_v1(msg2);
        let sig3 = kp3.sign_v1(msg3);

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let results = batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);
        assert_eq!(results, vec![true, true, true]);
    }

    #[test]
    fn test_batch_verify_bls_different_messages_partial_failure() {
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let sig1 = kp1.sign_v1(msg1);
        let sig2 = kp2.sign_v1(b"wrong"); // Wrong message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        let results = batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);
        assert_eq!(results, vec![true, false]);
    }
}
