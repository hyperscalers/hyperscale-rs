//! Batch verification helpers for Ed25519 and BLS12-381 signatures.

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};
use blst::{BLST_ERROR, blst_scalar, blst_scalar_from_bendian};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey as DalekVerifyingKey, verify_batch};
use radix_common::crypto::{
    BLS12381_CIPHERSITE_V1, Bls12381G1PublicKey, Bls12381G2Signature, Ed25519PublicKey,
    Ed25519Signature, aggregate_verify_bls12381_v1, verify_bls12381_v1,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng, rng};

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
        dalek_sigs.push(DalekSignature::from_bytes(&sig.0));

        match DalekVerifyingKey::from_bytes(&pk.0) {
            Ok(vk) => dalek_pks.push(vk),
            Err(_) => return false,
        }
    }

    verify_batch(messages, &dalek_sigs, &dalek_pks).is_ok()
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

    // Aggregate public keys without G1 subgroup validation: topology keys
    // enter the registry through the beacon fold's `RegisterValidator`
    // gate, which verifies a proof-of-possession — a key that proves
    // possession is a real G1 point, and the same proof forecloses the
    // rogue-key constructions unvalidated aggregation would otherwise
    // admit. (Genesis keys skip the gate; they are operator-trusted
    // config, not an adversarial channel.)
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
        let Ok(sig) = BlstSignature::from_bytes(&sig.0) else {
            return false;
        };
        let Ok(pk) = BlstPublicKey::from_bytes(&pk.0) else {
            return false;
        };
        bls_sigs.push(sig);
        bls_pks.push(pk);
    }

    // Generate random scalars for the linear combination
    let mut seed = [0u8; 32];
    rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);

    let mut rands = Vec::with_capacity(signatures.len());
    for _ in 0..signatures.len() {
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let mut scalar = blst_scalar::default();
        // SAFETY: `scalar` is a valid `blst_scalar` (zero-initialised above) and
        // `rand_bytes` is a 32-byte array whose pointer is valid for 32 bytes.
        // `blst_scalar_from_bendian` reads exactly 32 bytes from the pointer.
        unsafe {
            blst_scalar_from_bendian(&raw mut scalar, rand_bytes.as_ptr());
        }
        rands.push(scalar);
    }

    // Build reference slices for the blst API
    let sig_refs: Vec<&BlstSignature> = bls_sigs.iter().collect();
    let pk_refs: Vec<&BlstPublicKey> = bls_pks.iter().collect();

    // Use blst's batch verification with random linear combination
    let result = BlstSignature::verify_multiple_aggregate_signatures(
        messages,
        BLS12381_CIPHERSITE_V1, // DST must match sign_v1/verify_bls12381_v1
        &pk_refs,
        false, // pks_validate - already validated above
        &sig_refs,
        true, // sigs_groupcheck - verify signatures are in the group
        &rands,
        64, // rand_bits - 64 bits of randomness
    );

    result == BLST_ERROR::BLST_SUCCESS
}

/// Verify a single BLS aggregate signature where each signer signed a
/// DIFFERENT message.
///
/// Distinct from [`batch_verify_bls_different_messages_all_or_nothing`]
/// in that the input is **one combined sig** (already aggregated at
/// build time, e.g. via `Bls12381G2Signature::aggregate`), not a slice
/// of individual sigs. The PC inner-consensus QC verifiers consume this
/// shape — `PcQc1`/`PcQc2`/`PcQc3` carry a single `x_agg_sig` that
/// covers per-signer prefix messages.
///
/// Internally calls Radix's [`aggregate_verify_bls12381_v1`], so domain
/// separation lives in the message bytes (the BLS suite is the fixed
/// POP-style `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`). Rogue-key
/// safety holds because every post-genesis validator key proved
/// possession at registration: the beacon fold's `RegisterValidator`
/// arm verifies a proof-of-possession
/// (`validator_possession_proof_verify`) before the key enters the
/// registry. Genesis keys skip the gate — they are operator-trusted
/// config — so the topology pubkeys callers select from here are all
/// possession-proven or genesis-trusted.
///
/// Returns `false` on empty input, length mismatch between `messages`
/// and `pubkeys`, or invalid signature.
#[must_use]
pub fn aggregate_verify_bls_different_messages(
    messages: &[&[u8]],
    aggregate_sig: &Bls12381G2Signature,
    pubkeys: &[Bls12381G1PublicKey],
) -> bool {
    if messages.len() != pubkeys.len() || messages.is_empty() {
        return false;
    }
    let pairs: Vec<(Bls12381G1PublicKey, Vec<u8>)> = pubkeys
        .iter()
        .zip(messages.iter())
        .map(|(pk, m)| (*pk, m.to_vec()))
        .collect();
    aggregate_verify_bls12381_v1(&pairs, aggregate_sig)
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

    #[test]
    fn aggregate_verify_different_messages_accepts_valid_aggregate() {
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();
        let kp3 = generate_bls_keypair();

        let msg1 = b"prefix []";
        let msg2 = b"prefix [a]";
        let msg3 = b"prefix [a, b]";

        let sig1 = kp1.sign_v1(msg1);
        let sig2 = kp2.sign_v1(msg2);
        let sig3 = kp3.sign_v1(msg3);

        let agg_sig = Bls12381G2Signature::aggregate(&[sig1, sig2, sig3], true).unwrap();

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let pubkeys = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        assert!(aggregate_verify_bls_different_messages(
            &messages, &agg_sig, &pubkeys
        ));
    }

    #[test]
    fn aggregate_verify_different_messages_rejects_tampered_message() {
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();

        let msg1 = b"signed-1";
        let msg2 = b"signed-2";

        let sig1 = kp1.sign_v1(msg1);
        let sig2 = kp2.sign_v1(msg2);
        let agg_sig = Bls12381G2Signature::aggregate(&[sig1, sig2], true).unwrap();

        // Same sig, but verifier supplies a tampered message at index 1.
        let tampered: &[u8] = b"tampered-2";
        let messages: Vec<&[u8]> = vec![msg1, tampered];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!aggregate_verify_bls_different_messages(
            &messages, &agg_sig, &pubkeys
        ));
    }

    #[test]
    fn aggregate_verify_different_messages_rejects_swapped_pubkeys() {
        // kp1 signed msg1, kp2 signed msg2. Verifier supplies pubkeys in
        // swapped order — verify must fail because the per-signer
        // message-to-key binding is broken.
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();

        let msg1 = b"signed-by-kp1";
        let msg2 = b"signed-by-kp2";

        let sig1 = kp1.sign_v1(msg1);
        let sig2 = kp2.sign_v1(msg2);
        let agg_sig = Bls12381G2Signature::aggregate(&[sig1, sig2], true).unwrap();

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let swapped = vec![kp2.public_key(), kp1.public_key()];

        assert!(!aggregate_verify_bls_different_messages(
            &messages, &agg_sig, &swapped
        ));
    }

    #[test]
    fn aggregate_verify_different_messages_rejects_empty_input() {
        let kp = generate_bls_keypair();
        let sig = kp.sign_v1(b"x");
        let agg = Bls12381G2Signature::aggregate(&[sig], true).unwrap();

        assert!(!aggregate_verify_bls_different_messages(&[], &agg, &[]));
    }

    #[test]
    fn aggregate_verify_different_messages_rejects_length_mismatch() {
        let kp1 = generate_bls_keypair();
        let kp2 = generate_bls_keypair();
        let sig = kp1.sign_v1(b"x");
        let agg = Bls12381G2Signature::aggregate(&[sig], true).unwrap();

        let msg: &[u8] = b"x";
        let messages: Vec<&[u8]> = vec![msg];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        assert!(!aggregate_verify_bls_different_messages(
            &messages, &agg, &pubkeys
        ));
    }
}
