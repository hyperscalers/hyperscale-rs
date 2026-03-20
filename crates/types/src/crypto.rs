//! Cryptographic types and helpers.
//!
//! BLS12-381 types are framework-owned (see [`crate::bls`]).

// ── BLS (framework-owned) ───────────────────────────────────────────

pub use crate::bls::{
    batch_verify_bls_different_messages, batch_verify_bls_different_messages_all_or_nothing,
    batch_verify_bls_same_message, bls_keypair_from_seed, generate_bls_keypair, verify_bls12381_v1,
    zero_bls_signature, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, BlsError,
};

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_bls_keypair_from_seed() {
        let seed = [42u8; 32];
        let kp1 = bls_keypair_from_seed(&seed);
        let kp2 = bls_keypair_from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());

        let mut seed2 = [0u8; 32];
        seed2[31] = 1;
        let kp3 = bls_keypair_from_seed(&seed2);
        assert_ne!(kp1.public_key(), kp3.public_key());

        let mut seed_a = [0u8; 32];
        seed_a[30] = 0x30;
        seed_a[31] = 0x39;

        let mut seed_b = [0u8; 32];
        seed_b[30] = 0x30;
        seed_b[31] = 0x3a;

        let kp_a = bls_keypair_from_seed(&seed_a);
        let kp_b = bls_keypair_from_seed(&seed_b);
        assert_ne!(
            kp_a.public_key(),
            kp_b.public_key(),
            "Keys should differ even when first 8 bytes are identical"
        );
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
        let sig2 = kp2.sign_v1(b"different message");

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
        let sig2 = kp2.sign_v1(b"wrong");

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![kp1.public_key(), kp2.public_key()];

        let results = batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);
        assert_eq!(results, vec![true, false]);
    }
}
