//! [`Verifier`] over BLS12-381 (min-pk) signatures.

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};
use blst::{BLST_ERROR, MultiPoint, blst_scalar};
use hyperscale_crypto::{
    AggregateError, AggregateSignature, ConsensusPublicKey, ConsensusSignature, VerifiedSignature,
    Verifier, VrfProof,
};
use rand::{Rng, rng};

use crate::bls12381::{
    CIPHERSUITE, PublicKey as BlsPublicKey, Signature as BlsSignature, aggregate_verify, verify,
};

/// BLS verification.
///
/// Aggregates are G2 sums, and same-message aggregate checks run one
/// pairing against the aggregated pubkey. [`Verifier::verify_each`] is a
/// random linear combination over the set, so its verdict holds for every
/// signature on its own; its random scalars come from the thread CSPRNG
/// and decide cost, never an honest verdict.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlsVerifier;

const fn pk(key: &ConsensusPublicKey) -> BlsPublicKey {
    BlsPublicKey(*key.as_bytes())
}

const fn sig(s: &ConsensusSignature) -> BlsSignature {
    BlsSignature(*s.as_bytes())
}

const fn agg(a: &AggregateSignature) -> BlsSignature {
    BlsSignature(*a.as_bytes())
}

/// Bit width of the weights [`draw_weights`] draws.
const WEIGHT_BITS: usize = 64;

/// One fresh nonzero weight per signature, from the thread CSPRNG.
///
/// Checking a set of signatures by their plain sum accepts members that
/// are individually invalid but cancel. Weighting each member first, by a
/// scalar drawn after the signatures are fixed, closes that: an invalid
/// member survives only if its error meets the one weight value that
/// cancels it, so a set with any invalid member passes with probability
/// at most `2^-WEIGHT_BITS`. A valid set passes under every weight, so
/// the draw decides cost and never an honest verdict.
fn draw_weights(n: usize) -> Vec<u64> {
    let mut rng = rng();
    (0..n)
        .map(|_| {
            loop {
                let weight = rng.next_u64();
                if weight != 0 {
                    break weight;
                }
            }
        })
        .collect()
}

/// [`Verifier::verify_each`] over one shared message: the weighted
/// signature sum against the weighted key sum, one pairing check.
///
/// Every signature is group-checked first; keys are not, since every
/// topology key is possession-proven at registration (or
/// genesis-trusted).
fn verify_each_same_message(
    message: &[u8],
    signatures: &[BlsSignature],
    pubkeys: &[BlsPublicKey],
) -> bool {
    let Some(sigs): Option<Vec<BlstSignature>> = signatures
        .iter()
        .map(|s| BlstSignature::sig_validate(&s.0, false).ok())
        .collect()
    else {
        return false;
    };
    let Some(keys): Option<Vec<BlstPublicKey>> = pubkeys
        .iter()
        .map(|p| BlstPublicKey::from_bytes(&p.0).ok())
        .collect()
    else {
        return false;
    };
    let weights: Vec<u8> = draw_weights(sigs.len())
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let combined_sig = sigs.as_slice().mult(&weights, WEIGHT_BITS).to_signature();
    let combined_key = keys.as_slice().mult(&weights, WEIGHT_BITS).to_public_key();
    // The weighted sum of group-checked signatures is in the group.
    combined_sig.verify(false, message, CIPHERSUITE, &[], &combined_key, false)
        == BLST_ERROR::BLST_SUCCESS
}

/// [`Verifier::verify_each`] over messages that are not all one: blst's
/// weighted multi-signature check, one pairing per signature plus one.
///
/// blst group-checks every signature; keys are trusted as in
/// [`verify_each_same_message`].
fn verify_each_distinct(
    messages: &[&[u8]],
    signatures: &[BlsSignature],
    pubkeys: &[BlsPublicKey],
) -> bool {
    let Some(sigs): Option<Vec<BlstSignature>> = signatures
        .iter()
        .map(|s| BlstSignature::from_bytes(&s.0).ok())
        .collect()
    else {
        return false;
    };
    let Some(keys): Option<Vec<BlstPublicKey>> = pubkeys
        .iter()
        .map(|p| BlstPublicKey::from_bytes(&p.0).ok())
        .collect()
    else {
        return false;
    };
    let weights: Vec<blst_scalar> = draw_weights(sigs.len())
        .into_iter()
        .map(|w| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&w.to_le_bytes());
            blst_scalar { b }
        })
        .collect();
    let sig_refs: Vec<&BlstSignature> = sigs.iter().collect();
    let key_refs: Vec<&BlstPublicKey> = keys.iter().collect();
    BlstSignature::verify_multiple_aggregate_signatures(
        messages,
        CIPHERSUITE,
        &key_refs,
        false,
        &sig_refs,
        true,
        &weights,
        WEIGHT_BITS,
    ) == BLST_ERROR::BLST_SUCCESS
}

impl Verifier for BlsVerifier {
    fn verify(&self, key: &ConsensusPublicKey, message: &[u8], s: &ConsensusSignature) -> bool {
        verify(message, &pk(key), &sig(s))
    }

    fn aggregate(&self, sigs: &[ConsensusSignature]) -> Result<AggregateSignature, AggregateError> {
        if sigs.is_empty() {
            return Err(AggregateError::Empty);
        }
        let bls: Vec<BlsSignature> = sigs.iter().map(sig).collect();
        BlsSignature::aggregate(&bls, true)
            .map(|a| AggregateSignature::new(a.0))
            .ok_or(AggregateError::InvalidSignature)
    }

    /// Skips the G2 subgroup check on every input: each one already
    /// passed it in `verify`, `verify_each` or signing. Inputs still
    /// decode as curve points, and every verify op group-checks the
    /// aggregate it is handed.
    fn aggregate_verified(
        &self,
        sigs: &[VerifiedSignature],
    ) -> Result<AggregateSignature, AggregateError> {
        if sigs.is_empty() {
            return Err(AggregateError::Empty);
        }
        let bls: Vec<BlsSignature> = sigs.iter().map(|s| sig(&s.signature())).collect();
        BlsSignature::aggregate(&bls, false)
            .map(|a| AggregateSignature::new(a.0))
            .ok_or(AggregateError::InvalidSignature)
    }

    fn verify_aggregate_same_message(
        &self,
        message: &[u8],
        aggregate: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if keys.is_empty() {
            return false;
        }
        let pks: Vec<BlsPublicKey> = keys.iter().map(pk).collect();
        // Pubkey aggregation skips G1 subgroup validation: every topology
        // key is possession-proven at registration (or genesis-trusted),
        // which both guarantees real G1 points and forecloses rogue-key
        // constructions.
        let Some(agg_pk) = BlsPublicKey::aggregate(&pks, false) else {
            return false;
        };
        verify(message, &agg_pk, &agg(aggregate))
    }

    fn verify_aggregate_different_messages(
        &self,
        messages: &[&[u8]],
        aggregate: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if messages.len() != keys.len() || messages.is_empty() {
            return false;
        }
        let pairs: Vec<(BlsPublicKey, Vec<u8>)> = keys
            .iter()
            .zip(messages.iter())
            .map(|(k, m)| (pk(k), m.to_vec()))
            .collect();
        aggregate_verify(&pairs, &agg(aggregate))
    }

    fn verify_each(
        &self,
        messages: &[&[u8]],
        sigs: &[ConsensusSignature],
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if messages.is_empty() || messages.len() != sigs.len() || sigs.len() != keys.len() {
            return false;
        }
        if let ([message], [s], [key]) = (messages, sigs, keys) {
            return verify(message, &pk(key), &sig(s));
        }
        let bls_sigs: Vec<BlsSignature> = sigs.iter().map(sig).collect();
        let bls_pks: Vec<BlsPublicKey> = keys.iter().map(pk).collect();
        if messages.windows(2).all(|w| w[0] == w[1]) {
            verify_each_same_message(messages[0], &bls_sigs, &bls_pks)
        } else {
            verify_each_distinct(messages, &bls_sigs, &bls_pks)
        }
    }

    fn verify_vrf(&self, key: &ConsensusPublicKey, message: &[u8], proof: &VrfProof) -> bool {
        verify(message, &pk(key), &BlsSignature(*proof.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use blst::{
        BLST_ERROR, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_cneg, blst_p1_compress,
        blst_p1_from_affine, blst_p1_uncompress,
    };
    use hyperscale_crypto::{Signer, run_conformance_suite};

    use super::*;
    use crate::bls12381::PrivateKey;
    use crate::{BlsSigner, bls_keypair_from_seed, cancelling_pair};

    fn keypair(seed: u64) -> PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn consensus_key(key: &BlsPublicKey) -> ConsensusPublicKey {
        ConsensusPublicKey::new(key.0)
    }

    /// Decompress a pubkey to a G1 point.
    fn g1(pk: &BlsPublicKey) -> blst_p1 {
        // SAFETY: `affine` and `point` are valid zero-initialised blst
        // structs and `pk.0` is a 48-byte compressed G1 encoding;
        // `blst_p1_uncompress` reads exactly 48 bytes from the pointer.
        unsafe {
            let mut affine = blst_p1_affine::default();
            assert_eq!(
                blst_p1_uncompress(&raw mut affine, pk.0.as_ptr()),
                BLST_ERROR::BLST_SUCCESS,
            );
            let mut point = blst_p1::default();
            blst_p1_from_affine(&raw mut point, &raw const affine);
            point
        }
    }

    /// `pk_rogue = g^r · pk_H^{-1}` for a known scalar `r` and an honest
    /// registered key `pk_H` — the classical rogue-key construction. In
    /// min-pk BLS `g^r` is exactly `r`'s public key, so the rogue key is
    /// `r.public_key() − pk_H` in the G1 group.
    fn rogue_key_against(honest_pk: &BlsPublicKey, r: &PrivateKey) -> BlsPublicKey {
        let mut neg_honest = g1(honest_pk);
        let g_r = g1(&r.public_key());
        // SAFETY: all pointers reference valid, initialised blst structs;
        // `compressed` is 48 bytes, the exact width `blst_p1_compress`
        // writes.
        unsafe {
            blst_p1_cneg(&raw mut neg_honest, true);
            let mut rogue = blst_p1::default();
            blst_p1_add(&raw mut rogue, &raw const g_r, &raw const neg_honest);
            let mut compressed = [0u8; 48];
            blst_p1_compress(compressed.as_mut_ptr(), &raw const rogue);
            BlsPublicKey(compressed)
        }
    }

    /// [`Verifier::verify_aggregate_same_message`] aggregates public keys
    /// without subgroup validation, which is only sound because every
    /// registered key has proven possession. This pins the property that
    /// makes possession proofs a sufficient defence: a rogue key cannot
    /// self-sign.
    ///
    /// First confirm the key IS the classical attack — the aggregate of
    /// `{pk_H, pk_rogue}` collapses to `g^r`, so `r` alone forges aggregate
    /// signatures presenting `pk_H` as a co-signer — then confirm no secret
    /// the adversary holds signs anything that verifies under `pk_rogue`.
    #[test]
    fn a_rogue_key_cannot_sign_under_itself() {
        let honest = keypair(1);
        let r = keypair(999);
        let rogue_pk = rogue_key_against(&honest.public_key(), &r);

        // The attack is real: the two-key aggregate equals g^r, whose
        // discrete log the adversary knows.
        let agg = BlsPublicKey::aggregate(&[honest.public_key(), rogue_pk], true)
            .expect("rogue key is a valid G1 point");
        assert_eq!(agg, r.public_key());

        // The adversary's available forgeries: sign under each secret it
        // could hold. Neither verifies against the rogue key.
        let message = b"any message bound to the rogue key".as_slice();
        for secret in [&r, &honest] {
            let forged = secret.sign(message);
            assert!(
                !BlsVerifier.verify(
                    &consensus_key(&rogue_pk),
                    message,
                    &ConsensusSignature::new(forged.0)
                ),
                "no available secret may sign under the rogue key"
            );
        }
    }

    #[test]
    fn conformance() {
        run_conformance_suite(
            |seed_index| {
                let mut seed = [0u8; 32];
                seed[0] = seed_index;
                BlsSigner::from_seed(&seed)
            },
            &BlsVerifier,
        );
    }

    #[test]
    fn batch_verify_same_message_batches_verify_each_signature() {
        let signers: Vec<BlsSigner> = (0..3u8)
            .map(|i| BlsSigner::from_seed(&[i + 1; 32]))
            .collect();
        let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
        let message = b"same message for everyone".as_slice();
        let sigs: Vec<_> = signers
            .iter()
            .map(|s| s.sign(message).expect("bls sign cannot fail"))
            .collect();
        let messages = vec![message; 3];
        assert_eq!(
            BlsVerifier.batch_verify(&messages, &sigs, &keys),
            vec![true; 3]
        );

        // One forged entry must be singled out by the fallback.
        let mut bad = sigs;
        bad[1] = signers[1]
            .sign(b"other message")
            .expect("bls sign cannot fail");
        assert_eq!(
            BlsVerifier.batch_verify(&messages, &bad, &keys),
            vec![true, false, true]
        );
    }

    fn signer(seed: u8) -> BlsSigner {
        BlsSigner::from_seed(&[seed; 32])
    }

    fn sign(signer: &BlsSigner, message: &[u8]) -> ConsensusSignature {
        signer.sign(message).expect("bls sign cannot fail")
    }

    /// Two colluding voters shift their votes against each other. The
    /// shifted pair's aggregate is the honest aggregate, so a check of the
    /// sum passes; each signature alone is invalid, and a certificate built
    /// from either one without the other would not verify.
    #[test]
    fn cancelling_signatures_fail_a_same_message_batch() {
        let voters = [signer(1), signer(2), signer(3)];
        let keys: Vec<_> = voters.iter().map(Signer::public_key).collect();
        let message = b"a block vote".as_slice();
        let honest: Vec<_> = voters.iter().map(|v| sign(v, message)).collect();
        let delta = sign(&signer(9), b"any point in the group");
        let (a, b) = cancelling_pair(&honest[0], &honest[1], &delta);

        let shifted_agg = BlsVerifier.aggregate(&[a, b]).expect("both in the group");
        assert!(
            BlsVerifier.verify_aggregate_same_message(message, &shifted_agg, &keys[..2]),
            "the shifted pair's sum is the honest sum"
        );
        assert!(!BlsVerifier.verify(&keys[0], message, &a));
        assert!(!BlsVerifier.verify(&keys[1], message, &b));

        let messages = [message; 3];
        assert!(!BlsVerifier.verify_each(&messages[..2], &[a, b], &keys[..2]));
        assert_eq!(
            BlsVerifier.batch_verify(&messages[..2], &[a, b], &keys[..2]),
            vec![false, false]
        );
        assert_eq!(
            BlsVerifier.batch_verify(&messages, &[a, b, honest[2]], &keys),
            vec![false, false, true]
        );
    }

    /// One signer shifts two of its own signatures over distinct messages
    /// against each other: the shape of a vote carrying several prefix
    /// signatures under one key.
    #[test]
    fn cancelling_signatures_fail_a_distinct_message_set() {
        let voter = signer(7);
        let key = voter.public_key();
        let messages: [&[u8]; 3] = [b"prefix 0", b"prefix 1", b"prefix 2"];
        let honest: Vec<_> = messages.iter().map(|m| sign(&voter, m)).collect();
        let delta = sign(&signer(8), b"any point in the group");
        let (a, b) = cancelling_pair(&honest[0], &honest[1], &delta);
        let shifted = [a, b, honest[2]];
        let keys = [key; 3];

        let shifted_agg = BlsVerifier.aggregate(&shifted).expect("all in the group");
        assert!(
            BlsVerifier.verify_aggregate_different_messages(&messages, &shifted_agg, &keys),
            "the shifted set's sum is the honest sum"
        );
        assert!(!BlsVerifier.verify_each(&messages, &shifted, &keys));
        assert_eq!(
            BlsVerifier.batch_verify(&messages, &shifted, &keys),
            vec![false, false, true]
        );
        assert!(BlsVerifier.verify_each(&messages, &honest, &keys));
    }

    /// A batch that repeats some messages but not all takes the
    /// multi-message check, which needs no message to be distinct.
    #[test]
    fn verify_each_accepts_a_mixed_batch_and_refuses_a_forged_member() {
        let voters: Vec<_> = (1..=5).map(signer).collect();
        let keys: Vec<_> = voters.iter().map(Signer::public_key).collect();
        let messages: [&[u8]; 5] = [b"one", b"two", b"one", b"three", b"two"];
        let sigs: Vec<_> = voters
            .iter()
            .zip(messages)
            .map(|(v, m)| sign(v, m))
            .collect();
        assert!(BlsVerifier.verify_each(&messages, &sigs, &keys));

        let mut forged = sigs.clone();
        forged[3] = sign(&voters[3], b"four");
        assert!(!BlsVerifier.verify_each(&messages, &forged, &keys));

        let mut not_a_point = sigs;
        not_a_point[2] = ConsensusSignature::new([0x5a; 96]);
        assert!(!BlsVerifier.verify_each(&messages, &not_a_point, &keys));
        assert!(!BlsVerifier.verify_each(&[], &[], &[]));
        assert!(!BlsVerifier.verify_each(&messages[..4], &forged, &keys));
    }
}
