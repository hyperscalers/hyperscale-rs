//! [`Verifier`] over BLS12-381 (min-pk) signatures.

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};
use blst::{BLST_ERROR, blst_scalar, blst_scalar_from_bendian};
use hyperscale_crypto::{
    AggregateError, AggregateSignature, ConsensusPublicKey, ConsensusSignature, VerifiedSignature,
    Verifier, VrfProof,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng, rng};

use crate::bls12381::{
    CIPHERSUITE, PublicKey as BlsPublicKey, Signature as BlsSignature, aggregate_verify, verify,
};

/// BLS verification.
///
/// Aggregates are G2 sums, same-message aggregate checks run one
/// pairing against the aggregated pubkey, and batches use blst's
/// random-linear-combination fast path with individual fallback. The
/// random scalars affect performance only, never outcomes.
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

/// All-or-nothing batch verification over distinct messages via blst's
/// random linear combination (~2 pairings for the whole batch).
fn batch_all_or_nothing(
    messages: &[&[u8]],
    signatures: &[BlsSignature],
    pubkeys: &[BlsPublicKey],
) -> bool {
    let mut bls_sigs = Vec::with_capacity(signatures.len());
    let mut bls_pks = Vec::with_capacity(pubkeys.len());
    for (s, p) in signatures.iter().zip(pubkeys.iter()) {
        let Ok(s) = BlstSignature::from_bytes(&s.0) else {
            return false;
        };
        let Ok(p) = BlstPublicKey::from_bytes(&p.0) else {
            return false;
        };
        bls_sigs.push(s);
        bls_pks.push(p);
    }

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

    let sig_refs: Vec<&BlstSignature> = bls_sigs.iter().collect();
    let pk_refs: Vec<&BlstPublicKey> = bls_pks.iter().collect();

    let result = BlstSignature::verify_multiple_aggregate_signatures(
        messages,
        CIPHERSUITE, // DST must match `sign`/`verify`
        &pk_refs,
        false, // pks_validate - possession-proven or genesis-trusted
        &sig_refs,
        true, // sigs_groupcheck - verify signatures are in the group
        &rands,
        64, // rand_bits - 64 bits of randomness
    );

    result == BLST_ERROR::BLST_SUCCESS
}

/// Same-message batch fast path: aggregate signatures and pubkeys, then
/// run a single pairing check.
fn batch_same_message(
    message: &[u8],
    signatures: &[BlsSignature],
    pubkeys: &[BlsPublicKey],
) -> bool {
    let Some(agg_sig) = BlsSignature::aggregate(signatures, true) else {
        return false;
    };
    // Pubkey aggregation skips G1 subgroup validation: every topology key
    // is possession-proven at registration (or genesis-trusted), which
    // both guarantees real G1 points and forecloses rogue-key
    // constructions.
    let Some(agg_pk) = BlsPublicKey::aggregate(pubkeys, false) else {
        return false;
    };
    verify(message, &agg_pk, &agg_sig)
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
    /// passed it in `verify`, `batch_verify` or signing. Inputs still
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
        // Unvalidated aggregation: see `batch_same_message`.
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

    fn batch_verify(
        &self,
        messages: &[&[u8]],
        sigs: &[ConsensusSignature],
        keys: &[ConsensusPublicKey],
    ) -> Vec<bool> {
        if messages.len() != sigs.len() || sigs.len() != keys.len() {
            return vec![false; messages.len().max(sigs.len()).max(keys.len())];
        }
        if messages.is_empty() {
            return vec![];
        }
        let bls_sigs: Vec<BlsSignature> = sigs.iter().map(sig).collect();
        let bls_pks: Vec<BlsPublicKey> = keys.iter().map(pk).collect();

        // Fast path; blst's different-messages combination requires
        // distinct messages, so uniform batches take the aggregate route.
        let all_same = messages.windows(2).all(|w| w[0] == w[1]);
        let batch_ok = if all_same {
            batch_same_message(messages[0], &bls_sigs, &bls_pks)
        } else {
            batch_all_or_nothing(messages, &bls_sigs, &bls_pks)
        };
        if batch_ok {
            return vec![true; sigs.len()];
        }

        // Slow path: batch failed, verify individually to find failures
        messages
            .iter()
            .zip(bls_sigs.iter())
            .zip(bls_pks.iter())
            .map(|((m, s), p)| verify(m, p, s))
            .collect()
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
    use hyperscale_crypto::run_conformance_suite;

    use super::*;
    use crate::bls12381::PrivateKey;
    use crate::{BlsSigner, bls_keypair_from_seed};

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
    fn batch_verify_same_message_batches_take_the_aggregate_path() {
        use hyperscale_crypto::Signer;
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
}
