//! Domain-separated signing for validator BLS proof-of-possession.
//!
//! Every validator key proves possession of its secret at registration:
//! the registrant signs `(network, validator_id, pubkey)` under
//! [`DOMAIN_VALIDATOR_POSSESSION_PROOF`] with the key being registered. The beacon
//! fold verifies the proof before inserting the validator record, so no
//! key enters the registry that its registrant cannot sign for. This is
//! what makes rogue-key constructions (`pk_rogue = g^r · pk_H^{-1}`)
//! unregisterable — producing a valid proof for `pk_rogue` requires its
//! secret `r − x_H`, which the adversary does not know — and it is the
//! precondition the aggregate-signature verifiers rely on when they
//! aggregate topology pubkeys without further validation.
//!
//! Binding `validator_id` and `network` means a captured proof cannot be
//! replayed to register the same key under a different identity or on a
//! different network.

use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, NetworkDefinition, ValidatorId,
    verify_bls12381_v1,
};

/// Domain tag for validator BLS proof-of-possession.
pub const DOMAIN_VALIDATOR_POSSESSION_PROOF: &[u8] = b"HYPERSCALE_VALIDATOR_POSSESSION_PROOF_v1";

/// Build the canonical signing bytes for a proof-of-possession of
/// `pubkey` claimed under `validator_id` on `network`.
///
/// Layout: `domain || network.id || validator_id (8) || pubkey (48)`.
/// All fields are fixed-width, so no length prefixes are needed.
#[must_use]
pub fn validator_possession_proof_message(
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pubkey: &Bls12381G1PublicKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_VALIDATOR_POSSESSION_PROOF.len() + 1 + 8 + 48);
    out.extend_from_slice(DOMAIN_VALIDATOR_POSSESSION_PROOF);
    out.push(network.id);
    out.extend_from_slice(&validator_id.to_le_bytes());
    out.extend_from_slice(&pubkey.0);
    out
}

/// Sign the proof-of-possession for `sk`'s public key claimed under
/// `validator_id` on `network`.
///
/// The message covers `sk.public_key()` itself, so the proof is bound to
/// exactly the key that signs it.
#[must_use]
pub fn validator_possession_proof_sign(
    sk: &Bls12381G1PrivateKey,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
) -> Bls12381G2Signature {
    let msg = validator_possession_proof_message(network, validator_id, &sk.public_key());
    sk.sign_v1(&msg)
}

/// Verify that `possession_proof` proves possession of `pubkey` claimed under
/// `validator_id` on `network`.
#[must_use]
pub fn validator_possession_proof_verify(
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pubkey: &Bls12381G1PublicKey,
    possession_proof: &Bls12381G2Signature,
) -> bool {
    let msg = validator_possession_proof_message(network, validator_id, pubkey);
    verify_bls12381_v1(&msg, pubkey, possession_proof)
}

#[cfg(test)]
mod tests {
    use blst::{
        BLST_ERROR, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_cneg, blst_p1_compress,
        blst_p1_from_affine, blst_p1_uncompress,
    };

    use super::*;
    use crate::signing::{DOMAIN_READY_SIGNAL, DOMAIN_SHARD_REVEAL};
    use crate::{bls_keypair_from_seed, zero_bls_signature};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    /// Pins the byte layout of `validator_possession_proof_message`. Any change to the
    /// encoder — field order, width, domain tag — shifts these bytes and
    /// fails this test.
    #[test]
    fn validator_possession_proof_message_byte_layout_is_pinned() {
        let pk = keypair(1).public_key();
        let id = ValidatorId::new(0x0123_4567_89AB_CDEF);
        let bytes = validator_possession_proof_message(&net(), id, &pk);

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_VALIDATOR_POSSESSION_PROOF);
        expected.push(net().id);
        expected.extend_from_slice(&id.to_le_bytes());
        expected.extend_from_slice(&pk.0);

        assert_eq!(bytes, expected);
        assert_eq!(
            bytes.len(),
            DOMAIN_VALIDATOR_POSSESSION_PROOF.len() + 1 + 8 + 48
        );
    }

    /// A proof is bound to the claimed identity: the same key's proof under
    /// a different `ValidatorId` must not verify.
    #[test]
    fn validator_possession_proof_message_differs_across_ids() {
        let pk = keypair(1).public_key();
        let a = validator_possession_proof_message(&net(), ValidatorId::new(1), &pk);
        let b = validator_possession_proof_message(&net(), ValidatorId::new(2), &pk);
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: identical `(id, pubkey)` under
    /// different networks must produce different signing bytes.
    #[test]
    fn validator_possession_proof_message_differs_across_networks() {
        let pk = keypair(1).public_key();
        let id = ValidatorId::new(7);
        let mainnet = validator_possession_proof_message(&NetworkDefinition::mainnet(), id, &pk);
        let stokenet = validator_possession_proof_message(&NetworkDefinition::stokenet(), id, &pk);
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: the domain tag diverges from the
    /// sibling tags at the prefix.
    #[test]
    fn validator_possession_proof_domain_differs_from_other_domains() {
        assert_ne!(DOMAIN_VALIDATOR_POSSESSION_PROOF, DOMAIN_READY_SIGNAL);
        assert_ne!(DOMAIN_VALIDATOR_POSSESSION_PROOF, DOMAIN_SHARD_REVEAL);
    }

    #[test]
    fn validator_possession_proof_sign_verify_round_trip() {
        let sk = keypair(3);
        let id = ValidatorId::new(42);
        let proof = validator_possession_proof_sign(&sk, &net(), id);
        assert!(validator_possession_proof_verify(
            &net(),
            id,
            &sk.public_key(),
            &proof
        ));
    }

    /// A proof signed by one key does not prove possession of another.
    #[test]
    fn validator_possession_proof_verify_rejects_cross_key() {
        let sk_a = keypair(3);
        let sk_b = keypair(4);
        let id = ValidatorId::new(42);
        let proof = validator_possession_proof_sign(&sk_a, &net(), id);
        assert!(!validator_possession_proof_verify(
            &net(),
            id,
            &sk_b.public_key(),
            &proof
        ));
    }

    /// A proof for one identity does not verify under another — replay of a
    /// captured proof against a different `ValidatorId` fails.
    #[test]
    fn validator_possession_proof_verify_rejects_wrong_id() {
        let sk = keypair(3);
        let proof = validator_possession_proof_sign(&sk, &net(), ValidatorId::new(42));
        assert!(!validator_possession_proof_verify(
            &net(),
            ValidatorId::new(43),
            &sk.public_key(),
            &proof
        ));
    }

    #[test]
    fn validator_possession_proof_verify_rejects_zero_signature() {
        let sk = keypair(3);
        let id = ValidatorId::new(42);
        assert!(!validator_possession_proof_verify(
            &net(),
            id,
            &sk.public_key(),
            &zero_bls_signature()
        ));
    }

    /// Decompress a pubkey to a G1 point.
    fn g1(pk: &Bls12381G1PublicKey) -> blst_p1 {
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
    fn rogue_key_against(
        honest_pk: &Bls12381G1PublicKey,
        r: &Bls12381G1PrivateKey,
    ) -> Bls12381G1PublicKey {
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
            Bls12381G1PublicKey(compressed)
        }
    }

    /// The rogue construction cannot produce a valid proof-of-possession:
    /// signing under `pk_rogue` requires its secret `r − x_H`, and the only
    /// secret the adversary holds is `r`. First confirm the key IS the
    /// classical attack — the aggregate of `{pk_H, pk_rogue}` collapses to
    /// `g^r`, so `r` alone forges aggregate signatures presenting `pk_H` as
    /// a co-signer — then confirm no available secret signs its proof.
    #[test]
    fn rogue_key_cannot_produce_a_valid_pop() {
        let honest = keypair(1);
        let r = keypair(999);
        let rogue_pk = rogue_key_against(&honest.public_key(), &r);
        let id = ValidatorId::new(7);

        // The attack is real: the two-key aggregate equals g^r, whose
        // discrete log the adversary knows.
        let agg = Bls12381G1PublicKey::aggregate(&[honest.public_key(), rogue_pk], true)
            .expect("rogue key is a valid G1 point");
        assert_eq!(agg, r.public_key());

        // The adversary's available forgeries: sign the rogue key's PoP
        // message with each secret it could hold. None verifies.
        let msg = validator_possession_proof_message(&net(), id, &rogue_pk);
        let forged_with_r = r.sign_v1(&msg);
        assert!(!validator_possession_proof_verify(
            &net(),
            id,
            &rogue_pk,
            &forged_with_r
        ));
        let forged_with_honest = honest.sign_v1(&msg);
        assert!(!validator_possession_proof_verify(
            &net(),
            id,
            &rogue_pk,
            &forged_with_honest
        ));
    }
}
