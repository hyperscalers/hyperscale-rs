//! Domain-separated signing for per-block shard randomness reveals.
//!
//! Every shard block proposer signs `(network, shard, height)` under
//! [`DOMAIN_SHARD_REVEAL`] to produce an unforgeable, unchooseable VRF
//! reveal. The 96-byte BLS signature is the [`VrfProof`](crate::VrfProof);
//! its digest ([`vrf_output_from_proof`](crate::vrf_output_from_proof)) is
//! the [`VrfOutput`](crate::VrfOutput) that rides the beacon-witness
//! accumulator and folds into the next epoch's randomness.
//!
//! The VRF property — uniquely determined by `(secret_key, message)` —
//! follows from BLS signatures being deterministic in min-pk mode, so the
//! proposer decides only *whether* its reveal lands (governed by the fold's
//! accumulator range), never its value. The input binds `(shard, height)`
//! and nothing else: no round, so a same-proposer re-proposal after a view
//! change keeps the value (no self-re-roll); no epoch or prior-randomness
//! chaining, which would hand a neighbouring proposer a lever into the value
//! and buys nothing here (the co-inputs a key-grind would target are
//! unknowable at registration). Domain separation keeps a reveal from being
//! confused with a block vote or header sig, which reuse the same BLS keys.

use crate::{
    BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, NetworkDefinition,
    ShardId, VrfProof, verify_bls12381_v1,
};

/// Domain tag for per-block shard randomness reveals.
pub const DOMAIN_SHARD_REVEAL: &[u8] = b"HYPERSCALE_SHARD_REVEAL_v1";

/// Build the canonical signing bytes for a shard reveal at `(shard, height)`
/// under `network`.
///
/// Layout: `domain || network.id || shard_id (8) || height (8)`. All fields
/// are fixed-width, so no length prefixes are needed.
#[must_use]
pub fn shard_reveal_message(
    network: &NetworkDefinition,
    shard: ShardId,
    height: BlockHeight,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_SHARD_REVEAL.len() + 1 + 8 + 8);
    out.extend_from_slice(DOMAIN_SHARD_REVEAL);
    out.push(network.id);
    out.extend_from_slice(&shard.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out
}

/// Sign `(network, shard, height)` and return the reveal proof.
///
/// The output is [`vrf_output_from_proof`](crate::vrf_output_from_proof) of
/// the result — a pure function of the proof, never stored separately.
/// Deterministic — BLS sigs in min-pk mode are a function of `(sk, message)`
/// only, so the same `(sk, network, shard, height)` always produces the same
/// proof. That is what makes a view-change re-proposal by the same proposer
/// carry an identical reveal (no self-re-roll).
#[must_use]
pub fn shard_reveal_sign(
    sk: &Bls12381G1PrivateKey,
    network: &NetworkDefinition,
    shard: ShardId,
    height: BlockHeight,
) -> VrfProof {
    let msg = shard_reveal_message(network, shard, height);
    let sig = sk.sign_v1(&msg);
    VrfProof::new(sig.0)
}

/// Verify that `proof` was produced by `pk` over `(network, shard, height)`.
///
/// The reveal output is a pure function of the proof
/// ([`vrf_output_from_proof`](crate::vrf_output_from_proof)), so there is
/// nothing to grind and only one check: the proof, as a BLS sig, verifies
/// against `pk` over the bytes produced by [`shard_reveal_message`].
#[must_use]
pub fn shard_reveal_verify(
    pk: &Bls12381G1PublicKey,
    network: &NetworkDefinition,
    shard: ShardId,
    height: BlockHeight,
    proof: &VrfProof,
) -> bool {
    let msg = shard_reveal_message(network, shard, height);
    let sig = Bls12381G2Signature(*proof.as_bytes());
    verify_bls12381_v1(&msg, pk, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{DOMAIN_BLOCK_HEADER, DOMAIN_PC_VRF};
    use crate::{bls_keypair_from_seed, vrf_output_from_proof};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    /// Pins the byte layout of `shard_reveal_message`. Any change to the
    /// encoder — field order, width, domain tag — shifts these bytes and
    /// fails this test. Cross-arch determinism rides on this layout being
    /// identical regardless of `usize` width on the host.
    #[test]
    fn shard_reveal_message_byte_layout_is_pinned() {
        let bytes = shard_reveal_message(&net(), ShardId::leaf(2, 0b01), BlockHeight::new(5));

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_SHARD_REVEAL);
        expected.push(net().id);
        expected.extend_from_slice(&ShardId::leaf(2, 0b01).to_le_bytes());
        expected.extend_from_slice(&BlockHeight::new(5).to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_SHARD_REVEAL.len() + 1 + 8 + 8);
    }

    /// Distinct heights on one shard produce distinct signing bytes — every
    /// block's reveal is bound to its own height, so a reveal can't be
    /// replayed against another height.
    #[test]
    fn shard_reveal_message_differs_across_heights() {
        let a = shard_reveal_message(&net(), ShardId::leaf(1, 0), BlockHeight::new(1));
        let b = shard_reveal_message(&net(), ShardId::leaf(1, 0), BlockHeight::new(2));
        assert_ne!(a, b);
    }

    /// Distinct shards at one height produce distinct signing bytes — a
    /// reveal is bound to its shard, so it can't cross-fold from another.
    #[test]
    fn shard_reveal_message_differs_across_shards() {
        let a = shard_reveal_message(&net(), ShardId::leaf(1, 0), BlockHeight::new(7));
        let b = shard_reveal_message(&net(), ShardId::leaf(1, 1), BlockHeight::new(7));
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: identical `(shard, height)` under
    /// different networks must produce different signing bytes.
    #[test]
    fn shard_reveal_message_differs_across_networks() {
        let mainnet = shard_reveal_message(
            &NetworkDefinition::mainnet(),
            ShardId::leaf(1, 0),
            BlockHeight::new(7),
        );
        let stokenet = shard_reveal_message(
            &NetworkDefinition::stokenet(),
            ShardId::leaf(1, 0),
            BlockHeight::new(7),
        );
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: a shard reveal must not collide with
    /// the beacon VRF reveal or a block-header proposal signature under any
    /// input — the domain tags diverge at the prefix.
    #[test]
    fn shard_reveal_message_differs_from_other_domains() {
        let reveal = shard_reveal_message(&net(), ShardId::leaf(1, 0), BlockHeight::new(1));
        assert_ne!(&reveal[..DOMAIN_SHARD_REVEAL.len()], DOMAIN_PC_VRF);
        assert_ne!(&reveal[..DOMAIN_BLOCK_HEADER.len()], DOMAIN_BLOCK_HEADER);
    }

    #[test]
    fn shard_reveal_sign_verify_round_trip() {
        let sk = keypair(3);
        let proof = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 1), BlockHeight::new(42));
        assert!(shard_reveal_verify(
            &sk.public_key(),
            &net(),
            ShardId::leaf(1, 1),
            BlockHeight::new(42),
            &proof
        ));
    }

    /// Deterministic: same inputs → same proof (and thus same output) across
    /// replicas. A re-proposal at the same `(shard, height)` is byte-identical.
    #[test]
    fn shard_reveal_sign_is_deterministic() {
        let sk = keypair(7);
        let a = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 0), BlockHeight::new(100));
        let b = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 0), BlockHeight::new(100));
        assert_eq!(a, b);
        assert_eq!(vrf_output_from_proof(&a), vrf_output_from_proof(&b));
    }

    /// A reveal from party A doesn't verify under party B's pubkey — the
    /// value is bound to the signer's key, so a proposer can't lift another's.
    #[test]
    fn shard_reveal_verify_rejects_cross_party() {
        let sk_a = keypair(3);
        let sk_b = keypair(4);
        let proof = shard_reveal_sign(&sk_a, &net(), ShardId::leaf(1, 0), BlockHeight::new(42));
        assert!(!shard_reveal_verify(
            &sk_b.public_key(),
            &net(),
            ShardId::leaf(1, 0),
            BlockHeight::new(42),
            &proof
        ));
    }

    /// A reveal for height N doesn't verify against height M ≠ N.
    #[test]
    fn shard_reveal_verify_rejects_wrong_height() {
        let sk = keypair(3);
        let proof = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 0), BlockHeight::new(42));
        assert!(!shard_reveal_verify(
            &sk.public_key(),
            &net(),
            ShardId::leaf(1, 0),
            BlockHeight::new(43),
            &proof
        ));
    }

    /// A reveal for shard S doesn't verify against shard T ≠ S.
    #[test]
    fn shard_reveal_verify_rejects_wrong_shard() {
        let sk = keypair(3);
        let proof = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 0), BlockHeight::new(42));
        assert!(!shard_reveal_verify(
            &sk.public_key(),
            &net(),
            ShardId::leaf(1, 1),
            BlockHeight::new(42),
            &proof
        ));
    }

    /// Tampered proof (BLS sig invalid) must reject. The output can't be
    /// tampered independently — it's derived from the proof — so the proof's
    /// BLS check is the whole predicate.
    #[test]
    fn shard_reveal_verify_rejects_tampered_proof() {
        let sk = keypair(3);
        let proof = shard_reveal_sign(&sk, &net(), ShardId::leaf(1, 0), BlockHeight::new(42));
        let mut bytes = *proof.as_bytes();
        bytes[0] ^= 1;
        let proof = VrfProof::new(bytes);
        assert!(!shard_reveal_verify(
            &sk.public_key(),
            &net(),
            ShardId::leaf(1, 0),
            BlockHeight::new(42),
            &proof
        ));
    }
}
