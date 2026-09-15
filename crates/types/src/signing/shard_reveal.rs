//! Signing message for per-block shard randomness reveals.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::{NetworkId, signed_bytes};
use crate::{BlockHeight, ConsensusPublicKey, NetworkDefinition, ShardId, VrfProof};

/// What a shard reveal covers: `(shard, height)`, under the network. The
/// proposer's deterministic signature over it seeds the block's reveal
/// chain.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-shard-reveal-v1", signing_context = NetworkId)]
pub struct ShardRevealMessage {
    /// Shard whose chain the reveal extends.
    pub shard: ShardId,
    /// Height the reveal belongs to.
    pub(crate) height: BlockHeight,
}

/// Sign `(network, shard, height)` and return the reveal proof.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn shard_reveal_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    shard: ShardId,
    height: BlockHeight,
) -> Result<VrfProof, SignError> {
    let msg = signed_bytes(&ShardRevealMessage { shard, height }, network);
    signer.vrf_sign(&msg)
}

/// Verify that `proof` was produced by `pk` over `(network, shard,
/// height)`.
#[must_use]
pub fn shard_reveal_verify(
    verifier: &dyn Verifier,
    pk: &ConsensusPublicKey,
    network: &NetworkDefinition,
    shard: ShardId,
    height: BlockHeight,
    proof: &VrfProof,
) -> bool {
    let msg = signed_bytes(&ShardRevealMessage { shard, height }, network);
    verifier.verify_vrf(pk, &msg, proof)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed};

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn shard_reveal_sign_verify_round_trip() {
        let signer = signer_from_u64_seed(3);
        let proof = shard_reveal_sign(&signer, &net(), ShardId::leaf(1, 1), BlockHeight::new(42))
            .expect("sign");
        assert!(shard_reveal_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            ShardId::leaf(1, 1),
            BlockHeight::new(42),
            &proof
        ));
    }

    #[test]
    fn shard_reveal_verify_rejects_wrong_height() {
        let signer = signer_from_u64_seed(3);
        let proof = shard_reveal_sign(&signer, &net(), ShardId::leaf(1, 0), BlockHeight::new(42))
            .expect("sign");
        assert!(!shard_reveal_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            ShardId::leaf(1, 0),
            BlockHeight::new(43),
            &proof
        ));
    }
}
