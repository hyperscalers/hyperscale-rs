//! Signing message for validator proof-of-possession at registration.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::{NetworkId, signed_bytes};
use crate::{ConsensusPublicKey, ConsensusSignature, NetworkDefinition, StakePoolId, ValidatorId};

/// What a proof-of-possession signature covers: the registering
/// validator's id, the pool it registers in, and the public key itself.
///
/// The key, so a registration cannot adopt a key its owner never offered
/// for that identity. The pool, because anyone may found one: without it
/// a proof seen once, in a refused registration or in flight, could seat
/// its owner's key under a stranger's pool.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(
    signing_domain = "hyperscale-validator-possession-proof-v1",
    signing_context = NetworkId
)]
pub struct ValidatorPossessionProofMessage {
    /// The registering validator.
    pub(crate) validator_id: ValidatorId,
    /// The pool it registers in.
    pub(crate) pool: StakePoolId,
    /// The consensus public key being registered.
    pub(crate) pubkey: ConsensusPublicKey,
}

/// Sign the possession proof for `validator_id` in `pool` with `signer`'s
/// own key.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn validator_possession_proof_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pool: StakePoolId,
) -> Result<ConsensusSignature, SignError> {
    let msg = signed_bytes(
        &ValidatorPossessionProofMessage {
            validator_id,
            pool,
            pubkey: signer.public_key(),
        },
        network,
    );
    signer.sign(&msg)
}

/// Verify `possession_proof` was produced by `pubkey` over
/// `(network, validator_id, pool, pubkey)`.
#[must_use]
pub fn validator_possession_proof_verify(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pool: StakePoolId,
    pubkey: &ConsensusPublicKey,
    possession_proof: &ConsensusSignature,
) -> bool {
    let msg = signed_bytes(
        &ValidatorPossessionProofMessage {
            validator_id,
            pool,
            pubkey: *pubkey,
        },
        network,
    );
    verifier.verify(pubkey, &msg, possession_proof)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed as signer};

    use super::*;
    use crate::test_utils::test_pool;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    const POOL: StakePoolId = test_pool(1);

    fn proof() -> ConsensusSignature {
        validator_possession_proof_sign(&signer(1), &net(), ValidatorId::new(7), POOL).unwrap()
    }

    fn verifies(id: u64, pool: StakePoolId) -> bool {
        validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(id),
            pool,
            &signer(1).public_key(),
            &proof(),
        )
    }

    #[test]
    fn possession_proof_round_trips() {
        assert!(verifies(7, POOL));
    }

    #[test]
    fn possession_proof_binds_validator_id() {
        assert!(!verifies(8, POOL));
    }

    #[test]
    fn possession_proof_binds_the_pool() {
        assert!(!verifies(7, test_pool(2)));
    }
}
