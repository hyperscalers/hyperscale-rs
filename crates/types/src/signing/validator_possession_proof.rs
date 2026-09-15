//! Signing message for validator proof-of-possession at registration.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::{NetworkId, signed_bytes};
use crate::{ConsensusPublicKey, ConsensusSignature, NetworkDefinition, ValidatorId};

/// What a proof-of-possession signature covers: the registering
/// validator's id and the public key itself, so a registration cannot
/// adopt a key its owner never offered for that identity.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(
    signing_domain = "hyperscale-validator-possession-proof-v1",
    signing_context = NetworkId
)]
pub struct ValidatorPossessionProofMessage {
    /// The registering validator.
    pub(crate) validator_id: ValidatorId,
    /// The consensus public key being registered.
    pub(crate) pubkey: ConsensusPublicKey,
}

/// Sign the possession proof for `validator_id` with `signer`'s own key.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn validator_possession_proof_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
) -> Result<ConsensusSignature, SignError> {
    let msg = signed_bytes(
        &ValidatorPossessionProofMessage {
            validator_id,
            pubkey: signer.public_key(),
        },
        network,
    );
    signer.sign(&msg)
}

/// Verify `possession_proof` was produced by `pubkey` over
/// `(network, validator_id, pubkey)`.
#[must_use]
pub fn validator_possession_proof_verify(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pubkey: &ConsensusPublicKey,
    possession_proof: &ConsensusSignature,
) -> bool {
    let msg = signed_bytes(
        &ValidatorPossessionProofMessage {
            validator_id,
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

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn possession_proof_round_trips() {
        let s = signer(1);
        let proof = validator_possession_proof_sign(&s, &net(), ValidatorId::new(7)).unwrap();
        assert!(validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(7),
            &s.public_key(),
            &proof
        ));
    }

    #[test]
    fn possession_proof_binds_validator_id() {
        let s = signer(1);
        let proof = validator_possession_proof_sign(&s, &net(), ValidatorId::new(7)).unwrap();
        assert!(!validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(8),
            &s.public_key(),
            &proof
        ));
    }
}
