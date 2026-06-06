//! Domain-separated signing for the validator-bind protocol.

use crate::NetworkDefinition;

/// Domain tag for validator-bind protocol.
///
/// Format: `VALIDATOR_BIND` || `network.id` || `peer_id_bytes` || `nonce`
/// (32 bytes)
///
/// Signed by a validator's BLS key to cryptographically bind their
/// consensus identity (`ValidatorId`) to their ephemeral libp2p `PeerId`.
/// Verified by peers using the BLS public key from the topology.
///
/// The nonce is supplied by the *verifier* in a challenge-response exchange,
/// so the signature is fresh per session and cannot be replayed against the
/// same `(validator_id, peer_id)` pair across different sessions.
pub const DOMAIN_VALIDATOR_BIND: &[u8] = b"VALIDATOR_BIND";

/// Length of the bind-protocol nonce, in bytes.
pub const VALIDATOR_BIND_NONCE_LEN: usize = 32;

/// Build the signing message for the validator-bind protocol.
///
/// Binds a validator's BLS identity to their ephemeral libp2p `PeerId` over a
/// per-session `nonce` chosen by the verifier. The Noise handshake proves
/// `PeerId` ownership; this signature proves the BLS key holder authorised
/// that `PeerId` *for this specific session*.
#[must_use]
pub fn validator_bind_message(
    network: &NetworkDefinition,
    peer_id_bytes: &[u8],
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DOMAIN_VALIDATOR_BIND.len() + 1 + peer_id_bytes.len() + nonce.len());
    message.extend_from_slice(DOMAIN_VALIDATOR_BIND);
    message.push(network.id);
    message.extend_from_slice(peer_id_bytes);
    message.extend_from_slice(nonce);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::shard::block_vote_message;
    use crate::{BlockHash, BlockHeight, Hash, Round, ShardId};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn test_validator_bind_message_deterministic_for_fixed_nonce() {
        let peer_id = b"12D3KooWDummyPeerId000000000000000";
        let nonce = [7u8; VALIDATOR_BIND_NONCE_LEN];

        let msg1 = validator_bind_message(&net(), peer_id, &nonce);
        let msg2 = validator_bind_message(&net(), peer_id, &nonce);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_VALIDATOR_BIND));
    }

    #[test]
    fn test_validator_bind_message_differs_per_nonce() {
        let peer_id = b"12D3KooWDummyPeerId000000000000000";
        let nonce_a = [1u8; VALIDATOR_BIND_NONCE_LEN];
        let nonce_b = [2u8; VALIDATOR_BIND_NONCE_LEN];

        let msg_a = validator_bind_message(&net(), peer_id, &nonce_a);
        let msg_b = validator_bind_message(&net(), peer_id, &nonce_b);

        // Different nonces must produce different messages — replay protection.
        assert_ne!(msg_a, msg_b);
    }

    #[test]
    fn test_validator_bind_differs_from_other_domains() {
        let bytes = b"some_bytes_here_for_testing_1234";
        let nonce = [0u8; VALIDATOR_BIND_NONCE_LEN];

        let bind_msg = validator_bind_message(&net(), bytes, &nonce);
        let block_msg = block_vote_message(
            &net(),
            ShardId::ROOT,
            BlockHeight::GENESIS,
            Round::INITIAL,
            &BlockHash::from_raw(Hash::from_bytes(bytes)),
            &BlockHash::ZERO,
        );

        assert_ne!(bind_msg, block_msg);
    }
}
