//! Signing message for validator-bind endpoint authentication.

use hyperscale_hbor::Hbor;

use crate::network::gossip::ENDPOINT_ID_LEN;
use crate::signing::NetworkId;

/// Length of the challenge nonce a validator-bind signature covers.
pub const VALIDATOR_BIND_NONCE_LEN: usize = 32;

/// What a validator-bind handshake signature covers: the endpoint id being
/// bound plus the challenger's nonce, so a bind signature cannot be
/// replayed for a different endpoint or a different challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-validator-bind-v1", signing_context = NetworkId)]
pub struct ValidatorBindMessage {
    /// The endpoint id being bound to the validator key.
    pub endpoint_id: [u8; ENDPOINT_ID_LEN],
    /// The challenger's nonce.
    pub nonce: [u8; VALIDATOR_BIND_NONCE_LEN],
}
