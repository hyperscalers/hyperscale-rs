//! A bound peer as the limits on its traffic see it.

use hyperscale_types::ValidatorId;
use iroh::EndpointId;

/// A bound peer: the endpoint it connects from, and the validator it
/// answers as.
///
/// What a peer may cost this host is kept per principal, the lowest
/// validator it proved in the bind handshake, not per endpoint. An endpoint
/// costs nothing to replace, and a validator that bound again under a new
/// one would otherwise start every budget, cooldown and slot afresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub endpoint: EndpointId,
    pub principal: ValidatorId,
}
