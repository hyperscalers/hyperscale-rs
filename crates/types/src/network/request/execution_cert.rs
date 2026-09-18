//! Execution certificate fetch request for fallback recovery.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetExecutionCertsResponse;
use crate::{MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, Request, TxHash};

/// Request to fetch missing execution certificates from a source shard.
///
/// Sent by target shards when a source shard's certificate for a
/// transaction they are party to hasn't arrived within the timeout window.
/// Any node in the source shard that holds the certificate can serve it.
///
/// Keyed by transaction rather than by the certificate's own identity,
/// because the requester doesn't have that identity: it learned of the
/// transaction from the source shard's committed header, and which
/// certificate ends up covering it is the source shard's business. One
/// returned certificate can answer for several requested transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetExecutionCertsRequest {
    /// Transactions whose outcome from this shard is missing.
    pub tx_hashes: Capped<Vec<TxHash>, MAX_TXS_PER_BLOCK>,
}

impl NetworkMessage for GetExecutionCertsRequest {
    fn message_type_id() -> &'static str {
        "execution_cert.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetExecutionCertsRequest {
    type Response = GetExecutionCertsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.certificates.as_ref().is_none_or(Vec::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetExecutionCertsRequest {
            tx_hashes: Capped::from_array([
                TxHash::from(Hash::from_bytes(b"tx one")),
                TxHash::from(Hash::from_bytes(b"tx two")),
            ]),
        };

        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetExecutionCertsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
