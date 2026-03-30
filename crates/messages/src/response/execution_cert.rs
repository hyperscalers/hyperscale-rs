//! Execution certificate fetch response for fallback recovery.

use hyperscale_types::{ExecutionCertificate, MessagePriority, NetworkMessage};
use sbor::prelude::BasicSbor;

/// Response to an execution certificate fetch request.
///
/// Returns the requested execution certificates from the source shard's cache.
/// `None` means the source shard cannot serve this request (cert not cached,
/// or the block has been pruned). The requester should try a different peer.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetExecutionCertsResponse {
    /// The requested execution certificates.
    ///
    /// - `Some(certs)` — successfully found certificates (may be empty if
    ///   no matching waves were cached).
    /// - `None` — the source shard cannot serve this request.
    pub certificates: Option<Vec<ExecutionCertificate>>,
}

impl NetworkMessage for GetExecutionCertsResponse {
    fn message_type_id() -> &'static str {
        "execution_cert.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip_empty() {
        let response = GetExecutionCertsResponse {
            certificates: Some(vec![]),
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetExecutionCertsResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetExecutionCertsResponse { certificates: None };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetExecutionCertsResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
