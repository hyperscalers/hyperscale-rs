//! Certificate fetch request.

use crate::response::GetCertificatesResponse;
use hyperscale_types::{Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch wave certificates by hash for a pending block.
///
/// Used when a validator receives a block header but is missing some
/// certificates that weren't in their cache or didn't arrive via gossip.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetCertificatesRequest {
    /// Hash of the block that needs these certificates.
    /// Used by the responder to prioritize and validate the request.
    pub block_hash: Hash,

    /// Hashes of the certificates being requested.
    pub cert_hashes: Vec<Hash>,
}

impl GetCertificatesRequest {
    /// Create a new certificate fetch request.
    pub fn new(block_hash: Hash, cert_hashes: Vec<Hash>) -> Self {
        Self {
            block_hash,
            cert_hashes,
        }
    }

    /// Get the number of certificates being requested.
    pub fn count(&self) -> usize {
        self.cert_hashes.len()
    }
}

// Network message implementation
impl NetworkMessage for GetCertificatesRequest {
    fn message_type_id() -> &'static str {
        "certificate.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

/// Type-safe request/response pairing.
impl Request for GetCertificatesRequest {
    type Response = GetCertificatesResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbor::prelude::basic_encode;

    #[test]
    fn test_get_certificates_request() {
        let block_hash = Hash::from_bytes(b"block123");
        let cert_hashes = vec![
            Hash::from_bytes(b"cert1"),
            Hash::from_bytes(b"cert2"),
            Hash::from_bytes(b"cert3"),
        ];

        let request = GetCertificatesRequest::new(block_hash, cert_hashes.clone());
        assert_eq!(request.block_hash, block_hash);
        assert_eq!(request.cert_hashes, cert_hashes);
        assert_eq!(request.count(), 3);
    }

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetCertificatesRequest::new(
            Hash::from_bytes(b"block"),
            vec![Hash::from_bytes(b"cert1")],
        );
        let bytes = basic_encode(&request).unwrap();
        let decoded: GetCertificatesRequest = sbor::prelude::basic_decode(&bytes).unwrap();
        assert_eq!(request, decoded);
    }
}
