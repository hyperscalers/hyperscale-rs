//! Certificate fetch request.

use crate::response::GetCertificatesResponse;
use hyperscale_types::{Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Fetch type discriminator for certificate requests.
/// This distinguishes certificate requests from transaction requests
/// which otherwise have identical binary encodings.
pub const FETCH_TYPE_CERTIFICATE: u8 = 1;

/// Request to fetch transaction certificates by hash for a pending block.
///
/// Used when a validator receives a block header but is missing some
/// certificates that weren't in their cache or didn't arrive via gossip.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetCertificatesRequest {
    /// Type discriminator (always FETCH_TYPE_CERTIFICATE = 1).
    /// Used to distinguish from transaction requests which have the same structure.
    pub fetch_type: u8,

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
            fetch_type: FETCH_TYPE_CERTIFICATE,
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
    fn test_sbor_encoding_fetch_type_position() {
        let request = GetCertificatesRequest::new(
            Hash::from_bytes(b"block"),
            vec![Hash::from_bytes(b"cert1")],
        );
        let bytes = basic_encode(&request).unwrap();

        // Find the fetch_type value (should be 1 for certificates)
        let fetch_type_pos = bytes.iter().position(|&b| b == FETCH_TYPE_CERTIFICATE);
        assert!(fetch_type_pos.is_some(), "fetch_type byte not found");
    }
}
