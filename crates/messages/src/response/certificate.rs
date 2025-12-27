//! Certificate fetch response.

use hyperscale_types::{MessagePriority, NetworkMessage, TransactionCertificate};
use sbor::prelude::BasicSbor;

/// Response to a certificate fetch request.
///
/// Contains the requested certificates (those that the responder has).
/// Missing certificates are simply not included in the response.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetCertificatesResponse {
    /// The requested certificates that were found.
    pub certificates: Vec<TransactionCertificate>,
}

impl GetCertificatesResponse {
    /// Create a response with found certificates.
    pub fn new(certificates: Vec<TransactionCertificate>) -> Self {
        Self { certificates }
    }

    /// Create an empty response (no certificates found).
    pub fn empty() -> Self {
        Self {
            certificates: vec![],
        }
    }

    /// Get the number of certificates in the response.
    pub fn count(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the response is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Consume and return the certificates.
    pub fn into_certificates(self) -> Vec<TransactionCertificate> {
        self.certificates
    }
}

// Network message implementation
impl NetworkMessage for GetCertificatesResponse {
    fn message_type_id() -> &'static str {
        "certificate.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Hash, TransactionDecision};
    use sbor::prelude::{basic_decode, basic_encode};
    use std::collections::BTreeMap;

    fn make_test_certificate(tx_hash: Hash) -> TransactionCertificate {
        TransactionCertificate {
            transaction_hash: tx_hash,
            decision: TransactionDecision::Accept,
            shard_proofs: BTreeMap::new(),
        }
    }

    #[test]
    fn test_get_certificates_response() {
        let cert1 = make_test_certificate(Hash::from_bytes(b"tx1"));
        let cert2 = make_test_certificate(Hash::from_bytes(b"tx2"));

        let response = GetCertificatesResponse::new(vec![cert1.clone(), cert2.clone()]);
        assert_eq!(response.count(), 2);
        assert!(!response.is_empty());
    }

    #[test]
    fn test_empty_response() {
        let response = GetCertificatesResponse::empty();
        assert_eq!(response.count(), 0);
        assert!(response.is_empty());
    }

    #[test]
    fn test_sbor_roundtrip() {
        let cert1 = make_test_certificate(Hash::from_bytes(b"tx1"));
        let cert2 = make_test_certificate(Hash::from_bytes(b"tx2"));

        let response = GetCertificatesResponse::new(vec![cert1, cert2]);

        let encoded = basic_encode(&response).expect("encode");
        let decoded: GetCertificatesResponse = basic_decode(&encoded).expect("decode");

        assert_eq!(response, decoded);
    }
}
