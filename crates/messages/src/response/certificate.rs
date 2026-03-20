//! Certificate fetch response.

use hyperscale_codec as sbor;
use hyperscale_codec::{Decoder as _, Encoder as _};
use hyperscale_types::{
    LedgerReceiptEntry, MessagePriority, NetworkMessage, TransactionCertificate, TypeConfig,
};

/// Response to a certificate fetch request.
///
/// Contains the requested certificates (those that the responder has).
/// Missing certificates are simply not included in the response.
#[derive(Debug, Clone)]
pub struct GetCertificatesResponse<C: TypeConfig> {
    /// The requested certificates that were found.
    pub certificates: Vec<TransactionCertificate>,
    /// Ledger receipts for the found certificates.
    pub ledger_receipts: Vec<LedgerReceiptEntry<C>>,
}

impl<C: TypeConfig> GetCertificatesResponse<C> {
    /// Create a response with found certificates and their receipts.
    pub fn new(
        certificates: Vec<TransactionCertificate>,
        ledger_receipts: Vec<LedgerReceiptEntry<C>>,
    ) -> Self {
        Self {
            certificates,
            ledger_receipts,
        }
    }

    /// Create an empty response (no certificates found).
    pub fn empty() -> Self {
        Self {
            certificates: vec![],
            ledger_receipts: vec![],
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

    /// Consume and return the certificates and receipts.
    pub fn into_parts(self) -> (Vec<TransactionCertificate>, Vec<LedgerReceiptEntry<C>>) {
        (self.certificates, self.ledger_receipts)
    }

    /// Consume and return the certificates only.
    pub fn into_certificates(self) -> Vec<TransactionCertificate> {
        self.certificates
    }
}

// Manual SBOR impls — LedgerReceiptEntry<C> has manual SBOR.

impl<'a, C: TypeConfig> sbor::Encode<sbor::NoCustomValueKind, sbor::BasicEncoder<'a>>
    for GetCertificatesResponse<C>
{
    fn encode_value_kind(
        &self,
        encoder: &mut sbor::BasicEncoder<'a>,
    ) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut sbor::BasicEncoder<'a>) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.certificates)?;
        encoder.encode(&self.ledger_receipts)?;
        Ok(())
    }
}

impl<'a, C: TypeConfig> sbor::Decode<sbor::NoCustomValueKind, sbor::BasicDecoder<'a>>
    for GetCertificatesResponse<C>
{
    fn decode_body_with_value_kind(
        decoder: &mut sbor::BasicDecoder<'a>,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let certificates: Vec<TransactionCertificate> = decoder.decode()?;
        let ledger_receipts: Vec<LedgerReceiptEntry<C>> = decoder.decode()?;
        Ok(Self {
            certificates,
            ledger_receipts,
        })
    }
}

impl<C: TypeConfig> sbor::Categorize<sbor::NoCustomValueKind> for GetCertificatesResponse<C> {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl<C: TypeConfig> sbor::Describe<sbor::NoCustomTypeKind> for GetCertificatesResponse<C> {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetCertificatesResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// Network message implementation
impl<C: TypeConfig> NetworkMessage for GetCertificatesResponse<C> {
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
    use hyperscale_codec::{basic_decode, basic_encode};
    use hyperscale_types::{Hash, TransactionDecision};
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

        let response: GetCertificatesResponse<hyperscale_radix_config::RadixConfig> =
            GetCertificatesResponse::new(vec![cert1.clone(), cert2.clone()], vec![]);
        assert_eq!(response.count(), 2);
        assert!(!response.is_empty());
    }

    #[test]
    fn test_empty_response() {
        let response: GetCertificatesResponse<hyperscale_radix_config::RadixConfig> =
            GetCertificatesResponse::empty();
        assert_eq!(response.count(), 0);
        assert!(response.is_empty());
    }

    #[test]
    fn test_sbor_roundtrip() {
        let cert1 = make_test_certificate(Hash::from_bytes(b"tx1"));
        let cert2 = make_test_certificate(Hash::from_bytes(b"tx2"));

        let response: GetCertificatesResponse<hyperscale_radix_config::RadixConfig> =
            GetCertificatesResponse::new(vec![cert1, cert2], vec![]);

        let encoded = basic_encode(&response).expect("encode");
        let decoded: GetCertificatesResponse<hyperscale_radix_config::RadixConfig> =
            basic_decode(&encoded).expect("decode");

        assert_eq!(response.count(), decoded.count());
    }
}
