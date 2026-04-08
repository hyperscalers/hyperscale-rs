//! Certificate fetch response.

use hyperscale_types::{MessagePriority, NetworkMessage, WaveCertificate};
use std::sync::Arc;

/// Response to a certificate fetch request.
///
/// Contains the requested certificates (those that the responder has).
/// Missing certificates are simply not included in the response.
#[derive(Debug, Clone)]
pub struct GetCertificatesResponse {
    /// The requested certificates that were found.
    /// Uses Arc to avoid copying certificate data.
    pub certificates: Vec<Arc<WaveCertificate>>,
}

impl GetCertificatesResponse {
    /// Create a response with found certificates.
    pub fn new(certificates: Vec<Arc<WaveCertificate>>) -> Self {
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
    pub fn into_certificates(self) -> Vec<Arc<WaveCertificate>> {
        self.certificates
    }
}

// Manual PartialEq - compare by transaction hashes
impl PartialEq for GetCertificatesResponse {
    fn eq(&self, other: &Self) -> bool {
        if self.certificates.len() != other.certificates.len() {
            return false;
        }
        self.certificates
            .iter()
            .zip(other.certificates.iter())
            .all(|(a, b)| a.wave_id == b.wave_id)
    }
}

impl Eq for GetCertificatesResponse {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for GetCertificatesResponse
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(1)?; // 1 field

        // Encode certificates array (unwrap Arc for each)
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.certificates.len())?;
        for cert in &self.certificates {
            encoder.encode_deeper_body(cert.as_ref())?;
        }

        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for GetCertificatesResponse
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 1 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 1,
                actual: length,
            });
        }

        // Decode certificates array (wrap each in Arc)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let cert_count = decoder.read_size()?;
        if cert_count > 1_000 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 1_000,
                actual: cert_count,
            });
        }
        let mut certificates = Vec::with_capacity(cert_count);
        for _ in 0..cert_count {
            let cert: WaveCertificate =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            certificates.push(Arc::new(cert));
        }

        Ok(Self { certificates })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for GetCertificatesResponse {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for GetCertificatesResponse {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetCertificatesResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
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
