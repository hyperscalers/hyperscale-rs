//! Block top-up fetch response.

use hyperscale_types::{
    FinalizedWave, MessagePriority, NetworkMessage, ProvisionHash, Provisions, RoutableTransaction,
    TxHash, WaveIdHash,
};
use std::sync::Arc;

/// Response to a [`GetBlockTopUpRequest`](crate::request::GetBlockTopUpRequest).
///
/// Carries only the bodies the responder actually has for each requested
/// hash. Missing entries (e.g. the responder's own cache was evicted
/// since it served the main block response) are simply absent — the
/// requester merges what arrives into its pending elided block and, on
/// any still-missing body, falls back to a full refetch.
///
/// Pairs keep hashes alongside bodies so the requester can merge without
/// recomputing hashes over large payloads.
#[derive(Debug, Clone)]
pub struct GetBlockTopUpResponse {
    pub transactions: Vec<(TxHash, Arc<RoutableTransaction>)>,
    pub certificates: Vec<(WaveIdHash, Arc<FinalizedWave>)>,
    pub provisions: Vec<(ProvisionHash, Arc<Provisions>)>,
}

impl GetBlockTopUpResponse {
    /// Construct a response from resolved bodies.
    pub fn new(
        transactions: Vec<(TxHash, Arc<RoutableTransaction>)>,
        certificates: Vec<(WaveIdHash, Arc<FinalizedWave>)>,
        provisions: Vec<(ProvisionHash, Arc<Provisions>)>,
    ) -> Self {
        Self {
            transactions,
            certificates,
            provisions,
        }
    }

    /// Empty response — the responder had no requested bodies.
    pub fn empty() -> Self {
        Self {
            transactions: Vec::new(),
            certificates: Vec::new(),
            provisions: Vec::new(),
        }
    }

    /// Total number of bodies returned across categories.
    pub fn total(&self) -> usize {
        self.transactions.len() + self.certificates.len() + self.provisions.len()
    }
}

impl PartialEq for GetBlockTopUpResponse {
    fn eq(&self, other: &Self) -> bool {
        fn eq_tx(
            a: &[(TxHash, Arc<RoutableTransaction>)],
            b: &[(TxHash, Arc<RoutableTransaction>)],
        ) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|((ha, ta), (hb, tb))| ha == hb && ta.hash() == tb.hash())
        }
        fn eq_cert(
            a: &[(WaveIdHash, Arc<FinalizedWave>)],
            b: &[(WaveIdHash, Arc<FinalizedWave>)],
        ) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|((ha, fa), (hb, fb))| ha == hb && fa.as_ref() == fb.as_ref())
        }
        fn eq_prov(
            a: &[(ProvisionHash, Arc<Provisions>)],
            b: &[(ProvisionHash, Arc<Provisions>)],
        ) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|((ha, pa), (hb, pb))| ha == hb && pa.hash() == pb.hash())
        }
        eq_tx(&self.transactions, &other.transactions)
            && eq_cert(&self.certificates, &other.certificates)
            && eq_prov(&self.provisions, &other.provisions)
    }
}

impl Eq for GetBlockTopUpResponse {}

// ============================================================================
// Manual SBOR: each body is Arc-wrapped in memory; on the wire we encode the
// inner value via `encode_deeper_body(as_ref())` and Arc-wrap on decode.
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for GetBlockTopUpResponse
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;

        encode_pairs_arc(encoder, &self.transactions)?;
        encode_pairs_arc(encoder, &self.certificates)?;
        encode_pairs_arc(encoder, &self.provisions)?;

        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for GetBlockTopUpResponse
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let transactions = decode_pairs_arc::<_, TxHash, RoutableTransaction>(decoder)?;
        let certificates = decode_pairs_arc::<_, WaveIdHash, FinalizedWave>(decoder)?;
        let provisions = decode_pairs_arc::<_, ProvisionHash, Provisions>(decoder)?;
        Ok(Self {
            transactions,
            certificates,
            provisions,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for GetBlockTopUpResponse {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for GetBlockTopUpResponse {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetBlockTopUpResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

fn encode_pairs_arc<E, H, T>(
    encoder: &mut E,
    items: &[(H, Arc<T>)],
) -> Result<(), sbor::EncodeError>
where
    E: sbor::Encoder<sbor::NoCustomValueKind>,
    H: sbor::Encode<sbor::NoCustomValueKind, E>,
    T: sbor::Encode<sbor::NoCustomValueKind, E>,
{
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(items.len())?;
    for (h, body) in items {
        encoder.write_size(2)?;
        encoder.encode(h)?;
        encoder.encode_deeper_body(body.as_ref())?;
    }
    Ok(())
}

fn decode_pairs_arc<D, H, T>(decoder: &mut D) -> Result<Vec<(H, Arc<T>)>, sbor::DecodeError>
where
    D: sbor::Decoder<sbor::NoCustomValueKind>,
    H: sbor::Decode<sbor::NoCustomValueKind, D> + sbor::Categorize<sbor::NoCustomValueKind>,
    T: sbor::Decode<sbor::NoCustomValueKind, D>,
{
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let field_count = decoder.read_size()?;
        if field_count != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: field_count,
            });
        }
        let h: H = decoder.decode()?;
        let body: T = decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        out.push((h, Arc::new(body)));
    }
    Ok(out)
}

// Network message implementation
impl NetworkMessage for GetBlockTopUpResponse {
    fn message_type_id() -> &'static str {
        "block_topup.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_transaction;
    use sbor::prelude::{basic_decode, basic_encode};

    #[test]
    fn empty_response_defaults() {
        let r = GetBlockTopUpResponse::empty();
        assert_eq!(r.total(), 0);
        assert!(r.transactions.is_empty());
        assert!(r.certificates.is_empty());
        assert!(r.provisions.is_empty());
    }

    #[test]
    fn sbor_roundtrip_tx_only() {
        let tx = Arc::new(test_transaction(7));
        let resp =
            GetBlockTopUpResponse::new(vec![(tx.hash(), Arc::clone(&tx))], Vec::new(), Vec::new());
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetBlockTopUpResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }
}
