//! Finalized wave fetch response (intra-shard DA).

use std::sync::Arc;

use hyperscale_types::{
    FinalizedWave, MessageClass, NetworkMessage, decode_finalized_wave_vec,
    encode_finalized_wave_vec,
};
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

/// Cap on finalized waves returned in a single response at decode time.
///
/// Matches the per-collection cap used by [`hyperscale_types::Block`].
/// The fetch dispatcher chunks finalized-wave requests at 4 ids per call,
/// so legitimate responses sit in single digits; everything beyond is
/// rejected before any per-wave decode work.
const MAX_FINALIZED_WAVES_PER_RESPONSE: usize = 10_000;

/// Response to a finalized wave fetch request.
///
/// Contains the requested finalized waves that the responder has.
/// Missing waves are simply not included in the response.
#[derive(Debug, Clone)]
pub struct GetFinalizedWavesResponse {
    /// The requested finalized waves that were found.
    ///
    /// `Arc`-wrapped because both the server-side cache and every
    /// downstream consumer hold `FinalizedWave` behind `Arc` already.
    pub waves: Vec<Arc<FinalizedWave>>,
}

impl GetFinalizedWavesResponse {
    /// Build a response carrying the supplied finalized waves.
    #[must_use]
    pub const fn new(waves: Vec<Arc<FinalizedWave>>) -> Self {
        Self { waves }
    }

    /// Build an empty response (responder had none of the requested waves).
    #[must_use]
    pub const fn empty() -> Self {
        Self { waves: vec![] }
    }
}

impl NetworkMessage for GetFinalizedWavesResponse {
    fn message_type_id() -> &'static str {
        "finalized_wave.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

// Manual SBOR: Vec<FinalizedWave> where FinalizedWave has manual SBOR.
// We encode as a simple tuple with one field (the vec).
impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for GetFinalizedWavesResponse {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(1)?;
        encode_finalized_wave_vec(encoder, &self.waves)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for GetFinalizedWavesResponse {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 1 {
            return Err(DecodeError::UnexpectedSize {
                expected: 1,
                actual: length,
            });
        }
        let waves = decode_finalized_wave_vec(decoder, MAX_FINALIZED_WAVES_PER_RESPONSE)?;
        Ok(Self { waves })
    }
}

impl Categorize<NoCustomValueKind> for GetFinalizedWavesResponse {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for GetFinalizedWavesResponse {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("GetFinalizedWavesResponse", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode};

    use super::*;

    #[test]
    fn decode_rejects_oversized_waves_count() {
        // Hand-roll a response whose waves length prefix exceeds the cap.
        // The cap fires before any per-wave decode work is attempted.
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(1).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_FINALIZED_WAVES_PER_RESPONSE + 1)
                .unwrap();
        }
        let err = basic_decode::<GetFinalizedWavesResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_FINALIZED_WAVES_PER_RESPONSE
                    && actual == MAX_FINALIZED_WAVES_PER_RESPONSE + 1
        ));
    }

    #[test]
    fn empty_response_roundtrips() {
        use sbor::basic_encode;
        let original = GetFinalizedWavesResponse::empty();
        let bytes = basic_encode(&original).unwrap();
        let decoded: GetFinalizedWavesResponse = basic_decode(&bytes).unwrap();
        assert!(decoded.waves.is_empty());
    }
}
