//! Finalized wave fetch response (intra-shard DA).

use hyperscale_types::{FinalizedWave, MessagePriority, NetworkMessage};

/// Response to a finalized wave fetch request.
///
/// Contains the requested finalized waves that the responder has.
/// Missing waves are simply not included in the response.
///
/// `FinalizedWave` has manual SBOR impl (Arc fields) so it can be
/// encoded/decoded directly without a wire wrapper.
#[derive(Debug, Clone)]
pub struct GetFinalizedWavesResponse {
    /// The requested finalized waves that were found.
    pub waves: Vec<FinalizedWave>,
}

impl GetFinalizedWavesResponse {
    /// Build a response carrying the supplied finalized waves.
    #[must_use]
    pub fn new(waves: Vec<FinalizedWave>) -> Self {
        Self { waves }
    }

    /// Build an empty response (responder had none of the requested waves).
    #[must_use]
    pub fn empty() -> Self {
        Self { waves: vec![] }
    }
}

impl NetworkMessage for GetFinalizedWavesResponse {
    fn message_type_id() -> &'static str {
        "finalized_wave.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

// Manual SBOR: Vec<FinalizedWave> where FinalizedWave has manual SBOR.
// We encode as a simple tuple with one field (the vec).
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for GetFinalizedWavesResponse
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(1)?;
        encoder.encode(&self.waves)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for GetFinalizedWavesResponse
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
        let waves: Vec<FinalizedWave> = decoder.decode()?;
        Ok(Self { waves })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for GetFinalizedWavesResponse {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for GetFinalizedWavesResponse {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetFinalizedWavesResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}
