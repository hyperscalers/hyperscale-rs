//! Finalized wave fetch response (intra-shard DA).

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{BoundedVec, FinalizedWave, MessageClass, NetworkMessage};

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
#[derive(Debug, Clone, BasicSbor)]
pub struct GetFinalizedWavesResponse {
    /// The requested finalized waves that were found.
    ///
    /// `Arc`-wrapped because both the server-side cache and every
    /// downstream consumer hold `FinalizedWave` behind `Arc` already.
    pub waves: BoundedVec<Arc<FinalizedWave>, MAX_FINALIZED_WAVES_PER_RESPONSE>,
}

impl GetFinalizedWavesResponse {
    /// Build a response carrying the supplied finalized waves.
    ///
    /// # Panics
    ///
    /// Panics if `waves.len() > MAX_FINALIZED_WAVES_PER_RESPONSE`.
    #[must_use]
    pub fn new(waves: Vec<Arc<FinalizedWave>>) -> Self {
        Self {
            waves: waves.into(),
        }
    }

    /// Build an empty response (responder had none of the requested waves).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            waves: BoundedVec::new(),
        }
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

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
    };

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
