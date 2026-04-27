//! Finalized wave fetch request (intra-shard DA).

use crate::response::GetFinalizedWavesResponse;
#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{MessagePriority, NetworkMessage, Request, WaveIdHash};
use sbor::prelude::BasicSbor;

/// Request to fetch finalized waves by id-hash.
///
/// Used when a validator is missing finalized waves referenced by a pending
/// block. The responder resolves each id-hash from the local finalized-wave
/// cache — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetFinalizedWavesRequest {
    /// Wave ID hashes being requested.
    pub wave_id_hashes: Vec<WaveIdHash>,
}

impl GetFinalizedWavesRequest {
    /// Build a request for the listed `wave_id_hashes`.
    #[must_use]
    pub const fn new(wave_id_hashes: Vec<WaveIdHash>) -> Self {
        Self { wave_id_hashes }
    }
}

impl NetworkMessage for GetFinalizedWavesRequest {
    fn message_type_id() -> &'static str {
        "finalized_wave.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl Request for GetFinalizedWavesRequest {
    type Response = GetFinalizedWavesResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetFinalizedWavesRequest {
            wave_id_hashes: vec![
                WaveIdHash::from_raw(Hash::from_bytes(b"wave1")),
                WaveIdHash::from_raw(Hash::from_bytes(b"wave2")),
            ],
        };
        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetFinalizedWavesRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
