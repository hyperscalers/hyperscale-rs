//! Finalized wave fetch request (intra-shard DA).

use crate::response::GetFinalizedWavesResponse;
#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{BlockHash, MessagePriority, NetworkMessage, Request, WaveIdHash};
use sbor::prelude::BasicSbor;

/// Request to fetch finalized wave data for a pending block.
///
/// Used when a validator receives a block header with `cert_hashes`
/// but hasn't independently finalized those waves yet. Tries the proposer
/// first, rotates to local shard peers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetFinalizedWavesRequest {
    /// Hash of the block that needs these finalized waves.
    pub block_hash: BlockHash,

    /// Wave ID hashes (from `BlockManifest.cert_hashes`) being requested.
    pub wave_id_hashes: Vec<WaveIdHash>,
}

impl GetFinalizedWavesRequest {
    /// Build a request for the listed `wave_id_hashes` against `block_hash`.
    #[must_use]
    pub const fn new(block_hash: BlockHash, wave_id_hashes: Vec<WaveIdHash>) -> Self {
        Self {
            block_hash,
            wave_id_hashes,
        }
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
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
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
