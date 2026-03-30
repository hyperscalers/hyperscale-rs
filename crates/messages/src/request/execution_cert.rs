//! Execution certificate fetch request for fallback recovery.

use crate::response::GetExecutionCertsResponse;
use hyperscale_types::{MessagePriority, NetworkMessage, Request, WaveId};
use sbor::prelude::BasicSbor;

/// Request to fetch missing execution certificates from a source shard.
///
/// Sent by target shards when a remote block's designated broadcaster fails
/// to deliver execution certs within the timeout window. Any node in the
/// source shard that has aggregated the cert can serve this request.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetExecutionCertsRequest {
    /// Height of the source block whose execution certs are needed.
    pub block_height: u64,
    /// Which waves' certs are missing.
    pub wave_ids: Vec<WaveId>,
}

impl NetworkMessage for GetExecutionCertsRequest {
    fn message_type_id() -> &'static str {
        "execution_cert.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl Request for GetExecutionCertsRequest {
    type Response = GetExecutionCertsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::ShardGroupId;
    use std::collections::BTreeSet;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetExecutionCertsRequest {
            block_height: 42,
            wave_ids: vec![WaveId(BTreeSet::from([ShardGroupId(1), ShardGroupId(2)]))],
        };

        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetExecutionCertsRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
