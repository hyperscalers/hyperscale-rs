//! Local provisions fetch request (intra-shard DA).

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetLocalProvisionsResponse;
use crate::{MAX_PROVISIONS_PER_BLOCK, MessageClass, NetworkMessage, ProvisionHash, Request};

/// Request to fetch provision batches by hash.
///
/// Used when a validator is missing provisions referenced by a pending
/// block. The responder resolves each hash from the local provision store
/// — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetLocalProvisionsRequest {
    /// Hashes of the provisions being requested.
    ///
    /// Capped as the response is: a request asks for the batches a block
    /// names, and a block carries at most this many.
    pub batch_hashes: Capped<Vec<ProvisionHash>, MAX_PROVISIONS_PER_BLOCK>,
}

impl GetLocalProvisionsRequest {
    /// Build a request for the listed `batch_hashes`.
    #[must_use]
    pub const fn new(batch_hashes: Capped<Vec<ProvisionHash>, MAX_PROVISIONS_PER_BLOCK>) -> Self {
        Self { batch_hashes }
    }
}

impl NetworkMessage for GetLocalProvisionsRequest {
    fn message_type_id() -> &'static str {
        "local_provision.request"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

impl Request for GetLocalProvisionsRequest {
    type Response = GetLocalProvisionsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetLocalProvisionsRequest {
            batch_hashes: Capped::from_array([
                ProvisionHash::from_raw(Hash::from_bytes(b"batch1")),
                ProvisionHash::from_raw(Hash::from_bytes(b"batch2")),
            ]),
        };
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetLocalProvisionsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    /// A claimed length past the cap is refused before any element is
    /// decoded, so a peer cannot make the decoder allocate for a batch
    /// no honest block could name.
    #[test]
    fn decode_rejects_an_oversized_request() {
        use hyperscale_hbor::{DecodeError, varint};

        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        // Filler so the claimed length clears the input-capacity check
        // and the bound is what refuses it.
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_PROVISIONS_PER_BLOCK + 1) * 64,
        ));
        let err = hbor_from_slice::<GetLocalProvisionsRequest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_PROVISIONS_PER_BLOCK && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
