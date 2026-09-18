//! Finalization fetch request (intra-shard DA).

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetFinalizationsResponse;
use crate::{FinalizationHash, MAX_FINALIZED_TX_PER_BLOCK, MessageClass, NetworkMessage, Request};

/// Request to fetch finalizations by identity.
///
/// Used when a validator is missing finalizations referenced by a pending
/// block. The responder resolves each from the local finalization cache
/// (and falls through to storage where supported) — no scope information
/// is needed, since the identity is a hash of the finalization's own
/// content and the block manifest names exactly these.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetFinalizationsRequest {
    /// Finalization identities being requested.
    ///
    /// A block names at most this many, and a request asks for the ones
    /// a block names.
    pub finalization_hashes: Capped<Vec<FinalizationHash>, MAX_FINALIZED_TX_PER_BLOCK>,
}

impl GetFinalizationsRequest {
    /// Build a request for the listed `finalization_hashes`.
    #[must_use]
    pub const fn new(
        finalization_hashes: Capped<Vec<FinalizationHash>, MAX_FINALIZED_TX_PER_BLOCK>,
    ) -> Self {
        Self {
            finalization_hashes,
        }
    }
}

impl NetworkMessage for GetFinalizationsRequest {
    fn message_type_id() -> &'static str {
        "finalization.request"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

impl Request for GetFinalizationsRequest {
    type Response = GetFinalizationsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.finalizations.is_empty()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetFinalizationsRequest {
            finalization_hashes: Capped::from_array([
                FinalizationHash::from_raw(Hash::from_bytes(b"one")),
                FinalizationHash::from_raw(Hash::from_bytes(b"two")),
            ]),
        };
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetFinalizationsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    /// A claimed length past the cap is refused before any element is
    /// decoded, so a peer cannot make the decoder allocate for a batch
    /// no honest block could name.
    #[test]
    fn decode_rejects_an_oversized_request() {
        use hyperscale_hbor::{DecodeError, varint};

        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_FINALIZED_TX_PER_BLOCK + 1).unwrap();
        // Filler so the claimed length clears the input-capacity check
        // and the bound is what refuses it.
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_FINALIZED_TX_PER_BLOCK + 1) * 64,
        ));
        let err = hbor_from_slice::<GetFinalizationsRequest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_FINALIZED_TX_PER_BLOCK && actual == MAX_FINALIZED_TX_PER_BLOCK + 1
        ));
    }
}
