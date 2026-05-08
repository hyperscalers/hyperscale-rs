//! Local provisions fetch response (intra-shard DA).

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{BoundedVec, MAX_PROVISIONS_PER_BLOCK, MessageClass, NetworkMessage, Provisions};

/// Response to a local provisions fetch request.
///
/// `provisions` holds the batches the responder has. The requester knows the
/// hashes it asked for, so missing hashes are computed client-side as
/// `requested - returned`; the wire format does not duplicate that diff.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    /// Provision batches the responder had locally.
    ///
    /// Capped at [`MAX_PROVISIONS_PER_BLOCK`] — the natural ceiling since a
    /// single block can't reference more provisions than this, and the fetch
    /// dispatcher chunks at 16 ids per call. `Arc`-wrapped because the
    /// server-side provision store holds each batch behind `Arc` already.
    pub provisions: BoundedVec<Arc<Provisions>, MAX_PROVISIONS_PER_BLOCK>,
}

impl GetLocalProvisionsResponse {
    /// Build a response carrying `provisions`.
    ///
    /// # Panics
    ///
    /// Panics if `provisions.len() > MAX_PROVISIONS_PER_BLOCK`. The fetch
    /// dispatcher chunks at 16 ids per call, so well-behaved callers sit
    /// far below the cap.
    #[must_use]
    pub fn new(provisions: Vec<Arc<Provisions>>) -> Self {
        Self {
            provisions: provisions.into(),
        }
    }

    /// Build an empty response (responder had none of the requested batches).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            provisions: BoundedVec::new(),
        }
    }
}

impl NetworkMessage for GetLocalProvisionsResponse {
    fn message_type_id() -> &'static str {
        "local_provision.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    #[test]
    fn test_empty_response() {
        let resp = GetLocalProvisionsResponse::empty();
        assert!(resp.provisions.is_empty());
    }

    #[test]
    fn empty_response_roundtrips() {
        let original = GetLocalProvisionsResponse::empty();
        let bytes = basic_encode(&original).unwrap();
        let decoded: GetLocalProvisionsResponse = basic_decode(&bytes).unwrap();
        assert!(decoded.provisions.is_empty());
    }

    /// Hand-roll a response whose `provisions` length exceeds the cap. The
    /// `BoundedVec` decoder fires before any per-batch decode work happens.
    #[test]
    fn decode_rejects_oversized_provisions_count() {
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(1).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<GetLocalProvisionsResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
