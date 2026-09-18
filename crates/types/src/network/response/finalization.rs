//! Finalization fetch response (intra-shard DA).

use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor};

use crate::{Finalization, MessageClass, NetworkMessage};

/// Cap on finalizations returned in a single response at decode time.
///
/// Matches the per-collection cap used by [`hyperscale_types::Block`].
/// The fetch dispatcher chunks finalization requests at 4 ids per call,
/// so legitimate responses sit in single digits; everything beyond is
/// rejected before any per-tick decode work.
const MAX_FINALIZATIONS_PER_RESPONSE: usize = 10_000;

/// Response to a finalization fetch request.
///
/// Contains the requested finalizations that the responder has.
/// Missing entries are simply not included in the response.
#[derive(Debug, Clone, Hbor)]
pub struct GetFinalizationsResponse {
    /// The requested finalizations that were found.
    ///
    /// `Arc`-wrapped because both the server-side cache and every
    /// downstream consumer hold `Finalization` behind `Arc` already.
    pub finalizations: Capped<Vec<Arc<Finalization>>, MAX_FINALIZATIONS_PER_RESPONSE>,
}

impl GetFinalizationsResponse {
    /// Build a response carrying the supplied finalizations.
    ///
    /// # Panics
    ///
    /// Panics if `finalizations.len() > MAX_FINALIZATIONS_PER_RESPONSE`.
    #[must_use]
    pub const fn new(
        finalizations: Capped<Vec<Arc<Finalization>>, MAX_FINALIZATIONS_PER_RESPONSE>,
    ) -> Self {
        Self { finalizations }
    }

    /// Build an empty response (responder had none of those requested).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            finalizations: Capped::empty(),
        }
    }
}

impl NetworkMessage for GetFinalizationsResponse {
    fn message_type_id() -> &'static str {
        "finalization.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;

    #[test]
    fn decode_rejects_oversized_finalization_count() {
        // Hand-roll a response whose ticks length prefix exceeds the cap.
        // The cap fires before any per-tick decode work is attempted.
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_FINALIZATIONS_PER_RESPONSE + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_FINALIZATIONS_PER_RESPONSE + 1) * 256,
        ));
        let err = hbor_from_slice::<GetFinalizationsResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_FINALIZATIONS_PER_RESPONSE
                    && actual == MAX_FINALIZATIONS_PER_RESPONSE + 1
        ));
    }

    #[test]
    fn empty_response_roundtrips() {
        let original = GetFinalizationsResponse::empty();
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: GetFinalizationsResponse = hbor_from_slice(&bytes).unwrap();
        assert!(decoded.finalizations.is_empty());
    }
}
