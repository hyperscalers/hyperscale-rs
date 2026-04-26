//! Block top-up fetch request.

use crate::response::GetBlockTopUpResponse;
use hyperscale_types::{
    BlockHeight, MessagePriority, NetworkMessage, ProvisionHash, Request, TxHash, WaveIdHash,
};
use sbor::prelude::BasicSbor;

/// Request to fetch specific missing bodies for a previously-elided block.
///
/// Issued by a sync requester whose inventory bloom falsely claimed to
/// hold bodies it couldn't actually resolve at rehydration time. Instead
/// of discarding the whole block and refetching from scratch — which
/// would hit the same false positives on retry — the requester lists the
/// precisely-missing hashes and the responder returns just those bodies.
///
/// Each hash vec is empty if that category had no rehydration miss.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockTopUpRequest {
    /// Height of the block whose bodies are being topped up. Identifies
    /// the storage entry the responder reads from.
    pub height: BlockHeight,
    /// Transaction hashes whose bodies the requester needs.
    pub missing_tx: Vec<TxHash>,
    /// Finalized-wave hashes whose bodies the requester needs.
    pub missing_cert: Vec<WaveIdHash>,
    /// Provision hashes whose bodies the requester needs.
    pub missing_provision: Vec<ProvisionHash>,
}

impl GetBlockTopUpRequest {
    /// Create a new top-up request for the given block height and the
    /// per-category missing hashes.
    #[must_use]
    pub const fn new(
        height: BlockHeight,
        missing_tx: Vec<TxHash>,
        missing_cert: Vec<WaveIdHash>,
        missing_provision: Vec<ProvisionHash>,
    ) -> Self {
        Self {
            height,
            missing_tx,
            missing_cert,
            missing_provision,
        }
    }

    /// Total number of bodies being requested across categories.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.missing_tx.len() + self.missing_cert.len() + self.missing_provision.len()
    }

    /// Whether this request carries no hashes — a degenerate case the
    /// requester should skip rather than send.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

// Network message implementation
impl NetworkMessage for GetBlockTopUpRequest {
    fn message_type_id() -> &'static str {
        "block_topup.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

/// Type-safe request/response pairing.
impl Request for GetBlockTopUpRequest {
    type Response = GetBlockTopUpResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::Hash;
    use sbor::prelude::{basic_decode, basic_encode};

    #[test]
    fn total_and_is_empty() {
        let req = GetBlockTopUpRequest::new(BlockHeight(7), vec![], vec![], vec![]);
        assert!(req.is_empty());
        assert_eq!(req.total(), 0);

        let req = GetBlockTopUpRequest::new(
            BlockHeight(7),
            vec![TxHash::from_raw(Hash::from_bytes(b"tx"))],
            vec![],
            vec![ProvisionHash::from_raw(Hash::from_bytes(b"p"))],
        );
        assert!(!req.is_empty());
        assert_eq!(req.total(), 2);
    }

    #[test]
    fn sbor_roundtrip() {
        let req = GetBlockTopUpRequest::new(
            BlockHeight(42),
            vec![TxHash::from_raw(Hash::from_bytes(b"tx1"))],
            vec![WaveIdHash::from_raw(Hash::from_bytes(b"wave1"))],
            vec![ProvisionHash::from_raw(Hash::from_bytes(b"prov1"))],
        );
        let bytes = basic_encode(&req).unwrap();
        let decoded: GetBlockTopUpRequest = basic_decode(&bytes).unwrap();
        assert_eq!(req, decoded);
    }
}
