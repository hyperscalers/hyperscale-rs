//! Settled-transaction window response for the split-boundary fence.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MAX_FINALIZED_TX_PER_BLOCK, MessageClass, NetworkMessage, TxHash};

/// The complete settled-transaction window list of a terminated shard.
///
/// `txs` is `S_P` in full: every **cross-shard** transaction `P` settled
/// over the window ending at `B` and reaching back to its terminating
/// reshape's admission. The floor is the schedule's, not a fixed span
/// behind the terminal: a counterpart's fence holds straddlers from the
/// moment the reshape is admitted, so a terminal-relative span would drop
/// settlements made early in it and read their absence as "never settled".
/// Single-shard transactions are excluded —
/// they are never the subject of a counterpart's fence query — so the list
/// is proportional to cross-shard traffic, not total throughput. Verified,
/// not trusted bare — the requester recomputes
/// `settled_txs_root_from_hashes(txs)` and accepts only when it equals the
/// beacon-attested `settled_txs_root`. Because the root commits the whole
/// set, a server can neither hide a settled transaction (a missing leaf
/// changes the root) nor fabricate one, so the verified-complete set makes
/// the absence of any transaction from it sound.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetSettledTxsResponse {
    /// The terminated shard's complete settled-transaction window list, or
    /// `None` when this peer doesn't hold the terminal block — the
    /// requester rotates to another terminal-committee member.
    pub txs: Option<Capped<Vec<TxHash>, MAX_FINALIZED_TX_PER_BLOCK>>,
}

/// The window-list cap, checked at the wire boundary.
impl GetSettledTxsResponse {
    /// A complete window list for the terminated shard.
    #[must_use]
    pub const fn found(txs: Capped<Vec<TxHash>, MAX_FINALIZED_TX_PER_BLOCK>) -> Self {
        Self { txs: Some(txs) }
    }

    /// This peer can't serve the requested terminal block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { txs: None }
    }
}

impl NetworkMessage for GetSettledTxsResponse {
    fn message_type_id() -> &'static str {
        "settled_txs.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip_not_found() {
        let response = GetSettledTxsResponse::not_found();
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetSettledTxsResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_found() {
        let response = GetSettledTxsResponse::found(Capped::from_array([TxHash::from(
            Hash::from_bytes(b"settled tx"),
        )]));
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetSettledTxsResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
