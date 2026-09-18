//! Committed-transaction membership query for a reshape successor.
//!
//! A successor refuses every transaction whose validity window opened
//! before its own origin, because it holds no record of what the chain
//! before the cut committed. That refusal is a superset of the real
//! hazard: a transaction submitted before the cut and never committed is
//! harmless, and landing it on the successor is its first commit. This
//! request is how the successor tells the two apart — it names the
//! predecessor's terminal block and the transactions it wants resolved
//! against that terminal's `committed_txs_root`.
//!
//! Answers come back per transaction, in the order asked. Only absence
//! carries a proof; see [`GetCommittedTxsResponse`].

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetCommittedTxsResponse;
use crate::{
    BlockHash, BlockHeight, MAX_PROOFS_PER_QUERY, MessageClass, NetworkMessage, Request, TxHash,
};

/// Ask whether a terminated shard committed each of `tx_hashes`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetCommittedTxsRequest {
    /// Height of the terminal block the committed window ends at.
    pub terminal_height: BlockHeight,
    /// Expected hash of that terminal — the successor reads it off the
    /// terminal it commit-proved. The server resolves by height and
    /// answers `not_found` on a hash mismatch.
    pub terminal_block_hash: BlockHash,
    /// The transactions to resolve, in the order the answers come back.
    pub tx_hashes: Capped<Vec<TxHash>, MAX_PROOFS_PER_QUERY>,
}

impl GetCommittedTxsRequest {
    /// Resolve `tx_hashes` against the terminal at `(terminal_height,
    /// terminal_block_hash)`.
    #[must_use]
    pub const fn new(
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        tx_hashes: Capped<Vec<TxHash>, MAX_PROOFS_PER_QUERY>,
    ) -> Self {
        Self {
            terminal_height,
            terminal_block_hash,
            tx_hashes,
        }
    }
}

impl NetworkMessage for GetCommittedTxsRequest {
    fn message_type_id() -> &'static str {
        "committed_txs.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetCommittedTxsRequest {
    type Response = GetCommittedTxsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.verdicts.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetCommittedTxsRequest::new(
            BlockHeight::new(98),
            BlockHash::from_raw(Hash::from_bytes(b"terminal")),
            Capped::from_array([TxHash::from(Hash::from_bytes(b"probe"))]),
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetCommittedTxsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
