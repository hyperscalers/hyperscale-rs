//! Transaction fetch request.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetTransactionsResponse;
use crate::{MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, Request, TxHash};

/// Request to fetch transactions by hash.
///
/// Used when a validator is missing transactions referenced by a pending
/// block (or by any other consumer waiting on tx data). The responder
/// resolves each hash from local state — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetTransactionsRequest {
    /// Hashes of the transactions being requested.
    ///
    /// The response is capped the same way: a request asks for the
    /// transactions a block names, and a block carries at most this
    /// many.
    pub tx_hashes: Capped<Vec<TxHash>, MAX_TXS_PER_BLOCK>,
}

impl GetTransactionsRequest {
    /// Create a new transaction fetch request.
    #[must_use]
    pub const fn new(tx_hashes: Capped<Vec<TxHash>, MAX_TXS_PER_BLOCK>) -> Self {
        Self { tx_hashes }
    }

    /// Get the number of transactions being requested.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tx_hashes.len()
    }
}

// Network message implementation
impl NetworkMessage for GetTransactionsRequest {
    fn message_type_id() -> &'static str {
        "transaction.request"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

/// Type-safe request/response pairing.
impl Request for GetTransactionsRequest {
    type Response = GetTransactionsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_get_transactions_request() {
        let tx_hashes = vec![
            TxHash::from(Hash::from_bytes(b"tx1")),
            TxHash::from(Hash::from_bytes(b"tx2")),
            TxHash::from(Hash::from_bytes(b"tx3")),
        ];

        let request = GetTransactionsRequest::new(
            Capped::new(tx_hashes.clone()).expect("a list written out in a test"),
        );
        assert_eq!(request.tx_hashes, tx_hashes);
        assert_eq!(request.count(), 3);
    }

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetTransactionsRequest::new(Capped::from_array([TxHash::from(
            Hash::from_bytes(b"tx1"),
        )]));
        let bytes = hbor_to_vec(&request).unwrap();
        let decoded: GetTransactionsRequest = hbor_from_slice(&bytes).unwrap();
        assert_eq!(request, decoded);
    }

    /// A claimed length past the cap is refused before any element is
    /// decoded, so a peer cannot make the decoder allocate for a batch
    /// no honest block could name.
    #[test]
    fn decode_rejects_an_oversized_request() {
        use hyperscale_hbor::{DecodeError, varint};

        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        // Filler so the claimed length clears the input-capacity check
        // and the bound is what refuses it.
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 64));
        let err = hbor_from_slice::<GetTransactionsRequest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
