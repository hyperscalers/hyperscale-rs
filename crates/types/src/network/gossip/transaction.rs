//! Transaction gossip message.
//!
//! Each gossip message carries a batch of transactions for a single
//! destination shard topic. Batching at this layer trades a small
//! tail-latency cost (the batch window) for substantially less wire
//! work: per-message gossipsub overhead, IHAVE digest size, and `mcache`
//! pressure all scale with message *count*, not bytes — and at gossipsub
//! v1.2's IDONTWANT threshold larger messages activate cross-mesh dedup
//! that single-tx messages were too small to trigger.

use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor};

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, Transaction};

/// Cap on transactions accepted in a single gossip batch at decode time.
///
/// Bounds attacker-controlled `tx_count` decoded from the wire so a peer
/// can't pack a 28-bit LEB128 count into a few bytes and force a multi-GB
/// `Vec::with_capacity` pre-allocation per delivered gossip message.
/// Production batches sit in the low hundreds; 1000 leaves headroom.
pub const MAX_GOSSIP_TX_BATCH: usize = 1_000;

/// Gossips a batch of transactions to a single destination shard.
///
/// Each tx is broadcast on its declared (read ∪ write) shard set; a tx
/// touching multiple shards appears in multiple batches, one per audience.
#[derive(Debug, Clone, Hbor)]
pub struct TransactionGossip {
    /// The transactions in this batch.
    pub transactions: Capped<Vec<Arc<Transaction>>, MAX_GOSSIP_TX_BATCH>,
}

impl TransactionGossip {
    /// Build a gossip batch from a vector of `Arc`-wrapped transactions.
    /// The batch cap is enforced at encode and decode, not here.
    #[must_use]
    pub const fn new(transactions: Capped<Vec<Arc<Transaction>>, MAX_GOSSIP_TX_BATCH>) -> Self {
        Self { transactions }
    }

    /// Number of transactions in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

// Manual PartialEq/Eq — compare by per-tx hash for efficiency.
impl PartialEq for TransactionGossip {
    fn eq(&self, other: &Self) -> bool {
        self.transactions.len() == other.transactions.len()
            && self
                .transactions
                .iter()
                .zip(other.transactions.iter())
                .all(|(a, b)| a.hash() == b.hash())
    }
}

impl Eq for TransactionGossip {}

// Network message implementation
impl NetworkMessage for TransactionGossip {
    fn message_type_id() -> &'static str {
        "transaction.gossip"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

// Transactions are filtered to shards that have state touched by the batch.
// Single-publisher per batch (the host that received the tx via RPC),
// so gossipsub's bytes-id dedup covers the mesh-redundancy path — no
// content-key dedup needed here.
impl GossipMessage for TransactionGossip {
    const SCOPE: TopicScope = TopicScope::Shard;
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::test_utils::{test_prefix, test_transaction_with_prefixes};

    #[test]
    fn new_carries_transactions() {
        let tx1 = Arc::new(test_transaction_with_prefixes(
            &[1, 2, 3],
            &[test_prefix(1)],
            &[test_prefix(2)],
        ));
        let tx2 = Arc::new(test_transaction_with_prefixes(
            &[4, 5, 6],
            &[test_prefix(3)],
            &[test_prefix(4)],
        ));

        let gossip =
            TransactionGossip::new(Capped::from_array([Arc::clone(&tx1), Arc::clone(&tx2)]));
        assert_eq!(gossip.len(), 2);
        assert!(!gossip.is_empty());
        assert_eq!(gossip.transactions[0].hash(), tx1.hash());
        assert_eq!(gossip.transactions[1].hash(), tx2.hash());
    }

    #[test]
    fn empty_batch() {
        let gossip = TransactionGossip::new(Capped::empty());
        assert!(gossip.is_empty());
        assert_eq!(gossip.len(), 0);
    }

    #[test]
    fn hbor_roundtrip_multi_tx() {
        let txs: Vec<Arc<Transaction>> = (0..5)
            .map(|i| {
                Arc::new(test_transaction_with_prefixes(
                    &[i, i + 1, i + 2],
                    &[test_prefix(i)],
                    &[test_prefix(i + 1)],
                ))
            })
            .collect();
        let original =
            TransactionGossip::new(Capped::new(txs).expect("a batch written out in a test"));

        let bytes = hbor_to_vec(&original).expect("encode");
        let decoded: TransactionGossip = hbor_from_slice(&bytes).expect("decode");

        assert_eq!(original, decoded);
        assert_eq!(decoded.len(), 5);
    }

    #[test]
    fn hbor_roundtrip_empty() {
        let original = TransactionGossip::new(Capped::empty());
        let bytes = hbor_to_vec(&original).expect("encode");
        let decoded: TransactionGossip = hbor_from_slice(&bytes).expect("decode");
        assert_eq!(original, decoded);
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_rejects_oversized_tx_count() {
        // Hand-roll the prefix: a TransactionGossip whose tx_count exceeds
        // MAX_GOSSIP_TX_BATCH. Without the cap the decoder would call
        // Vec::with_capacity(huge) and OOM; with the cap it errors before
        // touching memory.
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_GOSSIP_TX_BATCH + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_GOSSIP_TX_BATCH + 1) * 256));
        let err = hbor_from_slice::<TransactionGossip>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_GOSSIP_TX_BATCH && actual == MAX_GOSSIP_TX_BATCH + 1
        ));
    }
}
