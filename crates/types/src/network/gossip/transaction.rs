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

use sbor::prelude::BasicSbor;

use crate::{BoundedVec, MessageClass, NetworkMessage, RoutableTransaction, ShardMessage};

/// Cap on transactions accepted in a single gossip batch at decode time.
///
/// Bounds attacker-controlled `tx_count` decoded from the wire so a peer
/// can't pack a 28-bit LEB128 count into a few bytes and force a multi-GB
/// `Vec::with_capacity` pre-allocation per delivered gossip message.
/// Production batches sit in the low hundreds; 1000 leaves headroom.
const MAX_GOSSIP_TX_BATCH: usize = 1_000;

/// Gossips a batch of transactions to a single destination shard.
///
/// Each tx is broadcast on its declared (read ∪ write) shard set; a tx
/// touching multiple shards appears in multiple batches, one per audience.
#[derive(Debug, Clone, BasicSbor)]
pub struct TransactionGossip {
    /// The transactions in this batch.
    pub transactions: BoundedVec<Arc<RoutableTransaction>, MAX_GOSSIP_TX_BATCH>,
}

impl TransactionGossip {
    /// Build a gossip batch from a vector of `Arc`-wrapped transactions.
    ///
    /// # Panics
    ///
    /// Panics if `transactions.len() > MAX_GOSSIP_TX_BATCH`.
    #[must_use]
    pub fn new(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
        Self {
            transactions: transactions.into(),
        }
    }

    /// Number of transactions in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
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
impl ShardMessage for TransactionGossip {}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::test_utils::{test_node, test_transaction_with_nodes};

    #[test]
    fn new_carries_transactions() {
        let tx1 = Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![test_node(1)],
            vec![test_node(2)],
        ));
        let tx2 = Arc::new(test_transaction_with_nodes(
            &[4, 5, 6],
            vec![test_node(3)],
            vec![test_node(4)],
        ));

        let gossip = TransactionGossip::new(vec![Arc::clone(&tx1), Arc::clone(&tx2)]);
        assert_eq!(gossip.len(), 2);
        assert!(!gossip.is_empty());
        assert_eq!(gossip.transactions[0].hash(), tx1.hash());
        assert_eq!(gossip.transactions[1].hash(), tx2.hash());
    }

    #[test]
    fn empty_batch() {
        let gossip = TransactionGossip::new(vec![]);
        assert!(gossip.is_empty());
        assert_eq!(gossip.len(), 0);
    }

    #[test]
    fn sbor_roundtrip_multi_tx() {
        let txs: Vec<Arc<RoutableTransaction>> = (0..5)
            .map(|i| {
                Arc::new(test_transaction_with_nodes(
                    &[i, i + 1, i + 2],
                    vec![test_node(i)],
                    vec![test_node(i + 1)],
                ))
            })
            .collect();
        let original = TransactionGossip::new(txs);

        let bytes = basic_encode(&original).expect("encode");
        let decoded: TransactionGossip = basic_decode(&bytes).expect("decode");

        assert_eq!(original, decoded);
        assert_eq!(decoded.len(), 5);
    }

    #[test]
    fn sbor_roundtrip_empty() {
        let original = TransactionGossip::new(vec![]);
        let bytes = basic_encode(&original).expect("encode");
        let decoded: TransactionGossip = basic_decode(&bytes).expect("decode");
        assert_eq!(original, decoded);
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_rejects_oversized_tx_count() {
        // Hand-roll the prefix: a TransactionGossip whose tx_count exceeds
        // MAX_GOSSIP_TX_BATCH. Without the cap the decoder would call
        // Vec::with_capacity(huge) and OOM; with the cap it errors before
        // touching memory.
        use sbor::{
            BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder,
            NoCustomValueKind, ValueKind, VecEncoder,
        };
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(1).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_GOSSIP_TX_BATCH + 1).unwrap();
        }
        let err = basic_decode::<TransactionGossip>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected,
                actual,
            } if expected == MAX_GOSSIP_TX_BATCH && actual == MAX_GOSSIP_TX_BATCH + 1
        ));
    }
}
