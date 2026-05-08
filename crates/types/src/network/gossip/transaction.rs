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

use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{MessageClass, NetworkMessage, RoutableTransaction, ShardMessage};

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
#[derive(Debug, Clone)]
pub struct TransactionGossip {
    /// The transactions in this batch.
    pub transactions: Vec<Arc<RoutableTransaction>>,
}

impl TransactionGossip {
    /// Build a gossip batch from a vector of `Arc`-wrapped transactions.
    #[must_use]
    pub const fn new(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
        Self { transactions }
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
                .zip(&other.transactions)
                .all(|(a, b)| a.hash() == b.hash())
    }
}

impl Eq for TransactionGossip {}

// ============================================================================
// Manual SBOR implementation: `Arc<RoutableTransaction>` doesn't derive
// BasicSbor, so we (de)serialize the inner data ourselves. Encoded as a
// 1-tuple to match the layout `BasicSbor` would produce for a single-field
// struct, leaving room to add fields without re-breaking wire.
// ============================================================================

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for TransactionGossip {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(1)?;

        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(
            <RoutableTransaction as Categorize<NoCustomValueKind>>::value_kind(),
        )?;
        encoder.write_size(self.transactions.len())?;
        for tx in &self.transactions {
            encoder.encode_deeper_body(tx.as_ref())?;
        }

        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for TransactionGossip {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 1 {
            return Err(DecodeError::UnexpectedSize {
                expected: 1,
                actual: length,
            });
        }

        decoder.read_and_check_value_kind(ValueKind::Array)?;
        let elem_kind = decoder.read_value_kind()?;
        let tx_count = decoder.read_size()?;
        if tx_count > MAX_GOSSIP_TX_BATCH {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX_GOSSIP_TX_BATCH,
                actual: tx_count,
            });
        }
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: RoutableTransaction = decoder.decode_deeper_body_with_value_kind(elem_kind)?;
            transactions.push(Arc::new(tx));
        }

        Ok(Self { transactions })
    }
}

impl Categorize<NoCustomValueKind> for TransactionGossip {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for TransactionGossip {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("TransactionGossip", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

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
        use sbor::{BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder};
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
