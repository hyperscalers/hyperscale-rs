//! Transaction gossip message.

use crate::trace_context::TraceContext;
use hyperscale_codec as sbor;
use hyperscale_codec::{Decoder as _, Encoder as _};
use hyperscale_types::{ConcreteConfig, MessagePriority, NetworkMessage, ShardMessage, TypeConfig};
use std::fmt::Debug;
use std::sync::Arc;

/// Gossips a transaction to all shard groups with state touched by it.
/// Broadcast to union of write_shards (cross-shard execution) and read_shards (provisioning).
///
/// When serializing for network transmission, the transaction data is fully copied.
pub struct TransactionGossip<C: TypeConfig = ConcreteConfig> {
    /// The transaction being gossiped.
    pub transaction: Arc<C::Transaction>,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl<C: TypeConfig> Debug for TransactionGossip<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionGossip")
            .field("transaction", &self.transaction)
            .field("trace_context", &self.trace_context)
            .finish()
    }
}

impl<C: TypeConfig> Clone for TransactionGossip<C> {
    fn clone(&self) -> Self {
        Self {
            transaction: Arc::clone(&self.transaction),
            trace_context: self.trace_context.clone(),
        }
    }
}

impl<C: TypeConfig> TransactionGossip<C> {
    /// Create a new transaction gossip message.
    ///
    /// Does not capture trace context. Use `with_trace_context()` to include
    /// distributed tracing information.
    pub fn new(transaction: C::Transaction) -> Self {
        Self {
            transaction: Arc::new(transaction),
            trace_context: TraceContext::default(),
        }
    }

    /// Create a new transaction gossip message from an Arc.
    pub fn from_arc(transaction: Arc<C::Transaction>) -> Self {
        Self {
            transaction,
            trace_context: TraceContext::default(),
        }
    }

    /// Create a new transaction gossip message with trace context from current span.
    ///
    /// When `trace-propagation` feature is enabled, captures the current OpenTelemetry
    /// span context for distributed tracing across nodes.
    pub fn with_trace_context(transaction: C::Transaction) -> Self {
        Self {
            transaction: Arc::new(transaction),
            trace_context: TraceContext::from_current(),
        }
    }

    /// Get a reference to the inner transaction.
    pub fn transaction(&self) -> &C::Transaction {
        &self.transaction
    }

    /// Get the Arc to the transaction.
    pub fn transaction_arc(&self) -> &Arc<C::Transaction> {
        &self.transaction
    }

    /// Consume and return the inner transaction.
    pub fn into_transaction(self) -> C::Transaction {
        Arc::try_unwrap(self.transaction).unwrap_or_else(|arc| (*arc).clone())
    }

    /// Get the trace context.
    pub fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }
}

// Manual PartialEq/Eq - compare by transaction hash for efficiency
impl<C: TypeConfig> PartialEq for TransactionGossip<C> {
    fn eq(&self, other: &Self) -> bool {
        C::transaction_hash(&self.transaction) == C::transaction_hash(&other.transaction)
            && self.trace_context == other.trace_context
    }
}

impl<C: TypeConfig> Eq for TransactionGossip<C> {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// We serialize/deserialize the inner transaction directly.
// ============================================================================

impl<'a, C: TypeConfig> sbor::Encode<sbor::NoCustomValueKind, sbor::BasicEncoder<'a>>
    for TransactionGossip<C>
{
    fn encode_value_kind(
        &self,
        encoder: &mut sbor::BasicEncoder<'a>,
    ) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut sbor::BasicEncoder<'a>) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?; // 2 fields
        encoder.encode(self.transaction.as_ref())?;
        encoder.encode(&self.trace_context)?;
        Ok(())
    }
}

impl<'a, C: TypeConfig> sbor::Decode<sbor::NoCustomValueKind, sbor::BasicDecoder<'a>>
    for TransactionGossip<C>
{
    fn decode_body_with_value_kind(
        decoder: &mut sbor::BasicDecoder<'a>,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }

        let transaction: C::Transaction = decoder.decode()?;
        let trace_context: TraceContext = decoder.decode()?;

        Ok(Self {
            transaction: Arc::new(transaction),
            trace_context,
        })
    }
}

impl<C: TypeConfig> sbor::Categorize<sbor::NoCustomValueKind> for TransactionGossip<C> {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl<C: TypeConfig> sbor::Describe<sbor::NoCustomTypeKind> for TransactionGossip<C> {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("TransactionGossip", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// Network message implementation
impl<C: TypeConfig> NetworkMessage for TransactionGossip<C> {
    fn message_type_id() -> &'static str {
        "transaction.gossip"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Propagation
    }
}

// Transactions are filtered to shards that have state touched by the transaction
impl<C: TypeConfig> ShardMessage for TransactionGossip<C> {}

#[cfg(test)]
mod tests {
    use super::*;

    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};

    #[test]
    fn test_transaction_gossip_creation() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip: TransactionGossip = TransactionGossip::new(tx.clone());
        assert_eq!(gossip.transaction().hash(), tx.hash());
    }

    #[test]
    fn test_transaction_gossip_into_transaction() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![], vec![test_node(1)]);

        let hash = tx.hash();
        let gossip: TransactionGossip = TransactionGossip::new(tx);
        let extracted = gossip.into_transaction();
        assert_eq!(extracted.hash(), hash);
    }

    #[test]
    fn test_transaction_gossip_hash_consistency() {
        let tx1 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let tx2 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip1: TransactionGossip = TransactionGossip::new(tx1);
        let gossip2: TransactionGossip = TransactionGossip::new(tx2);

        // Same data should produce same transaction hash
        assert_eq!(gossip1.transaction().hash(), gossip2.transaction().hash());
    }

    #[test]
    fn test_transaction_gossip_trace_context() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        // new() should have empty trace context
        let gossip: TransactionGossip = TransactionGossip::new(tx.clone());
        assert!(!gossip.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let gossip_with_ctx: TransactionGossip = TransactionGossip::with_trace_context(tx);
        // When no span is active, trace context will be empty
        assert!(!gossip_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }
}
