//! Transaction gossip message.

use crate::trace_context::TraceContext;
use hyperscale_codec as sbor;
use hyperscale_codec::{Decoder as _, Encoder as _};
use hyperscale_types::{
    ConsensusTransaction, MessagePriority, NetworkMessage, ShardMessage, TypeConfig,
};
use std::fmt::Debug;
use std::sync::Arc;

/// Gossips a transaction to all shard groups with state touched by it.
/// Broadcast to union of write_shards (cross-shard execution) and read_shards (provisioning).
///
/// When serializing for network transmission, the transaction data is fully copied.
pub struct TransactionGossip<C: TypeConfig> {
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
        self.transaction.tx_hash() == other.transaction.tx_hash()
            && self.trace_context == other.trace_context
    }
}

impl<C: TypeConfig> Eq for TransactionGossip<C> {}

sbor::impl_sbor_for_generic_struct! {
    struct TransactionGossip<C: TypeConfig> ["TransactionGossip"] {
        transaction: Arc<C::Transaction>;
        trace_context: TraceContext,
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
    use hyperscale_radix_config::RadixConfig;
    use hyperscale_radix_types::test_utils::{test_node, test_transaction_with_nodes};

    #[test]
    fn test_transaction_gossip_creation() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip: TransactionGossip<RadixConfig> = TransactionGossip::new(tx.clone());
        assert_eq!(gossip.transaction().hash(), tx.hash());
    }

    #[test]
    fn test_transaction_gossip_into_transaction() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![], vec![test_node(1)]);

        let hash = tx.hash();
        let gossip: TransactionGossip<RadixConfig> = TransactionGossip::new(tx);
        let extracted = gossip.into_transaction();
        assert_eq!(extracted.hash(), hash);
    }

    #[test]
    fn test_transaction_gossip_hash_consistency() {
        let tx1 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let tx2 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip1: TransactionGossip<RadixConfig> = TransactionGossip::new(tx1);
        let gossip2: TransactionGossip<RadixConfig> = TransactionGossip::new(tx2);

        // Same data should produce same transaction hash
        assert_eq!(gossip1.transaction().hash(), gossip2.transaction().hash());
    }

    #[test]
    fn test_transaction_gossip_trace_context() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        // new() should have empty trace context
        let gossip: TransactionGossip<RadixConfig> = TransactionGossip::new(tx.clone());
        assert!(!gossip.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let gossip_with_ctx: TransactionGossip<RadixConfig> =
            TransactionGossip::with_trace_context(tx);
        // When no span is active, trace context will be empty
        assert!(!gossip_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }
}
