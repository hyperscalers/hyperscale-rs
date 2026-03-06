//! StateProvisionsNotification message for cross-shard provisions.

use crate::trace_context::TraceContext;
use hyperscale_types::{Bls12381G2Signature, MessagePriority, NetworkMessage, ValidatorId};
use sbor::prelude::BasicSbor;

/// Batched state provisions for cross-shard transactions.
///
/// Only the block proposer sends these. The sender signature authenticates
/// the batch, allowing receivers to reject forged provisions before doing
/// expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateProvisionsNotification {
    /// The state provisions being sent.
    pub provisions: Vec<hyperscale_types::StateProvision>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl StateProvisionsNotification {
    /// Create a new signed state provision batch.
    pub fn new(
        provisions: Vec<hyperscale_types::StateProvision>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            provisions,
            sender,
            sender_signature,
            trace_context: TraceContext::default(),
        }
    }

    /// Build the canonical signing message for this batch.
    ///
    /// Requires that the batch is non-empty (panics otherwise).
    pub fn signing_message(&self) -> Vec<u8> {
        let first = &self.provisions[0];
        hyperscale_types::state_provision_batch_message(
            first.source_shard,
            first.target_shard,
            first.block_height,
            &self.provisions,
        )
    }

    /// Get the provisions.
    pub fn provisions(&self) -> &[hyperscale_types::StateProvision] {
        &self.provisions
    }

    /// Consume and return the provisions.
    pub fn into_provisions(self) -> Vec<hyperscale_types::StateProvision> {
        self.provisions
    }

    /// Get the trace context.
    pub fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.provisions.is_empty()
    }

    /// Get the number of provisions in the batch.
    pub fn len(&self) -> usize {
        self.provisions.len()
    }
}

impl NetworkMessage for StateProvisionsNotification {
    fn message_type_id() -> &'static str {
        "state.provision.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
