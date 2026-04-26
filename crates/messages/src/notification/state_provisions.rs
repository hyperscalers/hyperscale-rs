//! `StateProvisionNotification` message for cross-shard provisions.

use crate::trace_context::TraceContext;
use hyperscale_types::{
    Bls12381G2Signature, MerkleInclusionProof, MessagePriority, NetworkMessage, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// State provisions for cross-shard transactions.
///
/// Only the block proposer sends these. The sender signature authenticates
/// the notification, allowing receivers to reject forged provisions before
/// doing expensive merkle proof verification.
///
/// The aggregated merkle proof is stored once on the notification rather
/// than per-provision, avoiding redundant serialization of the (potentially
/// large) proof across N provisions.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateProvisionNotification {
    /// The state provisions being sent.
    pub provisions: Vec<hyperscale_types::StateProvision>,
    /// Aggregated merkle proof covering all entries across all provisions.
    pub proof: MerkleInclusionProof,
    /// The validator who sent this notification.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl StateProvisionNotification {
    /// Create a new signed state provisions.
    #[must_use]
    pub fn new(
        provisions: Vec<hyperscale_types::StateProvision>,
        proof: MerkleInclusionProof,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            provisions,
            proof,
            sender,
            sender_signature,
            trace_context: TraceContext::default(),
        }
    }

    /// Build the canonical signing message for this notification.
    ///
    /// # Panics
    ///
    /// Panics if `self.provisions` is empty.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let first = &self.provisions[0];
        hyperscale_types::state_provisions_message(
            first.source_shard,
            first.target_shard,
            first.block_height,
            &self.provisions,
        )
    }

    /// Get the provisions.
    #[must_use]
    pub fn provisions(&self) -> &[hyperscale_types::StateProvision] {
        &self.provisions
    }

    /// Consume and return the provisions and their shared proof.
    #[must_use]
    pub fn into_parts(self) -> (Vec<hyperscale_types::StateProvision>, MerkleInclusionProof) {
        (self.provisions, self.proof)
    }

    /// Get the trace context.
    #[must_use]
    pub const fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }

    /// Check if there are no provisions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.provisions.is_empty()
    }

    /// Get the number of provisions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.provisions.len()
    }
}

impl NetworkMessage for StateProvisionNotification {
    fn message_type_id() -> &'static str {
        "state.provision.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
