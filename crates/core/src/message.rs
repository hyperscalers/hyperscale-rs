//! Outbound message types for network communication.

use crate::Event;
use hyperscale_messages::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TraceContext, TransactionCertificateGossip, TransactionGossip,
};
use hyperscale_types::{MessagePriority, NetworkMessage};
use sbor::prelude::*;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Outbound network messages.
///
/// These are the messages that a node can send to other nodes.
/// The runner handles the actual network I/O.
///
/// State messages (provisions, votes, certificates) use batching to reduce
/// network overhead. The runner accumulates individual items and flushes
/// them periodically.
#[derive(Debug, Clone)]
pub enum OutboundMessage {
    // ═══════════════════════════════════════════════════════════════════════
    // BFT Messages
    // ═══════════════════════════════════════════════════════════════════════
    /// Block header announcement.
    /// Boxed to reduce enum size variance (BlockHeaderGossip is ~328 bytes).
    BlockHeader(Box<BlockHeaderGossip>),

    /// Vote on a block header.
    BlockVote(BlockVoteGossip),

    // ═══════════════════════════════════════════════════════════════════════
    // Execution Messages (Batched)
    // ═══════════════════════════════════════════════════════════════════════
    /// Batched state provisions for cross-shard execution.
    StateProvisionBatch(StateProvisionBatch),

    /// Batched votes on execution results.
    StateVoteBatch(StateVoteBatch),

    /// Batched certificates proving execution quorum.
    StateCertificateBatch(StateCertificateBatch),

    /// Finalized transaction certificate gossip for same-shard peers.
    /// Gossiped when certificates are finalized so peers have them before block inclusion.
    /// Uses individual gossip (not batched) for better deduplication by gossipsub.
    TransactionCertificateGossip(TransactionCertificateGossip),

    // ═══════════════════════════════════════════════════════════════════════
    // Mempool Messages
    // ═══════════════════════════════════════════════════════════════════════
    /// Transaction gossip.
    TransactionGossip(Box<TransactionGossip>),
}

impl OutboundMessage {
    /// Get a human-readable name for this message type.
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundMessage::BlockHeader(_) => "BlockHeader",
            OutboundMessage::BlockVote(_) => "BlockVote",
            OutboundMessage::StateProvisionBatch(_) => "StateProvisionBatch",
            OutboundMessage::StateVoteBatch(_) => "StateVoteBatch",
            OutboundMessage::StateCertificateBatch(_) => "StateCertificateBatch",
            OutboundMessage::TransactionCertificateGossip(_) => "TransactionCertificateGossip",
            OutboundMessage::TransactionGossip(_) => "TransactionGossip",
        }
    }

    /// Get the network priority for this message.
    ///
    /// Priority is determined by the underlying message type's implementation
    /// of [`NetworkMessage::priority()`]. This provides a unified interface
    /// for the network layer to make QoS decisions.
    pub fn priority(&self) -> MessagePriority {
        match self {
            OutboundMessage::BlockHeader(_) => BlockHeaderGossip::priority(),
            OutboundMessage::BlockVote(_) => BlockVoteGossip::priority(),
            OutboundMessage::StateProvisionBatch(_) => StateProvisionBatch::priority(),
            OutboundMessage::StateVoteBatch(_) => StateVoteBatch::priority(),
            OutboundMessage::StateCertificateBatch(_) => StateCertificateBatch::priority(),
            OutboundMessage::TransactionCertificateGossip(_) => {
                TransactionCertificateGossip::priority()
            }
            OutboundMessage::TransactionGossip(_) => TransactionGossip::priority(),
        }
    }

    /// Inject trace context into cross-shard messages for distributed tracing.
    ///
    /// Only affects messages that carry trace context:
    /// - `StateProvisionBatch` (cross-shard state)
    /// - `StateCertificateBatch` (cross-shard 2PC completion)
    /// - `TransactionGossip` (transaction propagation)
    ///
    /// Other message types (BFT consensus, state votes) are unaffected.
    ///
    /// When `trace-propagation` feature is disabled in the messages crate,
    /// this sets an empty trace context (no-op).
    pub fn inject_trace_context(&mut self) {
        let ctx = TraceContext::from_current();
        match self {
            OutboundMessage::StateProvisionBatch(batch) => {
                batch.trace_context = ctx;
            }
            OutboundMessage::StateCertificateBatch(batch) => {
                batch.trace_context = ctx;
            }
            OutboundMessage::TransactionGossip(gossip) => {
                gossip.trace_context = ctx;
            }
            // BFT consensus, state vote, and transaction certificate messages don't carry trace context
            OutboundMessage::BlockHeader(_)
            | OutboundMessage::BlockVote(_)
            | OutboundMessage::StateVoteBatch(_)
            | OutboundMessage::TransactionCertificateGossip(_) => {}
        }
    }

    /// Estimate the encoded size of this message in bytes.
    ///
    /// This uses SBOR encoding to get an accurate size estimate for bandwidth analysis.
    /// Returns (payload_size, wire_size) where wire_size includes framing overhead.
    pub fn encoded_size(&self) -> (usize, usize) {
        let payload_size = match self {
            OutboundMessage::BlockHeader(gossip) => {
                basic_encode(gossip.as_ref()).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::BlockVote(gossip) => {
                basic_encode(gossip).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::StateProvisionBatch(batch) => {
                basic_encode(batch).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::StateVoteBatch(batch) => {
                basic_encode(batch).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::StateCertificateBatch(batch) => {
                basic_encode(batch).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::TransactionCertificateGossip(gossip) => {
                basic_encode(gossip).map(|v| v.len()).unwrap_or(0)
            }
            OutboundMessage::TransactionGossip(gossip) => {
                basic_encode(gossip.as_ref()).map(|v| v.len()).unwrap_or(0)
            }
        };

        // Add framing overhead estimate:
        // - 4 bytes length prefix
        // - 1 byte message type tag
        // - ~10 bytes protocol overhead
        let wire_size = payload_size + 15;

        (payload_size, wire_size)
    }

    /// Compute a hash of the message content for deduplication.
    ///
    /// This matches the libp2p gossipsub `message_id_fn` approach: hash the
    /// encoded message data using `DefaultHasher`. Two identical messages
    /// will produce the same hash, allowing deduplication.
    pub fn message_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        match self {
            OutboundMessage::BlockHeader(g) => {
                if let Ok(encoded) = basic_encode(g.as_ref()) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::BlockVote(g) => {
                if let Ok(encoded) = basic_encode(g) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::StateProvisionBatch(batch) => {
                if let Ok(encoded) = basic_encode(batch) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::StateVoteBatch(batch) => {
                if let Ok(encoded) = basic_encode(batch) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::StateCertificateBatch(batch) => {
                if let Ok(encoded) = basic_encode(batch) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::TransactionCertificateGossip(gossip) => {
                if let Ok(encoded) = basic_encode(gossip) {
                    encoded.hash(&mut hasher);
                }
            }
            OutboundMessage::TransactionGossip(g) => {
                if let Ok(encoded) = basic_encode(g.as_ref()) {
                    encoded.hash(&mut hasher);
                }
            }
        }
        hasher.finish()
    }

    /// Convert an outbound message to the corresponding inbound events.
    ///
    /// This is used by both the deterministic and parallel simulators
    /// to handle received messages uniformly.
    ///
    /// Returns a Vec because batched messages expand to multiple events.
    pub fn to_received_events(&self) -> Vec<Event> {
        match self {
            OutboundMessage::BlockHeader(gossip) => vec![Event::BlockHeaderReceived {
                header: gossip.header.clone(),
                retry_hashes: gossip.retry_hashes.clone(),
                priority_hashes: gossip.priority_hashes.clone(),
                tx_hashes: gossip.transaction_hashes.clone(),
                cert_hashes: gossip.certificate_hashes.clone(),
                deferred: gossip.deferred.clone(),
                aborted: gossip.aborted.clone(),
                commitment_proofs: gossip.commitment_proofs.clone(),
            }],
            OutboundMessage::BlockVote(gossip) => vec![Event::BlockVoteReceived {
                vote: gossip.vote.clone(),
            }],
            OutboundMessage::StateProvisionBatch(batch) => batch
                .provisions
                .iter()
                .map(|provision| Event::StateProvisionReceived {
                    provision: provision.clone(),
                })
                .collect(),
            OutboundMessage::StateVoteBatch(batch) => batch
                .votes
                .iter()
                .map(|vote| Event::StateVoteReceived { vote: vote.clone() })
                .collect(),
            OutboundMessage::StateCertificateBatch(batch) => batch
                .certificates
                .iter()
                .map(|cert| Event::StateCertificateReceived { cert: cert.clone() })
                .collect(),
            OutboundMessage::TransactionCertificateGossip(gossip) => {
                vec![Event::TransactionCertificateReceived {
                    certificate: gossip.certificate.clone(),
                }]
            }
            OutboundMessage::TransactionGossip(gossip) => vec![Event::TransactionGossipReceived {
                tx: Arc::clone(&gossip.transaction),
            }],
        }
    }
}
