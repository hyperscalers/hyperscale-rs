//! Message encoding and decoding for network transport.
//!
//! # Wire Format
//!
//! All gossip messages are SBOR-encoded then LZ4-compressed:
//!
//! ```text
//! [LZ4 compressed SBOR payload]
//! ```
//!
//! # Topic-Based Type Dispatch
//!
//! Message type is determined by the gossipsub topic, not by a field in the
//! message. This simplifies the wire format and allows efficient routing.

use crate::wire;
use crate::Topic;
use hyperscale_core::Event;
use hyperscale_messages::gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TransactionCertificateGossip, TransactionGossip,
};
use hyperscale_messages::TraceContext;
use hyperscale_types::RoutableTransaction;
use std::sync::Arc;
use thiserror::Error;
use tracing::{trace, warn};

/// Errors that can occur during message encoding/decoding.
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Message too short")]
    MessageTooShort,

    #[error("SBOR decode error: {0}")]
    SborDecode(String),

    #[error("SBOR encode error: {0}")]
    SborEncode(String),

    #[error("Decompression error: {0}")]
    Decompress(String),

    #[error("Unknown topic: {0}")]
    UnknownTopic(String),
}

/// Encode a value to wire format (SBOR + LZ4 compression).
///
/// This is a generic helper that SBOR-encodes any `BasicEncode` type then
/// LZ4-compresses the result.
pub fn encode_to_wire<T: sbor::BasicEncode>(value: &T) -> Result<Vec<u8>, CodecError> {
    let sbor_bytes =
        sbor::basic_encode(value).map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?;
    Ok(wire::compress(&sbor_bytes))
}

/// Result of decoding a message, including optional trace context.
pub struct DecodedMessage {
    /// The decoded events (batched messages produce multiple events).
    pub events: Vec<Event>,
    /// Trace context from the message, if present.
    /// Only cross-shard messages (StateProvisionBatch, StateCertificateBatch, TransactionGossip)
    /// carry trace context.
    ///
    /// Only read when `trace-propagation` feature is enabled.
    #[allow(dead_code)]
    pub trace_context: Option<TraceContext>,
}

/// Decode a message from wire format based on topic.
///
/// LZ4-decompresses then SBOR-decodes the message.
/// The topic determines the message type (topic-based dispatch).
/// Returns the decoded events along with any trace context for distributed tracing.
pub fn decode_message(parsed_topic: &Topic, data: &[u8]) -> Result<DecodedMessage, CodecError> {
    if data.is_empty() {
        return Err(CodecError::MessageTooShort);
    }

    // Decompress
    let payload = wire::decompress(data).map_err(|e| CodecError::Decompress(e.to_string()))?;

    let msg_type = parsed_topic.message_type();

    // Dispatch based on message type from topic
    match msg_type {
        "block.header" => {
            let gossip: BlockHeaderGossip = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            Ok(DecodedMessage {
                events: vec![Event::BlockHeaderReceived {
                    header: gossip.header,
                    retry_hashes: gossip.retry_hashes,
                    priority_hashes: gossip.priority_hashes,
                    tx_hashes: gossip.transaction_hashes,
                    cert_hashes: gossip.certificate_hashes,
                    deferred: gossip.deferred,
                    aborted: gossip.aborted,
                    commitment_proofs: gossip.commitment_proofs,
                }],
                trace_context: None,
            })
        }
        "block.vote" => {
            let gossip: BlockVoteGossip = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            Ok(DecodedMessage {
                events: vec![Event::BlockVoteReceived { vote: gossip.vote }],
                trace_context: None,
            })
        }
        "state.provision.batch" => {
            let batch: StateProvisionBatch = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            let trace_ctx = if batch.trace_context.has_trace() {
                Some(batch.trace_context.clone())
            } else {
                None
            };
            let events = batch
                .into_provisions()
                .into_iter()
                .map(|provision| Event::StateProvisionReceived { provision })
                .collect();
            Ok(DecodedMessage {
                events,
                trace_context: trace_ctx,
            })
        }
        "state.vote.batch" => {
            let batch: StateVoteBatch = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            let events = batch
                .into_votes()
                .into_iter()
                .map(|vote| Event::StateVoteReceived { vote })
                .collect();
            Ok(DecodedMessage {
                events,
                trace_context: None,
            })
        }
        "state.certificate.batch" => {
            let batch: StateCertificateBatch = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            let trace_ctx = if batch.trace_context.has_trace() {
                Some(batch.trace_context.clone())
            } else {
                None
            };
            let events = batch
                .into_certificates()
                .into_iter()
                .map(|cert| Event::StateCertificateReceived { cert })
                .collect();
            Ok(DecodedMessage {
                events,
                trace_context: trace_ctx,
            })
        }
        "transaction.gossip" => {
            let gossip: TransactionGossip = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            let trace_ctx = if gossip.trace_context.has_trace() {
                Some(gossip.trace_context)
            } else {
                None
            };
            Ok(DecodedMessage {
                events: vec![Event::TransactionGossipReceived {
                    tx: gossip.transaction,
                }],
                trace_context: trace_ctx,
            })
        }
        "transaction.certificate" => {
            let gossip: TransactionCertificateGossip = sbor::basic_decode(&payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            Ok(DecodedMessage {
                events: vec![Event::TransactionCertificateReceived {
                    certificate: gossip.into_certificate(),
                }],
                trace_context: None,
            })
        }
        _ => Err(CodecError::UnknownTopic(parsed_topic.to_string())),
    }
}

/// Decode a gossipsub message and route the resulting events.
///
/// Transaction gossips are routed to `tx_sink`; all other consensus events
/// are sent via `event_sink`.
///
/// # Arguments
///
/// * `topic` - The parsed gossipsub topic (determines message type)
/// * `data` - Raw (compressed) message bytes
/// * `peer_label` - Human-readable peer identifier for logging (not tied to libp2p)
/// * `event_sink` - Callback for consensus events. Returns `true` if accepted.
/// * `tx_sink` - Callback for transaction gossips. Returns `true` if accepted.
pub fn decode_and_route(
    topic: &Topic,
    data: &[u8],
    peer_label: &str,
    event_sink: &dyn Fn(Event) -> bool,
    tx_sink: &dyn Fn(Arc<RoutableTransaction>) -> bool,
) -> Result<(), CodecError> {
    let decoded = decode_message(topic, data)?;

    for event in decoded.events {
        match event {
            Event::TransactionGossipReceived { tx } => {
                if !tx_sink(tx) {
                    trace!(peer = peer_label, "Transaction deduplicated or sink closed");
                }
            }
            event => {
                if !event_sink(event) {
                    warn!(
                        peer = peer_label,
                        "Failed to send decoded event to consensus"
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeader, BlockHeight, BlockVote, Hash, QuorumCertificate, ShardGroupId, ValidatorId,
    };
    use std::collections::HashMap;

    fn make_block_header() -> BlockHeader {
        BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(&[0u8; 32]),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 0,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        }
    }

    #[test]
    fn test_encode_decode_block_header() {
        let header = make_block_header();
        let gossip = BlockHeaderGossip {
            header: header.clone(),
            retry_hashes: vec![],
            priority_hashes: vec![],
            transaction_hashes: vec![],
            certificate_hashes: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        };

        let bytes = encode_to_wire(&gossip).unwrap();
        assert!(!bytes.is_empty());

        let topic_str = "hyperscale/block.header/shard-0/1.0.0";
        let topic = Topic::parse(topic_str).unwrap();
        let decoded = decode_message(&topic, &bytes).unwrap();

        assert!(decoded.trace_context.is_none());
        assert_eq!(decoded.events.len(), 1);

        match &decoded.events[0] {
            Event::BlockHeaderReceived {
                header: decoded_header,
                ..
            } => {
                assert_eq!(decoded_header.height, header.height);
                assert_eq!(decoded_header.proposer, header.proposer);
            }
            _ => panic!("Expected BlockHeaderReceived"),
        }
    }

    #[test]
    fn test_encode_decode_block_vote() {
        let vote = BlockVote {
            block_hash: Hash::from_bytes(&[1u8; 32]),
            height: BlockHeight(1),
            voter: ValidatorId(0),
            round: 0,
            signature: hyperscale_types::zero_bls_signature(),
            timestamp: 0,
        };
        let gossip = BlockVoteGossip { vote: vote.clone() };

        let bytes = encode_to_wire(&gossip).unwrap();
        let topic_str = "hyperscale/block.vote/shard-0/1.0.0";
        let topic = Topic::parse(topic_str).unwrap();
        let decoded = decode_message(&topic, &bytes).unwrap();

        assert!(decoded.trace_context.is_none());
        assert_eq!(decoded.events.len(), 1);

        match &decoded.events[0] {
            Event::BlockVoteReceived { vote: decoded_vote } => {
                assert_eq!(decoded_vote.block_hash, vote.block_hash);
                assert_eq!(decoded_vote.voter, vote.voter);
            }
            _ => panic!("Expected BlockVoteReceived"),
        }
    }

    #[test]
    fn test_invalid_compressed_data() {
        let bytes = vec![99, 1, 2, 3];
        let topic = Topic::parse("hyperscale/block.header/shard-0/1.0.0").unwrap();
        let result = decode_message(&topic, &bytes);
        assert!(matches!(result, Err(CodecError::Decompress(_))));
    }

    #[test]
    fn test_unknown_topic() {
        let sbor_bytes = sbor::basic_encode(&()).unwrap();
        let bytes = wire::compress(&sbor_bytes);
        let topic = Topic::parse("hyperscale/unknown.type/shard-0/1.0.0").unwrap();
        let result = decode_message(&topic, &bytes);
        assert!(matches!(result, Err(CodecError::UnknownTopic(_))));
    }

    #[test]
    fn test_topic_construction() {
        let topic = Topic::block_header(ShardGroupId(5));
        assert_eq!(topic.to_string(), "hyperscale/block.header/shard-5/1.0.0");
    }
}
