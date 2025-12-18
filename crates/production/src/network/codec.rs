//! Message encoding and decoding for network transport.
//!
//! # Wire Format
//!
//! ```text
//! [version: u8][payload: SBOR-encoded message]
//! ```
//!
//! - Version is currently `1`
//! - Payload is SBOR-encoded gossip struct (e.g., `BlockHeaderGossip`)
//!
//! # Topic-Based Type Dispatch
//!
//! Message type is determined by the gossipsub topic, not by a field in the
//! message. This simplifies the wire format and allows efficient routing.

use hyperscale_core::{Event, OutboundMessage};
use hyperscale_messages::gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TransactionGossip,
};
use hyperscale_messages::TraceContext;
use hyperscale_types::ShardGroupId;
use thiserror::Error;

/// Current wire format version.
pub const WIRE_VERSION: u8 = 1;

/// Errors that can occur during message encoding/decoding.
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Unknown wire version: {0}")]
    UnknownVersion(u8),

    #[error("Message too short")]
    MessageTooShort,

    #[error("SBOR decode error: {0}")]
    SborDecode(String),

    #[error("SBOR encode error: {0}")]
    SborEncode(String),

    #[error("Unknown topic: {0}")]
    UnknownTopic(String),
}

/// Encode an outbound message to wire format.
///
/// Returns the bytes to publish to gossipsub.
pub fn encode_message(message: &OutboundMessage) -> Result<Vec<u8>, CodecError> {
    let payload =
        match message {
            OutboundMessage::BlockHeader(gossip) => sbor::basic_encode(gossip)
                .map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?,
            OutboundMessage::BlockVote(gossip) => sbor::basic_encode(gossip)
                .map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?,
            OutboundMessage::StateProvisionBatch(batch) => {
                sbor::basic_encode(batch).map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?
            }
            OutboundMessage::StateVoteBatch(batch) => {
                sbor::basic_encode(batch).map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?
            }
            OutboundMessage::StateCertificateBatch(batch) => {
                sbor::basic_encode(batch).map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?
            }
            OutboundMessage::TransactionGossip(gossip) => sbor::basic_encode(gossip.as_ref())
                .map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?,
        };

    // Prepend version byte
    let mut bytes = Vec::with_capacity(1 + payload.len());
    bytes.push(WIRE_VERSION);
    bytes.extend(payload);
    Ok(bytes)
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
/// The topic determines the message type (topic-based dispatch).
/// Returns the decoded events along with any trace context for distributed tracing.
pub fn decode_message(topic: &str, data: &[u8]) -> Result<DecodedMessage, CodecError> {
    if data.is_empty() {
        return Err(CodecError::MessageTooShort);
    }

    // Check version
    let version = data[0];
    if version != WIRE_VERSION {
        return Err(CodecError::UnknownVersion(version));
    }

    let payload = &data[1..];

    // Parse topic to determine message type
    let parsed_topic = crate::network::Topic::parse(topic)
        .ok_or_else(|| CodecError::UnknownTopic(topic.to_string()))?;

    let msg_type = parsed_topic.message_type();

    // Dispatch based on message type from topic
    match msg_type {
        "block.header" => {
            let gossip: BlockHeaderGossip = sbor::basic_decode(payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            Ok(DecodedMessage {
                events: vec![Event::BlockHeaderReceived {
                    header: gossip.header,
                    tx_hashes: gossip.transaction_hashes,
                    cert_hashes: gossip.certificate_hashes,
                    deferred: gossip.deferred,
                    aborted: gossip.aborted,
                }],
                trace_context: None,
            })
        }
        "block.vote" => {
            let gossip: BlockVoteGossip = sbor::basic_decode(payload)
                .map_err(|e| CodecError::SborDecode(format!("{:?}", e)))?;
            Ok(DecodedMessage {
                events: vec![Event::BlockVoteReceived { vote: gossip.vote }],
                trace_context: None,
            })
        }
        "state.provision.batch" => {
            let batch: StateProvisionBatch = sbor::basic_decode(payload)
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
            let batch: StateVoteBatch = sbor::basic_decode(payload)
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
            let batch: StateCertificateBatch = sbor::basic_decode(payload)
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
            let gossip: TransactionGossip = sbor::basic_decode(payload)
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
        _ => Err(CodecError::UnknownTopic(topic.to_string())),
    }
}

/// Get the topic for an outbound message.
pub fn topic_for_message(message: &OutboundMessage, shard: ShardGroupId) -> crate::network::Topic {
    use crate::network::Topic;

    match message {
        OutboundMessage::BlockHeader(_) => Topic::block_header(shard),
        OutboundMessage::BlockVote(_) => Topic::block_vote(shard),
        OutboundMessage::StateProvisionBatch(_) => Topic::state_provision_batch(shard),
        OutboundMessage::StateVoteBatch(_) => Topic::state_vote_batch(shard),
        OutboundMessage::StateCertificateBatch(_) => Topic::state_certificate_batch(shard),
        OutboundMessage::TransactionGossip(_) => Topic::transaction_gossip(shard),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeader, BlockHeight, BlockVote, Hash, QuorumCertificate, Signature, ValidatorId,
    };

    fn make_block_header() -> BlockHeader {
        BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(&[0u8; 32]),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 0,
            round: 0,
            is_fallback: false,
        }
    }

    #[test]
    fn test_encode_decode_block_header() {
        let header = make_block_header();
        let gossip = BlockHeaderGossip {
            header: header.clone(),
            transaction_hashes: vec![],
            certificate_hashes: vec![],
            deferred: vec![],
            aborted: vec![],
        };
        let message = OutboundMessage::BlockHeader(Box::new(gossip));

        // Encode
        let bytes = encode_message(&message).unwrap();
        assert_eq!(bytes[0], WIRE_VERSION);

        // Decode with topic
        let topic = "hyperscale/block.header/shard-0/1.0.0";
        let decoded = decode_message(topic, &bytes).unwrap();

        // Block headers don't carry trace context
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
            signature: Signature::zero(),
            timestamp: 0,
        };
        let gossip = BlockVoteGossip { vote: vote.clone() };
        let message = OutboundMessage::BlockVote(gossip);

        let bytes = encode_message(&message).unwrap();
        let topic = "hyperscale/block.vote/shard-0/1.0.0";
        let decoded = decode_message(topic, &bytes).unwrap();

        // Block votes don't carry trace context
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
    fn test_unknown_version() {
        let bytes = vec![99, 1, 2, 3]; // version 99 doesn't exist
        let result = decode_message("hyperscale/block.header/shard-0/1.0.0", &bytes);
        assert!(matches!(result, Err(CodecError::UnknownVersion(99))));
    }

    #[test]
    fn test_unknown_topic() {
        let bytes = vec![WIRE_VERSION, 1, 2, 3];
        let result = decode_message("hyperscale/unknown.type/shard-0/1.0.0", &bytes);
        assert!(matches!(result, Err(CodecError::UnknownTopic(_))));
    }

    #[test]
    fn test_topic_for_message() {
        let header = make_block_header();
        let gossip = BlockHeaderGossip {
            header,
            transaction_hashes: vec![],
            certificate_hashes: vec![],
            deferred: vec![],
            aborted: vec![],
        };
        let message = OutboundMessage::BlockHeader(Box::new(gossip));

        let topic = topic_for_message(&message, ShardGroupId(5));
        assert_eq!(topic.to_string(), "hyperscale/block.header/shard-5/1.0.0");
    }
}
