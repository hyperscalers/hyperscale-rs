//! Structured gossipsub topic builder.
//!
//! This module provides a type-safe way to generate and parse gossipsub topics.
//! Topics follow the format: `hyperscale/{message_type}/[shard-{id}/]{major}.{minor}.0`
//!
//! # Examples
//!
//! ```
//! use hyperscale_network::Topic;
//! use hyperscale_types::ShardGroupId;
//!
//! // Global topic (no shard)
//! let global = Topic::global("block.header");
//! assert_eq!(global.to_string(), "hyperscale/block.header/1.0.0");
//!
//! // Shard-specific topic
//! let shard = Topic::shard("transaction.gossip", ShardGroupId(5));
//! assert_eq!(shard.to_string(), "hyperscale/transaction.gossip/shard-5/1.0.0");
//! ```

use hyperscale_types::ShardGroupId;

/// Protocol version for topic generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    /// Major version (breaking changes)
    pub major: u32,
    /// Minor version (backwards compatible changes)
    pub minor: u32,
}

impl ProtocolVersion {
    /// Current protocol version.
    pub const CURRENT: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Structured representation of a gossipsub topic for the **send path**.
///
/// Created via [`Topic::shard`] or [`Topic::global`] using `&'static str`
/// message type identifiers from `NetworkMessage::message_type_id()`.
///
/// # Topic Format
///
/// - Global: `hyperscale/{message_type}/{major}.{minor}.0`
/// - Shard: `hyperscale/{message_type}/shard-{id}/{major}.{minor}.0`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic {
    /// Message type identifier (e.g., "transaction.gossip", "block.header")
    message_type: &'static str,
    /// Optional shard targeting
    shard: Option<ShardGroupId>,
    /// Protocol version
    version: ProtocolVersion,
}

impl Topic {
    /// Create a global topic (no shard targeting).
    ///
    /// Global topics reach all validators regardless of shard assignment.
    #[must_use]
    pub fn global(message_type: &'static str) -> Self {
        Self {
            message_type,
            shard: None,
            version: ProtocolVersion::CURRENT,
        }
    }

    /// Create a shard-specific topic.
    ///
    /// Shard topics only reach validators subscribed to that shard.
    #[must_use]
    pub fn shard(message_type: &'static str, shard: ShardGroupId) -> Self {
        Self {
            message_type,
            shard: Some(shard),
            version: ProtocolVersion::CURRENT,
        }
    }

    /// Create a topic with a specific version.
    #[must_use]
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    /// Get the message type identifier.
    #[must_use]
    pub fn message_type(&self) -> &'static str {
        self.message_type
    }

    /// Get the optional shard ID.
    #[must_use]
    pub fn shard_id(&self) -> Option<ShardGroupId> {
        self.shard
    }

    /// Get the protocol version.
    #[must_use]
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Check if this is a global (non-shard) topic.
    #[must_use]
    pub fn is_global(&self) -> bool {
        self.shard.is_none()
    }

    /// Check if this is a shard-specific topic.
    #[must_use]
    pub fn is_shard(&self) -> bool {
        self.shard.is_some()
    }

    /// Convert to the gossipsub topic string.
    ///
    /// Format:
    /// - Global: `hyperscale/{message_type}/{major}.{minor}.0`
    /// - Shard: `hyperscale/{message_type}/shard-{id}/{major}.{minor}.0`
    #[must_use]
    pub fn to_topic_string(&self) -> String {
        match self.shard {
            Some(shard) => format!(
                "hyperscale/{}/shard-{}/{}.{}.0",
                self.message_type, shard.0, self.version.major, self.version.minor
            ),
            None => format!(
                "hyperscale/{}/{}.{}.0",
                self.message_type, self.version.major, self.version.minor
            ),
        }
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_topic_string())
    }
}

/// Result of parsing an incoming gossipsub topic string.
///
/// Used on the **receive path** where message types are dynamic strings
/// from the network, not compile-time `&'static str` identifiers.
#[derive(Debug, Clone)]
pub struct ParsedTopic<'a> {
    /// Message type identifier extracted from the topic string.
    pub message_type: &'a str,
    /// Optional shard targeting.
    pub shard_id: Option<ShardGroupId>,
}

/// Parse a gossipsub topic string into its components.
///
/// Extracts the message type and optional shard ID from topics matching:
/// - `hyperscale/{message_type}/{version}` (global)
/// - `hyperscale/{message_type}/shard-{id}/{version}` (shard-scoped)
///
/// Returns `None` if the topic format is invalid. Does **not** validate
/// the message type against a known set — handler lookup serves as
/// the validation step.
#[must_use]
pub fn parse_topic(topic_str: &str) -> Option<ParsedTopic<'_>> {
    let parts: Vec<&str> = topic_str.split('/').collect();

    // Must start with "hyperscale"
    if parts.is_empty() || parts[0] != "hyperscale" {
        return None;
    }

    match parts.len() {
        // Global format: hyperscale/{message_type}/{version}
        3 => {
            let message_type = parts[1];
            if message_type.is_empty() {
                return None;
            }
            if !validate_version(parts[2]) {
                return None;
            }
            Some(ParsedTopic {
                message_type,
                shard_id: None,
            })
        }
        // Shard format: hyperscale/{message_type}/shard-{id}/{version}
        4 => {
            let message_type = parts[1];
            if message_type.is_empty() {
                return None;
            }
            let shard_str = parts[2];
            let shard_id = if let Some(id_str) = shard_str.strip_prefix("shard-") {
                let shard_id: u64 = id_str.parse().ok()?;
                Some(ShardGroupId(shard_id))
            } else {
                return None;
            };

            if !validate_version(parts[3]) {
                return None;
            }
            Some(ParsedTopic {
                message_type,
                shard_id,
            })
        }
        _ => None,
    }
}

/// Validate that a version segment has the expected `major.minor.patch` shape.
///
/// We only need structural validation on the receive path (the actual version
/// is unused after parsing), so we just check for three dot-separated parts.
fn validate_version(version_str: &str) -> bool {
    version_str.split('.').count() == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_topic() {
        let topic = Topic::global("block.header");
        assert_eq!(topic.message_type(), "block.header");
        assert!(topic.is_global());
        assert!(!topic.is_shard());
        assert_eq!(topic.shard_id(), None);
        assert_eq!(topic.to_string(), "hyperscale/block.header/1.0.0");
    }

    #[test]
    fn test_shard_topic() {
        let topic = Topic::shard("transaction.gossip", ShardGroupId(5));
        assert_eq!(topic.message_type(), "transaction.gossip");
        assert!(!topic.is_global());
        assert!(topic.is_shard());
        assert_eq!(topic.shard_id(), Some(ShardGroupId(5)));
        assert_eq!(
            topic.to_string(),
            "hyperscale/transaction.gossip/shard-5/1.0.0"
        );
    }

    #[test]
    fn test_parse_global_topic() {
        let parsed = parse_topic("hyperscale/block.header/1.0.0").unwrap();
        assert_eq!(parsed.message_type, "block.header");
        assert!(parsed.shard_id.is_none());
    }

    #[test]
    fn test_parse_shard_topic() {
        let parsed = parse_topic("hyperscale/transaction.gossip/shard-3/1.0.0").unwrap();
        assert_eq!(parsed.message_type, "transaction.gossip");
        assert_eq!(parsed.shard_id, Some(ShardGroupId(3)));
    }

    #[test]
    fn test_parse_unknown_type_accepted() {
        // Any well-formed topic is accepted — validation is by handler lookup
        let parsed = parse_topic("hyperscale/unknown.type/1.0.0").unwrap();
        assert_eq!(parsed.message_type, "unknown.type");
    }

    #[test]
    fn test_parse_invalid_topics() {
        assert!(parse_topic("invalid/topic").is_none());
        assert!(parse_topic("hyperscale/").is_none());
        assert!(parse_topic("hyperscale/msg").is_none());
        assert!(parse_topic("hyperscale/msg/not-shard/1.0.0").is_none());
        assert!(parse_topic("other/block.header/1.0.0").is_none());
        assert!(parse_topic("hyperscale//1.0.0").is_none());
    }

    #[test]
    fn test_roundtrip() {
        let original = Topic::global("block.header");
        let string = original.to_string();
        let parsed = parse_topic(&string).unwrap();
        assert_eq!(parsed.message_type, original.message_type());
        assert_eq!(parsed.shard_id, original.shard_id());

        let original = Topic::shard("transaction.gossip", ShardGroupId(42));
        let string = original.to_string();
        let parsed = parse_topic(&string).unwrap();
        assert_eq!(parsed.message_type, original.message_type());
        assert_eq!(parsed.shard_id, original.shard_id());
    }
}
