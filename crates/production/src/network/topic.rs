//! Structured gossipsub topic builder.
//!
//! This module provides a type-safe way to generate and parse gossipsub topics.
//! Topics follow the format: `hyperscale/{message_type}/[shard-{id}/]{major}.{minor}.0`
//!
//! # Examples
//!
//! ```
//! use hyperscale_production::network::Topic;
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

/// Structured representation of a gossipsub topic.
///
/// Topics are used for:
/// - Subscribing to message types
/// - Routing broadcast messages
/// - Filtering incoming messages
///
/// # Topic Format
///
/// - Global: `hyperscale/{message_type}/{major}.{minor}.0`
/// - Shard: `hyperscale/{message_type}/shard-{id}/{major}.{minor}.0`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic {
    /// Message type identifier (e.g., "transaction.gossip", "block.header")
    message_type: String,
    /// Optional shard targeting
    shard: Option<ShardGroupId>,
    /// Protocol version
    version: ProtocolVersion,
}

impl Topic {
    /// Create a global topic (no shard targeting).
    ///
    /// Global topics reach all validators regardless of shard assignment.
    pub fn global(message_type: impl Into<String>) -> Self {
        Self {
            message_type: message_type.into(),
            shard: None,
            version: ProtocolVersion::CURRENT,
        }
    }

    /// Create a shard-specific topic.
    ///
    /// Shard topics only reach validators subscribed to that shard.
    pub fn shard(message_type: impl Into<String>, shard: ShardGroupId) -> Self {
        Self {
            message_type: message_type.into(),
            shard: Some(shard),
            version: ProtocolVersion::CURRENT,
        }
    }

    /// Create a topic with a specific version.
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    /// Get the message type identifier.
    pub fn message_type(&self) -> &str {
        &self.message_type
    }

    /// Get the optional shard ID.
    pub fn shard_id(&self) -> Option<ShardGroupId> {
        self.shard
    }

    /// Get the protocol version.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Check if this is a global (non-shard) topic.
    pub fn is_global(&self) -> bool {
        self.shard.is_none()
    }

    /// Check if this is a shard-specific topic.
    pub fn is_shard(&self) -> bool {
        self.shard.is_some()
    }

    /// Convert to the gossipsub topic string.
    ///
    /// Format:
    /// - Global: `hyperscale/{message_type}/{major}.{minor}.0`
    /// - Shard: `hyperscale/{message_type}/shard-{id}/{major}.{minor}.0`
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

    /// Parse a topic string back to a Topic.
    ///
    /// Returns `None` if the format is invalid.
    pub fn parse(topic_str: &str) -> Option<Self> {
        let parts: Vec<&str> = topic_str.split('/').collect();

        // Must start with "hyperscale"
        if parts.is_empty() || parts[0] != "hyperscale" {
            return None;
        }

        match parts.len() {
            // Global format: hyperscale/{message_type}/{version}
            3 => {
                let message_type = parts[1].to_string();
                let version = Self::parse_version(parts[2])?;
                Some(Self {
                    message_type,
                    shard: None,
                    version,
                })
            }
            // Shard format: hyperscale/{message_type}/shard-{id}/{version}
            4 => {
                let message_type = parts[1].to_string();
                let shard_str = parts[2];

                // Check for shard prefix
                let shard = if let Some(id_str) = shard_str.strip_prefix("shard-") {
                    let shard_id: u64 = id_str.parse().ok()?;
                    Some(ShardGroupId(shard_id))
                } else {
                    return None;
                };

                let version = Self::parse_version(parts[3])?;
                Some(Self {
                    message_type,
                    shard,
                    version,
                })
            }
            _ => None,
        }
    }

    /// Parse version string (e.g., "1.0.0")
    fn parse_version(version_str: &str) -> Option<ProtocolVersion> {
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(ProtocolVersion {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Predefined topics for message types
    // ═══════════════════════════════════════════════════════════════════════

    /// Topic for block header gossip.
    pub fn block_header(shard: ShardGroupId) -> Self {
        Self::shard("block.header", shard)
    }

    /// Topic for block vote gossip.
    pub fn block_vote(shard: ShardGroupId) -> Self {
        Self::shard("block.vote", shard)
    }

    // Note: view_change.vote and view_change.certificate topics removed
    // Using HotStuff-2 implicit rounds instead

    /// Topic for transaction gossip.
    pub fn transaction_gossip(shard: ShardGroupId) -> Self {
        Self::shard("transaction.gossip", shard)
    }

    /// Topic for transaction certificate gossip (finalized certificates).
    ///
    /// When a TransactionCertificate is finalized, it is gossiped to same-shard
    /// peers so they have it before the proposer includes it in a block.
    pub fn transaction_certificate(shard: ShardGroupId) -> Self {
        Self::shard("transaction.certificate", shard)
    }

    /// Topic for state provision batch gossip.
    pub fn state_provision_batch(shard: ShardGroupId) -> Self {
        Self::shard("state.provision.batch", shard)
    }

    /// Topic for state vote batch gossip.
    pub fn state_vote_batch(shard: ShardGroupId) -> Self {
        Self::shard("state.vote.batch", shard)
    }

    /// Topic for state certificate batch gossip.
    pub fn state_certificate_batch(shard: ShardGroupId) -> Self {
        Self::shard("state.certificate.batch", shard)
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_topic_string())
    }
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
        let topic = Topic::parse("hyperscale/block.header/1.0.0").unwrap();
        assert_eq!(topic.message_type(), "block.header");
        assert!(topic.is_global());
        assert_eq!(topic.version(), ProtocolVersion::CURRENT);
    }

    #[test]
    fn test_parse_shard_topic() {
        let topic = Topic::parse("hyperscale/transaction.gossip/shard-3/1.0.0").unwrap();
        assert_eq!(topic.message_type(), "transaction.gossip");
        assert_eq!(topic.shard_id(), Some(ShardGroupId(3)));
        assert_eq!(topic.version(), ProtocolVersion::CURRENT);
    }

    #[test]
    fn test_parse_invalid_topics() {
        assert!(Topic::parse("invalid/topic").is_none());
        assert!(Topic::parse("hyperscale/").is_none());
        assert!(Topic::parse("hyperscale/msg").is_none());
        assert!(Topic::parse("hyperscale/msg/not-shard/1.0.0").is_none());
        assert!(Topic::parse("other/block.header/1.0.0").is_none());
    }

    #[test]
    fn test_roundtrip() {
        // Global topic roundtrip
        let original = Topic::global("test.message");
        let string = original.to_string();
        let parsed = Topic::parse(&string).unwrap();
        assert_eq!(original, parsed);

        // Shard topic roundtrip
        let original = Topic::shard("test.message", ShardGroupId(42));
        let string = original.to_string();
        let parsed = Topic::parse(&string).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_predefined_topics() {
        let shard = ShardGroupId(0);

        assert_eq!(
            Topic::block_header(shard).to_string(),
            "hyperscale/block.header/shard-0/1.0.0"
        );
        assert_eq!(
            Topic::block_vote(shard).to_string(),
            "hyperscale/block.vote/shard-0/1.0.0"
        );
        assert_eq!(
            Topic::transaction_gossip(shard).to_string(),
            "hyperscale/transaction.gossip/shard-0/1.0.0"
        );
    }
}
