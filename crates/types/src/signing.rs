//! Domain-separated signing for cryptographic operations.
//!
//! This module provides type-safe domain separation tags for all signed messages
//! in the consensus protocol. Domain separation prevents cross-protocol attacks
//! where a signature from one context could be replayed in another.
//!
//! # Domain Tags
//!
//! Each signable message type has a unique domain tag prefix:
//!
//! | Tag | Purpose |
//! |-----|---------|
//! | `BLOCK_VOTE` | BFT block votes |
//! | `EXEC_VOTE` | Execution votes |
//! | `COMMITTED_BLOCK_HEADER` | Committed block header gossip |
//!
//! # Usage
//!
//! Types that need signing should implement the `Signable` trait or use the
//! `signing_message()` method pattern. The signing message is constructed
//! by prepending the domain tag to the serialized content.

use crate::{Hash, ShardGroupId};

/// Domain tag for BFT block votes.
///
/// Format: `BLOCK_VOTE` || shard_group_id || height || round || block_hash
pub const DOMAIN_BLOCK_VOTE: &[u8] = b"BLOCK_VOTE";

/// Domain tag for execution votes.
///
/// Format: `EXEC_VOTE` || tx_hash || state_root || shard_group || success
///
/// Note: ExecutionCertificates aggregate signatures from ExecutionVotes, so they
/// use the same domain tag since they verify the same underlying message.
pub const DOMAIN_EXEC_VOTE: &[u8] = b"EXEC_VOTE";

/// Domain tag for committed block header gossip.
///
/// Format: `COMMITTED_BLOCK_HEADER` || shard_group_id || height || block_hash
///
/// Signed by the sender (proposer) when broadcasting committed block headers
/// globally. Verified by IoLoop before admitting to the state machine.
pub const DOMAIN_COMMITTED_BLOCK_HEADER: &[u8] = b"COMMITTED_BLOCK_HEADER";

/// Build the signing message for a block vote.
///
/// This is used for:
/// - Individual block vote signatures
/// - QC aggregated signature verification
/// - View change highest_qc verification
pub fn block_vote_message(
    shard_group: ShardGroupId,
    height: u64,
    round: u64,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(DOMAIN_BLOCK_VOTE);
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Build the signing message for a committed block header gossip.
///
/// This is used for verifying the sender's signature on globally broadcast
/// committed block headers before admitting them to the state machine.
pub fn committed_block_header_message(
    shard_group_id: ShardGroupId,
    height: u64,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(DOMAIN_COMMITTED_BLOCK_HEADER);
    message.extend_from_slice(&shard_group_id.0.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Build the signing message for an execution vote.
///
/// This is used for:
/// - Individual ExecutionVote signatures
/// - ExecutionCertificate aggregated signature verification
///
/// Note: Both use the same message format because ExecutionCertificates aggregate
/// signatures from ExecutionVotes.
pub fn exec_vote_message(
    tx_hash: &Hash,
    writes_commitment: &Hash,
    shard_group: ShardGroupId,
    success: bool,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_EXEC_VOTE);
    message.extend_from_slice(tx_hash.as_bytes());
    message.extend_from_slice(writes_commitment.as_bytes());
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.push(if success { 1 } else { 0 });
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_vote_message_deterministic() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let msg1 = block_vote_message(shard, 10, 0, &block);
        let msg2 = block_vote_message(shard, 10, 0, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_VOTE));
    }

    #[test]
    fn test_exec_vote_message_deterministic() {
        let tx_hash = Hash::from_bytes(b"tx_hash");
        let state_root = Hash::from_bytes(b"state_root");

        let msg1 = exec_vote_message(&tx_hash, &state_root, ShardGroupId(0), true);
        let msg2 = exec_vote_message(&tx_hash, &state_root, ShardGroupId(0), true);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_EXEC_VOTE));
    }

    #[test]
    fn test_committed_block_header_message_deterministic() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let msg1 = committed_block_header_message(shard, 10, &block);
        let msg2 = committed_block_header_message(shard, 10, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_COMMITTED_BLOCK_HEADER));
    }

    #[test]
    fn test_different_domains_produce_different_messages() {
        let hash = Hash::from_bytes(b"same_hash_value_here");

        let block_msg = block_vote_message(ShardGroupId(0), 0, 0, &hash);
        let exec_msg = exec_vote_message(&hash, &hash, ShardGroupId(0), true);

        // All messages should be different due to domain tags
        assert_ne!(block_msg, exec_msg);
    }
}
