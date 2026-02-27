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
//! | `STATE_PROVISION` | Cross-shard state provisions |
//! | `EXEC_VOTE` | Execution state votes |
//!
//! # Usage
//!
//! Types that need signing should implement the `Signable` trait or use the
//! `signing_message()` method pattern. The signing message is constructed
//! by prepending the domain tag to the serialized content.

use crate::{BlockHeight, Hash, ShardGroupId};

/// Domain tag for BFT block votes.
///
/// Format: `BLOCK_VOTE` || shard_group_id || height || round || block_hash
pub const DOMAIN_BLOCK_VOTE: &[u8] = b"BLOCK_VOTE";

/// Domain tag for cross-shard state provisions.
///
/// Format: `STATE_PROVISION` || tx_hash || target_shard || source_shard || height || timestamp || entries_hash
pub const DOMAIN_STATE_PROVISION: &[u8] = b"STATE_PROVISION";

/// Domain tag for execution state votes.
///
/// Format: `EXEC_VOTE` || tx_hash || state_root || shard_group || success
///
/// Note: StateCertificates aggregate signatures from StateVoteBlocks, so they
/// use the same domain tag since they verify the same underlying message.
pub const DOMAIN_EXEC_VOTE: &[u8] = b"EXEC_VOTE";

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

/// Build the signing message for a state provision.
///
/// This is used for verifying cross-shard state provisions.
pub fn state_provision_message(
    tx_hash: &Hash,
    target_shard: ShardGroupId,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    block_timestamp: u64,
    entries_hashes: &[Hash],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_STATE_PROVISION);
    msg.extend_from_slice(tx_hash.as_bytes());
    msg.extend_from_slice(&target_shard.0.to_le_bytes());
    msg.extend_from_slice(&source_shard.0.to_le_bytes());
    msg.extend_from_slice(&block_height.0.to_le_bytes());
    msg.extend_from_slice(&block_timestamp.to_le_bytes());

    for hash in entries_hashes {
        msg.extend_from_slice(hash.as_bytes());
    }

    msg
}

/// Build the signing message for an execution state vote.
///
/// This is used for:
/// - Individual StateVoteBlock signatures
/// - StateCertificate aggregated signature verification
///
/// Note: Both use the same message format because StateCertificates aggregate
/// signatures from StateVoteBlocks.
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
    fn test_state_provision_message_deterministic() {
        let tx_hash = Hash::from_bytes(b"tx_hash");
        let entry1 = Hash::from_bytes(b"entry1");
        let entry2 = Hash::from_bytes(b"entry2");

        let msg1 = state_provision_message(
            &tx_hash,
            ShardGroupId(1),
            ShardGroupId(0),
            BlockHeight(10),
            1234567890,
            &[entry1, entry2],
        );
        let msg2 = state_provision_message(
            &tx_hash,
            ShardGroupId(1),
            ShardGroupId(0),
            BlockHeight(10),
            1234567890,
            &[entry1, entry2],
        );

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_STATE_PROVISION));
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
