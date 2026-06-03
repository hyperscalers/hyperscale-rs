//! Domain-separated signing for shard consensus messages.

use crate::{BlockHash, BlockHeight, NetworkDefinition, Round, ShardGroupId};

/// Domain tag for shard consensus block votes.
///
/// Format: `BLOCK_VOTE` || `network.id` || `shard_group_id` || height || round
/// || `block_hash`
pub const DOMAIN_BLOCK_VOTE: &[u8] = b"BLOCK_VOTE";

/// Domain tag for block header proposal gossip.
///
/// Format: `BLOCK_HEADER` || `network.id` || `shard_group_id` || height ||
/// round || `block_hash`
///
/// Signed by the proposer when broadcasting block header proposals.
/// Verified by receivers before admitting the proposal into shard consensus.
/// Distinct from `DOMAIN_BLOCK_VOTE` to prevent cross-protocol replay.
pub const DOMAIN_BLOCK_HEADER: &[u8] = b"BLOCK_HEADER";

/// Domain tag for committed block header gossip.
///
/// Format: `COMMITTED_BLOCK_HEADER` || `network.id` || `shard_group_id` ||
/// height || `block_hash`
///
/// Signed by the sender (proposer) when broadcasting committed block headers
/// globally. Verified by `IoLoop` before admitting to the state machine.
pub const DOMAIN_COMMITTED_BLOCK_HEADER: &[u8] = b"COMMITTED_BLOCK_HEADER";

/// Domain tag for shard consensus timeout messages.
///
/// Format: `TIMEOUT` || `network.id` || `shard_group_id` || round
///
/// Signed by a validator when its round timer fires. The share covers only
/// `(shard, round)` — the timeout also carries the signer's `high_qc`, but a
/// QC is self-authenticating (it is its own 2f+1 aggregate), so its round need
/// not be bound here. Distinct domain from `DOMAIN_BLOCK_VOTE` to prevent
/// cross-protocol replay.
pub const DOMAIN_TIMEOUT: &[u8] = b"TIMEOUT";

/// Build the signing message for a block vote.
///
/// This is used for:
/// - Individual block vote signatures
/// - QC aggregated signature verification
/// - View change `highest_qc` verification
///
/// `parent_block_hash` is bound in so the QC's committable-block selector (the
/// two-chain rule) is authenticated by the quorum, not merely trusted.
#[must_use]
pub fn block_vote_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
    parent_block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(113);
    message.extend_from_slice(DOMAIN_BLOCK_VOTE);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message.extend_from_slice(parent_block_hash.as_bytes());
    message
}

/// Build the signing message for a block header proposal.
///
/// This is used for:
/// - Proposer signature on `BlockHeaderNotification` (authenticated proposals)
/// - Verification before admitting proposals to the shard consensus state machine
#[must_use]
pub fn block_header_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(81);
    message.extend_from_slice(DOMAIN_BLOCK_HEADER);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Build the signing message for a shard consensus timeout.
///
/// Covers only `(shard, round)`; the carried `high_qc` self-authenticates as a
/// QC and is verified separately on receipt.
#[must_use]
pub fn timeout_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    round: Round,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_TIMEOUT.len() + 1 + 8 + 8);
    message.extend_from_slice(DOMAIN_TIMEOUT);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message
}

/// Build the signing message for a committed block header gossip.
///
/// This is used for verifying the sender's signature on globally broadcast
/// committed block headers before admitting them to the state machine.
#[must_use]
pub fn certified_block_header_message(
    network: &NetworkDefinition,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_COMMITTED_BLOCK_HEADER);
    message.push(network.id);
    message.extend_from_slice(&shard_group_id.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn test_block_vote_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));

        let msg1 = block_vote_message(
            &net(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent,
        );
        let msg2 = block_vote_message(
            &net(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent,
        );

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_VOTE));
    }

    #[test]
    fn block_vote_message_binds_parent_block_hash() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));
        let parent_a = BlockHash::from_raw(Hash::from_bytes(b"parent_a"));
        let parent_b = BlockHash::from_raw(Hash::from_bytes(b"parent_b"));

        // Same block, different parent → different message. This is what stops a
        // proposer forging a QC's parent_block_hash to point at a sibling block.
        let msg_a = block_vote_message(
            &net(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent_a,
        );
        let msg_b = block_vote_message(
            &net(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent_b,
        );

        assert_ne!(msg_a, msg_b);
    }

    #[test]
    fn test_certified_block_header_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let msg1 = certified_block_header_message(&net(), shard, BlockHeight::new(10), &block);
        let msg2 = certified_block_header_message(&net(), shard, BlockHeight::new(10), &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_COMMITTED_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let msg1 =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);
        let msg2 =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_differs_from_block_vote() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        let header_msg =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);
        let vote_msg = block_vote_message(
            &net(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent,
        );

        // Must differ due to different domain tags (prevents cross-protocol replay)
        assert_ne!(header_msg, vote_msg);
    }

    #[test]
    fn block_vote_message_differs_across_networks() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        let mainnet = block_vote_message(
            &NetworkDefinition::mainnet(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent,
        );
        let stokenet = block_vote_message(
            &NetworkDefinition::stokenet(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
            &parent,
        );
        // Cross-network replay protection: byte-identical inputs under
        // different networks must produce different messages.
        assert_ne!(mainnet, stokenet);
    }
}
