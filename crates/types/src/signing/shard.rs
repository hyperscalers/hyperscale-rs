//! Signing messages for shard consensus.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{BlockHash, BlockHeight, Round, ShardId};

/// What a block vote's signature covers.
///
/// Used for individual block vote signatures, QC aggregated signature
/// verification, and view-change `highest_qc` verification.
/// `parent_block_hash` is bound in so the QC's committable-block selector
/// (the two-chain rule) is authenticated by the quorum, not merely
/// trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-block-vote-v1", signing_context = NetworkId)]
pub struct BlockVoteMessage {
    /// Shard whose consensus the vote belongs to.
    pub shard_group: ShardId,
    /// Height of the block being voted on.
    pub height: BlockHeight,
    /// Consensus round of the vote.
    pub round: Round,
    /// The block being voted on.
    pub block_hash: BlockHash,
    /// The voted block's parent.
    pub parent_block_hash: BlockHash,
}

/// What a shard timeout share's signature covers: the round it gives up on
/// and the round of the QC it reports. A timeout certificate re-derives one
/// of these per signer to check its aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-timeout-v1", signing_context = NetworkId)]
pub struct TimeoutMessage {
    /// Shard whose consensus the timeout belongs to.
    pub shard_id: ShardId,
    /// The round timed out.
    pub round: Round,
    /// Round of the QC the signer reports as its highest.
    pub high_qc_round: Round,
}

/// What a QC announcement's sender signature covers: the round and block
/// the announced QC certifies. It authenticates the announcer, not the QC,
/// which authenticates itself; a receiver spends one QC verification per
/// announcer and round.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-qc-announcement-v1", signing_context = NetworkId)]
pub struct QcAnnouncementMessage {
    /// Shard whose consensus the QC belongs to.
    pub shard_id: ShardId,
    /// Round of the certified block.
    pub round: Round,
    /// The certified block.
    pub block_hash: BlockHash,
}

/// What a block header proposal's signature covers.
///
/// Signed by the proposer when broadcasting block header proposals;
/// verified before admitting the proposal into shard consensus. A domain
/// of its own so a proposal signature can't stand in for a vote.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-block-proposal-v1", signing_context = NetworkId)]
pub struct BlockProposalMessage {
    /// Shard whose consensus the proposal belongs to.
    pub shard_group: ShardId,
    /// Height of the proposed block.
    pub height: BlockHeight,
    /// Consensus round of the proposal.
    pub round: Round,
    /// The proposed block.
    pub block_hash: BlockHash,
}

/// What a committed block header gossip's signature covers.
///
/// Signed by the sender when broadcasting committed block headers
/// globally; verified before admitting them to the state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-certified-block-header-sender-v1", signing_context = NetworkId)]
pub struct CertifiedBlockHeaderSenderMessage {
    /// Shard the committed block belongs to.
    pub shard_id: ShardId,
    /// Height of the committed block.
    pub height: BlockHeight,
    /// The committed block.
    pub block_hash: BlockHash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::signed_bytes;
    use crate::{Hash, NetworkDefinition};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn block_vote_message_binds_parent_block_hash() {
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));
        let parent_a = BlockHash::from_raw(Hash::from_bytes(b"parent_a"));
        let parent_b = BlockHash::from_raw(Hash::from_bytes(b"parent_b"));

        // Same block, different parent → different message. This is what
        // stops a proposer forging a QC's parent_block_hash to point at a
        // sibling block.
        let mk = |parent: BlockHash| {
            signed_bytes(
                &BlockVoteMessage {
                    shard_group: ShardId::ROOT,
                    height: BlockHeight::new(10),
                    round: Round::INITIAL,
                    block_hash: block,
                    parent_block_hash: parent,
                },
                &net(),
            )
        };
        assert_ne!(mk(parent_a), mk(parent_b));
    }
}
