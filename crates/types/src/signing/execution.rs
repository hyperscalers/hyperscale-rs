//! Signing messages for execution votes and certificate gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{
    ExecutionCertificate, ExecutionVote, GlobalReceiptRoot, Hash, ShardId, TickId,
    WeightedTimestamp,
};

/// What an execution vote's signature covers.
///
/// Used for both individual [`ExecutionVote`] signatures and
/// [`ExecutionCertificate`] aggregated signature verification. The
/// `tick_id` is self-contained (shard + block height + remote shards), so
/// no separate block hash is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-execution-vote-v1", signing_context = NetworkId)]
pub struct ExecutionVoteMessage {
    /// BFT-authenticated anchor the vote was cast at.
    pub vote_anchor_ts: WeightedTimestamp,
    /// The tick being voted on.
    pub tick_id: TickId,
    /// Shard casting the vote.
    pub shard_group: ShardId,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: GlobalReceiptRoot,
    /// Number of transactions in the tick.
    pub tx_count: u32,
}

/// What an execution-vote batch gossip signature covers: the shard plus a
/// digest naming the batch's votes.
///
/// The digest binds every field a vote's own signature covers, plus its signer
/// and that signature. Digesting receipt roots alone would let a holder of one
/// valid envelope reattribute its votes to other validators, ticks and anchors
/// and still clear this gate; the rewritten votes would then fail their own
/// verification, but only after the batch had been admitted and paid for. The
/// fields are named explicitly rather than inferred from the signature,
/// because the point is to reject rewritten bytes *before* verifying them.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-execution-votes-sender-v1", signing_context = NetworkId)]
pub struct ExecutionVotesSenderMessage {
    /// Shard the votes belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's votes, in batch order.
    pub votes_digest: Hash,
}

impl ExecutionVotesSenderMessage {
    /// Assemble the message an execution-vote batch signs.
    #[must_use]
    pub fn new<'a, I>(shard_group: ShardId, votes: I) -> Self
    where
        I: IntoIterator<Item = &'a ExecutionVote>,
    {
        let mut hasher = Hasher::new();
        for v in votes {
            hasher.update(&v.validator().inner().to_le_bytes());
            hasher.update(&v.vote_anchor_ts().as_millis().to_le_bytes());
            hasher.update(&v.tick_id().shard_id().depth().to_le_bytes());
            hasher.update(&v.tick_id().shard_id().path().to_le_bytes());
            hasher.update(&v.tick_id().block_height().inner().to_le_bytes());
            hasher.update(&v.shard_id().depth().to_le_bytes());
            hasher.update(&v.shard_id().path().to_le_bytes());
            hasher.update(v.global_receipt_root().as_raw().as_bytes());
            hasher.update(&v.tx_count().to_le_bytes());
            hasher.update(v.signature().as_bytes());
        }
        Self {
            shard_group,
            votes_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

/// What an execution-certificate batch gossip signature covers.
///
/// Same shape as [`ExecutionVotesSenderMessage`] under its own domain, and
/// bound the same way: every field the aggregate stands for, plus the signer
/// set and the aggregate itself.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-execution-certificates-sender-v1", signing_context = NetworkId)]
pub struct ExecutionCertificatesSenderMessage {
    /// Shard the certificates belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's certificates, in batch order.
    pub certificates_digest: Hash,
}

impl ExecutionCertificatesSenderMessage {
    /// Assemble the message an execution-certificate batch signs.
    #[must_use]
    pub fn new(shard_group: ShardId, certificates: &[ExecutionCertificate]) -> Self {
        let mut hasher = Hasher::new();
        for c in certificates {
            hasher.update(&c.vote_anchor_ts().as_millis().to_le_bytes());
            hasher.update(&c.tick_id().shard_id().depth().to_le_bytes());
            hasher.update(&c.tick_id().shard_id().path().to_le_bytes());
            hasher.update(&c.tick_id().block_height().inner().to_le_bytes());
            hasher.update(&c.shard_id().depth().to_le_bytes());
            hasher.update(&c.shard_id().path().to_le_bytes());
            hasher.update(c.global_receipt_root().as_raw().as_bytes());
            hasher.update(&c.tx_count().to_le_bytes());
            for i in c.signers().set_indices() {
                hasher.update(&(i as u64).to_le_bytes());
            }
            hasher.update(c.aggregated_signature().as_bytes());
        }
        Self {
            shard_group,
            certificates_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockHash, BlockHeight, ConsensusSignature, ValidatorId};

    fn vote(validator: u64, anchor_ms: u64, tick_height: u64, sig: u8) -> ExecutionVote {
        ExecutionVote::new(
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(10),
            WeightedTimestamp::from_millis(anchor_ms),
            TickId::new(ShardId::ROOT, BlockHeight::new(tick_height)),
            ShardId::ROOT,
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
            5,
            vec![],
            ValidatorId::new(validator),
            ConsensusSignature::new([sig; 96]),
        )
    }

    /// Every vote in these batches carries the same `global_receipt_root`, so
    /// a digest over roots alone cannot tell them apart. The sender's message
    /// must, or a holder of one valid envelope could reattribute its votes to
    /// other validators, ticks and anchors and still clear the relay gate.
    #[test]
    fn the_sender_message_separates_votes_sharing_a_receipt_root() {
        let base = ExecutionVotesSenderMessage::new(ShardId::ROOT, [&vote(1, 11, 0, 0xAA)]);

        for (label, other) in [
            ("reattributed to another validator", vote(2, 11, 0, 0xAA)),
            ("moved to another anchor", vote(1, 12, 0, 0xAA)),
            ("moved to another tick", vote(1, 11, 1, 0xAA)),
            ("given another signature", vote(1, 11, 0, 0xBB)),
        ] {
            assert_ne!(
                base,
                ExecutionVotesSenderMessage::new(ShardId::ROOT, [&other]),
                "a vote {label} produced the same sender message",
            );
        }
    }

    /// Order is part of what the sender stands behind: the digest is a running
    /// hash, so a reordered batch is a different batch.
    #[test]
    fn the_sender_message_is_order_sensitive() {
        let (a, b) = (vote(1, 11, 0, 0xAA), vote(2, 11, 0, 0xBB));
        assert_ne!(
            ExecutionVotesSenderMessage::new(ShardId::ROOT, [&a, &b]),
            ExecutionVotesSenderMessage::new(ShardId::ROOT, [&b, &a]),
        );
    }
}
