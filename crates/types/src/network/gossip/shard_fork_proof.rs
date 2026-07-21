//! `ShardForkProof` gossip message for broadcasting committee-fork evidence.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, ShardForkProof, ShardId};

/// Gossips a shard fork proof globally.
///
/// A [`ShardForkProof`] is self-authenticating — it carries the accused
/// committee's own QCs — so the message needs no sender signature: every
/// recipient re-verifies the proof against its local topology and fences
/// uniformly, trusting the evidence rather than the messenger. Broadcast
/// on first local verification (assembly or a verified gossip receipt) so
/// the whole network converges on the fence.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardForkProofGossip {
    /// The self-proving fork evidence.
    pub proof: Arc<ShardForkProof>,
}

impl NetworkMessage for ShardForkProofGossip {
    fn message_type_id() -> &'static str {
        "shard.fork_proof"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for ShardForkProofGossip {
    const SCOPE: TopicScope = TopicScope::Global;

    fn source_shard(&self) -> Option<ShardId> {
        Some(self.proof.shard())
    }

    fn dedup_key(&self) -> Option<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // One fence per forked `(shard, height)`, so every node's copy of a
        // proof for the same fork collapses to a single key regardless of
        // which conflicting blocks each proof happens to carry.
        let mut hasher = DefaultHasher::new();
        self.proof.shard().hash(&mut hasher);
        self.proof.height().hash(&mut hasher);
        Some(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::test_utils::TestCommittee;
    use crate::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
        Bls12381G2Signature, CertificateRoot, CertifiedBlockHeader, ChainOrigin, CommitProof, Hash,
        InFlightCount, LocalReceiptRoot, NetworkDefinition, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, SignerBitfield, StateRoot, TransactionRoot, ValidatorId,
        WeightedTimestamp, block_vote_message,
    };

    fn certify(
        committee: &TestCommittee,
        height: u64,
        round: u64,
        parent: BlockHash,
        salt: u64,
    ) -> CertifiedBlockHeader {
        let net = NetworkDefinition::simulator();
        let shard = ShardId::ROOT;
        let h = BlockHeight::new(height);
        let header = BlockHeader::new(
            shard,
            h,
            parent,
            QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(salt),
            Round::new(round),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block_hash = header.hash();
        let msg = block_vote_message(&net, shard, h, Round::new(round), &block_hash, &parent);
        let quorum = committee.quorum_indices();
        let sigs: Vec<_> = quorum
            .iter()
            .map(|&i| committee.keypair(i).sign_v1(&msg))
            .collect();
        let agg = Bls12381G2Signature::aggregate(&sigs, true).unwrap();
        let mut signers = SignerBitfield::new(committee.size());
        for &i in &quorum {
            signers.set(i);
        }
        let qc = QuorumCertificate::new(
            block_hash,
            shard,
            h,
            parent,
            Round::new(round),
            signers,
            agg,
            WeightedTimestamp::from_millis(height * 1_000),
        );
        CertifiedBlockHeader::new(header, qc)
    }

    fn sample_proof() -> ShardForkProof {
        let committee = TestCommittee::new(4, 1);
        let parent = BlockHash::from_raw(Hash::from_bytes(b"p"));
        let a_block = certify(&committee, 5, 5, parent, 1);
        let a_child = certify(&committee, 6, 6, a_block.block_hash(), 2);
        let b_block = certify(&committee, 5, 7, parent, 3);
        let b_child = certify(&committee, 6, 8, b_block.block_hash(), 4);
        ShardForkProof::ConflictingCommits {
            a: CommitProof::direct(a_block, a_child),
            b: CommitProof::direct(b_block, b_child),
        }
    }

    #[test]
    fn message_type_id_is_stable() {
        assert_eq!(ShardForkProofGossip::message_type_id(), "shard.fork_proof");
    }

    #[test]
    fn sbor_round_trip() {
        let gossip = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        let bytes = basic_encode(&gossip).unwrap();
        let decoded: ShardForkProofGossip = basic_decode(&bytes).unwrap();
        assert_eq!(gossip, decoded);
    }

    #[test]
    fn dedup_key_folds_the_same_fork() {
        let g1 = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        let g2 = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        assert_eq!(g1.dedup_key(), g2.dedup_key());
        assert_eq!(g1.source_shard(), Some(ShardId::ROOT));
    }
}
