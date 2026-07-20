//! Shard vote-equivocation prosecution, end to end on the coordinator.
//!
//! One validator signs two votes for different blocks at a single
//! `(height, round)` — the self-proving hostility the safe-vote lock
//! guarantees an honest key never commits. A proposer that receives the
//! pair assembles [`ShardVoteEquivocation`] evidence, carries it in its next
//! block, and every voter re-verifies the two signatures as a block-validity
//! condition before the QC forms. The committed block's beacon-witness root
//! therefore carries a QC-attested `VoteEquivocation` leaf naming the
//! double-signer — the leaf the beacon fold jails on permanently.
//!
//! This drives the shard half on the real [`ShardCoordinator`]: detection,
//! the drain into a proposal, and the committed witness leaf. The beacon
//! fold that consumes the leaf and revokes the key is asserted in the beacon
//! crate (`state::witness` fold tests); the leaf produced here is exactly the
//! payload those tests apply.
//!
//! The single-shard sim cannot make a node double-sign through ordinary
//! delivery — the safe-vote lock stops an honest coordinator, and no honest
//! batch ever verifies both siblings — so the two conflicting votes are minted
//! as fixtures and fed through the aggregator's real QC-result path, the same
//! entry a verified-but-sub-quorum vote batch takes in production. The
//! portable fault harness can't drive this either: it drops and partitions
//! messages, it does not forge signatures.

mod common;

use common::{ShardCoordinatorSim, perturb_header_timestamp};
use hyperscale_types::{
    BlockHeight, NetworkDefinition, ShardVoteEquivocation, ShardWitnessPayload, ValidatorId,
    verify_shard_vote_equivocation,
};

const MAX_STEPS: usize = 20_000;

/// The `VoteEquivocation` payload a committed block carried, and the block's
/// height, if any replica committed such a leaf.
fn committed_equivocation_leaf(
    sim: &ShardCoordinatorSim,
    equivocator: ValidatorId,
) -> Option<(BlockHeight, ShardVoteEquivocation)> {
    for replica in 0..sim.n() {
        for commit in &sim.commits[replica] {
            for leaf in &commit.witness_leaves {
                if let ShardWitnessPayload::VoteEquivocation(ev) = leaf
                    && ev.validator == equivocator
                {
                    return Some((commit.height, (**ev).clone()));
                }
            }
        }
    }
    None
}

/// A shard double-vote flows detection → committed block's beacon-witness
/// root: one validator's two conflicting votes are assembled by an honest
/// proposer, carried in its next block, verified as a block-validity
/// condition by the committee, and folded into the committed block's witness
/// leaves as a `VoteEquivocation` naming the double-signer.
#[test]
fn double_vote_lands_verified_equivocation_leaf_on_chain() {
    let mut sim = ShardCoordinatorSim::new(4, 0xE9_1D);

    // Height 1 (round 1) proposer is idx 1. The aggregator that will detect
    // the double-vote is idx 0 — it leads round 4, so it carries the evidence
    // into the block it proposes there. The double-signer is idx 2, a plain
    // voter; jailing it does not disturb the shard sim, which has no beacon.
    let leader = ValidatorId::new(1);
    let aggregator = ValidatorId::new(0);
    let equivocator = ValidatorId::new(2);

    // Let idx 1 build and broadcast its height-1 block without yet driving it
    // to commit, so a real header is on hand to mint a same-height sibling.
    sim.kick_off();
    sim.step();
    let (block_a, manifest) = sim
        .proposed_block_at(BlockHeight::new(1))
        .expect("height-1 leader proposed a block");
    assert_eq!(block_a.proposer(), leader);
    let block_b = perturb_header_timestamp(&block_a);
    assert_ne!(block_a.hash(), block_b.hash());
    assert_eq!(block_a.parent_block_hash(), block_b.parent_block_hash());
    let (height, round) = (block_a.height(), block_a.round());
    let parent = block_a.parent_block_hash();

    // Seat both siblings in the aggregator's pending blocks so the parent-hash
    // lookup that evidence assembly needs resolves for each.
    sim.deliver_header_now(aggregator, &block_a, manifest.clone());
    sim.deliver_header_now(aggregator, &block_b, manifest);

    // Mint the double-signer's two genuine, conflicting votes for the same
    // `(height, round)` and feed them through the aggregator's QC-result path.
    // The first records; the second detects the conflict and assembles the
    // evidence into the aggregator's pending buffer.
    let vote_a = sim.sign_block_vote(equivocator, block_a.hash(), parent, height, round);
    let vote_b = sim.sign_block_vote(equivocator, block_b.hash(), parent, height, round);
    sim.feed_qc_result_no_quorum(aggregator, block_a.hash(), vote_a);
    assert_eq!(
        sim.coordinators[0].pending_equivocation_count(),
        0,
        "one vote is not yet an equivocation",
    );
    sim.feed_qc_result_no_quorum(aggregator, block_b.hash(), vote_b);
    assert_eq!(
        sim.coordinators[0].pending_equivocation_count(),
        1,
        "the conflicting sibling vote must assemble evidence",
    );

    // Drive the chain far enough that the aggregator proposes (round 4) and
    // commits the block carrying the evidence.
    sim.run_until_committed(4, MAX_STEPS);

    let (leaf_height, ev) = committed_equivocation_leaf(&sim, equivocator)
        .expect("a committed block must carry the VoteEquivocation leaf");
    assert!(
        leaf_height > height,
        "the evidence rides a block above the double-voted height",
    );
    assert_eq!(ev.validator, equivocator);
    assert_eq!(ev.shard, sim.shard);
    assert_eq!(ev.height, height);
    assert_eq!(ev.round, round);
    assert_eq!(ev.block_hash_a, block_a.hash());
    assert_eq!(ev.block_hash_b, block_b.hash());

    // The committed leaf carries two genuine conflicting signatures under the
    // double-signer's key — the block-validity soundness the QC attests and
    // the beacon fold trusts without re-verifying.
    let pubkey = sim
        .topology_schedule
        .head()
        .public_key(equivocator)
        .expect("equivocator is a committee member");
    assert_eq!(
        verify_shard_vote_equivocation(&ev, &NetworkDefinition::simulator(), &pubkey),
        Ok(()),
        "the on-chain evidence must verify against the double-signer's key",
    );
}
