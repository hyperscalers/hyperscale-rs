//! Shard vote-equivocation detection, end to end on the coordinator.
//!
//! One validator signs two votes for different blocks at a single
//! `(height, round)` — the self-proving hostility the safe-vote lock
//! guarantees an honest key never commits. The replica that receives the
//! pair assembles [`ShardVoteEquivocation`] evidence and hands it to its
//! host exactly once, as a `ShardVoteEquivocationDetected` continuation —
//! the host buffers the pair for the beacon and gossips it globally, so
//! the evidence reaches conviction however the committee churns. The
//! beacon half (admission, fold, conviction) is asserted in the beacon
//! crate; the pair emitted here is exactly the payload those tests apply.
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
    BlockHeight, NetworkDefinition, ValidatorId, verify_shard_vote_equivocation,
};

/// A shard double-vote flows detection → a single host-bound emission:
/// the two conflicting votes assemble self-proving evidence, the
/// detecting replica emits it exactly once (later sightings of the same
/// key are deduped), and the pair verifies under the double-signer's
/// registered key — ready for the beacon's admission gate.
#[test]
fn double_vote_emits_one_verifiable_detection() {
    let mut sim = ShardCoordinatorSim::new(4, 0xE9_1D);

    // Height 1 (round 1) proposer is idx 1. The aggregator that will detect
    // the double-vote is idx 0. The double-signer is idx 2, a plain voter.
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
    // The first records; the second detects the conflict and emits the
    // evidence to the host.
    let vote_a = sim.sign_block_vote(equivocator, block_a.hash(), parent, height, round);
    let vote_b = sim.sign_block_vote(equivocator, block_b.hash(), parent, height, round);
    sim.feed_qc_result_no_quorum(aggregator, block_a.hash(), vote_a);
    assert!(
        sim.detected_vote_equivocations.is_empty(),
        "one vote is not yet an equivocation",
    );
    sim.feed_qc_result_no_quorum(aggregator, block_b.hash(), vote_b.clone());
    assert_eq!(
        sim.coordinators[0].pending_equivocation_count(),
        1,
        "the conflicting sibling vote must assemble evidence",
    );

    // Replaying the same conflicting vote is not a second detection: the
    // emission is once per key.
    sim.feed_qc_result_no_quorum(aggregator, block_b.hash(), vote_b);
    let [(emitter, ev)] = sim.detected_vote_equivocations.as_slice() else {
        panic!(
            "expected exactly one detection, got {}",
            sim.detected_vote_equivocations.len()
        );
    };
    assert_eq!(*emitter, 0, "the aggregator is the detector");
    assert_eq!(ev.validator, equivocator);
    assert_eq!(ev.shard, sim.shard);
    assert_eq!(ev.height, height);
    assert_eq!(ev.round, round);
    assert_eq!(ev.block_hash_a, block_a.hash());
    assert_eq!(ev.block_hash_b, block_b.hash());

    // The emitted pair carries two genuine conflicting signatures under the
    // double-signer's key — exactly what the beacon's admission gate and
    // fold re-verify before convicting.
    let pubkey = sim
        .topology_schedule
        .head()
        .public_key(equivocator)
        .expect("equivocator is a committee member");
    assert_eq!(
        verify_shard_vote_equivocation(ev, &NetworkDefinition::simulator(), &pubkey),
        Ok(()),
        "the emitted evidence must verify against the double-signer's key",
    );
}
