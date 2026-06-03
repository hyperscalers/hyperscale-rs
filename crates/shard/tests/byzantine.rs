//! Byzantine + vote-locking invariants pinned by the shard sim.

mod common;

use common::{ByzantineBehaviour, ShardCoordinatorSim};
use hyperscale_types::{BlockHeight, Round, ValidatorId};

const MAX_STEPS: usize = 5_000;

/// An equivocating proposer (single Byzantine, the `f = 1`
/// threshold for `n = 4`) cannot split consensus. The two headers
/// share parent / QC / roots and differ only in `+1ms` of
/// `timestamp`, so honest receivers admit both into
/// `pending_blocks`, vote on whichever arrives first, and converge
/// on a single committed block by quorum intersection.
#[test]
fn equivocating_proposer_does_not_split_consensus() {
    let mut sim = ShardCoordinatorSim::new(4, 0xE9_01);
    let leader = ValidatorId::new(1); // proposer_for(1) = idx 1 (height 1, round 1)
    sim.with_byzantine(leader, ByzantineBehaviour::EquivocateProposal);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    assert_eq!(
        sim.byzantine_fires[1], 1,
        "equivocating proposer didn't fire its one-shot transform",
    );
    for other in (0..sim.n()).filter(|i| *i != 1) {
        assert_eq!(
            sim.byzantine_fires[other], 0,
            "byzantine_fires leaked to non-flagged replica {other}",
        );
    }

    let reference = &sim.commits[0][0];
    assert_eq!(reference.height, BlockHeight::new(1));
    for r in 1..sim.n() {
        let cmp = &sim.commits[r][0];
        assert_eq!(
            cmp.block_hash, reference.block_hash,
            "replica {r} diverged from replica 0 under proposer equivocation",
        );
        assert_eq!(
            cmp.state_root, reference.state_root,
            "replica {r} diverged on state root under proposer equivocation",
        );
    }
}

/// The HotStuff-2 one-vote-per-round rule (`last_voted_round`) keeps each
/// honest replica from voting on more than one block in a round, even when
/// an equivocating proposer's second header is admitted into
/// `pending_blocks` and runs through verification.
///
/// Deafen idx 2 and idx 3 so only the observer (idx 0) and the h=1 leader
/// (idx 1) stay active — two votes can't reach the 3-vote quorum, so no
/// QC{h=1} ever forms and the observer stays parked at round 1.
#[test]
fn safe_vote_rejects_equivocating_second_block() {
    let mut sim = ShardCoordinatorSim::new(4, 0xE9_15);
    let leader = ValidatorId::new(1); // proposer_for(1) = idx 1 (height 1, round 1)
    sim.drop_for(ValidatorId::new(2), 100_000);
    sim.drop_for(ValidatorId::new(3), 100_000);
    sim.with_byzantine(leader, ByzantineBehaviour::EquivocateProposal);
    sim.kick_off();
    sim.run_for_at_most(MAX_STEPS);

    assert_eq!(
        sim.byzantine_fires[1], 1,
        "equivocating proposer must have fired exactly once",
    );
    assert!(
        sim.commits[0].is_empty(),
        "idx 0 unexpectedly committed despite sub-quorum starvation",
    );

    // The observer voted once, at round 1: `last_voted_round` advanced to 1
    // on the first vote, so the equivocating sibling (also round 1) failed the
    // `round > last_voted_round` clause and was never signed.
    assert_eq!(
        sim.coordinators[0].last_voted_round(),
        Round::new(1),
        "idx 0 should have voted exactly once, at round 1",
    );
}
