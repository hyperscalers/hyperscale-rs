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

/// The own-vote lock keeps each honest replica from voting on
/// more than one block at the same `(height, round)`, even when
/// an equivocating proposer's second header is admitted into
/// `pending_blocks` and runs through verification.
///
/// `maybe_unlock_for_qc` clears the h=1 lock the moment a QC at
/// height ≥ 1 is adopted. To keep the lock observable, deafen idx 2
/// and idx 3 so only the observer (idx 0) and the h=1 leader (idx 1)
/// stay active — two votes can't reach the 3-vote quorum, so no
/// QC{h=1} ever forms to clear the observer's lock.
#[test]
fn own_vote_lock_rejects_equivocating_second_block() {
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

    let voted = sim.coordinators[0].voted_heights();
    let h1_entries: Vec<_> = voted
        .iter()
        .filter(|(h, _)| **h == BlockHeight::new(1))
        .collect();
    assert_eq!(
        h1_entries.len(),
        1,
        "idx 0 recorded {} vote-lock entries at h=1 (expected exactly 1 despite equivocating pair)",
        h1_entries.len(),
    );
    let (_, (_, round)) = h1_entries[0];
    assert_eq!(
        *round,
        Round::new(1),
        "idx 0 voted at h=1 in round {} (expected round 1)",
        round.inner(),
    );
}

/// Unlock-for-QC keeps `voted_heights` bounded over a
/// multi-commit chain. Each adopted QC at height `H` clears every
/// vote lock at heights ≤ `H` via `maybe_unlock_for_qc`, so the
/// committed prefix never appears in the live lock set.
#[test]
fn commit_clears_lower_height_vote_locks() {
    let mut sim = ShardCoordinatorSim::new(4, 0x10_60);
    sim.kick_off();
    sim.run_until_committed(4, MAX_STEPS);

    for replica in 0..sim.n() {
        let committed_height = sim.coordinators[replica].committed_height();
        let voted = sim.coordinators[replica].voted_heights();
        for h in voted.keys() {
            assert!(
                *h > committed_height,
                "replica {replica}: stale vote lock at {h:?} ≤ committed_height {committed_height:?} \
                 — unlock-for-QC must have fired",
            );
        }
        // Confirm the chain actually progressed so the assertion
        // had bite.
        assert!(
            committed_height >= BlockHeight::new(4),
            "replica {replica} committed_height {committed_height:?} below test target",
        );
    }
}
