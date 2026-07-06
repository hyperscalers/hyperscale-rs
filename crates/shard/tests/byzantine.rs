//! Byzantine + vote-locking invariants pinned by the shard sim.

mod common;

use common::{ByzantineBehaviour, ShardCoordinatorSim};
use hyperscale_types::{BlockHeight, Round, VIEW_CHANGE_TIMEOUT, ValidatorId};

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

/// A proposer slower than the network but still under the round timeout
/// costs nothing: its headers land late but before any receiver fires, so
/// every slot it leads still commits and no view change accrues.
///
/// Idx 1 leads round 1 (and every fourth round after). Holding each of its
/// headers for a second — well under the 3-second round timeout — delays
/// delivery without ever letting a receiver time out. The paced driver
/// advances the clock only when the queues stall, so the held header always
/// releases before the timeout it would otherwise trip.
#[test]
fn sub_timeout_slow_proposer_commits_without_view_change() {
    const TARGET: usize = 5;

    let mut sim = ShardCoordinatorSim::new(4, 0x51_04);
    let slow = ValidatorId::new(1);
    sim.with_byzantine(
        slow,
        ByzantineBehaviour::DelayProposal {
            delay: VIEW_CHANGE_TIMEOUT / 3,
        },
    );
    sim.kick_off();
    let all: Vec<usize> = (0..sim.n()).collect();
    sim.run_until_committed_paced(&all, TARGET, 400);

    assert!(
        sim.byzantine_fires[1] >= 1,
        "the slow proposer's delay transform never fired",
    );
    for idx in 0..sim.n() {
        assert_eq!(
            sim.coordinators[idx].stats().view_changes,
            0,
            "replica {idx} view-changed under a sub-timeout slow proposer",
        );
    }

    // The slow proposer's own slots still commit: its header arrives late
    // but in time to be voted, so a block it proposed reaches the chain.
    let slow_authored = sim.commits[0]
        .iter()
        .any(|c| c.certified.block().header().proposer() == slow);
    assert!(
        slow_authored,
        "no block the slow proposer authored committed — its slot was lost \
         despite sub-timeout slowness",
    );

    assert_no_fork(&sim, TARGET);
}

/// A proposer slower than the round timeout is rotated past: receivers fire
/// before its header lands, advance the round on the timeout quorum, and the
/// late header — now for an abandoned round — is never voted. Each slot the
/// slow proposer leads costs exactly one view change; the other three carry
/// the chain, and no height forks.
#[test]
fn super_timeout_slow_proposer_is_rotated_past() {
    const TARGET: usize = 5;

    let mut sim = ShardCoordinatorSim::new(4, 0x51_08);
    let slow = ValidatorId::new(1);
    sim.with_byzantine(
        slow,
        ByzantineBehaviour::DelayProposal {
            delay: VIEW_CHANGE_TIMEOUT * 2,
        },
    );
    sim.kick_off();
    let all: Vec<usize> = (0..sim.n()).collect();
    sim.run_until_committed_paced(&all, TARGET, 400);

    assert!(
        sim.byzantine_fires[1] >= 1,
        "the slow proposer's delay transform never fired",
    );

    // No block the slow proposer authored ever commits: every one of its
    // headers lands after its round has already been abandoned.
    for idx in 0..sim.n() {
        assert!(
            sim.commits[idx]
                .iter()
                .all(|c| c.certified.block().header().proposer() != slow),
            "replica {idx} committed a block the rotated-past proposer authored",
        );
    }

    // Every replica pays the same view-change toll, and it is bounded by the
    // slow proposer's own rotation slots — at most one per slot it leads,
    // never a storm.
    let vc0 = sim.coordinators[0].stats().view_changes;
    assert!(
        vc0 >= 1,
        "a super-timeout slow proposer must cost view changes"
    );
    for idx in 1..sim.n() {
        assert_eq!(
            sim.coordinators[idx].stats().view_changes,
            vc0,
            "replica {idx} view-change count diverged from replica 0",
        );
    }
    let max_view = sim.views().into_iter().max().expect("non-empty committee");
    let slow_slots =
        u64::try_from(sim.rounds_led_by(slow, max_view)).expect("rotation-slot count fits u64");
    assert!(
        vc0 <= slow_slots,
        "view changes ({vc0}) exceeded the slow proposer's {slow_slots} rotation \
         slots through round {max_view:?} — degradation was not bounded to its \
         own slots",
    );

    assert_no_fork(&sim, TARGET);
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

/// A proposer that ignores the freshest certificate and extends an older
/// ancestor cannot orphan its predecessor's certified block. The stale
/// proposal fails the safe-vote rule (its parent QC sits below the honest
/// lock), so honest replicas run it through verification but never vote it;
/// the round times out, the next leader adopts the quorum-max high QC, and
/// the block the adversary tried to orphan commits as the prefix of a later
/// two-chain — the non-contiguous commit path (rounds skipped by the
/// timeout leave a gap between a committed block and its justifying QC).
#[test]
fn stale_parent_proposal_cannot_orphan_certified_block() {
    const TARGET: usize = 6;

    let mut sim = ShardCoordinatorSim::new(4, 0x57_A1);
    // Idx 1 leads round 1 (shallow — it proposes normally there) and round
    // 5, by which point the chain is deep enough to re-parent below the
    // honest lock. Arming the transform up front lets it fire on that first
    // deep slot.
    let adversary = ValidatorId::new(1);
    sim.with_byzantine(adversary, ByzantineBehaviour::ExtendStaleParent);
    sim.kick_off();
    let all: Vec<usize> = (0..sim.n()).collect();
    sim.run_until_committed_paced(&all, TARGET, 200);

    assert!(
        sim.byzantine_fires[1] >= 1,
        "the stale-parent transform never fired — the chain never reached a \
         deep enough slot on the adversary's rotation",
    );

    // INV-SHARD-1: one committed block per height, identical roots — the
    // stale sibling never displaced the certified block at its height.
    assert_no_fork(&sim, TARGET);

    // The stale slot could not certify, so its round timed out: every
    // replica records a view change.
    for idx in 0..sim.n() {
        assert!(
            sim.coordinators[idx].stats().view_changes >= 1,
            "replica {idx} never view-changed — the stale proposal was not \
             rotated past",
        );
    }

    // INV-SHARD-4: the recovery leader adopts the quorum-max high QC and
    // extends it across the abandoned round, so a committed block is
    // justified by a QC more than one round below its own — the
    // non-contiguous prefix-commit path the stale proposal forces.
    let non_contiguous = sim.commits[0].iter().any(|c| {
        let header = c.certified.block().header();
        header.round().inner() > header.parent_qc().round().inner() + 1
    });
    assert!(
        non_contiguous,
        "no committed block was justified by a QC more than one round below \
         its own — the non-contiguous commit path was not exercised",
    );
}

/// Every replica committed the same block at each height up through `target`
/// — no fork survived and each height holds exactly one block.
fn assert_no_fork(sim: &ShardCoordinatorSim, target: usize) {
    for h in 0..target {
        let reference = &sim.commits[0][h];
        for r in 1..sim.n() {
            let cmp = &sim.commits[r][h];
            assert_eq!(
                cmp.height, reference.height,
                "replica {r} committed a different height at commit index {h}",
            );
            assert_eq!(
                cmp.block_hash, reference.block_hash,
                "replica {r} forked from replica 0 at height {:?}",
                reference.height,
            );
            assert_eq!(
                cmp.state_root, reference.state_root,
                "replica {r} diverged on state root at height {:?}",
                reference.height,
            );
        }
    }
}
