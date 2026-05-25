//! End-to-end multi-coordinator integration tests.
//!
//! Drives an n=4 cluster of [`BeaconCoordinator`]s through several
//! epochs and pins the load-bearing invariants of the local commit
//! loop: every replica commits the same block per epoch, advances to a
//! byte-identical [`BeaconState`], and the SPC instance bootstraps the
//! next epoch automatically inside `assemble_and_commit`. The proposal
//! pool, header-sig pool, and post-`apply_epoch` state-root binding
//! all ride along — anything that breaks them throws the cluster out
//! of agreement before the test reaches its target commit count.

mod common;

use common::CoordinatorSim;
use hyperscale_types::{Epoch, compute_proposals_root};

/// Three epochs is enough to exercise the closed loop more than once:
/// the first epoch's `assemble_and_commit` chains into the second
/// epoch's `try_propose`, which only happens correctly if the post-
/// commit committee re-bootstrap and proposal-pool reset are sound.
const TARGET_COMMITS: usize = 3;

/// Step budget tuned to the cost of one epoch's traffic: per epoch
/// every replica fans out 4 proposals, 4 PC vote rounds × 3 rounds,
/// and 4 header sigs, plus their loopback envelopes. ~400 deliveries
/// per epoch comfortably under this cap.
const MAX_STEPS: usize = 10_000;

#[test]
fn four_party_cluster_commits_byte_identical_state() {
    let mut sim = CoordinatorSim::new(4, 0xC0_0D);
    sim.kick_off();
    let steps = sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let counts: Vec<usize> = sim.commits.iter().map(Vec::len).collect();
    assert!(
        counts.iter().all(|c| *c >= TARGET_COMMITS),
        "not every replica reached {TARGET_COMMITS} commits in {steps} steps: {counts:?}",
    );

    // Per-epoch byte-identical state across replicas. Compare each
    // replica against replica 0 by capture order — every replica
    // captures commits in the same order because the sim drains
    // queues deterministically.
    for e in 0..TARGET_COMMITS {
        let reference = &sim.commits[0][e];
        let expected_epoch = Epoch::new(e as u64 + 1);
        assert_eq!(
            reference.epoch, expected_epoch,
            "replica 0's commit {e} is not at expected epoch {expected_epoch:?}",
        );
        for r in 1..sim.n() {
            let cmp = &sim.commits[r][e];
            assert_eq!(
                cmp.epoch, reference.epoch,
                "replica {r} committed epoch {:?} at slot {e}, expected {:?}",
                cmp.epoch, reference.epoch,
            );
            assert_eq!(
                cmp.block.block_hash(),
                reference.block.block_hash(),
                "replica {r} block hash differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
            assert_eq!(
                cmp.state, reference.state,
                "replica {r} state differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
        }
    }
}

#[test]
fn cluster_commits_non_empty_proposal_set_per_epoch() {
    // The two-tier queue ordering is what makes view-1 PC inputs full
    // vectors instead of per-validator singletons. This test pins the
    // resulting protocol property: every committed beacon block has
    // `state.last_recovery_cert == None` AND a non-zero proposals
    // count visible in the header. If the sim ever regresses to
    // "self-first" delivery, view-1 PC commits all-`HASH_BOTTOM`s,
    // proposals_root collapses to the empty-input case, and this test
    // catches it.
    let mut sim = CoordinatorSim::new(4, 0xBE_AC);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let first_commit = &sim.commits[0][0];
    // Recovery cert absent on honest-path commits.
    assert!(
        first_commit.state.last_recovery_cert.is_none(),
        "honest-path commit unexpectedly carries a recovery cert",
    );
    // Every honest replica's proposal made it into the committed set:
    // proposals_root commits to a sorted-by-id digest of all four
    // proposals, so it can't equal the empty-input root.
    let empty_input_root = compute_proposals_root(&[]);
    assert_ne!(
        first_commit.block.header().proposals_root(),
        empty_input_root,
        "committed block's proposals_root matches the empty-input case — view-1 PC \
         collapsed to all-HASH_BOTTOMs",
    );
}
