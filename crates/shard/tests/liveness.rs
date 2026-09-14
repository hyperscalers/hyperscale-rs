//! Honest-path liveness invariants pinned by the multi-coordinator
//! shard sim.

use std::time::Duration;

mod common;

use common::ShardCoordinatorSim;

/// Enough commits to roll through multiple two-chain cycles and
/// exercise the closed loop more than once.
const TARGET_COMMITS: usize = 3;

/// Step budget tuned to per-commit cost: build → broadcast (n-1
/// peers) → assemble (n replicas) → 8 root verifications × n →
/// vote → QC build → emit. Roughly 80-120 deliveries per commit;
/// budget is well above for headroom.
const MAX_STEPS: usize = 5_000;

/// Every replica converges per-height on a byte-identical
/// `committed_state_root` and committed block hash. The
/// load-bearing honest-path invariant.
#[test]
fn four_party_cluster_converges_per_height() {
    let mut sim = ShardCoordinatorSim::new(4, 0xC0_0D);
    sim.kick_off();
    let steps = sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let counts: Vec<usize> = sim.commits.iter().map(Vec::len).collect();
    assert!(
        counts.iter().all(|c| *c >= TARGET_COMMITS),
        "not every replica reached {TARGET_COMMITS} commits in {steps} steps: {counts:?}",
    );

    for h in 0..TARGET_COMMITS {
        let reference = &sim.commits[0][h];
        // Rounds increase per block: with no view change, the block at height
        // H is proposed in round H (genesis is round 0).
        assert_eq!(
            reference.certified.block().header().round().inner(),
            reference.height.inner(),
            "height {:?} committed at round {} (expected per-block round == height)",
            reference.height,
            reference.certified.block().header().round().inner(),
        );
        for (r, commits) in sim.commits.iter().enumerate().skip(1) {
            let cmp = &commits[h];
            assert_eq!(
                cmp.height, reference.height,
                "replica {r} committed at height {:?} at slot {h}, expected {:?}",
                cmp.height, reference.height,
            );
            assert_eq!(
                cmp.block_hash, reference.block_hash,
                "replica {r} block hash diverged from replica 0 at slot {h}",
            );
            assert_eq!(
                cmp.state_root, reference.state_root,
                "replica {r} state root diverged from replica 0 at slot {h}",
            );
        }
    }
}

/// Same seed → byte-identical commit chains across two sim
/// instances. Cheap canary for ordering regressions in shard
/// internals.
#[test]
fn determinism_seeded_reruns_byte_identical() {
    let seed = 0xDE_7E;

    let mut sim_a = ShardCoordinatorSim::new(4, seed);
    sim_a.kick_off();
    sim_a.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let mut sim_b = ShardCoordinatorSim::new(4, seed);
    sim_b.kick_off();
    sim_b.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    for r in 0..sim_a.n() {
        let a = &sim_a.commits[r];
        let b = &sim_b.commits[r];
        assert_eq!(
            a.len(),
            b.len(),
            "replica {r} commit count differs across runs: {} vs {}",
            a.len(),
            b.len(),
        );
        for (h, (ca, cb)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(
                ca.block_hash, cb.block_hash,
                "replica {r} block hash differs at height index {h}",
            );
            assert_eq!(
                ca.state_root, cb.state_root,
                "replica {r} state root differs at height index {h}",
            );
        }
    }
}

/// Verification pipelines stay bounded across many commits.
///
/// The chain auto-proposes on every commit, so the QC and
/// state-root pipelines are never empty at steady state — ≈1
/// verification per non-proposer is in flight for the pipelined
/// next block. A leaked slot would push the cumulative depth past
/// the per-replica ceiling, which this pin would catch.
#[test]
fn verification_pipelines_stay_bounded_across_many_commits() {
    let mut sim = ShardCoordinatorSim::new(4, 0xD_A100);
    sim.kick_off();
    sim.run_until_committed(8, MAX_STEPS * 3);
    let pending = sim.total_pending_verifications();
    // `n * 8` covers worst-case steady-state depth (3 non-proposers
    // × 1 in-flight header × 2 verifiers × margin) without being so
    // loose that a real leak would slip past.
    let bound = sim.n() * 8;
    assert!(
        pending <= bound,
        "verification pipelines drift unboundedly: pending={pending} > bound={bound}",
    );
}

/// A committee lookup that crosses epoch windows must not cost the shard
/// throughput.
///
/// The default sim runs on [`TopologySchedule::single`], whose zero-length
/// windows fold every weighted timestamp to genesis — so a committee lookup
/// there always answers, and always with the one snapshot. That makes it blind
/// to every way epoch resolution can behave: landing in a different window,
/// and failing to resolve at all. A regression that only appears once windows
/// are real is invisible to the rest of this suite, and has to be chased
/// through a ten-minute seeded run instead.
///
/// The committee is the same in every window here, so the epochs change
/// nothing a correct implementation can observe: the gridded run must reach
/// the same commits in comparable time as the flat one.
#[test]
fn crossing_epoch_windows_costs_no_throughput() {
    const EPOCH_MS: u64 = 20;
    const EPOCHS: u64 = 512;
    /// Sim time each delivery costs, so the run's weighted timestamps sweep
    /// across windows rather than sitting at genesis.
    const CLOCK_STEP: Duration = Duration::from_millis(2);
    const SEED: u64 = 0xE9_0C;
    const TARGET: usize = 6;
    const MAX_TICKS: usize = 400;

    let all: Vec<usize> = (0..4).collect();

    let mut flat = ShardCoordinatorSim::new(4, SEED);
    flat.kick_off();
    let flat_ticks = flat.run_until_committed_paced(&all, TARGET, MAX_TICKS);

    let mut grid = ShardCoordinatorSim::with_epoch_grid(4, SEED, EPOCH_MS, EPOCHS, CLOCK_STEP);
    grid.kick_off();
    let grid_ticks = grid.run_until_committed_paced(&all, TARGET, MAX_TICKS);

    // A grid the run never crosses proves nothing, so pin that it did.
    let epochs: std::collections::BTreeSet<u64> = grid.commits[0]
        .iter()
        .map(|c| {
            c.certified
                .block()
                .header()
                .parent_qc()
                .weighted_timestamp()
                .as_millis()
                / EPOCH_MS
        })
        .collect();
    assert!(
        epochs.len() > 1,
        "the run stayed inside one {EPOCH_MS} ms window ({epochs:?}), so the grid was never \
         exercised — shorten the window or lengthen the run",
    );

    assert!(
        grid_ticks <= flat_ticks.saturating_mul(2).max(4),
        "an epoch grid cost the shard its throughput: {TARGET} commits took {grid_ticks} ticks \
         across {EPOCH_MS} ms windows against {flat_ticks} on a single-window schedule, with the \
         same committee governing every window",
    );
}
