//! Two-chain commit + QC-chaining invariants pinned by the shard
//! sim.

mod common;

use common::ShardCoordinatorSim;

const MAX_STEPS: usize = 5_000;

/// Two-chain commit: a block at height `H` commits only when QC
/// for `H+1` is observed. A one-chain regression would push
/// `committed_height == latest_qc.height()` on the same step a QC
/// forms; step-by-step we assert `committed < latest_qc.height()`
/// so the moment of regression would be caught.
///
/// The assertion holds because QC adoption is synchronous in the
/// event handler, but commit firing happens on a subsequent step
/// via the `Continuation(BlockReadyToCommit)` loopback.
#[test]
fn commit_lags_qc_advancement() {
    let mut sim = ShardCoordinatorSim::new(4, 0xC0_61);
    sim.kick_off();

    let mut steps = 0;
    let mut max_qc_height_seen = 0u64;
    while steps < MAX_STEPS && sim.commits[0].len() < 4 {
        if !sim.step() {
            break;
        }
        steps += 1;

        let latest = sim.coordinators[0]
            .latest_qc()
            .map_or(0, |qc| qc.height().inner());
        let committed = sim.coordinators[0].committed_height().inner();

        if latest > 0 {
            assert!(
                committed < latest,
                "one-chain regression at step {steps}: \
                 committed_height={committed} == latest_qc.height={latest} \
                 (HotStuff-2 commits only when the CHILD QC observes)",
            );
            max_qc_height_seen = max_qc_height_seen.max(latest);
        }
    }

    assert!(
        sim.commits[0].len() >= 4,
        "expected at least 4 commits within step budget; got {}",
        sim.commits[0].len(),
    );
    // Confirm the QC chain rolled forward enough that the
    // invariant had teeth — without it a chain stuck at h=1
    // would pass vacuously.
    assert!(
        max_qc_height_seen >= 4,
        "QC chain didn't roll forward enough; max observed = {max_qc_height_seen}",
    );
}
