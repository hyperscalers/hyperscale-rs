//! Block-sync invariants pinned by the shard sim.

mod common;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{BlockHeight, ValidatorId};

const MAX_STEPS: usize = 10_000;

/// A replica that misses h=1's header but receives everything
/// else hits the missing-parent path on h=2's arrival, emits
/// `StartBlockSync`, then catches up when the missed block is
/// delivered manually via sync apply.
///
/// `drop_for` silences ALL inbound, which would make the lagging
/// replica's leader rotations no-op and wedge the chain (idx 3 is
/// the h=3 leader, so a silenced idx 3 can't propose h=3 and
/// nobody else can either). Holding only h=1's header keeps every
/// other envelope flowing; h=2's `parent_qc` then references the
/// missing h=1 and `absorb_parent_qc_from_header` emits
/// `StartBlockSync(h=1)`.
///
/// Under this fault only the aggregators that collect quorum on
/// h=2 commit h=1: `vote_recipients` for h=2 voters routes mostly
/// to idx 2 and the next-height leaders, so idx 0 and idx 2 hit
/// quorum locally and commit; idx 1's `vote_set` comes up one
/// short. Targeting `[0, 2]` is what's reachable.
#[test]
fn silenced_replica_triggers_sync_and_catches_up_via_apply() {
    let mut sim = ShardCoordinatorSim::new(4, 0x5C_DC);
    let lagging = ValidatorId::new(3);

    sim.hold_matching(
        lagging,
        HoldFilter::BlockHeaderAtHeight(BlockHeight::new(1)),
    );
    sim.kick_off();

    let aggregators: Vec<usize> = vec![0, 2];
    sim.run_until_committed_for(&aggregators, 1, MAX_STEPS);
    assert_eq!(
        sim.commits[3].len(),
        0,
        "lagging replica unexpectedly committed despite held h=1 header",
    );

    assert!(
        !sim.sync_targets[3].is_empty(),
        "replica 3 didn't emit StartBlockSync on missing-parent path",
    );
    let sync_target = *sim.sync_targets[3]
        .iter()
        .max()
        .expect("at least one sync target captured");
    assert!(
        sim.coordinators[3].is_block_syncing(),
        "replica 3 should be in sync mode after emitting StartBlockSync",
    );
    assert!(
        sync_target.inner() >= 1,
        "sync target {sync_target:?} must reference at least h=1",
    );

    // Feed each honest commit's `CertifiedBlock` into the lagging
    // replica's sync apply path. Each runs through the normal
    // verification + commit machinery — the sync entry attests QC
    // trust via `from_qc_attestation` instead of re-running
    // per-root verifications.
    let honest_chain: Vec<_> = sim.commits[0]
        .iter()
        .map(|c| (**c.certified).clone())
        .collect();
    for certified in &honest_chain {
        sim.deliver_synced_block(lagging, certified);
        sim.run_for_at_most(500);
    }

    // `BlockPersisted` at the sync target triggers
    // `on_block_sync_complete` and flips the lagging replica out
    // of sync mode.
    sim.deliver_block_persisted(lagging, sync_target);

    assert!(
        !sim.coordinators[3].is_block_syncing(),
        "replica 3 still in sync mode after BlockPersisted at target",
    );
    assert!(
        sim.coordinators[3].committed_height() >= sync_target,
        "replica 3 didn't catch up: committed={:?} target={:?}",
        sim.coordinators[3].committed_height(),
        sync_target,
    );

    // Every sync-applied height matches the honest reference
    // chain byte-for-byte.
    for h in 0..sim.commits[3].len().min(sim.commits[0].len()) {
        assert_eq!(
            sim.commits[3][h].block_hash, sim.commits[0][h].block_hash,
            "replica 3 diverged from replica 0 at sync-applied height {h}",
        );
        assert_eq!(
            sim.commits[3][h].state_root, sim.commits[0][h].state_root,
            "replica 3 diverged on state root at sync-applied height {h}",
        );
    }
}

/// Tripwire on the sim's capture machinery: a fresh coordinator
/// has no `StartBlockSync` targets recorded.
#[test]
fn fresh_sim_has_no_sync_targets_captured() {
    let sim = ShardCoordinatorSim::new(4, 0xCA_FE);
    for idx in 0..sim.n() {
        assert!(
            sim.sync_targets[idx].is_empty(),
            "replica {idx} reported a sync target before any deafening: {:?}",
            sim.sync_targets[idx],
        );
    }
    let _ = BlockHeight::new(0);
}
