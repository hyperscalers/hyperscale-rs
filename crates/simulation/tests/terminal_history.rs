//! A committee member that arrived by snap-sync can still attest its own
//! shard's terminal block.
//!
//! A terminating shard's boundary header carries the settled and
//! committed commitments it leaves its successors, and both are folded
//! from the committed chain — the settled one reaching back to the epoch
//! its reshape was admitted, several epochs below the tip. A member that
//! arrived by snap-sync imports state at a boundary and no block beneath
//! it, so without its own history that fold comes up short and the
//! member declines rather than attest a root taken over a prefix. The
//! terminal-roots bit is set for every block of the terminating epoch,
//! so it would decline all of them: past `f` such members the terminal
//! block reaches no quorum and the reshape cannot complete.
//!
//! The wipe has to land inside the terminating window. A member that
//! arrived before the settled window's floor holds everything the walk
//! asks for, so wiping it earlier exercises nothing — which is what the
//! first version of this test did.
//!
//! Sim-only. The wipe primitive discards a replica's store and seats it
//! again through snap-sync, which production reaches by losing a disk or
//! by rotating a validator onto a shard it never hosted.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_scenarios::query::{committee_size, scheduled_terminal_epoch};
use hyperscale_scenarios::tx::{build_probe_transfer_tx, genesis_accounts, validity_around};
use hyperscale_scenarios::wait::{await_beacon_epoch, await_split_admitted};
use hyperscale_scenarios::{Cluster, FaultableCluster, ScenarioConfig, epochs};
use hyperscale_types::ShardId;
use support::SimCluster;

/// Single-shard config with the split trigger armed (`split_bytes = 0`)
/// and one cohort of pool surplus — an organic root split, so the root
/// terminates on a schedule the test does not have to drive.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

/// Drive the root to its split, wiping `wiped` of its four members onto
/// empty stores once the terminating window has opened. Returns whether
/// both children committed past genesis within budget.
///
/// `wiped = 0` is the baseline: the same clock, the same traffic and the
/// same budgets, with nothing removed.
fn split_completes_with_wiped_members(seed: u64, wiped: usize) -> bool {
    let root = ShardId::ROOT;
    let (left, right) = root.children();
    let mut c = SimCluster::with_accounts(&split_config(), seed, &genesis_accounts(1, 1));

    assert!(
        await_split_admitted(&mut c, root, epochs(8)),
        "seed {seed}: the beacon must admit the root split before the wipe",
    );
    assert!(
        c.run_until(epochs(12), |c| scheduled_terminal_epoch(c, root).is_some()),
        "seed {seed}: the beacon must stamp the cut before the wipe can be timed to it",
    );
    let terminal = scheduled_terminal_epoch(&c, root).expect("the cut is stamped");
    assert!(
        await_beacon_epoch(&mut c, terminal.inner(), epochs(12)),
        "seed {seed}: the terminating window must open before the wipe",
    );
    // Activity through the parent's final window, as the lifecycle
    // scenario gives it: it coasts to its crossing and the fold seeds
    // both children from the terminal contribution.
    c.submit(Arc::new(build_probe_transfer_tx(validity_around(c.now()))));

    let strength = committee_size(&c, root).expect("the root committee is seated");
    let hosts = c.committee_hosts(root);
    for &host in hosts.iter().take(wiped) {
        c.resync_host(host, root);
    }
    assert_eq!(
        committee_size(&c, root),
        Some(strength),
        "seed {seed}: the wipe must leave the committee at strength, or the stall is the wipe",
    );

    c.run_until(epochs(28), |c| {
        let past_genesis = |child| c.committed_height(child).is_some_and(|h| h.inner() >= 1);
        past_genesis(left) && past_genesis(right)
    })
}

/// The seeds both runs sweep. One seed is one leader schedule, and the
/// wipe lands differently against each — the first shape of this test
/// passed on a seed where the joiner's anchor happened to sit below the
/// window floor, which exercised nothing.
const SEEDS: [u64; 4] = [11, 42, 7, 2026];

/// The control: nothing removed, and the split completes on this clock.
/// Without it a wiped run that completes for its own reasons would read
/// as a pass.
#[test]
fn a_split_completes_when_every_member_holds_its_window() {
    for seed in SEEDS {
        assert!(
            split_completes_with_wiped_members(seed, 0),
            "seed {seed}: the unperturbed split must complete, or the wiped run proves nothing",
        );
    }
}

/// Two of four members holding no block below their anchor is past `f`,
/// so nothing else can carry the terminal block: it certifies only if a
/// member that arrived by snap-sync can fold its own terminal window.
#[test]
fn a_split_completes_when_more_than_f_members_arrive_by_sync() {
    for seed in SEEDS {
        assert!(
            split_completes_with_wiped_members(seed, 2),
            "seed {seed}: two members of four short of their window must still reach the \
             terminal block",
        );
    }
}
