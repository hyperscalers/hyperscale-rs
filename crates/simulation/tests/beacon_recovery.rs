//! Beacon recovery paths under committee obstruction.
//!
//! Boots a multi-host sim with a beacon committee, blocks the commit path
//! (every SPC/PC notification dropped, or one host's proposals), and asserts
//! the chain advances past the obstruction — by skip cert or proposal fetch —
//! with every host agreeing on the committed `(block, state)` pair.

mod support;

use std::time::Duration;

use hyperscale_network_memory::HostId;
use hyperscale_scenarios::tx::genesis_accounts;
use hyperscale_scenarios::{Cluster, FaultableCluster, ScenarioConfig, epochs};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_types::{
    BeaconCert, BeaconChainConfig, BeaconState, BlockHash, Epoch, MIN_BEACON_COMMITTEE_SIZE,
    SKIP_TIMEOUT, SPC_VIEW_TIMEOUT, ShardId, ValidatorStatus,
};
use support::{SimCluster, sim_seed};
use tracing_test::traced_test;

/// The single-shard beacon chain config at `epoch_duration_ms`. One shard of
/// eight validators: the first four sit on the genesis beacon committee, the
/// other four are active shard members forming the eligibility slack the
/// shuffle needs once the derived interval fires and the skip-quorum
/// source when the committee stalls.
fn beacon_chain_config(epoch_duration_ms: u64) -> BeaconChainConfig {
    BeaconChainConfig {
        epoch_duration_ms,
        shard_size: 8,
        ..BeaconChainConfig::default()
    }
}

/// 8 validators on one shard, beacon committee 4.
fn beacon_committee_config() -> SimConfig {
    SimConfig {
        shard_size: 8,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(beacon_chain_config(EPOCH_MS)),
        ..Default::default()
    }
}

/// Assert that every host's beacon storage holds an identical
/// `(block_hash, state)` pair at `epoch`.
fn assert_beacon_consensus(runner: &SimulationRunner, epoch: Epoch, num_hosts: u32) {
    let storage_0 = runner.beacon_storage(0).expect("host 0 exists");
    let block_0 = storage_0
        .get_beacon_block_by_epoch(epoch)
        .unwrap_or_else(|| panic!("host 0 missing beacon block at {epoch:?}"));
    let state_0 = storage_0
        .get_state_by_epoch(epoch)
        .unwrap_or_else(|| panic!("host 0 missing beacon state at {epoch:?}"));
    let hash_0 = block_0.block_hash();

    for host_idx in 1..num_hosts {
        let storage = runner
            .beacon_storage(host_idx)
            .unwrap_or_else(|| panic!("host {host_idx} exists"));
        let block = storage
            .get_beacon_block_by_epoch(epoch)
            .unwrap_or_else(|| panic!("host {host_idx} missing beacon block at {epoch:?}"));
        let state = storage
            .get_state_by_epoch(epoch)
            .unwrap_or_else(|| panic!("host {host_idx} missing beacon state at {epoch:?}"));
        assert_eq!(
            block.block_hash(),
            hash_0,
            "host {host_idx} disagrees on beacon block hash at {epoch:?}"
        );
        assert_eq!(
            *state, *state_0,
            "host {host_idx} disagrees on beacon state at {epoch:?}"
        );
    }
}

/// Drop every PC and SPC notification so no beacon committee member can
/// reach quorum on the first epoch. Active-pool members watch the ratify
/// timer fire `SKIP_TIMEOUT` past the first epoch boundary, prevote the
/// canonical skip hash, and the chain advances past the abandoned
/// epoch with a `BeaconCert::Skip` cert.
#[traced_test]
#[test]
fn skip_path_advances_past_blocked_epoch() {
    let mut runner = SimulationRunner::new(&beacon_committee_config(), sim_seed(0xBE_AC));
    runner.initialize_genesis();

    // Suppress every channel SPC needs to commit. Beacon proposal
    // notifications and the spc.* round-trips are all gone; the
    // committee can't reach the n-f vote threshold and the first
    // epoch's SPC stalls. The active shard members off the beacon
    // committee (validators 4..8) still have working network — their
    // `BeaconRatifyTrigger` timer fires at `EPOCH_DURATION + SKIP_TIMEOUT`
    // and they prevote the skip hash for epoch 1 at the genesis tip.
    let _rules = [
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.proposal")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.spc.new_view")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.spc.new_commit")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.spc.empty_view")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.pc.vote1")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.pc.vote2")
            .install(),
        runner
            .network_mut()
            .fault()
            .drop_type("beacon.pc.vote3")
            .install(),
    ];

    // Cross the epoch-1 boundary (`EPOCH_MS`) plus the skip timeout (the
    // epoch length clamped into `[SPC_VIEW_TIMEOUT, SKIP_TIMEOUT]`), then
    // leave slack for the ratify cert to assemble and the skip block to
    // broadcast.
    let skip_timeout = Duration::from_millis(EPOCH_MS).clamp(SPC_VIEW_TIMEOUT, SKIP_TIMEOUT);
    runner.run_until(Duration::from_millis(EPOCH_MS) + skip_timeout + Duration::from_secs(30));

    let storage_0 = runner.beacon_storage(0).expect("host 0 exists");
    let block_1 = storage_0
        .get_beacon_block_by_epoch(Epoch::new(1))
        .expect("epoch 1 committed (as a skip)");
    assert!(
        matches!(block_1.cert(), BeaconCert::Skip(_)),
        "expected BeaconCert::Skip at epoch 1, got {:?}",
        block_1.cert()
    );

    // Every host converges on the same skipped-epoch block.
    for host_idx in 1..8 {
        let storage = runner.beacon_storage(host_idx).expect("host exists");
        let block = storage
            .get_beacon_block_by_epoch(Epoch::new(1))
            .unwrap_or_else(|| panic!("host {host_idx} missing epoch 1 skip block"));
        assert_eq!(
            block.block_hash(),
            block_1.block_hash(),
            "host {host_idx} disagrees on epoch 1 skip block hash"
        );
    }
}

/// Drop every `beacon.proposal` notification arriving at host 0.
/// The chain still commits across the other three committee members;
/// host 0 catches up through whichever path the protocol actually
/// uses — block gossip when host 0 isn't on the committee, the
/// fetch-binding round trip when host 0 *is* on the committee and
/// PC commits a value referencing proposals its pool never observed.
///
/// Verifies that the wired-up `GetBeaconProposalRequest` responder
/// (in `crates/node/src/process/network_handlers.rs`) doesn't
/// regress: when fetch fires, it serves real proposals rather than
/// the empty-response stub that used to live there.
#[traced_test]
#[test]
fn fetch_recovery_path_unblocks_dropped_peer() {
    // The whole drop-and-recover run stays below the first committee
    // shuffle, so a fetch-recovered block never commits against an evicted
    // committee — the 3-epoch topology retention window is sized for exactly
    // this shape.
    let mut runner = SimulationRunner::new(&beacon_committee_config(), sim_seed(0xFE_7C));
    runner.initialize_genesis();

    let drop_rule = runner
        .network_mut()
        .fault()
        .drop_type("beacon.proposal")
        .to(HostId(0))
        .install();

    // Several epochs so every host — including the dropped peer catching
    // up via fetch — commits well past the >=3 the assertion needs.
    runner.run_until(Duration::from_millis(EPOCH_MS) * 5);

    assert!(
        drop_rule.fired() >= 1,
        "expected `beacon.proposal` drop rule to fire at least once"
    );

    // All eight hosts caught up. Take the min latest-committed-epoch
    // so the iteration covers the prefix every host has committed.
    let mut min_latest = u64::MAX;
    for host_idx in 0..8 {
        let storage = runner.beacon_storage(host_idx).expect("host exists");
        let latest = storage
            .latest_committed_epoch()
            .unwrap_or_else(|| panic!("host {host_idx} committed nothing"))
            .inner();
        min_latest = min_latest.min(latest);
    }
    assert!(
        min_latest >= 3,
        "expected every host to commit >=3 epochs, min got {min_latest}"
    );

    for raw in 1..=min_latest {
        assert_beacon_consensus(&runner, Epoch::new(raw), 8);
    }
}

/// A jail that drops the beacon-eligible set below the committee floor
/// while a split's child anchors are still pending does not park the
/// beacon.
///
/// ROOT's four members are the whole proven set; the split's consumed
/// observers sit `ready` on the children but stay out of it until the
/// anchors seed. One parent half's beacon proposals are cut, so the next
/// healthy epoch jails it for withholding and leaves three proven members.
/// The committee draw tops up with one pending-anchor observer, which
/// keeps SPC above its floor; the three synced members carry the parent's
/// terminal boundary QC past the observer's abstention, the anchors seed,
/// and the beacon keeps committing normal blocks.
#[traced_test]
#[test]
fn a_jail_below_the_floor_mid_split_keeps_the_beacon_committing() {
    let config = ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    };
    // Each pool extra on a host of its own, so cutting the victim's host
    // silences no observer beside it.
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &config,
        sim_seed(11),
        &genesis_accounts(1, 1),
    );
    let children: [ShardId; 2] = ShardId::ROOT.children().into();
    let anchors_pending = |state: &BeaconState| {
        children.iter().all(|child| {
            state
                .boundaries
                .get(child)
                .is_some_and(|b| b.block_hash == BlockHash::ZERO)
        })
    };

    assert!(
        cluster.run_until(epochs(30), |c| c
            .beacon_state()
            .is_some_and(|s| !s.pending_anchor_observers().is_empty())),
        "the split did not place its observers within budget",
    );
    let executed = cluster.beacon_state().expect("a committed beacon state");
    assert!(anchors_pending(&executed));
    let proven = executed.beacon_eligible();
    let victim = executed
        .committee
        .iter()
        .copied()
        .find(|id| proven.contains(id))
        .expect("a proven member sits on the committee");
    let victim_host = cluster.host_of(victim).expect("the victim runs a host");
    let others: Vec<usize> = (0..cluster.host_count())
        .filter(|host| *host != victim_host)
        .collect();
    let _cut = [
        cluster.drop_type_between(&[victim_host], &others, "beacon.proposal"),
        cluster.drop_type_between(&others, &[victim_host], "beacon.proposal.request"),
    ];

    assert!(
        cluster.run_until(epochs(6), |c| c.beacon_state().is_some_and(|s| matches!(
            s.validators.get(&victim).map(|r| r.status),
            Some(ValidatorStatus::Jailed { .. })
        ))),
        "the victim was not jailed within budget",
    );
    let jailed = cluster.beacon_state().expect("a committed beacon state");
    assert!(
        anchors_pending(&jailed),
        "the jail must land while the child anchors are pending",
    );
    assert!(
        jailed.beacon_eligible_count() < MIN_BEACON_COMMITTEE_SIZE,
        "the jail must leave the proven set below the floor",
    );

    assert!(
        cluster.run_until(epochs(20), |c| c.beacon_state().is_some_and(
            |s| !anchors_pending(&s) && s.pending_anchor_observers().is_empty()
        )),
        "the child anchors never seeded: the beacon parked",
    );
    let seeded = cluster.beacon_state().expect("a committed beacon state");
    assert!(seeded.beacon_eligible_count() >= MIN_BEACON_COMMITTEE_SIZE);

    // The beacon keeps committing normal blocks past the seed.
    let seeded_epoch = seeded.current_epoch;
    let normal_after = |c: &SimCluster| {
        let storage = c.runner().beacon_storage(0).expect("host 0 exists");
        let latest = storage.latest_committed_epoch().map_or(0, Epoch::inner);
        (seeded_epoch.inner() + 1..=latest).any(|epoch| {
            storage
                .get_beacon_block_by_epoch(Epoch::new(epoch))
                .is_some_and(|block| matches!(block.cert(), BeaconCert::Normal { .. }))
        })
    };
    assert!(
        cluster.run_until(epochs(6), normal_after),
        "the beacon committed no normal block after the anchors seeded",
    );
}
