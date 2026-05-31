//! End-to-end beacon-runner integration.
//!
//! Boots a multi-host sim with a beacon committee, runs through several
//! epochs, and asserts every host's `BeaconStorage` agrees on the
//! committed `(block, state)` pair at every epoch.

use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{BeaconCert, BeaconChainConfig, Epoch};
use tracing_test::traced_test;

/// 1-second epoch boundary so the first kickoff fires within the test's
/// run window. The cascade then runs at SPC-round speed.
const TEST_EPOCH_MS: u64 = 1000;

/// 2 shards × 4 validators = 8 total. The first four sit on the
/// genesis beacon committee; the other four form the eligibility slack
/// the shuffle needs once `SHUFFLE_INTERVAL_EPOCHS == 16` fires.
fn beacon_committee_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(100),
        cross_shard_latency: Duration::from_millis(100),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

/// Assert that every host's beacon storage holds an identical
/// `(block_hash, state)` pair at `epoch`. Returns the agreed pair so
/// callers can chain further assertions.
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

#[traced_test]
#[test]
fn happy_path_commits_multiple_epochs() {
    let mut runner = SimulationRunner::new(&beacon_committee_config(), 42);
    runner.initialize_genesis();

    // First `BeaconCommitteeStart` timer fires at
    // `chain_config.epoch_duration` (1 sec here). Epochs cascade
    // through `adopt_block` self-perpetuation at SPC-round speed
    // afterwards; 30 sim-seconds is well past the few rounds needed
    // for three epochs to land.
    runner.run_until(Duration::from_secs(30));

    let storage_0 = runner.beacon_storage(0).expect("host 0 exists");
    let latest = storage_0
        .latest_committed_epoch()
        .expect("at least one epoch committed past genesis");
    assert!(
        latest >= Epoch::new(3),
        "expected ≥3 post-genesis epochs committed, got latest={latest:?}"
    );

    // Genesis lives in-memory only; `commit_beacon_block` writes from
    // epoch 1 onward.
    for raw in 1..=latest.inner() {
        assert_beacon_consensus(&runner, Epoch::new(raw), 8);
    }
}

/// Drop every PC and SPC notification so no beacon committee member can
/// reach quorum on the first epoch. Active-pool members watch the skip
/// timer fire `SKIP_TIMEOUT` past the first epoch boundary, broadcast
/// signed `SkipRequest`s, and the chain advances past the abandoned
/// epoch with a `BeaconCert::Skip` cert.
#[traced_test]
#[test]
fn skip_path_advances_past_blocked_epoch() {
    let mut runner = SimulationRunner::new(&beacon_committee_config(), 0xBE_AC);
    runner.initialize_genesis();

    // Suppress every channel SPC needs to commit. Beacon proposal
    // notifications and the spc.* round-trips are all gone; the
    // committee can't reach the n-f vote threshold and the first
    // epoch's SPC stalls. Active-pool members on shard 1 (validators
    // 4..8) still have working network — their `BeaconSkipTrigger`
    // timer fires at `EPOCH_DURATION + SKIP_TIMEOUT` and they sign a
    // `SkipRequest` for epoch 1 at the genesis tip.
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

    // Need to cross `EPOCH_DURATION + SKIP_TIMEOUT` (1 sec + 45 sec
    // here) plus a few seconds for the skip cert to assemble and the
    // skip block to broadcast.
    runner.run_until(Duration::from_mins(1));

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

/// Drop every `beacon.proposal` notification arriving at validator 0.
/// SPC commits on every epoch the way the other three committee
/// members agree; assembling the committed block on validator 0
/// requires the missing proposals, which it pulls via the
/// `FetchRequest::BeaconProposal` pipeline. Every host's storage
/// converges on the same `(block, state)` pair.
#[traced_test]
#[test]
fn fetch_recovery_path_unblocks_dropped_peer() {
    let mut runner = SimulationRunner::new(&beacon_committee_config(), 0xFE_7C);
    runner.initialize_genesis();

    let drop_rule = runner
        .network_mut()
        .fault()
        .drop_type("beacon.proposal")
        .to(0)
        .install();

    runner.run_until(Duration::from_secs(30));

    assert!(
        drop_rule.fired() >= 1,
        "expected the `beacon.proposal` drop rule to fire at least once"
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
