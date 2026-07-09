//! Production runner lifecycle tests: construction with real networking,
//! graceful shutdown, and runtime shard join/leave through the supervisor.
//!
//! Real localhost QUIC and `RocksDB`. `#[serial]` to avoid port conflicts and
//! state leakage; runs on a multi-threaded runtime to match the production
//! host's runtime shape.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::{ShardCommand, VnodeConfig};
use hyperscale_storage::BeaconChainReader;
use hyperscale_types::{BeaconChainConfig, ReshapeThresholds, ShardId, ValidatorId};
use serial_test::serial;
use support::{CONNECTION_TIMEOUT, build_runner};
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

/// A single-validator runner builds against real networking, listens on
/// localhost QUIC, and exits cleanly (returning `Ok`) when its shutdown
/// handle drops.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn runner_boots_listens_and_shuts_down_cleanly() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[0], vec![], None);

    sleep(Duration::from_millis(100)).await;
    let addrs = runner.network().listen_addresses().await;
    assert!(!addrs.is_empty(), "runner listens on localhost QUIC");

    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;
    drop(shutdown);

    let joined = timeout(Duration::from_secs(5), handle)
        .await
        .expect("runner exits within the graceful-shutdown budget")
        .expect("runner task joins");
    assert!(joined.is_ok(), "runner returns Ok on shutdown");
}

/// Runtime shard teardown through the supervisor: a runner seated on the root
/// shard leaves it mid-run — the departing vnode's pinned thread is joined and
/// its network subscriptions torn down — then shuts down cleanly hosting no
/// shard. The startup/join half is covered by
/// [`pooled_validator_boots_as_follower_only_host`].
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn runtime_shard_leave_tears_down() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(43, 1);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[0], vec![], None);

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;
    assert!(adapter.local_shards().contains(&ShardId::ROOT));

    // Leave the root shard: the single vnode departing tears the shard down.
    reconfigure
        .send(ShardCommand::Leave {
            shard: ShardId::ROOT,
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("left shard is removed from the adapter");
    assert!(
        adapter.local_shards().is_empty(),
        "the host hosts no shard after leaving the root"
    );

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after the leave");
    assert!(result.unwrap().is_ok(), "runner returns Ok");
}

/// A validator the beacon genesis leaves `Pooled` — registered in the global
/// set but in no shard committee — boots as a follower-only host. The runner
/// reads the committed beacon state, derives no seat, and brings the host up
/// hosting no shard with its beacon-follower pool thread running. A later
/// `ShardCommand::Join` seats it onto a shard, draining it from the pool —
/// the startup half of the drain/pool/reseat cycle the sim covers end to end.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pooled_validator_boots_as_follower_only_host() {
    let _ = fmt().with_test_writer().try_init();

    // One seated validator (id 0 on ROOT) plus one pool surplus (id 1) that
    // the genesis committee never seats.
    let fixtures = TestFixtures::with_surplus(44, 1, 1);
    let surplus = ValidatorId::new(1);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[1], vec![], None);

    // Derivation seated nothing: the host carries no shard before it runs.
    assert!(
        runner.network().local_shards().is_empty(),
        "a pooled validator seats no shard at startup"
    );

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;

    // Still hosts no shard while the follower pool thread runs.
    assert!(
        adapter.local_shards().is_empty(),
        "follower-only host hosts no shard"
    );

    // Seat the pooled validator onto ROOT: the supervisor opens the store,
    // brings the shard up, and retires the validator's pool follower.
    reconfigure
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signing_key: fixtures.signing_key(1),
            }],
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while !adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("seated shard becomes hosted on the adapter");

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after seating");
    assert!(result.unwrap().is_ok(), "runner returns Ok");
}

/// The `beacon_chain_config` builder setter threads a custom config through into
/// the committed beacon genesis state. Every other production test leaves the
/// setter unused and is unaffected: a custom `epoch_duration_ms` and reshape
/// `split_bytes` reach the genesis state only when set explicitly.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);
    let chain_config = BeaconChainConfig {
        epoch_duration_ms: 400,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 50_000,
        },
        ..BeaconChainConfig::default()
    };
    let (_runner, _dir, beacon_storage) = build_runner(&fixtures, &[0], vec![], Some(chain_config));

    // Build commits the genesis (block, state) pair into the beacon store.
    let (_block, state) = beacon_storage
        .latest_committed()
        .expect("genesis pair committed at build time");
    assert_eq!(
        state.chain_config.epoch_duration_ms, 400,
        "custom epoch duration reaches the beacon genesis state"
    );
    assert_eq!(
        state.params.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold seeds the live network params at genesis"
    );
}
