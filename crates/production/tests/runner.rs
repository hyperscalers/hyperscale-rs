//! Production runner lifecycle tests: construction with real networking,
//! graceful shutdown, and runtime shard join/leave through the supervisor.
//!
//! Real localhost QUIC and `RocksDB`. `#[serial]` to avoid port conflicts and
//! state leakage; runs on a multi-threaded runtime to match the production
//! host's runtime shape.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::{LocalValidator, ShardCommand, VnodeConfig};
use hyperscale_storage::BeaconChainReader;
use hyperscale_types::{
    BeaconChainConfig, BlockHash, Epoch, RecoveryCause, ReshapeThresholds, ShardId, ShardRecovery,
    ValidatorId,
};
use serial_test::serial;
use support::harness::{ClusterSpec, Harness, HostSpec};
use support::{CONNECTION_TIMEOUT, build_runner, temp_storage_dir, temp_storage_factory};
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry, fmt};

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
            validator: ValidatorId::new(0),
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

/// A leave names the vnode it releases. With two vnodes seated on the
/// root, one leaving twice releases only itself — the second leave names
/// a vnode no longer seated — and the shard stays up for the other, which
/// tears it down when it leaves in turn.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_leave_releases_the_vnode_it_names() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(44, 2);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[0, 1], vec![], None);

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;
    assert!(adapter.local_shards().contains(&ShardId::ROOT));

    for _ in 0..2 {
        reconfigure
            .send(ShardCommand::Leave {
                shard: ShardId::ROOT,
                validator: ValidatorId::new(1),
            })
            .await
            .expect("supervisor accepts commands");
    }
    sleep(Duration::from_millis(500)).await;
    assert!(
        adapter.local_shards().contains(&ShardId::ROOT),
        "the shard stays up for the vnode that did not leave"
    );

    reconfigure
        .send(ShardCommand::Leave {
            shard: ShardId::ROOT,
            validator: ValidatorId::new(0),
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the last vnode leaving tears the shard down");

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after the leaves");
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
                signer: fixtures.signer(1),
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

/// Leaving a shard releases its store: a host that leaves a shard and is
/// later re-seated on it must reopen the same `RocksDB` directory. Guards the
/// teardown storage-release path a halt-recovery redraw depends on — a leaked
/// store handle leaves every rejoin spinning on the `RocksDB` lock
/// ("Join rejected: storage open failed … lock hold by current process").
///
/// The reopen is the test's own, against the directory the supervisor
/// opened, rather than a second `Join`. The supervisor reconciles hosted
/// shards against the committed view on a one-second tick, and a
/// validator the view never seats has its manual join retired at the
/// next one — the shard is seated for a window a poll can miss. A
/// validator the view does seat is no better: its manual leave is undone
/// by the join backstop on the same tick, racing the assertion that it
/// left. `RocksDB` holds an exclusive lock per directory, so the open
/// answers the question directly: it succeeds once the departed thread
/// has dropped its handle and never while one is leaked. The teardown
/// releases the store off the supervisor loop, so the open is retried
/// within the timeout rather than asserted at the first try.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn leaving_a_shard_releases_its_store() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::with_surplus(45, 1, 1);
    let surplus = ValidatorId::new(1);
    let (mut runner, dir, _) = build_runner(&fixtures, &[1], vec![], None);

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;

    reconfigure
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signer: fixtures.signer(1),
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
    .expect("the join seats the shard");

    // The lock is what the reopen below measures: while the shard is
    // hosted, its thread holds it and a second opener is refused.
    let open = temp_storage_factory();
    let root_dir = temp_storage_dir(&dir)(ShardId::ROOT);
    assert!(
        open(&root_dir, ShardId::ROOT).is_err(),
        "a hosted shard holds its store's lock",
    );

    reconfigure
        .send(ShardCommand::Leave {
            shard: ShardId::ROOT,
            validator: surplus,
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the left shard is removed from the adapter");

    let reopened = timeout(CONNECTION_TIMEOUT, async {
        loop {
            match open(&root_dir, ShardId::ROOT) {
                Ok(storage) => break storage,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("leaving the shard releases its store for a reopen");
    drop(reopened);

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after the leave");
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
            split_fullness: u32::MAX,
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

/// A restarted host starts on the topology its committed beacon state
/// projects, not the genesis one: before it folds a beacon block of the
/// new run, its view already carries the anchor ROOT's crossing attested.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_restarted_host_starts_on_its_committed_topology() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(49, 4);
    let hosts = (0..4)
        .map(|i| {
            HostSpec::new(vec![LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signer: fixtures.signer(i),
            }])
        })
        .collect();
    let mut cluster = Harness::start(ClusterSpec {
        genesis: fixtures.genesis_validators(),
        hosts,
        beacon_chain_config: BeaconChainConfig {
            epoch_duration_ms: 3_000,
            shard_size: 4,
            ..BeaconChainConfig::default()
        },
        genesis_config: None,
        simulated_outbound_latency: Duration::from_millis(50),
    })
    .await;
    assert!(
        cluster.topology(3).load().boundary(ShardId::ROOT).is_none(),
        "a network at genesis has no attested anchor"
    );

    let restarted = 3;
    timeout(CONNECTION_TIMEOUT * 12, async {
        while cluster
            .topology(restarted)
            .load()
            .boundary(ShardId::ROOT)
            .is_none_or(|anchor| anchor.block_hash == BlockHash::ZERO)
        {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the beacon attests a ROOT crossing");

    let startup = cluster.restart_with_wiped_shards(restarted, &[]).await;
    assert!(
        startup.boundary(ShardId::ROOT).is_some(),
        "the restarted host starts on the attested anchor its beacon chain holds"
    );

    cluster.shutdown().await;
}

/// Every event the process logs, in order: its message, then each other
/// field as `name=value`.
#[derive(Clone, Default)]
struct Messages(Arc<Mutex<Vec<String>>>);

impl Messages {
    fn contains(&self, needle: &str) -> bool {
        self.0
            .lock()
            .expect("messages lock")
            .iter()
            .any(|message| message.contains(needle))
    }
}

impl<S: Subscriber> Layer<S> for Messages {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        #[derive(Default)]
        struct Message {
            text: String,
            fields: String,
        }
        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
                if field.name() == "message" {
                    self.text = format!("{value:?}");
                } else {
                    let _ = write!(self.fields, " {}={value:?}", field.name());
                }
            }
        }
        let mut message = Message::default();
        event.record(&mut message);
        self.0
            .lock()
            .expect("messages lock")
            .push(message.text + &message.fields);
    }
}

/// A validator joining a shard its host already runs is seated into the
/// running loop rather than refused, and the committed-view reconcile
/// releases it again — the committee never placed it — while the host's
/// other seat keeps the shard up throughout.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_join_for_a_running_shard_seats_into_its_loop() {
    let messages = Messages::default();
    let _ = Registry::default()
        .with(messages.clone())
        .with(fmt::layer().with_test_writer())
        .try_init();

    // Validator 0 holds ROOT's one seat; validator 1, local to the same
    // host, is left pooled.
    let fixtures = TestFixtures::with_surplus(46, 1, 1);
    let surplus = ValidatorId::new(1);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[0, 1], vec![], None);

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;
    assert!(adapter.local_shards().contains(&ShardId::ROOT));

    reconfigure
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signer: fixtures.signer(1),
            }],
        })
        .await
        .expect("supervisor accepts commands");
    for (needle, what) in [
        (
            "Seat admitted on a running shard",
            "the running loop admits the seat",
        ),
        (
            "Vnode left a running shard",
            "the reconcile releases a seat the committee never placed",
        ),
    ] {
        timeout(CONNECTION_TIMEOUT, async {
            while !messages.contains(needle) {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect(what);
        assert!(
            adapter.local_shards().contains(&ShardId::ROOT),
            "the shard stays up across its seat changes"
        );
    }

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after the seat changes");
    assert!(result.unwrap().is_ok(), "runner returns Ok");
}

/// A join for a running shard under a fork recovery, whose store has
/// committed past the recovery's attested frontier, rebuilds the shard at
/// its anchor rather than seating the joiner onto the loop's tip: the
/// rebuilt loop resumes at the frontier.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_join_under_a_fork_recovery_rebuilds_a_loop_past_its_frontier() {
    // Four hosts' consensus at trace level floods the run; the supervisor's
    // lines are at info.
    let messages = Messages::default();
    let _ = Registry::default()
        .with(messages.clone().with_filter(LevelFilter::INFO))
        .with(
            fmt::layer()
                .with_test_writer()
                .with_filter(LevelFilter::INFO),
        )
        .try_init();

    // ROOT's four seats on four hosts; host 0 also carries the pooled
    // surplus validator the join names.
    let fixtures = TestFixtures::with_surplus(46, 4, 1);
    let local = |i: u32| LocalValidator {
        validator_id: ValidatorId::new(u64::from(i)),
        signer: fixtures.signer(i),
    };
    let surplus = ValidatorId::new(4);
    let mut cluster = Harness::start(ClusterSpec {
        genesis: fixtures.genesis_validators(),
        hosts: vec![
            HostSpec::new(vec![local(0), local(4)]),
            HostSpec::new(vec![local(1)]),
            HostSpec::new(vec![local(2)]),
            HostSpec::new(vec![local(3)]),
        ],
        beacon_chain_config: BeaconChainConfig {
            epoch_duration_ms: 3_000,
            shard_size: 4,
            ..BeaconChainConfig::default()
        },
        genesis_config: None,
        simulated_outbound_latency: Duration::from_millis(50),
    })
    .await;

    // The beacon attests a ROOT boundary host 0's loop has committed
    // past; a fork recovery pinned there makes everything above it a
    // suffix no fresh member may extend.
    let topology = cluster.topology(0);
    let frontier = timeout(CONNECTION_TIMEOUT * 12, async {
        loop {
            let snapshot = topology.load_full();
            if let Some(anchor) = snapshot
                .boundary(ShardId::ROOT)
                .filter(|anchor| anchor.block_hash != BlockHash::ZERO)
            {
                let forked = (*snapshot)
                    .clone()
                    .with_pending_recoveries(BTreeMap::from([(
                        ShardId::ROOT,
                        ShardRecovery {
                            cause: RecoveryCause::Fork,
                            rotated_at: Epoch::GENESIS,
                            retained: Vec::new(),
                            attested_frontier: anchor.height,
                        },
                    )]));
                topology.store(Arc::new(forked));
                break anchor.height;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the beacon attests a ROOT boundary");

    cluster
        .reconfigure(0)
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signer: fixtures.signer(4),
            }],
        })
        .await
        .expect("supervisor accepts commands");
    let rebuilt = format!(
        "Shard rebuilt at its attested anchor shard=ShardId {{ depth: 0, path: 0 }} committed={}",
        frontier.inner()
    );
    timeout(CONNECTION_TIMEOUT * 2, async {
        while !messages.contains(&rebuilt) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the join rebuilds the shard at the attested frontier");
    timeout(CONNECTION_TIMEOUT, async {
        while !messages.contains("Shard joined at runtime") {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the rebuilt store is seated");

    cluster.shutdown().await;
}

/// A join whose fresh store finds no attested anchor parks rather than
/// seating at genesis, unless the shard's chain runs from network genesis
/// with no crossing yet; the reshape tick retries it once this host's
/// topology says the shard is seatable. ROOT here never crosses (its one
/// seat runs nowhere), so the beacon projects it as a genesis replay; the
/// test withholds that from the view to park the join, then restores it.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_join_without_an_anchor_parks_until_the_shard_is_seatable() {
    let messages = Messages::default();
    let _ = Registry::default()
        .with(messages.clone())
        .with(fmt::layer().with_test_writer())
        .try_init();

    let fixtures = TestFixtures::with_surplus(47, 1, 1);
    let surplus = ValidatorId::new(1);
    let (mut runner, _dir, _) = build_runner(&fixtures, &[1], vec![], None);

    let topology = Arc::clone(runner.topology_snapshot());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner.shutdown_handle().expect("shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;

    let projected = topology.load_full();
    assert!(
        projected.boundary(ShardId::ROOT).is_none() && projected.genesis_unanchored(ShardId::ROOT),
        "the beacon projects a genesis shard with no crossing as a genesis replay"
    );
    topology.store(Arc::new(
        (*projected)
            .clone()
            .with_genesis_unanchored(BTreeSet::new()),
    ));

    reconfigure
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signer: fixtures.signer(1),
            }],
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while !messages
            .contains("Join parked until this host's topology carries the shard's anchor")
        {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("a fresh store with no anchor parks the join");
    // Reshape ticks pass with the view unchanged; the join stays parked.
    sleep(Duration::from_millis(2_500)).await;
    assert!(
        !messages.contains("Shard joined at runtime"),
        "a parked join seats nothing while the view carries no anchor"
    );

    topology.store(projected);
    for (needle, what) in [
        (
            "Retrying a join parked on its anchor",
            "the reshape tick retries the parked join",
        ),
        (
            "Shard joined at runtime",
            "the retried join seats the shard",
        ),
    ] {
        timeout(CONNECTION_TIMEOUT, async {
            while !messages.contains(needle) {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect(what);
    }

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "runner exits after seating");
    assert!(result.unwrap().is_ok(), "runner returns Ok");
}
