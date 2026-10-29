//! A host restarted onto an empty store for a shard it is seated on: the
//! store has to rejoin the shard's chain, not start one of its own.
//!
//! Real localhost QUIC and `RocksDB`, `#[serial]` against port and state
//! leakage.

mod support;

use std::time::Duration;

use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_production::LocalValidator;
use hyperscale_scenarios::{
    Budget, Cluster, FaultableCluster, RestartableCluster, ScenarioConfig,
    a_restart_beside_a_departed_parent_store_resumes,
    a_restart_mid_handoff_keeping_its_stores_catches_the_child_up, grow_to,
};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{
    BeaconChainConfig, BlockHeight, NetworkDefinition, ReshapeThresholds, ShardId, ValidatorId,
};
use serial_test::serial;
use support::ProdCluster;
use support::harness::{ClusterSpec, Harness, HostSpec};
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

/// How far past its height at the restart a wiped host's shard has to
/// commit before it counts as caught up with the chain.
const CATCH_UP_BLOCKS: u64 = 3;

/// A host whose store for a never-crossed genesis shard is wiped rejoins
/// that chain at the network genesis: its fresh store commits the block
/// every member began from, and block sync extends it to the live tip.
/// The epoch outlasts the test, so ROOT never crosses and has no anchor to
/// snap-sync from.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_wiped_store_on_a_never_crossed_shard_rejoins_at_genesis() {
    let mut cluster = start_never_crossing_cluster().await;

    let restarted = 3;
    let before = await_height(&cluster, None, BlockHeight::new(CATCH_UP_BLOCKS)).await;
    let topology = cluster
        .restart_with_wiped_shards(restarted, &[ShardId::ROOT])
        .await;
    assert!(
        topology.boundary(ShardId::ROOT).is_none() && topology.genesis_unanchored(ShardId::ROOT),
        "ROOT has not crossed, so a fresh store rejoins it at genesis"
    );

    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    await_height(&cluster, Some(restarted), target).await;

    cluster.shutdown().await;
}

/// A host that crashed after its fresh store installed the network
/// genesis and before it committed block 1 resumes from that genesis: the
/// store is not fresh, so the ceremony does not run again over it, and
/// block sync extends the installed genesis to the live tip.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_store_that_installed_genesis_resumes_from_it() {
    let mut cluster = start_never_crossing_cluster().await;

    let restarted = 3;
    let before = await_height(&cluster, None, BlockHeight::new(CATCH_UP_BLOCKS)).await;
    cluster
        .restart_with_installed_genesis(restarted, &[ShardId::ROOT])
        .await;

    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    await_height(&cluster, Some(restarted), target).await;

    cluster.shutdown().await;
}

/// A fresh host holding a quorum attests its genesis state from block 1:
/// the first proposal is built inside the step that installs genesis, and
/// the host's own signers certify it without checking its claim, so a
/// count missing the genesis total would be carried by every later block.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_fresh_host_holding_a_quorum_claims_its_genesis_state() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(48, 4);
    let mut cluster = Harness::start(ClusterSpec {
        genesis: fixtures.genesis_validators(),
        hosts: vec![HostSpec::new(
            (0..4)
                .map(|i| LocalValidator {
                    validator_id: ValidatorId::new(u64::from(i)),
                    signer: fixtures.signer(i),
                })
                .collect(),
        )],
        beacon_chain_config: BeaconChainConfig {
            epoch_duration_ms: 600_000,
            shard_size: 4,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: 1 << 40,
                ..ReshapeThresholds::DISABLED
            },
            ..BeaconChainConfig::default()
        },
        genesis_config: None,
        simulated_outbound_latency: Duration::from_millis(50),
    })
    .await;

    let through = BlockHeight::new(5);
    await_height(&cluster, None, through).await;
    let genesis = cluster
        .genesis_substate_bytes(ShardId::ROOT)
        .expect("ROOT's store records its genesis total");
    assert!(genesis > 0, "genesis lays down state");
    let claims = cluster.substate_claims(ShardId::ROOT, through);
    assert_eq!(claims.len(), 5, "{claims:?}");
    assert!(
        claims
            .iter()
            .all(|claim| claim.is_some_and(|n| n >= genesis)),
        "every claim counts the {genesis} genesis bytes: {claims:?}"
    );

    cluster.shutdown().await;
}

/// Four hosts of one validator each on a single ROOT shard, under an
/// epoch that outlasts the test, so ROOT never crosses and has no anchor
/// to snap-sync from.
async fn start_never_crossing_cluster() -> Harness {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(48, 4);
    let hosts = (0..4)
        .map(|i| {
            HostSpec::new(vec![LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signer: fixtures.signer(i),
            }])
        })
        .collect();
    Harness::start(ClusterSpec {
        genesis: fixtures.genesis_validators(),
        hosts,
        beacon_chain_config: BeaconChainConfig {
            epoch_duration_ms: 600_000,
            shard_size: 4,
            ..BeaconChainConfig::default()
        },
        genesis_config: None,
        simulated_outbound_latency: Duration::from_millis(50),
    })
    .await
}

/// Wait until `host` (any host when `None`) has committed ROOT to
/// `height`, returning the height it reached.
async fn await_height(cluster: &Harness, host: Option<usize>, height: BlockHeight) -> BlockHeight {
    timeout(Duration::from_secs(60), async {
        loop {
            let reached = host
                .map_or_else(
                    || cluster.committed_height(ShardId::ROOT),
                    |host| cluster.host_committed_height(host, ShardId::ROOT),
                )
                .map(BlockHeight::new);
            if let Some(reached) = reached.filter(|&reached| reached >= height) {
                return reached;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("ROOT reaches {height:?} on {host:?}"))
}

/// Epoch length for the split test: the shortest a chain may run, so a
/// grow to two shards finishes in minutes of wall clock.
const SPLIT_EPOCH_MS: u64 = 30_000;

/// The scenario suite's split config: the trigger armed, one cohort of
/// pool surplus, one validator per host, and paced inter-host latency.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
    }
}

/// A host whose store for a split child is wiped rejoins the child's
/// chain against its attested anchor and catches up with the live tip.
/// A split child's chain did not begin at the network genesis, so a
/// fresh store has nothing to replay from genesis: it has to snap-sync.
#[test]
#[serial]
fn a_wiped_store_on_a_split_child_rejoins_its_chain() {
    let mut cluster = ProdCluster::start(&split_config(), 11, SPLIT_EPOCH_MS);
    grow_to(&mut cluster, 2);

    // Restart once the split's handoff is done and the child holds an
    // attested anchor: from then on the child is an ordinary shard, and a
    // seat on it is a join rather than a reshape duty.
    let child = ShardId::leaf(1, 0);
    let settled = |c: &ProdCluster| {
        c.beacon_state().is_some_and(|state| {
            let topology = state.derive_topology_snapshot(NetworkDefinition::simulator());
            !topology.reshape_handoff_pending(ShardId::ROOT)
                && topology.reshape_parent_half_cohorts().is_empty()
                && topology.boundary(child).is_some()
        })
    };
    assert!(
        cluster.run_until(Budget(20), settled),
        "the split hands off to its children"
    );
    let member = cluster
        .beacon_state()
        .expect("a beacon state is committed")
        .derive_topology_snapshot(NetworkDefinition::simulator())
        .committee_for_shard(child)
        .first()
        .copied()
        .expect("the child has a committee");
    let host = cluster.host_of(member).expect("a host runs the member");
    let before = cluster
        .committed_height(child)
        .expect("the child commits after the grow");

    // The split parent's store goes with the child's: the host keeps
    // only its beacon chain, so the restart has no departed store to
    // serve and every shard it seats starts from nothing.
    cluster.restart_with_wiped_shards(host, &[ShardId::ROOT, child]);

    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    assert!(
        cluster.run_until(Budget(20), |c| c
            .host_committed_height(host, child)
            .is_some_and(|height| height >= target)),
        "the restarted host's child store catches up with the chain",
    );
}

/// A former member of a split parent restarted with the parent's store
/// still on disk comes back up and catches its child store up.
#[test]
#[serial]
fn a_restart_beside_a_departed_parent_store_resumes_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, SPLIT_EPOCH_MS);
    a_restart_beside_a_departed_parent_store_resumes(&mut cluster);
}

/// A split child's parent-half member restarted before the handoff
/// completes, with both the parent's store and its own child store wiped,
/// rejoins the child's chain. The duty that would seed the child from a
/// hosted parent store has none to clone, so it hands the seat to the
/// join, which snap-syncs the child against its attested anchor.
#[test]
#[serial]
fn a_restart_mid_handoff_without_the_parent_store_rejoins_the_child() {
    let mut cluster = ProdCluster::start(&split_config(), 11, SPLIT_EPOCH_MS);
    grow_to(&mut cluster, 2);

    let (child, member) = cluster
        .beacon_state()
        .expect("a beacon state is committed")
        .derive_topology_snapshot(NetworkDefinition::simulator())
        .reshape_parent_half_cohorts()
        .iter()
        .find_map(|(&child, cohort)| cohort.keys().next().map(|&member| (child, member)))
        .expect("the handoff is still in flight once both children commit");
    let host = cluster.host_of(member).expect("a host runs the member");
    let before = cluster
        .committed_height(child)
        .expect("the child commits after the grow");

    let topology = cluster.restart_with_wiped_shards(host, &[ShardId::ROOT, child]);
    assert!(
        topology
            .reshape_parent_half_cohorts()
            .get(&child)
            .is_some_and(|cohort| cohort.contains_key(&member)),
        "the restarted host starts on a topology that still publishes its parent-half seat"
    );

    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    assert!(
        cluster.run_until(Budget(20), |c| c
            .host_committed_height(host, child)
            .is_some_and(|height| height >= target)),
        "the restarted host's child store catches up with the chain",
    );
}

/// A split child's parent-half member restarted before the handoff
/// completes, with every store it held kept, catches the child up.
#[test]
#[serial]
fn a_restart_mid_handoff_keeping_its_stores_catches_the_child_up_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, SPLIT_EPOCH_MS);
    a_restart_mid_handoff_keeping_its_stores_catches_the_child_up(&mut cluster);
}

/// A split child's parent-half member restarted between cloning its parent
/// store for the child and adopting the child's genesis into the clone
/// catches the child up. The clone holds the parent's chain through its
/// terminal, not the child's, so the restart resumes nothing from it.
#[test]
#[serial]
fn a_restart_before_a_clones_adoption_catches_the_child_up() {
    let mut cluster = ProdCluster::start(&split_config(), 11, SPLIT_EPOCH_MS);
    grow_to(&mut cluster, 2);

    let (child, member) = cluster
        .beacon_state()
        .expect("a beacon state is committed")
        .derive_topology_snapshot(NetworkDefinition::simulator())
        .reshape_parent_half_cohorts()
        .iter()
        .find_map(|(&child, cohort)| cohort.keys().next().map(|&member| (child, member)))
        .expect("the handoff is still in flight once both children commit");
    // The children seat off the parent's cut ahead of the fold that
    // records its terminal.
    let terminal = |c: &ProdCluster| {
        c.beacon_state()?
            .derive_topology_snapshot(NetworkDefinition::simulator())
            .boundary(ShardId::ROOT)
            .filter(|anchor| anchor.terminal_epoch.is_some())
    };
    assert!(
        cluster.run_until(Budget(4), |c| terminal(c).is_some()),
        "the beacon records the parent's terminal"
    );
    let terminal = terminal(&cluster).expect("just recorded");
    let host = cluster.host_of(member).expect("a host runs the member");
    let before = cluster
        .committed_height(child)
        .expect("the child commits after the grow");

    cluster.stop_host(host, Budget(0));
    cluster.clone_unadopted(host, ShardId::ROOT, &[child]);
    let cloned = cluster.read_stored(host, child, |store| {
        store
            .get_certified_header(terminal.height)
            .map(|certified| (certified.header().hash(), certified.header().state_root()))
    });
    assert_eq!(
        cloned,
        Some(Some((terminal.block_hash, terminal.state_root))),
        "before the host starts, its child store holds the parent's chain and state at the \
         terminal {terminal:?}",
    );
    assert!(
        cluster.run_until(Budget(1), |c| c.is_up(host)),
        "host {host} comes back"
    );

    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    assert!(
        cluster.run_until(Budget(20), |c| c
            .host_committed_height(host, child)
            .is_some_and(|height| height >= target)),
        "the restarted host's child store catches up with the chain",
    );
}

/// One shard of four hosts, the split trigger disarmed.
const fn one_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(60),
    }
}

/// A host stopped for an epoch reads as down, with no shard to its name,
/// comes back on the disk it left and commits ROOT past where the chain
/// stood when it returned.
#[test]
#[serial]
fn a_stopped_host_reads_as_down_then_commits_again() {
    let mut cluster = ProdCluster::start(&one_shard_config(), 11, SPLIT_EPOCH_MS);
    let host = 3;
    assert!(
        cluster.run_until(Budget(2), |c| c
            .host_committed_height(host, ShardId::ROOT)
            .is_some_and(|height| height.inner() >= CATCH_UP_BLOCKS)),
        "host {host} commits ROOT before it stops",
    );

    cluster.stop_host(host, Budget(1));
    assert!(
        !cluster.is_up(host)
            && cluster.host_committed_height(host, ShardId::ROOT).is_none()
            && !cluster.committee_hosts(ShardId::ROOT).contains(&host),
        "a stopped host reads as down and serves nothing",
    );

    assert!(
        cluster.run_until(Budget(2), |c| c.is_up(host)),
        "host {host} comes back once its downtime is over"
    );
    let returned = cluster
        .committed_height(ShardId::ROOT)
        .expect("ROOT commits");
    assert!(
        cluster.run_until(Budget(2), |c| c
            .host_committed_height(host, ShardId::ROOT)
            .is_some_and(|height| height > returned)),
        "host {host} commits ROOT past {returned:?} again",
    );
}
