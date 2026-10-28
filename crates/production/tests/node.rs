//! The library front door: hosts started through `Node::start` alone, as an
//! embedder starts them. Each host's address is fixed before it starts (a
//! chosen port, and on iroh a chosen key), so the second host can be pointed at
//! the first without reaching into the transport.

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hex::encode as hex_encode;
use hyperscale_production::network_file::{Chain, Genesis, ValidatorEntry};
use hyperscale_production::{LocalValidator, NetworkFile, Node, NodeSetup, Observation};
use hyperscale_types::{BeaconChainConfig, BlockHeight, ShardId, ValidatorId};
use serial_test::serial;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

/// How long a fresh four-validator network gets to commit its first blocks.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(60);
/// The height every hosted validator must reach.
const TARGET_HEIGHT: u64 = 3;

/// How soon a peer sees a stopped host's connection close: inside the
/// transports' idle timeouts, so only a close that reached it passes.
const LEAVE_SEEN_WITHIN: Duration = Duration::from_secs(3);

/// A localhost QUIC port nothing holds right now.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("bind a free port")
        .port()
}

/// Where a host listens and what another host dials to reach it.
mod net {
    use std::net::{Ipv4Addr, SocketAddr};

    pub use hyperscale_network_iroh::test_utils::TestFixtures;
    use hyperscale_network_iroh::{EndpointAddr, IrohConfig, SecretKey};

    #[derive(Clone)]
    pub struct Listen {
        key: SecretKey,
        at: SocketAddr,
    }
    pub type Dial = EndpointAddr;

    pub fn listen(port: u16) -> Listen {
        Listen {
            key: SecretKey::generate(),
            at: (Ipv4Addr::LOCALHOST, port).into(),
        }
    }

    pub fn dial(listen: &Listen) -> Dial {
        EndpointAddr::new(listen.key.public()).with_ip_addr(listen.at)
    }

    pub fn config(listen: Listen, bootstrap_peers: Vec<Dial>) -> IrohConfig {
        IrohConfig {
            bootstrap_peers,
            ..IrohConfig::for_testing(listen.key, listen.at)
        }
    }
}

use net::{Dial, Listen, TestFixtures};

/// The network file the fixtures' network would ship: its genesis committee
/// listed with their keys, and `beacon_chain`'s parameters.
fn network_file(fixtures: &TestFixtures, beacon_chain: BeaconChainConfig) -> NetworkFile {
    let genesis = fixtures.genesis_validators();
    let validators = genesis
        .committee
        .iter()
        .map(|&id| {
            let info = genesis
                .validators
                .validators
                .iter()
                .find(|v| v.validator_id == id)
                .expect("a committee member is registered");
            ValidatorEntry {
                id: id.inner(),
                public_key: hex_encode(info.public_key.as_bytes()),
            }
        })
        .collect();
    NetworkFile {
        network: genesis.network,
        bootstrap_peers: Vec::new(),
        relays: Vec::new(),
        chain: Chain {
            genesis_timestamp_ms: beacon_chain.genesis_timestamp_ms,
            epoch_duration_ms: Some(beacon_chain.epoch_duration_ms),
            shard_size: Some(beacon_chain.shard_size),
            ready_timeout_epochs: Some(beacon_chain.ready_timeout_epochs),
            split_bytes: Some(beacon_chain.reshape_thresholds.split_bytes),
        },
        genesis: Genesis {
            validators,
            ..Genesis::default()
        },
    }
}

fn setup(
    data_dir: &Path,
    fixtures: &TestFixtures,
    validators: &[u32],
    listen: Listen,
    bootstrap_peers: Vec<Dial>,
    beacon_chain: BeaconChainConfig,
) -> NodeSetup {
    let validators = validators
        .iter()
        .map(|&i| LocalValidator {
            validator_id: ValidatorId::new(u64::from(i)),
            signer: fixtures.signer(i),
        })
        .collect();
    let mut setup = NodeSetup::from_network(
        data_dir.to_path_buf(),
        validators,
        &network_file(fixtures, beacon_chain),
        net::config(listen, bootstrap_peers),
    )
    .expect("the fixtures' network file starts a host");
    // A file seats every validator it lists; a genesis that leaves some in
    // the draw is the fixtures' own.
    let genesis = fixtures.genesis_validators();
    if genesis.committee.len() < genesis.validators.validators.len() {
        setup.genesis = genesis;
    }
    setup
}

fn now_ms() -> u64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970");
    u64::try_from(since.as_millis()).expect("milliseconds fit u64")
}

/// One network's beacon configuration, starting now, as a fresh testnet's
/// genesis does. Every host of the network takes the same value.
fn network(epoch_duration_ms: Option<u64>) -> BeaconChainConfig {
    let defaults = BeaconChainConfig::default();
    BeaconChainConfig {
        genesis_timestamp_ms: now_ms(),
        epoch_duration_ms: epoch_duration_ms.unwrap_or(defaults.epoch_duration_ms),
        ..defaults
    }
}

/// Two hosts of co-hosted validators, the second pointed at the first.
fn start_pair(
    dirs: [&Path; 2],
    fixtures: &TestFixtures,
    hosted: [&[u32]; 2],
    beacon_chain: BeaconChainConfig,
) -> (Node, Node) {
    let listen0 = net::listen(free_port());
    let dial0 = net::dial(&listen0);
    let node0 = Node::start(setup(
        dirs[0],
        fixtures,
        hosted[0],
        listen0,
        vec![],
        beacon_chain,
    ))
    .expect("start host 0");
    let node1 = Node::start(setup(
        dirs[1],
        fixtures,
        hosted[1],
        net::listen(free_port()),
        vec![dial0],
        beacon_chain,
    ))
    .expect("start host 1");
    (node0, node1)
}

/// The lowest height any of the node's hosted validators has committed.
fn lowest_height(node: &Node) -> Option<u64> {
    let status = node.status().load_full();
    status.vnodes.iter().map(|v| v.block_height).min()
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_co_hosted_nodes_commit() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(11, 4);
    let (dir0, dir1) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (node0, node1) = start_pair(
        [dir0.path(), dir1.path()],
        &fixtures,
        [&[0, 1], &[2, 3]],
        network(None),
    );

    timeout(COMMIT_TIMEOUT, async {
        loop {
            let heights = (lowest_height(&node0), lowest_height(&node1));
            if let (Some(h0), Some(h1)) = heights
                && h0 >= TARGET_HEIGHT
                && h1 >= TARGET_HEIGHT
            {
                return;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("every co-hosted validator reaches the target height");

    // Each host keeps the root chain's certified headers once per height,
    // every certificate past genesis signed by members of the four-validator
    // committee (genesis's own certificate carries no votes).
    let validators: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
    for node in [&node0, &node1] {
        let kept = node.headers(ShardId::ROOT, BlockHeight::new(1));
        assert!(
            kept.len() >= usize::try_from(TARGET_HEIGHT).unwrap(),
            "the host kept the root chain's headers"
        );
        for pair in kept.windows(2) {
            assert!(pair[0].height < pair[1].height, "one summary per height");
        }
        for summary in &kept {
            let signers = summary.signers.as_ref().expect("the committee resolves");
            assert!(!signers.is_empty());
            assert!(signers.iter().all(|s| validators.contains(s)));
            assert!(validators.contains(&summary.proposer));
        }
    }

    node0.stop().await.expect("host 0 stops cleanly");
    node1.stop().await.expect("host 1 stops cleanly");
}

/// A stopped host whose runtime is gone has closed its stores: the same
/// process starts it again on the same data, as an embedder restarting its
/// node does.
#[test]
#[serial]
fn a_stopped_host_starts_again_on_its_own_data() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(11, 4);
    let dir = TempDir::new().unwrap();
    let beacon_chain = network(None);
    let run = |first: bool| {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let node = Node::start(setup(
                dir.path(),
                &fixtures,
                &[0, 1, 2, 3],
                net::listen(free_port()),
                vec![],
                beacon_chain,
            ))
            .expect("the host starts on its own data");
            if first {
                timeout(COMMIT_TIMEOUT, async {
                    while lowest_height(&node).is_none_or(|h| h < 1) {
                        sleep(Duration::from_millis(200)).await;
                    }
                })
                .await
                .expect("the host commits before it stops");
            }
            node.stop().await.expect("the host stops cleanly");
        });
    };
    run(true);
    run(false);
}

/// A stopped host has closed its stores and its socket by the time `stop`
/// returns, while the caller's runtime and a connected peer live on: its
/// peer sees it leave, and the same process starts it again at once on the
/// same data, address and key, and it rejoins the peer.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_host_stopped_beside_a_live_peer_starts_again_at_once() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(11, 4);
    let (dir0, dir1) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let beacon_chain = network(None);
    let listen0 = net::listen(free_port());
    let dial0 = net::dial(&listen0);
    let node0 = Node::start(setup(
        dir0.path(),
        &fixtures,
        &[0, 1],
        listen0,
        vec![],
        beacon_chain,
    ))
    .expect("start host 0");
    let listen1 = net::listen(free_port());
    let start1 = || {
        Node::start(setup(
            dir1.path(),
            &fixtures,
            &[2, 3],
            listen1.clone(),
            vec![dial0.clone()],
            beacon_chain,
        ))
    };
    let reach = |node: &Node, target: u64| {
        let node_status = node.status();
        async move {
            timeout(COMMIT_TIMEOUT, async {
                loop {
                    let status = node_status.load_full();
                    let lowest = status.vnodes.iter().map(|v| v.block_height).min();
                    if lowest.is_some_and(|h| h >= target) {
                        return;
                    }
                    sleep(Duration::from_millis(200)).await;
                }
            })
            .await
        }
    };

    let node1 = start1().expect("start host 1");
    reach(&node1, TARGET_HEIGHT)
        .await
        .expect("host 1 commits beside its peer");
    node1.stop().await.expect("host 1 stops cleanly");
    let node0_status = node0.status();
    timeout(LEAVE_SEEN_WITHIN, async {
        while node0_status.load().connected_peers > 0 {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("host 0 sees host 1 leave before any idle timeout would tell it");

    let node1 = start1().expect("host 1 starts again on its own data");
    reach(&node1, TARGET_HEIGHT * 2)
        .await
        .expect("host 1 commits again beside its peer");

    node1.stop().await.expect("host 1 stops cleanly again");
    node0.stop().await.expect("host 0 stops cleanly");
}

/// A host runs on a runtime of its own, so a caller on any runtime starts
/// and stops one.
#[tokio::test(flavor = "current_thread")]
#[serial]
async fn a_current_thread_caller_starts_and_stops_a_host() {
    let fixtures = TestFixtures::new(11, 4);
    let dir = TempDir::new().unwrap();
    let node = Node::start(setup(
        dir.path(),
        &fixtures,
        &[0, 1, 2, 3],
        net::listen(free_port()),
        vec![],
        network(None),
    ))
    .expect("the host starts");
    node.stop().await.expect("the host stops cleanly");
}

/// The shortest epochs a chain may run, so a test sees the beacon adopt
/// several.
const SHORT_EPOCH_MS: u64 = 30_000;
/// How long a test watching epochs waits: twelve of them.
const EPOCHS_TIMEOUT: Duration = Duration::from_millis(SHORT_EPOCH_MS * 12);
/// The epoch each host's observation must have adopted.
const TARGET_EPOCH: u64 = 2;

/// The host's observations up to the target epoch: the last, and the
/// committee each published root tip said its child is proposed under.
async fn watch_to_target(
    node: &Node,
) -> (Arc<Observation>, BTreeMap<BlockHeight, Vec<ValidatorId>>) {
    let mut observe = node.observe();
    let mut proposing = BTreeMap::new();
    let last = timeout(EPOCHS_TIMEOUT, async {
        loop {
            observe.changed().await.expect("the host publishes");
            let Some(observation) = observe.borrow_and_update().clone() else {
                continue;
            };
            // Never an epoch past genesis published without its effects: a
            // fresh network adopts every one of them in this process.
            if observation.beacon.current_epoch.inner() > 0 {
                let (epoch, _) = observation
                    .effects
                    .back()
                    .expect("an adopted epoch carries its effects");
                assert_eq!(*epoch, observation.beacon.current_epoch);
            }
            if let (Some(tip), Some(committee)) = (
                observation.tips.get(&ShardId::ROOT),
                observation.proposing.get(&ShardId::ROOT),
            ) {
                proposing.insert(tip.height, committee.clone());
            }
            if observation.beacon.current_epoch.inner() >= TARGET_EPOCH {
                return observation;
            }
        }
    })
    .await
    .expect("the host adopts the target epoch");
    (last, proposing)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn each_observation_carries_its_epochs_effects() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(13, 4);
    let (dir0, dir1) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (node0, node1) = start_pair(
        [dir0.path(), dir1.path()],
        &fixtures,
        [&[0, 1], &[2, 3]],
        network(Some(SHORT_EPOCH_MS)),
    );

    // Watched together: a watch channel keeps only its newest value, so a
    // host awaited after the other would skip its early tips.
    let (watched0, watched1) = tokio::join!(watch_to_target(&node0), watch_to_target(&node1));
    let mut seen = Vec::new();
    for (node, (last, proposing)) in [(&node0, watched0), (&node1, watched1)] {
        let epochs: Vec<u64> = last.effects.iter().map(|(e, _)| e.inner()).collect();
        assert!(
            epochs.windows(2).all(|pair| pair[0] < pair[1]),
            "effects in epoch order: {epochs:?}"
        );
        assert!(last.tips.contains_key(&ShardId::ROOT));
        // The header after each published tip is proposed and signed by the
        // committee the tip said its child is proposed under.
        let kept = node.headers(ShardId::ROOT, BlockHeight::new(1));
        let mut checked = 0;
        for (height, committee) in &proposing {
            let Some(child) = kept.iter().find(|s| s.height == height.next()) else {
                continue;
            };
            assert!(committee.contains(&child.proposer));
            let signers = child.signers.as_ref().expect("the committee resolves");
            assert!(signers.iter().all(|s| committee.contains(s)));
            checked += 1;
        }
        assert!(checked > 0, "a published tip's child was kept");
        seen.push(last.genesis);
    }
    assert_eq!(seen[0], seen[1], "one network, one genesis");

    node0.stop().await.expect("host 0 stops cleanly");
    node1.stop().await.expect("host 1 stops cleanly");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_rotation_retires_the_head_of_the_published_order() {
    let _ = fmt().with_test_writer().try_init();
    // Five seated on the root shard and one pooled, so the beacon-eligible
    // set clears its floor and the shuffle has an entrant to draw. A
    // one-epoch ready timeout puts the first shuffle boundary at epoch 2.
    let fixtures = TestFixtures::with_surplus(17, 5, 1);
    let beacon_chain = BeaconChainConfig {
        shard_size: 5,
        ready_timeout_epochs: 1,
        ..network(Some(SHORT_EPOCH_MS))
    };
    let (dir0, dir1) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (node0, node1) = start_pair(
        [dir0.path(), dir1.path()],
        &fixtures,
        [&[0, 1, 2], &[3, 4, 5]],
        beacon_chain,
    );

    let mut observe = node0.observe();
    let mut published = BTreeMap::new();
    let (boundary, before, after) = timeout(EPOCHS_TIMEOUT, async {
        loop {
            observe.changed().await.expect("the host publishes");
            let Some(observation) = observe.borrow_and_update().clone() else {
                continue;
            };
            let epoch = observation.beacon.current_epoch;
            let opened = observation
                .beacon
                .pending_rotations
                .get(&ShardId::ROOT)
                .is_some_and(|rotations| rotations.values().any(|r| r.opened_at == epoch));
            if opened {
                let before = published
                    .remove(&(epoch.inner() - 1))
                    .expect("the epoch before the boundary was published");
                return (epoch, before, observation);
            }
            published.insert(epoch.inner(), observation);
        }
    })
    .await
    .expect("the root shard opens a rotation");

    // Nothing the boundary folded ahead of its shuffle moved the order.
    let (_, effects) = after
        .effects
        .iter()
        .find(|(epoch, _)| *epoch == boundary)
        .expect("the boundary's effects");
    assert!(effects.jailed.is_empty() && effects.readied.is_empty());
    assert_eq!(before.beacon.params, after.beacon.params);

    assert_eq!(before.answers.next_shuffle_epoch, boundary);
    let victims: Vec<ValidatorId> = after.beacon.pending_rotations[&ShardId::ROOT]
        .iter()
        .filter(|(_, rotation)| rotation.opened_at == boundary)
        .map(|(victim, _)| *victim)
        .collect();
    let order = &before.answers.rotation_order[&ShardId::ROOT];
    assert_eq!(victims, vec![order[0]], "order published: {order:?}");

    node0.stop().await.expect("host 0 stops cleanly");
    node1.stop().await.expect("host 1 stops cleanly");
}
