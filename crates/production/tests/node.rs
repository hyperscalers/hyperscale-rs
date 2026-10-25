//! The library front door: hosts started through `Node::start` alone, as an
//! embedder starts them. Each host's address is fixed before it starts (a
//! chosen port, and on iroh a chosen key), so the second host can be pointed at
//! the first without reaching into the transport.

use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyperscale_dispatch_pooled::ThreadPoolConfig;
use hyperscale_engine::GenesisConfig as EngineGenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_production::{LocalValidator, Node, NodeError, NodeSetup};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage_rocksdb::RocksDbConfig;
use hyperscale_types::{BeaconChainConfig, BlockHeight, ShardId, ValidatorId};
use serial_test::serial;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

/// How long a fresh four-validator network gets to commit its first blocks.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(60);
/// The height every hosted validator must reach.
const TARGET_HEIGHT: u64 = 3;

/// A localhost QUIC port nothing holds right now.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("bind a free port")
        .port()
}

/// Where a host listens and what another host dials to reach it.
#[cfg(feature = "iroh")]
mod net {
    use std::net::{Ipv4Addr, SocketAddr};

    pub use hyperscale_network_iroh::test_utils::TestFixtures;
    use hyperscale_network_iroh::{EndpointAddr, IrohConfig, SecretKey};

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

/// Where a host listens and what another host dials to reach it.
#[cfg(not(feature = "iroh"))]
mod net {
    use hyperscale_network_libp2p::Libp2pConfig;
    pub use hyperscale_network_libp2p::test_utils::TestFixtures;
    use libp2p::Multiaddr;

    pub type Listen = Multiaddr;
    pub type Dial = Multiaddr;

    pub fn listen(port: u16) -> Listen {
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .expect("a QUIC multiaddr")
    }

    pub fn dial(listen: &Listen) -> Dial {
        listen.clone()
    }

    pub fn config(listen: Listen, bootstrap_peers: Vec<Dial>) -> Libp2pConfig {
        Libp2pConfig {
            listen_addresses: vec![listen],
            bootstrap_peers,
            ..Default::default()
        }
    }
}

use net::{Dial, Listen, TestFixtures};

fn setup(
    data_dir: &Path,
    fixtures: &TestFixtures,
    validators: &[u32],
    listen: Listen,
    bootstrap_peers: Vec<Dial>,
    beacon_chain: BeaconChainConfig,
) -> NodeSetup {
    NodeSetup {
        data_dir: data_dir.to_path_buf(),
        validators: validators
            .iter()
            .map(|&i| LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signer: fixtures.signer(i),
            })
            .collect(),
        genesis: fixtures.genesis_validators(),
        engine_genesis: EngineGenesisConfig::default(),
        beacon_chain,
        shard_consensus: ShardConsensusConfig::default(),
        mempool: MempoolConfig::default(),
        provisions: ProvisionConfig::default(),
        transport: net::config(listen, bootstrap_peers),
        threads: ThreadPoolConfig::minimal(),
        storage: RocksDbConfig::default(),
    }
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

/// Two hosts of two co-hosted validators each, the second pointed at the
/// first.
fn start_pair(
    dir0: &Path,
    dir1: &Path,
    fixtures: &TestFixtures,
    epoch_duration_ms: Option<u64>,
) -> (Node, Node) {
    let beacon_chain = network(epoch_duration_ms);
    let listen0 = net::listen(free_port());
    let dial0 = net::dial(&listen0);
    let node0 = Node::start(setup(
        dir0,
        fixtures,
        &[0, 1],
        listen0,
        vec![],
        beacon_chain,
    ))
    .expect("start host 0");
    let node1 = Node::start(setup(
        dir1,
        fixtures,
        &[2, 3],
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
    let (node0, node1) = start_pair(dir0.path(), dir1.path(), &fixtures, None);

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

#[tokio::test(flavor = "current_thread")]
async fn a_current_thread_runtime_is_refused() {
    let fixtures = TestFixtures::new(11, 4);
    let dir = TempDir::new().unwrap();
    let started = Node::start(setup(
        dir.path(),
        &fixtures,
        &[0],
        net::listen(free_port()),
        vec![],
        network(None),
    ));
    assert!(matches!(started, Err(NodeError::Runtime)));
}

/// Five-second epochs, so a test sees the beacon adopt several.
const SHORT_EPOCH_MS: u64 = 5_000;
/// The epoch each host's observation must have adopted.
const TARGET_EPOCH: u64 = 2;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn each_observation_carries_its_epochs_effects() {
    let _ = fmt().with_test_writer().try_init();
    let fixtures = TestFixtures::new(13, 4);
    let (dir0, dir1) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (node0, node1) = start_pair(dir0.path(), dir1.path(), &fixtures, Some(SHORT_EPOCH_MS));

    let mut seen = Vec::new();
    for node in [&node0, &node1] {
        let mut observe = node.observe();
        let last = timeout(COMMIT_TIMEOUT, async {
            loop {
                observe.changed().await.expect("the host publishes");
                let Some(observation) = observe.borrow_and_update().clone() else {
                    continue;
                };
                // Never an epoch past genesis published without its effects:
                // a fresh network adopts every one of them in this process.
                if observation.beacon.current_epoch.inner() > 0 {
                    let (epoch, _) = observation
                        .effects
                        .back()
                        .expect("an adopted epoch carries its effects");
                    assert_eq!(*epoch, observation.beacon.current_epoch);
                }
                if observation.beacon.current_epoch.inner() >= TARGET_EPOCH {
                    return observation;
                }
            }
        })
        .await
        .expect("the host adopts the target epoch");
        let epochs: Vec<u64> = last.effects.iter().map(|(e, _)| e.inner()).collect();
        assert!(
            epochs.windows(2).all(|pair| pair[0] < pair[1]),
            "effects in epoch order: {epochs:?}"
        );
        assert!(last.tips.contains_key(&ShardId::ROOT));
        seen.push(last.genesis);
    }
    assert_eq!(seen[0], seen[1], "one network, one genesis");

    node0.stop().await.expect("host 0 stops cleanly");
    node1.stop().await.expect("host 1 stops cleanly");
}
