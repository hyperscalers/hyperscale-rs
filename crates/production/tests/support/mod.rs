//! Shared helpers for the production e2e test binaries, plus the two
//! harnesses: the bespoke QUIC + `RocksDB` [`harness`] and the portable
//! scenarios adaptor [`prod_cluster`] over it.
//!
//! The suites each compile their own copy of this module and use a
//! different subset, so a helper unused in any one binary isn't dead code.

#![allow(dead_code)]

pub mod harness;
pub mod prod_cluster;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_dispatch_pooled::ThreadPoolConfig;
use hyperscale_engine::GenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::{EndpointAddr, IrohConfig, SecretKey};
use hyperscale_production::{
    LocalValidator, Node, NodeSetup, StorageDirResolver, StorageFactory, shard_data_dir,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage_rocksdb::{RocksDbConfig, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, GenesisValidators, ShardId, ValidatorId, shard_prefix_path,
};
#[allow(unused_imports)] // the lifecycle binaries compile support but never drive the adaptor
pub use prod_cluster::ProdCluster;
use tempfile::TempDir;

/// Budget for a transport connection / validator-bind handshake to complete
/// over localhost QUIC.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// A loopback configuration bootstrapped to `bootstrap_peers`: no relay
/// and no port mapping, every host at a socket address the others are
/// told.
pub fn test_config(
    key: &SecretKey,
    bootstrap_peers: Vec<EndpointAddr>,
    simulated_outbound_latency: Duration,
) -> IrohConfig {
    IrohConfig {
        bootstrap_peers,
        simulated_outbound_latency,
        ..IrohConfig::for_testing(key.clone(), (Ipv4Addr::LOCALHOST, 0).into())
    }
}

/// A test host's setup: the given identity and network, on minimal thread
/// pools, a two-worker runtime and default stores, with every protocol
/// setting at its default.
pub fn test_setup(
    data_dir: PathBuf,
    validators: Vec<LocalValidator>,
    genesis: GenesisValidators,
    beacon_chain: BeaconChainConfig,
    engine_genesis: GenesisConfig,
    transport: IrohConfig,
) -> NodeSetup {
    NodeSetup {
        data_dir,
        validators,
        genesis,
        engine_genesis,
        beacon_chain,
        shard_consensus: ShardConsensusConfig::default(),
        mempool: MempoolConfig::default(),
        provisions: ProvisionConfig::default(),
        transport,
        threads: ThreadPoolConfig::minimal(),
        io_threads: 2,
        storage: RocksDbConfig::default(),
    }
}

/// `validators` (indices into `fixtures`' deterministic keys) with their
/// signers.
pub fn local_validators(fixtures: &TestFixtures, validators: &[u32]) -> Vec<LocalValidator> {
    validators
        .iter()
        .map(|&i| LocalValidator {
            validator_id: ValidatorId::new(u64::from(i)),
            signer: fixtures.signer(i),
        })
        .collect()
}

/// Start a one-host node at `data_dir` hosting `validators` of `fixtures`'
/// network on `beacon_chain`, bootstrapped to `bootstrap_peers` from a fresh
/// network key.
pub fn start_host_at(
    data_dir: &Path,
    fixtures: &TestFixtures,
    validators: &[u32],
    bootstrap_peers: Vec<EndpointAddr>,
    beacon_chain: BeaconChainConfig,
) -> Node {
    Node::start(test_setup(
        data_dir.to_path_buf(),
        local_validators(fixtures, validators),
        fixtures.genesis_validators(),
        beacon_chain,
        GenesisConfig::default(),
        test_config(&SecretKey::generate(), bootstrap_peers, Duration::ZERO),
    ))
    .expect("start the host")
}

/// [`start_host_at`] in a fresh temp dir, returned with the node: keep it
/// alive for the node's life.
pub fn start_host(
    fixtures: &TestFixtures,
    validators: &[u32],
    bootstrap_peers: Vec<EndpointAddr>,
    beacon_chain: BeaconChainConfig,
) -> (Node, TempDir) {
    let dir = TempDir::new().expect("temp dir");
    let node = start_host_at(
        dir.path(),
        fixtures,
        validators,
        bootstrap_peers,
        beacon_chain,
    );
    (node, dir)
}

/// Storage-directory resolver rooted in the test's temp dir. Runtime-joined
/// shards get `shard-d{depth}p{path}` directories, mirroring the validator
/// binary's data-dir convention.
pub fn temp_storage_dir(dir: &TempDir) -> StorageDirResolver {
    let root = dir.path().to_path_buf();
    Arc::new(move |shard: ShardId| shard_data_dir(&root, shard))
}

/// Storage factory opening a `RocksDbShardStorage` at whatever directory
/// the supervisor names.
pub fn temp_storage_factory() -> StorageFactory {
    Arc::new(|dir: &Path, shard: ShardId| {
        RocksDbShardStorage::open(dir, shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
}
