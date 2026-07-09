//! Shared helpers for the production e2e test binaries, plus the two
//! harnesses: the bespoke QUIC + `RocksDB` [`cluster`] and the portable
//! scenarios adaptor [`prod_cluster`] over it.
//!
//! The suites each compile their own copy of this module and use a
//! different subset, so a helper unused in any one binary isn't dead code.

#![allow(dead_code)]

pub mod cluster;
pub mod prod_cluster;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::{
    LocalValidator, ProductionRunner, StorageDirResolver, StorageFactory, shard_data_dir,
};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::BeaconStorage;
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{BeaconChainConfig, ShardId, ValidatorId, shard_prefix_path};
use libp2p::Multiaddr;
use tempfile::TempDir;

/// Budget for a transport connection / validator-bind handshake to complete
/// over localhost QUIC.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a one-host production runner hosting `validators` (indices into
/// `fixtures`' deterministic keys), bootstrapped to `bootstrap_peers`. The
/// adapter binds localhost QUIC and starts peering at build; the caller spawns
/// the runner. Returns the runner, the temp dir its stores live in (keep it
/// alive for the runner's lifetime), and its beacon store for tests that read
/// committed beacon state.
pub fn build_runner(
    fixtures: &TestFixtures,
    validators: &[u32],
    bootstrap_peers: Vec<Multiaddr>,
    beacon_chain_config: Option<BeaconChainConfig>,
) -> (ProductionRunner, TempDir, Arc<RocksDbBeaconStorage>) {
    let temp_dir = TempDir::new().expect("temp dir");
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers,
        ..Default::default()
    };
    let beacon_storage = Arc::new(
        RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).expect("open beacon db"),
    );
    let local_validators = validators
        .iter()
        .map(|&i| LocalValidator {
            validator_id: ValidatorId::new(u64::from(i)),
            signing_key: fixtures.signing_key(i),
        })
        .collect();
    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let mut builder = ProductionRunner::builder(
        local_validators,
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_reader,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    );
    if let Some(cfg) = beacon_chain_config {
        builder = builder.beacon_chain_config(cfg);
    }
    let runner = builder.build().expect("build runner");
    (runner, temp_dir, beacon_storage)
}

/// Storage-directory resolver rooted in the test's temp dir. Runtime-joined
/// shards get `shard-d{depth}p{path}` directories, mirroring the validator
/// binary's data-dir convention.
pub fn temp_storage_dir(dir: &TempDir) -> StorageDirResolver {
    let root = dir.path().to_path_buf();
    Arc::new(move |shard: ShardId| shard_data_dir(&root, shard))
}

/// Storage factory rooted in the test's temp dir, opening a fresh
/// `RocksDbShardStorage` for any shard the supervisor joins at runtime.
pub fn temp_storage_factory(dir: &TempDir) -> StorageFactory {
    let resolve = temp_storage_dir(dir);
    Arc::new(move |shard: ShardId| {
        RocksDbShardStorage::open(resolve(shard), shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
}
