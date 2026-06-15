//! Production resharding end-to-end tests.
//!
//! Drives real beacon folds over a real libp2p cluster on real
//! `RocksDbShardStorage` to cover the production-only reshape wiring the
//! simulation suite never touches: the beacon fold → `ParticipationChange`
//! → `ShardSupervisor` duty chain and the `RocksDbShardStorage` flips.
//! Like `e2e_tests.rs` these are `#[serial]`, real-time, and bounded by
//! `timeout` — never fixed sleeps for assertions.

mod fixtures;

use std::collections::HashMap;
use std::sync::Arc;

use fixtures::TestFixtures;
use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{ProductionRunner, StorageDirResolver, StorageFactory, VnodeConfig};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, ReshapeThresholds, ShardId, ValidatorId, shard_prefix_path,
};
use serial_test::serial;
use tempfile::TempDir;
use tracing_subscriber::fmt;

/// Storage factory rooted in the test's temp dir, mirroring the
/// validator binary's `shard-{path}` data-dir convention.
fn temp_storage_dir(dir: &TempDir) -> StorageDirResolver {
    let root = dir.path().to_path_buf();
    Arc::new(move |shard: ShardId| root.join(format!("shard-d{}p{}", shard.depth(), shard.path())))
}

fn temp_storage_factory(dir: &TempDir) -> StorageFactory {
    let resolve = temp_storage_dir(dir);
    Arc::new(move |shard: ShardId| {
        RocksDbShardStorage::open(resolve(shard), shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
}

/// A custom `beacon_chain_config` threads through the builder into the
/// committed beacon genesis state. This is the single production hook the
/// rest of the reshape suite depends on: the default path (every
/// `e2e_tests.rs` test) leaves the setter unused and is unaffected, so a
/// custom `epoch_duration_ms` + reshape `split_bytes` reach the genesis
/// state only when set explicitly.
#[tokio::test]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(
        RocksDbShardStorage::open(
            temp_dir.path().join("test_db"),
            shard_prefix_path(ShardId::ROOT),
        )
        .unwrap(),
    );
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: 400,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 50_000,
        },
        ..BeaconChainConfig::default()
    };

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let runner = ProductionRunner::builder(
        vec![VnodeConfig {
            validator_id: ValidatorId::new(0),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([(ShardId::ROOT, storage)]),
        beacon_reader,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    )
    .beacon_chain_config(chain_config)
    .build();
    assert!(
        runner.is_ok(),
        "runner builds with a custom beacon chain config"
    );

    // Build commits the genesis (block, state) pair into the beacon store.
    let (_block, state) = beacon_storage
        .latest_committed()
        .expect("genesis pair committed at build time");
    assert_eq!(
        state.chain_config.epoch_duration_ms, 400,
        "custom epoch duration reaches the beacon genesis state"
    );
    assert_eq!(
        state.chain_config.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold reaches the beacon genesis state"
    );
}
