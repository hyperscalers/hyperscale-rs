//! Shared helpers for the production e2e test binaries.
//!
//! The network, validator-bind, runner, and multi-vnode suites each compile
//! their own copy of this module and use a different subset, so a helper
//! unused in any one binary isn't dead code.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network::ValidatorKeyMap;
use hyperscale_production::{StorageDirResolver, StorageFactory};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    Bls12381G1PrivateKey, ShardId, ValidatorId, generate_bls_keypair, shard_prefix_path,
};
use tempfile::TempDir;

/// Budget for a transport connection / validator-bind handshake to complete
/// over localhost QUIC.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Create a dummy bind signing key + validator key map for tests that create
/// adapters directly. Returns the BLS signing key (consumed by the
/// validator-bind service to produce per-session signatures) plus the keymap
/// that will verify signatures from this validator.
pub fn test_bind_args(
    validator_id: ValidatorId,
) -> (Arc<Bls12381G1PrivateKey>, Arc<ValidatorKeyMap>) {
    let bls_key = generate_bls_keypair();
    let pubkey = bls_key.public_key();
    let mut keys = ValidatorKeyMap::new();
    keys.insert(validator_id, pubkey);
    (Arc::new(bls_key), Arc::new(keys))
}

/// Storage-directory resolver rooted in the test's temp dir. Runtime-joined
/// shards get `shard-d{depth}p{path}` directories, mirroring the validator
/// binary's data-dir convention.
pub fn temp_storage_dir(dir: &TempDir) -> StorageDirResolver {
    let root = dir.path().to_path_buf();
    Arc::new(move |shard: ShardId| root.join(format!("shard-d{}p{}", shard.depth(), shard.path())))
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
