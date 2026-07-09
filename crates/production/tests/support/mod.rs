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

use hyperscale_production::{StorageDirResolver, StorageFactory, shard_data_dir};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{ShardId, shard_prefix_path};
use tempfile::TempDir;

/// Budget for a transport connection / validator-bind handshake to complete
/// over localhost QUIC.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

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
