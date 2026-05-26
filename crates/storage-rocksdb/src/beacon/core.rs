//! Core `RocksDbBeaconStorage` struct.
//!
//! The beacon `RocksDB` instance lives in its own directory and is
//! independent of the per-shard tier. One handle is shared across every
//! vnode's `BeaconCoordinator` via `Arc`; the `commit_lock` serialises
//! writes from concurrent emits without blocking reads.

use std::path::Path;
use std::sync::{Arc, Mutex};

use hyperscale_types::{BeaconState, CertifiedBeaconBlock};
use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch, WriteOptions};

use super::column_families::{
    ALL_COLUMN_FAMILIES, BeaconBlocksByEpochCf, BeaconHashToEpochCf, BeaconStateByEpochCf,
    CfHandles,
};
use crate::StorageError;
use crate::config::RocksDbConfig;
use crate::typed_cf::{TypedCf, batch_put, get};

/// `RocksDB`-backed beacon-chain storage.
///
/// Persists committed [`BeaconBlock`](hyperscale_types::BeaconBlock)s
/// alongside their resulting
/// [`BeaconState`](hyperscale_types::BeaconState) in three column
/// families: a primary `epoch → block` store, a secondary
/// `block_hash → epoch` index, and a parallel `epoch → state` store.
/// Writes go through a single atomic `WriteBatch` per commit so the
/// secondary index and the state row never lag the primary block row.
pub struct RocksDbBeaconStorage {
    pub(super) db: Arc<DB>,
    /// Serialises commits so concurrent multi-vnode emits land in a
    /// deterministic order. Reads run lock-free; idempotent commits
    /// of the same `(epoch, hash, state_root)` no-op at the storage
    /// level.
    pub(super) commit_lock: Mutex<()>,
}

impl RocksDbBeaconStorage {
    /// Open or create the beacon-chain database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if `RocksDB` fails to open the database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Self::open_with_config(path, &RocksDbConfig::default())
    }

    /// Open the beacon-chain database with a custom `RocksDB` config.
    ///
    /// Reuses the workspace-wide [`RocksDbConfig`] surface; beacon's
    /// access patterns are write-cold (one commit per beacon epoch,
    /// minutes apart) so the shard tier's per-CF tuning isn't worth
    /// porting here.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if `RocksDB` fails to open the database.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        config: &RocksDbConfig,
    ) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_background_jobs(config.max_background_jobs);
        opts.set_keep_log_file_num(config.keep_log_file_num);
        opts.set_compression_type(config.compression.to_rocksdb());

        let cf_descriptors: Vec<_> = ALL_COLUMN_FAMILIES
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Validate all expected column families exist at startup so we
        // fail fast instead of panicking on first access at runtime.
        CfHandles::resolve(&db);

        Ok(Self {
            db: Arc::new(db),
            commit_lock: Mutex::new(()),
        })
    }

    /// Resolve typed column-family handles. Cheap (`HashMap` lookups).
    pub(super) fn cf(&self) -> CfHandles<'_> {
        CfHandles::resolve(&self.db)
    }

    /// Typed get against the beacon backend.
    pub(super) fn cf_get<CF>(&self, key: &CF::Key) -> Option<CF::Value>
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        get::<CF>(&*self.db, CF::handle(&self.cf()), key)
    }

    /// Typed put into a `WriteBatch` against the beacon backend.
    pub(super) fn cf_batch_put<CF>(&self, batch: &mut WriteBatch, key: &CF::Key, value: &CF::Value)
    where
        for<'a> CF: TypedCf<Handles<'a> = CfHandles<'a>>,
    {
        batch_put::<CF>(batch, CF::handle(&self.cf()), key, value);
    }

    /// Convenience for committing one (block, state) pair atomically:
    /// typed writes for all three CFs in a single `WriteBatch`, flushed
    /// sync under `commit_lock`.
    pub(super) fn commit_block_inner(&self, block: &CertifiedBeaconBlock, state: &BeaconState) {
        let _guard = self
            .commit_lock
            .lock()
            .expect("beacon commit_lock poisoned");
        let epoch = block.epoch().inner();
        let mut batch = WriteBatch::default();
        self.cf_batch_put::<BeaconBlocksByEpochCf>(&mut batch, &epoch, block);
        self.cf_batch_put::<BeaconHashToEpochCf>(
            &mut batch,
            &block.block_hash().into_raw(),
            &epoch,
        );
        self.cf_batch_put::<BeaconStateByEpochCf>(&mut batch, &epoch, state);
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: beacon commit write failed");
    }
}
