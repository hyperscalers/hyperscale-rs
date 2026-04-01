//! Snapshot-based tree store for concurrent JVT reads.

use crate::column_families::{CfHandles, JvtNodesCf, StateCf};
use crate::typed_cf::{self, TypedCf};

use hyperscale_storage::{
    jmt::{ReadableTreeStore, StoredNode, StoredNodeKey},
    DbPartitionKey, DbSortKey, StateRootHash, SubstateLookup,
};
use rocksdb::{Snapshot, DB};

/// A tree store that reads JVT nodes from a RocksDB snapshot.
///
/// This provides point-in-time isolation for JVT reads: any nodes deleted by
/// concurrent block commits remain visible through this snapshot. This prevents
/// the race condition where speculative JVT computation reads nodes that are
/// being deleted by a concurrent commit.
///
/// # Lifetime
/// The snapshot must outlive all reads through this store. When dropped, the
/// snapshot releases its hold on the RocksDB version, allowing garbage collection.
pub(crate) struct SnapshotTreeStore<'a> {
    /// RocksDB snapshot for point-in-time reads.
    snapshot: Snapshot<'a>,
    /// Reference to the DB for column family handles.
    db: &'a DB,
}

impl<'a> SnapshotTreeStore<'a> {
    /// Create a new snapshot-based tree store.
    ///
    /// Takes a RocksDB snapshot at the current point in time. All reads through
    /// this store will see the database state as of this moment, regardless of
    /// any concurrent writes.
    pub fn new(db: &'a DB) -> Self {
        Self {
            snapshot: db.snapshot(),
            db,
        }
    }

    /// Read a substate value from this snapshot.
    ///
    /// Used to look up unchanged substate values when
    /// collecting historical state associations.
    pub fn get_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        let cf = CfHandles::resolve(self.db);
        typed_cf::get::<StateCf>(
            &self.snapshot,
            StateCf::handle(&cf),
            &(partition_key.clone(), sort_key.clone()),
        )
    }

    /// Read the JVT version and root hash from this snapshot.
    ///
    /// Uses the same single-key `jmt:metadata` encoding as `RocksDbStorage`,
    /// ensuring atomicity and consistency with the nodes visible through
    /// this snapshot.
    ///
    /// Returns `(version, root_hash)`. For an empty/uninitialized JVT, returns `(0, [0; 32])`.
    pub fn read_jvt_metadata(&self) -> (u64, StateRootHash) {
        crate::metadata::read_jvt_metadata(&self.snapshot)
    }
}

impl ReadableTreeStore for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &StoredNodeKey) -> Option<StoredNode> {
        let cf = CfHandles::resolve(self.db);
        typed_cf::get::<JvtNodesCf>(&self.snapshot, JvtNodesCf::handle(&cf), key)
            .map(|v| v.into_latest())
    }

    fn get_nodes_batch(&self, keys: &[StoredNodeKey]) -> Vec<Option<StoredNode>> {
        let cf = CfHandles::resolve(self.db);
        typed_cf::multi_get::<JvtNodesCf>(&self.snapshot, JvtNodesCf::handle(&cf), keys)
            .into_iter()
            .map(|opt| opt.map(|v| v.into_latest()))
            .collect()
    }
}

// SubstateLookup implementation for snapshot-based historical value lookup.
impl SubstateLookup for SnapshotTreeStore<'_> {
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        self.get_substate(partition_key, sort_key)
    }
}
