//! Snapshot-based tree store for concurrent JVT reads.

use std::sync::Arc;

use crate::column_families::{CfHandles, JvtNodesCf, StateCf};
use crate::jvt_stored::StoredNodeKey;
use crate::node_cache::NodeCache;
use crate::typed_cf::{self, TypedCf};

use hyperscale_storage::{DbPartitionKey, DbSortKey, StateRootHash, SubstateLookup};
use jellyfish_verkle_tree as jvt;
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
    /// Shared node cache for hydrated JVT nodes.
    node_cache: &'a NodeCache,
}

impl<'a> SnapshotTreeStore<'a> {
    /// Create a new snapshot-based tree store.
    ///
    /// Takes a RocksDB snapshot at the current point in time. All reads through
    /// this store will see the database state as of this moment, regardless of
    /// any concurrent writes.
    pub fn new(db: &'a DB, node_cache: &'a NodeCache) -> Self {
        Self {
            snapshot: db.snapshot(),
            db,
            node_cache,
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

impl jvt::TreeReader for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        // Fast path: serve from in-memory cache.
        if let Some(node) = self.node_cache.get(key) {
            return Some(node);
        }
        // Slow path: snapshot read + deserialize.
        let stored_key = StoredNodeKey::from_jvt(key);
        let cf = CfHandles::resolve(self.db);
        let node =
            typed_cf::get::<JvtNodesCf>(&self.snapshot, JvtNodesCf::handle(&cf), &stored_key)
                .map(|v| Arc::new(v.into_latest().to_jvt()));
        // Populate cache on miss so subsequent reads benefit.
        if let Some(ref n) = node {
            self.node_cache.insert(key.clone(), Arc::clone(n));
        }
        node
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        let root = jvt::NodeKey::root(version);
        if self.node_cache.get(&root).is_some() {
            return Some(root);
        }
        let stored_key = StoredNodeKey::from_jvt(&root);
        let cf = CfHandles::resolve(self.db);
        if typed_cf::get::<JvtNodesCf>(&self.snapshot, JvtNodesCf::handle(&cf), &stored_key)
            .is_some()
        {
            Some(root)
        } else {
            None
        }
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
