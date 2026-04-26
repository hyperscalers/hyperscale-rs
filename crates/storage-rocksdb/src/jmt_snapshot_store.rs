//! Snapshot-based tree store for concurrent JMT reads.

use std::sync::Arc;

use crate::column_families::{CfHandles, JmtNodesCf, StateCf};
use crate::jmt_stored::StoredNodeKey;
use crate::typed_cf::{self, TypedCf};

use hyperscale_jmt as jmt;
use hyperscale_storage::{DbPartitionKey, DbSortKey, StateRoot, SubstateLookup};
use rocksdb::{DB, Snapshot};

/// A tree store that reads JMT nodes from a `RocksDB` snapshot.
///
/// Provides point-in-time isolation: any nodes deleted by concurrent
/// block commits remain visible through this snapshot. This prevents
/// speculative JMT computation from reading nodes that are being deleted
/// by a concurrent commit.
///
/// # Lifetime
/// The snapshot must outlive all reads through this store. When dropped,
/// the snapshot releases its hold on the `RocksDB` version, allowing
/// garbage collection.
pub(crate) struct SnapshotTreeStore<'a> {
    snapshot: Snapshot<'a>,
    db: &'a DB,
}

impl<'a> SnapshotTreeStore<'a> {
    pub fn new(db: &'a DB) -> Self {
        Self {
            snapshot: db.snapshot(),
            db,
        }
    }

    /// Read the current substate value visible through this `RocksDB`
    /// snapshot. Used when collecting historical state associations
    /// during proof generation.
    pub fn get_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        let cf = CfHandles::resolve(self.db);
        let state_cf = StateCf::handle(&cf);
        // Direct point lookup on the unversioned state CF.
        let state_key = (partition_key.clone(), sort_key.clone());
        typed_cf::get::<StateCf>(&self.snapshot, state_cf, &state_key)
    }

    /// Read the JMT version and root hash from this snapshot. Uses the
    /// same `jmt:metadata` encoding as `RocksDbStorage`, so reads are
    /// atomic with respect to the nodes visible through this snapshot.
    ///
    /// Returns `(version, root_hash)`. For an empty tree, returns `(0, [0; 32])`.
    pub fn read_jmt_metadata(&self) -> (u64, StateRoot) {
        crate::metadata::read_jmt_metadata(&self.snapshot)
    }
}

impl jmt::TreeReader for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
        let stored_key = StoredNodeKey::from_jmt(key);
        let cf = CfHandles::resolve(self.db);
        typed_cf::get::<JmtNodesCf>(&self.snapshot, JmtNodesCf::handle(&cf), &stored_key)
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<jmt::NodeKey> {
        let root = jmt::NodeKey::root(version);
        let stored_key = StoredNodeKey::from_jmt(&root);
        let cf = CfHandles::resolve(self.db);
        if typed_cf::get::<JmtNodesCf>(&self.snapshot, JmtNodesCf::handle(&cf), &stored_key)
            .is_some()
        {
            Some(root)
        } else {
            None
        }
    }
}

impl SubstateLookup for SnapshotTreeStore<'_> {
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        self.get_substate(partition_key, sort_key)
    }
}
