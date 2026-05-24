//! Snapshot-based tree store for concurrent JMT reads.

use std::sync::Arc;

use hyperscale_jmt::{Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::{DbPartitionKey, DbSortKey, SubstateLookup};
use hyperscale_types::StateRoot;
use rocksdb::{ColumnFamily, DB, Snapshot};

use super::column_families::{CfHandles, JmtNodesCf, StateCf};
use super::jmt_stored::StoredNodeKey;
use super::metadata::read_jmt_metadata;
use crate::typed_cf::{self, TypedCf};

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
pub struct SnapshotTreeStore<'a> {
    snapshot: Snapshot<'a>,
    /// Pre-resolved at construction so repeated `TreeReader::get_node`
    /// calls don't re-walk all 12 column families per JMT node lookup.
    /// Proof generation walks O(log N) nodes per key; with K keys per
    /// proof and ~12 hashmap lookups per `CfHandles::resolve`, the
    /// uncached overhead grows quickly.
    jmt_nodes_cf: &'a ColumnFamily,
    state_cf: &'a ColumnFamily,
}

impl<'a> SnapshotTreeStore<'a> {
    pub fn new(db: &'a DB) -> Self {
        let cf = CfHandles::resolve(db);
        Self {
            snapshot: db.snapshot(),
            jmt_nodes_cf: JmtNodesCf::handle(&cf),
            state_cf: StateCf::handle(&cf),
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
        let state_key = (partition_key.clone(), sort_key.clone());
        typed_cf::get::<StateCf>(&self.snapshot, self.state_cf, &state_key)
    }

    /// Read the JMT version and root hash from this snapshot. Uses the
    /// same `jmt:metadata` encoding as `RocksDbShardStorage`, so reads are
    /// atomic with respect to the nodes visible through this snapshot.
    ///
    /// Returns `(version, root_hash)`. For an empty tree, returns `(0, [0; 32])`.
    pub fn read_jmt_metadata(&self) -> (u64, StateRoot) {
        read_jmt_metadata(&self.snapshot)
    }
}

impl TreeReader for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        let stored_key = StoredNodeKey::from_jmt(key);
        typed_cf::get::<JmtNodesCf>(&self.snapshot, self.jmt_nodes_cf, &stored_key)
            .map(|v| Arc::new(v.into_latest().to_jmt()))
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        let root = JmtNodeKey::root(version);
        let stored_key = StoredNodeKey::from_jmt(&root);
        if typed_cf::get::<JmtNodesCf>(&self.snapshot, self.jmt_nodes_cf, &stored_key).is_some() {
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
