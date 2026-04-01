//! Snapshot-based tree store for concurrent JVT reads.

use crate::config::CfHandles;
use hyperscale_storage::{
    jmt::{
        encode_key as encode_jvt_key, ReadableTreeStore, StoredNode, StoredNodeKey,
        VersionedStoredNode,
    },
    keys, DbPartitionKey, DbSortKey, StateRootHash, SubstateLookup,
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
        let key = keys::to_storage_key(partition_key, sort_key);
        self.snapshot
            .get_cf(CfHandles::resolve(self.db).state, &key)
            .expect("RocksDB snapshot read failure on state CF")
            .map(|v| v.to_vec())
    }

    /// Read the JVT version and root hash from this snapshot.
    ///
    /// Uses the same single-key `jmt:metadata` encoding as `RocksDbStorage`,
    /// ensuring atomicity and consistency with the nodes visible through
    /// this snapshot.
    ///
    /// Returns `(version, root_hash)`. For an empty/uninitialized JVT, returns `(0, [0; 32])`.
    pub fn read_jvt_metadata(&self) -> (u64, StateRootHash) {
        crate::core::decode_jvt_metadata(
            self.snapshot
                .get(b"jmt:metadata")
                .expect("BFT CRITICAL: failed to read jmt:metadata from snapshot"),
        )
    }
}

impl ReadableTreeStore for SnapshotTreeStore<'_> {
    fn get_node(&self, key: &StoredNodeKey) -> Option<StoredNode> {
        let encoded_key = encode_jvt_key(key);
        self.snapshot
            .get_cf(CfHandles::resolve(self.db).jvt_nodes, &encoded_key)
            .expect("RocksDB snapshot read failure on jmt_nodes CF")
            .map(|bytes| {
                sbor::basic_decode::<VersionedStoredNode>(&bytes)
                    .unwrap_or_else(|e| panic!("JVT node corruption detected: {e:?}"))
                    .into_latest()
            })
    }

    fn get_nodes_batch(&self, keys: &[StoredNodeKey]) -> Vec<Option<StoredNode>> {
        let cf = CfHandles::resolve(self.db).jvt_nodes;
        let encoded_keys: Vec<Vec<u8>> = keys.iter().map(encode_jvt_key).collect();
        let cf_keys: Vec<_> = encoded_keys.iter().map(|k| (cf, k.as_slice())).collect();
        self.snapshot
            .multi_get_cf(cf_keys)
            .into_iter()
            .map(|result| {
                result
                    .expect("RocksDB snapshot batch read failure on jmt_nodes CF")
                    .map(|bytes| {
                        sbor::basic_decode::<VersionedStoredNode>(&bytes)
                            .unwrap_or_else(|e| panic!("JVT node corruption detected: {e:?}"))
                            .into_latest()
                    })
            })
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
