//! Layered substate reader for unpersisted block state.
//!
//! [`SubstateOverlay`] wraps a base [`SubstateStore`] and overlays
//! pending [`DatabaseUpdates`] from blocks that have been committed by
//! consensus but not yet written to RocksDB. Reads check the overlay
//! first, falling through to the base for keys not covered.
//!
//! This is the substate analogue of [`OverlayTreeReader`](crate::tree::OverlayTreeReader)
//! (which does the same for JVT tree nodes).

use crate::{DatabaseUpdates, DbPartitionKey, DbSortKey, PartitionDatabaseUpdates, SubstateStore};
use ::jellyfish_verkle_tree as jvt;
use hyperscale_types::{Hash, NodeId, VerkleInclusionProof};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::SubstateDatabase;
use std::collections::HashMap;
use std::sync::Arc;

/// Flattened overlay entries: `(partition_key, sort_key) → Some(value)` or `None` (tombstone).
type OverlayEntries = HashMap<(DbPartitionKey, DbSortKey), Option<Vec<u8>>>;

/// Flatten a slice of `DatabaseUpdates` into overlay entries.
///
/// Updates should be in commit order (earliest first). Later entries
/// override earlier ones for the same key.
fn flatten_updates(updates: &[&DatabaseUpdates]) -> OverlayEntries {
    let mut entries = HashMap::new();
    for db_updates in updates {
        for (node_key, node_updates) in &db_updates.node_updates {
            for (&partition_num, partition_updates) in &node_updates.partition_updates {
                let pk = DbPartitionKey {
                    node_key: node_key.clone(),
                    partition_num,
                };
                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let value = match update {
                                DatabaseUpdate::Set(v) => Some(v.clone()),
                                DatabaseUpdate::Delete => None,
                            };
                            entries.insert((pk.clone(), sort_key.clone()), value);
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        entries.retain(|(epk, _), _| epk != &pk);
                        for (sort_key, value) in new_substate_values {
                            entries.insert((pk.clone(), sort_key.clone()), Some(value.clone()));
                        }
                    }
                }
            }
        }
    }
    entries
}

/// Apply overlay entries on top of a `SubstateDatabase` read.
fn overlay_get(
    entries: &OverlayEntries,
    base: &dyn SubstateDatabase,
    partition_key: &DbPartitionKey,
    sort_key: &DbSortKey,
) -> Option<Vec<u8>> {
    if let Some(v) = entries.get(&(partition_key.clone(), sort_key.clone())) {
        return v.clone();
    }
    base.get_raw_substate_by_db_key(partition_key, sort_key)
}

/// Apply overlay entries on top of a `SubstateDatabase` list.
fn overlay_list<'a>(
    entries: &'a OverlayEntries,
    base: &'a dyn SubstateDatabase,
    partition_key: &DbPartitionKey,
    from_sort_key: Option<&DbSortKey>,
) -> Vec<(DbSortKey, Vec<u8>)> {
    let mut overlay_for_partition: Vec<(DbSortKey, Option<Vec<u8>>)> = entries
        .iter()
        .filter(|((pk, _), _)| pk == partition_key)
        .filter(|((_, sk), _)| from_sort_key.is_none_or(|from| sk >= from))
        .map(|((_, sk), v)| (sk.clone(), v.clone()))
        .collect();
    overlay_for_partition.sort_by(|(a, _), (b, _)| a.cmp(b));

    let overlay_keys: std::collections::HashSet<DbSortKey> = overlay_for_partition
        .iter()
        .map(|(sk, _)| sk.clone())
        .collect();

    let base_entries: Vec<(DbSortKey, Vec<u8>)> = base
        .list_raw_values_from_db_key(partition_key, from_sort_key)
        .filter(|(sk, _)| !overlay_keys.contains(sk))
        .collect();

    let overlay_live: Vec<(DbSortKey, Vec<u8>)> = overlay_for_partition
        .into_iter()
        .filter_map(|(sk, v)| v.map(|val| (sk, val)))
        .collect();

    let mut merged = Vec::with_capacity(overlay_live.len() + base_entries.len());
    merged.extend(overlay_live);
    merged.extend(base_entries);
    merged.sort_by(|(a, _), (b, _)| a.cmp(b));
    merged
}

/// JVT node index: `NodeKey → Arc<Node>` for O(1) lookup during proof generation.
type JvtNodeIndex = HashMap<jvt::NodeKey, Arc<jvt::Node>>;

/// Layered substate store with JVT overlay for unpersisted blocks.
///
/// Wraps a base `SubstateStore` with in-memory changes from blocks
/// committed by consensus but not yet persisted to RocksDB. Implements
/// `SubstateStore`, `ChainWriter`, `ChainReader`, and `TreeReader` so
/// it can substitute for the base storage in all delegated action handlers.
///
/// Uses `Arc` internally so snapshots share overlay entries cheaply.
pub struct SubstateOverlay<S> {
    base: Arc<S>,
    /// Flattened overlay for current-state `SubstateDatabase` reads.
    entries: Arc<OverlayEntries>,
    /// Height-keyed updates for historical `list_substates_for_node_at_height`.
    /// Sorted by height ascending. Used to layer unpersisted changes on top
    /// of the base's MVCC scan result.
    versioned_updates: Arc<Vec<(u64, Arc<DatabaseUpdates>)>>,
    /// Pre-built JVT node index from unpersisted snapshots.
    /// O(1) lookup instead of linear scan through snapshot vecs.
    jvt_nodes: Arc<JvtNodeIndex>,
}

impl<S> SubstateOverlay<S> {
    /// Build an overlay from an `Arc`-wrapped base store, height-keyed
    /// database updates, and pending JVT snapshots.
    ///
    /// `updates` should be `(block_height, Arc<DatabaseUpdates>)` sorted by
    /// height ascending. No cloning of `DatabaseUpdates` — only `Arc` bumps.
    ///
    /// `jvt_snapshots` are pending tree snapshots from unpersisted blocks.
    /// Their nodes are indexed into a HashMap for O(1) lookup during proof
    /// generation (same approach as `OverlayTreeReader`).
    pub fn new(
        base: Arc<S>,
        updates: Vec<(u64, Arc<DatabaseUpdates>)>,
        jvt_snapshots: Vec<Arc<crate::JvtSnapshot>>,
    ) -> Self {
        let refs: Vec<&DatabaseUpdates> = updates.iter().map(|(_, u)| u.as_ref()).collect();

        // Build JVT node index from all snapshots (same as OverlayTreeReader::new).
        let mut jvt_nodes = HashMap::new();
        for snap in &jvt_snapshots {
            for (key, node) in &snap.nodes {
                jvt_nodes.insert(key.clone(), Arc::clone(node));
            }
        }

        Self {
            base,
            entries: Arc::new(flatten_updates(&refs)),
            versioned_updates: Arc::new(updates),
            jvt_nodes: Arc::new(jvt_nodes),
        }
    }
}

impl<S: SubstateDatabase> SubstateDatabase for SubstateOverlay<S> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        overlay_get(&self.entries, &*self.base, partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        Box::new(overlay_list(&self.entries, &*self.base, partition_key, from_sort_key).into_iter())
    }
}

/// Snapshot from a `SubstateOverlay` — overlays the same entries on the
/// base storage's snapshot.
pub struct OverlaySnapshot<Snap> {
    base_snapshot: Snap,
    entries: Arc<OverlayEntries>,
}

impl<Snap: SubstateDatabase> SubstateDatabase for OverlaySnapshot<Snap> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        overlay_get(&self.entries, &self.base_snapshot, partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        Box::new(
            overlay_list(
                &self.entries,
                &self.base_snapshot,
                partition_key,
                from_sort_key,
            )
            .into_iter(),
        )
    }
}

impl<S: SubstateStore> SubstateStore for SubstateOverlay<S> {
    type Snapshot<'a>
        = OverlaySnapshot<S::Snapshot<'a>>
    where
        Self: 'a;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        OverlaySnapshot {
            base_snapshot: (*self.base).snapshot(),
            entries: Arc::clone(&self.entries),
        }
    }

    fn jvt_version(&self) -> u64 {
        (*self.base).jvt_version()
    }

    fn state_root_hash(&self) -> Hash {
        (*self.base).state_root_hash()
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        let persisted_version = (*self.base).jvt_version();

        // If the requested height is within persisted range, delegate directly.
        if block_height <= persisted_version {
            return (*self.base).list_substates_for_node_at_height(node_id, block_height);
        }

        // Get base result at the persisted version (latest available on disk).
        let base_result =
            (*self.base).list_substates_for_node_at_height(node_id, persisted_version);

        // Build a map from base result, then apply overlay updates up to block_height.
        let entity_key = crate::keys::node_entity_key(node_id);
        let mut substates: HashMap<(u8, DbSortKey), Vec<u8>> = base_result
            .unwrap_or_default()
            .into_iter()
            .map(|(part, sk, v)| ((part, sk), v))
            .collect();

        // Apply each unpersisted block's updates up to the requested height.
        for (h, updates) in self.versioned_updates.iter() {
            if *h > block_height {
                break;
            }
            if let Some(node_updates) = updates.node_updates.get(&entity_key) {
                for (&partition_num, partition_updates) in &node_updates.partition_updates {
                    match partition_updates {
                        PartitionDatabaseUpdates::Delta { substate_updates } => {
                            for (sort_key, update) in substate_updates {
                                match update {
                                    DatabaseUpdate::Set(v) => {
                                        substates
                                            .insert((partition_num, sort_key.clone()), v.clone());
                                    }
                                    DatabaseUpdate::Delete => {
                                        substates.remove(&(partition_num, sort_key.clone()));
                                    }
                                }
                            }
                        }
                        PartitionDatabaseUpdates::Reset {
                            new_substate_values,
                        } => {
                            substates.retain(|(p, _), _| *p != partition_num);
                            for (sort_key, value) in new_substate_values {
                                substates.insert((partition_num, sort_key.clone()), value.clone());
                            }
                        }
                    }
                }
            }
        }

        Some(
            substates
                .into_iter()
                .map(|((p, sk), v)| (p, sk, v))
                .collect(),
        )
    }

    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<VerkleInclusionProof> {
        // Try base first — works for heights already persisted.
        if let Some(proof) = (*self.base).generate_verkle_proofs(storage_keys, block_height) {
            return Some(proof);
        }
        // Base returned None — height is beyond persisted. Use self as
        // TreeReader (overlays JVT snapshots on top of base).
        None
    }
}

/// Override `generate_verkle_proofs` when `S` implements `TreeReader`,
/// using the JVT snapshots for unpersisted heights.
impl<S: SubstateStore + jvt::TreeReader + Sync> SubstateOverlay<S> {
    /// Generate verkle proofs, falling back to the JVT overlay for
    /// unpersisted block heights.
    pub fn generate_verkle_proofs_overlay(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<VerkleInclusionProof> {
        // Try base first.
        if let Some(proof) = (*self.base).generate_verkle_proofs(storage_keys, block_height) {
            return Some(proof);
        }
        // Use self as TreeReader — overlays JVT snapshots on base.
        crate::tree::proofs::generate_proof(self, storage_keys, block_height)
    }
}

impl<S: jvt::TreeReader + Sync> jvt::TreeReader for SubstateOverlay<S> {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        self.jvt_nodes
            .get(key)
            .cloned()
            .or_else(|| (*self.base).get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        let root_key = jvt::NodeKey::root(version);
        if self.jvt_nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            (*self.base).get_root_key(version)
        }
    }
}

impl<S: crate::ChainWriter> crate::ChainWriter for SubstateOverlay<S> {
    type PreparedCommit = S::PreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        parent_block_height: u64,
        receipts: &[hyperscale_types::ReceiptBundle],
        block_height: u64,
        pending_snapshots: &[Arc<crate::JvtSnapshot>],
    ) -> (Hash, Self::PreparedCommit) {
        (*self.base).prepare_block_commit(
            parent_state_root,
            parent_block_height,
            receipts,
            block_height,
            pending_snapshots,
        )
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(
            Self::PreparedCommit,
            Arc<hyperscale_types::Block>,
            Arc<hyperscale_types::QuorumCertificate>,
        )>,
    ) -> Vec<Hash> {
        (*self.base).commit_prepared_blocks(blocks)
    }

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
        receipts: &[hyperscale_types::ReceiptBundle],
    ) -> Hash {
        (*self.base).commit_block(block, qc, receipts)
    }

    fn jvt_snapshot(prepared: &Self::PreparedCommit) -> &crate::JvtSnapshot {
        S::jvt_snapshot(prepared)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        (*self.base).memory_usage_bytes()
    }

    fn node_cache_len(&self) -> usize {
        (*self.base).node_cache_len()
    }
}

impl<S: crate::ChainReader> crate::ChainReader for SubstateOverlay<S> {
    fn get_block(
        &self,
        height: hyperscale_types::BlockHeight,
    ) -> Option<(hyperscale_types::Block, hyperscale_types::QuorumCertificate)> {
        (*self.base).get_block(height)
    }

    fn committed_height(&self) -> hyperscale_types::BlockHeight {
        (*self.base).committed_height()
    }

    fn committed_hash(&self) -> Option<Hash> {
        (*self.base).committed_hash()
    }

    fn latest_qc(&self) -> Option<hyperscale_types::QuorumCertificate> {
        (*self.base).latest_qc()
    }

    fn get_block_for_sync(
        &self,
        height: hyperscale_types::BlockHeight,
    ) -> Option<(hyperscale_types::Block, hyperscale_types::QuorumCertificate)> {
        (*self.base).get_block_for_sync(height)
    }

    fn get_transactions_batch(
        &self,
        hashes: &[Hash],
    ) -> Vec<hyperscale_types::RoutableTransaction> {
        (*self.base).get_transactions_batch(hashes)
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<hyperscale_types::WaveCertificate> {
        (*self.base).get_certificates_batch(hashes)
    }

    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        (*self.base).get_local_receipt(tx_hash)
    }

    fn get_execution_certificates_by_height(
        &self,
        block_height: u64,
    ) -> Vec<hyperscale_types::ExecutionCertificate> {
        (*self.base).get_execution_certificates_by_height(block_height)
    }

    fn get_wave_certificate_for_tx(
        &self,
        tx_hash: &Hash,
    ) -> Option<hyperscale_types::WaveCertificate> {
        (*self.base).get_wave_certificate_for_tx(tx_hash)
    }

    fn get_ec_hashes_for_tx(
        &self,
        tx_hash: &Hash,
    ) -> Option<Vec<(hyperscale_types::ShardGroupId, Hash)>> {
        (*self.base).get_ec_hashes_for_tx(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::empty_substate_database;
    use radix_substate_store_interface::interface::{DatabaseUpdates, PartitionDatabaseUpdates};

    fn make_delta(
        node_key: &[u8],
        partition: u8,
        sort_key: Vec<u8>,
        value: Vec<u8>,
    ) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let node = updates.node_updates.entry(node_key.to_vec()).or_default();
        let part = node.partition_updates.entry(partition).or_insert_with(|| {
            PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            }
        });
        if let PartitionDatabaseUpdates::Delta { substate_updates } = part {
            substate_updates.insert(DbSortKey(sort_key), DatabaseUpdate::Set(value));
        }
        updates
    }

    fn make_delete(node_key: &[u8], partition: u8, sort_key: Vec<u8>) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let node = updates.node_updates.entry(node_key.to_vec()).or_default();
        let part = node.partition_updates.entry(partition).or_insert_with(|| {
            PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            }
        });
        if let PartitionDatabaseUpdates::Delta { substate_updates } = part {
            substate_updates.insert(DbSortKey(sort_key), DatabaseUpdate::Delete);
        }
        updates
    }

    #[test]
    fn test_overlay_get_returns_overlay_value() {
        let base = empty_substate_database();
        let updates = make_delta(b"node1", 0, vec![1], vec![42]);
        let overlay = SubstateOverlay::new(Arc::new(base), vec![(0, Arc::new(updates))], vec![]);

        let pk = DbPartitionKey {
            node_key: b"node1".to_vec(),
            partition_num: 0,
        };
        let result = overlay.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1]));
        assert_eq!(result, Some(vec![42]));
    }

    #[test]
    fn test_overlay_get_falls_through_to_base() {
        let base = empty_substate_database();
        let updates = make_delta(b"node1", 0, vec![1], vec![42]);
        let overlay = SubstateOverlay::new(Arc::new(base), vec![(0, Arc::new(updates))], vec![]);

        let pk = DbPartitionKey {
            node_key: b"node1".to_vec(),
            partition_num: 0,
        };
        let result = overlay.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![99]));
        assert_eq!(result, None);
    }

    #[test]
    fn test_overlay_tombstone_hides_base() {
        struct FakeBase;
        impl SubstateDatabase for FakeBase {
            fn get_raw_substate_by_db_key(
                &self,
                _pk: &DbPartitionKey,
                _sk: &DbSortKey,
            ) -> Option<Vec<u8>> {
                Some(vec![99])
            }
            fn list_raw_values_from_db_key(
                &self,
                _pk: &DbPartitionKey,
                _from: Option<&DbSortKey>,
            ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
                Box::new(std::iter::once((DbSortKey(vec![1]), vec![99])))
            }
        }

        let delete = make_delete(b"node1", 0, vec![1]);
        let overlay = SubstateOverlay::new(Arc::new(FakeBase), vec![(0, Arc::new(delete))], vec![]);

        let pk = DbPartitionKey {
            node_key: b"node1".to_vec(),
            partition_num: 0,
        };
        let result = overlay.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1]));
        assert_eq!(result, None);
    }

    #[test]
    fn test_overlay_later_update_wins() {
        let base = empty_substate_database();
        let u1 = make_delta(b"node1", 0, vec![1], vec![10]);
        let u2 = make_delta(b"node1", 0, vec![1], vec![20]);
        let overlay = SubstateOverlay::new(
            Arc::new(base),
            vec![(0, Arc::new(u1)), (1, Arc::new(u2))],
            vec![],
        );

        let pk = DbPartitionKey {
            node_key: b"node1".to_vec(),
            partition_num: 0,
        };
        let result = overlay.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1]));
        assert_eq!(result, Some(vec![20]));
    }

    #[test]
    fn test_overlay_list_merges_with_base() {
        struct FakeBase;
        impl SubstateDatabase for FakeBase {
            fn get_raw_substate_by_db_key(
                &self,
                _pk: &DbPartitionKey,
                _sk: &DbSortKey,
            ) -> Option<Vec<u8>> {
                None
            }
            fn list_raw_values_from_db_key(
                &self,
                _pk: &DbPartitionKey,
                _from: Option<&DbSortKey>,
            ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
                Box::new(
                    vec![
                        (DbSortKey(vec![1]), vec![10]),
                        (DbSortKey(vec![3]), vec![30]),
                    ]
                    .into_iter(),
                )
            }
        }

        let updates = make_delta(b"node1", 0, vec![2], vec![20]);
        let overlay =
            SubstateOverlay::new(Arc::new(FakeBase), vec![(0, Arc::new(updates))], vec![]);

        let pk = DbPartitionKey {
            node_key: b"node1".to_vec(),
            partition_num: 0,
        };
        let result: Vec<_> = overlay.list_raw_values_from_db_key(&pk, None).collect();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], (DbSortKey(vec![1]), vec![10]));
        assert_eq!(result[1], (DbSortKey(vec![2]), vec![20]));
        assert_eq!(result[2], (DbSortKey(vec![3]), vec![30]));
    }
}
