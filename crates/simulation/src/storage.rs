//! # Simulated Storage
//!
//! In-memory storage implementation for deterministic simulation testing (DST).
//!
//! Uses `im::OrdMap` for O(1) structural-sharing clones, enabling efficient
//! snapshots without copying the entire dataset. This is critical for parallel
//! transaction execution where each transaction needs an isolated view.

use hyperscale_engine::{
    keys, CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{
    Block, BlockHeight, Hash, NodeId, QuorumCertificate, TransactionCertificate,
};
use im::OrdMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

/// In-memory storage for simulation and testing.
///
/// Uses `im::OrdMap` which provides:
/// - Deterministic ordering (like BTreeMap)
/// - O(1) clone via structural sharing
/// - Thread-safe with Arc internally
///
/// This is critical for DST - same operations produce identical results,
/// and snapshots are cheap regardless of data size.
///
/// Implements Radix's `SubstateDatabase` and `CommittableSubstateDatabase` directly,
/// plus our `SubstateStore` extension for snapshots and node listing.
///
/// Also stores consensus metadata:
/// - Committed blocks indexed by height
/// - Transaction certificates indexed by hash
/// - Chain metadata (committed height)
/// - Own votes (for BFT safety across restarts)
pub struct SimStorage {
    /// Radix substate data.
    data: Arc<RwLock<OrdMap<Vec<u8>, Vec<u8>>>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Consensus storage
    // ═══════════════════════════════════════════════════════════════════════
    /// Committed blocks indexed by height.
    /// BTreeMap for efficient range queries.
    blocks: BTreeMap<BlockHeight, (Block, QuorumCertificate)>,

    /// Highest committed block height.
    committed_height: BlockHeight,

    /// Transaction certificates indexed by transaction hash.
    /// Used for cross-shard transaction finalization.
    certificates: HashMap<Hash, TransactionCertificate>,

    /// Our own votes indexed by height.
    /// **BFT Safety Critical**: Used to prevent equivocation after restart.
    /// Key: height → (block_hash, round)
    own_votes: HashMap<u64, (Hash, u64)>,
}

impl SimStorage {
    /// Create a new empty simulated storage.
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(OrdMap::new())),
            blocks: BTreeMap::new(),
            committed_height: BlockHeight(0),
            certificates: HashMap::new(),
            own_votes: HashMap::new(),
        }
    }

    /// Clear all data (useful for testing).
    pub fn clear(&mut self) {
        self.data.write().unwrap().clear();
        self.blocks.clear();
        self.committed_height = BlockHeight(0);
        self.certificates.clear();
        self.own_votes.clear();
    }

    /// Get number of substate keys stored.
    pub fn len(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Check if substate storage is empty.
    pub fn is_empty(&self) -> bool {
        self.data.read().unwrap().is_empty()
    }

    /// Internal: iterate over a key range.
    fn iter_range(&self, start: &[u8], end: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let data = self.data.read().unwrap();
        data.iter()
            .filter(|(k, _)| k.as_slice() >= start && k.as_slice() < end)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Block storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a committed block with its quorum certificate.
    pub fn put_block(&mut self, height: BlockHeight, block: Block, qc: QuorumCertificate) {
        self.blocks.insert(height, (block, qc));
    }

    /// Get a committed block by height.
    pub fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.blocks.get(&height).cloned()
    }

    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order.
    pub fn get_blocks_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Vec<(Block, QuorumCertificate)> {
        self.blocks
            .range(from..to)
            .map(|(_, v)| v.clone())
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Chain metadata
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the highest committed block height.
    pub fn set_committed_height(&mut self, height: BlockHeight) {
        self.committed_height = height;
    }

    /// Get the highest committed block height.
    pub fn committed_height(&self) -> BlockHeight {
        self.committed_height
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction certificate.
    pub fn put_certificate(&mut self, hash: Hash, cert: TransactionCertificate) {
        self.certificates.insert(hash, cert);
    }

    /// Get a transaction certificate by transaction hash.
    pub fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate> {
        self.certificates.get(hash).cloned()
    }

    /// Atomically commit a certificate and its state writes.
    ///
    /// This is the deferred commit operation that applies state writes when
    /// a `TransactionCertificate` is included in a committed block. It mirrors
    /// the production `RocksDbStorage::commit_certificate_with_writes()` to
    /// ensure DST catches timing bugs where code incorrectly assumes state
    /// is available before certificate persistence.
    ///
    /// # Arguments
    ///
    /// * `certificate` - The transaction certificate to store
    /// * `writes` - The state writes from the certificate's shard_proofs for the local shard
    pub fn commit_certificate_with_writes(
        &mut self,
        certificate: &TransactionCertificate,
        writes: &[hyperscale_types::SubstateWrite],
    ) {
        // 1. Commit state writes
        let updates = hyperscale_engine::substate_writes_to_database_updates(writes);
        self.commit(&updates);

        // 2. Store certificate
        self.certificates
            .insert(certificate.transaction_hash, certificate.clone());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Own vote storage (BFT safety)
    // ═══════════════════════════════════════════════════════════════════════

    /// Store our own vote for a height.
    ///
    /// **BFT Safety Critical**: This must be called before broadcasting the vote.
    /// If we crash and restart, we must remember what we voted for to prevent
    /// voting for a different block at the same height (equivocation).
    pub fn put_own_vote(&mut self, height: u64, round: u64, block_hash: Hash) {
        self.own_votes.insert(height, (block_hash, round));
    }

    /// Get our own vote for a height (if any).
    ///
    /// Returns `Some((block_hash, round))` if we previously voted at this height.
    pub fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        self.own_votes.get(&height).copied()
    }

    /// Get all our own votes (for recovery on startup).
    ///
    /// Returns a map of height → (block_hash, round).
    pub fn get_all_own_votes(&self) -> &HashMap<u64, (Hash, u64)> {
        &self.own_votes
    }

    /// Remove votes at or below a committed height (cleanup).
    ///
    /// Once a height is committed, we no longer need to track our vote for it.
    pub fn prune_own_votes(&mut self, committed_height: u64) {
        self.own_votes
            .retain(|height, _| *height > committed_height);
    }
}

impl Default for SimStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SubstateDatabase for SimStorage {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        let data = self.data.read().unwrap();
        data.get(&key).cloned()
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();

        let start = match from_sort_key {
            Some(sort_key) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sort_key.0);
                s
            }
            None => prefix.clone(),
        };
        let end = keys::next_prefix(&prefix);

        let items = self.iter_range(&start, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let sort_key_bytes = full_key[prefix_len..].to_vec();
                Some((DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }
}

impl CommittableSubstateDatabase for SimStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        let mut data = self.data.write().unwrap();

        for (node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                let partition_key = DbPartitionKey {
                    node_key: node_key.clone(),
                    partition_num: *partition_num,
                };

                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            match update {
                                DatabaseUpdate::Set(value) => {
                                    data.insert(key, value.clone());
                                }
                                DatabaseUpdate::Delete => {
                                    data.remove(&key);
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        // Delete all existing in partition
                        let prefix = keys::partition_prefix(&partition_key);
                        let end = keys::next_prefix(&prefix);

                        let existing_keys: Vec<Vec<u8>> = data
                            .iter()
                            .filter(|(k, _)| {
                                k.as_slice() >= prefix.as_slice() && k.as_slice() < end.as_slice()
                            })
                            .map(|(k, _)| k.clone())
                            .collect();

                        for key in existing_keys {
                            data.remove(&key);
                        }

                        // Insert new values
                        for (sort_key, value) in new_substate_values {
                            let key = keys::to_storage_key(&partition_key, sort_key);
                            data.insert(key, value.clone());
                        }
                    }
                }
            }
        }
    }
}

impl SubstateStore for SimStorage {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // O(1) clone with structural sharing!
        let data = self.data.read().unwrap().clone();
        SimSnapshot { data }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix);

        let items = self.iter_range(&prefix, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let partition_num = full_key[prefix_len];
                let sort_key_bytes = full_key[prefix_len + 1..].to_vec();
                Some((partition_num, DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }
}

/// Snapshot of in-memory storage.
///
/// Contains a structurally-shared copy of the data at snapshot time.
/// The clone is O(1) - only increments reference counts internally.
///
/// Implements `SubstateDatabase` for read-only access.
pub struct SimSnapshot {
    data: OrdMap<Vec<u8>, Vec<u8>>,
}

impl SubstateDatabase for SimSnapshot {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        self.data.get(&key).cloned()
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();

        let start = match from_sort_key {
            Some(sort_key) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sort_key.0);
                s
            }
            None => prefix.clone(),
        };
        let end = keys::next_prefix(&prefix);

        // Clone data (O(1) structural sharing) for the iterator
        let data = self.data.clone();
        let start_owned = start;
        let end_owned = end;

        Box::new(
            data.into_iter()
                .filter(move |(k, _)| {
                    k.as_slice() >= start_owned.as_slice() && k.as_slice() < end_owned.as_slice()
                })
                .filter_map(move |(full_key, value)| {
                    if full_key.len() > prefix_len {
                        let sort_key_bytes = full_key[prefix_len..].to_vec();
                        Some((DbSortKey(sort_key_bytes), value))
                    } else {
                        None
                    }
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_engine::{NodeDatabaseUpdates, SubstateDatabase};

    #[test]
    fn test_basic_substate_operations() {
        let mut storage = SimStorage::new();

        // Create a partition key and sort key
        let partition_key = DbPartitionKey {
            node_key: vec![1, 2, 3],
            partition_num: 0,
        };
        let sort_key = DbSortKey(vec![10, 20]);

        // Initially empty
        assert!(storage
            .get_raw_substate_by_db_key(&partition_key, &sort_key)
            .is_none());

        // Commit a value
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(
                            sort_key.clone(),
                            DatabaseUpdate::Set(vec![99, 88, 77]),
                        )]
                        .into_iter()
                        .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates);

        // Now we can read it
        let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
        assert_eq!(value, Some(vec![99, 88, 77]));
    }

    #[test]
    fn test_snapshot_isolation() {
        let mut storage = SimStorage::new();

        let partition_key = DbPartitionKey {
            node_key: vec![1, 2, 3],
            partition_num: 0,
        };
        let sort_key = DbSortKey(vec![10]);

        // Write initial value
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![1]))]
                            .into_iter()
                            .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates);

        // Take snapshot
        let snapshot = storage.snapshot();

        // Modify storage
        let mut updates2 = DatabaseUpdates::default();
        updates2.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![2]))]
                            .into_iter()
                            .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit(&updates2);

        // Snapshot has old value
        assert_eq!(
            snapshot.get_raw_substate_by_db_key(&partition_key, &sort_key),
            Some(vec![1])
        );

        // Storage has new value
        assert_eq!(
            storage.get_raw_substate_by_db_key(&partition_key, &sort_key),
            Some(vec![2])
        );
    }

    #[test]
    fn test_snapshot_structural_sharing_performance() {
        let mut storage = SimStorage::new();

        // Insert 10,000 items
        for i in 0..10_000u32 {
            let partition_key = DbPartitionKey {
                node_key: i.to_be_bytes().to_vec(),
                partition_num: 0,
            };
            let sort_key = DbSortKey(vec![0]);

            let mut updates = DatabaseUpdates::default();
            updates.node_updates.insert(
                partition_key.node_key.clone(),
                NodeDatabaseUpdates {
                    partition_updates: [(
                        partition_key.partition_num,
                        PartitionDatabaseUpdates::Delta {
                            substate_updates: [(sort_key, DatabaseUpdate::Set(vec![i as u8]))]
                                .into_iter()
                                .collect(),
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            );
            storage.commit(&updates);
        }

        // Snapshot should be nearly instant (O(1), not O(n))
        let start = std::time::Instant::now();
        let _snap1 = storage.snapshot();
        let _snap2 = storage.snapshot();
        let _snap3 = storage.snapshot();
        let _snap4 = storage.snapshot();
        let _snap5 = storage.snapshot();
        let elapsed = start.elapsed();

        // 5 snapshots of 10k items should be very fast
        // With BTreeMap clone this would take 10+ ms; with OrdMap it's < 1ms
        assert!(
            elapsed.as_millis() < 50,
            "5 snapshots took {:?}, expected < 50ms",
            elapsed
        );
    }
}
