//! Deterministic conflict detection from committed provisions.
//!
//! Detects node-ID overlap between local cross-shard transactions and remote
//! provision batches committed via `provision_root`. A bidirectional cycle
//! exists when a local tx needs nodes from shard S, and a remote tx from S
//! touches overlapping nodes.
//!
//! Detection is bidirectional — works regardless of commit ordering:
//! - **Provision commit after local tx**: `detect_conflicts` finds the overlap.
//! - **Local tx commits after provisions**: `register_tx` checks against stored
//!   provision node-IDs and returns any conflicts.
//!
//! On overlap the lower tx hash wins; the loser is aborted at the provision
//! commit height. All validators derive the same conflicts from the same
//! committed chain state.

use hyperscale_types::{Hash, NodeId, Provision, ShardGroupId, TopologySnapshot};
use std::collections::{HashMap, HashSet};

/// A detected conflict: the loser tx should be aborted at the given height.
#[derive(Debug, Clone)]
pub struct DetectedConflict {
    pub loser_tx: Hash,
    pub committed_at_height: u64,
}

/// Stored provision data for reverse conflict detection.
#[derive(Debug, Clone)]
struct StoredProvision {
    remote_tx: Hash,
    node_ids: HashSet<NodeId>,
    committed_at_height: u64,
}

/// Tracks local cross-shard transactions and committed provision node-IDs
/// for bidirectional conflict detection.
///
/// Two-way detection:
/// 1. When provisions commit → checked against registered local txs
/// 2. When local tx registers → checked against stored provision data
#[derive(Debug, Default)]
pub struct ConflictDetector {
    // ── Local tx tracking ────────────────────────────────────────────
    /// tx_hash → per-shard node needs.
    tx_needs: HashMap<Hash, HashMap<ShardGroupId, HashSet<NodeId>>>,
    /// Reverse index: shard → tx_hashes needing provisions from that shard.
    txs_by_shard: HashMap<ShardGroupId, HashSet<Hash>>,

    // ── Provision tracking (for reverse detection) ───────────────────
    /// Stored provision node-IDs keyed by (remote_tx_hash, source_shard).
    /// Used when a local tx registers after provisions already committed.
    stored_provisions: HashMap<(Hash, ShardGroupId), StoredProvision>,
    /// Reverse index: source_shard → remote tx hashes with stored provisions.
    provisions_by_shard: HashMap<ShardGroupId, HashSet<Hash>>,
}

impl ConflictDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a local cross-shard transaction for conflict tracking.
    ///
    /// Extracts which remote nodes the tx needs from each shard, then checks
    /// against already-stored provision data for conflicts (reverse direction).
    pub fn register_tx(
        &mut self,
        tx_hash: Hash,
        topology: &TopologySnapshot,
        declared_reads: &[NodeId],
        declared_writes: &[NodeId],
    ) -> Vec<DetectedConflict> {
        let local_shard = topology.local_shard();
        let mut nodes_by_shard: HashMap<ShardGroupId, HashSet<NodeId>> = HashMap::new();

        for node_id in declared_reads.iter().chain(declared_writes.iter()) {
            let shard = topology.shard_for_node_id(node_id);
            if shard != local_shard {
                nodes_by_shard.entry(shard).or_default().insert(*node_id);
            }
        }

        for &shard in nodes_by_shard.keys() {
            self.txs_by_shard.entry(shard).or_default().insert(tx_hash);
        }

        // Check against already-committed provisions (reverse direction).
        let mut conflicts = Vec::new();
        for (shard, needed_nodes) in &nodes_by_shard {
            if let Some(remote_txs) = self.provisions_by_shard.get(shard) {
                for remote_tx_hash in remote_txs {
                    if let Some(prov) = self.stored_provisions.get(&(*remote_tx_hash, *shard)) {
                        if needed_nodes.is_disjoint(&prov.node_ids) {
                            continue;
                        }
                        // Overlap — lower hash wins.
                        if tx_hash > prov.remote_tx {
                            conflicts.push(DetectedConflict {
                                loser_tx: tx_hash,
                                committed_at_height: prov.committed_at_height,
                            });
                        }
                        // If local tx wins, remote shard handles their loser.
                    }
                }
            }
        }

        self.tx_needs.insert(tx_hash, nodes_by_shard);
        conflicts
    }

    /// Detect conflicts between a committed provision batch and local transactions.
    ///
    /// For each tx in the batch, extracts its node IDs, stores them for future
    /// reverse detection, and checks against all local txs that need provisions
    /// from the batch's source shard.
    pub fn detect_conflicts(
        &mut self,
        batch: &Provision,
        committed_at_height: u64,
    ) -> Vec<DetectedConflict> {
        let source_shard = batch.source_shard;
        let mut conflicts = Vec::new();

        for tx_entry in &batch.transactions {
            let remote_tx = tx_entry.tx_hash;
            let remote_nodes: HashSet<NodeId> = tx_entry.node_ids();

            if remote_nodes.is_empty() {
                continue;
            }

            // Store for reverse detection when future local txs register.
            self.stored_provisions.insert(
                (remote_tx, source_shard),
                StoredProvision {
                    remote_tx,
                    node_ids: remote_nodes.clone(),
                    committed_at_height,
                },
            );
            self.provisions_by_shard
                .entry(source_shard)
                .or_default()
                .insert(remote_tx);

            // Check against already-registered local txs.
            if let Some(local_txs) = self.txs_by_shard.get(&source_shard) {
                for &local_tx in local_txs {
                    let Some(local_needs) = self
                        .tx_needs
                        .get(&local_tx)
                        .and_then(|n| n.get(&source_shard))
                    else {
                        continue;
                    };

                    if local_needs.is_disjoint(&remote_nodes) {
                        continue;
                    }

                    // Node-ID overlap — lower hash wins.
                    if local_tx > remote_tx {
                        conflicts.push(DetectedConflict {
                            loser_tx: local_tx,
                            committed_at_height,
                        });
                    }
                    // If remote tx loses, their shard detects it.
                }
            }
        }

        conflicts
    }

    /// Remove a transaction from local tx tracking (terminal state reached).
    pub fn remove_tx(&mut self, tx_hash: &Hash) {
        if let Some(needs) = self.tx_needs.remove(tx_hash) {
            for shard in needs.keys() {
                if let Some(txs) = self.txs_by_shard.get_mut(shard) {
                    txs.remove(tx_hash);
                    if txs.is_empty() {
                        self.txs_by_shard.remove(shard);
                    }
                }
            }
        }
    }

    /// Remove stored provision data for a remote tx (committed provisions pruned).
    pub fn remove_provision(&mut self, remote_tx: &Hash, source_shard: ShardGroupId) {
        if self
            .stored_provisions
            .remove(&(*remote_tx, source_shard))
            .is_some()
        {
            if let Some(txs) = self.provisions_by_shard.get_mut(&source_shard) {
                txs.remove(remote_tx);
                if txs.is_empty() {
                    self.provisions_by_shard.remove(&source_shard);
                }
            }
        }
    }

    /// Number of local transactions being tracked.
    pub fn tracked_tx_count(&self) -> usize {
        self.tx_needs.len()
    }

    /// Number of stored provision entries.
    pub fn stored_provision_count(&self) -> usize {
        self.stored_provisions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        bls_keypair_from_seed, BlockHeight, NodeId, ShardGroupId, StateEntry, TopologySnapshot,
        TxEntries, ValidatorId, ValidatorInfo, ValidatorSet, VerkleInclusionProof,
    };

    /// Create a NodeId that routes to `target_shard` under modulo-hash routing.
    fn node_on_shard(target_shard: ShardGroupId, num_shards: u64) -> NodeId {
        for i in 0u64.. {
            let mut bytes = [0u8; 30];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            let node = NodeId(bytes);
            if hyperscale_types::shard_for_node(&node, num_shards) == target_shard {
                return node;
            }
        }
        unreachable!()
    }

    /// Find two distinct NodeIds that both route to the given shard.
    fn two_nodes_on_shard(target_shard: ShardGroupId, num_shards: u64) -> (NodeId, NodeId) {
        let mut found = Vec::new();
        for i in 0u64.. {
            let mut bytes = [0u8; 30];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            let node = NodeId(bytes);
            if hyperscale_types::shard_for_node(&node, num_shards) == target_shard {
                found.push(node);
                if found.len() == 2 {
                    return (found[0], found[1]);
                }
            }
        }
        unreachable!()
    }

    fn make_topology() -> TopologySnapshot {
        let mut seed = [0u8; 32];
        seed[0] = 42;
        let kp = bls_keypair_from_seed(&seed);
        let vs = ValidatorSet::new(vec![ValidatorInfo {
            validator_id: ValidatorId(0),
            public_key: kp.public_key(),
            voting_power: 1,
        }]);
        // Local shard = 0, 2 shards total
        TopologySnapshot::with_local_shard(ValidatorId(0), ShardGroupId(0), 2, vs)
    }

    fn make_entry(node: NodeId) -> StateEntry {
        // Storage key: 20-byte hash prefix + 30-byte NodeId + 1-byte partition
        let mut key = vec![0u8; 20];
        key.extend_from_slice(&node.0);
        key.push(0);
        StateEntry::new(key, Some(vec![1]))
    }

    fn make_batch(
        source_shard: ShardGroupId,
        height: u64,
        txs: Vec<(Hash, Vec<NodeId>)>,
    ) -> Provision {
        Provision::new(
            source_shard,
            BlockHeight(height),
            VerkleInclusionProof::dummy(),
            txs.into_iter()
                .map(|(hash, nodes)| TxEntries {
                    tx_hash: hash,
                    entries: nodes.into_iter().map(make_entry).collect(),
                })
                .collect(),
        )
    }

    /// Determine which hash is higher/lower (blake3 output order).
    fn ordered_hashes(a: &[u8], b: &[u8]) -> (Hash, Hash) {
        let ha = Hash::from_bytes(a);
        let hb = Hash::from_bytes(b);
        if ha > hb {
            (ha, hb) // (higher=loser, lower=winner)
        } else {
            (hb, ha)
        }
    }

    #[test]
    fn test_no_overlap_no_conflict() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();

        let (node_a, node_b) = two_nodes_on_shard(ShardGroupId(1), 2);

        let local_tx = Hash::from_bytes(b"tx_alpha");
        detector.register_tx(local_tx, &topo, &[node_a], &[]);

        // Remote batch touches node_b (same shard, different node) — no overlap
        let remote_tx = Hash::from_bytes(b"tx_beta");
        let batch = make_batch(ShardGroupId(1), 10, vec![(remote_tx, vec![node_b])]);

        let conflicts = detector.detect_conflicts(&batch, 10);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_overlap_higher_hash_loses() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let (higher, lower) = ordered_hashes(b"tx_alpha", b"tx_beta");

        // Register the higher hash as local — it should lose
        detector.register_tx(higher, &topo, &[node], &[]);

        let batch = make_batch(ShardGroupId(1), 10, vec![(lower, vec![node])]);
        let conflicts = detector.detect_conflicts(&batch, 10);

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].loser_tx, higher);
        assert_eq!(conflicts[0].committed_at_height, 10);
    }

    #[test]
    fn test_local_wins_no_conflict_emitted() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let (higher, lower) = ordered_hashes(b"tx_alpha", b"tx_beta");

        // Register the lower hash as local — it wins
        detector.register_tx(lower, &topo, &[node], &[]);

        let batch = make_batch(ShardGroupId(1), 10, vec![(higher, vec![node])]);
        let conflicts = detector.detect_conflicts(&batch, 10);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_reverse_detection_provisions_before_local_tx() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let (higher, lower) = ordered_hashes(b"tx_local", b"tx_remote");

        // Provision commit FIRST (local tx not registered yet)
        let batch = make_batch(ShardGroupId(1), 5, vec![(lower, vec![node])]);
        let fwd_conflicts = detector.detect_conflicts(&batch, 5);
        assert!(fwd_conflicts.is_empty()); // No local txs registered yet

        // Local tx registers AFTER — reverse detection catches it
        let rev_conflicts = detector.register_tx(higher, &topo, &[node], &[]);
        assert_eq!(rev_conflicts.len(), 1);
        assert_eq!(rev_conflicts[0].loser_tx, higher);
        assert_eq!(rev_conflicts[0].committed_at_height, 5);
    }

    #[test]
    fn test_reverse_detection_local_wins() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let (higher, lower) = ordered_hashes(b"tx_local", b"tx_remote");

        // Provision commit first with the higher hash
        let batch = make_batch(ShardGroupId(1), 5, vec![(higher, vec![node])]);
        detector.detect_conflicts(&batch, 5);

        // Local tx registers with lower hash — wins, no conflict
        let rev_conflicts = detector.register_tx(lower, &topo, &[node], &[]);
        assert!(rev_conflicts.is_empty());
    }

    #[test]
    fn test_remove_tx_stops_detection() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let local_tx = Hash::from_bytes(b"tx_alpha");
        detector.register_tx(local_tx, &topo, &[node], &[]);
        detector.remove_tx(&local_tx);
        assert_eq!(detector.tracked_tx_count(), 0);

        let remote_tx = Hash::from_bytes(b"tx_beta");
        let batch = make_batch(ShardGroupId(1), 10, vec![(remote_tx, vec![node])]);
        let conflicts = detector.detect_conflicts(&batch, 10);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_wrong_shard_no_conflict() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let local_tx = Hash::from_bytes(b"tx_alpha");
        detector.register_tx(local_tx, &topo, &[node], &[]);

        // Batch from shard 0 (our shard) — not the shard we need provisions from
        let remote_tx = Hash::from_bytes(b"tx_beta");
        let batch = make_batch(ShardGroupId(0), 10, vec![(remote_tx, vec![node])]);
        let conflicts = detector.detect_conflicts(&batch, 10);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_remove_provision_stops_reverse_detection() {
        let topo = make_topology();
        let mut detector = ConflictDetector::new();
        let node = node_on_shard(ShardGroupId(1), 2);

        let (higher, lower) = ordered_hashes(b"tx_local", b"tx_remote");

        // Store provisions
        let batch = make_batch(ShardGroupId(1), 5, vec![(lower, vec![node])]);
        detector.detect_conflicts(&batch, 5);
        assert_eq!(detector.stored_provision_count(), 1);

        // Remove stored provision
        detector.remove_provision(&lower, ShardGroupId(1));
        assert_eq!(detector.stored_provision_count(), 0);

        // Register local tx — no reverse conflict (provision was removed)
        let rev_conflicts = detector.register_tx(higher, &topo, &[node], &[]);
        assert!(rev_conflicts.is_empty());
    }
}
