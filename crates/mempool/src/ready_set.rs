//! Pending-transaction ready/deferred tracking.
//!
//! Maintains the incremental ready set that backs O(1) proposal selection.
//! Every known Pending transaction is in exactly one of:
//!
//! - **ready** — no blocking nodes, eligible for inclusion in the next block.
//! - **deferred** — at least one declared node is locked by an in-flight
//!   transaction, or already claimed by another ready-set transaction.
//! - **neither** — never added, or explicitly removed.
//!
//! Three maintained reverse indices keep add/remove/block/promote O(1) in the
//! number of transactions touching a given node:
//!
//! - `ready_txs_by_node`: node → ready hashes declaring it.
//! - `txs_deferred_by_node`: node → deferred hashes blocked by it.
//! - `deferred_by_nodes`: hash → set of nodes blocking it.

use crate::lock_tracker::LockTracker;
use hyperscale_types::{LocalTimestamp, NodeId, RoutableTransaction, TxHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

struct ReadyEntry {
    tx: Arc<RoutableTransaction>,
    added_at: LocalTimestamp,
}

pub(crate) struct ReadySet {
    ready: BTreeMap<TxHash, ReadyEntry>,
    deferred_by_nodes: HashMap<TxHash, HashSet<NodeId>>,
    txs_deferred_by_node: HashMap<NodeId, HashSet<TxHash>>,
    ready_txs_by_node: HashMap<NodeId, HashSet<TxHash>>,
}

impl ReadySet {
    pub fn new() -> Self {
        Self {
            ready: BTreeMap::new(),
            deferred_by_nodes: HashMap::new(),
            txs_deferred_by_node: HashMap::new(),
            ready_txs_by_node: HashMap::new(),
        }
    }

    /// Add a transaction. If any declared node is currently locked or already
    /// claimed by another ready-set tx, the tx lands in the deferred set;
    /// otherwise it lands in the ready set. `locks` is read-only — the store
    /// does not mutate lock state. Idempotent: a hash already in either set
    /// is a no-op.
    pub fn add(
        &mut self,
        hash: TxHash,
        tx: Arc<RoutableTransaction>,
        added_at: LocalTimestamp,
        locks: &LockTracker,
    ) {
        if self.ready.contains_key(&hash) || self.deferred_by_nodes.contains_key(&hash) {
            return;
        }

        let blocking_nodes: HashSet<NodeId> = tx
            .all_declared_nodes()
            .filter(|node| locks.is_locked(node) || self.ready_txs_by_node.contains_key(node))
            .copied()
            .collect();

        if !blocking_nodes.is_empty() {
            for node in &blocking_nodes {
                self.txs_deferred_by_node
                    .entry(*node)
                    .or_default()
                    .insert(hash);
            }
            self.deferred_by_nodes.insert(hash, blocking_nodes);
            return;
        }

        for node in tx.all_declared_nodes() {
            self.ready_txs_by_node
                .entry(*node)
                .or_default()
                .insert(hash);
        }
        self.ready.insert(hash, ReadyEntry { tx, added_at });
    }

    /// Remove `hash` from whichever tracking structure it lives in. Returns
    /// the set of nodes that were freed by removing a ready-set entry so the
    /// caller can cascade-promote deferred txs whose ready-set claim has now
    /// been released. Empty `Vec` when `hash` was deferred or absent.
    pub fn remove(&mut self, hash: &TxHash) -> Vec<NodeId> {
        let mut freed_nodes = Vec::new();
        if let Some(entry) = self.ready.remove(hash) {
            for node in entry.tx.all_declared_nodes() {
                freed_nodes.push(*node);
                if let Some(txs) = self.ready_txs_by_node.get_mut(node) {
                    txs.remove(hash);
                    if txs.is_empty() {
                        self.ready_txs_by_node.remove(node);
                    }
                }
            }
        }

        if let Some(blocking_nodes) = self.deferred_by_nodes.remove(hash) {
            for node in blocking_nodes {
                if let Some(deferred_txs) = self.txs_deferred_by_node.get_mut(&node) {
                    deferred_txs.remove(hash);
                    if deferred_txs.is_empty() {
                        self.txs_deferred_by_node.remove(&node);
                    }
                }
            }
        }

        freed_nodes
    }

    /// Move every ready-set tx touching `node` into the deferred set. Called
    /// when `node` becomes locked.
    pub fn block_node(&mut self, node: NodeId) {
        let Some(tx_hashes) = self.ready_txs_by_node.remove(&node) else {
            return;
        };

        for hash in tx_hashes {
            let Some(entry) = self.ready.remove(&hash) else {
                continue;
            };
            for other_node in entry.tx.all_declared_nodes() {
                if *other_node != node
                    && let Some(txs) = self.ready_txs_by_node.get_mut(other_node)
                {
                    txs.remove(&hash);
                    if txs.is_empty() {
                        self.ready_txs_by_node.remove(other_node);
                    }
                }
            }
            self.deferred_by_nodes.entry(hash).or_default().insert(node);
            self.txs_deferred_by_node
                .entry(node)
                .or_default()
                .insert(hash);
        }
    }

    /// Remove `node` from every deferred tx's blocker set. Returns the hashes
    /// whose last blocker was `node` — those are candidates for ready-set
    /// promotion. The caller must verify each hash is still a valid, Pending
    /// pool entry before re-adding it via [`add`](Self::add).
    pub fn promotable_for_node(&mut self, node: NodeId) -> Vec<TxHash> {
        let Some(deferred_txs) = self.txs_deferred_by_node.remove(&node) else {
            return Vec::new();
        };

        let mut promotable = Vec::new();
        for tx_hash in deferred_txs {
            if let Some(blocking_nodes) = self.deferred_by_nodes.get_mut(&tx_hash) {
                blocking_nodes.remove(&node);
                if blocking_nodes.is_empty() {
                    self.deferred_by_nodes.remove(&tx_hash);
                    promotable.push(tx_hash);
                }
            }
        }
        promotable
    }

    /// Iterate ready transactions in hash order, skipping entries whose dwell
    /// time is below `min_dwell`.
    pub fn iter_ready(
        &self,
        min_dwell: Duration,
        now: LocalTimestamp,
    ) -> impl Iterator<Item = Arc<RoutableTransaction>> + '_ {
        self.ready
            .values()
            .filter(move |entry| now.saturating_sub(entry.added_at) >= min_dwell)
            .map(|entry| Arc::clone(&entry.tx))
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    pub fn deferred_count(&self) -> usize {
        self.deferred_by_nodes.len()
    }

    pub fn txs_deferred_by_node_len(&self) -> usize {
        self.txs_deferred_by_node.len()
    }

    pub fn ready_txs_by_node_len(&self) -> usize {
        self.ready_txs_by_node.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};

    fn tx_with(seed: u8, nodes: &[u8]) -> (TxHash, Arc<RoutableTransaction>) {
        let nodes: Vec<_> = nodes.iter().map(|n| test_node(*n)).collect();
        let tx = test_transaction_with_nodes(&[seed], nodes.clone(), nodes);
        let hash = tx.hash();
        (hash, Arc::new(tx))
    }

    // ─── Invariant helpers ──────────────────────────────────────────────

    /// Central consistency check — also used by the property test. Returns
    /// a descriptive `Err` on violation so proptest prints meaningful output.
    fn check_invariants(rs: &ReadySet) -> Result<(), String> {
        // Ready and deferred are disjoint.
        for hash in rs.ready.keys() {
            if rs.deferred_by_nodes.contains_key(hash) {
                return Err(format!("{hash:?} is in both ready and deferred"));
            }
        }

        // ready_txs_by_node reverse index is consistent with ready set.
        for (hash, entry) in &rs.ready {
            for node in entry.tx.all_declared_nodes() {
                let Some(hashes) = rs.ready_txs_by_node.get(node) else {
                    return Err(format!(
                        "ready tx {hash:?} declares node {node:?}, but reverse index missing"
                    ));
                };
                if !hashes.contains(hash) {
                    return Err(format!(
                        "ready tx {hash:?} declares node {node:?}, but reverse index entry missing"
                    ));
                }
            }
        }
        for (node, hashes) in &rs.ready_txs_by_node {
            if hashes.is_empty() {
                return Err(format!("empty ready_txs_by_node entry for {node:?}"));
            }
            for hash in hashes {
                let Some(entry) = rs.ready.get(hash) else {
                    return Err(format!(
                        "ready_txs_by_node[{node:?}] has {hash:?} but it's not in ready"
                    ));
                };
                if !entry.tx.all_declared_nodes().any(|n| n == node) {
                    return Err(format!(
                        "ready_txs_by_node[{node:?}] has {hash:?} which does not declare that node"
                    ));
                }
            }
        }

        // deferred_by_nodes / txs_deferred_by_node are consistent reverse
        // indices.
        for (hash, blockers) in &rs.deferred_by_nodes {
            if blockers.is_empty() {
                return Err(format!("empty blocker set for deferred tx {hash:?}"));
            }
            for node in blockers {
                let Some(deferred) = rs.txs_deferred_by_node.get(node) else {
                    return Err(format!(
                        "deferred tx {hash:?} blocked by {node:?}, but reverse index missing"
                    ));
                };
                if !deferred.contains(hash) {
                    return Err(format!(
                        "deferred tx {hash:?} blocked by {node:?}, but reverse index entry missing"
                    ));
                }
            }
        }
        for (node, hashes) in &rs.txs_deferred_by_node {
            if hashes.is_empty() {
                return Err(format!("empty txs_deferred_by_node entry for {node:?}"));
            }
            for hash in hashes {
                let Some(blockers) = rs.deferred_by_nodes.get(hash) else {
                    return Err(format!(
                        "txs_deferred_by_node[{node:?}] has {hash:?} but it's not deferred"
                    ));
                };
                if !blockers.contains(node) {
                    return Err(format!(
                        "txs_deferred_by_node[{node:?}] has {hash:?} but its blockers don't include that node"
                    ));
                }
            }
        }

        Ok(())
    }

    // ─── Unit tests ─────────────────────────────────────────────────────

    #[test]
    fn fresh_set_is_empty() {
        let rs = ReadySet::new();
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 0);
        assert_eq!(rs.ready_txs_by_node_len(), 0);
        assert_eq!(rs.txs_deferred_by_node_len(), 0);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn add_with_no_locks_lands_in_ready_set() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        let (hash, tx) = tx_with(1, &[10]);

        rs.add(hash, tx, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferred_count(), 0);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn add_with_locked_node_lands_in_deferred() {
        let mut rs = ReadySet::new();
        let mut locks = LockTracker::new();
        locks.lock_nodes([test_node(10)]);

        let (hash, tx) = tx_with(1, &[10]);
        rs.add(hash, tx, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn second_tx_touching_same_node_as_ready_tx_is_deferred() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        let (h1, tx1) = tx_with(1, &[10]);
        let (h2, tx2) = tx_with(2, &[10]);

        rs.add(h1, tx1, LocalTimestamp::ZERO, &locks);
        rs.add(h2, tx2, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn remove_ready_tx_frees_its_nodes() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        let (h, tx) = tx_with(1, &[10, 20]);

        rs.add(h, tx, LocalTimestamp::ZERO, &locks);
        // `all_declared_nodes` iterates reads then writes; the fixture passes
        // the same nodes for both, so duplicates in `freed` are expected.
        // Only membership matters — the caller feeds each node through the
        // idempotent promote path.
        let freed = rs.remove(&h);
        assert!(freed.contains(&test_node(10)));
        assert!(freed.contains(&test_node(20)));
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn remove_deferred_tx_returns_no_freed_nodes() {
        let mut rs = ReadySet::new();
        let mut locks = LockTracker::new();
        locks.lock_nodes([test_node(10)]);
        let (h, tx) = tx_with(1, &[10]);

        rs.add(h, tx, LocalTimestamp::ZERO, &locks);
        let freed = rs.remove(&h);
        assert!(freed.is_empty());
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn block_node_moves_ready_tx_to_deferred() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        let (h, tx) = tx_with(1, &[10]);
        rs.add(h, tx, LocalTimestamp::ZERO, &locks);

        rs.block_node(test_node(10));
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn promotable_for_node_lists_only_last_blocker_txs() {
        let mut rs = ReadySet::new();
        let mut locks = LockTracker::new();
        locks.lock_nodes([test_node(10), test_node(20)]);

        // Single-blocker tx: only blocked by node 10.
        let (h_single, tx_single) = tx_with(1, &[10]);
        rs.add(h_single, tx_single, LocalTimestamp::ZERO, &locks);

        // Dual-blocker tx: blocked by both 10 and 20. Removing node 10 from
        // its blocker set should NOT mark it promotable (20 still blocks).
        let (h_dual, tx_dual) = tx_with(2, &[10, 20]);
        rs.add(h_dual, tx_dual, LocalTimestamp::ZERO, &locks);

        let promotable = rs.promotable_for_node(test_node(10));
        assert_eq!(promotable, vec![h_single]);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn iter_ready_filters_below_dwell() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        let (h, tx) = tx_with(1, &[10]);
        rs.add(h, tx, LocalTimestamp::from_millis(100), &locks);

        let below: Vec<_> = rs
            .iter_ready(Duration::from_millis(200), LocalTimestamp::from_millis(250))
            .collect();
        assert!(below.is_empty());

        let above: Vec<_> = rs
            .iter_ready(Duration::from_millis(100), LocalTimestamp::from_millis(250))
            .collect();
        assert_eq!(above.len(), 1);
    }

    #[test]
    fn iter_ready_yields_hash_order() {
        let mut rs = ReadySet::new();
        let locks = LockTracker::new();
        // Two non-conflicting txs on different nodes.
        let (h1, tx1) = tx_with(1, &[10]);
        let (h2, tx2) = tx_with(2, &[20]);

        rs.add(h1, tx1, LocalTimestamp::ZERO, &locks);
        rs.add(h2, tx2, LocalTimestamp::ZERO, &locks);

        let order: Vec<_> = rs
            .iter_ready(Duration::ZERO, LocalTimestamp::from_millis(1_000))
            .map(|tx| tx.hash())
            .collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
    }

    // ─── Property test ──────────────────────────────────────────────────

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Add(u8),       // tx index into the fixture pool
        Remove(u8),    // tx index
        BlockNode(u8), // node seed
        UnlockNode(u8),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u8>().prop_map(Op::Add),
            any::<u8>().prop_map(Op::Remove),
            any::<u8>().prop_map(Op::BlockNode),
            any::<u8>().prop_map(Op::UnlockNode),
        ]
    }

    /// Execute `op` against a coordinator-shaped wrapper that mirrors how
    /// `MempoolCoordinator` drives the store: unlock cascades re-add
    /// promotable txs, and remove cascades promote waiting deferred txs.
    fn apply(
        op: &Op,
        rs: &mut ReadySet,
        locks: &mut LockTracker,
        fixture: &[(TxHash, Arc<RoutableTransaction>)],
    ) {
        let pool_len = fixture.len();
        match op {
            Op::Add(i) => {
                let (hash, tx) = &fixture[(*i as usize) % pool_len];
                rs.add(*hash, Arc::clone(tx), LocalTimestamp::ZERO, locks);
            }
            Op::Remove(i) => {
                let (hash, _) = &fixture[(*i as usize) % pool_len];
                let freed = rs.remove(hash);
                for node in freed {
                    cascade_promote(rs, locks, fixture, node);
                }
            }
            Op::BlockNode(n) => {
                let node = test_node(*n);
                if !locks.lock_nodes([node]).is_empty() {
                    rs.block_node(node);
                }
            }
            Op::UnlockNode(n) => {
                let node = test_node(*n);
                if !locks.unlock_nodes([node]).is_empty() {
                    cascade_promote(rs, locks, fixture, node);
                }
            }
        }
    }

    fn cascade_promote(
        rs: &mut ReadySet,
        locks: &LockTracker,
        fixture: &[(TxHash, Arc<RoutableTransaction>)],
        node: NodeId,
    ) {
        let mut promotable = rs.promotable_for_node(node);
        promotable.sort();
        for hash in promotable {
            if let Some((_, tx)) = fixture.iter().find(|(h, _)| *h == hash) {
                rs.add(hash, Arc::clone(tx), LocalTimestamp::ZERO, locks);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        #[test]
        fn invariants_hold_under_arbitrary_op_sequences(
            ops in prop::collection::vec(op_strategy(), 0..40),
        ) {
            // Fixture: 8 txs over 4 declared-node seeds, heavy overlap so the
            // deferred path gets real exercise.
            let fixture: Vec<(TxHash, Arc<RoutableTransaction>)> = (0..8)
                .map(|seed| tx_with(seed, &[0, 1, 2, 3][..=((seed as usize) % 4)]))
                .collect();

            let mut rs = ReadySet::new();
            let mut locks = LockTracker::new();

            for op in &ops {
                apply(op, &mut rs, &mut locks, &fixture);
                if let Err(e) = check_invariants(&rs) {
                    return Err(TestCaseError::Fail(
                        format!("invariant broken after {op:?}: {e}").into(),
                    ));
                }
            }
        }
    }
}
