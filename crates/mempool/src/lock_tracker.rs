//! Node-level state locks + in-flight transaction counters.
//!
//! A node is locked while any transaction that declares it is in a
//! lock-holding status (`Committed` or `Executed`). The tracker owns:
//!
//! - **`locked_nodes`** — the current set of locked `NodeId`s. `lock_nodes`
//!   and `unlock_nodes` return the *newly*-locked / *newly*-unlocked subsets
//!   so the coordinator can drive the ready-set cascade (blocking deferred
//!   txs, promoting them on release).
//! - **`committed_count` / `executed_count`** — cached counters maintained
//!   incrementally through status transitions. Summed by `in_flight()` for
//!   backpressure checks; both reported individually by the contention
//!   stats.

use hyperscale_types::NodeId;
use std::collections::HashSet;

pub(crate) struct LockTracker {
    locked_nodes: HashSet<NodeId>,
    committed_count: usize,
    executed_count: usize,
}

impl LockTracker {
    pub fn new() -> Self {
        Self {
            locked_nodes: HashSet::new(),
            committed_count: 0,
            executed_count: 0,
        }
    }

    /// Mark each node in `nodes` as locked. Returns the subset that was not
    /// already locked — the coordinator uses this to block deferred txs that
    /// touch those nodes.
    pub fn lock_nodes(&mut self, nodes: impl IntoIterator<Item = NodeId>) -> Vec<NodeId> {
        nodes
            .into_iter()
            .filter(|node| self.locked_nodes.insert(*node))
            .collect()
    }

    /// Mark each node in `nodes` as unlocked. Returns the subset that was
    /// actually locked before this call — the coordinator uses this to
    /// promote deferred txs waiting on those nodes.
    pub fn unlock_nodes(&mut self, nodes: impl IntoIterator<Item = NodeId>) -> Vec<NodeId> {
        nodes
            .into_iter()
            .filter(|node| self.locked_nodes.remove(node))
            .collect()
    }

    pub fn is_locked(&self, node: &NodeId) -> bool {
        self.locked_nodes.contains(node)
    }

    pub fn locked_nodes_count(&self) -> usize {
        self.locked_nodes.len()
    }

    pub fn inc_committed(&mut self) {
        self.committed_count += 1;
    }

    pub fn dec_committed(&mut self) {
        self.committed_count = self.committed_count.saturating_sub(1);
    }

    pub fn inc_executed(&mut self) {
        self.executed_count += 1;
    }

    pub fn dec_executed(&mut self) {
        self.executed_count = self.executed_count.saturating_sub(1);
    }

    pub fn committed_count(&self) -> usize {
        self.committed_count
    }

    pub fn executed_count(&self) -> usize {
        self.executed_count
    }

    /// Sum of committed and executed counts — transactions currently holding
    /// state locks. Used for backpressure.
    pub fn in_flight(&self) -> usize {
        self.committed_count + self.executed_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_node;

    #[test]
    fn fresh_tracker_is_empty() {
        let tracker = LockTracker::new();
        assert_eq!(tracker.locked_nodes_count(), 0);
        assert_eq!(tracker.committed_count(), 0);
        assert_eq!(tracker.executed_count(), 0);
        assert_eq!(tracker.in_flight(), 0);
        assert!(!tracker.is_locked(&test_node(1)));
    }

    #[test]
    fn lock_nodes_returns_only_newly_locked() {
        let mut tracker = LockTracker::new();
        let a = test_node(1);
        let b = test_node(2);

        let newly_locked = tracker.lock_nodes([a, b]);
        assert_eq!(newly_locked.len(), 2);
        assert!(tracker.is_locked(&a));
        assert!(tracker.is_locked(&b));

        // Locking the same nodes again yields no newly-locked entries.
        let newly_locked = tracker.lock_nodes([a, b]);
        assert!(newly_locked.is_empty());
        assert_eq!(tracker.locked_nodes_count(), 2);
    }

    #[test]
    fn lock_nodes_handles_partial_overlap() {
        let mut tracker = LockTracker::new();
        let a = test_node(1);
        let b = test_node(2);
        let c = test_node(3);

        tracker.lock_nodes([a, b]);
        // Locking [b, c] should only report c as newly locked.
        let newly_locked = tracker.lock_nodes([b, c]);
        assert_eq!(newly_locked, vec![c]);
        assert_eq!(tracker.locked_nodes_count(), 3);
    }

    #[test]
    fn unlock_nodes_returns_only_newly_unlocked() {
        let mut tracker = LockTracker::new();
        let a = test_node(1);
        let b = test_node(2);
        tracker.lock_nodes([a, b]);

        let newly_unlocked = tracker.unlock_nodes([a, b]);
        assert_eq!(newly_unlocked.len(), 2);
        assert!(!tracker.is_locked(&a));
        assert!(!tracker.is_locked(&b));

        // Unlocking again yields nothing.
        let newly_unlocked = tracker.unlock_nodes([a, b]);
        assert!(newly_unlocked.is_empty());
    }

    #[test]
    fn unlock_ignores_never_locked_nodes() {
        let mut tracker = LockTracker::new();
        let locked = test_node(1);
        let unlocked = test_node(2);
        tracker.lock_nodes([locked]);

        let newly_unlocked = tracker.unlock_nodes([locked, unlocked]);
        assert_eq!(newly_unlocked, vec![locked]);
    }

    #[test]
    fn counter_increments_and_saturates_on_decrement() {
        let mut tracker = LockTracker::new();

        tracker.inc_committed();
        tracker.inc_committed();
        assert_eq!(tracker.committed_count(), 2);

        tracker.dec_committed();
        assert_eq!(tracker.committed_count(), 1);

        // Over-decrementing saturates at 0 rather than wrapping.
        tracker.dec_committed();
        tracker.dec_committed();
        tracker.dec_committed();
        assert_eq!(tracker.committed_count(), 0);
    }

    #[test]
    fn in_flight_sums_committed_and_executed() {
        let mut tracker = LockTracker::new();
        tracker.inc_committed();
        tracker.inc_committed();
        tracker.inc_executed();
        assert_eq!(tracker.in_flight(), 3);

        tracker.dec_committed();
        assert_eq!(tracker.in_flight(), 2);
    }

    #[test]
    fn committed_and_executed_counters_are_independent() {
        let mut tracker = LockTracker::new();
        tracker.inc_committed();
        tracker.inc_executed();
        tracker.inc_executed();

        tracker.dec_committed();
        assert_eq!(tracker.committed_count(), 0);
        assert_eq!(tracker.executed_count(), 2);
    }
}
