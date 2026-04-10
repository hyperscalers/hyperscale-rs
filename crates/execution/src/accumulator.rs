//! Execution accumulator for collecting per-tx execution results within a wave.
//!
//! When a block is committed, transactions are partitioned into deterministic
//! waves based on their provision dependency sets. The `ExecutionAccumulator` tracks
//! which transactions in a wave have completed execution or been aborted.
//!
//! ## Vote Height Determination
//!
//! The accumulator separates two concerns:
//!
//! 1. **Target vote height** — the lowest height at which every tx is *coverable*
//!    (has provisions OR has an abort intent at that height). This changes only
//!    when provisions arrive or abort intents are committed.
//!
//! 2. **Vote emission** — requires all covered-by-execution txs at the target
//!    height to have their execution results back. This is just waiting for
//!    async work to complete.

use hyperscale_types::{
    compute_execution_receipt_root, ExecutionOutcome, Hash, ShardGroupId, TxOutcome, WaveId,
};
use std::collections::{HashMap, HashSet};

/// Tracks execution progress for a single wave within a block.
///
/// Created when a block is committed, one per wave. Records per-tx execution
/// results as they complete (single-shard txs complete immediately, cross-shard
/// txs complete when provisions arrive and execution finishes).
///
/// Supports height-indexed abort tracking for the re-voting protocol:
/// a tx is "coverable" at vote_height N if it has provisions (execution
/// possible) OR has an abort intent committed at or before wave_start + N.
#[derive(Debug)]
pub struct ExecutionAccumulator {
    /// Wave identifier (provision dependency set).
    wave_id: WaveId,
    /// Block this wave belongs to.
    block_hash: Hash,
    /// Block height (= wave_starting_height).
    block_height: u64,
    /// Expected transactions in wave order (block order within the wave).
    /// Each entry is (tx_hash, participating_shards for that tx).
    expected_txs: Vec<(Hash, Vec<ShardGroupId>)>,
    /// Execution results from the engine, keyed by tx_hash. Does NOT include
    /// abort outcomes — those are tracked separately in `aborts`.
    execution_results: HashMap<Hash, TxResult>,
    /// Txs that have received provisions (execution is possible/in-flight).
    provisioned: HashSet<Hash>,
    /// Abort intents indexed by the local block height at which they were committed.
    /// Key: tx_hash, Value: committed_at_height (absolute).
    aborts: HashMap<Hash, AbortEntry>,
    /// Cached target vote height. Recomputed when inputs change (provisions or aborts).
    cached_target_vote_height: Option<u64>,
    /// The vote height at which we last emitted a vote. Only re-vote downward.
    last_voted_height: Option<u64>,
}

/// Execution result for a single transaction.
#[derive(Debug, Clone)]
struct TxResult {
    outcome: ExecutionOutcome,
}

/// An abort intent with its commit height.
#[derive(Debug, Clone)]
struct AbortEntry {
    /// The local block height at which this abort intent was committed.
    committed_at_height: u64,
    /// Whether this abort was consensus-committed (deterministic) or
    /// propagated from a remote EC (async, used only for coverability).
    consensus: bool,
}

impl ExecutionAccumulator {
    /// Create a new execution accumulator.
    ///
    /// `expected_txs` must be in wave order (= block order within the wave).
    /// Each entry is `(tx_hash, participating_shards)`.
    pub fn new(
        wave_id: WaveId,
        block_hash: Hash,
        block_height: u64,
        expected_txs: Vec<(Hash, Vec<ShardGroupId>)>,
    ) -> Self {
        Self {
            wave_id,
            block_hash,
            block_height,
            expected_txs,
            execution_results: HashMap::new(),
            provisioned: HashSet::new(),
            aborts: HashMap::new(),
            cached_target_vote_height: None,
            last_voted_height: None,
        }
    }

    /// Wave identifier.
    pub fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Block hash.
    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }

    /// Block height (= wave_starting_height).
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Number of expected transactions in this wave.
    pub fn expected_count(&self) -> usize {
        self.expected_txs.len()
    }

    /// Number of transactions with results (execution result or abort).
    pub fn completed_count(&self) -> usize {
        let mut count = self.execution_results.len();
        // Count aborts that don't also have an execution result
        for tx_hash in self.aborts.keys() {
            if !self.execution_results.contains_key(tx_hash) {
                count += 1;
            }
        }
        count
    }

    /// Whether all expected transactions have some outcome (execution result or abort).
    /// This is the legacy check — all txs resolved regardless of vote height.
    pub fn is_complete(&self) -> bool {
        self.expected_txs
            .iter()
            .all(|(h, _)| self.execution_results.contains_key(h) || self.aborts.contains_key(h))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Coverage Tracking (inputs that change vote height)
    // ═══════════════════════════════════════════════════════════════════════

    /// Mark a transaction as having received provisions.
    ///
    /// This means execution is possible/in-flight. Changes the target vote
    /// height because a previously uncovered tx becomes covered.
    pub fn mark_provisioned(&mut self, tx_hash: Hash) {
        if self.expected_txs.iter().any(|(h, _)| *h == tx_hash) && self.provisioned.insert(tx_hash)
        {
            self.invalidate_cached_target();
        }
    }

    /// Record an abort intent with the local block height at which it was committed.
    ///
    /// Abort intents are tracked separately from execution results.
    /// At vote emission time, the appropriate outcome (abort or execution) is
    /// chosen based on the target vote height.
    /// Returns `true` if the wave is now complete (all txs have some outcome).
    pub fn record_abort(
        &mut self,
        tx_hash: Hash,
        committed_at_height: u64,
        consensus: bool,
    ) -> bool {
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        self.aborts.insert(
            tx_hash,
            AbortEntry {
                committed_at_height,
                consensus,
            },
        );

        self.invalidate_cached_target();
        self.is_complete()
    }

    /// Record a transaction's execution outcome.
    ///
    /// Returns `true` if the wave is now complete (all txs have results).
    /// First-write-wins: ignores duplicate execution results for the same tx_hash.
    /// Use [`record_abort`] for abort intents, which override execution results.
    pub fn record_result(&mut self, tx_hash: Hash, outcome: ExecutionOutcome) -> bool {
        // Only record if this tx is expected in this wave
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        self.execution_results
            .entry(tx_hash)
            .or_insert(TxResult { outcome });

        self.is_complete()
    }

    /// Check if a specific transaction has an execution result or abort.
    pub fn has_result(&self, tx_hash: &Hash) -> bool {
        self.execution_results.contains_key(tx_hash) || self.aborts.contains_key(tx_hash)
    }

    /// Check if a specific transaction has an execution result (not just an abort).
    pub fn has_executed(&self, tx_hash: &Hash) -> bool {
        self.execution_results.contains_key(tx_hash)
    }

    /// Remove a transaction from the wave entirely.
    ///
    /// Called when a TC is committed for a transaction before local execution
    /// completes. The TX is done (canonical decision made), so it should no
    /// longer block the wave from completing. All validators process committed
    /// blocks identically, so the reduced expected set is deterministic.
    ///
    /// Returns `true` if the wave is now complete after removal.
    pub fn remove_expected(&mut self, tx_hash: &Hash) -> bool {
        self.expected_txs.retain(|(h, _)| h != tx_hash);
        self.execution_results.remove(tx_hash);
        self.provisioned.remove(tx_hash);
        self.aborts.remove(tx_hash);
        self.invalidate_cached_target();
        self.is_complete()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Vote Height Determination
    // ═══════════════════════════════════════════════════════════════════════

    /// Returns the target vote height — the lowest height at which every tx
    /// in the wave is *coverable*.
    ///
    /// A tx is coverable at vote_height N if:
    /// - It has provisions (execution possible), OR
    /// - It has an abort intent committed at block height ≤ wave_start + N
    ///
    /// Returns `None` if no vote height is coverable (some txs have neither
    /// provisions nor any abort intent).
    pub fn target_vote_height(&mut self) -> Option<u64> {
        if let Some(cached) = self.cached_target_vote_height {
            return Some(cached);
        }

        let wave_start = self.block_height;

        // For each tx, determine the minimum vote_height at which it's covered.
        // - If provisioned: covered at height 0 (no abort needed)
        // - If aborted: covered at height (committed_at - wave_start)
        // - If neither: not coverable at any height → return None
        let mut max_required_height: u64 = 0;

        for (tx_hash, _) in &self.expected_txs {
            if self.provisioned.contains(tx_hash) {
                // Covered at height 0
                continue;
            }
            if let Some(abort) = self.aborts.get(tx_hash) {
                // Covered at the height when the abort was committed
                let required = abort.committed_at_height.saturating_sub(wave_start);
                max_required_height = max_required_height.max(required);
            } else {
                // Not coverable at any height
                return None;
            }
        }

        self.cached_target_vote_height = Some(max_required_height);
        Some(max_required_height)
    }

    /// Whether a vote can be emitted at the current target height.
    ///
    /// Requires:
    /// 1. A target vote height exists (all txs coverable)
    /// 2. All txs covered by execution (not abort) at that height have results
    /// 3. The target height is lower than (or equal to) any previous vote
    ///    (only re-vote downward), OR no previous vote exists
    pub fn can_emit_vote(&mut self) -> bool {
        let Some(target) = self.target_vote_height() else {
            return false;
        };

        // Only re-vote downward
        if let Some(last) = self.last_voted_height {
            if target >= last {
                return false;
            }
        }

        // Check that all execution-covered txs at this height have results
        let wave_start = self.block_height;
        for (tx_hash, _) in &self.expected_txs {
            if self.is_covered_by_abort_at(tx_hash, wave_start + target) {
                continue; // Abort outcome is known immediately
            }
            // Must be covered by execution — check if result is available
            if !self.execution_results.contains_key(tx_hash) {
                return false;
            }
        }
        true
    }

    /// Build the receipt data at the target vote height.
    ///
    /// At the target height, each tx's outcome is:
    /// - Abort intent outcome (if abort committed at ≤ wave_start + target)
    /// - Execution result (otherwise — must exist since can_emit_vote() passed)
    ///
    /// Returns `(vote_height, global_receipt_root, tx_outcomes)`.
    /// Returns `None` if the vote cannot be emitted.
    pub fn build_vote_data(&mut self) -> Option<(u64, Hash, Vec<TxOutcome>)> {
        if !self.can_emit_vote() {
            return None;
        }

        let target = self.cached_target_vote_height.unwrap();
        let wave_start = self.block_height;

        let outcomes: Vec<TxOutcome> = self
            .expected_txs
            .iter()
            .map(|(tx_hash, _)| {
                let outcome = if let Some(abort) = self.aborts.get(tx_hash) {
                    if abort.consensus && abort.committed_at_height <= wave_start + target {
                        // Consensus-committed abort — deterministic, overrides execution.
                        ExecutionOutcome::Aborted
                    } else if !abort.consensus
                        && !self.execution_results.contains_key(tx_hash)
                        && abort.committed_at_height <= wave_start + target
                    {
                        // Async abort (remote EC) — only use if no execution result.
                        // If the tx executed, ignore the async abort; the consensus
                        // timeout will produce a deterministic abort later if needed.
                        ExecutionOutcome::Aborted
                    } else {
                        // Abort doesn't apply — use execution result
                        self.execution_results[tx_hash].outcome.clone()
                    }
                } else {
                    // No abort — use execution result
                    self.execution_results[tx_hash].outcome.clone()
                };
                TxOutcome {
                    tx_hash: *tx_hash,
                    outcome,
                }
            })
            .collect();

        let root = compute_execution_receipt_root(&outcomes);

        // Record that we voted at this height
        self.last_voted_height = Some(target);

        Some((target, root, outcomes))
    }

    /// Record that we voted at a specific height (set by external caller).
    pub fn set_last_voted_height(&mut self, height: u64) {
        self.last_voted_height = Some(height);
    }

    /// Build the receipt data once all transactions are complete (legacy path).
    ///
    /// Returns `(global_receipt_root, tx_outcomes)` where outcomes are in
    /// wave order (block order within the wave).
    ///
    /// Returns `None` if not all transactions have completed.
    pub fn build_data(&self) -> Option<(Hash, Vec<TxOutcome>)> {
        if !self.is_complete() {
            return None;
        }

        // Build outcomes in wave order (same as expected_txs order).
        // Abort outcomes take priority over execution results.
        let outcomes: Vec<TxOutcome> = self
            .expected_txs
            .iter()
            .map(|(tx_hash, _)| {
                let outcome = if self.aborts.contains_key(tx_hash) {
                    ExecutionOutcome::Aborted
                } else {
                    self.execution_results[tx_hash].outcome.clone()
                };
                TxOutcome {
                    tx_hash: *tx_hash,
                    outcome,
                }
            })
            .collect();

        let root = compute_execution_receipt_root(&outcomes);
        Some((root, outcomes))
    }

    /// Get the union of all participating shards across all txs in this wave.
    ///
    /// Used to determine which remote shards should receive the execution certificate.
    pub fn all_participating_shards(&self) -> Vec<ShardGroupId> {
        let mut shards: std::collections::BTreeSet<ShardGroupId> =
            std::collections::BTreeSet::new();
        for (_, participating) in &self.expected_txs {
            shards.extend(participating.iter());
        }
        shards.into_iter().collect()
    }

    /// Get the transaction hashes in wave order.
    pub fn tx_hashes(&self) -> Vec<Hash> {
        self.expected_txs.iter().map(|(h, _)| *h).collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn invalidate_cached_target(&mut self) {
        self.cached_target_vote_height = None;
    }

    /// Check if a tx is covered by an abort intent at or before the given absolute height.
    fn is_covered_by_abort_at(&self, tx_hash: &Hash, abs_height: u64) -> bool {
        self.aborts
            .get(tx_hash)
            .is_some_and(|a| a.committed_at_height <= abs_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn make_accumulator(n: usize) -> ExecutionAccumulator {
        let txs: Vec<(Hash, Vec<ShardGroupId>)> = (0..n)
            .map(|i| {
                (
                    Hash::from_bytes(&[i as u8; 4]),
                    vec![ShardGroupId(0), ShardGroupId(1)],
                )
            })
            .collect();

        ExecutionAccumulator::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            10,
            txs,
        )
    }

    fn executed(receipt: Hash) -> ExecutionOutcome {
        ExecutionOutcome::Executed {
            receipt_hash: receipt,
            success: true,
            write_nodes: vec![],
        }
    }

    fn executed_fail(receipt: Hash) -> ExecutionOutcome {
        ExecutionOutcome::Executed {
            receipt_hash: receipt,
            success: false,
            write_nodes: vec![],
        }
    }

    #[test]
    fn test_empty_accumulator() {
        let mut acc = make_accumulator(0);
        assert!(acc.is_complete());
        let (root, outcomes) = acc.build_data().unwrap();
        assert_eq!(root, Hash::ZERO);
        assert!(outcomes.is_empty());
        // Empty wave: target vote height is 0, can emit immediately
        assert_eq!(acc.target_vote_height(), Some(0));
    }

    #[test]
    fn test_single_tx_provisioned_and_executed() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);
        let receipt = Hash::from_bytes(b"receipt");

        // Not coverable yet — no provisions, no abort
        assert_eq!(acc.target_vote_height(), None);

        // Provisions arrive
        acc.mark_provisioned(tx_hash);
        assert_eq!(acc.target_vote_height(), Some(0));

        // Can't emit yet — no execution result
        assert!(!acc.can_emit_vote());

        // Execution completes
        acc.record_result(tx_hash, executed(receipt));
        assert!(acc.can_emit_vote());

        let (vh, root, outcomes) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 0);
        assert_ne!(root, Hash::ZERO);
        assert_eq!(outcomes.len(), 1);
    }

    #[test]
    fn test_abort_at_height() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);

        // No provisions, no abort — not coverable
        assert_eq!(acc.target_vote_height(), None);

        // Abort committed at height 15 (wave starts at 10)
        acc.record_abort(tx_hash, 15, true);

        // Target vote height = 15 - 10 = 5
        assert_eq!(acc.target_vote_height(), Some(5));

        // Can emit immediately (abort outcome is known)
        assert!(acc.can_emit_vote());

        let (vh, _, outcomes) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 5);
        assert!(outcomes[0].is_aborted());
    }

    #[test]
    fn test_mixed_wave_provisioned_and_aborted() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        let tx1 = Hash::from_bytes(&[1u8; 4]);

        // tx0 gets provisions, tx1 gets abort at height 12
        acc.mark_provisioned(tx0);
        acc.record_abort(tx1, 12, true);

        // Target = max(0, 12-10) = 2
        assert_eq!(acc.target_vote_height(), Some(2));

        // Can't emit yet — tx0 has provisions but no execution result
        assert!(!acc.can_emit_vote());

        // tx0 execution completes
        acc.record_result(tx0, executed(Hash::from_bytes(b"r0")));
        assert!(acc.can_emit_vote());

        let (vh, _, outcomes) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 2);
        assert!(!outcomes[0].is_aborted()); // tx0 executed
        assert!(outcomes[1].is_aborted()); // tx1 aborted
    }

    #[test]
    fn test_revote_downward_on_provision_arrival() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        let tx1 = Hash::from_bytes(&[1u8; 4]);

        // tx0 provisioned, tx1 has abort at height 15
        acc.mark_provisioned(tx0);
        acc.record_abort(tx1, 15, true);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r0")));

        // Vote at height 5 (15-10)
        let (vh, _, _) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 5);

        // Now tx1 provisions arrive → target drops to 0
        acc.mark_provisioned(tx1);
        assert_eq!(acc.target_vote_height(), Some(0));

        // Can't emit at height 0 yet — tx1 has no execution result
        // (abort is at height 5, but at height 0 there's no abort, so we need execution)
        assert!(!acc.can_emit_vote());

        // tx1 execution completes
        acc.record_result(tx1, executed(Hash::from_bytes(b"r1")));
        assert!(acc.can_emit_vote());

        let (vh, _, outcomes) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 0);
        // At height 0, both txs use execution results (no aborts at height 0)
        assert!(!outcomes[0].is_aborted());
        assert!(!outcomes[1].is_aborted());
    }

    #[test]
    fn test_no_revote_upward() {
        let mut acc = make_accumulator(1);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        // Provisioned and executed → vote at height 0
        acc.mark_provisioned(tx0);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r")));

        let (vh, _, _) = acc.build_vote_data().unwrap();
        assert_eq!(vh, 0);

        // Can't emit again at height 0 (already voted there)
        assert!(!acc.can_emit_vote());
    }

    #[test]
    fn test_multi_tx_completion() {
        let mut acc = make_accumulator(3);

        let tx1 = Hash::from_bytes(&[1u8; 4]);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        let tx2 = Hash::from_bytes(&[2u8; 4]);

        assert!(!acc.record_result(tx1, executed(Hash::from_bytes(b"r1"))));
        assert_eq!(acc.completed_count(), 1);
        assert!(!acc.is_complete());

        assert!(!acc.record_result(tx0, executed(Hash::from_bytes(b"r0"))));
        assert_eq!(acc.completed_count(), 2);

        assert!(acc.record_result(tx2, executed_fail(Hash::from_bytes(b"r2"))));
        assert!(acc.is_complete());
    }

    #[test]
    fn test_order_preserved() {
        let mut acc = make_accumulator(3);

        for i in (0..3).rev() {
            let tx = Hash::from_bytes(&[i as u8; 4]);
            let receipt = Hash::from_bytes(&[i as u8 + 100; 4]);
            acc.record_result(tx, executed(receipt));
        }

        let (_, outcomes) = acc.build_data().unwrap();

        // Outcomes should be in wave order (0, 1, 2), not completion order (2, 1, 0)
        for (i, outcome) in outcomes.iter().enumerate().take(3) {
            assert_eq!(outcome.tx_hash, Hash::from_bytes(&[i as u8; 4]));
        }
    }

    #[test]
    fn test_duplicate_result_ignored() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        acc.record_result(tx, executed(Hash::from_bytes(b"first")));
        acc.record_result(tx, executed_fail(Hash::from_bytes(b"second")));

        let (_, outcomes) = acc.build_data().unwrap();
        match &outcomes[0].outcome {
            ExecutionOutcome::Executed {
                receipt_hash,
                success,
                ..
            } => {
                assert_eq!(*receipt_hash, Hash::from_bytes(b"first"));
                assert!(success);
            }
            _ => panic!("expected Executed outcome"),
        }
    }

    #[test]
    fn test_unknown_tx_ignored() {
        let mut acc = make_accumulator(1);
        let unknown = Hash::from_bytes(b"unknown_tx");

        assert!(!acc.record_result(unknown, executed(Hash::from_bytes(b"r"))));
        assert_eq!(acc.completed_count(), 0);
    }

    #[test]
    fn test_build_returns_none_when_incomplete() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r")));

        assert!(acc.build_data().is_none());
    }

    #[test]
    fn test_abort_overrides_execution() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        // Execution result arrives first
        acc.record_result(tx, executed(Hash::from_bytes(b"exec")));

        // Abort intent arrives later — overrides
        acc.record_abort(tx, 12, true);

        let (_, outcomes) = acc.build_data().unwrap();
        assert!(outcomes[0].is_aborted());
    }

    #[test]
    fn test_all_participating_shards() {
        let txs = vec![
            (
                Hash::from_bytes(&[0u8; 4]),
                vec![ShardGroupId(0), ShardGroupId(1)],
            ),
            (
                Hash::from_bytes(&[1u8; 4]),
                vec![ShardGroupId(1), ShardGroupId(2)],
            ),
        ];
        let acc = ExecutionAccumulator::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"b"),
            1,
            txs,
        );

        let shards = acc.all_participating_shards();
        assert_eq!(
            shards,
            vec![ShardGroupId(0), ShardGroupId(1), ShardGroupId(2)]
        );
    }

    #[test]
    fn test_partially_coverable() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        // Only tx0 has provisions — tx1 has nothing
        acc.mark_provisioned(tx0);
        assert_eq!(acc.target_vote_height(), None); // tx1 uncoverable
    }
}
