//! Execution accumulator for collecting per-tx execution results within a wave.
//!
//! When a block is committed, transactions are partitioned into deterministic
//! waves based on their provision dependency sets. The `ExecutionAccumulator` tracks
//! which transactions in a wave have completed execution or been aborted.
//!
//! ## Vote Height Determination
//!
//! The target vote height is the lowest height at which every tx is *coverable*:
//! - Provisioned txs are covered at height 0 (execution possible)
//! - Conflict-aborted txs (node-ID overlap from committed provisions) are covered
//!   at the height the conflict was committed
//! - Unprovisioned txs are implicitly covered at `WAVE_TIMEOUT_BLOCKS` (deterministic timeout)
//!
//! Validators vote exactly once per wave. Vote emission requires all
//! execution-covered txs at the target height to have their results back.
//! Aborted/timed-out txs have known outcomes immediately.

use hyperscale_types::{
    compute_execution_receipt_root, ExecutionOutcome, Hash, ShardGroupId, TxOutcome, WaveId,
};
use std::collections::{HashMap, HashSet};

/// Number of blocks after wave start before unprovisioned txs are implicitly aborted.
/// Deterministic: all validators compute the same timeout from the same wave start height.
pub const WAVE_TIMEOUT_BLOCKS: u64 = 32;

/// Tracks execution progress for a single wave within a block.
///
/// Created when a block is committed, one per wave. Records per-tx execution
/// results as they complete (single-shard txs complete immediately, cross-shard
/// txs complete when provisions arrive and execution finishes).
///
/// Supports height-indexed abort tracking: a tx is "coverable" at vote_height N
/// if it has provisions, has a conflict committed at or before wave_start + N,
/// or N >= WAVE_TIMEOUT_BLOCKS.
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
    /// Explicit aborts (node-ID overlap conflicts from committed provisions)
    /// indexed by tx_hash. Value: the local block height at which the conflict
    /// was committed.
    aborts: HashMap<Hash, AbortEntry>,
    /// Cached target vote height. Recomputed when inputs change (provisions or aborts).
    cached_target_vote_height: Option<u64>,
    /// Whether we've emitted a vote for this wave. Once true, no more votes.
    voted: bool,
}

/// Execution result for a single transaction.
#[derive(Debug, Clone)]
struct TxResult {
    outcome: ExecutionOutcome,
}

/// An explicit abort (from a node-ID overlap conflict) with its commit height.
#[derive(Debug, Clone)]
struct AbortEntry {
    /// The local block height at which the conflict was committed.
    committed_at_height: u64,
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
            voted: false,
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

    /// Whether all expected transactions have a stored outcome (execution result or
    /// explicit abort). Does not account for implicit timeouts.
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

    /// Record an explicit abort (from a node-ID overlap conflict) at the given commit height.
    ///
    /// Aborts are tracked separately from execution results. At vote emission
    /// time, the appropriate outcome (abort or execution) is chosen based on
    /// the target vote height.
    /// Returns `true` if the wave is now complete (all txs have some stored outcome).
    pub fn record_abort(&mut self, tx_hash: Hash, committed_at_height: u64) -> bool {
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        self.aborts.insert(
            tx_hash,
            AbortEntry {
                committed_at_height,
            },
        );

        self.invalidate_cached_target();
        self.is_complete()
    }

    /// Record a transaction's execution outcome.
    ///
    /// Returns `true` if the wave is now complete (all txs have results).
    /// First-write-wins: ignores duplicate execution results for the same tx_hash.
    /// Use [`record_abort`] for conflict aborts, which take priority at the abort height.
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
    /// - It has provisions (execution possible) → covered at height 0
    /// - It has an explicit abort (conflict) committed at height H → covered at H - wave_start
    /// - Neither → implicitly covered at WAVE_TIMEOUT_BLOCKS (deterministic timeout)
    ///
    /// Always returns a value — every tx is coverable at worst by timeout.
    pub fn target_vote_height(&mut self) -> u64 {
        if let Some(cached) = self.cached_target_vote_height {
            return cached;
        }

        let wave_start = self.block_height;
        let mut max_required_height: u64 = 0;

        for (tx_hash, _) in &self.expected_txs {
            if self.provisioned.contains(tx_hash) {
                continue;
            }
            if let Some(abort) = self.aborts.get(tx_hash) {
                let required = abort.committed_at_height.saturating_sub(wave_start);
                max_required_height = max_required_height.max(required);
            } else {
                // Implicit timeout — coverable at WAVE_TIMEOUT_BLOCKS
                max_required_height = max_required_height.max(WAVE_TIMEOUT_BLOCKS);
            }
        }

        self.cached_target_vote_height = Some(max_required_height);
        max_required_height
    }

    /// Whether a vote can be emitted at the current target height.
    ///
    /// Requires:
    /// 1. We haven't voted yet
    /// 2. The committed chain has reached the target height
    /// 3. All txs covered by execution (not abort/timeout) at that height have results
    pub fn can_emit_vote(&mut self, committed_height: u64) -> bool {
        if self.voted {
            return false;
        }

        let target = self.target_vote_height();

        // Gate: committed chain must have reached the target height
        if committed_height < self.block_height + target {
            return false;
        }

        // Check that all execution-covered txs at this height have results.
        // Timed-out txs (not provisioned, no explicit abort, target >= TIMEOUT) and
        // explicitly aborted txs have known outcomes — no execution result needed.
        let wave_start = self.block_height;
        for (tx_hash, _) in &self.expected_txs {
            if self.is_covered_by_abort_at(tx_hash, wave_start + target) {
                continue;
            }
            if !self.provisioned.contains(tx_hash) && target >= WAVE_TIMEOUT_BLOCKS {
                continue; // Implicit timeout — abort outcome known
            }
            if !self.execution_results.contains_key(tx_hash) {
                return false;
            }
        }
        true
    }

    /// Build the receipt data at the target vote height.
    ///
    /// At the target height, each tx's outcome is:
    /// - Abort (if explicit abort committed at ≤ wave_start + target)
    /// - Abort (if implicit timeout: not provisioned and target ≥ WAVE_TIMEOUT_BLOCKS)
    /// - Execution result (otherwise — must exist since can_emit_vote() passed)
    ///
    /// Returns `(vote_height, global_receipt_root, tx_outcomes)`.
    /// Returns `None` if the vote cannot be emitted.
    pub fn build_vote_data(
        &mut self,
        committed_height: u64,
    ) -> Option<(u64, Hash, Vec<TxOutcome>)> {
        if !self.can_emit_vote(committed_height) {
            return None;
        }

        let target = self.cached_target_vote_height.unwrap();
        let wave_start = self.block_height;

        let outcomes: Vec<TxOutcome> = self
            .expected_txs
            .iter()
            .map(|(tx_hash, _)| {
                let outcome = if let Some(abort) = self.aborts.get(tx_hash) {
                    if abort.committed_at_height <= wave_start + target {
                        ExecutionOutcome::Aborted
                    } else {
                        self.execution_results[tx_hash].outcome.clone()
                    }
                } else if !self.provisioned.contains(tx_hash) && target >= WAVE_TIMEOUT_BLOCKS {
                    // Implicit timeout — no provisions, no explicit abort
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

        // Mark as voted — no more votes for this wave.
        self.voted = true;

        Some((target, root, outcomes))
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

    /// Check if a tx is covered by an explicit abort at or before the given absolute height.
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

    /// Wave starts at height 10. Use committed_height >= 10 + target to gate votes.
    const WAVE_START: u64 = 10;
    /// A committed_height high enough that timeout has elapsed.
    const HIGH: u64 = WAVE_START + WAVE_TIMEOUT_BLOCKS + 10;

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
            WAVE_START,
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
        assert_eq!(acc.target_vote_height(), 0);
        assert!(acc.can_emit_vote(WAVE_START));
        let (vh, root, outcomes) = acc.build_vote_data(WAVE_START).unwrap();
        assert_eq!(vh, 0);
        assert_eq!(root, Hash::ZERO);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn test_single_tx_provisioned_and_executed() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);
        let receipt = Hash::from_bytes(b"receipt");

        // No provisions — target is WAVE_TIMEOUT_BLOCKS (implicit timeout)
        assert_eq!(acc.target_vote_height(), WAVE_TIMEOUT_BLOCKS);

        // Provisions arrive → target drops to 0
        acc.mark_provisioned(tx_hash);
        assert_eq!(acc.target_vote_height(), 0);

        // Can't emit yet — no execution result
        assert!(!acc.can_emit_vote(WAVE_START));

        // Execution completes
        acc.record_result(tx_hash, executed(receipt));
        assert!(acc.can_emit_vote(WAVE_START));

        let (vh, root, outcomes) = acc.build_vote_data(WAVE_START).unwrap();
        assert_eq!(vh, 0);
        assert_ne!(root, Hash::ZERO);
        assert_eq!(outcomes.len(), 1);
    }

    #[test]
    fn test_abort_at_height() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);

        // No provisions, no abort — target is WAVE_TIMEOUT_BLOCKS
        assert_eq!(acc.target_vote_height(), WAVE_TIMEOUT_BLOCKS);

        // Abort committed at height 15 (wave starts at 10) → target = 5
        acc.record_abort(tx_hash, 15);
        assert_eq!(acc.target_vote_height(), 5);

        // Can emit once committed_height >= 15
        assert!(!acc.can_emit_vote(14));
        assert!(acc.can_emit_vote(15));

        let (vh, _, outcomes) = acc.build_vote_data(15).unwrap();
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
        acc.record_abort(tx1, 12);

        // Target = max(0, 12-10) = 2
        assert_eq!(acc.target_vote_height(), 2);

        // Can't emit yet — tx0 has provisions but no execution result
        assert!(!acc.can_emit_vote(12));

        // tx0 execution completes
        acc.record_result(tx0, executed(Hash::from_bytes(b"r0")));
        assert!(acc.can_emit_vote(12));

        let (vh, _, outcomes) = acc.build_vote_data(12).unwrap();
        assert_eq!(vh, 2);
        assert!(!outcomes[0].is_aborted()); // tx0 executed
        assert!(outcomes[1].is_aborted()); // tx1 aborted
    }

    #[test]
    fn test_vote_exactly_once() {
        let mut acc = make_accumulator(1);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        // Provisioned and executed → vote at height 0
        acc.mark_provisioned(tx0);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r")));

        let (vh, _, _) = acc.build_vote_data(WAVE_START).unwrap();
        assert_eq!(vh, 0);

        // Can't emit again — already voted once
        assert!(!acc.can_emit_vote(HIGH));
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
            acc.mark_provisioned(tx);
            let receipt = Hash::from_bytes(&[i as u8 + 100; 4]);
            acc.record_result(tx, executed(receipt));
        }

        let (_, _, outcomes) = acc.build_vote_data(WAVE_START).unwrap();

        // Outcomes should be in wave order (0, 1, 2), not completion order (2, 1, 0)
        for (i, outcome) in outcomes.iter().enumerate().take(3) {
            assert_eq!(outcome.tx_hash, Hash::from_bytes(&[i as u8; 4]));
        }
    }

    #[test]
    fn test_duplicate_result_ignored() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        acc.mark_provisioned(tx);
        acc.record_result(tx, executed(Hash::from_bytes(b"first")));
        acc.record_result(tx, executed_fail(Hash::from_bytes(b"second")));

        let (_, _, outcomes) = acc.build_vote_data(WAVE_START).unwrap();
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
    fn test_abort_overrides_execution_at_abort_height() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        // Execution result arrives first
        acc.mark_provisioned(tx);
        acc.record_result(tx, executed(Hash::from_bytes(b"exec")));

        // Conflict abort arrives later at height 12 — overrides at target >= 2
        acc.record_abort(tx, 12);

        // Target is still 0 (provisioned), but abort exists at height 2
        // At target 0, abort doesn't apply (committed_at 12 > wave_start + 0)
        let (vh, _, outcomes) = acc.build_vote_data(WAVE_START).unwrap();
        assert_eq!(vh, 0);
        assert!(!outcomes[0].is_aborted()); // execution result used at height 0
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
    fn test_implicit_timeout_coverable() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        // Only tx0 has provisions — tx1 falls back to implicit timeout
        acc.mark_provisioned(tx0);
        assert_eq!(acc.target_vote_height(), WAVE_TIMEOUT_BLOCKS);
    }

    #[test]
    fn test_implicit_timeout_emits_all_abort() {
        let mut acc = make_accumulator(2);

        // Neither tx has provisions — both timeout
        assert_eq!(acc.target_vote_height(), WAVE_TIMEOUT_BLOCKS);

        // Not yet at timeout height
        assert!(!acc.can_emit_vote(WAVE_START + WAVE_TIMEOUT_BLOCKS - 1));

        // At timeout height — can emit, all aborted
        assert!(acc.can_emit_vote(WAVE_START + WAVE_TIMEOUT_BLOCKS));

        let (vh, _, outcomes) = acc
            .build_vote_data(WAVE_START + WAVE_TIMEOUT_BLOCKS)
            .unwrap();
        assert_eq!(vh, WAVE_TIMEOUT_BLOCKS);
        assert!(outcomes[0].is_aborted());
        assert!(outcomes[1].is_aborted());
    }

    #[test]
    fn test_no_revote_after_timeout() {
        let mut acc = make_accumulator(1);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        // No provisions → timeout at WAVE_TIMEOUT_BLOCKS
        let (vh, _, outcomes) = acc.build_vote_data(HIGH).unwrap();
        assert_eq!(vh, WAVE_TIMEOUT_BLOCKS);
        assert!(outcomes[0].is_aborted());

        // Provisions arrive later — but we already voted, no re-vote allowed
        acc.mark_provisioned(tx0);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r")));
        assert!(!acc.can_emit_vote(HIGH));
    }

    #[test]
    fn test_committed_height_gates_vote() {
        let mut acc = make_accumulator(1);
        let tx0 = Hash::from_bytes(&[0u8; 4]);

        acc.mark_provisioned(tx0);
        acc.record_result(tx0, executed(Hash::from_bytes(b"r")));

        // target = 0, so need committed_height >= WAVE_START + 0 = 10
        assert!(!acc.can_emit_vote(WAVE_START - 1));
        assert!(acc.can_emit_vote(WAVE_START));
    }
}
