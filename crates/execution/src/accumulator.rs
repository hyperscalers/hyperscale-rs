//! Execution accumulator for collecting per-tx execution results within a wave.
//!
//! When a block is committed, transactions are partitioned into deterministic
//! waves based on their provision dependency sets. The `ExecutionAccumulator` tracks
//! which transactions in a wave have completed execution. Once all transactions
//! complete, the receipt merkle tree can be built and an execution vote signed.

use hyperscale_types::{
    compute_execution_receipt_root, Hash, ShardGroupId, TxExecutionOutcome, TxOutcome, WaveId,
};
use std::collections::HashMap;

/// Tracks execution progress for a single wave within a block.
///
/// Created when a block is committed, one per wave. Records per-tx execution
/// results as they complete (single-shard txs complete immediately, cross-shard
/// txs complete when provisions arrive and execution finishes).
///
/// When all expected txs have results, `build_data()` produces the
/// receipt merkle root and outcome list for execution vote signing.
#[derive(Debug)]
pub struct ExecutionAccumulator {
    /// Wave identifier (provision dependency set).
    wave_id: WaveId,
    /// Block this wave belongs to.
    block_hash: Hash,
    /// Block height.
    block_height: u64,
    /// Expected transactions in wave order (block order within the wave).
    /// Each entry is (tx_hash, participating_shards for that tx).
    expected_txs: Vec<(Hash, Vec<ShardGroupId>)>,
    /// Completed execution results, keyed by tx_hash.
    completed: HashMap<Hash, TxResult>,
}

/// Execution result for a single transaction.
#[derive(Debug, Clone)]
struct TxResult {
    outcome: TxExecutionOutcome,
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
            completed: HashMap::new(),
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

    /// Block height.
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Number of expected transactions in this wave.
    pub fn expected_count(&self) -> usize {
        self.expected_txs.len()
    }

    /// Number of completed transactions.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Whether all expected transactions have completed execution.
    pub fn is_complete(&self) -> bool {
        self.completed.len() == self.expected_txs.len()
    }

    /// Record a transaction's execution outcome.
    ///
    /// Returns `true` if the wave is now complete (all txs have results).
    /// First-write-wins: ignores duplicate execution results for the same tx_hash.
    /// Use [`record_abort`] for abort intents, which override execution results.
    pub fn record_result(&mut self, tx_hash: Hash, outcome: TxExecutionOutcome) -> bool {
        // Only record if this tx is expected in this wave
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        self.completed
            .entry(tx_hash)
            .or_insert(TxResult { outcome });

        self.is_complete()
    }

    /// Record an abort for a transaction, overriding any existing result.
    ///
    /// Abort intents are committed in blocks (deterministic), so they take
    /// precedence over async execution results. This ensures all validators
    /// converge to the same receipt_root regardless of execution timing.
    ///
    /// Returns `true` if the wave is now complete (all txs have results).
    pub fn record_abort(&mut self, tx_hash: Hash, outcome: TxExecutionOutcome) -> bool {
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        // Unconditional insert — abort overrides any existing execution result
        self.completed.insert(tx_hash, TxResult { outcome });

        self.is_complete()
    }

    /// Check if a specific transaction has completed.
    pub fn has_result(&self, tx_hash: &Hash) -> bool {
        self.completed.contains_key(tx_hash)
    }

    /// Build the receipt data once all transactions are complete.
    ///
    /// Returns `(receipt_root, tx_outcomes)` where outcomes are in
    /// wave order (block order within the wave).
    ///
    /// Returns `None` if not all transactions have completed.
    pub fn build_data(&self) -> Option<(Hash, Vec<TxOutcome>)> {
        if !self.is_complete() {
            return None;
        }

        // Build outcomes in wave order (same as expected_txs order)
        let outcomes: Vec<TxOutcome> = self
            .expected_txs
            .iter()
            .map(|(tx_hash, _)| {
                let result = &self.completed[tx_hash];
                TxOutcome {
                    tx_hash: *tx_hash,
                    outcome: result.outcome.clone(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_accumulator(n: usize) -> ExecutionAccumulator {
        let txs: Vec<(Hash, Vec<ShardGroupId>)> = (0..n)
            .map(|i| {
                (
                    Hash::from_bytes(&[i as u8; 4]),
                    vec![ShardGroupId(0), ShardGroupId(1)],
                )
            })
            .collect();

        ExecutionAccumulator::new(WaveId::zero(), Hash::from_bytes(b"block"), 10, txs)
    }

    fn executed(receipt: Hash) -> TxExecutionOutcome {
        TxExecutionOutcome::Executed {
            receipt_hash: receipt,
            success: true,
            write_nodes: vec![],
        }
    }

    fn executed_fail(receipt: Hash) -> TxExecutionOutcome {
        TxExecutionOutcome::Executed {
            receipt_hash: receipt,
            success: false,
            write_nodes: vec![],
        }
    }

    #[test]
    fn test_empty_accumulator() {
        let acc = make_accumulator(0);
        assert!(acc.is_complete());
        let (root, outcomes) = acc.build_data().unwrap();
        assert_eq!(root, Hash::ZERO);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn test_single_tx() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);
        let receipt = Hash::from_bytes(b"receipt");

        assert!(!acc.is_complete());
        assert!(acc.record_result(tx_hash, executed(receipt)));
        assert!(acc.is_complete());

        let (root, outcomes) = acc.build_data().unwrap();
        assert_ne!(root, Hash::ZERO);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].tx_hash, tx_hash);
        match &outcomes[0].outcome {
            TxExecutionOutcome::Executed { receipt_hash, .. } => {
                assert_eq!(*receipt_hash, receipt);
            }
            _ => panic!("expected Executed outcome"),
        }
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
            TxExecutionOutcome::Executed {
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
    fn test_abort_intent_wins_race() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        // Abort intent arrives first
        let abort = TxExecutionOutcome::Aborted {
            reason: hyperscale_types::AbortReason::ExecutionTimeout {
                committed_at: hyperscale_types::BlockHeight(5),
            },
        };
        assert!(acc.record_result(tx, abort));

        // Execution result arrives later — ignored (first-write-wins)
        acc.record_result(tx, executed(Hash::from_bytes(b"late")));

        let (_, outcomes) = acc.build_data().unwrap();
        assert!(outcomes[0].is_aborted());
    }

    #[test]
    fn test_execution_wins_race() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        // Execution result arrives first
        assert!(acc.record_result(tx, executed(Hash::from_bytes(b"exec"))));

        // Abort intent arrives later — ignored (first-write-wins)
        let abort = TxExecutionOutcome::Aborted {
            reason: hyperscale_types::AbortReason::ExecutionTimeout {
                committed_at: hyperscale_types::BlockHeight(5),
            },
        };
        acc.record_result(tx, abort);

        let (_, outcomes) = acc.build_data().unwrap();
        assert!(!outcomes[0].is_aborted());
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
        let acc = ExecutionAccumulator::new(WaveId::zero(), Hash::from_bytes(b"b"), 1, txs);

        let shards = acc.all_participating_shards();
        assert_eq!(
            shards,
            vec![ShardGroupId(0), ShardGroupId(1), ShardGroupId(2)]
        );
    }
}
