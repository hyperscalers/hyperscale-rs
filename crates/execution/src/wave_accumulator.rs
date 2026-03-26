//! Wave accumulator for collecting per-tx execution results within a wave.
//!
//! When a block is committed, transactions are partitioned into deterministic
//! waves based on their provision dependency sets. The `WaveAccumulator` tracks
//! which transactions in a wave have completed execution. Once all transactions
//! complete, the wave's receipt merkle tree can be built and a wave vote signed.

use hyperscale_types::{
    compute_wave_receipt_root, Hash, NodeId, ShardGroupId, WaveId, WaveTxOutcome,
};
use std::collections::HashMap;

/// Tracks execution progress for a single wave within a block.
///
/// Created when a block is committed, one per wave. Records per-tx execution
/// results as they complete (single-shard txs complete immediately, cross-shard
/// txs complete when provisions arrive and execution finishes).
///
/// When all expected txs have results, `build_wave_data()` produces the
/// receipt merkle root and outcome list for wave vote signing.
#[derive(Debug)]
pub struct WaveAccumulator {
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
    receipt_hash: Hash,
    success: bool,
    write_nodes: Vec<NodeId>,
}

impl WaveAccumulator {
    /// Create a new wave accumulator.
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

    /// Record a transaction's execution result.
    ///
    /// Returns `true` if the wave is now complete (all txs have results).
    /// Ignores duplicate results for the same tx_hash.
    pub fn record_result(
        &mut self,
        tx_hash: Hash,
        receipt_hash: Hash,
        success: bool,
        write_nodes: Vec<NodeId>,
    ) -> bool {
        // Only record if this tx is expected in this wave
        if !self.expected_txs.iter().any(|(h, _)| *h == tx_hash) {
            return false;
        }

        self.completed.entry(tx_hash).or_insert(TxResult {
            receipt_hash,
            success,
            write_nodes,
        });

        self.is_complete()
    }

    /// Check if a specific transaction has completed.
    pub fn has_result(&self, tx_hash: &Hash) -> bool {
        self.completed.contains_key(tx_hash)
    }

    /// Build the wave receipt data once all transactions are complete.
    ///
    /// Returns `(wave_receipt_root, tx_outcomes)` where outcomes are in
    /// wave order (block order within the wave).
    ///
    /// Returns `None` if not all transactions have completed.
    pub fn build_wave_data(&self) -> Option<(Hash, Vec<WaveTxOutcome>)> {
        if !self.is_complete() {
            return None;
        }

        // Build outcomes in wave order (same as expected_txs order)
        let outcomes: Vec<WaveTxOutcome> = self
            .expected_txs
            .iter()
            .map(|(tx_hash, _)| {
                let result = &self.completed[tx_hash];
                WaveTxOutcome {
                    tx_hash: *tx_hash,
                    receipt_hash: result.receipt_hash,
                    success: result.success,
                    write_nodes: result.write_nodes.clone(),
                }
            })
            .collect();

        let root = compute_wave_receipt_root(&outcomes);
        Some((root, outcomes))
    }

    /// Get the union of all participating shards across all txs in this wave.
    ///
    /// Used to determine which remote shards should receive the wave certificate.
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

    fn make_accumulator(n: usize) -> WaveAccumulator {
        let txs: Vec<(Hash, Vec<ShardGroupId>)> = (0..n)
            .map(|i| {
                (
                    Hash::from_bytes(&[i as u8; 4]),
                    vec![ShardGroupId(0), ShardGroupId(1)],
                )
            })
            .collect();

        WaveAccumulator::new(WaveId::zero(), Hash::from_bytes(b"block"), 10, txs)
    }

    #[test]
    fn test_empty_wave() {
        let acc = make_accumulator(0);
        assert!(acc.is_complete());
        let (root, outcomes) = acc.build_wave_data().unwrap();
        assert_eq!(root, Hash::ZERO);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn test_single_tx_wave() {
        let mut acc = make_accumulator(1);
        let tx_hash = Hash::from_bytes(&[0u8; 4]);
        let receipt = Hash::from_bytes(b"receipt");

        assert!(!acc.is_complete());
        assert!(acc.record_result(tx_hash, receipt, true, vec![]));
        assert!(acc.is_complete());

        let (root, outcomes) = acc.build_wave_data().unwrap();
        assert_ne!(root, Hash::ZERO);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].tx_hash, tx_hash);
        assert_eq!(outcomes[0].receipt_hash, receipt);
    }

    #[test]
    fn test_multi_tx_wave_completion() {
        let mut acc = make_accumulator(3);

        // Complete txs out of order
        let tx1 = Hash::from_bytes(&[1u8; 4]);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        let tx2 = Hash::from_bytes(&[2u8; 4]);

        assert!(!acc.record_result(tx1, Hash::from_bytes(b"r1"), true, vec![]));
        assert_eq!(acc.completed_count(), 1);
        assert!(!acc.is_complete());

        assert!(!acc.record_result(tx0, Hash::from_bytes(b"r0"), true, vec![]));
        assert_eq!(acc.completed_count(), 2);

        assert!(acc.record_result(tx2, Hash::from_bytes(b"r2"), false, vec![]));
        assert!(acc.is_complete());
    }

    #[test]
    fn test_wave_order_preserved() {
        let mut acc = make_accumulator(3);

        // Complete in reverse order
        for i in (0..3).rev() {
            let tx = Hash::from_bytes(&[i as u8; 4]);
            let receipt = Hash::from_bytes(&[i as u8 + 100; 4]);
            acc.record_result(tx, receipt, true, vec![]);
        }

        let (_, outcomes) = acc.build_wave_data().unwrap();
        // Outcomes should be in wave order (0, 1, 2), not completion order (2, 1, 0)
        for i in 0..3 {
            assert_eq!(outcomes[i].tx_hash, Hash::from_bytes(&[i as u8; 4]));
        }
    }

    #[test]
    fn test_duplicate_result_ignored() {
        let mut acc = make_accumulator(1);
        let tx = Hash::from_bytes(&[0u8; 4]);

        acc.record_result(tx, Hash::from_bytes(b"first"), true, vec![]);
        acc.record_result(tx, Hash::from_bytes(b"second"), false, vec![]);

        let (_, outcomes) = acc.build_wave_data().unwrap();
        // First result should win
        assert_eq!(outcomes[0].receipt_hash, Hash::from_bytes(b"first"));
        assert!(outcomes[0].success);
    }

    #[test]
    fn test_unknown_tx_ignored() {
        let mut acc = make_accumulator(1);
        let unknown = Hash::from_bytes(b"unknown_tx");

        assert!(!acc.record_result(unknown, Hash::from_bytes(b"r"), true, vec![]));
        assert_eq!(acc.completed_count(), 0);
    }

    #[test]
    fn test_build_returns_none_when_incomplete() {
        let mut acc = make_accumulator(2);
        let tx0 = Hash::from_bytes(&[0u8; 4]);
        acc.record_result(tx0, Hash::from_bytes(b"r"), true, vec![]);

        assert!(acc.build_wave_data().is_none());
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
        let acc = WaveAccumulator::new(WaveId::zero(), Hash::from_bytes(b"b"), 1, txs);

        let shards = acc.all_participating_shards();
        assert_eq!(
            shards,
            vec![ShardGroupId(0), ShardGroupId(1), ShardGroupId(2)]
        );
    }
}
