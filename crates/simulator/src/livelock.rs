//! Livelock analysis for post-simulation diagnostics.
//!
//! This module provides tools to analyze transactions left in mempools after
//! simulation completes. Livelocks can occur in cross-shard scenarios where
//! multiple transactions hold locks on state that other transactions need.
//!
//! # Livelock Example
//!
//! ```text
//! Shard A receives TX_A first → locks state A → commits TX_A to block
//! Shard B receives TX_B first → locks state B → commits TX_B to block
//! Both shards broadcast provisions for their committed transaction
//!
//! Shard A receives TX_B gossip, but can't commit it because TX_A holds the lock
//! Shard B receives TX_A gossip, but can't commit it because TX_B holds the lock
//!
//! Deadlock: TX_A waits for provisions from shard B (which is waiting on TX_B)
//!           TX_B waits for provisions from shard A (which is waiting on TX_A)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let analyzer = LivelockAnalyzer::from_runner(&runner);
//! let report = analyzer.analyze();
//! report.print_summary();
//! ```

use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{
    shard_for_node, Hash, NodeId, RoutableTransaction, ShardGroupId, TransactionStatus,
};
use std::collections::{HashMap, HashSet};

/// Information about a stuck transaction.
#[derive(Debug, Clone)]
pub struct StuckTransaction {
    /// Transaction hash
    pub hash: Hash,
    /// Current status
    pub status: TransactionStatus,
    /// The transaction itself
    pub transaction: RoutableTransaction,
    /// Shard this transaction was found on
    pub shard: ShardGroupId,
    /// All shards this transaction writes to
    pub write_shards: Vec<ShardGroupId>,
    /// All shards this transaction reads from (cross-shard provisions)
    pub read_shards: Vec<ShardGroupId>,
    /// Whether this is a cross-shard transaction
    pub is_cross_shard: bool,
}

/// Potential livelock cycle between transactions.
#[derive(Debug, Clone)]
pub struct LivelockCycle {
    /// Transactions involved in the potential cycle
    pub transactions: Vec<Hash>,
    /// Addresses (NodeIds) that form the contention
    pub contended_addresses: Vec<NodeId>,
    /// Shards involved in the cycle
    pub involved_shards: Vec<ShardGroupId>,
}

/// Report of livelock analysis.
#[derive(Debug)]
pub struct LivelockReport {
    /// Total number of incomplete transactions found
    pub total_incomplete: usize,
    /// Transactions stuck in each status
    pub by_status: HashMap<String, Vec<StuckTransaction>>,
    /// Transactions grouped by shard
    pub by_shard: HashMap<ShardGroupId, Vec<StuckTransaction>>,
    /// Potential livelock cycles detected
    pub potential_cycles: Vec<LivelockCycle>,
    /// Cross-shard transactions that are stuck
    pub cross_shard_stuck: Vec<StuckTransaction>,
    /// Address contention map: address -> list of transactions holding/waiting
    pub address_contention: HashMap<NodeId, Vec<Hash>>,
    /// Analysis of blocked transactions: what status is each winner in?
    /// Maps winner_status -> count of blocked transactions waiting for winners in that status
    pub blocked_winner_analysis: HashMap<String, usize>,
}

impl LivelockReport {
    /// Check if there are any stuck transactions.
    pub fn has_stuck_transactions(&self) -> bool {
        self.total_incomplete > 0
    }

    /// Print a human-readable summary of the livelock analysis.
    pub fn print_summary(&self) {
        println!("\n🔍 Livelock Analysis Report");
        println!("============================\n");

        if self.total_incomplete == 0 {
            println!(
                "✅ No incomplete transactions found - all transactions finalized successfully!\n"
            );
            return;
        }

        println!("📊 Summary:");
        println!("  Total incomplete transactions: {}", self.total_incomplete);
        println!("  Cross-shard stuck: {}", self.cross_shard_stuck.len());
        println!(
            "  Potential livelock cycles: {}",
            self.potential_cycles.len()
        );
        println!();

        // Status breakdown
        println!("📈 By Status:");
        let status_order = ["Pending", "Committed", "Blocked", "Retried"];
        for status in &status_order {
            if let Some(txs) = self.by_status.get(*status) {
                if !txs.is_empty() {
                    println!("  {}: {} transactions", status, txs.len());
                }
            }
        }
        // Print any other statuses not in the predefined list
        for (status, txs) in &self.by_status {
            if !status_order.contains(&status.as_str()) && !txs.is_empty() {
                println!("  {}: {} transactions", status, txs.len());
            }
        }
        println!();

        // Shard breakdown
        println!("🗂️  By Shard:");
        let mut shard_ids: Vec<_> = self.by_shard.keys().collect();
        shard_ids.sort_by_key(|s| s.0);
        for shard_id in shard_ids {
            if let Some(txs) = self.by_shard.get(shard_id) {
                if !txs.is_empty() {
                    let cross_shard_count = txs.iter().filter(|tx| tx.is_cross_shard).count();
                    println!(
                        "  Shard {}: {} transactions ({} cross-shard)",
                        shard_id.0,
                        txs.len(),
                        cross_shard_count
                    );
                }
            }
        }
        println!();

        // Blocked winner analysis
        if !self.blocked_winner_analysis.is_empty() {
            println!("🔒 Blocked Transactions - Winner Status Analysis:");
            println!("  (Why are blocked transactions not getting retried?)");
            let mut sorted: Vec<_> = self.blocked_winner_analysis.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
            for (status, count) in sorted {
                println!("  Winner in {}: {} blocked txs waiting", status, count);
            }
            println!();
        }

        // Potential cycles
        if !self.potential_cycles.is_empty() {
            println!("⚠️  Potential Livelock Cycles:");
            for (i, cycle) in self.potential_cycles.iter().take(5).enumerate() {
                println!(
                    "  Cycle {}: {} transactions across shards {:?}",
                    i + 1,
                    cycle.transactions.len(),
                    cycle.involved_shards
                );
                println!(
                    "    Contended addresses: {}",
                    cycle.contended_addresses.len()
                );
            }
            if self.potential_cycles.len() > 5 {
                println!("  ... and {} more cycles", self.potential_cycles.len() - 5);
            }
            println!();
        }
    }
}

/// Analyzer for detecting livelocks in mempool state.
pub struct LivelockAnalyzer {
    /// Incomplete transactions collected from all shards
    stuck_transactions: Vec<StuckTransaction>,
    /// All transaction statuses (for looking up winner status)
    all_statuses: HashMap<Hash, TransactionStatus>,
}

impl LivelockAnalyzer {
    /// Create a new analyzer from the simulation runner.
    ///
    /// Collects incomplete transactions from all nodes in all shards.
    pub fn from_runner(
        runner: &SimulationRunner,
        num_shards: u64,
        validators_per_shard: u32,
    ) -> Self {
        let mut stuck_transactions = Vec::new();
        let mut seen_hashes = HashSet::new();
        let mut all_statuses = HashMap::new();

        // Collect from first validator of each shard (all validators see same mempool)
        for shard_idx in 0..num_shards {
            let shard = ShardGroupId(shard_idx);
            let first_node_idx = shard_idx as u32 * validators_per_shard;

            if let Some(node) = runner.node(first_node_idx) {
                let incomplete = node.mempool().incomplete_transactions();

                for (hash, status, tx) in incomplete {
                    // Store status for later lookup
                    all_statuses.insert(hash, status.clone());

                    // Avoid duplicates (same transaction may appear on multiple shards)
                    if seen_hashes.insert(hash) {
                        let write_shards: Vec<_> = tx
                            .declared_writes
                            .iter()
                            .map(|node_id| shard_for_node(node_id, num_shards))
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect();

                        let read_shards: Vec<_> = tx
                            .declared_reads
                            .iter()
                            .map(|node_id| shard_for_node(node_id, num_shards))
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .filter(|s| !write_shards.contains(s))
                            .collect();

                        let is_cross_shard = write_shards.len() > 1 || !read_shards.is_empty();

                        stuck_transactions.push(StuckTransaction {
                            hash,
                            status,
                            transaction: tx,
                            shard,
                            write_shards,
                            read_shards,
                            is_cross_shard,
                        });
                    }
                }
            }
        }

        Self {
            stuck_transactions,
            all_statuses,
        }
    }

    /// Analyze the collected transactions for livelocks.
    pub fn analyze(&self) -> LivelockReport {
        let total_incomplete = self.stuck_transactions.len();

        // Group by status
        let mut by_status: HashMap<String, Vec<StuckTransaction>> = HashMap::new();
        for tx in &self.stuck_transactions {
            by_status
                .entry(status_name(&tx.status))
                .or_default()
                .push(tx.clone());
        }

        // Group by shard
        let mut by_shard: HashMap<ShardGroupId, Vec<StuckTransaction>> = HashMap::new();
        for tx in &self.stuck_transactions {
            by_shard.entry(tx.shard).or_default().push(tx.clone());
        }

        // Find cross-shard stuck transactions
        let cross_shard_stuck: Vec<_> = self
            .stuck_transactions
            .iter()
            .filter(|tx| tx.is_cross_shard)
            .cloned()
            .collect();

        // Build address contention map
        let mut address_contention: HashMap<NodeId, Vec<Hash>> = HashMap::new();
        for tx in &self.stuck_transactions {
            for addr in &tx.transaction.declared_writes {
                address_contention.entry(*addr).or_default().push(tx.hash);
            }
        }

        // Detect potential cycles
        let potential_cycles = self.detect_cycles(&address_contention);

        // Analyze blocked transactions - what status is each winner in?
        let mut blocked_winner_analysis: HashMap<String, usize> = HashMap::new();
        for tx in &self.stuck_transactions {
            if let TransactionStatus::Blocked { by: winner_hash } = &tx.status {
                let winner_status_name =
                    if let Some(winner_status) = self.all_statuses.get(winner_hash) {
                        status_name(winner_status)
                    } else {
                        "Unknown/NotInPool".to_string()
                    };
                *blocked_winner_analysis
                    .entry(winner_status_name)
                    .or_insert(0) += 1;
            }
        }

        LivelockReport {
            total_incomplete,
            by_status,
            by_shard,
            potential_cycles,
            cross_shard_stuck,
            address_contention,
            blocked_winner_analysis,
        }
    }

    /// Detect potential livelock cycles based on address contention.
    ///
    /// A cycle occurs when transactions on different shards hold locks that
    /// other transactions need, forming a circular dependency.
    fn detect_cycles(
        &self,
        _address_contention: &HashMap<NodeId, Vec<Hash>>,
    ) -> Vec<LivelockCycle> {
        let mut cycles = Vec::new();

        // Simple cycle detection: find pairs of transactions where:
        // 1. TX_A writes to addr_x and reads from addr_y
        // 2. TX_B writes to addr_y and reads from addr_x
        // 3. TX_A and TX_B are on different shards
        for tx_a in &self.stuck_transactions {
            if !tx_a.is_cross_shard {
                continue;
            }

            for tx_b in &self.stuck_transactions {
                if tx_a.hash == tx_b.hash || !tx_b.is_cross_shard {
                    continue;
                }

                // Check if tx_a's writes conflict with tx_b's reads and vice versa
                let a_writes: HashSet<_> = tx_a.transaction.declared_writes.iter().collect();
                let b_writes: HashSet<_> = tx_b.transaction.declared_writes.iter().collect();
                let a_reads: HashSet<_> = tx_a.transaction.declared_reads.iter().collect();
                let b_reads: HashSet<_> = tx_b.transaction.declared_reads.iter().collect();

                // Check for bidirectional dependency
                let a_blocks_b = a_writes.intersection(&b_reads).count() > 0
                    || a_writes.intersection(&b_writes).count() > 0;
                let b_blocks_a = b_writes.intersection(&a_reads).count() > 0
                    || b_writes.intersection(&a_writes).count() > 0;

                if a_blocks_b && b_blocks_a {
                    // Found a potential cycle
                    let contended: Vec<_> = a_writes
                        .intersection(&b_reads)
                        .chain(a_writes.intersection(&b_writes))
                        .chain(b_writes.intersection(&a_reads))
                        .chain(b_writes.intersection(&a_writes))
                        .copied()
                        .copied()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();

                    let involved_shards: Vec<_> = tx_a
                        .write_shards
                        .iter()
                        .chain(&tx_b.write_shards)
                        .copied()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();

                    cycles.push(LivelockCycle {
                        transactions: vec![tx_a.hash, tx_b.hash],
                        contended_addresses: contended,
                        involved_shards,
                    });
                }
            }
        }

        // Deduplicate cycles (A-B same as B-A)
        let mut unique_cycles = Vec::new();
        let mut seen_pairs: HashSet<(Hash, Hash)> = HashSet::new();
        for cycle in cycles {
            if cycle.transactions.len() == 2 {
                let (a, b) = (cycle.transactions[0], cycle.transactions[1]);
                let pair = if a < b { (a, b) } else { (b, a) };
                if seen_pairs.insert(pair) {
                    unique_cycles.push(cycle);
                }
            } else {
                unique_cycles.push(cycle);
            }
        }

        unique_cycles
    }

    /// Get the number of incomplete transactions.
    pub fn incomplete_count(&self) -> usize {
        self.stuck_transactions.len()
    }

    /// Check if there are any incomplete transactions.
    pub fn has_incomplete(&self) -> bool {
        !self.stuck_transactions.is_empty()
    }
}

/// Get a human-readable name for a transaction status.
fn status_name(status: &TransactionStatus) -> String {
    status.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, TransactionDecision};

    #[test]
    fn test_status_name() {
        assert_eq!(status_name(&TransactionStatus::Pending), "pending");
        assert_eq!(
            status_name(&TransactionStatus::Committed(BlockHeight(1))),
            "committed(1)"
        );
        assert_eq!(
            status_name(&TransactionStatus::Completed(TransactionDecision::Accept)),
            "completed(accept)"
        );
    }
}
