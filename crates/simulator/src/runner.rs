//! Main simulator runner.
//!
//! Orchestrates workload generation, transaction submission, and metrics collection
//! using the deterministic simulation framework.

use crate::accounts::AccountPool;
use crate::config::SimulatorConfig;
use crate::metrics::{MetricsCollector, SimulationReport};
use crate::workload::{MixedWorkload, TransferWorkload, WorkloadGenerator};
use hyperscale_core::{Event, RequestId};
use hyperscale_mempool::LockContentionStats;
use hyperscale_simulation::NodeIndex;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{
    shard_for_node, Hash, ShardGroupId, TransactionDecision, TransactionStatus,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Main simulator that orchestrates workload generation and metrics collection.
pub struct Simulator {
    /// Underlying deterministic simulation runner.
    runner: SimulationRunner,

    /// Account pool for transaction generation.
    accounts: AccountPool,

    /// Workload generator.
    workload: MixedWorkload,

    /// Metrics collector.
    metrics: MetricsCollector,

    /// Configuration.
    config: SimulatorConfig,

    /// RNG for workload generation.
    rng: ChaCha8Rng,

    /// Tracks in-flight transactions: hash -> (submit_time, target_shard).
    in_flight: HashMap<Hash, (Duration, ShardGroupId)>,

    /// Request ID counter.
    next_request_id: u64,
}

impl Simulator {
    /// Create a new simulator with the given configuration.
    pub fn new(config: SimulatorConfig) -> Result<Self, SimulatorError> {
        let network_config = config.to_network_config();
        let runner = SimulationRunner::new(network_config, config.seed);

        // Generate accounts
        let accounts = AccountPool::generate(config.num_shards as u64, config.accounts_per_shard)?;

        // Create workload generator
        let transfer = TransferWorkload::new(config.workload.cross_shard_ratio)
            .with_distribution(config.workload.account_distribution);
        let workload = MixedWorkload::new(transfer, config.workload.batch_size);

        // RNG for workload (separate from simulation RNG for independence)
        let rng = ChaCha8Rng::seed_from_u64(config.seed.wrapping_add(1));

        // Metrics start at time zero (will be reset when we actually start)
        let metrics = MetricsCollector::new(Duration::ZERO);

        info!(
            num_shards = config.num_shards,
            validators_per_shard = config.validators_per_shard,
            accounts_per_shard = config.accounts_per_shard,
            "Simulator created"
        );

        Ok(Self {
            runner,
            accounts,
            workload,
            metrics,
            config,
            rng,
            in_flight: HashMap::new(),
            next_request_id: 1,
        })
    }

    /// Initialize the simulation (genesis, etc).
    ///
    /// This funds all generated accounts at genesis time with the configured
    /// initial balance, allowing transactions to execute without failing due
    /// to insufficient funds.
    ///
    /// Also runs a warmup period to let the consensus establish before
    /// transaction submission begins. This ensures cross-shard provisioning
    /// works correctly from the start.
    pub fn initialize(&mut self) {
        // Collect all account balances for genesis
        let balances: Vec<_> = self
            .accounts
            .shards()
            .flat_map(|shard| {
                self.accounts
                    .genesis_balances_for_shard(shard, self.config.initial_balance)
            })
            .collect();

        info!(
            num_accounts = balances.len(),
            initial_balance = %self.config.initial_balance,
            "Funding accounts at genesis"
        );

        self.runner.initialize_genesis_with_balances(balances);

        // Run a warmup period to let consensus establish.
        // This ensures at least a few blocks are committed before we start
        // submitting transactions. Without this, cross-shard transactions
        // submitted immediately after genesis may fail because provisioning
        // requires blocks to be committed first.
        //
        // Warmup time: 3 block intervals (default 300ms each = 900ms)
        // This allows:
        // - Block 1 to be proposed and committed
        // - Block 2 to be proposed and committed
        // - Consensus to stabilize across all shards
        let warmup_duration = Duration::from_millis(900);
        info!(
            warmup_ms = warmup_duration.as_millis(),
            "Running warmup period for consensus to establish"
        );
        self.runner.run_until(self.runner.now() + warmup_duration);

        info!("Genesis initialized with funded accounts");
    }

    /// Run the simulation for the specified duration.
    ///
    /// Returns a report with throughput and latency metrics.
    pub fn run_for(&mut self, duration: Duration) -> SimulationReport {
        let start_time = self.runner.now();
        self.metrics = MetricsCollector::new(start_time);

        let batch_interval = self.config.workload.batch_interval;
        let submission_end_time = start_time + duration;

        info!(
            duration_secs = duration.as_secs(),
            batch_interval_ms = batch_interval.as_millis(),
            batch_size = self.config.workload.batch_size,
            "Starting simulation"
        );

        // Main simulation loop
        let mut last_progress_time = start_time;
        let progress_interval = Duration::from_secs(5);

        while self.runner.now() < submission_end_time {
            // Generate and submit a batch of transactions
            let current_time = self.runner.now();
            let batch = self
                .workload
                .generate_batch(&mut self.accounts, &mut self.rng);

            for tx in batch {
                let hash = tx.hash();
                let target_shard = self.get_target_shard(&tx);

                // Submit to ALL validators in the shard to ensure the proposer has the tx.
                // This mirrors real-world behavior where clients submit to multiple validators.
                // Without this, transactions may miss the next block because gossip hasn't
                // propagated to the proposer yet when their proposal timer fires.
                let shard_nodes = self.nodes_for_shard(target_shard);
                for node_idx in shard_nodes {
                    let request_id = RequestId(self.next_request_id);
                    self.next_request_id += 1;

                    self.runner.schedule_initial_event(
                        node_idx,
                        Duration::ZERO,
                        Event::SubmitTransaction {
                            tx: tx.clone(),
                            request_id,
                        },
                    );
                }

                self.in_flight.insert(hash, (current_time, target_shard));
                self.metrics.record_submission();
            }

            // First, run a tiny step to process the submitted transactions
            // This ensures they're in mempools before any proposal timers fire.
            // The event priority system processes Client events last, so we need
            // to advance time slightly to get them processed.
            self.runner
                .run_until(self.runner.now() + Duration::from_micros(1));

            // Advance simulation by one batch interval
            let next_time = self.runner.now() + batch_interval;
            self.runner.run_until(next_time);

            // Check for completed transactions
            self.check_completions();

            // Progress logging
            if self.runner.now() - last_progress_time >= progress_interval {
                self.log_progress(start_time, submission_end_time);
                last_progress_time = self.runner.now();
            }
        }

        // Submission phase complete
        self.metrics.set_submission_end_time(self.runner.now());
        info!(
            in_flight = self.in_flight.len(),
            "Submission phase complete, entering ramp-down"
        );

        // Ramp-down: wait for in-flight transactions to complete
        let ramp_down_timeout = Duration::from_secs(30);
        let ramp_down_deadline = self.runner.now() + ramp_down_timeout;

        while !self.in_flight.is_empty() && self.runner.now() < ramp_down_deadline {
            let step = Duration::from_millis(100);
            self.runner.run_until(self.runner.now() + step);
            self.check_completions();
        }

        if !self.in_flight.is_empty() {
            warn!(
                remaining = self.in_flight.len(),
                "Ramp-down timeout reached with in-flight transactions"
            );
            // Debug: dump status of remaining transactions
            self.dump_in_flight_status();
        }

        let end_time = self.runner.now();
        info!(
            total_time_secs = (end_time - start_time).as_secs_f64(),
            "Simulation complete"
        );

        // Generate and return report
        let report = std::mem::replace(&mut self.metrics, MetricsCollector::new(Duration::ZERO))
            .finalize(end_time);

        report.print_summary();
        report
    }

    /// Check for completed transactions and record metrics.
    fn check_completions(&mut self) {
        let current_time = self.runner.now();

        // We need to check the mempool status for each in-flight transaction
        // This is a polling approach - in a more sophisticated version we'd use events
        let hashes: Vec<Hash> = self.in_flight.keys().copied().collect();

        for hash in hashes {
            if let Some((submit_time, shard)) = self.in_flight.get(&hash).copied() {
                // Check status from a node in the target shard
                let node_idx = self.get_node_for_shard(shard);
                if let Some(node) = self.runner.node(node_idx) {
                    if let Some(status) = node.mempool().status(&hash) {
                        match status {
                            TransactionStatus::Completed => {
                                let latency = current_time.saturating_sub(submit_time);
                                self.metrics.record_finalization(latency);
                                self.in_flight.remove(&hash);
                                debug!(
                                    ?hash,
                                    latency_ms = latency.as_millis(),
                                    "Transaction completed"
                                );
                            }
                            TransactionStatus::Finalized(TransactionDecision::Accept) => {
                                let latency = current_time.saturating_sub(submit_time);
                                self.metrics.record_finalization(latency);
                                self.in_flight.remove(&hash);
                                debug!(
                                    ?hash,
                                    latency_ms = latency.as_millis(),
                                    "Transaction finalized (accept)"
                                );
                            }
                            TransactionStatus::Finalized(TransactionDecision::Reject) => {
                                self.metrics.record_rejection();
                                self.in_flight.remove(&hash);
                                debug!(?hash, "Transaction rejected");
                            }
                            TransactionStatus::Retried { new_tx } => {
                                // Transaction was retried - track the new hash instead
                                self.in_flight.remove(&hash);
                                self.in_flight.insert(new_tx, (submit_time, shard));
                                debug!(?hash, ?new_tx, "Transaction retried");
                            }
                            _ => {
                                // Still in progress
                            }
                        }
                    }
                }
            }
        }
    }

    /// Determine the target shard for a transaction.
    fn get_target_shard(&self, tx: &hyperscale_types::RoutableTransaction) -> ShardGroupId {
        tx.declared_writes
            .first()
            .map(|node_id| shard_for_node(node_id, self.config.num_shards as u64))
            .unwrap_or(ShardGroupId(0))
    }

    /// Get a node index for submitting to a shard (for status checks).
    fn get_node_for_shard(&self, shard: ShardGroupId) -> u32 {
        // Return the first validator in the shard
        shard.0 as u32 * self.config.validators_per_shard
    }

    /// Get all node indices in a shard.
    fn nodes_for_shard(&self, shard: ShardGroupId) -> Vec<NodeIndex> {
        let start = shard.0 as u32 * self.config.validators_per_shard;
        let end = start + self.config.validators_per_shard;
        (start..end).collect()
    }

    /// Log progress during simulation.
    fn log_progress(&mut self, start_time: Duration, end_time: Duration) {
        let (submitted, finalized, rejected) = self.metrics.current_stats();
        let elapsed = self.runner.now() - start_time;
        let remaining = end_time.saturating_sub(self.runner.now());

        let tps = if elapsed.as_secs_f64() > 0.0 {
            finalized as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        // Aggregate lock contention stats from all shards
        let lock_stats = self.aggregate_lock_contention();

        // Take a sample
        self.metrics
            .sample(self.runner.now(), self.in_flight.len() as u64, lock_stats);

        info!(
            elapsed_secs = elapsed.as_secs(),
            remaining_secs = remaining.as_secs(),
            submitted,
            finalized,
            rejected,
            in_flight = self.in_flight.len(),
            tps = format!("{:.2}", tps),
            "Simulation progress"
        );
    }

    /// Aggregate lock contention stats from all shards.
    ///
    /// Sums stats from the first validator of each shard (they all see the same mempool).
    fn aggregate_lock_contention(&self) -> LockContentionStats {
        let mut total = LockContentionStats::default();

        for shard_idx in 0..self.config.num_shards {
            let node_idx = shard_idx * self.config.validators_per_shard;
            if let Some(node) = self.runner.node(node_idx) {
                let stats = node.mempool().lock_contention_stats();
                total.locked_nodes += stats.locked_nodes;
                total.blocked_count += stats.blocked_count;
                total.pending_count += stats.pending_count;
                total.pending_blocked += stats.pending_blocked;
            }
        }

        total
    }

    /// Get the underlying simulation runner (for advanced use).
    pub fn runner(&self) -> &SimulationRunner {
        &self.runner
    }

    /// Get mutable access to the simulation runner.
    pub fn runner_mut(&mut self) -> &mut SimulationRunner {
        &mut self.runner
    }

    /// Get account usage statistics.
    pub fn account_usage_stats(&self) -> crate::accounts::AccountUsageStats {
        self.accounts.usage_stats()
    }

    /// Analyze stuck transactions and potential livelocks.
    ///
    /// Returns a report of all incomplete transactions, grouped by status
    /// and shard, with potential cycle detection.
    pub fn analyze_livelocks(&self) -> crate::livelock::LivelockReport {
        let analyzer = crate::livelock::LivelockAnalyzer::from_runner(
            &self.runner,
            self.config.num_shards as u64,
            self.config.validators_per_shard,
        );
        analyzer.analyze()
    }

    /// Debug helper: dump the status of all in-flight transactions.
    fn dump_in_flight_status(&self) {
        use std::collections::BTreeMap;

        // Group by status for cleaner output
        let mut by_status: BTreeMap<String, Vec<Hash>> = BTreeMap::new();
        let mut not_found = Vec::new();

        for (hash, (submit_time, shard)) in &self.in_flight {
            let node_idx = self.get_node_for_shard(*shard);
            if let Some(node) = self.runner.node(node_idx) {
                if let Some(status) = node.mempool().status(hash) {
                    let status_str = format!("{:?}", status);
                    // Truncate long status strings
                    let status_key = if status_str.len() > 50 {
                        format!("{}...", &status_str[..50])
                    } else {
                        status_str
                    };
                    by_status.entry(status_key).or_default().push(*hash);
                } else {
                    not_found.push((*hash, *submit_time, *shard));
                }
            }
        }

        warn!("=== In-flight transaction status breakdown ===");
        for (status, hashes) in &by_status {
            warn!(
                status = %status,
                count = hashes.len(),
                sample = ?hashes.first(),
                "Status group"
            );
        }

        if !not_found.is_empty() {
            warn!(count = not_found.len(), "Transactions not found in mempool");
            // Log a few samples
            for (hash, submit_time, shard) in not_found.iter().take(3) {
                warn!(
                    ?hash,
                    submit_time_ms = submit_time.as_millis(),
                    shard = shard.0,
                    "Not found in mempool"
                );
            }
        }
    }
}

/// Errors that can occur during simulation.
#[derive(Debug, thiserror::Error)]
pub enum SimulatorError {
    #[error("Account pool error: {0}")]
    AccountPool(#[from] crate::accounts::AccountPoolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkloadConfig;

    #[test]
    fn test_simulator_creation() {
        let config = SimulatorConfig::new(1, 4)
            .with_accounts_per_shard(20)
            .with_workload(WorkloadConfig::transfers_only().with_batch_size(5));

        let simulator = Simulator::new(config);
        assert!(simulator.is_ok());
    }
}
