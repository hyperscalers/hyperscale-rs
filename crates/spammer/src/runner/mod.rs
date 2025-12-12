//! Spammer runner that orchestrates transaction generation and submission.

use crate::accounts::AccountPool;
use crate::client::{RpcClient, RpcError};
use crate::config::SpammerConfig;
use crate::latency::{LatencyReport, LatencyTracker};
use crate::workloads::{TransferWorkload, WorkloadGenerator};
use hyperscale_types::{shard_for_node, RoutableTransaction};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Transaction spammer that submits to real network endpoints.
pub struct Spammer {
    config: SpammerConfig,
    accounts: AccountPool,
    workload: Box<dyn WorkloadGenerator>,
    clients: Vec<RpcClient>,
    stats: SpammerStats,
    rng: ChaCha8Rng,
    latency_tracker: Option<LatencyTracker>,
    /// RNG for latency sampling (separate from tx generation).
    latency_rng: ChaCha8Rng,
}

impl Spammer {
    /// Create a new spammer with the given configuration.
    pub fn new(config: SpammerConfig) -> Result<Self, SpammerError> {
        config.validate().map_err(SpammerError::Config)?;

        // Generate accounts
        let accounts = AccountPool::generate(config.num_shards, config.accounts_per_shard)
            .map_err(SpammerError::AccountGeneration)?;

        // Load nonces from file to continue where previous runs left off
        match accounts.load_nonces_default() {
            Ok(n) if n > 0 => info!(loaded = n, "Loaded account nonces from file"),
            Ok(_) => {} // No file or empty, starting fresh
            Err(e) => warn!(error = %e, "Failed to load nonces, starting fresh"),
        }

        // Create RPC clients
        let clients: Vec<RpcClient> = config.rpc_endpoints.iter().map(RpcClient::new).collect();

        // Create workload generator
        let workload = Box::new(
            TransferWorkload::new(config.network.clone())
                .with_cross_shard_ratio(config.cross_shard_ratio)
                .with_selection_mode(config.selection_mode),
        );

        // Create latency tracker if enabled
        let latency_tracker = if config.latency_tracking {
            Some(LatencyTracker::new(
                clients.clone(),
                config.latency_poll_interval,
            ))
        } else {
            None
        };

        // Use current time as seed to generate unique transactions each run
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Ok(Self {
            config,
            accounts,
            workload,
            clients,
            stats: SpammerStats::default(),
            rng: ChaCha8Rng::seed_from_u64(seed),
            latency_tracker,
            latency_rng: ChaCha8Rng::seed_from_u64(seed.wrapping_add(1)),
        })
    }

    /// Run the spammer for a specified duration.
    pub async fn run_for(&mut self, duration: Duration) -> SpammerReport {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Spawn a task to cancel after duration
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            cancel_clone.cancel();
        });

        self.run_until_cancelled(cancel).await
    }

    /// Run the spammer until the cancellation token is triggered.
    pub async fn run_until_cancelled(&mut self, cancel: CancellationToken) -> SpammerReport {
        let start = Instant::now();
        self.stats.start_time = Some(start);
        let mut last_progress = Instant::now();
        let batch_interval = self.config.batch_interval();

        // Start latency tracking if enabled
        if let Some(ref mut tracker) = self.latency_tracker {
            tracker.start_polling();
        }

        info!(
            target_tps = self.config.target_tps,
            batch_size = self.config.batch_size,
            batch_interval_ms = batch_interval.as_millis(),
            latency_tracking = self.latency_tracker.is_some(),
            "Starting spammer"
        );

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // Generate a batch of transactions
            let batch =
                self.workload
                    .generate_batch(&self.accounts, self.config.batch_size, &mut self.rng);

            // Submit all transactions in the batch
            for tx in batch {
                self.submit_transaction(tx).await;
            }

            // Print progress periodically
            if last_progress.elapsed() >= self.config.progress_interval {
                self.print_progress(start.elapsed()).await;
                last_progress = Instant::now();
            }

            // Sleep to maintain target TPS
            tokio::time::sleep(batch_interval).await;
        }

        // Print final progress
        self.print_progress(start.elapsed()).await;

        // Save nonces for next run
        match self.accounts.save_nonces_default() {
            Ok(n) => info!(saved = n, "Saved account nonces to file"),
            Err(e) => warn!(error = %e, "Failed to save nonces"),
        }

        // Finalize latency tracking
        let latency_report = if let Some(tracker) = self.latency_tracker.take() {
            Some(tracker.finalize().await)
        } else {
            None
        };

        SpammerReport {
            duration: start.elapsed(),
            total_submitted: self.stats.submitted.load(Ordering::SeqCst),
            total_accepted: self.stats.accepted.load(Ordering::SeqCst),
            total_rejected: self.stats.rejected.load(Ordering::SeqCst),
            total_errors: self.stats.errors.load(Ordering::SeqCst),
            avg_tps: self.stats.tps(),
            latency_report,
        }
    }

    /// Submit a single transaction to the appropriate shard endpoint.
    async fn submit_transaction(&mut self, tx: RoutableTransaction) {
        self.stats.submitted.fetch_add(1, Ordering::SeqCst);

        // Determine which shard to submit to based on the transaction's writes
        let target_shard = if let Some(first_write) = tx.declared_writes.first() {
            shard_for_node(first_write, self.config.num_shards).0 as usize
        } else {
            0
        };

        // Get the client for this shard (modulo number of clients)
        let client_idx = target_shard % self.clients.len();
        let client = &self.clients[client_idx];

        // Decide if we should track this transaction for latency
        let should_track = self.latency_tracker.is_some()
            && self.latency_rng.gen::<f64>() < self.config.latency_sample_rate;

        // Submit the transaction
        match client.submit_transaction(&tx).await {
            Ok(result) => {
                if result.accepted {
                    self.stats.accepted.fetch_add(1, Ordering::SeqCst);

                    // Track for latency measurement if sampled
                    if should_track {
                        if let Some(ref tracker) = self.latency_tracker {
                            tracker.track(result.hash, client_idx).await;
                        }
                    }
                } else {
                    self.stats.rejected.fetch_add(1, Ordering::SeqCst);
                    if let Some(error) = result.error {
                        warn!(error = %error, "Transaction rejected");
                    }
                }
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Ordering::SeqCst);
                warn!(error = %e, "Failed to submit transaction");
            }
        }
    }

    /// Print progress statistics.
    async fn print_progress(&self, elapsed: Duration) {
        let submitted = self.stats.submitted.load(Ordering::SeqCst);
        let accepted = self.stats.accepted.load(Ordering::SeqCst);
        let rejected = self.stats.rejected.load(Ordering::SeqCst);
        let errors = self.stats.errors.load(Ordering::SeqCst);
        let tps = self.stats.tps();

        // Get in-flight count for latency tracking
        let in_flight_info = if let Some(ref tracker) = self.latency_tracker {
            let count = tracker.in_flight_count().await;
            format!(" | tracking: {}", count)
        } else {
            String::new()
        };

        println!(
            "[{:>3}s] submitted: {} | accepted: {} | rejected: {} | errors: {} | tps: {:.0}{}",
            elapsed.as_secs(),
            submitted,
            accepted,
            rejected,
            errors,
            tps,
            in_flight_info
        );
    }

    /// Get current statistics.
    pub fn stats(&self) -> &SpammerStats {
        &self.stats
    }

    /// Get genesis balances for all accounts.
    pub fn genesis_balances(&self, balance: Decimal) -> Vec<(ComponentAddress, Decimal)> {
        self.accounts.all_genesis_balances(balance)
    }

    /// Wait for all RPC endpoints to be ready.
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<(), SpammerError> {
        let start = Instant::now();

        while start.elapsed() < timeout {
            let mut all_ready = true;

            for client in &self.clients {
                if !client.is_ready().await {
                    all_ready = false;
                    break;
                }
            }

            if all_ready {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(SpammerError::NodesNotReady)
    }
}

/// Statistics collected during spamming.
#[derive(Default)]
pub struct SpammerStats {
    /// Number of transactions submitted.
    pub submitted: AtomicU64,
    /// Number of transactions accepted.
    pub accepted: AtomicU64,
    /// Number of transactions rejected.
    pub rejected: AtomicU64,
    /// Number of errors (network failures, etc.).
    pub errors: AtomicU64,
    /// Start time of the run.
    pub start_time: Option<Instant>,
}

impl SpammerStats {
    /// Calculate current transactions per second.
    pub fn tps(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.submitted.load(Ordering::SeqCst) as f64 / elapsed;
            }
        }
        0.0
    }

    /// Calculate acceptance rate.
    pub fn acceptance_rate(&self) -> f64 {
        let submitted = self.submitted.load(Ordering::SeqCst);
        if submitted > 0 {
            self.accepted.load(Ordering::SeqCst) as f64 / submitted as f64
        } else {
            0.0
        }
    }
}

/// Report generated after a spammer run.
pub struct SpammerReport {
    /// Total duration of the run.
    pub duration: Duration,
    /// Total transactions submitted.
    pub total_submitted: u64,
    /// Total transactions accepted.
    pub total_accepted: u64,
    /// Total transactions rejected.
    pub total_rejected: u64,
    /// Total errors encountered.
    pub total_errors: u64,
    /// Average transactions per second.
    pub avg_tps: f64,
    /// Latency report (if latency tracking was enabled).
    pub latency_report: Option<LatencyReport>,
}

impl SpammerReport {
    /// Print the report to stdout.
    pub fn print(&self) {
        println!("\n=== Spammer Report ===");
        println!("Duration: {:?}", self.duration);
        println!("Submitted: {}", self.total_submitted);
        println!("Accepted: {}", self.total_accepted);
        println!("Rejected: {}", self.total_rejected);
        println!("Errors: {}", self.total_errors);
        println!("Avg TPS: {:.2}", self.avg_tps);

        if let Some(ref latency) = self.latency_report {
            latency.print_summary();
        }
    }
}

/// Errors that can occur during spamming.
#[derive(Debug, thiserror::Error)]
pub enum SpammerError {
    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("Account generation failed: {0}")]
    AccountGeneration(#[from] crate::accounts::AccountPoolError),

    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    #[error("Nodes not ready within timeout")]
    NodesNotReady,
}
