//! Spammer runner that orchestrates transaction generation and submission.

use crate::accounts::{AccountPartition, AccountPool};
use crate::client::{RpcClient, RpcError};
use crate::config::SpammerConfig;
use crate::latency::{LatencyReport, LatencyTracker};
use crate::workloads::TransferWorkload;
use futures::future::join_all;
use hyperscale_types::{RoutableTransaction, ShardGroupId};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Transaction spammer that submits to real network endpoints.
///
/// Distributes transactions equally across shards, ensuring each shard's validators
/// only receive transactions that are relevant to that shard (i.e., transactions
/// that involve accounts on that shard).
///
/// Supports multi-threaded parallel submission via the `num_workers` config option.
/// When workers > 1, accounts are partitioned and each worker gets exclusive ownership
/// of its partition, enabling lock-free concurrent operation.
pub struct Spammer {
    config: SpammerConfig,
    accounts: AccountPool,
    clients: Arc<Vec<RpcClient>>,
    stats: Arc<SpammerStats>,
    latency_tracker: Option<LatencyTracker>,
    /// Round-robin counter for distributing load across validators within each shard.
    /// Indexed by shard number.
    shard_round_robin: Arc<Vec<AtomicU64>>,
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

        // Create latency tracker if enabled
        let latency_tracker = if config.latency_tracking {
            Some(LatencyTracker::new(
                clients.clone(),
                config.latency_poll_interval,
            ))
        } else {
            None
        };

        // Initialize round-robin counters for each shard
        let shard_round_robin = (0..config.num_shards).map(|_| AtomicU64::new(0)).collect();

        Ok(Self {
            config,
            accounts,
            clients: Arc::new(clients),
            stats: Arc::new(SpammerStats::default()),
            latency_tracker,
            shard_round_robin: Arc::new(shard_round_robin),
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
        self.stats.start_time.store(
            start.elapsed().as_nanos() as u64, // Store start reference
            Ordering::SeqCst,
        );

        // Start latency tracking if enabled
        if let Some(ref mut tracker) = self.latency_tracker {
            tracker.start_polling();
        }

        let num_workers = self.config.num_workers;

        if num_workers <= 1 {
            // Single-threaded mode (original behavior but with join_all for concurrent submission)
            self.run_single_threaded(cancel.clone(), start).await;
        } else {
            // Multi-threaded mode: partition accounts and spawn workers
            self.run_multi_threaded(cancel.clone(), start, num_workers)
                .await;
        }

        // Print final progress
        self.print_progress(start.elapsed());

        // Save nonces for next run
        match self.accounts.save_nonces_default() {
            Ok(n) => info!(saved = n, "Saved account nonces to file"),
            Err(e) => warn!(error = %e, "Failed to save nonces"),
        }

        // Finalize latency tracking
        let latency_report = if let Some(tracker) = self.latency_tracker.take() {
            Some(
                tracker
                    .finalize(self.config.latency_finalization_timeout)
                    .await,
            )
        } else {
            None
        };

        SpammerReport {
            duration: start.elapsed(),
            total_submitted: self.stats.submitted.load(Ordering::SeqCst),
            total_accepted: self.stats.accepted.load(Ordering::SeqCst),
            total_rejected: self.stats.rejected.load(Ordering::SeqCst),
            total_errors: self.stats.errors.load(Ordering::SeqCst),
            avg_tps: self.stats.tps(start),
            latency_report,
        }
    }

    /// Run in single-threaded mode with concurrent submission via join_all.
    async fn run_single_threaded(&mut self, cancel: CancellationToken, start: Instant) {
        let mut last_progress = Instant::now();
        let batch_interval = self.config.batch_interval();
        let num_shards = self.config.num_shards as usize;
        let txs_per_shard = self.config.batch_size.div_ceil(num_shards);

        // Use current time as seed for RNG
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut latency_rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(1));

        // Create workload generator
        let workload = TransferWorkload::new(self.config.network.clone())
            .with_cross_shard_ratio(self.config.cross_shard_ratio)
            .with_selection_mode(self.config.selection_mode);

        info!(
            target_tps = self.config.target_tps,
            batch_size = self.config.batch_size,
            batch_interval_ms = batch_interval.as_millis(),
            latency_tracking = self.latency_tracker.is_some(),
            num_shards = num_shards,
            txs_per_shard = txs_per_shard,
            workers = 1,
            "Starting spammer (single-threaded mode with concurrent submission)"
        );

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // Generate and submit batches per shard
            for shard_idx in 0..num_shards {
                let target_shard = ShardGroupId(shard_idx as u64);

                // Generate transactions
                let batch = workload.generate_batch_for_shard(
                    &self.accounts,
                    target_shard,
                    txs_per_shard,
                    &mut rng,
                );

                // Submit all transactions concurrently using join_all
                let futures: Vec<_> = batch
                    .into_iter()
                    .map(|tx| {
                        let should_track = self.latency_tracker.is_some()
                            && latency_rng.gen::<f64>() < self.config.latency_sample_rate;
                        self.submit_transaction_concurrent(tx, shard_idx, should_track)
                    })
                    .collect();

                join_all(futures).await;
            }

            // Print progress periodically
            if last_progress.elapsed() >= self.config.progress_interval {
                self.print_progress(start.elapsed());
                last_progress = Instant::now();
            }

            // Sleep to maintain target TPS
            tokio::time::sleep(batch_interval).await;
        }
    }

    /// Run in multi-threaded mode with partitioned accounts.
    async fn run_multi_threaded(
        &mut self,
        cancel: CancellationToken,
        start: Instant,
        num_workers: usize,
    ) {
        let batch_interval = self.config.batch_interval();
        let num_shards = self.config.num_shards as usize;

        // Partition accounts across workers
        let partitions = self.accounts.partition(num_workers);

        // Calculate TPS per worker
        let tps_per_worker = self.config.target_tps / num_workers as u64;
        let batch_size_per_worker = self.config.batch_size / num_workers;

        info!(
            target_tps = self.config.target_tps,
            tps_per_worker = tps_per_worker,
            batch_size = self.config.batch_size,
            batch_size_per_worker = batch_size_per_worker,
            batch_interval_ms = batch_interval.as_millis(),
            latency_tracking = self.latency_tracker.is_some(),
            num_shards = num_shards,
            workers = num_workers,
            accounts_per_partition = partitions.first().map(|p| p.total_accounts()).unwrap_or(0),
            "Starting spammer (multi-threaded mode)"
        );

        // Spawn worker tasks
        let mut handles = Vec::with_capacity(num_workers);

        for (worker_id, partition) in partitions.into_iter().enumerate() {
            let worker = Worker {
                worker_id,
                partition,
                clients: Arc::clone(&self.clients),
                stats: Arc::clone(&self.stats),
                shard_round_robin: Arc::clone(&self.shard_round_robin),
                latency_tracker: self.latency_tracker.as_ref().map(|t| t.clone_tracker()),
                config: WorkerConfig {
                    num_shards: num_shards as u64,
                    validators_per_shard: self.config.validators_per_shard,
                    batch_size: batch_size_per_worker.max(1),
                    batch_interval,
                    cross_shard_ratio: self.config.cross_shard_ratio,
                    selection_mode: self.config.selection_mode,
                    network: self.config.network.clone(),
                    latency_sample_rate: self.config.latency_sample_rate,
                },
            };

            let cancel = cancel.clone();
            let handle = tokio::spawn(async move {
                worker.run(cancel).await;
            });
            handles.push(handle);
        }

        // Spawn progress reporter
        let stats_for_progress = Arc::clone(&self.stats);
        let latency_tracker_for_progress = self.latency_tracker.as_ref().map(|t| t.clone_tracker());
        let progress_interval = self.config.progress_interval;
        let cancel_for_progress = cancel.clone();

        let progress_handle = tokio::spawn(async move {
            let mut last_progress = Instant::now();
            loop {
                if cancel_for_progress.is_cancelled() {
                    break;
                }

                if last_progress.elapsed() >= progress_interval {
                    print_progress_static(
                        &stats_for_progress,
                        start.elapsed(),
                        start,
                        latency_tracker_for_progress.as_ref(),
                    );
                    last_progress = Instant::now();
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Wait for all workers to complete
        for handle in handles {
            let _ = handle.await;
        }

        progress_handle.abort();
    }

    /// Submit a single transaction concurrently (returns a future).
    async fn submit_transaction_concurrent(
        &self,
        tx: RoutableTransaction,
        target_shard: usize,
        should_track: bool,
    ) {
        self.stats.submitted.fetch_add(1, Ordering::SeqCst);

        let validators_per_shard = self.config.validators_per_shard;
        let base_idx = target_shard * validators_per_shard;

        let rr_counter = &self.shard_round_robin[target_shard];
        let offset = rr_counter.fetch_add(1, Ordering::Relaxed) as usize % validators_per_shard;

        let client_idx = (base_idx + offset) % self.clients.len();
        let client = &self.clients[client_idx];

        match client.submit_transaction(&tx).await {
            Ok(result) => {
                if result.accepted {
                    self.stats.accepted.fetch_add(1, Ordering::SeqCst);

                    if should_track {
                        if let Some(ref tracker) = self.latency_tracker {
                            tracker.track(result.hash, client_idx);
                        }
                    }
                } else {
                    self.stats.rejected.fetch_add(1, Ordering::SeqCst);
                }
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Ordering::SeqCst);
                warn!(error = %e, "Failed to submit transaction");
            }
        }
    }

    /// Print progress statistics.
    fn print_progress(&self, elapsed: Duration) {
        let submitted = self.stats.submitted.load(Ordering::SeqCst);
        let accepted = self.stats.accepted.load(Ordering::SeqCst);
        let rejected = self.stats.rejected.load(Ordering::SeqCst);
        let errors = self.stats.errors.load(Ordering::SeqCst);

        let tps = if elapsed.as_secs_f64() > 0.0 {
            submitted as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let in_flight_info = if let Some(ref tracker) = self.latency_tracker {
            let count = tracker.in_flight_count();
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

            for client in self.clients.iter() {
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

/// Print progress from a static context (for multi-threaded mode).
fn print_progress_static(
    stats: &SpammerStats,
    elapsed: Duration,
    start: Instant,
    latency_tracker: Option<&LatencyTracker>,
) {
    let submitted = stats.submitted.load(Ordering::SeqCst);
    let accepted = stats.accepted.load(Ordering::SeqCst);
    let rejected = stats.rejected.load(Ordering::SeqCst);
    let errors = stats.errors.load(Ordering::SeqCst);

    let tps = stats.tps(start);

    let in_flight_info = if let Some(tracker) = latency_tracker {
        let count = tracker.in_flight_count();
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

/// Configuration for a worker task.
#[derive(Clone)]
struct WorkerConfig {
    num_shards: u64,
    validators_per_shard: usize,
    batch_size: usize,
    batch_interval: Duration,
    cross_shard_ratio: f64,
    selection_mode: crate::accounts::SelectionMode,
    network: NetworkDefinition,
    latency_sample_rate: f64,
}

/// A worker task that owns a partition of accounts and submits transactions.
struct Worker {
    worker_id: usize,
    partition: AccountPartition,
    clients: Arc<Vec<RpcClient>>,
    stats: Arc<SpammerStats>,
    shard_round_robin: Arc<Vec<AtomicU64>>,
    latency_tracker: Option<LatencyTracker>,
    config: WorkerConfig,
}

impl Worker {
    async fn run(mut self, cancel: CancellationToken) {
        let num_shards = self.config.num_shards as usize;
        let txs_per_shard = self.config.batch_size.div_ceil(num_shards);

        // Each worker has its own RNG with a unique seed
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            + self.worker_id as u64 * 1000;

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut latency_rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(1));

        // Create workload generator for this partition
        let workload = PartitionWorkload::new(self.config.network.clone())
            .with_cross_shard_ratio(self.config.cross_shard_ratio)
            .with_selection_mode(self.config.selection_mode);

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // Generate and submit batches per shard
            for shard_idx in 0..num_shards {
                let target_shard = ShardGroupId(shard_idx as u64);

                // Generate transactions from this worker's partition
                let batch = workload.generate_batch_for_shard(
                    &mut self.partition,
                    target_shard,
                    txs_per_shard,
                    &mut rng,
                );

                // Submit all transactions concurrently
                let futures: Vec<_> = batch
                    .into_iter()
                    .map(|tx| {
                        let should_track = self.latency_tracker.is_some()
                            && latency_rng.gen::<f64>() < self.config.latency_sample_rate;
                        self.submit_transaction(tx, shard_idx, should_track)
                    })
                    .collect();

                join_all(futures).await;
            }

            // Sleep to maintain target TPS
            tokio::time::sleep(self.config.batch_interval).await;
        }
    }

    async fn submit_transaction(
        &self,
        tx: RoutableTransaction,
        target_shard: usize,
        should_track: bool,
    ) {
        self.stats.submitted.fetch_add(1, Ordering::SeqCst);

        let validators_per_shard = self.config.validators_per_shard;
        let base_idx = target_shard * validators_per_shard;

        let rr_counter = &self.shard_round_robin[target_shard];
        let offset = rr_counter.fetch_add(1, Ordering::Relaxed) as usize % validators_per_shard;

        let client_idx = (base_idx + offset) % self.clients.len();
        let client = &self.clients[client_idx];

        match client.submit_transaction(&tx).await {
            Ok(result) => {
                if result.accepted {
                    self.stats.accepted.fetch_add(1, Ordering::SeqCst);

                    if should_track {
                        if let Some(ref tracker) = self.latency_tracker {
                            tracker.track(result.hash, client_idx);
                        }
                    }
                } else {
                    self.stats.rejected.fetch_add(1, Ordering::SeqCst);
                }
            }
            Err(_) => {
                self.stats.errors.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Workload generator that uses AccountPartition (mutable, no locks).
struct PartitionWorkload {
    cross_shard_ratio: f64,
    selection_mode: crate::accounts::SelectionMode,
    amount: Decimal,
    network: NetworkDefinition,
}

impl PartitionWorkload {
    fn new(network: NetworkDefinition) -> Self {
        Self {
            cross_shard_ratio: 0.0,
            selection_mode: crate::accounts::SelectionMode::NoContention,
            amount: Decimal::from(100u32),
            network,
        }
    }

    fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    fn with_selection_mode(mut self, mode: crate::accounts::SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    fn generate_batch_for_shard(
        &self,
        partition: &mut AccountPartition,
        target_shard: ShardGroupId,
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<RoutableTransaction> {
        (0..count)
            .filter_map(|_| self.generate_for_shard(partition, target_shard, rng))
            .collect()
    }

    fn generate_for_shard(
        &self,
        partition: &mut AccountPartition,
        target_shard: ShardGroupId,
        rng: &mut impl Rng,
    ) -> Option<RoutableTransaction> {
        let is_cross_shard =
            partition.num_shards() >= 2 && rng.gen::<f64>() < self.cross_shard_ratio;

        if is_cross_shard {
            self.generate_cross_shard_for(partition, target_shard, rng)
        } else {
            self.generate_same_shard_for(partition, target_shard, rng)
        }
    }

    fn generate_same_shard_for(
        &self,
        partition: &mut AccountPartition,
        target_shard: ShardGroupId,
        rng: &mut impl Rng,
    ) -> Option<RoutableTransaction> {
        let (from, to) = partition.pair_for_shard(target_shard, rng, self.selection_mode)?;
        self.build_transfer(from, to)
    }

    fn generate_cross_shard_for(
        &self,
        partition: &mut AccountPartition,
        target_shard: ShardGroupId,
        rng: &mut impl Rng,
    ) -> Option<RoutableTransaction> {
        if partition.num_shards() < 2 {
            return None;
        }

        let mut other_shard = ShardGroupId(rng.gen_range(0..partition.num_shards()));
        while other_shard == target_shard {
            other_shard = ShardGroupId(rng.gen_range(0..partition.num_shards()));
        }

        let target_is_sender = rng.gen_bool(0.5);

        let (from, to) = if target_is_sender {
            partition.cross_shard_pair_for(target_shard, other_shard, rng, self.selection_mode)?
        } else {
            partition.cross_shard_pair_for(other_shard, target_shard, rng, self.selection_mode)?
        };

        self.build_transfer(from, to)
    }

    fn build_transfer(
        &self,
        from: &crate::accounts::FundedAccount,
        to: &crate::accounts::FundedAccount,
    ) -> Option<RoutableTransaction> {
        use radix_common::constants::XRD;
        use radix_transactions::builder::ManifestBuilder;

        let manifest = ManifestBuilder::new()
            .lock_fee(from.address, Decimal::from(10u32))
            .withdraw_from_account(from.address, XRD, self.amount)
            .try_deposit_entire_worktop_or_abort(to.address, None)
            .build();

        let nonce = from.next_nonce();

        let notarized = match hyperscale_types::sign_and_notarize(
            manifest,
            &self.network,
            nonce as u32,
            &from.keypair,
        ) {
            Ok(n) => n,
            Err(_) => return None,
        };

        notarized.try_into().ok()
    }
}

/// Statistics collected during spamming.
pub struct SpammerStats {
    /// Number of transactions submitted.
    pub submitted: AtomicU64,
    /// Number of transactions accepted.
    pub accepted: AtomicU64,
    /// Number of transactions rejected.
    pub rejected: AtomicU64,
    /// Number of errors (network failures, etc.).
    pub errors: AtomicU64,
    /// Start time stored as nanos (for Arc sharing).
    start_time: AtomicU64,
}

impl Default for SpammerStats {
    fn default() -> Self {
        Self {
            submitted: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
        }
    }
}

impl SpammerStats {
    /// Calculate current transactions per second.
    pub fn tps(&self, start: Instant) -> f64 {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.submitted.load(Ordering::SeqCst) as f64 / elapsed
        } else {
            0.0
        }
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
