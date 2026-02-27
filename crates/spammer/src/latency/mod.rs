//! Latency tracking for submitted transactions.
//!
//! Provides infrastructure for measuring end-to-end transaction latency by
//! tracking submitted transactions and polling for their completion status.
//!
//! When a transaction is retried (e.g., due to conflicts), this tracker follows
//! the retry chain to the final transaction, measuring latency from the original
//! submission time to the final completion.

use crate::client::RpcClient;
use dashmap::DashMap;
use hdrhistogram::Histogram;
use hyperscale_types::TransactionStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Tracks in-flight transactions and measures their latency.
///
/// Uses lock-free data structures to minimize contention:
/// - DashMap for in-flight transaction tracking (sharded concurrent map)
/// - Atomics for stats counters
/// - parking_lot::Mutex for histogram (only acquired when recording, not reading)
pub struct LatencyTracker {
    /// In-flight transactions: tx_hash -> (submit_time, client_index)
    /// Uses DashMap for lock-free concurrent access from multiple threads.
    in_flight: Arc<DashMap<String, (Instant, usize)>>,
    /// Latency histogram (microseconds).
    /// Uses parking_lot::Mutex which is faster than tokio::sync::Mutex for short critical sections.
    histogram: Arc<parking_lot::Mutex<Histogram<u64>>>,
    /// Completion counts - using atomics for lock-free updates.
    stats: Arc<LatencyStats>,
    /// Poll interval for checking transaction status.
    poll_interval: Duration,
    /// RPC clients for polling.
    clients: Vec<RpcClient>,
    /// Handle to the polling task.
    poll_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Statistics collected during latency tracking.
/// Uses atomics for lock-free concurrent updates.
#[derive(Default)]
pub struct LatencyStats {
    /// Number of transactions tracked.
    pub tracked: AtomicU64,
    /// Number of transactions completed successfully.
    pub completed: AtomicU64,
    /// Number of transactions that failed/aborted.
    pub failed: AtomicU64,
    /// Number of transactions that timed out (still in-flight at end).
    pub timed_out: AtomicU64,
    /// Number of retries followed (transactions that were retried).
    pub retries: AtomicU64,
}

impl LatencyStats {
    /// Get a snapshot of the current stats.
    fn snapshot(&self) -> LatencyStatsSnapshot {
        LatencyStatsSnapshot {
            tracked: self.tracked.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time snapshot of latency stats.
#[derive(Default)]
pub struct LatencyStatsSnapshot {
    pub tracked: u64,
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub retries: u64,
}

impl LatencyTracker {
    /// Create a new latency tracker.
    pub fn new(clients: Vec<RpcClient>, poll_interval: Duration) -> Self {
        Self {
            in_flight: Arc::new(DashMap::new()),
            histogram: Arc::new(parking_lot::Mutex::new(
                Histogram::new(3).expect("histogram creation should succeed"),
            )),
            stats: Arc::new(LatencyStats::default()),
            poll_interval,
            clients,
            poll_handle: None,
        }
    }

    /// Start the background polling task.
    pub fn start_polling(&mut self) {
        let in_flight = self.in_flight.clone();
        let histogram = self.histogram.clone();
        let stats = self.stats.clone();
        let poll_interval = self.poll_interval;
        let clients = self.clients.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll_interval).await;

                // Collect keys to check - this is a quick read that doesn't block writers
                let to_check: Vec<(String, Instant, usize)> = in_flight
                    .iter()
                    .map(|entry| {
                        let (hash, (time, idx)) = entry.pair();
                        (hash.clone(), *time, *idx)
                    })
                    .collect();

                if to_check.is_empty() {
                    continue;
                }

                // Check each transaction - no locks held during RPC calls
                for (tx_hash, submit_time, client_idx) in to_check {
                    let client = &clients[client_idx % clients.len()];

                    match client.get_transaction_status(&tx_hash).await {
                        Ok(status_response) => {
                            // Try to convert to typed status for better handling
                            let typed_status = status_response.to_status();

                            // Check if this is a retry - follow the new transaction hash
                            if let Some(TransactionStatus::Retried { new_tx }) = typed_status {
                                // Atomically update: remove old hash, add new hash with same submit time
                                // This preserves the original submit time for accurate latency
                                let new_hash = format!("{}", new_tx);

                                // Remove old and insert new - DashMap operations are lock-free
                                in_flight.remove(&tx_hash);
                                in_flight.insert(new_hash.clone(), (submit_time, client_idx));

                                // Atomic increment - no lock needed
                                stats.retries.fetch_add(1, Ordering::Relaxed);

                                debug!(
                                    old_hash = %tx_hash,
                                    new_hash = %new_hash,
                                    "Following retried transaction"
                                );
                                continue;
                            }

                            if status_response.is_terminal() {
                                let latency = submit_time.elapsed();
                                let latency_us = latency.as_micros() as u64;

                                // Remove from in-flight - lock-free
                                in_flight.remove(&tx_hash);

                                // Record latency - short critical section with parking_lot mutex
                                {
                                    let mut hist = histogram.lock();
                                    let _ = hist.record(latency_us);
                                }

                                // Update stats - atomic, no lock
                                if status_response.is_success() {
                                    stats.completed.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    stats.failed.fetch_add(1, Ordering::Relaxed);
                                }

                                debug!(
                                    tx_hash = %tx_hash,
                                    latency_ms = latency.as_millis(),
                                    status = %status_response.status,
                                    "Transaction completed"
                                );
                            }
                        }
                        Err(e) => {
                            // Transaction not found yet or error - keep polling
                            debug!(tx_hash = %tx_hash, error = %e, "Polling error");
                        }
                    }
                }
            }
        });

        self.poll_handle = Some(handle);
    }

    /// Stop the background polling task.
    pub fn stop_polling(&mut self) {
        if let Some(handle) = self.poll_handle.take() {
            handle.abort();
        }
    }

    /// Track a submitted transaction for latency measurement.
    ///
    /// Lock-free — can be called from the hot path with minimal overhead.
    #[inline]
    pub fn track(&self, tx_hash: String, client_idx: usize) {
        // DashMap insert is lock-free (uses fine-grained sharding)
        self.in_flight.insert(tx_hash, (Instant::now(), client_idx));
        // Atomic increment - no lock
        self.stats.tracked.fetch_add(1, Ordering::Relaxed);
    }

    /// Finalize tracking and generate a report.
    ///
    /// Any transactions still in-flight are counted as timed out.
    pub async fn finalize(mut self, timeout: Duration) -> LatencyReport {
        // Wait for any in-flight transactions to complete
        tokio::time::sleep(timeout).await;

        // Stop the polling task
        self.stop_polling();

        // Count remaining in-flight as timed out
        let timed_out = self.in_flight.len() as u64;
        self.stats.timed_out.store(timed_out, Ordering::Relaxed);

        // Take snapshot of stats
        let stats = self.stats.snapshot();

        // Clone the histogram
        let histogram = {
            let guard = self.histogram.lock();
            guard.clone()
        };

        LatencyReport { histogram, stats }
    }

    /// Get current in-flight count.
    #[inline]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Create a lightweight clone that shares the same backing data structures.
    ///
    /// This is useful for multi-threaded spamming where each worker needs to
    /// track latency but all data should be aggregated in one place.
    /// The clone does NOT own the polling task or clients - only the main tracker does.
    pub fn clone_tracker(&self) -> Self {
        Self {
            in_flight: Arc::clone(&self.in_flight),
            histogram: Arc::clone(&self.histogram),
            stats: Arc::clone(&self.stats),
            poll_interval: self.poll_interval,
            clients: Vec::new(), // Workers don't need clients - they just track
            poll_handle: None,   // Workers don't own the polling task
        }
    }
}

impl Clone for RpcClient {
    fn clone(&self) -> Self {
        RpcClient::new(self.base_url().to_string())
    }
}

/// Report containing latency measurements.
pub struct LatencyReport {
    /// Latency histogram (values in microseconds).
    histogram: Histogram<u64>,
    /// Statistics snapshot.
    stats: LatencyStatsSnapshot,
}

impl LatencyReport {
    /// Get the P50 (median) latency.
    pub fn p50_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.value_at_quantile(0.50))
    }

    /// Get the P90 latency.
    pub fn p90_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.value_at_quantile(0.90))
    }

    /// Get the P99 latency.
    pub fn p99_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.value_at_quantile(0.99))
    }

    /// Get the maximum latency.
    pub fn max_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.max())
    }

    /// Get the average latency.
    pub fn avg_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.mean() as u64)
    }

    /// Get the minimum latency.
    pub fn min_latency(&self) -> Duration {
        Duration::from_micros(self.histogram.min())
    }

    /// Number of transactions tracked.
    pub fn tracked(&self) -> u64 {
        self.stats.tracked
    }

    /// Number of transactions completed successfully.
    pub fn completed(&self) -> u64 {
        self.stats.completed
    }

    /// Number of transactions that failed.
    pub fn failed(&self) -> u64 {
        self.stats.failed
    }

    /// Number of transactions that timed out.
    pub fn timed_out(&self) -> u64 {
        self.stats.timed_out
    }

    /// Number of retries followed.
    pub fn retries(&self) -> u64 {
        self.stats.retries
    }

    /// Check if we have any latency measurements.
    pub fn has_measurements(&self) -> bool {
        !self.histogram.is_empty()
    }

    /// Print a summary of the latency report.
    pub fn print_summary(&self) {
        println!("\n--- Latency Report ---");
        println!("Tracked:   {}", self.stats.tracked);
        println!("Completed: {}", self.stats.completed);
        println!("Failed:    {}", self.stats.failed);
        println!("Timed out: {}", self.stats.timed_out);
        println!("Retries:   {}", self.stats.retries);

        if self.has_measurements() {
            println!();
            println!("Latency:");
            println!("  P50:  {:?}", self.p50_latency());
            println!("  P90:  {:?}", self.p90_latency());
            println!("  P99:  {:?}", self.p99_latency());
            println!("  Max:  {:?}", self.max_latency());
            println!("  Avg:  {:?}", self.avg_latency());
            if !self.histogram.is_empty() {
                println!("  Min:  {:?}", self.min_latency());
            }
        } else {
            println!("\nNo latency measurements recorded.");
        }
    }
}
