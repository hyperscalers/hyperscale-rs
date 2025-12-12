//! Latency tracking for submitted transactions.
//!
//! Provides infrastructure for measuring end-to-end transaction latency by
//! tracking submitted transactions and polling for their completion status.

use crate::client::RpcClient;
use hdrhistogram::Histogram;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

/// Tracks in-flight transactions and measures their latency.
pub struct LatencyTracker {
    /// In-flight transactions: tx_hash -> (submit_time, client_index)
    in_flight: Arc<Mutex<HashMap<String, (Instant, usize)>>>,
    /// Latency histogram (microseconds).
    histogram: Arc<Mutex<Histogram<u64>>>,
    /// Completion counts.
    stats: Arc<Mutex<LatencyStats>>,
    /// Poll interval for checking transaction status.
    poll_interval: Duration,
    /// RPC clients for polling.
    clients: Vec<RpcClient>,
    /// Handle to the polling task.
    poll_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Statistics collected during latency tracking.
#[derive(Default)]
pub struct LatencyStats {
    /// Number of transactions tracked.
    pub tracked: u64,
    /// Number of transactions completed successfully.
    pub completed: u64,
    /// Number of transactions that failed/aborted.
    pub failed: u64,
    /// Number of transactions that timed out (still in-flight at end).
    pub timed_out: u64,
}

impl LatencyTracker {
    /// Create a new latency tracker.
    pub fn new(clients: Vec<RpcClient>, poll_interval: Duration) -> Self {
        Self {
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            histogram: Arc::new(Mutex::new(
                Histogram::new(3).expect("histogram creation should succeed"),
            )),
            stats: Arc::new(Mutex::new(LatencyStats::default())),
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

                // Get all in-flight transactions
                let to_check: Vec<(String, Instant, usize)> = {
                    let guard = in_flight.lock().await;
                    guard
                        .iter()
                        .map(|(hash, (time, idx))| (hash.clone(), *time, *idx))
                        .collect()
                };

                if to_check.is_empty() {
                    continue;
                }

                // Check each transaction
                for (tx_hash, submit_time, client_idx) in to_check {
                    let client = &clients[client_idx % clients.len()];

                    match client.get_transaction_status(&tx_hash).await {
                        Ok(status) => {
                            if status.is_terminal() {
                                let latency = submit_time.elapsed();
                                let latency_us = latency.as_micros() as u64;

                                // Remove from in-flight
                                in_flight.lock().await.remove(&tx_hash);

                                // Record latency
                                {
                                    let mut hist = histogram.lock().await;
                                    let _ = hist.record(latency_us);
                                }

                                // Update stats
                                {
                                    let mut s = stats.lock().await;
                                    if status.is_success() {
                                        s.completed += 1;
                                    } else {
                                        s.failed += 1;
                                    }
                                }

                                debug!(
                                    tx_hash = %tx_hash,
                                    latency_ms = latency.as_millis(),
                                    status = %status.status,
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
    pub async fn track(&self, tx_hash: String, client_idx: usize) {
        let mut guard = self.in_flight.lock().await;
        guard.insert(tx_hash, (Instant::now(), client_idx));
        drop(guard);

        let mut s = self.stats.lock().await;
        s.tracked += 1;
    }

    /// Finalize tracking and generate a report.
    ///
    /// Any transactions still in-flight are counted as timed out.
    pub async fn finalize(mut self) -> LatencyReport {
        // Stop the polling task
        self.stop_polling();

        // Wait a short time for any final polls
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Mark remaining in-flight as timed out
        let timed_out = {
            let guard = self.in_flight.lock().await;
            guard.len() as u64
        };

        let stats = {
            let mut s = self.stats.lock().await;
            s.timed_out = timed_out;
            std::mem::take(&mut *s)
        };

        let histogram = {
            let guard = self.histogram.lock().await;
            guard.clone()
        };

        LatencyReport { histogram, stats }
    }

    /// Get current in-flight count.
    pub async fn in_flight_count(&self) -> usize {
        self.in_flight.lock().await.len()
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
    /// Statistics.
    stats: LatencyStats,
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
