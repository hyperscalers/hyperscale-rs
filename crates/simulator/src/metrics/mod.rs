//! Metrics collection and reporting for simulations.
//!
//! Provides latency histograms, TPS tracking, lock contention stats, and comprehensive reports.

use hdrhistogram::Histogram;
use hyperscale_mempool::LockContentionStats;
use std::time::Duration;

/// Collects metrics during a simulation run.
pub struct MetricsCollector {
    /// Submission count.
    submissions: u64,

    /// Completion count (transactions fully executed).
    completions: u64,

    /// Rejection count.
    rejections: u64,

    /// Retry count (transactions that entered Retried state).
    retries: u64,

    /// Latency histogram (microseconds).
    latency_histogram: Histogram<u64>,

    /// Start time (simulated).
    start_time: Duration,

    /// Time when submissions stopped.
    submission_end_time: Option<Duration>,

    /// Peak TPS observed in any sample window.
    peak_tps: f64,

    /// Samples for time-series analysis.
    samples: Vec<MetricsSample>,

    /// Last sample time.
    last_sample_time: Duration,

    /// Completions at last sample.
    last_sample_completions: u64,

    // Lock contention tracking
    /// Peak locked nodes observed.
    peak_locked_nodes: u64,

    /// Peak blocked transactions observed.
    peak_blocked: u64,

    /// Peak contention ratio observed.
    peak_contention_ratio: f64,

    /// In-flight transactions at simulation end.
    in_flight_at_end: u64,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new(start_time: Duration) -> Self {
        Self {
            submissions: 0,
            completions: 0,
            rejections: 0,
            retries: 0,
            latency_histogram: Histogram::new(3).expect("histogram creation should succeed"),
            start_time,
            submission_end_time: None,
            peak_tps: 0.0,
            samples: Vec::new(),
            last_sample_time: start_time,
            last_sample_completions: 0,
            peak_locked_nodes: 0,
            peak_blocked: 0,
            peak_contention_ratio: 0.0,
            in_flight_at_end: 0,
        }
    }

    /// Record a transaction submission.
    pub fn record_submission(&mut self) {
        self.submissions += 1;
    }

    /// Record multiple submissions.
    #[allow(dead_code)]
    pub fn record_submissions(&mut self, count: u64) {
        self.submissions += count;
    }

    /// Record a transaction completion with its latency.
    pub fn record_completion(&mut self, latency: Duration) {
        self.completions += 1;
        // Store latency in microseconds for better resolution
        let latency_us = latency.as_micros() as u64;
        let _ = self.latency_histogram.record(latency_us);
    }

    /// Record a transaction rejection.
    pub fn record_rejection(&mut self) {
        self.rejections += 1;
    }

    /// Record a transaction retry.
    pub fn record_retry(&mut self) {
        self.retries += 1;
    }

    /// Set the submission end time for accurate TPS calculation.
    pub fn set_submission_end_time(&mut self, time: Duration) {
        self.submission_end_time = Some(time);
    }

    /// Set the number of in-flight transactions at simulation end.
    pub fn set_in_flight_at_end(&mut self, count: u64) {
        self.in_flight_at_end = count;
    }

    /// Take a sample for time-series tracking.
    ///
    /// Accepts lock contention stats aggregated from all shards.
    pub fn sample(
        &mut self,
        current_time: Duration,
        in_flight: u64,
        lock_stats: LockContentionStats,
    ) {
        let elapsed_since_last = current_time.saturating_sub(self.last_sample_time);
        let completions_since_last = self
            .completions
            .saturating_sub(self.last_sample_completions);

        // Calculate instantaneous TPS
        let instant_tps = if elapsed_since_last.as_secs_f64() > 0.0 {
            completions_since_last as f64 / elapsed_since_last.as_secs_f64()
        } else {
            0.0
        };

        // Track peak TPS
        if instant_tps > self.peak_tps {
            self.peak_tps = instant_tps;
        }

        // Track peak lock contention
        if lock_stats.locked_nodes > self.peak_locked_nodes {
            self.peak_locked_nodes = lock_stats.locked_nodes;
        }
        if lock_stats.blocked_count > self.peak_blocked {
            self.peak_blocked = lock_stats.blocked_count;
        }
        let contention_ratio = lock_stats.contention_ratio();
        if contention_ratio > self.peak_contention_ratio {
            self.peak_contention_ratio = contention_ratio;
        }

        self.samples.push(MetricsSample {
            time: current_time,
            submissions: self.submissions,
            completions: self.completions,
            rejections: self.rejections,
            in_flight,
            instant_tps,
            locked_nodes: lock_stats.locked_nodes,
            blocked_count: lock_stats.blocked_count,
            contention_ratio,
        });

        self.last_sample_time = current_time;
        self.last_sample_completions = self.completions;
    }

    /// Current raw stats: (submitted, completed, rejected).
    pub fn current_stats(&self) -> (u64, u64, u64) {
        (self.submissions, self.completions, self.rejections)
    }

    /// Finalize and generate a report.
    pub fn finalize(self, end_time: Duration) -> SimulationReport {
        let total_duration = end_time.saturating_sub(self.start_time);
        let submission_duration = self
            .submission_end_time
            .map(|t| t.saturating_sub(self.start_time))
            .unwrap_or(total_duration);

        // Calculate TPS based on submission duration
        let average_tps = if submission_duration.as_secs_f64() > 0.0 {
            self.completions as f64 / submission_duration.as_secs_f64()
        } else {
            0.0
        };

        SimulationReport {
            total_submitted: self.submissions,
            total_completed: self.completions,
            total_rejected: self.rejections,
            total_retries: self.retries,
            in_flight_at_end: self.in_flight_at_end,
            average_tps,
            peak_tps: self.peak_tps,
            latency_histogram: self.latency_histogram,
            total_duration,
            submission_duration,
            samples: self.samples,
            peak_locked_nodes: self.peak_locked_nodes,
            peak_blocked: self.peak_blocked,
            peak_contention_ratio: self.peak_contention_ratio,
        }
    }
}

/// A point-in-time metrics sample.
#[derive(Clone, Debug)]
pub struct MetricsSample {
    /// Simulation time of this sample.
    pub time: Duration,
    /// Cumulative submissions at this point.
    pub submissions: u64,
    /// Cumulative completions at this point.
    pub completions: u64,
    /// Cumulative rejections at this point.
    pub rejections: u64,
    /// Transactions in flight at this point.
    pub in_flight: u64,
    /// Instantaneous TPS at this point.
    pub instant_tps: f64,
    /// Number of locked nodes at this point.
    pub locked_nodes: u64,
    /// Number of blocked transactions at this point.
    pub blocked_count: u64,
    /// Contention ratio at this point (pending_blocked / pending_count).
    pub contention_ratio: f64,
}

/// Final simulation report.
pub struct SimulationReport {
    /// Total transactions submitted.
    pub total_submitted: u64,
    /// Total transactions completed (fully executed).
    pub total_completed: u64,
    /// Total transactions rejected.
    pub total_rejected: u64,
    /// Total retries (transactions that entered Retried state).
    pub total_retries: u64,
    /// Transactions still in-flight at simulation end.
    pub in_flight_at_end: u64,
    /// Average TPS over the submission period.
    pub average_tps: f64,
    /// Peak instantaneous TPS observed.
    pub peak_tps: f64,
    /// Latency histogram (values in microseconds).
    latency_histogram: Histogram<u64>,
    /// Total simulation duration (including ramp-down).
    pub total_duration: Duration,
    /// Submission phase duration (for TPS calculation).
    pub submission_duration: Duration,
    /// Time-series samples.
    pub samples: Vec<MetricsSample>,
    /// Peak number of locked nodes observed.
    pub peak_locked_nodes: u64,
    /// Peak number of blocked transactions observed.
    pub peak_blocked: u64,
    /// Peak contention ratio observed.
    pub peak_contention_ratio: f64,
}

impl SimulationReport {
    /// Get the P50 (median) latency.
    pub fn p50_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.value_at_quantile(0.50))
    }

    /// Get the P90 latency.
    pub fn p90_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.value_at_quantile(0.90))
    }

    /// Get the P99 latency.
    pub fn p99_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.value_at_quantile(0.99))
    }

    /// Get the maximum latency.
    pub fn max_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.max())
    }

    /// Get the average latency.
    pub fn avg_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.mean() as u64)
    }

    /// Get the minimum latency.
    pub fn min_latency(&self) -> Duration {
        Duration::from_micros(self.latency_histogram.min())
    }

    /// Rejection rate (rejected / (completed + rejected)).
    /// This is the meaningful failure rate - how many decided transactions failed.
    pub fn rejection_rate(&self) -> f64 {
        let decided = self.total_completed + self.total_rejected;
        if decided > 0 {
            self.total_rejected as f64 / decided as f64
        } else {
            0.0
        }
    }

    /// Print a summary of the report.
    pub fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════");
        println!("           SIMULATION REPORT                ");
        println!("═══════════════════════════════════════════");
        println!();
        println!("Transactions:");
        println!("  Submitted:  {}", self.total_submitted);
        println!("  Completed:  {}", self.total_completed);
        println!("  Rejected:   {}", self.total_rejected);
        println!("  Retries:    {}", self.total_retries);
        println!("  In-flight:  {} (at cutoff)", self.in_flight_at_end);
        println!();
        println!("Throughput:");
        println!("  Average TPS: {:.2}", self.average_tps);
        println!("  Peak TPS:    {:.2}", self.peak_tps);
        println!();
        println!("Latency (completed txs):");
        println!("  P50:  {:?}", self.p50_latency());
        println!("  P90:  {:?}", self.p90_latency());
        println!("  P99:  {:?}", self.p99_latency());
        println!("  Max:  {:?}", self.max_latency());
        println!("  Avg:  {:?}", self.avg_latency());
        println!();
        println!("Lock Contention (peak):");
        println!("  Locked nodes:     {}", self.peak_locked_nodes);
        println!("  Blocked txs:      {}", self.peak_blocked);
        println!(
            "  Contention ratio: {:.2}%",
            self.peak_contention_ratio * 100.0
        );
        println!();
        println!("Duration: {:?}", self.total_duration);
        println!("═══════════════════════════════════════════\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let mut collector = MetricsCollector::new(Duration::ZERO);

        // Simulate some transactions
        for i in 0..100 {
            collector.record_submission();
            collector.record_completion(Duration::from_millis(10 + i % 50));
        }
        collector.record_rejection();

        collector.set_submission_end_time(Duration::from_secs(10));
        let report = collector.finalize(Duration::from_secs(12));

        assert_eq!(report.total_submitted, 100);
        assert_eq!(report.total_completed, 100);
        assert_eq!(report.total_rejected, 1);
        assert!(report.average_tps > 0.0);
    }
}
