//! Metrics for parallel simulation.

use std::time::Duration;

/// Final simulation report.
#[derive(Debug, Clone)]
pub struct SimulationReport {
    pub wall_duration: Duration,
    pub simulated_duration: Duration,
    pub submitted: u64,
    pub completed: u64,
    pub rejected: u64,
    pub retries: u64,
    pub in_flight: u64,
    pub messages_dropped_loss: u64,
    pub messages_dropped_partition: u64,
    /// Average TPS: protocol throughput in simulated time
    pub avg_tps: f64,
    pub latency_p50_us: u64,
    pub latency_p90_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    pub latency_avg_us: u64,
}

impl SimulationReport {
    pub fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════");
        println!("       PARALLEL SIMULATION REPORT           ");
        println!("═══════════════════════════════════════════");
        println!();
        println!("Transactions:");
        println!("  Submitted:  {}", self.submitted);
        println!("  Completed:  {}", self.completed);
        println!("  Rejected:   {}", self.rejected);
        println!("  Retries:    {}", self.retries);
        println!("  In-flight:  {} (at cutoff)", self.in_flight);
        println!();
        println!("Throughput:");
        println!("  Average TPS: {:.2}", self.avg_tps);
        println!();
        println!("Latency (completed txs):");
        println!("  P50:  {:.3}ms", self.latency_p50_us as f64 / 1000.0);
        println!("  P90:  {:.3}ms", self.latency_p90_us as f64 / 1000.0);
        println!("  P99:  {:.3}ms", self.latency_p99_us as f64 / 1000.0);
        println!("  Max:  {:.3}ms", self.latency_max_us as f64 / 1000.0);
        println!("  Avg:  {:.3}ms", self.latency_avg_us as f64 / 1000.0);
        println!();
        println!("Message Drops:");
        println!("  Packet loss: {}", self.messages_dropped_loss);
        println!("  Partitions:  {}", self.messages_dropped_partition);
        println!();
        println!(
            "Duration: {:.2}s (simulated: {:.3}s)",
            self.wall_duration.as_secs_f64(),
            self.simulated_duration.as_secs_f64()
        );
        println!("═══════════════════════════════════════════\n");
    }
}
