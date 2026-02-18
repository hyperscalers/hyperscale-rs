//! Hyperscale Simulator CLI
//!
//! Run long-running deterministic workload simulations with configurable parameters.
//!
//! # Example
//!
//! ```bash
//! # Run a deterministic simulation with a fixed seed
//! hyperscale-sim --seed 42 -s 2 -v 4 -d 60 --tps 1000
//!
//! # Run with a random seed
//! hyperscale-sim -s 4 -v 5 -d 120 --cross-shard-ratio 0.3
//! ```

use clap::Parser;
use hyperscale_simulator::{Simulator, SimulatorConfig, WorkloadConfig};
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Hyperscale Simulator
///
/// Runs deterministic workload simulations. Single-threaded, reproducible
/// when the same seed is used.
#[derive(Parser, Debug)]
#[command(name = "hyperscale-sim")]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of shards
    #[arg(short = 's', long, default_value = "1")]
    shards: u32,

    /// Number of validators per shard
    #[arg(short = 'v', long, default_value = "4")]
    validators: u32,

    /// Simulation duration in seconds
    #[arg(short = 'd', long, default_value = "30")]
    duration: u64,

    /// Random seed for reproducible results. When omitted, a random seed is used.
    #[arg(long)]
    seed: Option<u64>,

    /// Number of accounts per shard
    #[arg(short = 'a', long, default_value = "500")]
    accounts: usize,

    /// Transactions per second target
    #[arg(long, default_value = "100")]
    tps: usize,

    /// Ratio of cross-shard transactions (0.0-1.0). Defaults to natural ratio (1 - 1/shards).
    #[arg(long)]
    cross_shard_ratio: Option<f64>,

    /// Show livelock analysis at end
    #[arg(long)]
    analyze_livelocks: bool,

    /// Enable network traffic analysis for bandwidth estimation
    #[arg(long)]
    network_analysis: bool,

    /// Use no-contention account distribution (disjoint pairs for zero conflicts)
    #[arg(long)]
    no_contention: bool,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,hyperscale_simulator=info")),
        )
        .init();

    let args = Args::parse();

    // Calculate cross-shard ratio: default to natural probability (1 - 1/shards)
    // With random account selection, probability of same-shard is 1/shards,
    // so cross-shard probability is (shards-1)/shards = 1 - 1/shards
    let cross_shard_ratio = args.cross_shard_ratio.unwrap_or_else(|| {
        if args.shards <= 1 {
            0.0
        } else {
            1.0 - 1.0 / args.shards as f64
        }
    });

    let seed = args.seed.unwrap_or_else(rand::random);

    info!(
        shards = args.shards,
        validators = args.validators,
        duration_secs = args.duration,
        seed,
        accounts = args.accounts,
        tps = args.tps,
        cross_shard_ratio,
        "Starting simulation"
    );

    // Calculate batch parameters to achieve target TPS
    // batch_interval * batches_per_sec = 1
    // batch_size * batches_per_sec = tps
    // => batch_size = tps * batch_interval
    let batch_interval_ms = 50u64; // 50ms between batches = 20 batches/sec
    let batches_per_sec = 1000 / batch_interval_ms;
    let batch_size = (args.tps as u64 / batches_per_sec).max(1) as usize;

    info!(
        batch_size,
        batch_interval_ms,
        effective_tps = batch_size * batches_per_sec as usize,
        "Workload parameters"
    );

    // Configure workload
    let mut workload = WorkloadConfig::transfers_only()
        .with_batch_size(batch_size)
        .with_batch_interval(Duration::from_millis(batch_interval_ms))
        .with_cross_shard_ratio(cross_shard_ratio);

    if args.no_contention {
        workload = workload.with_no_contention();
    }

    // Create simulator config
    let config = SimulatorConfig::new(args.shards, args.validators)
        .with_accounts_per_shard(args.accounts)
        .with_seed(seed)
        .with_workload(workload);

    // Create and initialize simulator
    let mut simulator = Simulator::new(config).expect("Failed to create simulator");

    // Enable traffic analysis if requested
    if args.network_analysis {
        simulator.enable_traffic_analysis();
    }

    simulator.initialize();

    // Run simulation for the specified duration (hard stop, no ramp-down)
    let _report = simulator.run_for(Duration::from_secs(args.duration));

    // Network traffic analysis
    if args.network_analysis {
        if let Some(traffic_report) = simulator.traffic_report() {
            traffic_report.print_summary();
        }
    }

    // Livelock analysis
    if args.analyze_livelocks {
        let livelock_report = simulator.analyze_livelocks();
        livelock_report.print_summary();
    }

    // Account usage stats
    let usage = simulator.account_usage_stats();
    if usage.skew_ratio() > 0.0 {
        println!("\n=== Account Usage ===");
        println!("Skew ratio: {:.2}", usage.skew_ratio());
    }
}
