//! Hyperscale Simulator
//!
//! A long-running workload simulator built on top of the simulation framework.
//! Provides tools for stress testing, performance measurement, and system validation.
//!
//! # Architecture
//!
//! The simulator builds on `hyperscale-simulation` to provide:
//!
//! - **Account Management**: Pre-funded accounts with shard-targeted generation (via `hyperscale-spammer`)
//! - **Workload Generation**: Configurable transaction generators (transfers, etc.) (via `hyperscale-spammer`)
//! - **Metrics Collection**: TPS, latency percentiles, lock contention tracking
//! - **Configuration**: Flexible setup for various test scenarios
//!
//! # Example
//!
//! ```ignore
//! use hyperscale_simulator::{Simulator, SimulatorConfig, WorkloadConfig};
//! use std::time::Duration;
//!
//! // Create a simulator with 2 shards, 3 validators each
//! let config = SimulatorConfig::new(2, 3)
//!     .with_accounts_per_shard(100)
//!     .with_workload(WorkloadConfig::transfers_only());
//!
//! let mut simulator = Simulator::new(config)?;
//! simulator.initialize();
//! let report = simulator.run_for(Duration::from_secs(60));
//!
//! println!("TPS: {:.2}", report.average_tps());
//! println!("P99 latency: {:?}", report.p99_latency());
//! ```

mod config;
mod livelock;
mod metrics;
mod runner;

pub use config::{SimulatorConfig, WorkloadConfig};
pub use runner::Simulator;
