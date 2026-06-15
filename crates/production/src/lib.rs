//! Production runner with async I/O.
//!
//! This crate provides the production runner that wraps the deterministic
//! state machine with real async I/O:
//!
//! - Network messages via tokio channels
//! - Timers via tokio intervals
//! - Crypto verification on dedicated rayon thread pool
//! - Transaction execution on dedicated rayon thread pool
//!
//! # Architecture
//!
//! Uses the event aggregator pattern: a single task owns the state machine
//! and receives events via an mpsc channel. This avoids mutex contention.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Production Node                                 │
//! │                                                                         │
//! │  Core 0 (pinned):  State Machine + Event Loop                           │
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │  ProductionRunner                                                   ││
//! │  │    └─ loop { event = recv(); actions = state.handle(event); }       ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! │                                │                                        │
//! │    ┌───────────────────────────┼───────────────────────────────┐        │
//! │    ▼                           ▼                               ▼        │
//! │  Crypto Pool (rayon)      Execution Pool (rayon)       I/O Pool (tokio) │
//! │  - BLS verification       - Radix Engine               - Network        │
//! │  - Signature checks       - Merkle computation         - Storage        │
//! │                                                        - Timers         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Pool Configuration
//!
//! The number of threads for each pool is configurable:
//!
//! ```no_run
//! use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
//! use hyperscale_production::ProductionRunner;
//! use std::sync::Arc;
//!
//! // Configure thread pools with explicit counts
//! let config = ThreadPoolConfig::builder()
//!     .consensus_threads(2)
//!     .throughput_threads(12)
//!     .build()
//!     .unwrap();
//!
//! // Enable core pinning for cache locality (Linux only)
//! let config = ThreadPoolConfig::builder()
//!     .consensus_threads(2)
//!     .throughput_threads(12)
//!     .pin_cores(true)
//!     .consensus_core_start(1)   // Consensus pool on cores 1-2
//!     .throughput_core_start(3)  // Throughput pool on cores 3-14
//!     .build()
//!     .unwrap();
//!
//! let dispatch = PooledDispatch::new(config, tokio::runtime::Handle::current()).unwrap();
//!
//! // Share dispatch across multiple runners (e.g., multi-shard node)
//! let shared_dispatch = Arc::new(dispatch);
//! ```

mod bootstrap;
mod drain;
pub mod rpc;
mod runner;
mod status;
mod supervisor;
mod telemetry;
pub use runner::{ProductionRunner, RunnerError, ShutdownHandle, VnodeConfig};
pub use status::SyncStatus;
pub use supervisor::{ShardCommand, StorageDirResolver, StorageFactory};
pub use telemetry::{TelemetryConfig, TelemetryGuard, init_telemetry};
