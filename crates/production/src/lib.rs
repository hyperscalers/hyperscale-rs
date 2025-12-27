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
//! use hyperscale_production::{ThreadPoolConfig, ThreadPoolManager, ProductionRunner};
//! use std::sync::Arc;
//!
//! // Auto-detect cores and use default ratios (25% crypto, 50% execution, 25% I/O)
//! let config = ThreadPoolConfig::auto();
//!
//! // Or customize for your hardware
//! let config = ThreadPoolConfig::builder()
//!     .crypto_threads(4)
//!     .execution_threads(8)
//!     .io_threads(2)
//!     .build()
//!     .unwrap();
//!
//! // Enable core pinning for cache locality (Linux only)
//! let config = ThreadPoolConfig::builder()
//!     .crypto_threads(4)
//!     .execution_threads(8)
//!     .io_threads(2)
//!     .pin_cores(true)
//!     .state_machine_core(0)    // Pin state machine to core 0
//!     .crypto_core_start(1)     // Crypto pool on cores 1-4
//!     .execution_core_start(5)  // Execution pool on cores 5-12
//!     .io_core_start(13)        // I/O pool on cores 13-14
//!     .build()
//!     .unwrap();
//!
//! let manager = ThreadPoolManager::new(config).unwrap();
//!
//! // Share thread pools across multiple runners (e.g., multi-shard node)
//! let shared_pools = Arc::new(manager);
//! ```

mod action_dispatcher;
mod fetch;
mod fetch_handler;
mod message_batcher;
pub(crate) mod metrics;
pub mod network;
pub mod rpc;
mod runner;
mod storage;
mod sync;
mod sync_error;
mod telemetry;
mod thread_pools;
mod timers;
mod validation_batcher;

pub use network::Libp2pConfig;
pub use runner::{ProductionRunner, RunnerError};
pub use storage::{CompressionType, RocksDbConfig, RocksDbStorage, StorageError};
pub use sync::SyncStatus;
pub use sync_error::SyncResponseError;
pub use telemetry::{init_telemetry, TelemetryConfig};
pub use thread_pools::{ThreadPoolConfig, ThreadPoolManager};
pub use validation_batcher::{
    spawn_tx_validation_batcher, ValidationBatcherConfig, ValidationBatcherHandle,
};
