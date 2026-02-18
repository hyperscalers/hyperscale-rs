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
//! use hyperscale_production::{ThreadPoolConfig, PooledDispatch, ProductionRunner};
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
//! let dispatch = PooledDispatch::new(config).unwrap();
//!
//! // Share dispatch across multiple runners (e.g., multi-shard node)
//! let shared_dispatch = Arc::new(dispatch);
//! ```

mod fetch;
pub mod rpc;
mod runner;
mod sync;
mod telemetry;
mod timers;
pub use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
pub use hyperscale_network_libp2p::{Libp2pConfig, Libp2pKeypair};
pub use hyperscale_storage_rocksdb::{
    CompressionType, RocksDbConfig, RocksDbStorage, StorageError,
};
pub use hyperscale_validation::{
    spawn_tx_validation_batcher, TransactionSink, ValidationBatcherConfig, ValidationBatcherHandle,
};
pub use runner::{ProductionRunner, RunnerError};
pub use sync::{SyncStateKind, SyncStatus};
pub use telemetry::{init_telemetry, TelemetryConfig, TelemetryGuard};
