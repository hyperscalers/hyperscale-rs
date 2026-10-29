//! Production runner with real async I/O.
//!
//! Wraps the deterministic node core with the process architecture a live
//! validator runs: one pinned `std::thread` per hosted shard, each driving
//! that shard's [`ShardLoop`] and draining a (timer, callback, shutdown)
//! channel triple in priority order, plus a shared tokio runtime carrying
//! the iroh transport, the RPC server, the per-shard timer sleep tasks, and the
//! per-host metrics + JMT GC ticks.
//!
//! Runtime shard membership — beacon-driven joins and leaves, reshape
//! duties, and the chains registered with the beacon loop — is executed by the
//! `ShardSupervisor` on the runner's tokio loop, never on a shard thread.
//!
//! Crypto verification and transaction execution are delegated through a
//! [`PooledDispatch`] whose thread counts and core pinning are configurable:
//!
//! ```no_run
//! use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
//! use std::sync::Arc;
//!
//! // Configure thread pools with explicit counts.
//! let config = ThreadPoolConfig::builder()
//!     .consensus_threads(2)
//!     .throughput_threads(12)
//!     .build()
//!     .unwrap();
//!
//! // Enable core pinning for cache locality (Linux only).
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
//! // Share one dispatch across every shard thread on the host.
//! let shared_dispatch = Arc::new(dispatch);
//! ```
//!
//! [`ShardLoop`]: hyperscale_node::shard::ShardLoop
//! [`PooledDispatch`]: hyperscale_dispatch_pooled::PooledDispatch

mod beacon_thread;
mod bootstrap;
mod handle;
pub mod network_file;
mod node;
mod observe;
pub mod rpc;
mod runner;
mod shard_thread;
mod status;
mod supervisor;
mod telemetry;
#[cfg(feature = "test-utils")]
pub mod testing;
mod transport;
pub use handle::{HandleHistory, NodeHandle};
pub use hyperscale_engine::{PreviewOutcome, PreviewReport};
pub use hyperscale_network_iroh::{SecretKey, load_or_generate_secret_key};
pub use hyperscale_storage::BeaconChainReader;
pub use network_file::{NetworkFile, NetworkFileError};
pub use node::{DEFAULT_BLOCK_CACHE_MB, Node, NodeError, NodeSetup, beacon_data_dir};
pub use observe::{Answers, HeaderSummary, Observation};
pub use runner::{LocalValidator, ProductionRunner, RunnerCommand, RunnerError, ShutdownHandle};
pub use supervisor::{
    AddValidatorError, ShardCommand, StorageDirResolver, StorageFactory, shard_data_dir,
};
pub use telemetry::{TelemetryConfig, TelemetryGuard, init_telemetry};
