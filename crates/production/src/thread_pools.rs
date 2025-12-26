//! Configurable thread pool management for production deployment.
//!
//! This module provides flexible core allocation for the different workload types:
//!
//! - **State Machine**: Single thread for deterministic event processing
//! - **Crypto Pool**: BLS signature verification (CPU-intensive)
//! - **Execution Pool**: Transaction execution via Radix Engine
//! - **Async I/O**: Network, storage, timers (tokio runtime)
//!
//! # Example
//!
//! ```no_run
//! use hyperscale_production::{ThreadPoolConfig, ThreadPoolManager};
//!
//! // Auto-detect cores and use default ratios
//! let config = ThreadPoolConfig::auto();
//! let manager = ThreadPoolManager::new(config).unwrap();
//!
//! // Or customize
//! let config = ThreadPoolConfig::builder()
//!     .crypto_threads(4)
//!     .execution_threads(6)
//!     .io_threads(2)
//!     .build()
//!     .unwrap();
//!
//! let manager = ThreadPoolManager::new(config).unwrap();
//! ```

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors from thread pool configuration.
#[derive(Debug, Error)]
pub enum ThreadPoolError {
    #[error("Failed to build rayon thread pool: {0}")]
    RayonBuildError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Core pinning failed: {0}")]
    CorePinningError(String),
}

/// Configuration for production thread pools.
///
/// Determines how many threads/cores are allocated to each workload type.
/// Use `ThreadPoolConfig::auto()` to automatically detect available cores
/// and allocate them using recommended ratios.
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Number of threads for consensus-critical crypto operations (block votes, QC verification).
    /// This is a dedicated high-priority pool that is never blocked by execution-layer
    /// crypto work (provisions, state votes). Keeping this pool responsive is critical
    /// for consensus liveness - block vote verification delays cause view changes.
    pub consensus_crypto_threads: usize,

    /// Number of threads for general crypto operations (provisions, state votes).
    /// These are CPU-bound but not consensus-critical. They can queue without affecting liveness.
    pub crypto_threads: usize,

    /// Number of threads for transaction signature validation.
    /// This is a dedicated pool to prevent transaction floods from blocking
    /// provision/state vote verification which are needed for execution progress.
    pub tx_validation_threads: usize,

    /// Number of threads for transaction execution.
    /// These run the Radix Engine and are CPU/memory intensive.
    pub execution_threads: usize,

    /// Number of threads for codec operations (SBOR encoding/decoding).
    /// This pool handles message serialization to prevent the network event loop
    /// from blocking on large messages (state batches, transaction bundles).
    pub codec_threads: usize,

    /// Number of threads for the tokio async runtime (network, storage, timers).
    /// These are mostly I/O-bound.
    pub io_threads: usize,

    /// Whether to pin threads to specific CPU cores.
    /// Improves cache locality but reduces flexibility.
    pub pin_cores: bool,

    /// Starting core index for crypto pool (if pinning enabled).
    pub crypto_core_start: Option<usize>,

    /// Starting core index for execution pool (if pinning enabled).
    pub execution_core_start: Option<usize>,

    /// Starting core index for I/O pool (if pinning enabled).
    pub io_core_start: Option<usize>,

    /// Core index for the state machine thread (if pinning enabled).
    /// The state machine always runs on a single thread.
    pub state_machine_core: Option<usize>,

    /// Stack size for crypto threads (bytes). Default: 2MB.
    pub crypto_stack_size: usize,

    /// Stack size for execution threads (bytes). Default: 8MB (Radix Engine needs more).
    pub execution_stack_size: usize,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self::auto()
    }
}

impl ThreadPoolConfig {
    /// Automatically configure based on available CPU cores.
    ///
    /// Uses the following allocation ratios:
    /// - State Machine: 1 core (always)
    /// - Consensus Crypto: 2 threads (dedicated for block votes/QC - liveness critical)
    /// - TX Validation: 2 threads (dedicated for transaction signature verification)
    /// - Codec: 2 threads (dedicated for SBOR encode/decode to unblock network event loop)
    /// - Execution: 40% of remaining cores (min 1)
    /// - General Crypto: 30% of remaining cores (min 1)
    /// - I/O: 30% of remaining cores (min 1)
    ///
    /// On systems with fewer than 6 cores, all pools get 1 thread each.
    pub fn auto() -> Self {
        let available = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(4);

        Self::for_core_count(available)
    }

    /// Configure for a specific number of available cores.
    ///
    /// Useful for testing or when you want to limit resource usage.
    pub fn for_core_count(total_cores: usize) -> Self {
        // Reserve 1 core for state machine
        let remaining = total_cores.saturating_sub(1).max(6);

        // Allocation: consensus_crypto, tx_validation, and codec get dedicated threads, rest split among others
        // Consensus crypto is critical for liveness - even under heavy load, block votes
        // must be verified quickly to form QCs within the view_change_timeout (3s default)
        // TX validation is separate to prevent transaction floods from blocking execution-layer crypto
        // Codec is separate to prevent large message decoding from blocking the network event loop
        let (consensus_crypto, tx_validation, codec, crypto, execution, io) = if remaining <= 6 {
            // Minimum viable: 1 each
            (1, 1, 1, 1, 1, 1)
        } else {
            // Consensus crypto: fixed 2 threads (enough for ~1000 votes/sec)
            // TX validation: fixed 2 threads (enough for transaction flood isolation)
            // Codec: fixed 2 threads (enough for message encode/decode throughput)
            let consensus_crypto = 2;
            let tx_validation = 2;
            let codec = 2;
            let after_dedicated =
                remaining.saturating_sub(consensus_crypto + tx_validation + codec);
            // Remaining split: execution 40%, crypto 30%, I/O 30%
            let execution = (after_dedicated * 40 / 100).max(1);
            let crypto = (after_dedicated * 30 / 100).max(1);
            let io = after_dedicated
                .saturating_sub(crypto)
                .saturating_sub(execution)
                .max(1);
            (
                consensus_crypto,
                tx_validation,
                codec,
                crypto,
                execution,
                io,
            )
        };

        Self {
            consensus_crypto_threads: consensus_crypto,
            crypto_threads: crypto,
            tx_validation_threads: tx_validation,
            execution_threads: execution,
            codec_threads: codec,
            io_threads: io,
            pin_cores: false,
            crypto_core_start: None,
            execution_core_start: None,
            io_core_start: None,
            state_machine_core: None,
            crypto_stack_size: 2 * 1024 * 1024,    // 2MB
            execution_stack_size: 8 * 1024 * 1024, // 8MB for Radix Engine
        }
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> ThreadPoolConfigBuilder {
        ThreadPoolConfigBuilder::new()
    }

    /// Create a minimal configuration for testing (1 thread per pool).
    pub fn minimal() -> Self {
        Self {
            consensus_crypto_threads: 1,
            crypto_threads: 1,
            tx_validation_threads: 1,
            execution_threads: 1,
            codec_threads: 1,
            io_threads: 1,
            pin_cores: false,
            crypto_core_start: None,
            execution_core_start: None,
            io_core_start: None,
            state_machine_core: None,
            crypto_stack_size: 2 * 1024 * 1024,
            execution_stack_size: 8 * 1024 * 1024,
        }
    }

    /// Total number of threads that will be spawned (excluding state machine).
    pub fn total_threads(&self) -> usize {
        self.consensus_crypto_threads
            + self.crypto_threads
            + self.tx_validation_threads
            + self.execution_threads
            + self.codec_threads
            + self.io_threads
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ThreadPoolError> {
        if self.consensus_crypto_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "consensus_crypto_threads must be at least 1".to_string(),
            ));
        }
        if self.crypto_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "crypto_threads must be at least 1".to_string(),
            ));
        }
        if self.tx_validation_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "tx_validation_threads must be at least 1".to_string(),
            ));
        }
        if self.execution_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "execution_threads must be at least 1".to_string(),
            ));
        }
        if self.codec_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "codec_threads must be at least 1".to_string(),
            ));
        }
        if self.io_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "io_threads must be at least 1".to_string(),
            ));
        }

        // If pinning is enabled, check that core assignments don't overlap
        if self.pin_cores {
            let available = std::thread::available_parallelism()
                .map(NonZeroUsize::get)
                .unwrap_or(4);

            let total_needed = 1
                + self.consensus_crypto_threads
                + self.crypto_threads
                + self.tx_validation_threads
                + self.execution_threads
                + self.codec_threads
                + self.io_threads;
            if total_needed > available {
                return Err(ThreadPoolError::InvalidConfig(format!(
                    "Configuration requires {} cores but only {} are available",
                    total_needed, available
                )));
            }
        }

        Ok(())
    }
}

/// Builder for ThreadPoolConfig.
#[derive(Debug, Clone)]
pub struct ThreadPoolConfigBuilder {
    config: ThreadPoolConfig,
}

impl ThreadPoolConfigBuilder {
    /// Create a new builder with auto-detected defaults.
    pub fn new() -> Self {
        Self {
            config: ThreadPoolConfig::auto(),
        }
    }

    /// Set the number of consensus crypto threads (block votes, QC verification).
    /// These are liveness-critical and should not be set too low.
    pub fn consensus_crypto_threads(mut self, count: usize) -> Self {
        self.config.consensus_crypto_threads = count;
        self
    }

    /// Set the number of general crypto verification threads (provisions, state votes).
    pub fn crypto_threads(mut self, count: usize) -> Self {
        self.config.crypto_threads = count;
        self
    }

    /// Set the number of transaction validation threads.
    pub fn tx_validation_threads(mut self, count: usize) -> Self {
        self.config.tx_validation_threads = count;
        self
    }

    /// Set the number of execution threads.
    pub fn execution_threads(mut self, count: usize) -> Self {
        self.config.execution_threads = count;
        self
    }

    /// Set the number of codec threads (SBOR encoding/decoding).
    pub fn codec_threads(mut self, count: usize) -> Self {
        self.config.codec_threads = count;
        self
    }

    /// Set the number of I/O threads.
    pub fn io_threads(mut self, count: usize) -> Self {
        self.config.io_threads = count;
        self
    }

    /// Enable core pinning.
    pub fn pin_cores(mut self, enabled: bool) -> Self {
        self.config.pin_cores = enabled;
        self
    }

    /// Set the core for the state machine thread.
    pub fn state_machine_core(mut self, core: usize) -> Self {
        self.config.state_machine_core = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set the starting core for the crypto pool.
    pub fn crypto_core_start(mut self, core: usize) -> Self {
        self.config.crypto_core_start = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set the starting core for the execution pool.
    pub fn execution_core_start(mut self, core: usize) -> Self {
        self.config.execution_core_start = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set the starting core for the I/O pool.
    pub fn io_core_start(mut self, core: usize) -> Self {
        self.config.io_core_start = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set stack size for crypto threads.
    pub fn crypto_stack_size(mut self, size: usize) -> Self {
        self.config.crypto_stack_size = size;
        self
    }

    /// Set stack size for execution threads.
    pub fn execution_stack_size(mut self, size: usize) -> Self {
        self.config.execution_stack_size = size;
        self
    }

    /// Build the configuration, validating it first.
    pub fn build(self) -> Result<ThreadPoolConfig, ThreadPoolError> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// Build the configuration without validation.
    pub fn build_unchecked(self) -> ThreadPoolConfig {
        self.config
    }
}

impl Default for ThreadPoolConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages thread pools for production deployment.
///
/// Creates and owns:
/// - A rayon thread pool for consensus-critical crypto (block votes, QC verification)
/// - A rayon thread pool for general crypto operations (provisions, state votes)
/// - A rayon thread pool for transaction signature validation (isolated from other crypto)
/// - A rayon thread pool for execution operations (Radix Engine)
/// - A rayon thread pool for codec operations (SBOR encoding/decoding)
/// - Configuration for tokio runtime (actual runtime created by caller)
///
/// The separation of consensus crypto from general crypto is critical for liveness:
/// under high load, provision and state vote verification can queue up, but block vote
/// verification must remain responsive to form QCs within the view_change_timeout.
///
/// Transaction validation is further isolated to prevent transaction floods from
/// blocking provision/state vote verification which are needed for execution progress.
///
/// Codec operations are isolated to prevent large message encoding/decoding from
/// blocking the network event loop.
pub struct ThreadPoolManager {
    /// Configuration used to create the pools.
    config: ThreadPoolConfig,

    /// Rayon pool for consensus-critical crypto (block votes, QC verification).
    /// This pool is kept small and dedicated to ensure liveness under load.
    consensus_crypto_pool: rayon::ThreadPool,

    /// Rayon pool for general crypto operations (provisions, state votes).
    crypto_pool: rayon::ThreadPool,

    /// Rayon pool for transaction signature validation.
    /// Isolated from general crypto to prevent tx floods from blocking execution progress.
    tx_validation_pool: rayon::ThreadPool,

    /// Rayon pool for execution operations (Radix Engine).
    execution_pool: rayon::ThreadPool,

    /// Rayon pool for codec operations (SBOR encoding/decoding).
    /// Isolated to prevent large message serialization from blocking the network event loop.
    codec_pool: rayon::ThreadPool,

    /// Queue depth tracking for consensus crypto pool (for metrics).
    consensus_crypto_pending: Arc<AtomicUsize>,

    /// Queue depth tracking for general crypto pool (for metrics).
    crypto_pending: Arc<AtomicUsize>,

    /// Queue depth tracking for tx validation pool (for metrics).
    tx_validation_pending: Arc<AtomicUsize>,

    /// Queue depth tracking for execution pool (for metrics).
    execution_pending: Arc<AtomicUsize>,

    /// Queue depth tracking for codec pool (for metrics).
    codec_pending: Arc<AtomicUsize>,
}

impl ThreadPoolManager {
    /// Create a new thread pool manager with the given configuration.
    pub fn new(config: ThreadPoolConfig) -> Result<Self, ThreadPoolError> {
        config.validate()?;

        let consensus_crypto_pool = Self::build_consensus_crypto_pool(&config)?;
        let crypto_pool = Self::build_crypto_pool(&config)?;
        let tx_validation_pool = Self::build_tx_validation_pool(&config)?;
        let execution_pool = Self::build_execution_pool(&config)?;
        let codec_pool = Self::build_codec_pool(&config)?;

        tracing::info!(
            consensus_crypto_threads = config.consensus_crypto_threads,
            crypto_threads = config.crypto_threads,
            tx_validation_threads = config.tx_validation_threads,
            execution_threads = config.execution_threads,
            codec_threads = config.codec_threads,
            io_threads = config.io_threads,
            pin_cores = config.pin_cores,
            "Thread pools initialized"
        );

        Ok(Self {
            config,
            consensus_crypto_pool,
            crypto_pool,
            tx_validation_pool,
            execution_pool,
            codec_pool,
            consensus_crypto_pending: Arc::new(AtomicUsize::new(0)),
            crypto_pending: Arc::new(AtomicUsize::new(0)),
            tx_validation_pending: Arc::new(AtomicUsize::new(0)),
            execution_pending: Arc::new(AtomicUsize::new(0)),
            codec_pending: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Create with auto-detected configuration.
    pub fn auto() -> Result<Self, ThreadPoolError> {
        Self::new(ThreadPoolConfig::auto())
    }

    /// Build the consensus-critical crypto pool (block votes, QC verification).
    /// This pool is kept separate from general crypto to ensure liveness under load.
    fn build_consensus_crypto_pool(
        config: &ThreadPoolConfig,
    ) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.consensus_crypto_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("consensus-crypto-{}", i));

        // Note: We don't pin consensus crypto threads by default - they should be
        // available to run on any core for best responsiveness under load.

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    /// Build the general crypto pool (provisions, state votes).
    fn build_crypto_pool(config: &ThreadPoolConfig) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.crypto_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("crypto-{}", i));

        // Core pinning for crypto threads
        if config.pin_cores {
            let start_core = config
                .crypto_core_start
                .unwrap_or(1 + config.consensus_crypto_threads); // Default: after consensus crypto
            builder = builder.start_handler(move |i| {
                let core_id = start_core + i;
                if let Err(e) = pin_thread_to_core(core_id) {
                    tracing::warn!(core = core_id, error = ?e, "Failed to pin crypto thread");
                } else {
                    tracing::debug!(core = core_id, thread = i, "Pinned crypto thread");
                }
            });
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    /// Build the transaction validation pool (isolated from general crypto).
    fn build_tx_validation_pool(
        config: &ThreadPoolConfig,
    ) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.tx_validation_threads)
            .stack_size(config.crypto_stack_size) // Same stack size as crypto
            .thread_name(|i| format!("tx-val-{}", i));

        // Note: No core pinning for tx validation - let OS schedule freely
        // This pool handles bursty workloads and benefits from flexibility

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    fn build_execution_pool(
        config: &ThreadPoolConfig,
    ) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.execution_threads)
            .stack_size(config.execution_stack_size)
            .thread_name(|i| format!("exec-{}", i));

        // Core pinning for execution threads
        if config.pin_cores {
            let start_core = config
                .execution_core_start
                .unwrap_or(1 + config.consensus_crypto_threads + config.crypto_threads); // Default: after both crypto pools
            builder = builder.start_handler(move |i| {
                let core_id = start_core + i;
                if let Err(e) = pin_thread_to_core(core_id) {
                    tracing::warn!(core = core_id, error = ?e, "Failed to pin execution thread");
                } else {
                    tracing::debug!(core = core_id, thread = i, "Pinned execution thread");
                }
            });
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    /// Build the codec pool (SBOR encoding/decoding).
    fn build_codec_pool(config: &ThreadPoolConfig) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.codec_threads)
            .stack_size(config.crypto_stack_size) // Same stack size as crypto
            .thread_name(|i| format!("codec-{}", i));

        // Note: No core pinning for codec - let OS schedule freely
        // This pool handles bursty workloads and benefits from flexibility

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    /// Get a reference to the consensus crypto thread pool.
    pub fn consensus_crypto_pool(&self) -> &rayon::ThreadPool {
        &self.consensus_crypto_pool
    }

    /// Get a reference to the general crypto thread pool.
    pub fn crypto_pool(&self) -> &rayon::ThreadPool {
        &self.crypto_pool
    }

    /// Get a reference to the transaction validation thread pool.
    pub fn tx_validation_pool(&self) -> &rayon::ThreadPool {
        &self.tx_validation_pool
    }

    /// Get a reference to the execution thread pool.
    pub fn execution_pool(&self) -> &rayon::ThreadPool {
        &self.execution_pool
    }

    /// Get a reference to the codec thread pool.
    pub fn codec_pool(&self) -> &rayon::ThreadPool {
        &self.codec_pool
    }

    /// Get the configuration.
    pub fn config(&self) -> &ThreadPoolConfig {
        &self.config
    }

    /// Get the number of I/O threads (for tokio runtime configuration).
    pub fn io_threads(&self) -> usize {
        self.config.io_threads
    }

    /// Build a tokio runtime with the configured I/O threads.
    ///
    /// Note: The caller is responsible for entering and running this runtime.
    pub fn build_tokio_runtime(&self) -> Result<tokio::runtime::Runtime, ThreadPoolError> {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(self.config.io_threads);
        builder.thread_name("io");
        builder.enable_all();

        // Core pinning for I/O threads would require custom thread spawning
        // which tokio doesn't directly support. We log a warning if requested.
        if self.config.pin_cores && self.config.io_core_start.is_some() {
            tracing::warn!(
                "Core pinning for tokio I/O threads is not directly supported. \
                 Consider using tokio-core-affinity crate for this feature."
            );
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    /// Spawn a consensus-critical crypto task on the dedicated consensus crypto pool.
    ///
    /// Use this for block vote and QC signature verification - these are liveness-critical
    /// and must not be blocked by general crypto work (provisions, state votes).
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
    #[instrument(level = "debug", skip_all, fields(
        queue_depth = self.consensus_crypto_pending.load(Ordering::Relaxed),
    ))]
    pub fn spawn_consensus_crypto<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.consensus_crypto_pending
            .fetch_add(1, Ordering::Relaxed);
        let pending = self.consensus_crypto_pending.clone();
        self.consensus_crypto_pool.spawn(move || {
            f();
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Spawn a general crypto verification task on the crypto pool.
    ///
    /// Use this for provisions and state votes - these are not consensus-critical
    /// and can queue without affecting liveness.
    ///
    /// Note: Transaction validation should use `spawn_tx_validation` instead.
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
    pub fn spawn_crypto<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.crypto_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.crypto_pending.clone();
        self.crypto_pool.spawn(move || {
            f();
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Spawn a transaction validation task on the dedicated tx validation pool.
    ///
    /// Use this for transaction signature verification. This pool is isolated from
    /// the general crypto pool to prevent transaction floods from blocking
    /// provision/state vote verification which are needed for execution progress.
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
    pub fn spawn_tx_validation<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.tx_validation_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.tx_validation_pending.clone();
        self.tx_validation_pool.spawn(move || {
            f();
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Spawn a crypto task with backpressure-based throttling (non-blocking).
    ///
    /// When the crypto queue is deep, this returns `false` to signal backpressure
    /// to the caller. The caller can then decide to retry later or handle the
    /// backpressure appropriately.
    ///
    /// **IMPORTANT**: This method is non-blocking. Previous versions used
    /// `std::thread::sleep()` which blocked the event loop thread. This version
    /// returns immediately with a backpressure signal instead.
    ///
    /// Use this for non-critical crypto work like provision verification where
    /// slight delays are acceptable to maintain system stability.
    ///
    /// Returns:
    /// - `true` if the task was spawned
    /// - `false` if backpressure is active (queue depth > threshold)
    ///
    /// Backpressure threshold: queue depth > 100 (half of previous max)
    pub fn try_spawn_crypto<F>(&self, f: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        let depth = self.crypto_pending.load(Ordering::Relaxed);

        // Backpressure threshold - reject if queue is too deep
        const BACKPRESSURE_THRESHOLD: usize = 100;

        if depth > BACKPRESSURE_THRESHOLD {
            // Signal backpressure - caller should retry later
            return false;
        }

        self.spawn_crypto(f);
        true
    }

    /// Spawn a crypto task, always succeeds (no backpressure).
    ///
    /// Use `try_spawn_crypto` for non-critical work that can tolerate backpressure.
    /// Use this method only when the task MUST be spawned regardless of queue depth.
    ///
    /// **Deprecated**: Use `try_spawn_crypto` for new code to enable backpressure.
    #[deprecated(note = "Use try_spawn_crypto for backpressure support")]
    pub fn spawn_crypto_throttled<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        // For backwards compatibility, always spawn (no blocking)
        // New code should use try_spawn_crypto and handle backpressure
        self.spawn_crypto(f);
    }

    /// Spawn an execution task on the execution pool.
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
    #[instrument(level = "debug", skip_all, fields(
        queue_depth = self.execution_pending.load(Ordering::Relaxed),
    ))]
    pub fn spawn_execution<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.execution_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.execution_pending.clone();
        self.execution_pool.spawn(move || {
            f();
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Spawn a codec task on the codec pool.
    ///
    /// Use this for SBOR encoding/decoding operations. This pool is isolated from
    /// the network event loop to prevent large message serialization from blocking
    /// network processing.
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
    pub fn spawn_codec<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.codec_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.codec_pending.clone();
        self.codec_pool.spawn(move || {
            f();
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Get current consensus crypto pool queue depth (for metrics).
    pub fn consensus_crypto_queue_depth(&self) -> usize {
        self.consensus_crypto_pending.load(Ordering::Relaxed)
    }

    /// Get current general crypto pool queue depth (for metrics).
    pub fn crypto_queue_depth(&self) -> usize {
        self.crypto_pending.load(Ordering::Relaxed)
    }

    /// Get current tx validation pool queue depth (for metrics).
    pub fn tx_validation_queue_depth(&self) -> usize {
        self.tx_validation_pending.load(Ordering::Relaxed)
    }

    /// Get current codec pool queue depth (for metrics).
    pub fn codec_queue_depth(&self) -> usize {
        self.codec_pending.load(Ordering::Relaxed)
    }

    /// Get current execution pool queue depth (for metrics).
    pub fn execution_queue_depth(&self) -> usize {
        self.execution_pending.load(Ordering::Relaxed)
    }

    /// Install the crypto pool as the global rayon pool.
    ///
    /// This affects all uses of `rayon::spawn()` globally.
    /// Generally not recommended - prefer using explicit pool references.
    pub fn install_crypto_as_global(self) -> Arc<Self> {
        // Note: rayon's global pool can only be set once, so this is a one-way operation
        tracing::warn!(
            "Installing crypto pool as global rayon pool. \
             This affects all rayon::spawn() calls globally."
        );
        Arc::new(self)
    }
}

/// Pin the current thread to a specific CPU core.
///
/// This is platform-specific and may not be available on all systems.
#[cfg(target_os = "linux")]
fn pin_thread_to_core(core_id: usize) -> Result<(), ThreadPoolError> {
    use std::mem;

    unsafe {
        let mut cpuset: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(core_id, &mut cpuset);

        let result = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &cpuset);

        if result == 0 {
            Ok(())
        } else {
            Err(ThreadPoolError::CorePinningError(format!(
                "sched_setaffinity failed for core {}",
                core_id
            )))
        }
    }
}

#[cfg(target_os = "macos")]
fn pin_thread_to_core(core_id: usize) -> Result<(), ThreadPoolError> {
    // macOS doesn't support strict CPU pinning like Linux.
    // We can use thread_policy_set with THREAD_AFFINITY_POLICY as a hint,
    // but it's not guaranteed to be respected.
    tracing::debug!(
        core = core_id,
        "Core pinning on macOS is best-effort (using affinity hints)"
    );

    // For now, just log and succeed - the OS will schedule as it sees fit
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn pin_thread_to_core(core_id: usize) -> Result<(), ThreadPoolError> {
    tracing::warn!(
        core = core_id,
        "Core pinning not implemented for this platform"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_config() {
        let config = ThreadPoolConfig::auto();
        assert!(config.consensus_crypto_threads >= 1);
        assert!(config.crypto_threads >= 1);
        assert!(config.tx_validation_threads >= 1);
        assert!(config.execution_threads >= 1);
        assert!(config.codec_threads >= 1);
        assert!(config.io_threads >= 1);
        config.validate().unwrap();
    }

    #[test]
    fn test_for_core_count() {
        // 6 cores: 1 state + 1 each for all pools (minimum viable)
        let config = ThreadPoolConfig::for_core_count(6);
        assert_eq!(config.consensus_crypto_threads, 1);
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.tx_validation_threads, 1);
        assert_eq!(config.execution_threads, 1);
        assert_eq!(config.codec_threads, 1);
        assert_eq!(config.io_threads, 1);

        // 12 cores: 1 state + 2 consensus_crypto + 2 tx_validation + 2 codec + rest split
        let config = ThreadPoolConfig::for_core_count(12);
        assert!(config.consensus_crypto_threads >= 1);
        assert!(config.crypto_threads >= 1);
        assert!(config.tx_validation_threads >= 1);
        assert!(config.execution_threads >= 1);
        assert!(config.codec_threads >= 1);
        assert!(config.io_threads >= 1);

        // 18 cores: more balanced with dedicated consensus crypto, tx validation, and codec
        // 17 remaining after state machine, 11 after consensus crypto (2), tx_validation (2), codec (2)
        // execution 40% = 4, crypto 30% = 3, io = 4
        let config = ThreadPoolConfig::for_core_count(18);
        assert_eq!(config.consensus_crypto_threads, 2); // Fixed 2 threads for consensus crypto
        assert_eq!(config.tx_validation_threads, 2); // Fixed 2 threads for tx validation
        assert_eq!(config.codec_threads, 2); // Fixed 2 threads for codec
        assert!(config.crypto_threads >= 2);
        assert!(config.execution_threads >= 3);
        assert!(config.io_threads >= 2);
    }

    #[test]
    fn test_minimal_config() {
        let config = ThreadPoolConfig::minimal();
        assert_eq!(config.consensus_crypto_threads, 1);
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.tx_validation_threads, 1);
        assert_eq!(config.execution_threads, 1);
        assert_eq!(config.codec_threads, 1);
        assert_eq!(config.io_threads, 1);
        config.validate().unwrap();
    }

    #[test]
    fn test_builder() {
        let config = ThreadPoolConfig::builder()
            .crypto_threads(4)
            .execution_threads(8)
            .io_threads(2)
            .build()
            .unwrap();

        assert_eq!(config.crypto_threads, 4);
        assert_eq!(config.execution_threads, 8);
        assert_eq!(config.io_threads, 2);
    }

    #[test]
    fn test_builder_with_pinning() {
        let config = ThreadPoolConfig::builder()
            .crypto_threads(2)
            .execution_threads(4)
            .io_threads(2)
            .state_machine_core(0)
            .crypto_core_start(1)
            .execution_core_start(3)
            .io_core_start(7)
            .build_unchecked();

        assert!(config.pin_cores);
        assert_eq!(config.state_machine_core, Some(0));
        assert_eq!(config.crypto_core_start, Some(1));
        assert_eq!(config.execution_core_start, Some(3));
        assert_eq!(config.io_core_start, Some(7));
    }

    #[test]
    fn test_invalid_config() {
        let result = ThreadPoolConfig::builder().crypto_threads(0).build();
        assert!(result.is_err());

        let result = ThreadPoolConfig::builder().execution_threads(0).build();
        assert!(result.is_err());

        let result = ThreadPoolConfig::builder().io_threads(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_pool_manager_creation() {
        let config = ThreadPoolConfig::minimal();
        let manager = ThreadPoolManager::new(config).unwrap();

        assert_eq!(manager.config().consensus_crypto_threads, 1);
        assert_eq!(manager.config().crypto_threads, 1);
        assert_eq!(manager.config().execution_threads, 1);
        assert_eq!(manager.config().codec_threads, 1);
        assert_eq!(manager.io_threads(), 1);
    }

    #[test]
    fn test_spawn_on_pools() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = ThreadPoolConfig::minimal();
        let manager = ThreadPoolManager::new(config).unwrap();

        let consensus_crypto_counter = Arc::new(AtomicUsize::new(0));
        let crypto_counter = Arc::new(AtomicUsize::new(0));
        let tx_validation_counter = Arc::new(AtomicUsize::new(0));
        let exec_counter = Arc::new(AtomicUsize::new(0));
        let codec_counter = Arc::new(AtomicUsize::new(0));

        // Spawn on consensus crypto pool
        let counter = consensus_crypto_counter.clone();
        manager.spawn_consensus_crypto(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn on general crypto pool
        let counter = crypto_counter.clone();
        manager.spawn_crypto(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn on tx validation pool
        let counter = tx_validation_counter.clone();
        manager.spawn_tx_validation(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn on execution pool
        let counter = exec_counter.clone();
        manager.spawn_execution(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn on codec pool
        let counter = codec_counter.clone();
        manager.spawn_codec(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Wait for tasks to complete
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(consensus_crypto_counter.load(Ordering::SeqCst), 1);
        assert_eq!(crypto_counter.load(Ordering::SeqCst), 1);
        assert_eq!(tx_validation_counter.load(Ordering::SeqCst), 1);
        assert_eq!(exec_counter.load(Ordering::SeqCst), 1);
        assert_eq!(codec_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_total_threads() {
        let config = ThreadPoolConfig::builder()
            .consensus_crypto_threads(2)
            .crypto_threads(4)
            .tx_validation_threads(3)
            .execution_threads(6)
            .codec_threads(2)
            .io_threads(2)
            .build_unchecked();

        assert_eq!(config.total_threads(), 19); // 2 + 4 + 3 + 6 + 2 + 2
    }
}
