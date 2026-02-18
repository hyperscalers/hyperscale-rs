//! Rayon thread pool dispatch for production deployment.
//!
//! This module provides [`PooledDispatch`] which schedules work across
//! priority-isolated rayon thread pools:
//!
//! - **Consensus Crypto**: Liveness-critical (block votes, QC verification)
//! - **Crypto**: General signature verification (provisions, state votes)
//! - **TX Validation**: Transaction signature verification (isolated from crypto)
//! - **Execution**: Radix Engine transaction execution
//! - **Codec**: SBOR message encoding/decoding
//!
//! # Example
//!
//! ```no_run
//! use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
//!
//! // Auto-detect cores and use default ratios
//! let config = ThreadPoolConfig::auto();
//! let dispatch = PooledDispatch::new(config).unwrap();
//!
//! // Or customize
//! let config = ThreadPoolConfig::builder()
//!     .crypto_threads(4)
//!     .execution_threads(6)
//!     .io_threads(2)
//!     .build()
//!     .unwrap();
//!
//! let dispatch = PooledDispatch::new(config).unwrap();
//! ```

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

use hyperscale_dispatch::Dispatch;

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
    /// These are mostly I/O-bound. Not used by dispatch itself — provided for
    /// runner configuration.
    pub io_threads: usize,

    /// Whether to pin threads to specific CPU cores.
    /// Improves cache locality but reduces flexibility.
    pub pin_cores: bool,

    /// Starting core index for consensus crypto pool (if pinning enabled).
    pub consensus_crypto_core_start: Option<usize>,

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
    /// - After reserving state machine and consensus crypto, remaining cores are split:
    ///   - Crypto: 35% (provisions, state votes, gossiped cert verification - highest load)
    ///   - Execution: 25% (Radix Engine)
    ///   - TX Validation: 15% (transaction signature verification)
    ///   - I/O: 15% (network, storage, timers)
    ///   - Codec: 10% (SBOR encode/decode)
    ///
    /// On systems with fewer than 8 cores, all pools get 1 thread each.
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
        // Reserve 1 core for state machine + 2 for consensus crypto.
        // Floor at 6 so small machines still get 1 thread per pool (over-subscribing is fine).
        let pool_budget = total_cores.saturating_sub(3).max(6);

        // Allocation:
        // - Consensus crypto is fixed at 2 threads (liveness critical for block votes/QC)
        // - All other pools use percentage-based allocation from pool_budget
        let (consensus_crypto, tx_validation, codec, crypto, execution, io) = if pool_budget <= 6 {
            // Minimum viable: 1 each for variable pools, 2 for consensus crypto
            (2, 1, 1, 1, 1, 1)
        } else {
            // Consensus crypto: fixed 2 threads (enough for ~1000 votes/sec)
            let consensus_crypto = 2;

            // Pool budget split by percentage:
            // - Crypto: 35% (provisions, state votes, gossiped cert verification - highest load)
            // - Execution: 25% (Radix Engine)
            // - TX Validation: 15% (transaction signature verification, bursty)
            // - I/O: 15% (network, storage, timers)
            // - Codec: 10% (SBOR encode/decode)
            let crypto = (pool_budget * 35 / 100).max(1);
            let execution = (pool_budget * 25 / 100).max(1);
            let tx_validation = (pool_budget * 15 / 100).max(1);
            let io = (pool_budget * 15 / 100).max(1);
            // Codec gets the remainder to ensure we use all cores
            let codec = pool_budget
                .saturating_sub(crypto)
                .saturating_sub(execution)
                .saturating_sub(tx_validation)
                .saturating_sub(io)
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
            consensus_crypto_core_start: None,
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
            consensus_crypto_core_start: None,
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

    /// Set the starting core for the consensus crypto pool.
    pub fn consensus_crypto_core_start(mut self, core: usize) -> Self {
        self.config.consensus_crypto_core_start = Some(core);
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

/// Rayon thread pool dispatch for production deployment.
///
/// Creates and owns priority-isolated rayon thread pools:
/// - Consensus crypto pool (block votes, QC verification) — liveness-critical
/// - General crypto pool (provisions, state votes)
/// - TX validation pool (transaction signatures) — isolated from crypto
/// - Execution pool (Radix Engine)
/// - Codec pool (SBOR encoding/decoding)
///
/// Spawned closures are automatically wrapped in `rayon::ThreadPool::install()`,
/// ensuring that `par_iter` and other parallel primitives use the correct pool.
pub struct PooledDispatch {
    config: ThreadPoolConfig,
    consensus_crypto_pool: Arc<rayon::ThreadPool>,
    crypto_pool: Arc<rayon::ThreadPool>,
    tx_validation_pool: Arc<rayon::ThreadPool>,
    execution_pool: Arc<rayon::ThreadPool>,
    codec_pool: Arc<rayon::ThreadPool>,
    consensus_crypto_pending: Arc<AtomicUsize>,
    crypto_pending: Arc<AtomicUsize>,
    tx_validation_pending: Arc<AtomicUsize>,
    execution_pending: Arc<AtomicUsize>,
    codec_pending: Arc<AtomicUsize>,
}

impl PooledDispatch {
    /// Create a new pooled dispatch with the given configuration.
    pub fn new(config: ThreadPoolConfig) -> Result<Self, ThreadPoolError> {
        config.validate()?;

        let consensus_crypto_pool = Arc::new(Self::build_consensus_crypto_pool(&config)?);
        let crypto_pool = Arc::new(Self::build_crypto_pool(&config)?);
        let tx_validation_pool = Arc::new(Self::build_tx_validation_pool(&config)?);
        let execution_pool = Arc::new(Self::build_execution_pool(&config)?);
        let codec_pool = Arc::new(Self::build_codec_pool(&config)?);

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

    /// Get the configuration.
    pub fn config(&self) -> &ThreadPoolConfig {
        &self.config
    }

    fn build_consensus_crypto_pool(
        config: &ThreadPoolConfig,
    ) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.consensus_crypto_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("consensus-crypto-{}", i));

        if config.pin_cores {
            let start_core = config.consensus_crypto_core_start.unwrap_or(1);
            builder = builder.start_handler(move |i| {
                let core_id = start_core + i;
                if let Err(e) = pin_thread_to_core(core_id) {
                    tracing::warn!(core = core_id, error = ?e, "Failed to pin consensus crypto thread");
                } else {
                    tracing::debug!(core = core_id, thread = i, "Pinned consensus crypto thread");
                }
            });
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    fn build_crypto_pool(config: &ThreadPoolConfig) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.crypto_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("crypto-{}", i));

        if config.pin_cores {
            let start_core = config
                .crypto_core_start
                .unwrap_or(1 + config.consensus_crypto_threads);
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

    fn build_tx_validation_pool(
        config: &ThreadPoolConfig,
    ) -> Result<rayon::ThreadPool, ThreadPoolError> {
        rayon::ThreadPoolBuilder::new()
            .num_threads(config.tx_validation_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("tx-val-{}", i))
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

        if config.pin_cores {
            let start_core = config
                .execution_core_start
                .unwrap_or(1 + config.consensus_crypto_threads + config.crypto_threads);
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

    fn build_codec_pool(config: &ThreadPoolConfig) -> Result<rayon::ThreadPool, ThreadPoolError> {
        rayon::ThreadPoolBuilder::new()
            .num_threads(config.codec_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("codec-{}", i))
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }
}

impl Dispatch for PooledDispatch {
    #[instrument(level = "debug", skip_all)]
    fn spawn_consensus_crypto(&self, f: impl FnOnce() + Send + 'static) {
        self.consensus_crypto_pending
            .fetch_add(1, Ordering::Relaxed);
        let pending = self.consensus_crypto_pending.clone();
        let pool = Arc::clone(&self.consensus_crypto_pool);
        self.consensus_crypto_pool.spawn(move || {
            pool.install(f);
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn spawn_crypto(&self, f: impl FnOnce() + Send + 'static) {
        self.crypto_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.crypto_pending.clone();
        let pool = Arc::clone(&self.crypto_pool);
        self.crypto_pool.spawn(move || {
            pool.install(f);
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn try_spawn_crypto(&self, f: impl FnOnce() + Send + 'static) -> bool {
        let depth = self.crypto_pending.load(Ordering::Relaxed);

        const BACKPRESSURE_THRESHOLD: usize = 100;

        if depth > BACKPRESSURE_THRESHOLD {
            return false;
        }

        self.spawn_crypto(f);
        true
    }

    fn spawn_tx_validation(&self, f: impl FnOnce() + Send + 'static) {
        self.tx_validation_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.tx_validation_pending.clone();
        let pool = Arc::clone(&self.tx_validation_pool);
        self.tx_validation_pool.spawn(move || {
            pool.install(f);
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    #[instrument(level = "debug", skip_all)]
    fn spawn_execution(&self, f: impl FnOnce() + Send + 'static) {
        self.execution_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.execution_pending.clone();
        let pool = Arc::clone(&self.execution_pool);
        self.execution_pool.spawn(move || {
            pool.install(f);
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn spawn_codec(&self, f: impl FnOnce() + Send + 'static) {
        self.codec_pending.fetch_add(1, Ordering::Relaxed);
        let pending = self.codec_pending.clone();
        let pool = Arc::clone(&self.codec_pool);
        self.codec_pool.spawn(move || {
            pool.install(f);
            pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn consensus_crypto_queue_depth(&self) -> usize {
        self.consensus_crypto_pending.load(Ordering::Relaxed)
    }

    fn crypto_queue_depth(&self) -> usize {
        self.crypto_pending.load(Ordering::Relaxed)
    }

    fn tx_validation_queue_depth(&self) -> usize {
        self.tx_validation_pending.load(Ordering::Relaxed)
    }

    fn execution_queue_depth(&self) -> usize {
        self.execution_pending.load(Ordering::Relaxed)
    }

    fn codec_queue_depth(&self) -> usize {
        self.codec_pending.load(Ordering::Relaxed)
    }

    fn map_execution<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        self.execution_pool.install(|| {
            use rayon::prelude::*;
            items.par_iter().map(f).collect()
        })
    }

    fn map_crypto<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        self.crypto_pool.install(|| {
            use rayon::prelude::*;
            items.par_iter().map(f).collect()
        })
    }
}

/// Pin the current thread to a specific CPU core.
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
    tracing::debug!(
        core = core_id,
        "Core pinning on macOS is best-effort (using affinity hints)"
    );
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
        // 6 cores: pool_budget = max(6-3, 6) = 6, so minimum viable mode
        // 2 consensus_crypto + 1 each for other pools
        let config = ThreadPoolConfig::for_core_count(6);
        assert_eq!(config.consensus_crypto_threads, 2);
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.tx_validation_threads, 1);
        assert_eq!(config.execution_threads, 1);
        assert_eq!(config.codec_threads, 1);
        assert_eq!(config.io_threads, 1);

        // 12 cores: pool_budget = 12 - 3 = 9 (percentage mode)
        // crypto 35% = 3, execution 25% = 2, tx_validation 15% = 1, io 15% = 1, codec = remainder = 2
        let config = ThreadPoolConfig::for_core_count(12);
        assert_eq!(config.consensus_crypto_threads, 2);
        assert_eq!(config.crypto_threads, 3);
        assert_eq!(config.execution_threads, 2);
        assert_eq!(config.tx_validation_threads, 1);
        assert_eq!(config.io_threads, 1);
        assert_eq!(config.codec_threads, 2);

        // 18 cores: pool_budget = 18 - 3 = 15 (percentage mode)
        // crypto 35% = 5, execution 25% = 3, tx_validation 15% = 2, io 15% = 2, codec = remainder = 3
        let config = ThreadPoolConfig::for_core_count(18);
        assert_eq!(config.consensus_crypto_threads, 2);
        assert_eq!(config.crypto_threads, 5);
        assert_eq!(config.execution_threads, 3);
        assert_eq!(config.tx_validation_threads, 2);
        assert_eq!(config.io_threads, 2);
        assert_eq!(config.codec_threads, 3);

        // 32 cores: pool_budget = 32 - 3 = 29 (percentage mode)
        // crypto 35% = 10, execution 25% = 7, tx_validation 15% = 4, io 15% = 4, codec = remainder = 4
        let config = ThreadPoolConfig::for_core_count(32);
        assert_eq!(config.consensus_crypto_threads, 2);
        assert_eq!(config.crypto_threads, 10);
        assert_eq!(config.execution_threads, 7);
        assert_eq!(config.tx_validation_threads, 4);
        assert_eq!(config.io_threads, 4);
        assert_eq!(config.codec_threads, 4);
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
            .consensus_crypto_core_start(1)
            .crypto_core_start(3)
            .execution_core_start(5)
            .io_core_start(9)
            .build_unchecked();

        assert!(config.pin_cores);
        assert_eq!(config.state_machine_core, Some(0));
        assert_eq!(config.consensus_crypto_core_start, Some(1));
        assert_eq!(config.crypto_core_start, Some(3));
        assert_eq!(config.execution_core_start, Some(5));
        assert_eq!(config.io_core_start, Some(9));
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
    fn test_pooled_dispatch_creation() {
        let config = ThreadPoolConfig::minimal();
        let dispatch = PooledDispatch::new(config).unwrap();

        assert_eq!(dispatch.config().consensus_crypto_threads, 1);
        assert_eq!(dispatch.config().crypto_threads, 1);
        assert_eq!(dispatch.config().execution_threads, 1);
        assert_eq!(dispatch.config().codec_threads, 1);
    }

    #[test]
    fn test_spawn_on_pools() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = ThreadPoolConfig::minimal();
        let dispatch = PooledDispatch::new(config).unwrap();

        let consensus_crypto_counter = Arc::new(AtomicUsize::new(0));
        let crypto_counter = Arc::new(AtomicUsize::new(0));
        let tx_validation_counter = Arc::new(AtomicUsize::new(0));
        let exec_counter = Arc::new(AtomicUsize::new(0));
        let codec_counter = Arc::new(AtomicUsize::new(0));

        let counter = consensus_crypto_counter.clone();
        dispatch.spawn_consensus_crypto(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let counter = crypto_counter.clone();
        dispatch.spawn_crypto(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let counter = tx_validation_counter.clone();
        dispatch.spawn_tx_validation(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let counter = exec_counter.clone();
        dispatch.spawn_execution(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let counter = codec_counter.clone();
        dispatch.spawn_codec(move || {
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
