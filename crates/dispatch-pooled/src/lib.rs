//! Rayon thread pool dispatch for production deployment.
//!
//! This module provides [`PooledDispatch`] which schedules work across
//! priority-isolated rayon thread pools:
//!
//! - **Consensus Crypto**: Liveness-critical (block votes, QC verification)
//! - **Crypto**: General signature verification (provisions, execution votes)
//! - **TX Validation**: Transaction signature verification (isolated from crypto)
//! - **Execution**: Radix Engine transaction execution
//!
//! # Example
//!
//! ```no_run
//! use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
//!
//! let config = ThreadPoolConfig::builder()
//!     .consensus_crypto_threads(2)
//!     .crypto_threads(4)
//!     .execution_threads(6)
//!     .tx_validation_threads(2)
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

/// Configuration for production rayon thread pools.
///
/// Specifies how many threads are allocated to each rayon pool.
/// All thread counts are mandatory — the caller is responsible for
/// computing appropriate values (e.g. based on available cores).
///
/// This config does **not** include I/O (tokio) thread counts — those are
/// a runtime concern owned by the binary that constructs the tokio runtime.
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Number of threads for consensus-critical crypto operations (block votes, QC verification).
    /// This is a dedicated high-priority pool that is never blocked by execution-layer
    /// crypto work (provisions, execution votes). Keeping this pool responsive is critical
    /// for consensus liveness - block vote verification delays cause view changes.
    pub consensus_crypto_threads: usize,

    /// Number of threads for general crypto operations (provisions, execution votes).
    /// These are CPU-bound but not consensus-critical. They can queue without affecting liveness.
    pub crypto_threads: usize,

    /// Number of threads for transaction signature validation.
    /// This is a dedicated pool to prevent transaction floods from blocking
    /// provision/execution vote verification which are needed for execution progress.
    pub tx_validation_threads: usize,

    /// Number of threads for transaction execution.
    /// These run the Radix Engine and are CPU/memory intensive.
    pub execution_threads: usize,

    /// Whether to pin threads to specific CPU cores.
    /// Improves cache locality but reduces flexibility.
    pub pin_cores: bool,

    /// Starting core index for consensus crypto pool (if pinning enabled).
    pub consensus_crypto_core_start: Option<usize>,

    /// Starting core index for crypto pool (if pinning enabled).
    pub crypto_core_start: Option<usize>,

    /// Starting core index for execution pool (if pinning enabled).
    pub execution_core_start: Option<usize>,

    /// Core index for the state machine thread (if pinning enabled).
    /// The state machine always runs on a single thread.
    pub state_machine_core: Option<usize>,

    /// Stack size for crypto threads (bytes). Default: 2MB.
    pub crypto_stack_size: usize,

    /// Stack size for execution threads (bytes). Default: 8MB (Radix Engine needs more).
    pub execution_stack_size: usize,
}

impl ThreadPoolConfig {
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
            pin_cores: false,
            consensus_crypto_core_start: None,
            crypto_core_start: None,
            execution_core_start: None,
            state_machine_core: None,
            crypto_stack_size: 2 * 1024 * 1024,
            execution_stack_size: 8 * 1024 * 1024,
        }
    }

    /// Total number of rayon pool threads (excluding state machine and I/O).
    pub fn total_threads(&self) -> usize {
        self.consensus_crypto_threads
            + self.crypto_threads
            + self.tx_validation_threads
            + self.execution_threads
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

        // If pinning is enabled, check that core assignments don't overlap
        if self.pin_cores {
            let available = std::thread::available_parallelism()
                .map(NonZeroUsize::get)
                .unwrap_or(4);

            // +1 for the state machine thread
            let total_needed = 1
                + self.consensus_crypto_threads
                + self.crypto_threads
                + self.tx_validation_threads
                + self.execution_threads;
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
    /// Create a new builder starting from minimal defaults (1 thread per pool).
    pub fn new() -> Self {
        Self {
            config: ThreadPoolConfig::minimal(),
        }
    }

    /// Set the number of consensus crypto threads (block votes, QC verification).
    /// These are liveness-critical and should not be set too low.
    pub fn consensus_crypto_threads(mut self, count: usize) -> Self {
        self.config.consensus_crypto_threads = count;
        self
    }

    /// Set the number of general crypto verification threads (provisions, execution votes).
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
/// - General crypto pool (provisions, execution votes)
/// - TX validation pool (transaction signatures) — isolated from crypto
/// - Execution pool (Radix Engine)
///
/// Spawned closures are automatically wrapped in `rayon::ThreadPool::install()`,
/// ensuring that `par_iter` and other parallel primitives use the correct pool.
#[derive(Clone)]
pub struct PooledDispatch {
    config: ThreadPoolConfig,
    consensus_crypto_pool: Arc<rayon::ThreadPool>,
    crypto_pool: Arc<rayon::ThreadPool>,
    tx_validation_pool: Arc<rayon::ThreadPool>,
    execution_pool: Arc<rayon::ThreadPool>,
    consensus_crypto_pending: Arc<AtomicUsize>,
    crypto_pending: Arc<AtomicUsize>,
    tx_validation_pending: Arc<AtomicUsize>,
    execution_pending: Arc<AtomicUsize>,
}

impl PooledDispatch {
    /// Create a new pooled dispatch with the given configuration.
    pub fn new(config: ThreadPoolConfig) -> Result<Self, ThreadPoolError> {
        config.validate()?;

        let consensus_crypto_pool = Arc::new(Self::build_consensus_crypto_pool(&config)?);
        let crypto_pool = Arc::new(Self::build_crypto_pool(&config)?);
        let tx_validation_pool = Arc::new(Self::build_tx_validation_pool(&config)?);
        let execution_pool = Arc::new(Self::build_execution_pool(&config)?);

        tracing::info!(
            consensus_crypto_threads = config.consensus_crypto_threads,
            crypto_threads = config.crypto_threads,
            tx_validation_threads = config.tx_validation_threads,
            execution_threads = config.execution_threads,
            pin_cores = config.pin_cores,
            "Thread pools initialized"
        );

        Ok(Self {
            config,
            consensus_crypto_pool,
            crypto_pool,
            tx_validation_pool,
            execution_pool,
            consensus_crypto_pending: Arc::new(AtomicUsize::new(0)),
            crypto_pending: Arc::new(AtomicUsize::new(0)),
            tx_validation_pending: Arc::new(AtomicUsize::new(0)),
            execution_pending: Arc::new(AtomicUsize::new(0)),
        })
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

    fn map_tx_validation<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        self.tx_validation_pool.install(|| {
            use rayon::prelude::*;
            items.par_iter().map(f).collect()
        })
    }
}

/// Pin the current thread to a specific CPU core.
///
/// Uses `core_affinity` which validates the core ID against the set of
/// available cores, avoiding out-of-bounds issues with raw libc calls.
fn pin_thread_to_core(core_id: usize) -> Result<(), ThreadPoolError> {
    let core_ids = core_affinity::get_core_ids().ok_or_else(|| {
        ThreadPoolError::CorePinningError("failed to enumerate CPU cores".to_string())
    })?;

    let target = core_ids
        .into_iter()
        .find(|c| c.id == core_id)
        .ok_or_else(|| {
            ThreadPoolError::CorePinningError(format!("core {} not in available core set", core_id))
        })?;

    if core_affinity::set_for_current(target) {
        Ok(())
    } else {
        Err(ThreadPoolError::CorePinningError(format!(
            "set_for_current failed for core {}",
            core_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config() {
        let config = ThreadPoolConfig::minimal();
        assert_eq!(config.consensus_crypto_threads, 1);
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.tx_validation_threads, 1);
        assert_eq!(config.execution_threads, 1);
        config.validate().unwrap();
    }

    #[test]
    fn test_builder() {
        let config = ThreadPoolConfig::builder()
            .crypto_threads(4)
            .execution_threads(8)
            .build()
            .unwrap();

        assert_eq!(config.crypto_threads, 4);
        assert_eq!(config.execution_threads, 8);
    }

    #[test]
    fn test_builder_with_pinning() {
        let config = ThreadPoolConfig::builder()
            .crypto_threads(2)
            .execution_threads(4)
            .state_machine_core(0)
            .consensus_crypto_core_start(1)
            .crypto_core_start(3)
            .execution_core_start(5)
            .build_unchecked();

        assert!(config.pin_cores);
        assert_eq!(config.state_machine_core, Some(0));
        assert_eq!(config.consensus_crypto_core_start, Some(1));
        assert_eq!(config.crypto_core_start, Some(3));
        assert_eq!(config.execution_core_start, Some(5));
    }

    #[test]
    fn test_invalid_config() {
        let result = ThreadPoolConfig::builder().crypto_threads(0).build();
        assert!(result.is_err());

        let result = ThreadPoolConfig::builder().execution_threads(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_pooled_dispatch_creation() {
        let config = ThreadPoolConfig::minimal();
        let dispatch = PooledDispatch::new(config).unwrap();

        assert_eq!(dispatch.config().consensus_crypto_threads, 1);
        assert_eq!(dispatch.config().crypto_threads, 1);
        assert_eq!(dispatch.config().execution_threads, 1);
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

        // Wait for tasks to complete
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(consensus_crypto_counter.load(Ordering::SeqCst), 1);
        assert_eq!(crypto_counter.load(Ordering::SeqCst), 1);
        assert_eq!(tx_validation_counter.load(Ordering::SeqCst), 1);
        assert_eq!(exec_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_total_threads() {
        let config = ThreadPoolConfig::builder()
            .consensus_crypto_threads(2)
            .crypto_threads(4)
            .tx_validation_threads(3)
            .execution_threads(6)
            .build_unchecked();

        assert_eq!(config.total_threads(), 15); // 2 + 4 + 3 + 6
    }
}
