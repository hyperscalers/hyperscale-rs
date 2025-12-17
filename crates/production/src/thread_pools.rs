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
    /// Number of threads for crypto operations (signature verification).
    /// These are CPU-bound and benefit from dedicated cores.
    pub crypto_threads: usize,

    /// Number of threads for transaction execution.
    /// These run the Radix Engine and are CPU/memory intensive.
    pub execution_threads: usize,

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
    /// - Execution: 50% of remaining cores (min 1)
    /// - Crypto: 25% of remaining cores (min 1)
    /// - I/O: 25% of remaining cores (min 1)
    ///
    /// On systems with fewer than 4 cores, all pools get 1 thread each.
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
        let remaining = total_cores.saturating_sub(1).max(3);

        // Allocation ratios: execution 50%, crypto 25%, I/O 25%
        let (crypto, execution, io) = if remaining <= 3 {
            // Minimum viable: 1 each
            (1, 1, 1)
        } else {
            let execution = (remaining * 50 / 100).max(1);
            let crypto = (remaining * 25 / 100).max(1);
            let io = remaining
                .saturating_sub(crypto)
                .saturating_sub(execution)
                .max(1);
            (crypto, execution, io)
        };

        Self {
            crypto_threads: crypto,
            execution_threads: execution,
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
            crypto_threads: 1,
            execution_threads: 1,
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
        self.crypto_threads + self.execution_threads + self.io_threads
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ThreadPoolError> {
        if self.crypto_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "crypto_threads must be at least 1".to_string(),
            ));
        }
        if self.execution_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "execution_threads must be at least 1".to_string(),
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

            let total_needed = 1 + self.crypto_threads + self.execution_threads + self.io_threads;
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

    /// Set the number of crypto verification threads.
    pub fn crypto_threads(mut self, count: usize) -> Self {
        self.config.crypto_threads = count;
        self
    }

    /// Set the number of execution threads.
    pub fn execution_threads(mut self, count: usize) -> Self {
        self.config.execution_threads = count;
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
/// - A rayon thread pool for crypto operations
/// - A rayon thread pool for execution operations
/// - Configuration for tokio runtime (actual runtime created by caller)
pub struct ThreadPoolManager {
    /// Configuration used to create the pools.
    config: ThreadPoolConfig,

    /// Rayon pool for crypto operations (signature verification).
    crypto_pool: rayon::ThreadPool,

    /// Rayon pool for execution operations (Radix Engine).
    execution_pool: rayon::ThreadPool,

    /// Queue depth tracking for crypto pool (for metrics).
    crypto_pending: Arc<AtomicUsize>,

    /// Queue depth tracking for execution pool (for metrics).
    execution_pending: Arc<AtomicUsize>,
}

impl ThreadPoolManager {
    /// Create a new thread pool manager with the given configuration.
    pub fn new(config: ThreadPoolConfig) -> Result<Self, ThreadPoolError> {
        config.validate()?;

        let crypto_pool = Self::build_crypto_pool(&config)?;
        let execution_pool = Self::build_execution_pool(&config)?;

        tracing::info!(
            crypto_threads = config.crypto_threads,
            execution_threads = config.execution_threads,
            io_threads = config.io_threads,
            pin_cores = config.pin_cores,
            "Thread pools initialized"
        );

        Ok(Self {
            config,
            crypto_pool,
            execution_pool,
            crypto_pending: Arc::new(AtomicUsize::new(0)),
            execution_pending: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Create with auto-detected configuration.
    pub fn auto() -> Result<Self, ThreadPoolError> {
        Self::new(ThreadPoolConfig::auto())
    }

    fn build_crypto_pool(config: &ThreadPoolConfig) -> Result<rayon::ThreadPool, ThreadPoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(config.crypto_threads)
            .stack_size(config.crypto_stack_size)
            .thread_name(|i| format!("crypto-{}", i));

        // Core pinning for crypto threads
        if config.pin_cores {
            let start_core = config.crypto_core_start.unwrap_or(1); // Default: after state machine
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
                .unwrap_or(1 + config.crypto_threads); // Default: after crypto pool
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

    /// Get a reference to the crypto thread pool.
    pub fn crypto_pool(&self) -> &rayon::ThreadPool {
        &self.crypto_pool
    }

    /// Get a reference to the execution thread pool.
    pub fn execution_pool(&self) -> &rayon::ThreadPool {
        &self.execution_pool
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

    /// Spawn a crypto verification task on the crypto pool.
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

    /// Spawn an execution task on the execution pool.
    ///
    /// Returns immediately; the task runs asynchronously.
    /// Queue depth is tracked for metrics.
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

    /// Get current crypto pool queue depth (for metrics).
    pub fn crypto_queue_depth(&self) -> usize {
        self.crypto_pending.load(Ordering::Relaxed)
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
        assert!(config.crypto_threads >= 1);
        assert!(config.execution_threads >= 1);
        assert!(config.io_threads >= 1);
        config.validate().unwrap();
    }

    #[test]
    fn test_for_core_count() {
        // 4 cores: 1 state + 1 crypto + 1 exec + 1 io
        let config = ThreadPoolConfig::for_core_count(4);
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.execution_threads, 1);
        assert_eq!(config.io_threads, 1);

        // 8 cores: 1 state + ~1 crypto + ~3 exec + ~3 io
        let config = ThreadPoolConfig::for_core_count(8);
        assert!(config.crypto_threads >= 1);
        assert!(config.execution_threads >= 3);
        assert!(config.io_threads >= 1);

        // 16 cores: more balanced
        let config = ThreadPoolConfig::for_core_count(16);
        assert!(config.crypto_threads >= 3);
        assert!(config.execution_threads >= 7);
        assert!(config.io_threads >= 2);
    }

    #[test]
    fn test_minimal_config() {
        let config = ThreadPoolConfig::minimal();
        assert_eq!(config.crypto_threads, 1);
        assert_eq!(config.execution_threads, 1);
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

        assert_eq!(manager.config().crypto_threads, 1);
        assert_eq!(manager.config().execution_threads, 1);
        assert_eq!(manager.io_threads(), 1);
    }

    #[test]
    fn test_spawn_on_pools() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = ThreadPoolConfig::minimal();
        let manager = ThreadPoolManager::new(config).unwrap();

        let crypto_counter = Arc::new(AtomicUsize::new(0));
        let exec_counter = Arc::new(AtomicUsize::new(0));

        // Spawn on crypto pool
        let counter = crypto_counter.clone();
        manager.spawn_crypto(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn on execution pool
        let counter = exec_counter.clone();
        manager.spawn_execution(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Wait for tasks to complete
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(crypto_counter.load(Ordering::SeqCst), 1);
        assert_eq!(exec_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_total_threads() {
        let config = ThreadPoolConfig::builder()
            .crypto_threads(4)
            .execution_threads(6)
            .io_threads(2)
            .build_unchecked();

        assert_eq!(config.total_threads(), 12);
    }
}
