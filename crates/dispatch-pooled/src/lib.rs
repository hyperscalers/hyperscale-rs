//! Rayon thread pool dispatch for production deployment.
//!
//! [`PooledDispatch`] runs two rayon pools:
//!
//! - **Consensus** — small dedicated pool for liveness-critical work
//!   (block votes, QC verification, state root, proposal building). Never
//!   blocked by execution batches.
//! - **Throughput** — single shared work-stealing pool for general crypto
//!   verification, transaction signature validation, and VM engine
//!   execution. In-handler `par_iter` fans batches across this pool's
//!   workers.
//!
//! [`DispatchPool::Io`] routes to tokio's blocking pool.
//!
//! # Example
//!
//! ```no_run
//! use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
//!
//! let config = ThreadPoolConfig::builder()
//!     .consensus_threads(2)
//!     .throughput_threads(12)
//!     .build()
//!     .unwrap();
//!
//! // Must be called from inside a tokio runtime; pass the handle explicitly.
//! let dispatch = PooledDispatch::new(config, tokio::runtime::Handle::current()).unwrap();
//! ```

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use core_affinity::{get_core_ids, set_for_current};
use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};
use hyperscale_metrics::record_pool_task_completed;
use rayon::{ThreadPool, ThreadPoolBuilder};
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::instrument;

/// Errors from thread pool configuration.
#[derive(Debug, Error)]
pub enum ThreadPoolError {
    /// Underlying rayon thread-pool builder rejected the configuration.
    #[error("Failed to build rayon thread pool: {0}")]
    RayonBuildError(String),

    /// User-supplied thread counts or core indices were invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// `core_affinity` failed to pin a worker thread to its target core.
    #[error("Core pinning failed: {0}")]
    CorePinningError(String),
}

/// Default stack size for consensus-pool workers (verifies, JMT roots).
const DEFAULT_CONSENSUS_STACK_SIZE: usize = 2 * 1024 * 1024;
/// Default stack size for throughput-pool workers (the VM engine needs more).
const DEFAULT_THROUGHPUT_STACK_SIZE: usize = 8 * 1024 * 1024;

/// Configuration for the two production rayon thread pools.
///
/// The caller computes appropriate thread counts (typically via the
/// validator binary's vnode-aware sizer). I/O thread count is not part of
/// this config — it's a tokio runtime concern owned by the binary.
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Threads in the consensus pool. Liveness-critical work — block
    /// votes, QC verification, state root, proposal building. Kept small
    /// and dedicated so a long execution batch can never queue ahead of
    /// it.
    pub consensus_threads: usize,

    /// Threads in the throughput pool. General crypto verification,
    /// transaction signature validation, and VM engine execution share
    /// this pool; rayon's work-stealing interleaves them automatically and
    /// in-handler `par_iter` calls fan batches across the same workers.
    pub throughput_threads: usize,

    /// Whether to pin threads to specific CPU cores.
    /// Improves cache locality but reduces flexibility.
    pub pin_cores: bool,

    /// Starting core index for the consensus pool (if pinning enabled).
    pub consensus_core_start: Option<usize>,

    /// Starting core index for the throughput pool (if pinning enabled).
    pub throughput_core_start: Option<usize>,

    /// Stack size for consensus pool threads (bytes).
    pub consensus_stack_size: usize,

    /// Stack size for throughput pool threads (bytes). The VM engine
    /// execution lives here, so this is sized larger than the consensus
    /// pool's stack.
    pub throughput_stack_size: usize,
}

impl ThreadPoolConfig {
    /// Create a builder for custom configuration.
    #[must_use]
    pub const fn builder() -> ThreadPoolConfigBuilder {
        ThreadPoolConfigBuilder::new()
    }

    /// Minimal configuration for tests (2 consensus + 2 throughput).
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            consensus_threads: 2,
            throughput_threads: 2,
            pin_cores: false,
            consensus_core_start: None,
            throughput_core_start: None,
            consensus_stack_size: DEFAULT_CONSENSUS_STACK_SIZE,
            throughput_stack_size: DEFAULT_THROUGHPUT_STACK_SIZE,
        }
    }

    /// Total number of rayon pool threads (excluding state machine and I/O).
    #[must_use]
    pub const fn total_threads(&self) -> usize {
        self.consensus_threads + self.throughput_threads
    }

    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ThreadPoolError::InvalidConfig`] when either pool's thread
    /// count is below its minimum (consensus ≥ 2, throughput ≥ 1) or when
    /// core pinning is enabled but the configured pools exceed
    /// `available_parallelism()`.
    pub fn validate(&self) -> Result<(), ThreadPoolError> {
        if self.consensus_threads < 2 {
            return Err(ThreadPoolError::InvalidConfig(
                "consensus_threads must be at least 2 (verify + build concurrently)".to_string(),
            ));
        }
        if self.throughput_threads == 0 {
            return Err(ThreadPoolError::InvalidConfig(
                "throughput_threads must be at least 1".to_string(),
            ));
        }

        if self.pin_cores {
            let available = std::thread::available_parallelism().map_or(4, NonZeroUsize::get);
            let total_needed = self.consensus_threads + self.throughput_threads;
            if total_needed > available {
                return Err(ThreadPoolError::InvalidConfig(format!(
                    "Configuration requires {total_needed} cores but only {available} are available"
                )));
            }
        }

        Ok(())
    }
}

/// Builder for [`ThreadPoolConfig`].
#[derive(Debug, Clone)]
pub struct ThreadPoolConfigBuilder {
    config: ThreadPoolConfig,
}

impl ThreadPoolConfigBuilder {
    /// Create a new builder starting from minimal defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: ThreadPoolConfig::minimal(),
        }
    }

    /// Set the number of consensus-pool threads.
    #[must_use]
    pub const fn consensus_threads(mut self, count: usize) -> Self {
        self.config.consensus_threads = count;
        self
    }

    /// Set the number of throughput-pool threads.
    #[must_use]
    pub const fn throughput_threads(mut self, count: usize) -> Self {
        self.config.throughput_threads = count;
        self
    }

    /// Enable core pinning.
    #[must_use]
    pub const fn pin_cores(mut self, enabled: bool) -> Self {
        self.config.pin_cores = enabled;
        self
    }

    /// Set the starting core for the consensus pool.
    #[must_use]
    pub const fn consensus_core_start(mut self, core: usize) -> Self {
        self.config.consensus_core_start = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set the starting core for the throughput pool.
    #[must_use]
    pub const fn throughput_core_start(mut self, core: usize) -> Self {
        self.config.throughput_core_start = Some(core);
        self.config.pin_cores = true;
        self
    }

    /// Set stack size for consensus pool threads.
    #[must_use]
    pub const fn consensus_stack_size(mut self, size: usize) -> Self {
        self.config.consensus_stack_size = size;
        self
    }

    /// Set stack size for throughput pool threads.
    #[must_use]
    pub const fn throughput_stack_size(mut self, size: usize) -> Self {
        self.config.throughput_stack_size = size;
        self
    }

    /// Build the configuration, validating it first.
    ///
    /// # Errors
    ///
    /// Forwards any [`ThreadPoolError`] returned by [`ThreadPoolConfig::validate`].
    pub fn build(self) -> Result<ThreadPoolConfig, ThreadPoolError> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// Build the configuration without validation.
    #[must_use]
    pub const fn build_unchecked(self) -> ThreadPoolConfig {
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
/// Two rayon pools (consensus + throughput) plus a tokio handle for I/O.
/// Spawned closures are automatically wrapped in `rayon::ThreadPool::install()`,
/// ensuring `par_iter` and other parallel primitives use the correct pool.
#[derive(Clone)]
pub struct PooledDispatch {
    config: ThreadPoolConfig,
    consensus_pool: Arc<ThreadPool>,
    throughput_pool: Arc<ThreadPool>,
    /// Tokio handle for [`DispatchPool::Io`] tasks. Captured at construction
    /// time, so [`PooledDispatch::new`] must be called from inside a tokio
    /// runtime context.
    tokio_handle: Handle,
    consensus_pending: Arc<AtomicUsize>,
    throughput_pending: Arc<AtomicUsize>,
    io_pending: Arc<AtomicUsize>,
}

impl PooledDispatch {
    /// Create a new pooled dispatch with the given configuration.
    ///
    /// `tokio_handle` is used to route [`DispatchPool::Io`] tasks. Pass
    /// [`Handle::current`] from inside a runtime, or a handle
    /// from a runtime constructed by the caller.
    ///
    /// # Errors
    ///
    /// Returns a [`ThreadPoolError`] when validation fails or when either
    /// underlying rayon thread pool cannot be built.
    pub fn new(config: ThreadPoolConfig, tokio_handle: Handle) -> Result<Self, ThreadPoolError> {
        config.validate()?;

        let consensus_pool = Arc::new(Self::build_consensus_pool(&config)?);
        let throughput_pool = Arc::new(Self::build_throughput_pool(&config)?);

        tracing::info!(
            consensus_threads = config.consensus_threads,
            throughput_threads = config.throughput_threads,
            pin_cores = config.pin_cores,
            "Thread pools initialized"
        );

        Ok(Self {
            config,
            consensus_pool,
            throughput_pool,
            tokio_handle,
            consensus_pending: Arc::new(AtomicUsize::new(0)),
            throughput_pending: Arc::new(AtomicUsize::new(0)),
            io_pending: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &ThreadPoolConfig {
        &self.config
    }

    fn build_consensus_pool(config: &ThreadPoolConfig) -> Result<ThreadPool, ThreadPoolError> {
        let mut builder = ThreadPoolBuilder::new()
            .num_threads(config.consensus_threads)
            .stack_size(config.consensus_stack_size)
            .thread_name(|i| format!("consensus-{i}"));

        if config.pin_cores {
            let start_core = config.consensus_core_start.unwrap_or(1);
            builder = builder.start_handler(move |i| {
                let core_id = start_core + i;
                if let Err(e) = pin_thread_to_core(core_id) {
                    tracing::warn!(core = core_id, error = ?e, "Failed to pin consensus thread");
                } else {
                    tracing::debug!(core = core_id, thread = i, "Pinned consensus thread");
                }
            });
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }

    fn build_throughput_pool(config: &ThreadPoolConfig) -> Result<ThreadPool, ThreadPoolError> {
        let mut builder = ThreadPoolBuilder::new()
            .num_threads(config.throughput_threads)
            .stack_size(config.throughput_stack_size)
            .thread_name(|i| format!("throughput-{i}"));

        if config.pin_cores {
            let start_core = config
                .throughput_core_start
                .unwrap_or(1 + config.consensus_threads);
            builder = builder.start_handler(move |i| {
                let core_id = start_core + i;
                if let Err(e) = pin_thread_to_core(core_id) {
                    tracing::warn!(core = core_id, error = ?e, "Failed to pin throughput thread");
                } else {
                    tracing::debug!(core = core_id, thread = i, "Pinned throughput thread");
                }
            });
        }

        builder
            .build()
            .map_err(|e| ThreadPoolError::RayonBuildError(e.to_string()))
    }
}

impl PooledDispatch {
    /// Rayon pool + pending counter + metric label for CPU pools.
    /// Returns `None` for [`DispatchPool::Io`] which routes to tokio.
    const fn rayon_pool_state(
        &self,
        pool: DispatchPool,
    ) -> Option<(&Arc<ThreadPool>, &Arc<AtomicUsize>, &'static str)> {
        match pool {
            DispatchPool::Consensus => {
                Some((&self.consensus_pool, &self.consensus_pending, "consensus"))
            }
            DispatchPool::Throughput => Some((
                &self.throughput_pool,
                &self.throughput_pending,
                "throughput",
            )),
            DispatchPool::Io => None,
        }
    }

    const fn pending_counter(&self, pool: DispatchPool) -> &Arc<AtomicUsize> {
        match pool {
            DispatchPool::Consensus => &self.consensus_pending,
            DispatchPool::Throughput => &self.throughput_pending,
            DispatchPool::Io => &self.io_pending,
        }
    }
}

impl Dispatch for PooledDispatch {
    #[instrument(level = "debug", skip_all, fields(?pool))]
    fn spawn(&self, pool: DispatchPool, f: impl FnOnce() + Send + 'static) {
        if let Some((rayon_pool, pending, label)) = self.rayon_pool_state(pool) {
            pending.fetch_add(1, Ordering::Relaxed);
            let pending = pending.clone();
            let rayon_pool_owned = Arc::clone(rayon_pool);
            rayon_pool.spawn_fifo(move || {
                let start = std::time::Instant::now();
                rayon_pool_owned.install(f);
                pending.fetch_sub(1, Ordering::Relaxed);
                record_pool_task_completed(label, start.elapsed().as_secs_f64());
            });
        } else {
            // DispatchPool::Io — route to tokio's blocking pool. Sized for
            // work that doesn't yield (fsync, network sends behind sync
            // libp2p adapters, GC). Non-blocking ops tolerate it fine; the
            // blocking pool just runs them straight through.
            let pending = Arc::clone(&self.io_pending);
            pending.fetch_add(1, Ordering::Relaxed);
            self.tokio_handle.spawn_blocking(move || {
                let start = std::time::Instant::now();
                f();
                pending.fetch_sub(1, Ordering::Relaxed);
                record_pool_task_completed("io", start.elapsed().as_secs_f64());
            });
        }
    }

    fn queue_depth(&self, pool: DispatchPool) -> usize {
        self.pending_counter(pool).load(Ordering::Relaxed)
    }

    fn parallelism(&self) -> Parallelism {
        Parallelism::Rayon
    }
}

/// Pin the current thread to a specific CPU core.
///
/// Uses `core_affinity` which validates the core ID against the set of
/// available cores, avoiding out-of-bounds issues with raw libc calls.
fn pin_thread_to_core(core_id: usize) -> Result<(), ThreadPoolError> {
    let core_ids = get_core_ids().ok_or_else(|| {
        ThreadPoolError::CorePinningError("failed to enumerate CPU cores".to_string())
    })?;

    let target = core_ids
        .into_iter()
        .find(|c| c.id == core_id)
        .ok_or_else(|| {
            ThreadPoolError::CorePinningError(format!("core {core_id} not in available core set"))
        })?;

    if set_for_current(target) {
        Ok(())
    } else {
        Err(ThreadPoolError::CorePinningError(format!(
            "set_for_current failed for core {core_id}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    #[test]
    fn test_minimal_config() {
        let config = ThreadPoolConfig::minimal();
        assert_eq!(config.consensus_threads, 2);
        assert_eq!(config.throughput_threads, 2);
        config.validate().unwrap();
    }

    #[test]
    fn test_builder() {
        let config = ThreadPoolConfig::builder()
            .consensus_threads(2)
            .throughput_threads(12)
            .build()
            .unwrap();

        assert_eq!(config.consensus_threads, 2);
        assert_eq!(config.throughput_threads, 12);
    }

    #[test]
    fn test_builder_with_pinning() {
        let config = ThreadPoolConfig::builder()
            .consensus_threads(2)
            .throughput_threads(4)
            .consensus_core_start(1)
            .throughput_core_start(3)
            .build_unchecked();

        assert!(config.pin_cores);
        assert_eq!(config.consensus_core_start, Some(1));
        assert_eq!(config.throughput_core_start, Some(3));
    }

    #[test]
    fn test_invalid_config() {
        let result = ThreadPoolConfig::builder().consensus_threads(1).build();
        assert!(result.is_err());

        let result = ThreadPoolConfig::builder().throughput_threads(0).build();
        assert!(result.is_err());
    }

    fn test_runtime() -> Runtime {
        Builder::new_current_thread().build().unwrap()
    }

    #[test]
    fn test_pooled_dispatch_creation() {
        let rt = test_runtime();
        let config = ThreadPoolConfig::minimal();
        let dispatch = PooledDispatch::new(config, rt.handle().clone()).unwrap();

        assert_eq!(dispatch.config().consensus_threads, 2);
        assert_eq!(dispatch.config().throughput_threads, 2);
    }

    #[test]
    fn test_spawn_on_pools() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let rt = test_runtime();
        let config = ThreadPoolConfig::minimal();
        let dispatch = PooledDispatch::new(config, rt.handle().clone()).unwrap();

        let consensus_counter = Arc::new(AtomicUsize::new(0));
        let throughput_counter = Arc::new(AtomicUsize::new(0));

        let counter = consensus_counter.clone();
        dispatch.spawn(DispatchPool::Consensus, move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let counter = throughput_counter.clone();
        dispatch.spawn(DispatchPool::Throughput, move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // Wait for tasks to complete
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert_eq!(consensus_counter.load(Ordering::SeqCst), 1);
        assert_eq!(throughput_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_total_threads() {
        let config = ThreadPoolConfig::builder()
            .consensus_threads(2)
            .throughput_threads(12)
            .build_unchecked();

        assert_eq!(config.total_threads(), 14);
    }
}
