//! Dispatch trait for scheduling work across priority-isolated pools.
//!
//! This crate defines the [`Dispatch`] trait used by runners to schedule
//! CPU-intensive work (crypto verification, transaction execution, codec).
//!
//! Dispatch is an implementation detail of runners, not the state machine.
//! The state machine emits `Action` variants; runners use a `Dispatch`
//! implementation to schedule the corresponding work:
//!
//! - [`SyncDispatch`](https://docs.rs/hyperscale-dispatch-sync) runs closures inline (deterministic simulation)
//! - [`PooledDispatch`](https://docs.rs/hyperscale-dispatch-pooled) uses rayon thread pools (production)
//!
//! # Pool Categories
//!
//! Work is categorized by priority and isolation requirements:
//!
//! - **Consensus Crypto**: Liveness-critical (block votes, QC verification, state root, proposal building)
//! - **Crypto**: General signature verification (provisions, execution votes, cert aggregation)
//! - **TX Validation**: Transaction signature verification (isolated from crypto)
//! - **Execution**: Radix Engine transaction execution

/// Thread-pool kind hint for [`Dispatch::spawn`]. Production runners use
/// this to pick a dedicated pool; simulation runners ignore it (everything
/// runs inline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchPool {
    /// Liveness-critical consensus crypto (block votes, QC verification,
    /// state root, proposal building).
    ConsensusCrypto,
    /// General crypto verification (provisions, execution votes, cert
    /// aggregation).
    Crypto,
    /// Transaction signature validation. Isolated from general crypto so
    /// transaction floods can't block provision/execution vote
    /// verification.
    TxValidation,
    /// Radix Engine transaction execution.
    Execution,
    /// Network I/O and other non-CPU work. Production routes to the tokio
    /// runtime; simulation runs inline. Use for broadcasts, request sends,
    /// and any path that posts to the network or filesystem.
    Io,
}

/// Parallelism strategy advertised by a [`Dispatch`] backend.
///
/// Threaded through to delegated-action handlers (via `ActionContext`)
/// so they can fan a batch of independent work out across the dispatched
/// pool's workers in production, while still iterating sequentially under
/// the deterministic simulation runner.
///
/// [`Parallelism::map`] is the typical entry point: a parallel-map
/// equivalent to `items.into_par_iter().map(f).collect()` in production
/// and the plain sequential `items.into_iter()...` in simulation. Both
/// preserve input order in the returned `Vec`.
#[derive(Copy, Clone, Debug)]
pub enum Parallelism {
    /// Rayon `par_iter` on the current pool. When called from inside a
    /// closure already running on a rayon pool (the standard case for
    /// delegated-action handlers), work-stealing fans out across that
    /// pool's workers.
    Rayon,
    /// Sequential `iter`, deterministic, runs on the caller's thread.
    /// Used by the simulation runner so thread-local state (metrics
    /// recorders, fault-test ordering) stays intact.
    Sequential,
}

impl Parallelism {
    /// Map `items` to `Vec<R>` using this strategy.
    pub fn map<T, R, F>(self, items: Vec<T>, f: F) -> Vec<R>
    where
        T: Send,
        R: Send,
        F: Fn(T) -> R + Send + Sync,
    {
        use rayon::prelude::*;
        match self {
            Self::Rayon => items.into_par_iter().map(f).collect(),
            Self::Sequential => items.into_iter().map(f).collect(),
        }
    }
}

/// Trait for dispatching CPU-intensive work to priority-isolated pools.
///
/// Implementations schedule fire-and-forget closures on appropriate pools.
/// Results are communicated back via channels captured in the closures.
pub trait Dispatch: Send + Sync + Clone + 'static {
    /// Spawn a task on the pool corresponding to `pool`.
    fn spawn(&self, pool: DispatchPool, f: impl FnOnce() + Send + 'static);

    /// Current queue depth for the given pool.
    fn queue_depth(&self, pool: DispatchPool) -> usize;

    /// Parallelism strategy this backend uses for in-handler fan-out.
    /// Production runners return [`Parallelism::Rayon`]; the simulation
    /// runner returns [`Parallelism::Sequential`].
    fn parallelism(&self) -> Parallelism;
}
