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

/// Trait for dispatching CPU-intensive work to priority-isolated pools.
///
/// Implementations schedule fire-and-forget closures on appropriate pools.
/// Results are communicated back via channels captured in the closures.
pub trait Dispatch: Send + Sync + Clone + 'static {
    /// Spawn a task on the pool corresponding to `pool`.
    fn spawn(&self, pool: DispatchPool, f: impl FnOnce() + Send + 'static);

    /// Current queue depth for the given pool.
    fn queue_depth(&self, pool: DispatchPool) -> usize;
}
