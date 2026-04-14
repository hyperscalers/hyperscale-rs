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
//! - **Consensus Crypto**: Liveness-critical (block votes, QC verification)
//! - **Crypto**: General signature verification (provisions, execution votes)
//! - **TX Validation**: Transaction signature verification (isolated from crypto)
//! - **Execution**: Radix Engine transaction execution

/// Trait for dispatching CPU-intensive work to priority-isolated pools.
///
/// Implementations schedule fire-and-forget closures on appropriate pools.
/// Results are communicated back via channels captured in the closures.
pub trait Dispatch: Send + Sync + Clone + 'static {
    /// Spawn a consensus-critical crypto task.
    ///
    /// Use for block vote and QC signature verification. These are liveness-critical
    /// and must not be blocked by general crypto work.
    fn spawn_consensus_crypto(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a general crypto verification task.
    ///
    /// Use for provisions and execution votes. Not consensus-critical.
    fn spawn_crypto(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a crypto task with backpressure.
    ///
    /// Returns `true` if spawned, `false` if the pool is overloaded.
    /// Use for non-critical crypto work that can tolerate delays.
    fn try_spawn_crypto(&self, f: impl FnOnce() + Send + 'static) -> bool;

    /// Spawn a transaction validation task.
    ///
    /// Isolated from general crypto to prevent transaction floods from
    /// blocking provision/execution vote verification.
    fn spawn_tx_validation(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn an execution task (Radix Engine).
    fn spawn_execution(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a provision task (IPA proof generation/verification).
    ///
    /// Isolated from execution to prevent transaction floods from starving
    /// time-sensitive provision proof generation.
    fn spawn_provisions(&self, f: impl FnOnce() + Send + 'static);

    /// Current consensus crypto pool queue depth.
    fn consensus_crypto_queue_depth(&self) -> usize;

    /// Current general crypto pool queue depth.
    fn crypto_queue_depth(&self) -> usize;

    /// Current tx validation pool queue depth.
    fn tx_validation_queue_depth(&self) -> usize;

    /// Current execution pool queue depth.
    fn execution_queue_depth(&self) -> usize;

    /// Current provisions pool queue depth.
    fn provisions_queue_depth(&self) -> usize;
}
