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
//! - **Crypto**: General signature verification (provisions, state votes)
//! - **TX Validation**: Transaction signature verification (isolated from crypto)
//! - **Execution**: Radix Engine transaction execution
//! - **Codec**: SBOR message encoding/decoding

/// Trait for dispatching CPU-intensive work to priority-isolated pools.
///
/// Implementations schedule fire-and-forget closures on appropriate pools.
/// Results are communicated back via channels captured in the closures.
///
/// # Parallelism Guarantee
///
/// Implementations must ensure that `rayon::par_iter()` and similar parallel
/// primitives used inside spawned closures execute on the correct pool (not the
/// global rayon pool). The pooled implementation achieves this by wrapping
/// closures in `rayon::ThreadPool::install()`.
pub trait Dispatch: Send + Sync + Clone {
    /// Spawn a consensus-critical crypto task.
    ///
    /// Use for block vote and QC signature verification. These are liveness-critical
    /// and must not be blocked by general crypto work.
    fn spawn_consensus_crypto(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a general crypto verification task.
    ///
    /// Use for provisions and state votes. Not consensus-critical.
    fn spawn_crypto(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a crypto task with backpressure.
    ///
    /// Returns `true` if spawned, `false` if the pool is overloaded.
    /// Use for non-critical crypto work that can tolerate delays.
    fn try_spawn_crypto(&self, f: impl FnOnce() + Send + 'static) -> bool;

    /// Spawn a transaction validation task.
    ///
    /// Isolated from general crypto to prevent transaction floods from
    /// blocking provision/state vote verification.
    fn spawn_tx_validation(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn an execution task (Radix Engine).
    fn spawn_execution(&self, f: impl FnOnce() + Send + 'static);

    /// Spawn a codec task (SBOR encoding/decoding).
    fn spawn_codec(&self, f: impl FnOnce() + Send + 'static);

    /// Current consensus crypto pool queue depth.
    fn consensus_crypto_queue_depth(&self) -> usize;

    /// Current general crypto pool queue depth.
    fn crypto_queue_depth(&self) -> usize;

    /// Current tx validation pool queue depth.
    fn tx_validation_queue_depth(&self) -> usize;

    /// Current execution pool queue depth.
    fn execution_queue_depth(&self) -> usize;

    /// Current codec pool queue depth.
    fn codec_queue_depth(&self) -> usize;

    /// Map a function over items on the execution pool, potentially in parallel.
    ///
    /// `PooledDispatch` uses `rayon::par_iter` for parallelism.
    /// `SyncDispatch` uses sequential iteration (deterministic).
    ///
    /// This is a **blocking** call — it returns when all items are processed.
    /// In production, call this from within a `spawn_execution` closure (already
    /// off the event loop). In simulation, call inline.
    fn map_execution<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send;

    /// Map a function over items on the crypto pool, potentially in parallel.
    ///
    /// Same semantics as `map_execution` but runs on the crypto pool.
    /// Used for parallelizing pre-processing steps in batch crypto verification.
    fn map_crypto<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send;

    /// Map a function over items on the tx validation pool, potentially in parallel.
    ///
    /// Same semantics as `map_execution` but runs on the tx validation pool.
    /// Used for parallelizing batch transaction signature verification.
    fn map_tx_validation<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send;
}
