//! Deterministic simulation runner.
//!
//! This crate provides a fully deterministic simulation environment for
//! testing consensus. Given the same seed, it produces identical results
//! every run.

mod event_queue;
mod memo_verifier;
mod runner;

// The delivery log's types appear in `SimulationRunner`'s signature, so a
// caller that reads it needs them without also depending on the transport.
pub use hyperscale_engine::ExecutionMode;
pub use hyperscale_network_memory::{ClassTally, DeliveryDrain, DeliveryRecord, NodeIndex};
pub use runner::membership::JoinKind;
pub use runner::{CryptoScheme, SimConfig, SimulationRunner};

/// Beacon epoch length the simulations run at.
///
/// Under the `production-epochs` feature the sims use the production 5-minute
/// epoch. The consensus recovery timeouts (`SPC_VIEW_TIMEOUT` = 15s,
/// `SKIP_TIMEOUT` = 45s) are sized as a small fraction of it, so running at
/// the same epoch keeps that ratio real: a skipped view or a stalled SPC
/// instance costs a fraction of an epoch, not several epochs, and the
/// epoch-counted reshape budgets and TTLs behave as they do in production.
#[cfg(feature = "production-epochs")]
pub const EPOCH_MS: u64 = 300_000;

/// Beacon epoch length the simulations run at.
///
/// Without the `production-epochs` feature the epoch shrinks to 30s so local
/// runs finish quickly. The recovery-timeout ratio is no longer
/// production-faithful, so the epoch-counted reshape budgets and TTLs can
/// behave differently than they do in production — run with
/// `--features production-epochs` before trusting those.
#[cfg(not(feature = "production-epochs"))]
pub const EPOCH_MS: u64 = 30_000;
