//! Deterministic simulation runner.
//!
//! This crate provides a fully deterministic simulation environment for
//! testing consensus. Given the same seed, it produces identical results
//! every run.

mod event_queue;
mod runner;

pub use runner::membership::JoinKind;
pub use runner::{SimConfig, SimulationRunner};

/// Beacon epoch length the simulations run at.
///
/// Under the `ci` feature the sims use the production 5-minute epoch. The
/// consensus recovery timeouts (`SPC_VIEW_TIMEOUT` = 15s, `SKIP_TIMEOUT` =
/// 45s) are sized as a small fraction of it, so running at the same epoch
/// keeps that ratio real: a skipped view or a stalled SPC instance costs a
/// fraction of an epoch, not several epochs, and the epoch-counted reshape
/// budgets and TTLs behave as they do in production.
#[cfg(feature = "ci")]
pub const EPOCH_MS: u64 = 300_000;

/// Beacon epoch length the simulations run at.
///
/// Without the `ci` feature the epoch shrinks to 30s so local runs finish
/// quickly. The recovery-timeout ratio is no longer production-faithful, so
/// the epoch-counted reshape budgets and TTLs can behave differently than
/// they do in production — run with `--features ci` before trusting those.
#[cfg(not(feature = "ci"))]
pub const EPOCH_MS: u64 = 30_000;
