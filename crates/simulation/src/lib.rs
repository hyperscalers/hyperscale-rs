//! Deterministic simulation runner.
//!
//! This crate provides a fully deterministic simulation environment for
//! testing consensus. Given the same seed, it produces identical results
//! every run.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                  SimulationRunner                       │
//! │                                                         │
//! │  ┌────────────────────────────────────────────────────┐ │
//! │  │     Event Queue (BTreeMap<EventKey, Event>)        │ │
//! │  │     Ordered by: time, priority, node, sequence     │ │
//! │  └────────────────────────┬───────────────────────────┘ │
//! │                           │                             │
//! │                           ▼                             │
//! │  ┌────────────────────────────────────────────────────┐ │
//! │  │     nodes: Vec<NodeStateMachine>                   │ │
//! │  │     Each processes events sequentially             │ │
//! │  └────────────────────────┬───────────────────────────┘ │
//! │                           │                             │
//! │                           ▼                             │
//! │  ┌────────────────────────────────────────────────────┐ │
//! │  │     Actions → schedule new events                  │ │
//! │  └────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────┘
//! ```

mod event_queue;
mod runner;

pub use runner::SimulationRunner;
pub use runner::relocation::JoinKind;

/// Beacon epoch length every simulation runs at — production parity.
///
/// The production beacon paces at a 5-minute epoch, and the consensus
/// recovery timeouts (`SPC_VIEW_TIMEOUT` = 15s, `SKIP_TIMEOUT` = 45s) are
/// sized as a small fraction of it. Running the sims at the same epoch
/// keeps that ratio real: a skipped view or a stalled SPC instance costs a
/// fraction of an epoch, not several epochs, so the epoch-counted reshape
/// budgets and TTLs behave as they do in production.
pub const EPOCH_MS: u64 = 300_000;
