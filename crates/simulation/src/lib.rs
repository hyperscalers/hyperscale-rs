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
