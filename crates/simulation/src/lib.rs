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
mod network;
mod runner;
mod storage;
mod traffic;

pub use network::{NetworkConfig, SimulatedNetwork};
pub use runner::SimulationRunner;
pub use storage::SimStorage;
pub use traffic::{BandwidthReport, NetworkTrafficAnalyzer};

/// Type alias for deterministic node indexing in simulation.
///
/// This is a simulation-only concept for routing between in-process nodes.
/// Production code uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;
