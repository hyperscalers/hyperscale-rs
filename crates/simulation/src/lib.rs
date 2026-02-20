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

pub use hyperscale_network_memory::{
    BandwidthReport, NetworkConfig, NetworkTrafficAnalyzer, SimulatedNetwork,
};
pub use hyperscale_node::TimerOp;
pub use hyperscale_storage_memory::SimStorage;
pub use runner::SimulationRunner;

// Re-export NodeIndex from network-memory (canonical definition).
pub use hyperscale_network_memory::NodeIndex;
