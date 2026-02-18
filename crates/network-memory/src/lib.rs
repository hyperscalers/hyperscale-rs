//! Deterministic in-memory network transport for simulation.
//!
//! Provides [`SimulatedNetwork`] with configurable latency, packet loss,
//! and network partitions, all driven by a seeded RNG for reproducibility.
//!
//! [`NetworkTrafficAnalyzer`] tracks per-message-type and per-node bandwidth
//! statistics for real-world deployment estimates.

mod network;
mod traffic;

pub use network::{NetworkConfig, SimulatedNetwork};
pub use traffic::{
    AggregateBandwidth, BandwidthEstimates, BandwidthReport, MessageTypeReport, MessageTypeStats,
    NetworkTrafficAnalyzer, NodeBandwidthReport, NodeTrafficStats,
};

/// Type alias for deterministic node indexing in simulation.
///
/// This is a simulation-only concept for routing between in-process nodes.
/// Production code uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;
