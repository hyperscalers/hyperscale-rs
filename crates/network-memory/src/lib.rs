//! Deterministic in-memory network transport for simulation.
//!
//! Provides [`SimulatedNetwork`] with configurable latency, packet loss,
//! and network partitions, all driven by a seeded RNG for reproducibility.
//!
//! [`NetworkTrafficAnalyzer`] tracks per-message-type and per-node bandwidth
//! statistics for real-world deployment estimates.

mod network;
mod sim_network;
mod traffic;

// Faults are host-granular and the sim's `NodeIndex` is the host index, so it
// wraps into `HostId`; the engine itself lives in `hyperscale-network` under
// `test-utils` (shared with the libp2p transport) and sim code reaches it there.
pub use hyperscale_network::fault::HostId;
pub use network::{FulfillmentStats, HostLayout, NetworkConfig, SimulatedNetwork};
pub use sim_network::{OutboxEntry, PendingNotification, SimNetworkAdapter};
pub use traffic::{BandwidthReport, NetworkTrafficAnalyzer};

/// Type alias for deterministic node indexing in simulation.
///
/// This is a simulation-only concept for routing between in-process nodes.
/// Production code uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;
