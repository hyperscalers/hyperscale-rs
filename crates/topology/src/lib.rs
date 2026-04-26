//! Topology state for shard committee management.
//!
//! `TopologyState` is owned by `NodeStateMachine` and wraps an immutable
//! `TopologySnapshot` (from `hyperscale-types`) plus epoch lifecycle state.
//!
//! Consumers that need concurrent read access to the current snapshot (e.g.
//! the `io_loop` and network layer) should wrap `Arc<TopologySnapshot>` in an
//! `ArcSwap` at their own layer and update it when the state machine emits
//! `Action::TopologyChanged`.

mod state;

pub use state::{TopologyError, TopologyState};
