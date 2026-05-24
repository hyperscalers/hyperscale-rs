//! Beacon-chain coordinator crate.
//!
//! Hosts the [`BeaconCoordinator`] state machine and its sub-machines:
//! PC / SPC / MSC consensus, `BeaconState` application via `apply_slot`,
//! pending-block tracking, verification dispatch, witness fetching,
//! recovery, and equivocation observation.
//!
//! `BeaconCoordinator` is also the topology source — after each
//! successful `apply_slot` it derives a fresh
//! [`TopologySnapshot`](hyperscale_types::TopologySnapshot) from
//! `BeaconState` and exposes it via `current_topology_snapshot()`.

pub mod constants;
pub mod genesis;
pub mod msc;
pub mod pc;
pub mod prefix_ops;
pub mod sampling;
pub mod spc;
pub mod state;
