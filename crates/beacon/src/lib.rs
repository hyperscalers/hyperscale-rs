//! Beacon-chain coordinator crate.
//!
//! Hosts the [`BeaconCoordinator`] state machine and its sub-machines:
//! PC / SPC consensus (one SPC instance per epoch), `BeaconState`
//! application via `apply_epoch`, pending-block tracking, verification
//! dispatch, witness fetching, epoch ratification, and equivocation
//! observation.
//!
//! `BeaconCoordinator` is also the topology source — after each
//! successful `apply_epoch` it derives a fresh
//! [`TopologySnapshot`](hyperscale_types::TopologySnapshot) from
//! `BeaconState` and exposes it via `current_topology_snapshot()`.

pub mod action_handlers;
pub mod boundary;
pub mod commit_assembly;
pub mod coordinator;
pub mod equivocations;
pub mod fork_observations;
pub mod genesis;
pub mod pc;
pub mod proposal_pool;
pub mod ratify;
pub mod rules;
pub mod sampling;
pub mod shard_source;
pub mod spc;
pub mod spc_driver;
pub mod state;
pub mod verification;
