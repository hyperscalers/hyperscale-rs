//! Beacon-chain coordinator crate.
//!
//! Hosts the [`BeaconCoordinator`] state machine and its sub-machines:
//! PC / SPC consensus (one SPC instance per epoch), `BeaconState`
//! application via `apply_epoch`, pending-block tracking, verification
//! dispatch, witness fetching, skip-quorum assembly, and equivocation
//! observation.
//!
//! `BeaconCoordinator` is also the topology source — after each
//! successful `apply_epoch` it derives a fresh
//! [`TopologySnapshot`](hyperscale_types::TopologySnapshot) from
//! `BeaconState` and exposes it via `current_topology_snapshot()`.

pub mod action_handlers;
pub mod block_sync;
pub mod constants;
pub mod coordinator;
pub mod equivocations;
pub mod genesis;
pub mod pc;
pub mod pending_blocks;
pub mod proposal_pool;
pub mod sampling;
pub mod skip;
pub mod skip_tracker;
pub mod spc;
pub mod state;
pub mod verification;
pub mod witness_fetcher;
