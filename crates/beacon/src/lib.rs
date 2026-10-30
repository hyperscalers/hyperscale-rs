//! Beacon-chain state machines.
//!
//! A host follows the beacon chain with one [`BeaconFold`]: the committed
//! `BeaconState` and its application via `apply_epoch`, the topology
//! schedule, pending-block tracking, block verification and witness
//! fetching for every shard chain the host runs. Each validator identity
//! the host holds runs one [`BeaconParticipant`] against the fold: PC /
//! SPC consensus (one SPC instance per epoch), proposals, epoch
//! ratification, and equivocation observation.
//!
//! The fold is the topology source: each adoption derives a fresh
//! [`TopologySnapshot`](hyperscale_types::TopologySnapshot) from the
//! `BeaconState` it commits.

pub mod action_handlers;
pub mod boundary;
pub mod commit_assembly;
pub mod coordinator;
pub mod equivocations;
mod fold;
pub mod fork_observations;
pub mod genesis;
mod participant;
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
pub mod vote_equivocation_observations;

pub use fold::{Adopted, BeaconFold, CandidateKeys, ChainRegistration, HostedChain};
pub use participant::{BeaconParticipant, ParticipantStep};
