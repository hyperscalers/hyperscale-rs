//! Deterministic execution state machine.
//!
//! Implements the transaction execution layer as a pure, synchronous state
//! machine. The [`ExecutionCoordinator`] consumes `ProtocolEvent`s from the
//! shard consensus layer and the network, drives the tick lifecycle, and emits
//! `Action`s for asynchronous work (signature verification, state provisioning,
//! transaction execution against substate).
//!
//! # Tick lifecycle
//!
//! A block's commit composes a *tick* from the transactions that can
//! execute at it: the shard's own, and every cross-shard leg whose
//! counterparts' provisions have arrived. The tick executes as one batch
//! and is certified by an `ExecutionCertificate` aggregating execution
//! votes from the committee seated at it. Once every participating shard
//! has certified its members, the tick is finalized into a
//! `Finalization` that lives in a later block.
//!
pub mod action_handlers;
pub mod candidates;
pub mod tick_state;

mod coordinator;
mod counterparts;
mod early_arrivals;
mod exec_cert_store;
mod expected_certs;
mod finalizations;
#[cfg(test)]
mod fixtures;
mod gate;
mod ledger;
mod lookups;
mod outbound_certs;
mod parked;
mod provisional;
mod provisioning;
mod ticks;
mod vote_tracker;

pub use coordinator::{CompletionData, ExecutionCoordinator, ExecutionMemoryStats};
pub use counterparts::Offers;
pub use exec_cert_store::ExecCertStore;
pub use finalizations::FinalizationStore;
pub use lookups::{crossing_requests, provision_request};
pub use tick_state::TickState;
pub use vote_tracker::VoteTracker;
