//! Deterministic execution state machine.
//!
//! Implements the transaction execution layer as a pure, synchronous state
//! machine. The [`ExecutionCoordinator`] consumes `ProtocolEvent`s from the
//! BFT layer and the network, drives the wave/EC lifecycle, and emits
//! `Action`s for asynchronous work (BLS verification, state provisioning,
//! transaction execution against substate).
//!
//! # Wave lifecycle
//!
//! Cross-shard transactions are grouped into deterministic *waves*. Each
//! wave is provisioned by the source shards (state entries with JMT
//! proofs), executed once provisions are complete, and certified by an
//! `ExecutionCertificate` aggregating execution votes from the committee.
//! Resolved waves are finalized into a `FinalizedWave` receipt that lives
//! in the corresponding block.
//!
//! # Conflict handling
//!
//! When two transactions in flight contend on overlapping state, the
//! conflict detector ([`crate::conflict`]) deterministically aborts one
//! using `committed_at` ordering and replays the survivor. The
//! `WAVE_TIMEOUT` floor bounds how long detector entries are retained
//! past commit; see the prune call in the coordinator for the rationale.

pub mod action_handlers;
pub mod conflict;
pub mod wave_state;

mod coordinator;
mod early_arrivals;
mod exec_cert_store;
mod expected_certs;
mod finalized_waves;
mod lookups;
mod outbound_certs;
mod provisioning;
mod vote_tracker;
mod waves;

pub use coordinator::{CompletionData, ExecutionCoordinator, ExecutionMemoryStats};
pub use exec_cert_store::ExecCertStore;
pub use finalized_waves::FinalizedWaveStore;
pub use vote_tracker::VoteTracker;
pub use wave_state::WaveState;
