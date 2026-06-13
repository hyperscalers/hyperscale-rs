//! Shard consensus state machine (HotStuff-2).
//!
//! This crate provides a synchronous shard consensus implementation
//! that can be used for both simulation and production.
//!
//! # Architecture
//!
//! The shard consensus state machine processes events synchronously:
//!
//! - new-content latch → Build and broadcast block if we're the proposer
//! - `Event::BlockHeaderReceived` → Validate header, assemble block, vote
//! - `Event::{Verified,Unverified}BlockVoteReceived` → Collect votes, form QC when quorum reached
//! - `Event::QuorumCertificateFormed` → Update chain state, commit if ready
//!
//! All I/O is performed by the runner via returned `Action`s.
//!
//! # Terminology
//!
//! - **Height**: Position in the chain (0, 1, 2, ...). Strictly sequential; a block
//!   at height N can only be proposed after a QC exists for height N-1.
//!
//! - **Round/View**: Attempt number for proposing a block. Multiple rounds may be
//!   needed at a single height if proposals fail (timeout, Byzantine leader, etc.).
//!   These terms are used interchangeably in the codebase.
//!
//! - **Block**: Contains a header (consensus metadata) and payload (transactions).
//!   Validators vote on the block header; the full block is assembled from gossip.
//!
//! - **QC (Quorum Certificate)**: Aggregated signature from 2f+1 validators proving
//!   they voted for a block. Carried in the next block's header as `parent_qc`.
//!
//! # Consensus Protocol (HotStuff-2)
//!
//! Rounds increase per block (genesis is round 0, the next block round 1, …);
//! a view change leaves a gap. Safety is carried entirely in two local,
//! monotone round counters — nothing but the `parent_qc` rides on a block.
//!
//! ## Safety
//!
//! - **Safe-vote rule**: a validator votes for block `B` only if `B.round` is
//!   its current round, strictly above every round it has already voted or timed
//!   out in (`last_voted_round`), and `B`'s `parent_qc` round is at least its
//!   `locked_round`. On voting it sets `last_voted_round = B.round` and raises
//!   `locked_round` to `B.parent_qc.round`.
//!
//! - **Quorum intersection**: any two quorums of 2f+1 overlap in at least one
//!   honest validator. With `last_voted_round` giving one vote per round, at
//!   most one QC forms per round; the safe-vote lock then forces every QC above
//!   a committed block to extend it.
//!
//! - **Round-contiguous two-chain commit**: a block `B` commits only when a QC
//!   forms for a child at exactly `B.round + 1`. A block proposed after a view
//!   change defers until a direct two-chain forms above it, then commits with
//!   the whole intervening prefix.
//!
//! ## Liveness
//!
//! - **Timeout pacemaker**: when its round timer fires, a validator broadcasts a
//!   `Timeout` carrying its `high_qc` instead of advancing locally. f+1 timeouts
//!   for a round trigger Bracha amplification (broadcast your own); a 2f+1
//!   timeout quorum advances the round and adopts the quorum-max `high_qc`, which
//!   the new round's leader extends.
//!
//! - **View synchronization**: adopting a verified QC for round R advances the
//!   local view to R+1, so rounds track the chain; a lagging validator also
//!   nudges its view toward a higher round observed on a header or vote.

pub mod action_handlers;
pub mod beacon_witnesses;
pub mod ready_signal_pool;

mod block_sync;
mod chain_view;
mod commit_dedup;
mod commit_pipeline;
mod config;
mod coordinator;
mod deferred_qc;
mod lookups;
mod pending;
mod proposal;
mod timeout_keeper;
mod validation;
mod verification;
mod view_change;
mod vote_keeper;
mod vote_set;

pub use config::ShardConsensusConfig;
pub use coordinator::{SettledWaveSet, ShardCoordinator, ShardMemoryStats, ShardStats};
pub use verification::ReadyStateRootVerification;
