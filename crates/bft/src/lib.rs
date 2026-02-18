//! BFT consensus state machine.
//!
//! This crate provides a synchronous BFT consensus implementation
//! that can be used for both simulation and production.
//!
//! # Architecture
//!
//! The BFT state machine processes events synchronously:
//!
//! - `Event::ProposalTimer` → Build and broadcast block if we're the proposer
//! - `Event::BlockHeaderReceived` → Validate header, assemble block, vote
//! - `Event::BlockVoteReceived` → Collect votes, form QC when quorum reached
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
//! This implementation follows HotStuff-2 with implicit view changes:
//!
//! ## Safety
//!
//! - **Vote locking**: Once a validator votes for block B at height H, it cannot
//!   vote for a different block at height H (prevents equivocation).
//!
//! - **Quorum intersection**: Any two quorums of 2f+1 overlap in at least one
//!   honest validator, so conflicting blocks cannot both get QCs.
//!
//! - **Two-chain commit**: A block at height H is committed when a QC forms for
//!   height H+1. This ensures finality even under asynchrony.
//!
//! ## Liveness
//!
//! - **Timeout-based view change**: Each validator advances its round locally on
//!   timeout. No coordinated view-change voting is required.
//!
//! - **Unlock rule**: When a validator sees a QC at height H, it unlocks any vote
//!   locks at heights ≤ H. This allows voting for new blocks after failed rounds.
//!
//! - **View synchronization**: When a validator sees a QC formed at round R, it
//!   advances its local view to R. This keeps validators in sync with network
//!   progress and prevents view divergence.

pub mod handlers;

mod config;
mod pending;
mod state;
mod vote_set;

pub use config::BftConfig;
pub use state::{BftState, BftStats, RecoveredState};
