//! Centralized remote block header coordination for cross-shard verification.
//!
//! This crate owns the full lifecycle of remote committed block headers:
//! receive → verify → store → notify → timeout → fallback request.
//!
//! ## Why a dedicated crate?
//!
//! Remote headers are consumed by BFT (deferral merkle proofs), Provision
//! (state root verification), and Execution (expected cert tracking).
//! `RemoteHeaderCoordinator` is the single source of truth — it verifies,
//! stores, and prunes headers once, then emits `RemoteHeaderVerified`
//! continuations for all downstream consumers.
//!
//! ## Header Flow
//!
//! 1. Gossip arrives → `IoLoop` verifies sender BLS signature → `RemoteBlockCommitted` event
//! 2. Coordinator stores header as pending, emits `Action::VerifyRemoteHeaderQc`
//! 3. Async QC verification completes → `RemoteHeaderQcVerified` event
//! 4. Coordinator promotes to verified, emits `Action::Continuation(RemoteHeaderVerified)`
//! 5. BFT, Provision, Execution consume the verified header
//!
//! ## Fallback
//!
//! With proposer-only gossip, headers may not arrive (proposer is byzantine/slow).
//! The coordinator tracks per-shard liveness and emits
//! `Action::RequestMissingCommittedBlockHeader` after a timeout, triggering a
//! point-to-point fetch from any validator in the source shard.

mod coordinator;

pub use coordinator::{RemoteHeaderCoordinator, RemoteHeaderMemoryStats};
