//! Centralized **receive-side** remote block header coordination for
//! cross-shard verification.
//!
//! This crate owns the lifecycle of remote committed block headers as
//! they arrive at this node from peer shards:
//! receive → verify → store → notify → timeout → fallback request.
//! It is the consumer-side staging area; the responder-side serve path
//! (answering peers' `GetRemoteHeadersRequest`s for headers from this
//! node's own committed chain) lives in `crates/node` and reads through
//! `PendingChain::committed_header` — those are plain local-chain reads,
//! not remote headers.
//!
//! ## Why a dedicated crate?
//!
//! Remote headers are consumed by shard consensus (deferral merkle proofs), Provision
//! (state root verification), and Execution (expected cert tracking).
//! `RemoteHeaderCoordinator` is the single source of truth — it verifies,
//! stores, and prunes headers once, then emits `RemoteHeaderAdmitted`
//! continuations for all downstream consumers.
//!
//! ## Header Flow
//!
//! 1. Gossip arrives → `IoLoop` verifies sender BLS signature → `RemoteHeaderReceived` event
//! 2. Coordinator stores header as pending, emits `Action::VerifyRemoteHeaderQc`
//! 3. Async QC verification completes → `RemoteHeaderQcVerified` event
//! 4. Coordinator promotes to verified, emits `Action::Continuation(RemoteHeaderAdmitted)`
//! 5. shard consensus, Provision, Execution consume the verified header
//!
//! ## Fallback
//!
//! With proposer-only gossip, headers may not arrive (proposer is byzantine/slow).
//! The coordinator tracks per-shard liveness and emits
//! `Action::StartRemoteHeaderSync` after a staleness threshold, raising the
//! per-shard target on the I/O loop's sliding-window `RemoteHeaderSync`
//! state machine.

mod coordinator;

pub use coordinator::{RemoteHeaderCoordinator, RemoteHeaderMemoryStats};
