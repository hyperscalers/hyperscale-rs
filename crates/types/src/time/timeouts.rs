//! Shared Duration constants used by multiple sub-state machines.
//!
//! Sub-state-machine-local timeouts (fallback fetch, etc.) stay in their
//! owning crate. This module is for policies that are enforced by more than
//! one crate and must stay in lockstep — most retention windows downstream
//! derive their invariants from `WAVE_TIMEOUT`, which defines the cross-shard
//! execution window.

use crate::MAX_VALIDITY_RANGE;
use std::time::Duration;

/// How long after wave start before a not-fully-provisioned wave is aborted
/// in its entirety.
///
/// This is the cross-shard execution window — every retention window that
/// must outlive a live wave is sized in terms of this.
///
/// Sized at 3× `VOTE_RETRY_TIMEOUT` (8s) so at least two vote retries can
/// fire against rotated wave leaders before the timeout-abort path takes over.
///
/// Deterministic — measured against the BFT-authenticated
/// `weighted_timestamp_ms` of the committing QC, so every validator derives
/// the same abort anchor.
pub const WAVE_TIMEOUT: Duration = Duration::from_secs(24);

/// How long to retain remote block headers below each shard's tip.
///
/// Shared by `hyperscale-bft` (deferral-proof verification) and
/// `hyperscale-remote-headers` (provision/exec-cert verification). Measured
/// against the BFT-authenticated `weighted_timestamp_ms` on the tip vs the
/// stored header. Sized generously above `WAVE_TIMEOUT` so late-arriving
/// proofs still find a header to verify against.
pub const REMOTE_HEADER_RETENTION: Duration = Duration::from_secs(30);

/// Single principled retention bound for every artefact derived from a tx
/// — provisions, ECs, mempool tombstones, conflict-detector entries.
///
/// A tx included at the latest possible moment
/// (`weighted_ts ≈ end_timestamp_exclusive - 1ms`) gets `WAVE_TIMEOUT`
/// after that to terminate (success or abort, both via WC). After both
/// elapse, the tx is provably terminal everywhere — no shard can still
/// need its provision data, EC, or any other artefact. Safe to drop on
/// every node simultaneously.
///
/// Replaces the per-batch / per-cert / per-wave timers that previously
/// scattered through provisions and execution: every retention site
/// uses this single constant, derived from tx data, agreed on by every
/// validator.
pub const RETENTION_HORIZON: Duration =
    Duration::from_secs(MAX_VALIDITY_RANGE.as_secs() + WAVE_TIMEOUT.as_secs());
