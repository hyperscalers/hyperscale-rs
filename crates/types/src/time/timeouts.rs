//! Duration constants that are part of the consensus protocol.
//!
//! Every constant here must be enforced identically on every validator.
//! Two flavors live side by side:
//!
//! - **Retention / abort windows** (`WAVE_TIMEOUT`, `REMOTE_HEADER_RETENTION`,
//!   `RETENTION_HORIZON`) — durations after which a wave aborts or a piece
//!   of derived state becomes safe to drop on every node simultaneously.
//!   Most downstream invariants derive from `WAVE_TIMEOUT`.
//! - **shard consensus liveness timers** (`VIEW_CHANGE_TIMEOUT*`, `MAX_PROGRESS_WAIT`) —
//!   round-timer cadences and the absolute ceiling on view-change
//!   suppression while a proposal is in flight. Validators that disagree on
//!   these values either time out asymmetrically (degraded liveness) or
//!   weaken the stall-attack bound that `MAX_PROGRESS_WAIT` enforces.
//!
//! Sub-state-machine-local timeouts (fallback fetch, IO retry backoff, etc.)
//! stay in their owning crate.

use std::time::Duration;

use crate::MAX_VALIDITY_RANGE;

/// How long after wave start before a not-fully-provisioned wave is aborted
/// in its entirety.
///
/// This is the cross-shard execution window — every retention window that
/// must outlive a live wave is sized in terms of this.
///
/// Sized at 3× `VOTE_RETRY_TIMEOUT` (8s) so at least two vote retries can
/// fire against rotated wave leaders before the timeout-abort path takes over.
///
/// Deterministic — measured against the shard consensus-authenticated
/// `weighted_timestamp_ms` of the committing QC, so every validator derives
/// the same abort anchor.
pub const WAVE_TIMEOUT: Duration = Duration::from_secs(24);

/// How long to retain remote block headers below each shard's tip.
///
/// Shared by `hyperscale-shard` (deferral-proof verification) and
/// `hyperscale-remote-headers` (provision/exec-cert verification). Measured
/// against the shard consensus-authenticated `weighted_timestamp_ms` on the tip vs the
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
pub const RETENTION_HORIZON: Duration =
    Duration::from_secs(MAX_VALIDITY_RANGE.as_secs() + WAVE_TIMEOUT.as_secs());

/// Base view-change timeout for the first round at any height.
///
/// Combined with `VIEW_CHANGE_TIMEOUT_INCREMENT` and capped by
/// `VIEW_CHANGE_TIMEOUT_MAX` to produce the per-round timeout:
/// `min(base + increment * rounds_at_height, max)`. Round numbers are
/// QC- and header-attested, so every validator computes the same
/// effective timeout for any `(height, round)`.
pub const VIEW_CHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// Linear backoff increment per failed round at the same height.
///
/// Prevents thundering-herd view changes when the network is briefly
/// stressed: each successive round at the same height extends the
/// timeout by this much before the cap kicks in.
pub const VIEW_CHANGE_TIMEOUT_INCREMENT: Duration = Duration::from_secs(1);

/// Cap on the effective view-change timeout after linear backoff.
///
/// Bounds round latency in extreme network conditions so a stuck height
/// can't ratchet timeouts upward indefinitely.
pub const VIEW_CHANGE_TIMEOUT_MAX: Duration = Duration::from_secs(30);

/// Absolute ceiling on view-change suppression while a block is in
/// progress at the proposal tip.
///
/// View changes are normally suppressed while we're fetching block
/// content, awaiting our own QC, or processing the leader's pending
/// block. This cap bounds how long a Byzantine proposer can stall the
/// round timer purely by keeping a header alive without ever advancing
/// the chain. Once this elapses since the last leader-activity reset,
/// the timer fires regardless of pending work.
pub const MAX_PROGRESS_WAIT: Duration = Duration::from_secs(9);

/// Beacon-chain epoch length, measured against committed beacon-slot
/// `weighted_timestamp`.
///
/// Epoch boundaries are time-based, not slot-count-based: a slot's epoch
/// is `(slot.weighted_timestamp - genesis_wt) / EPOCH_DURATION`, derivable
/// independently by every validator without consensus on which slot
/// counts as the boundary. Recovery slots can wedge in mid-epoch without
/// rolling the epoch counter, decoupling committee-replacement from
/// natural epoch rotation.
///
/// Also bounds the witness-inclusion window: a [`ShardWitness`](crate::ShardWitness)
/// is includable in a beacon proposal during epoch `E` if its source
/// block's `weighted_timestamp ≤ t_end_E`.
pub const EPOCH_DURATION: Duration = Duration::from_mins(5);

/// Wall-clock interval an active validator waits past an epoch's
/// expected block time before broadcasting a
/// [`SkipRequest`](crate::SkipRequest).
///
/// Consensus-critical: every validator must derive the same trigger
/// instant or the cert-assembly quorum splits. Sized so a normal SPC
/// commit (well under 10 s on a healthy network) never trips the
/// timer, while a genuine stall doesn't burn an entire epoch waiting.
/// Starting value picked mid-range against the 30–60 s envelope; tune
/// from operational data.
pub const SKIP_TIMEOUT: Duration = Duration::from_secs(45);
