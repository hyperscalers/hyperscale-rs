//! Duration constants that are part of the consensus protocol.
//!
//! Every constant here must be enforced identically on every validator.
//! Two flavors live side by side:
//!
//! - **Retention / abort windows** (`MAX_FINALIZATION_DELAY`, `REMOTE_HEADER_RETENTION`,
//!   `RETENTION_HORIZON`) — durations after which a tick aborts or a piece
//!   of derived state becomes safe to drop on every node simultaneously.
//!   Most downstream invariants derive from `MAX_FINALIZATION_DELAY`.
//! - **shard consensus liveness bounds** (`VIEW_CHANGE_TIMEOUT_*`,
//!   `VIEW_CHANGE_DELAY_MULTIPLIER`, `PROGRESS_WAIT_MULTIPLIER`) — the round
//!   timer's base is derived from the committed chain, so replicas agree on
//!   it by construction; these bound it and size the ceiling on view-change
//!   suppression while a proposal is in flight, the stall-attack bound every
//!   validator must enforce alike.
//!
//! Sub-state-machine-local timeouts (fallback fetch, IO retry backoff, etc.)
//! stay in their owning crate.

use std::time::Duration;

use hyperscale_vm_types::{ARTIFACT_GRACE_MS, COMMITTED_GRACE_MS};

use crate::MAX_VALIDITY_RANGE;

/// The longest a cross-shard transaction may take to finalize, past the
/// last block that could have included it.
///
/// This is the cross-shard settlement window — every retention window
/// that must outlive a transaction in flight is sized in terms of it, and
/// past it the transaction is abandoned rather than waited for. So the
/// last moment a transaction can be included plus this is
/// [`RETENTION_HORIZON`].
///
/// Sized at 3× `VOTE_RETRY_TIMEOUT` (8s) so at least two vote retries can
/// fire against rotated tick leaders inside it.
///
/// Deterministic — measured against the shard consensus-authenticated
/// `weighted_timestamp_ms` of the committing QC, so every validator
/// derives the same deadline.
pub const MAX_FINALIZATION_DELAY: Duration = Duration::from_secs(24);

/// How long to retain remote block headers below each shard's tip.
///
/// Shared by `hyperscale-shard` (deferral-proof verification) and
/// `hyperscale-remote-headers` (provision/exec-cert verification). Measured
/// against the shard consensus-authenticated `weighted_timestamp_ms` on the tip vs the
/// stored header. Sized generously above `MAX_FINALIZATION_DELAY` so late-arriving
/// proofs still find a header to verify against.
pub const REMOTE_HEADER_RETENTION: Duration = Duration::from_secs(30);

/// Single principled retention bound for every artefact derived from a tx
/// — provisions, ECs, conflict-detector entries.
///
/// Not the mempool's tombstones, which key on the `admissible_until` that
/// let their transaction in: a tombstone has to stop refusing exactly
/// where admission stops taking it back, and that instant is the
/// transaction's own, not a horizon.
///
/// A tx included at the latest possible moment
/// (`weighted_ts ≈ end_timestamp_exclusive - 1ms`) gets `MAX_FINALIZATION_DELAY`
/// after that to terminate (success or abort, both via WC). After both
/// elapse, the tx is provably terminal everywhere — no shard can still
/// need its provision data, EC, or any other artefact. Safe to drop on
/// every node simultaneously.
///
/// Sized from the transaction window and never from
/// [`MAX_INTENT_VALIDITY_RANGE`](crate::MAX_INTENT_VALIDITY_RANGE),
/// which is far wider: what is retained here is derived from a
/// transaction, and a transaction binding a long-standing offer still
/// runs inside its own window.
pub const RETENTION_HORIZON: Duration =
    Duration::from_secs(MAX_VALIDITY_RANGE.as_secs() + MAX_FINALIZATION_DELAY.as_secs());

/// How far back a chain is folded to rebuild the committed-artifact
/// dedup window.
///
/// One figure for every tier, and they are one figure rather than three
/// that happen to agree. Every transaction is held to its own deadline
/// ([`admissible_until`](crate::admissible_until)), which sits at most
/// this far past the block at anchor `A` that carried it: a validity
/// range to the end, a finalization delay past that. The provision tier
/// keys `A + RETENTION_HORIZON` outright, and a finalization's deadline
/// is its transaction's, which sits at or below the block carrying it.
/// So the walk's depth and the entries it keeps move together.
pub const DEDUP_WINDOW: Duration = RETENTION_HORIZON;

const _: () = assert!(
    DEDUP_WINDOW.as_secs() == RETENTION_HORIZON.as_secs(),
    "the dedup walk is exactly as deep as the tiers it rebuilds",
);

/// How far back a chain is folded to rebuild the fee reservations the
/// payer shard still holds engaged.
///
/// A hold lives to its transaction's validity end plus
/// [`RETENTION_HORIZON`], and the block that committed it sits no earlier
/// than a whole [`MAX_VALIDITY_RANGE`] before that end — a transaction is
/// only admissible inside its own window, and the window is no wider than
/// that. So a hold still engaged can come from a block that far back, and
/// the walk has to reach it or the ledger it seeds under-counts.
///
/// Deeper than [`DEDUP_WINDOW`], whose deepest entry stands to its
/// transaction's own deadline where a hold ends one settlement window
/// past it. The two walks share a descent and each tier stops at its own
/// floor, so this is the figure the descent is floored at.
pub const FEE_HOLD_WINDOW: Duration =
    Duration::from_secs(RETENTION_HORIZON.as_secs() + MAX_VALIDITY_RANGE.as_secs());

const _: () = assert!(
    FEE_HOLD_WINDOW.as_secs() >= DEDUP_WINDOW.as_secs(),
    "the recovery descent is floored at the deepest tier it seeds",
);

/// The VM keys and values each sweepable family by an expiry it derives
/// from the family alone, and this is where the spellings are held
/// together. A grace each, so an assert each.
///
/// A nullifier's floor is the last transaction that could have bound the
/// subintent, admitted before the intent's window ends and terminated
/// one [`MAX_FINALIZATION_DELAY`] later, which is `RETENTION_HORIZON`.
const _: () = assert!(
    RETENTION_HORIZON.as_secs() * 1_000 == ARTIFACT_GRACE_MS,
    "an artifact lives its signed window plus the retention horizon",
);

/// A committed cell's floor is the close of `Window::Core`, which is
/// where the argument for the span it runs is. The VM spells the figure
/// and this chain spells the window; they are the same instant or an
/// absence read inside the window is a swept cell.
const _: () = assert!(
    (MAX_FINALIZATION_DELAY.as_secs() + MAX_VALIDITY_RANGE.as_secs() * 2) * 1_000
        == COMMITTED_GRACE_MS,
    "a committed cell lives to the close of the window its absence answers in",
);

/// The horizon must not outlive the epoch that produced what it retains.
///
/// A reshape's cut is scheduled one window ahead, so a successor
/// inheriting a predecessor's tx-derived state has one epoch of chain to
/// read it from. A horizon past that reaches back further than the
/// reshape spans, and the successor has to fetch below what it already
/// walks. Half an epoch is the working margin, not the hard bound.
const _: () = assert!(RETENTION_HORIZON.as_secs() < EPOCH_DURATION.as_secs());

/// A skipped epoch and its recovery must not expire the transactions a
/// shard is holding. `SKIP_TIMEOUT` bounds the wait before the pool
/// prevotes a skip, and ratification rounds follow it; a validity window
/// under a small multiple of that turns one stalled epoch into a
/// cleared mempool.
const _: () = assert!(MAX_VALIDITY_RANGE.as_secs() >= 2 * SKIP_TIMEOUT.as_secs());

/// The round timer's base while the committed chain has yet to measure a
/// full committee rotation: a fresh chain, a restarted replica with no
/// stored history, or a committee that just grew.
///
/// Once a rotation has committed, the base is
/// `VIEW_CHANGE_DELAY_MULTIPLIER` times the chain-derived network delay,
/// bounded by `VIEW_CHANGE_TIMEOUT_MIN` and `VIEW_CHANGE_TIMEOUT_MAX`, and
/// doubles per round abandoned at a height. The delay is a function of
/// committed chain data and round numbers are QC- and header-attested, so
/// every validator computes the same timeout for any `(height, round)`.
pub const VIEW_CHANGE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(3);

/// Floor on the round timer's base.
///
/// Absorbs proposer-to-voter clock skew, which the chain's delay sample
/// cannot tell from delay, and keeps a fast committee's timer above the
/// cadence of the duties that retry once per round.
pub const VIEW_CHANGE_TIMEOUT_MIN: Duration = Duration::from_secs(1);

/// Cap on the round timer after backoff.
///
/// Bounds round latency in extreme network conditions so a stuck height
/// can't ratchet timeouts upward indefinitely.
pub const VIEW_CHANGE_TIMEOUT_MAX: Duration = Duration::from_secs(30);

/// Network delays per round timer base.
///
/// After a QC forms the next leader needs up to one delay to receive it
/// and one to land its header on a follower, so a healthy round's silence
/// is at most two delays; six is a threefold margin over that.
pub const VIEW_CHANGE_DELAY_MULTIPLIER: u32 = 6;

/// Round timer bases per progress wait: the ceiling on view-change
/// suppression while a block is in progress at the proposal tip.
///
/// View changes are normally suppressed while we're fetching block
/// content, awaiting our own QC, or processing the leader's pending
/// block. The progress wait bounds how long a Byzantine proposer can
/// stall the round timer purely by keeping a header alive without ever
/// advancing the chain. Once it elapses since the last leader-activity
/// reset, the timer fires regardless of pending work.
pub const PROGRESS_WAIT_MULTIPLIER: u32 = 3;

/// How long a committee seated for a halt recovery waits for a retained
/// ex-member to offer a tip above the snap-synced anchor before it adopts
/// the anchor as the chain's frontier.
///
/// The offer rides the retained member's timeout, re-sent on its cleanup
/// tick for as long as the recovery names it retained, so the wait covers
/// several ticks at the default interval with margin. It is measured from
/// the first tick on which the seating window is open: before that neither
/// side can send or receive an offer, and a wait counted from the seating
/// fold would elapse with nothing measured. It is not derived from the
/// cleanup interval, which is the retained member's local knob and not
/// something the waiting member can read.
pub const HALT_HARVEST_WAIT: Duration = Duration::from_secs(10);

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
/// Also bounds the witness-inclusion window: a witness leaf is includable
/// in a beacon proposal during epoch `E` if its source block's
/// `weighted_timestamp ≤ t_end_E`.
pub const EPOCH_DURATION: Duration = Duration::from_mins(5);

/// Wall-clock interval an active validator waits past an epoch's
/// expected block time before prevoting the skip block in
/// ratification round 1.
///
/// Loosely synchronized clocks suffice: a validator that prevoted the
/// candidate before its deadline and one that prevoted skip after it
/// split round 1 below both quorums at worst, and round 2 converges.
/// Sized so a normal SPC commit (well under 10 s on a healthy network)
/// never trips the timer, while a genuine stall doesn't burn an entire
/// epoch waiting. Starting value picked mid-range against the 30–60 s
/// envelope; tune from operational data.
pub const SKIP_TIMEOUT: Duration = Duration::from_secs(45);

/// Wall-clock length of one ratification round past the first: a
/// round with neither a commit certificate nor a polka worth waiting
/// on re-prevotes in the next round after this long.
///
/// Long enough for a pool-wide vote broadcast plus aggregation
/// (seconds), short enough that a split round-1 vote converges well
/// within the epoch. A spuriously short value costs an extra benign
/// round; a long one only delays skipping a genuinely dead committee.
pub const RATIFY_ROUND_TIMEOUT: Duration = Duration::from_secs(15);
