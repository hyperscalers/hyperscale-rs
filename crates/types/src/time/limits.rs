//! Proposer-timestamp admission bounds.
//!
//! Hard caps applied at header admission on the proposer's local-clock
//! timestamp, measured against the receiving validator's own clock.
//! Reject obviously rushed or stale headers before they enter the shard consensus
//! state machine.
//!
//! These are protocol invariants, not operator-tunable config: every
//! validator must enforce the same bound, otherwise a Byzantine
//! proposer can craft a header that some validators accept and others
//! reject — splitting the QC and degrading liveness.

use std::time::Duration;

/// Maximum acceptable lag of a proposer's timestamp behind the
/// receiving validator's local clock.
///
/// Headers whose `timestamp` is older than `now - MAX_TIMESTAMP_DELAY`
/// are rejected at admission. Sized generously to tolerate typical
/// inter-validator clock skew and propagation latency without admitting
/// stale-clock proposers whose timestamps would distort the
/// stake-weighted timestamp aggregation.
pub const MAX_TIMESTAMP_DELAY: Duration = Duration::from_secs(30);

/// Maximum acceptable rush of a proposer's timestamp ahead of the
/// receiving validator's local clock.
///
/// Headers whose `timestamp` is newer than `now + MAX_TIMESTAMP_RUSH`
/// are rejected at admission. Tighter than `MAX_TIMESTAMP_DELAY` because
/// a forward-skewed timestamp can pull the QC's
/// [`WeightedTimestamp`](crate::WeightedTimestamp) ahead of real time,
/// shrinking subsequent retention windows.
pub const MAX_TIMESTAMP_RUSH: Duration = Duration::from_secs(2);
