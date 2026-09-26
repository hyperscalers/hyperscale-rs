//! What history a shard keeps, and until when.
//!
//! Retention is a span of weighted time. Every window that licenses a
//! read of history — a reclaim probe's, a provision's, a state proof's —
//! is stated in milliseconds against the consensus-authenticated
//! weighted timestamp, so a count of versions answers those windows only
//! through whatever block rate the chain happens to be running at.
//! Nothing enforces a rate, which makes a count an answer to a different
//! question: whether a licensed anchor is servable would depend on how
//! fast blocks had happened to arrive.
//!
//! So the floor is [`RETENTION_HORIZON`] behind the tip's own timestamp,
//! and every version a consumer may name is servable by construction.
//! What that costs is history proportional to the block rate, and what
//! bounds it is the per-block write caps the protocol already sets: what
//! is kept is the writes of the last horizon, which is what a consumer is
//! licensed to ask about.
//!
//! # One floor, four readers
//!
//! The floor is stored rather than recomputed. A historical cell read, a
//! historical range read, `snapshot_at` and the collectors ask for it,
//! and what a reader may ask for has to be exactly what the collector has
//! not deleted. Admitting `height >= floor` and deleting below it is that
//! relationship, and it holds because there is one value rather than four
//! arithmetic expressions that have to agree — and one fold moving it,
//! [`retire_dated`], whichever backend dates the versions.
//!
//! # The hold
//!
//! A consumer's licence is not the only thing that names a version. This
//! node's own execution reads the base at the anchor of whichever tick it
//! is running, which trails consensus — so the tick chain refuses to evict
//! a fold below the lower of what has persisted and what has executed.
//! The base those folds resolve against is held to the same floor, by the
//! same number, published through
//! [`hold_retention_at`](super::store::VersionedStore::hold_retention_at):
//! a fold that survives over a base that does not is a read with no answer.
//!
//! The horizon alone would be enough if the tip's clock moved with the
//! chain. It does not have to. A halted shard's recovery commit carries a
//! timestamp the whole halt ahead of its parent's, so every dated version
//! beneath it ages out at once and the floor arrives at the tip — where a
//! reader one event behind, which every reader keyed on `BlockPersisted`
//! is, names a version that has just gone. The hold is what the floor
//! cannot pass however far the clock jumps.
//!
//! # Versions this store never committed
//!
//! The floor is the first *dated* version at or above where it stands, so
//! a store whose history begins above zero needs nothing said about the
//! versions below. A snap-synced store dates its first committed block
//! and the floor arrives there; a split child's dates start at its
//! adoption. Neither needs a seed, because a version with no date is one
//! with no history to serve.

use hyperscale_types::{RETENTION_HORIZON, WeightedTimestamp};

/// What dating a version retires: the dated versions that fell outside
/// [`RETENTION_HORIZON`] of the tip, and the floor that leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    /// The versions whose dates aged out, ascending.
    pub versions: Vec<u64>,
    /// The oldest version still answered for.
    pub floor: u64,
}

/// Move `floor` past what a commit at `version`, dated `tip_ts`, retires,
/// holding at `hold`.
///
/// `dated` is every dated version from `floor` on, ascending, with its
/// timestamp — the scan runs forward from the stored floor, so each dated
/// version is passed once over the life of the store whatever the block
/// rate. The floor moves only past what it retires: a version with no
/// date of its own — the empty tree at zero, or anything below where a
/// snap-synced store's history begins — is left where it was rather than
/// skipped over, since nothing about it has aged out. Reading stops at
/// `version` itself, so a commit re-recording a height it already holds
/// retires nothing at or past it.
///
/// `hold` is the oldest version this node's own readers still name, and
/// stops the scan the same way the cutoff does: a version a reader is
/// anchored at is retained whatever its age. A store nothing has held
/// passes `u64::MAX` and the horizon is the whole rule.
#[must_use]
pub fn retire_dated(
    floor: u64,
    version: u64,
    hold: u64,
    tip_ts: WeightedTimestamp,
    dated: impl IntoIterator<Item = (u64, u64)>,
) -> Retired {
    let cutoff = tip_ts.minus(RETENTION_HORIZON).as_millis();
    let versions: Vec<u64> = dated
        .into_iter()
        .take_while(|(dated, ts)| *dated < version && *dated < hold && *ts < cutoff)
        .map(|(dated, _)| dated)
        .collect();
    let floor = versions.last().map_or(floor, |last| last + 1);
    Retired { versions, floor }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn horizon_ms() -> u64 {
        u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits")
    }

    /// Versions age out in order until one is inside the horizon, and the
    /// floor lands just past the last one retired.
    #[test]
    fn the_floor_moves_past_what_aged_out() {
        let step = horizon_ms() / 2;
        let dated = (1..=5u64).map(|v| (v, v * step));
        let tip = WeightedTimestamp::from_millis(6 * step);
        let retired = retire_dated(1, 6, u64::MAX, tip, dated);
        assert_eq!(retired.versions, vec![1, 2, 3]);
        assert_eq!(retired.floor, 4);
    }

    /// Nothing aged out leaves the floor where it stood, and a version at
    /// or past the one being dated is never read.
    #[test]
    fn nothing_retired_leaves_the_floor_and_the_commit_itself_is_never_read() {
        let tip = WeightedTimestamp::from_millis(horizon_ms());
        let stood = retire_dated(3, 4, u64::MAX, tip, [(3, horizon_ms() - 1)]);
        assert_eq!(
            stood,
            Retired {
                versions: Vec::new(),
                floor: 3
            }
        );
        let stopped = retire_dated(0, 2, u64::MAX, tip, [(2, 0), (3, 0)]);
        assert_eq!(stopped.versions, Vec::<u64>::new());
        assert_eq!(stopped.floor, 0);
    }

    /// A held version is retained however far past the horizon it is,
    /// and the floor lands on the hold rather than past it.
    #[test]
    fn the_hold_stops_the_floor_short_of_what_a_reader_names() {
        let step = horizon_ms() / 2;
        let dated = (1..=5u64).map(|v| (v, v * step));
        let tip = WeightedTimestamp::from_millis(6 * step);
        let held = retire_dated(1, 6, 2, tip, dated);
        assert_eq!(held.versions, vec![1]);
        assert_eq!(held.floor, 2);
    }

    /// A hold at or below the floor retires nothing at all: every commit
    /// while execution sits there leaves the history where it stands.
    #[test]
    fn a_hold_at_the_floor_retires_nothing() {
        let step = horizon_ms() / 2;
        let dated = (1..=5u64).map(|v| (v, v * step));
        let tip = WeightedTimestamp::from_millis(6 * step);
        let held = retire_dated(1, 6, 1, tip, dated);
        assert_eq!(held.versions, Vec::<u64>::new());
        assert_eq!(held.floor, 1);
    }

    /// The clock jumping a whole halt ahead retires every version
    /// beneath it, and the hold is the only thing that keeps the one a
    /// lagging reader is anchored at.
    #[test]
    fn a_clock_that_jumps_a_halt_does_not_retire_what_is_held() {
        let dated = (1067..=1068u64).map(|v| (v, v));
        let tip = WeightedTimestamp::from_millis(1069 + horizon_ms());
        let jumped = retire_dated(1067, 1069, u64::MAX, tip, dated.clone());
        assert_eq!(jumped.floor, 1069, "the floor arrives at the tip");
        let held = retire_dated(1067, 1069, 1067, tip, dated);
        assert_eq!(held.floor, 1067);
    }
}
