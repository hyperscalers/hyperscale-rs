//! The crossing index's recent changes, for a reader that keeps what it
//! derives from the rows and reads only the rows that moved.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_jmt::NibblePath;
use hyperscale_types::SubstateKey;

use crate::key_under_prefix;

/// The most row keys a journal keeps. A reader further behind than this
/// reads the rows whole.
const JOURNAL_KEYS: usize = 1 << 16;

/// Where one reader of a store's crossing index stands in its changes:
/// every change at or below `version` on the line is in what it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossingCursor {
    line: u64,
    version: u64,
}

/// The keys whose crossing index row a store has put or removed, each
/// with the version that wrote it, in the order the store wrote them.
///
/// One line per run of forward commits. Anything else that moves the
/// index, an import or a re-rooting, a restore from an image, a write
/// below a version already recorded, or a fresh store, starts a new
/// line, and a cursor from any other line reads the rows whole. So a
/// reader never takes a key list for a complete account of what changed
/// unless every change since its cursor was a commit this line
/// recorded.
///
/// A copy is a new line: an image restored over a live store is not the
/// state the store's readers followed.
#[derive(Debug)]
pub struct CrossingJournal {
    line: u64,
    /// The newest version a dropped key was written at.
    floor: u64,
    keys: VecDeque<(u64, SubstateKey)>,
}

impl CrossingJournal {
    /// A journal on a line of its own.
    #[must_use]
    pub fn new() -> Self {
        static LINES: AtomicU64 = AtomicU64::new(0);
        Self {
            line: LINES.fetch_add(1, Ordering::Relaxed),
            floor: 0,
            keys: VecDeque::new(),
        }
    }

    /// Record `keys` as put or removed by the write at `version`.
    ///
    /// The journal never lags the committed head a reader can see: a
    /// store records a write no later than its head names the write, so
    /// a reader that takes the head and then the changes through it is
    /// never handed a cursor at a version whose keys it was not given.
    /// A write recorded before it lands is harmless, since [`Self::since`]
    /// names nothing above the version a reader reads at.
    ///
    /// Every key one version moves is recorded in one call: a reader
    /// that has read through `version` takes nothing more at it, so a
    /// second call at the same version after such a read is never
    /// named.
    pub fn record(&mut self, version: u64, keys: impl IntoIterator<Item = SubstateKey>) {
        if self
            .keys
            .back()
            .is_some_and(|(newest, _)| *newest > version)
        {
            self.restart(version);
        }
        let mut keys: Vec<SubstateKey> = keys.into_iter().collect();
        let over = (self.keys.len() + keys.len()).saturating_sub(JOURNAL_KEYS);
        for (dropped, _) in self.keys.drain(..over.min(self.keys.len())) {
            self.floor = self.floor.max(dropped);
        }
        if keys.len() > JOURNAL_KEYS {
            keys.drain(..keys.len() - JOURNAL_KEYS);
            self.floor = self.floor.max(version);
        }
        self.keys.extend(keys.into_iter().map(|key| (version, key)));
    }

    /// Start a new line at the write at `version`: what the index holds
    /// no longer follows from the keys recorded.
    ///
    /// A store restarts no later than its head names the write, as it
    /// records one. Nothing at or below `version` is followed on the new
    /// line, so a reader that takes a cursor on it while the head still
    /// stands below `version` reads whole again rather than following
    /// across the write. The floor covers a write that moves the head
    /// forward only: a store restarts at a version above every head a
    /// reader may hold, or with no reader on it.
    pub fn restart(&mut self, version: u64) {
        *self = Self {
            floor: version,
            ..Self::new()
        };
    }

    /// The keys under `under` written above `since` and at or below
    /// `through`, the version a reader reads the rows at, ascending and
    /// each once, or `None` where this journal cannot say, with where
    /// the reader stands once it has read them.
    #[must_use]
    pub fn since(
        &self,
        under: &NibblePath,
        since: Option<CrossingCursor>,
        through: u64,
    ) -> (Option<Vec<SubstateKey>>, CrossingCursor) {
        let readable = || {
            self.keys
                .iter()
                .rev()
                .skip_while(move |(version, _)| *version > through)
        };
        let newest = readable()
            .next()
            .map_or(self.floor, |(version, _)| *version);
        let Some(from) = since
            .filter(|cursor| cursor.line == self.line)
            .map(|cursor| cursor.version)
            .filter(|version| *version >= self.floor)
        else {
            let now = CrossingCursor {
                line: self.line,
                version: newest.max(self.floor).min(through),
            };
            return (None, now);
        };
        let changed: BTreeSet<SubstateKey> = readable()
            .take_while(|(version, _)| *version > from)
            .map(|(_, key)| *key)
            .filter(|key| key_under_prefix(&key.to_bytes(), under))
            .collect();
        let now = CrossingCursor {
            line: self.line,
            version: newest.max(from),
        };
        (Some(changed.into_iter().collect()), now)
    }
}

impl Default for CrossingJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CrossingJournal {
    /// Starts a new line, as the type says a copy does.
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_key;

    use super::*;

    #[test]
    fn a_cursor_reads_what_its_line_recorded_since_up_to_its_version() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        let (whole, start) = journal.since(&all, None, 0);
        assert_eq!(whole, None, "no cursor reads the rows whole");
        journal.record(1, [test_key(2), test_key(1), test_key(2)]);
        journal.record(2, [test_key(3)]);
        let (changed, cursor) = journal.since(&all, Some(start), 1);
        assert_eq!(
            changed,
            Some(vec![test_key(1), test_key(2)]),
            "a write above the version read at waits",
        );
        let (changed, cursor) = journal.since(&all, Some(cursor), 2);
        assert_eq!(changed, Some(vec![test_key(3)]));
        assert_eq!(journal.since(&all, Some(cursor), 2).0, Some(Vec::new()));

        let copy = journal.clone();
        assert_eq!(
            copy.since(&all, Some(cursor), 2).0,
            None,
            "a copy is a new line"
        );
        journal.record(1, [test_key(4)]);
        assert_eq!(
            journal.since(&all, Some(cursor), 2).0,
            None,
            "a write below one recorded starts a new line",
        );
    }

    #[test]
    fn a_whole_read_stands_at_the_newest_version_it_saw() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        journal.record(3, [test_key(1)]);
        let (whole, cursor) = journal.since(&all, None, 5);
        assert_eq!(whole, None);
        // Version 4 recorded late: the whole read at 5 may already hold
        // it, and reading it again is harmless.
        journal.record(4, [test_key(2)]);
        assert_eq!(
            journal.since(&all, Some(cursor), 5).0,
            Some(vec![test_key(2)])
        );
    }

    /// Review probe: a batch larger than the cap leaves every reader
    /// whose span it trimmed reading whole, and a reader caught up past
    /// it following.
    #[test]
    fn an_oversized_batch_sends_every_reader_behind_it_whole() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        let (_, start) = journal.since(&all, None, 0);
        journal.record(1, [test_key(1)]);
        let (_, at_one) = journal.since(&all, Some(start), 1);
        let big: Vec<SubstateKey> = (0..JOURNAL_KEYS + 5)
            .map(|i| {
                let mut key = test_key(2);
                key.local.0[..8].copy_from_slice(&(i as u64).to_le_bytes());
                key
            })
            .collect();
        journal.record(2, big);
        assert_eq!(journal.since(&all, Some(start), 2).0, None);
        assert_eq!(
            journal.since(&all, Some(at_one), 2).0,
            None,
            "trimmed span reads whole"
        );
        let (_, at_two) = journal.since(&all, None, 2);
        journal.record(3, [test_key(3)]);
        assert_eq!(
            journal.since(&all, Some(at_two), 3).0,
            Some(vec![test_key(3)])
        );
        // A cap-sized batch on top of standing keys drops them all.
        let (_, at_three) = journal.since(&all, Some(at_two), 3);
        journal.record(4, (0..JOURNAL_KEYS).map(|_| test_key(4)));
        assert_eq!(journal.since(&all, Some(at_two), 4).0, None);
        assert_eq!(
            journal.since(&all, Some(at_three), 4).0,
            Some(vec![test_key(4)])
        );
    }

    #[test]
    fn a_whole_read_below_the_floor_reads_whole_again() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        journal.record(10, (0..=JOURNAL_KEYS).map(|_| test_key(1)));
        let (whole, cursor) = journal.since(&all, None, 5);
        assert_eq!(whole, None);
        assert_eq!(
            journal.since(&all, Some(cursor), 10).0,
            None,
            "a read at 5 stands no higher than 5, and version 10's write is behind the floor",
        );
    }

    /// A restart lands before the write it is for: a reader taking its
    /// cursor on the new line while its head still stands below the
    /// write reads whole again, rather than following across a write the
    /// line holds no keys for.
    #[test]
    fn a_cursor_taken_below_a_restart_reads_whole_again() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        journal.record(4, [test_key(1)]);
        journal.restart(6);
        let (whole, below) = journal.since(&all, None, 5);
        assert_eq!(whole, None);
        assert_eq!(
            journal.since(&all, Some(below), 6).0,
            None,
            "a cursor at 5 does not follow across the write at 6",
        );
        let (whole, at) = journal.since(&all, Some(below), 6);
        assert_eq!(whole, None);
        journal.record(7, [test_key(2)]);
        assert_eq!(journal.since(&all, Some(at), 7).0, Some(vec![test_key(2)]));
    }

    #[test]
    fn a_cursor_the_journal_has_dropped_reads_the_rows_whole() {
        let mut journal = CrossingJournal::new();
        let all = NibblePath::empty();
        let (_, start) = journal.since(&all, None, 0);
        journal.record(1, (0..=JOURNAL_KEYS).map(|_| test_key(1)));
        assert_eq!(journal.since(&all, Some(start), 1).0, None);
    }
}
