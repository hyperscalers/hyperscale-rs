//! State-history-based `RocksDB` snapshot.
//!
//! Current-tip reads are a direct point lookup on `StateCf`. Historical
//! reads at version V use a single forward seek on `StateHistoryCf` to
//! find the smallest entry `(K, v')` with `v' > V`; its stored prior
//! value is the value at V. If no such entry exists, `StateCf[K]` was
//! stable since V and is the answer.

use hyperscale_storage::{Anchored, Substates};
use hyperscale_types::{BlockHeight, SubstateKey};
use hyperscale_vm_types::{Address, CollectionId};
use rocksdb::{DB, ReadOptions, Snapshot};

use super::column_families::{CfHandles, EntriesCf, EntriesHistoryCf, StateCf, StateHistoryCf};
use super::entry_key::{EntryKeyCodec, VersionedEntryKeyCodec, entry_range_bounds, scan_entries};
use crate::typed_cf::{DbCodec, HborCodec, TypedCf, get};

/// Length of the version suffix on each state-history key (`u64` big-endian).
const VERSION_LEN: usize = 8;

/// Point-in-time `RocksDB` snapshot scoped to a specific version within
/// the retention window. Retention enforcement happens at construction
/// in `RocksDbShardStorage::snapshot_at`.
pub struct RocksDbSnapshot<'a> {
    pub(crate) snapshot: Snapshot<'a>,
    pub(crate) db: &'a DB,
    /// Target version for all reads from this snapshot.
    pub(crate) version: u64,
    /// Current committed tip at snapshot-construction time. When
    /// `version >= current_version` we take the trivial branch
    /// (direct `StateCf` read) for every operation.
    pub(crate) current_version: u64,
}

impl RocksDbSnapshot<'_> {
    /// Build a `read_opts` that pins this snapshot. Required so raw
    /// iterators observe our point-in-time view rather than the live DB.
    fn read_opts(&self) -> ReadOptions {
        let mut opts = ReadOptions::default();
        opts.set_snapshot(&self.snapshot);
        opts
    }
}

impl Anchored for RocksDbSnapshot<'_> {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::new(self.version)
    }
}

impl Substates for RocksDbSnapshot<'_> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        let cf = CfHandles::resolve(self.db);
        let state_cf = StateCf::handle(&cf);

        // Current-tip fast path: single StateCf read, no history seek.
        if self.version >= self.current_version {
            return get::<StateCf>(&self.snapshot, state_cf, &key);
        }

        // Historical path: try StateHistoryCf first, fall back to StateCf
        // only if no history entry is found. Inverted order matters — at
        // high retention depths most keys have a history entry within
        // `[V, current]`, so returning early from the history seek avoids
        // the StateCf read entirely. If no entry exists, K was unchanged
        // since V and StateCf is the correct answer.
        //
        // StateHistoryCf key encoding is `key_bytes ++ BE8(version)`,
        // so `seek(K ++ BE8(V+1))` lands on the first entry for K
        // strictly after V (or the next key's first entry if K has no
        // entries after V).
        let history_cf = StateHistoryCf::handle(&cf);
        let key_bytes = key.to_bytes();
        let mut seek_target = key_bytes.to_vec();
        seek_target.extend_from_slice(&(self.version + 1).to_be_bytes());

        let mut iter = self.db.raw_iterator_cf_opt(history_cf, self.read_opts());
        iter.seek(&seek_target);

        if iter.valid()
            && let Some(raw_key) = iter.key()
        {
            // Entry must still belong to this key's prefix group.
            if raw_key.len() == key_bytes.len() + VERSION_LEN
                && &raw_key[..key_bytes.len()] == key_bytes.as_slice()
            {
                let value_codec: HborCodec<Option<Vec<u8>>> = HborCodec::default();
                return value_codec.decode(iter.value().unwrap_or_default());
            }
        }

        // No history entry for K after V → K unchanged since V → StateCf
        // is authoritative. This is the only path that pays for both a
        // history seek and a StateCf read.
        get::<StateCf>(&self.snapshot, state_cf, &key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if lo > hi || limit == 0 {
            return Vec::new();
        }
        let cf = CfHandles::resolve(self.db);
        let entries_cf = EntriesCf::handle(&cf);
        let at_tip = self.version >= self.current_version;

        // At the tip the interval's current rows are the answer, so the
        // walk stops at the limit.
        if at_tip {
            return scan_entries(
                self.db.raw_iterator_cf_opt(entries_cf, self.read_opts()),
                owner,
                collection,
                lo,
                hi,
                Some(limit),
            );
        }

        // Historically the current rows are the base the history
        // overlay corrects: for each order with history rows after V,
        // the value at V is the prior of the smallest such row — the
        // per-key rule `cell` applies, per order over the interval. The
        // two iterators walk in lockstep by order, so the walk stops at
        // `limit` visible entries and touches no row past the last one
        // returned, whatever the interval holds beyond it.
        let (start, end) = entry_range_bounds(owner, collection, lo, hi);
        let history_cf = EntriesHistoryCf::handle(&cf);
        let value_codec: HborCodec<Option<Vec<u8>>> = HborCodec::default();
        let mut current = self.db.raw_iterator_cf_opt(entries_cf, self.read_opts());
        let mut history = self.db.raw_iterator_cf_opt(history_cf, self.read_opts());
        current.seek(&start);
        history.seek(&start);
        let mut visible = Vec::with_capacity(limit);
        while visible.len() < limit {
            let head = bounded(current.key(), &end).map(|raw| EntryKeyCodec.decode(raw).order);
            let rewritten =
                bounded(history.key(), &end).map(|raw| VersionedEntryKeyCodec.decode(raw).0.order);
            let order = match (head, rewritten) {
                (Some(head), Some(rewritten)) => head.min(rewritten),
                (Some(head), None) => head,
                (None, Some(rewritten)) => rewritten,
                (None, None) => break,
            };
            // Every history row of this order: rows at or before V are
            // writes the current row already reflects; the first past V
            // holds the value at V.
            let mut prior: Option<Option<Vec<u8>>> = None;
            while let Some(raw) = bounded(history.key(), &end) {
                let (key, version) = VersionedEntryKeyCodec.decode(raw);
                if key.order != order {
                    break;
                }
                if version > self.version && prior.is_none() {
                    prior = Some(value_codec.decode(history.value().unwrap_or_default()));
                }
                history.next();
            }
            let now = if head == Some(order) {
                let value = current.value().unwrap_or_default().to_vec();
                current.next();
                Some(value)
            } else {
                None
            };
            if let Some(value) = prior.unwrap_or(now) {
                visible.push((order, value));
            }
        }
        visible
    }
}

/// `raw` where it is a key inside the interval ending at `end`, or
/// nothing where the iterator has run out or past it.
fn bounded<'a>(raw: Option<&'a [u8]>, end: &[u8]) -> Option<&'a [u8]> {
    raw.filter(|raw| *raw < end)
}
