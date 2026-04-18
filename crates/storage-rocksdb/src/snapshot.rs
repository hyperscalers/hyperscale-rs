//! MVCC-aware RocksDB snapshot: reads return values as of a specific version.
//!
//! Reads land on the floor entry directly via `seek_for_prev` rather than
//! walking all versions of a substate. This keeps `get` at O(log N) on the
//! CF regardless of how many historical versions a key has accumulated —
//! important for hot keys where the retention window fills up with
//! hundreds of versions.

use crate::column_families::{CfHandles, StateCf};
use crate::substate_key;
use crate::typed_cf::TypedCf;
use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use rocksdb::{ReadOptions, Snapshot, DB};

/// Length of the version suffix on each state-CF key (`u64` big-endian).
const VERSION_LEN: usize = 8;

/// RocksDB snapshot scoped to a specific JMT version.
///
/// Every read returns the substate value as of `version`. Tombstones (empty
/// values) correctly resolve to `None`.
pub struct RocksDbSnapshot<'a> {
    pub(crate) snapshot: Snapshot<'a>,
    pub(crate) db: &'a DB,
    pub(crate) version: u64,
}

impl RocksDbSnapshot<'_> {
    /// Build a read_opts that pins this snapshot. Required so raw
    /// iterators observe our point-in-time view rather than the live DB.
    fn read_opts(&self) -> ReadOptions {
        let mut opts = ReadOptions::default();
        opts.set_snapshot(&self.snapshot);
        opts
    }
}

impl SubstateDatabase for RocksDbSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let cf = CfHandles::resolve(self.db);
        let state_cf = StateCf::handle(&cf);

        // Seek to (storage_key, target_version). `seek_for_prev` lands on
        // the largest key ≤ seek target, which — if still within this
        // substate's prefix — is the floor entry for our version.
        let storage_key = substate_key::substate_prefix(partition_key, sort_key);
        let mut seek_target = storage_key.clone();
        seek_target.extend_from_slice(&self.version.to_be_bytes());

        let mut iter = self.db.raw_iterator_cf_opt(state_cf, self.read_opts());
        iter.seek_for_prev(&seek_target);

        let raw_key = iter.key()?;
        // The entry must belong to this storage_key. If seek_for_prev
        // walked into a different substate (or off the CF entirely), we
        // have nothing at or below our version.
        if raw_key.len() != storage_key.len() + VERSION_LEN
            || &raw_key[..storage_key.len()] != storage_key.as_slice()
        {
            return None;
        }

        let value = iter.value()?;
        if value.is_empty() {
            None // tombstone
        } else {
            Some(value.to_vec())
        }
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        // Per-substate seek_for_prev: walk unique substate keys within the
        // partition and jump directly to each one's floor entry at our
        // target version. Avoids scanning every historical version.
        let cf = CfHandles::resolve(self.db);
        let state_cf = StateCf::handle(&cf);

        let partition_prefix = substate_key::partition_prefix(partition_key);
        let prefix_len = partition_prefix.len();
        let start = match from_sort_key {
            Some(sk) => {
                let mut s = partition_prefix.clone();
                s.extend_from_slice(&sk.0);
                s
            }
            None => partition_prefix.clone(),
        };

        let mut iter = self.db.raw_iterator_cf_opt(state_cf, self.read_opts());
        iter.seek(&start);

        let mut results: Vec<PartitionEntry> = Vec::new();
        let target = self.version;

        while iter.valid() {
            let raw_key = match iter.key() {
                Some(k) => k,
                None => break,
            };

            // Out of partition → done.
            if !raw_key.starts_with(&partition_prefix) {
                break;
            }
            if raw_key.len() < VERSION_LEN {
                iter.next();
                continue;
            }

            // storage_key = raw_key minus the 8-byte version suffix.
            let storage_key_len = raw_key.len() - VERSION_LEN;
            let storage_key = raw_key[..storage_key_len].to_vec();

            // Seek to this substate's floor at target_version.
            let mut seek_target = storage_key.clone();
            seek_target.extend_from_slice(&target.to_be_bytes());
            iter.seek_for_prev(&seek_target);

            if let (Some(found_raw), Some(found_val)) = (iter.key(), iter.value()) {
                if found_raw.len() == storage_key.len() + VERSION_LEN
                    && &found_raw[..storage_key.len()] == storage_key.as_slice()
                    && !found_val.is_empty()
                {
                    let sort_key_bytes = storage_key[prefix_len..].to_vec();
                    results.push((DbSortKey(sort_key_bytes), found_val.to_vec()));
                }
            }

            // Advance past all versions of this storage_key. The next
            // lexicographic prefix steps us onto the first entry of a
            // different substate (or out of the partition).
            match next_lex_prefix(&storage_key) {
                Some(next) => iter.seek(&next),
                None => break, // storage_key was all 0xFF — nothing beyond
            }
        }

        Box::new(results.into_iter())
    }
}

/// Return the lexicographic successor of `prefix`, or `None` if `prefix`
/// is all-0xFF (no successor exists).
fn next_lex_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    for i in (0..out.len()).rev() {
        if out[i] < 0xff {
            out[i] += 1;
            out.truncate(i + 1);
            return Some(out);
        }
    }
    None
}
