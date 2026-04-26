//! State-history-based `RocksDB` snapshot.
//!
//! Current-tip reads are a direct point lookup on `StateCf`. Historical
//! reads at version V use a single forward seek on `StateHistoryCf` to
//! find the smallest entry `(K, v')` with `v' > V`; its stored prior
//! value is the value at V. If no such entry exists, `StateCf[K]` was
//! stable since V and is the answer.

use crate::column_families::{CfHandles, StateCf, StateHistoryCf};
use crate::substate_key;
use crate::typed_cf::{DbCodec, SborCodec, TypedCf};
use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use hyperscale_types::NodeId;
use rocksdb::{DB, ReadOptions, Snapshot};
use std::collections::HashMap;

/// Length of the version suffix on each state-history key (`u64` big-endian).
const VERSION_LEN: usize = 8;

/// Point-in-time `RocksDB` snapshot scoped to a specific version within
/// the retention window. Retention enforcement happens at construction
/// in `RocksDbStorage::snapshot_at`.
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

    /// Shared 2-pass algorithm: list `(storage_key, value)` pairs for
    /// all keys under `prefix` at `self.version`. Returns live
    /// (non-tombstoned) entries sorted by `storage_key` ascending.
    fn list_at_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cf = CfHandles::resolve(self.db);
        let state_cf = StateCf::handle(&cf);

        if self.version >= self.current_version {
            // Trivial: direct prefix scan on StateCf.
            return crate::typed_cf::prefix_iter_snap::<StateCf>(&self.snapshot, state_cf, prefix)
                .map(|((pk, sk), value)| {
                    let mut k = pk.node_key;
                    k.push(pk.partition_num);
                    k.extend_from_slice(&sk.0);
                    (k, value)
                })
                .collect();
        }

        let history_cf = StateHistoryCf::handle(&cf);
        let mut value_at_v: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();

        // Pass 1: scan StateHistoryCf for the prefix. Entries ordered by
        // (storage_key asc, version asc); for each storage_key the
        // first entry with v' > version is the smallest — that's the
        // one that captured value-at-version.
        let mut history_iter = self.db.raw_iterator_cf_opt(history_cf, self.read_opts());
        history_iter.seek(prefix);
        let value_codec: SborCodec<Option<Vec<u8>>> = SborCodec::default();
        while history_iter.valid() {
            let Some(raw_key) = history_iter.key() else {
                break;
            };
            if !raw_key.starts_with(prefix) {
                break;
            }
            if raw_key.len() < VERSION_LEN {
                history_iter.next();
                continue;
            }
            let storage_key_len = raw_key.len() - VERSION_LEN;
            let storage_key = raw_key[..storage_key_len].to_vec();
            let v_prime =
                u64::from_be_bytes(raw_key[storage_key_len..].try_into().expect("u64 suffix"));
            if v_prime <= self.version {
                history_iter.next();
                continue;
            }
            let prior = value_codec.decode(history_iter.value().unwrap_or_default());
            value_at_v.entry(storage_key).or_insert(prior);
            history_iter.next();
        }
        if let Err(e) = history_iter.status() {
            panic!("BFT CRITICAL: state-history iterator error: {e}");
        }

        // Pass 2: fill in unchanged keys from StateCf.
        for ((pk, sk), value) in
            crate::typed_cf::prefix_iter_snap::<StateCf>(&self.snapshot, state_cf, prefix)
        {
            let mut k = pk.node_key;
            k.push(pk.partition_num);
            k.extend_from_slice(&sk.0);
            value_at_v.entry(k).or_insert(Some(value));
        }

        let mut out: Vec<_> = value_at_v
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    /// Entity-scoped list used by cross-shard provisioning.
    /// Decomposes each `storage_key` into `(partition_num, sort_key, value)`.
    #[must_use]
    pub fn list_raw_values_for_node(&self, node_id: &NodeId) -> Vec<(u8, DbSortKey, Vec<u8>)> {
        let entity_key = substate_key::node_entity_key(node_id);
        let entity_len = entity_key.len();
        self.list_at_prefix(&entity_key)
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() <= entity_len {
                    return None;
                }
                let partition_num = k[entity_len];
                let sort_key = DbSortKey(k[entity_len + 1..].to_vec());
                Some((partition_num, sort_key, v))
            })
            .collect()
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
        let state_key = (partition_key.clone(), sort_key.clone());

        // Current-tip fast path: single StateCf read, no history seek.
        if self.version >= self.current_version {
            return crate::typed_cf::get::<StateCf>(&self.snapshot, state_cf, &state_key);
        }

        // Historical path: try StateHistoryCf first, fall back to StateCf
        // only if no history entry is found. Inverted order matters — at
        // high retention depths most keys have a history entry within
        // `[V, current]`, so returning early from the history seek avoids
        // the StateCf read entirely. If no entry exists, K was unchanged
        // since V and StateCf is the correct answer.
        //
        // StateHistoryCf key encoding is `storage_key ++ BE8(version)`,
        // so `seek(K ++ BE8(V+1))` lands on the first entry for K
        // strictly after V (or the next storage_key's first entry if K
        // has no entries after V).
        let history_cf = StateHistoryCf::handle(&cf);
        let storage_key_bytes = substate_key::substate_prefix(partition_key, sort_key);
        let mut seek_target = storage_key_bytes.clone();
        seek_target.extend_from_slice(&(self.version + 1).to_be_bytes());

        let mut iter = self.db.raw_iterator_cf_opt(history_cf, self.read_opts());
        iter.seek(&seek_target);

        if iter.valid()
            && let Some(raw_key) = iter.key()
        {
            // Entry must still belong to this storage_key's prefix group.
            if raw_key.len() == storage_key_bytes.len() + VERSION_LEN
                && &raw_key[..storage_key_bytes.len()] == storage_key_bytes.as_slice()
            {
                let value_codec: SborCodec<Option<Vec<u8>>> = SborCodec::default();
                return value_codec.decode(iter.value().unwrap_or_default());
            }
        }

        // No history entry for K after V → K unchanged since V → StateCf
        // is authoritative. This is the only path that pays for both a
        // history seek and a StateCf read.
        crate::typed_cf::get::<StateCf>(&self.snapshot, state_cf, &state_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = substate_key::partition_prefix(partition_key);
        let prefix_len = prefix.len();
        let entries: Vec<_> = self
            .list_at_prefix(&prefix)
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() < prefix_len {
                    return None;
                }
                let sort_key = DbSortKey(k[prefix_len..].to_vec());
                if let Some(from) = from_sort_key
                    && sort_key < *from
                {
                    return None;
                }
                Some((sort_key, v))
            })
            .collect();
        Box::new(entries.into_iter())
    }
}
