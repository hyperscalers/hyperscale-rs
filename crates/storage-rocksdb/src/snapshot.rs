//! MVCC-aware RocksDB snapshot: reads return values as of a specific version.
//!
//! Reads walk the `versioned_substates` CF and take the latest write at or
//! below the snapshot's target version. Used both for current-state reads
//! (via `snapshot_at(jmt_version())`) and anchor-based reads from
//! [`SubstateView`](hyperscale_storage::SubstateView).

use crate::column_families::{CfHandles, VersionedSubstatesCf};
use crate::substate_key;
use crate::typed_cf::{self, TypedCf};
use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use rocksdb::{Snapshot, DB};

/// RocksDB snapshot scoped to a specific JMT version.
///
/// Every read returns the substate value as of `version`. Tombstones (empty
/// values in `versioned_substates`) correctly resolve to `None`.
pub struct RocksDbSnapshot<'a> {
    pub(crate) snapshot: Snapshot<'a>,
    pub(crate) db: &'a DB,
    pub(crate) version: u64,
}

impl SubstateDatabase for RocksDbSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let versioned_cf = VersionedSubstatesCf::handle(&CfHandles::resolve(self.db));
        // Walk the single-substate version list in ascending order; keep the
        // latest version <= self.version (empty value = tombstone → None).
        let prefix = substate_key::substate_prefix(partition_key, sort_key);
        let mut best: Option<Vec<u8>> = None;
        for ((_key, version), value) in typed_cf::prefix_iter_snap::<VersionedSubstatesCf>(
            &self.snapshot,
            versioned_cf,
            &prefix,
        ) {
            if version > self.version {
                break;
            }
            best = if value.is_empty() { None } else { Some(value) };
        }
        best
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        // MVCC scan by partition prefix: group by (pk, sk), pick latest
        // version <= self.version per group. Collected eagerly since the
        // iterator has to do a stateful group-by over the MVCC rows anyway.
        let versioned_cf = VersionedSubstatesCf::handle(&CfHandles::resolve(self.db));
        let partition_prefix = substate_key::partition_prefix(partition_key);
        let start = match from_sort_key {
            Some(sk) => {
                let mut s = partition_prefix.clone();
                s.extend_from_slice(&sk.0);
                s
            }
            None => partition_prefix.clone(),
        };

        type SubstateKey = (DbPartitionKey, DbSortKey);
        let mut results: Vec<PartitionEntry> = Vec::new();
        let mut current_key: Option<SubstateKey> = None;
        let mut current_best: Option<Vec<u8>> = None;

        for ((substate_key, version), value) in
            typed_cf::prefix_iter_from_snap::<VersionedSubstatesCf>(
                &self.snapshot,
                versioned_cf,
                &partition_prefix,
                &start,
            )
        {
            if current_key.as_ref() != Some(&substate_key) {
                if let (Some((_pk, sk)), Some(val)) = (current_key.take(), current_best.take()) {
                    results.push((sk, val));
                }
                current_key = Some(substate_key);
                current_best = None;
            }
            if version <= self.version {
                current_best = if value.is_empty() { None } else { Some(value) };
            }
        }
        if let (Some((_pk, sk)), Some(val)) = (current_key, current_best) {
            results.push((sk, val));
        }

        Box::new(results.into_iter())
    }
}
