//! The retention floor over the version-time column.

use hyperscale_storage::retire_dated;
use hyperscale_types::WeightedTimestamp;
use rocksdb::WriteBatch;

use super::column_families::VersionTimeCf;
use super::core::RocksDbShardStorage;
use super::metadata::{read_retention_floor, write_retention_floor};
use crate::typed_cf::{self, ReadableStore, TypedCf};

/// The oldest version `store` answers historical reads at.
///
/// Read through whatever view the caller already holds: a reader that
/// took a snapshot and then consulted the live floor could be told a
/// version is retained by one and gone by the other.
pub fn retention_floor(store: &impl ReadableStore) -> u64 {
    read_retention_floor(store)
}

impl RocksDbShardStorage {
    /// The oldest version this store answers historical reads at.
    #[must_use]
    pub(crate) fn retention_floor(&self) -> u64 {
        read_retention_floor(&*self.db)
    }

    /// Date `version` with the weighted timestamp of the QC that
    /// certified it, and move the floor past what that retires
    /// ([`retire_dated`]).
    ///
    /// Written into the batch that advances the tree, so a version is
    /// dated atomically with the state it commits: a date with no tree at
    /// that version, or the reverse, would leave the floor ruling on a
    /// version that does not exist.
    ///
    /// Returns the floor this commit establishes, which is what anything
    /// else pruning in the same batch cuts at: reading it back off the
    /// store would give the floor before this commit and cut a version
    /// short.
    pub(crate) fn advance_retention_floor(
        &self,
        batch: &mut WriteBatch,
        version: u64,
        tip_ts: WeightedTimestamp,
    ) -> u64 {
        let cf = self.cf();
        let handle = VersionTimeCf::handle(&cf);
        typed_cf::batch_put::<VersionTimeCf>(batch, handle, &version, &tip_ts.as_millis());
        let floor = read_retention_floor(&*self.db);
        let retired = retire_dated(
            floor,
            version,
            tip_ts,
            typed_cf::iter_from::<VersionTimeCf>(&self.db, handle, &floor),
        );
        for dated in &retired.versions {
            typed_cf::batch_delete::<VersionTimeCf>(batch, handle, dated);
        }
        write_retention_floor(batch, retired.floor);
        retired.floor
    }
}
