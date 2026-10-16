//! What a sibling reads of a member a recovery released, over the lines
//! a block names for its row and a store that folds them.
//!
//! The lines are the ones [`member_lines`] names and the readings are
//! proven against a store's committed roots, so the abort a released
//! row that ran takes at once is held to the exit its sibling reads: the
//! row and its verdict cell absent beside the committed marker.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_engine::tick_select::{CommittedSets, member_lines};
use hyperscale_jmt::NibblePath;
use hyperscale_storage::MemberIndex;
use hyperscale_storage::test_helpers::test_a_sibling_reads_a_released_rows_abort_as_an_exit;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{Evidence, TickLine, WeightedTimestamp};
use tempfile::TempDir;

/// The lines a block names for `rows`, with every sibling live.
fn named(rows: &MemberIndex, anchor: WeightedTimestamp) -> Vec<TickLine> {
    let (lines, missing, _) = member_lines(
        rows,
        anchor,
        &CommittedSets::default(),
        &|_, _| Evidence::Live { terminating: false },
        false,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(missing.is_empty());
    lines
}

#[test]
fn a_sibling_reads_a_released_rows_abort_as_an_exit() {
    let storage = SimShardStorage::default();
    test_a_sibling_reads_a_released_rows_abort_as_an_exit(&storage, &named);
}

#[test]
fn a_sibling_reads_a_released_rows_abort_as_an_exit_on_rocksdb() {
    let dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).unwrap();
    test_a_sibling_reads_a_released_rows_abort_as_an_exit(&storage, &named);
}
