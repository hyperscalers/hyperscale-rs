//! What a sibling reads of a member a recovery released, over the lines
//! a block names for its row and a store that folds them.
//!
//! The lines are the ones [`member_lines`] names and the readings are
//! proven against a store's committed roots, so the abort a released
//! row's deadline licenses is held to the exit its sibling reads: the
//! row and its verdict cell absent beside the committed marker.

use std::collections::BTreeSet;

use hyperscale_engine::tick_select::{CommittedSets, member_lines};
use hyperscale_storage::test_helpers::test_a_sibling_reads_a_released_rows_abort_as_an_exit;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::Evidence;

#[test]
fn a_sibling_reads_a_released_rows_abort_as_an_exit() {
    let storage = SimShardStorage::default();
    test_a_sibling_reads_a_released_rows_abort_as_an_exit(&storage, &|rows, anchor| {
        let (lines, missing, _) = member_lines(
            rows,
            anchor,
            &CommittedSets::default(),
            &|_| Evidence::Live { terminating: false },
            None,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty());
        lines
    });
}
