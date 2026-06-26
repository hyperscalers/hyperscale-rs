//! Reshape lifecycle scenarios.

use std::sync::Arc;

use hyperscale_types::ShardId;
use radix_common::network::NetworkDefinition;

use crate::grow::vote_reshape_threshold;
use crate::tx::{account_from_seed, build_faucet_tx, signer_from_seed, validity_around};
use crate::wait::{
    assert_height_frozen, await_height, await_merge_keeper_count, await_root_matches_anchor,
    await_serves, await_split_admitted,
};
use crate::{Cluster, epochs};

/// Reshape `split_bytes` the vote installs after the grow. Its derived
/// `merge_bytes = split_bytes / 8` sits far above each cold child's byte total,
/// so both assert the merge once the change activates, while staying far above
/// them so neither re-splits.
const MERGE_VOTE_SPLIT_BYTES: u64 = 80_000_000;

/// Arm an organic split of the root shard and drive it to completion.
///
/// The beacon admits the split from the armed trigger, both children are served
/// and commit past genesis at the beacon-composed anchor root, and the parent
/// terminates. Requires a config with `split_bytes = 0` and one cohort of pool
/// surplus.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn split_lifecycle(c: &mut impl Cluster) {
    let root = ShardId::ROOT;
    let (left, right) = root.children();

    assert!(
        await_split_admitted(c, root, epochs(8)),
        "beacon did not admit the root split within budget"
    );

    // Keep the parent committing through its final window: a real transfer
    // gives it activity so it coasts to its crossing and the fold seeds both
    // children from the terminal contribution.
    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    c.submit(Arc::new(transfer));

    assert!(
        await_serves(c, left, epochs(28)) && await_serves(c, right, epochs(28)),
        "both split children were not served within budget"
    );
    assert!(
        await_height(c, left, 1, epochs(8)) && await_height(c, right, 1, epochs(8)),
        "split children did not commit past genesis within budget"
    );
    assert!(
        await_root_matches_anchor(c, left, epochs(8))
            && await_root_matches_anchor(c, right, epochs(8)),
        "split child roots did not match the beacon anchor within budget"
    );
    assert_height_frozen(c, root, epochs(2));
}

/// Grow the root into two shards, then merge the two cold children back into it.
///
/// Composes [`split_lifecycle`] for the grow, then votes the reshape threshold
/// up so the children fall under the derived merge threshold — a grown topology
/// can't merge under the frozen threshold that split it, so the vote is the
/// honest trigger. The beacon pairs the merge and draws the keeper committee,
/// the keepers seat the reformed parent, and its committed root reproduces the
/// beacon-composed anchor. Requires a config with `split_bytes = 0`, one cohort
/// of pool surplus, and a funded straddler account (`31`) to pay the vote.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn merge_lifecycle(c: &mut impl Cluster) {
    let root = ShardId::ROOT;

    split_lifecycle(c);

    // Vote the reshape threshold up so the cold grown children fall under the
    // derived merge threshold. The straddler account `31`, funded at genesis and
    // seated on a child by the grow, pays the system-action fee.
    vote_reshape_threshold(c, &signer_from_seed(31), MERGE_VOTE_SPLIT_BYTES);

    // The vote activates, both children assert the merge, and the beacon pairs
    // it — drawing a quorum (2f+1 of the four-validator merged committee).
    assert!(
        await_merge_keeper_count(c, root, 3, epochs(20)),
        "the merge did not pair a keeper quorum within budget"
    );
    // The keepers seat the reformed parent, which commits past its merged
    // genesis at the beacon-composed anchor root.
    assert!(
        await_serves(c, root, epochs(28)),
        "the merged parent was not served within budget"
    );
    assert!(
        await_height(c, root, 1, epochs(8)),
        "the merged parent did not commit past genesis within budget"
    );
    assert!(
        await_root_matches_anchor(c, root, epochs(8)),
        "the merged root did not match the beacon anchor within budget"
    );
}
