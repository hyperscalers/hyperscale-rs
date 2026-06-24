//! Reshape lifecycle scenarios.

use std::sync::Arc;

use hyperscale_types::ShardId;
use radix_common::network::NetworkDefinition;

use crate::tx::{account_from_seed, build_faucet_tx, signer_from_seed, validity_around};
use crate::wait::{
    assert_height_frozen, await_height, await_root_matches_anchor, await_serves,
    await_split_admitted,
};
use crate::{Cluster, epochs};

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
