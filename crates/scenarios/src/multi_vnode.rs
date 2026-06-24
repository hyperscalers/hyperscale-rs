//! Multi-vnode hosting scenarios.
//!
//! Several vnodes share one host's `io_loop`: it fans inbound events to each and
//! dispatches their votes independently. This scenario asserts that the sharing
//! does not stall consensus.

use hyperscale_types::ShardId;

use crate::wait::await_height;
use crate::{Cluster, epochs};

/// Same-shard multi-vnode hosting makes consensus progress.
///
/// With several vnodes of one shard on a host, the single `io_loop` fans inbound
/// events to each vnode and dispatches their votes with per-vnode keys, sharing
/// one `ShardIo`. This must not stall consensus: the root commits past genesis
/// and keeps climbing. The vnode count is a property of the harness config; the
/// body asserts only that committed height advances.
///
/// Cross-shard multi-vnode hosting — one `io_loop` servicing a vnode in each of
/// two shards — arises organically after a split and is exercised by
/// [`cross_shard_tx`](crate::cross_shard_tx), whose transfer settles only when
/// both co-hosted children stay live.
///
/// # Panics
///
/// Panics if the root does not commit past genesis or stops advancing within
/// budget.
pub fn multi_vnode_progress(c: &mut impl Cluster) {
    let root = ShardId::ROOT;

    assert!(
        await_height(c, root, 2, epochs(6)),
        "the root must commit past genesis under same-shard multi-vnode hosting",
    );
    let base = c.committed_height(root).expect("the root commits");
    assert!(
        c.run_until(epochs(6), |c| c
            .committed_height(root)
            .is_some_and(|h| h > base)),
        "the root must keep committing under same-shard multi-vnode hosting",
    );
}
