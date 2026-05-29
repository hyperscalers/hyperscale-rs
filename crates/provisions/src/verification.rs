//! Build the `VerifyProvisions` action for an inbound (provisions, header) pair.
//!
//! Runs the provisions completeness check first: the source block's
//! `provision_tx_roots[local_shard]` commits to the ordered tx hashes the
//! target shard is meant to receive. A mismatch means the proposer
//! dropped txs on the broadcast path (or the provisions were tampered
//! with) — reject entirely so the fallback timer refetches a complete
//! set from a peer.
//!
//! The QC was already verified by `RemoteHeaderCoordinator`, so the
//! emitted `VerifyProvisions` action only needs to check merkle proofs
//! against the committed state root.

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    CertifiedBlockHeader, Hash, ProvisionTxRoot, Provisions, ShardGroupId, Verified,
    compute_merkle_root,
};
use tracing::warn;

/// Validate the tx-root and emit a `VerifyProvisions` action, or `None` if
/// the provisions don't match the source header's commitment.
pub fn build_verify_action(
    local_shard: ShardGroupId,
    provisions: Provisions,
    certified_header: Arc<Verified<CertifiedBlockHeader>>,
) -> Option<Action> {
    let Some(expected_root) = certified_header
        .header()
        .provision_tx_roots()
        .get(&local_shard)
        .copied()
    else {
        warn!(
            source_shard = provisions.source_shard().inner(),
            block_height = provisions.block_height().inner(),
            local_shard = local_shard.inner(),
            "Dropping provisions: source header has no provision_tx_root for us"
        );
        return None;
    };

    let leaves: Vec<Hash> = provisions
        .transactions()
        .iter()
        .map(|t| t.tx_hash.into_raw())
        .collect();
    let computed_root = ProvisionTxRoot::from_raw(compute_merkle_root(&leaves));

    if computed_root != expected_root {
        warn!(
            source_shard = provisions.source_shard().inner(),
            block_height = provisions.block_height().inner(),
            local_shard = local_shard.inner(),
            tx_count = provisions.transactions().len(),
            ?expected_root,
            ?computed_root,
            "Rejecting incomplete provisions — tx-root mismatch; \
             fallback fetch will request a complete set"
        );
        return None;
    }

    Some(Action::VerifyProvisions {
        provisions,
        certified_header,
    })
}
