//! Judge an inbound (provisions, header) pair before its proof is checked.
//!
//! The source block's `provision_tx_roots[local_shard]` commits to the
//! ordered tx hashes the target shard is meant to receive. A bundle whose
//! transactions compute another root, or one from a header that owes this
//! shard nothing, is refused with a verdict: the refusal releases every
//! fetch that could have carried it as failed, so another peer is asked,
//! and leaves the expectation armed.
//!
//! The QC was already verified by `RemoteHeaderCoordinator`, so the
//! emitted `VerifyProvisions` action only needs to check merkle proofs
//! against the committed state root.

use hyperscale_core::{Action, ProtocolEvent, ProvisionAction, ProvisionRefusal};
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_types::{
    Anchor, CertifiedBlockHeader, Hash, ProvisionTxRoot, Provisions, ShardId, Verified,
    compute_merkle_root,
};

/// Hold `provisions`' transactions to the root `certified_header` commits
/// for `local_shard`.
///
/// # Errors
///
/// [`ProvisionRefusal::NotOwed`] when the header commits nothing to
/// `local_shard`; [`ProvisionRefusal::ContentMismatch`] when the
/// transactions compute another root.
pub fn judge_owed(
    local_shard: ShardId,
    provisions: &Provisions,
    certified_header: &Verified<CertifiedBlockHeader>,
) -> Result<(), ProvisionRefusal> {
    let Some(expected_root) = certified_header
        .header()
        .provision_tx_roots()
        .get(&local_shard)
        .copied()
    else {
        record_fetch_response_refused("provision", "content_mismatch");
        return Err(ProvisionRefusal::NotOwed);
    };

    let leaves: Vec<Hash> = provisions
        .transactions()
        .iter()
        .map(|t| Hash::from(t.tx_hash))
        .collect();
    if ProvisionTxRoot::from_raw(compute_merkle_root(&leaves)) != expected_root {
        record_fetch_response_refused("provision", "content_mismatch");
        return Err(ProvisionRefusal::ContentMismatch);
    }
    Ok(())
}

/// The verdict refusing `provisions` checked against `anchor`.
#[must_use]
pub const fn refused(provisions: Provisions, refusal: ProvisionRefusal, anchor: Anchor) -> Action {
    Action::Continuation(ProtocolEvent::StateProvisionsVerified {
        result: Err((provisions, refusal)),
        anchor,
    })
}

/// Emit a `VerifyProvisions` action for a bundle its header owes, or the
/// verdict refusing it.
#[must_use]
pub fn build_verify_action(
    local_shard: ShardId,
    provisions: Provisions,
    certified_header: &Verified<CertifiedBlockHeader>,
) -> Action {
    let anchor = Anchor::of(certified_header);
    match judge_owed(local_shard, &provisions, certified_header) {
        Ok(()) => Action::Provisions(ProvisionAction::VerifyProvisions { provisions, anchor }),
        Err(refusal) => refused(provisions, refusal, anchor),
    }
}
