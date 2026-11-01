//! Judge inbound (part, header) pairs before their proofs are checked.
//!
//! The source block's `provision_tx_roots[local_shard]` commits to the
//! ordered leaves the target shard is meant to receive and to their
//! count. A part whose leaf does not walk its path to that root, or one
//! from a header that owes this shard nothing, is refused with a
//! verdict: the refusal releases every fetch that could have carried it
//! as failed, so another peer is asked, and leaves the expectation
//! armed.
//!
//! The QC was already verified by `RemoteHeaderCoordinator`, so the
//! emitted `VerifyProvisions` action only needs to check merkle proofs
//! against the committed state root.

use hyperscale_core::{Action, ProtocolEvent, ProvisionAction, ProvisionRefusal, ProvisionVerdict};
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_types::{
    Anchor, CertifiedBlockHeader, Provision, ProvisionTxRoot, ShardId, Verified,
};

/// Hold `part`'s leaf to the root `certified_header` commits for
/// `local_shard`.
///
/// # Errors
///
/// [`ProvisionRefusal::NotOwed`] when the header commits nothing to
/// `local_shard`; [`ProvisionRefusal::ContentMismatch`] when the leaf
/// does not walk its path to the committed root.
pub fn judge_owed(
    local_shard: ShardId,
    part: &Provision,
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

    if ProvisionTxRoot::through(part.leaf_hash(), part.leaf()) != Some(expected_root) {
        record_fetch_response_refused("provision", "content_mismatch");
        return Err(ProvisionRefusal::ContentMismatch);
    }
    Ok(())
}

/// The verdict refusing `refused` checked against `anchor`.
#[must_use]
pub const fn refused(refused: Vec<ProvisionVerdict>, anchor: Anchor) -> Action {
    Action::Continuation(ProtocolEvent::StateProvisionsVerified {
        results: refused,
        anchor,
    })
}

/// One `VerifyProvisions` action for the parts of `parts` their header
/// owes, and the verdict refusing the rest.
#[must_use]
pub fn build_verify_actions(
    local_shard: ShardId,
    parts: Vec<Provision>,
    certified_header: &Verified<CertifiedBlockHeader>,
) -> Vec<Action> {
    let anchor = Anchor::of(certified_header);
    let mut owed = Vec::new();
    let mut refusals = Vec::new();
    for part in parts {
        match judge_owed(local_shard, &part, certified_header) {
            Ok(()) => owed.push(part),
            Err(refusal) => refusals.push(Err((part, refusal))),
        }
    }
    let mut actions = Vec::with_capacity(2);
    if !owed.is_empty() {
        actions.push(Action::Provisions(ProvisionAction::VerifyProvisions {
            parts: owed,
            anchor,
        }));
    }
    if !refusals.is_empty() {
        actions.push(refused(refusals, anchor));
    }
    actions
}
