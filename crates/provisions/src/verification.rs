//! Judge inbound (part, header) pairs before their proofs are checked.
//!
//! The source block's `provision_tx_roots[local_shard]` commits to the
//! ordered leaves the target shard is meant to receive and to their
//! count, each leaf binding its transaction to the keys its part serves.
//! A part whose leaf, recomputed from the keys it carries, does not walk
//! its path to that root, or one
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        BlockHeader, BlockHeaderParts, BlockHeight, ChainOrigin, Hash, LeafPath,
        MerkleInclusionProof, ProvisionParts, QuorumCertificate, TxHash, WeightedTimestamp,
        provision_leaf, served_digest,
    };

    use super::*;

    const SOURCE: ShardId = ShardId::leaf(1, 0);
    const LOCAL: ShardId = ShardId::leaf(1, 1);

    /// A keyless part for `tx` stating `clock`, its leaf the one leaf of
    /// its root.
    fn part(tx: TxHash, clock: WeightedTimestamp) -> Provision {
        Provision::new(ProvisionParts {
            source_shard: SOURCE,
            target_shard: LOCAL,
            block_height: BlockHeight::new(3),
            source_block_ts: WeightedTimestamp::from_millis(9_000),
            clock,
            tx_hash: tx,
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(Vec::new()),
            leaf: LeafPath {
                count: 1,
                index: 0,
                siblings: Capped::empty(),
            },
        })
    }

    /// A part stating another clock than the one its source's root binds
    /// for its transaction walks to another root and is refused; the
    /// part stating the bound clock is owed. The rooting block's own
    /// clock is neither.
    #[test]
    fn a_part_whose_clock_is_not_its_leafs_fails() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let committed = WeightedTimestamp::from_millis(5_000);
        let leaf = provision_leaf(tx, committed, served_digest(std::iter::empty()));
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: SOURCE,
            height: BlockHeight::new(3),
            provision_tx_roots: Capped::new(BTreeMap::from([(
                LOCAL,
                ProvisionTxRoot::over(&[leaf]),
            )]))
            .expect("one target"),
            ..Default::default()
        });
        let certified = Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header,
            QuorumCertificate::genesis(SOURCE, ChainOrigin::root(WeightedTimestamp::ZERO)),
        ));

        assert_eq!(judge_owed(LOCAL, &part(tx, committed), &certified), Ok(()));
        for other in [5_001, 9_000] {
            assert_eq!(
                judge_owed(
                    LOCAL,
                    &part(tx, WeightedTimestamp::from_millis(other)),
                    &certified
                ),
                Err(ProvisionRefusal::ContentMismatch),
                "a part stating {other} ms",
            );
        }
    }
}
