//! Shared provision construction.
//!
//! Both the gossip emit path ([`fetch_and_broadcast_provision`]) and the
//! fetch serve path (`build_served_parts` in the node crate) flow
//! through [`build_provisions_until`]. Keeping a single function means a
//! receiver absorbs byte-identical parts regardless of which transport
//! delivered them — any future field-ordering leak gets caught in one
//! place rather than drifting between two near-identical loops.
//!
//! [`fetch_and_broadcast_provision`]: crate::action_handlers::fetch_and_broadcast_provision

use std::ops::ControlFlow;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{SubstateStore, SubstateView, Substates, VersionedStore};
use hyperscale_types::network::encoded_len;
use hyperscale_types::{
    Hash, LeafPath, MAX_PROVISION_PART_BYTES, MerkleInclusionProof, Provision, ProvisionCount,
    ProvisionParts, ShardId, SubstateEntry, WeightedTimestamp, provision_leaf,
};
use tracing::warn;

use crate::content::{leaves_over_requests, served_keys};

/// The requests among `requests` that name `target_shard`, in order: one
/// leaf each under the source header's root for that target.
fn requests_for(
    requests: &[ProvisionsRequest],
    target_shard: ShardId,
) -> impl Iterator<Item = &ProvisionsRequest> {
    requests
        .iter()
        .filter(move |req| req.targets.contains(&target_shard))
}

/// The count witness for what `requests` owe `target_shard`.
///
/// Their leaf count and the merkle root over their leaves, or `None`
/// where they owe it nothing. Any holder of the block states it, whether
/// or not it can build a single part.
#[must_use]
pub fn provision_count(
    requests: &[ProvisionsRequest],
    target_shard: ShardId,
) -> Option<ProvisionCount> {
    leaves_over_requests(requests)
        .get(&target_shard)
        .map(|leaves| ProvisionCount::over(leaves))
}

/// Build the parts of a source → target pair whose leaf index `wanted`
/// names, in index order, out of `view`: the view anchored at the source
/// block itself, whose height every part names.
///
/// Each part stands alone: one whose reads the view does not hold at its
/// anchor, whose proof passes a decode cap, whose encoding passes
/// [`MAX_PROVISION_PART_BYTES`], or whose range reads name an entry with
/// no leaf is left out, and costs only its own transaction.
///
/// `requests` may name several target shards. Only those naming
/// `target_shard` participate, and their order is the leaf order.
#[must_use]
pub fn build_provisions<S>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    requests: &[ProvisionsRequest],
    wanted: impl Fn(u32) -> bool,
) -> Vec<Provision>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut parts = Vec::new();
    build_provisions_until(
        view,
        source_shard,
        target_shard,
        source_block_ts,
        requests,
        |index, build| {
            if wanted(index) {
                parts.extend(build());
            }
            ControlFlow::Continue(())
        },
    );
    parts
}

/// Offer each leaf index of what `requests` owe `target_shard` to
/// `take`, in index order, with a builder for its part, until `take`
/// breaks.
///
/// The builder answers [`build_provisions`]' part for that index, or
/// `None` where it is unbuildable, and runs only if `take` calls it: a
/// caller answering within a budget builds what it takes and nothing
/// past the point it stops.
pub fn build_provisions_until<S>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    requests: &[ProvisionsRequest],
    mut take: impl FnMut(u32, &mut dyn FnMut() -> Option<Provision>) -> ControlFlow<()>,
) where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let source_block_height = view.anchor_height();
    let state = view.served_snapshot();
    let owed: Vec<&ProvisionsRequest> = requests_for(requests, target_shard).collect();
    let leaves: Vec<Hash> = owed.iter().map(|req| provision_leaf(req.tx_hash)).collect();
    for (req, leaf) in owed.into_iter().zip(LeafPath::all(&leaves)) {
        let index = leaf.index;
        let mut leaf = Some(leaf);
        let mut build = || {
            let part = build_part(
                view,
                state.as_ref(),
                source_shard,
                target_shard,
                source_block_ts,
                req,
                leaf.take()?,
            );
            if part.is_none() {
                warn!(
                    source_shard = source_shard.inner(),
                    target_shard = target_shard.inner(),
                    block_height = source_block_height.inner(),
                    tx_hash = %req.tx_hash,
                    index,
                    "build_provisions: part unbuildable"
                );
            }
            part
        };
        if take(index, &mut build).is_break() {
            return;
        }
    }
}

/// One transaction's part at `leaf`, read out of `state`, the view's
/// reading at its anchor, and proven through the view's tree, or `None`
/// where it cannot be built. A keyless request reads nothing, so it
/// builds whether or not the view holds its anchor's state.
fn build_part<S>(
    view: &SubstateView<S>,
    state: Option<&impl Substates>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    req: &ProvisionsRequest,
    leaf: LeafPath,
) -> Option<Provision>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let source_block_height = view.anchor_height();
    let entries = if req.local_keys.is_empty() && req.local_ranges.is_empty() {
        Vec::new()
    } else {
        read_served(state?, source_shard, req)?
    };
    let proof = if entries.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else {
        // The view is the proof walk's tree reader: pending snapshots'
        // nodes over the base store, one root lookup for persisted and
        // unpersisted heights alike. `None` — the root or a node pruned
        // mid-walk, or a proof past a decode cap — leaves this part out,
        // never a wrong proof.
        let keys: Vec<_> = entries.iter().map(|entry| entry.key).collect();
        generate_proof(view, &keys, source_block_height)?
    };
    let part = Provision::new(ProvisionParts {
        source_shard,
        target_shard,
        block_height: source_block_height,
        source_block_ts,
        tx_hash: req.tx_hash,
        entries: Capped::new(entries).ok()?,
        proof,
        leaf,
    });
    (encoded_len(&part) <= MAX_PROVISION_PART_BYTES).then_some(part)
}

/// One transaction's [`served_keys`] with the values `state` holds at
/// each, or `None` where a range names an entry with no leaf.
///
/// The exact flat keys of the read set, with no ownership walk — identity
/// keying made ownership maps structurally absent — and nothing naming
/// what the receiver needs: it re-derives that from the envelope. A
/// keyless request reads nothing, and its transaction still stages: the
/// payer shard's empty part is the engagement evidence. A declared cell
/// absent from `state` is carried as `None` and proven absent, so a
/// receiver can tell it from one left out. An entry leaf is read like
/// any cell: the receiver re-derives the interval from the
/// self-describing leaf values, and every leaf verifies against the
/// source root like a cell's does.
fn read_served(
    state: &impl Substates,
    source_shard: ShardId,
    req: &ProvisionsRequest,
) -> Option<Vec<SubstateEntry>> {
    let mut declared = req.local_keys.clone();
    declared.sort_unstable();
    let keys = served_keys(state, req);
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        let value = state.cell(key);
        if value.is_none() && declared.binary_search(&key).is_err() {
            // The range read named this entry, so its leaf must exist —
            // the "index ≡ leaves" invariant. Serving without it would
            // ship an under-provisioned part whose failure surfaces as
            // untraceable receipt divergence on the target shard;
            // refusing keeps the defect at its source.
            warn!(
                source_shard = source_shard.inner(),
                tx_hash = %req.tx_hash,
                ?key,
                "build_provisions: a range names an entry with no leaf"
            );
            return None;
        }
        entries.push(SubstateEntry::new(
            key,
            value.map(|value| {
                Bytes::new(value).expect("a list under the cap its source already met")
            }),
        ));
    }
    Some(entries)
}
