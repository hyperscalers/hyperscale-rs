//! Shared provision construction.
//!
//! Both the gossip emit path ([`fetch_and_broadcast_provision`]) and the
//! fetch serve path (`build_served_parts` in the node crate) build each
//! part through [`build_part`], over the keys [`served_keys`] gives and
//! only once the leaves those keys make walk to the source header's own
//! root. Keeping a single function means a receiver absorbs
//! byte-identical parts regardless of which transport delivered them.
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
    ProvisionParts, ProvisionTxRoot, ShardId, SubstateEntry, SubstateKey, WeightedTimestamp,
};
use tracing::warn;

use crate::content::{served_keys, served_leaf};

/// What one source block owes one target out of the state the block
/// left: the requests naming the target, in leaf order, beside the keys
/// each part serves and the leaves those make.
pub struct Owed<'r> {
    requests: Vec<&'r ProvisionsRequest>,
    keys: Vec<Vec<SubstateKey>>,
    leaves: Vec<Hash>,
}

impl<'r> Owed<'r> {
    /// What `requests` owe `target_shard`, their keys read out of
    /// `state`.
    #[must_use]
    pub fn of(
        state: &impl Substates,
        requests: &'r [ProvisionsRequest],
        target_shard: ShardId,
    ) -> Self {
        Self::from_keyed(
            requests_for(requests, target_shard)
                .map(|request| (request, served_keys(state, request))),
        )
    }

    /// What `requests` owe `target_shard`, `keys` holding each request's
    /// served keys in request order.
    #[must_use]
    pub(crate) fn over(
        requests: &'r [ProvisionsRequest],
        keys: &[Vec<SubstateKey>],
        target_shard: ShardId,
    ) -> Self {
        Self::from_keyed(
            requests
                .iter()
                .zip(keys)
                .filter(|(request, _)| request.targets.contains(&target_shard))
                .map(|(request, keys)| (request, keys.clone())),
        )
    }

    fn from_keyed(keyed: impl Iterator<Item = (&'r ProvisionsRequest, Vec<SubstateKey>)>) -> Self {
        let (requests, keys): (Vec<_>, Vec<_>) = keyed.unzip();
        let leaves = requests
            .iter()
            .zip(&keys)
            .map(|(request, keys)| served_leaf(request, keys))
            .collect();
        Self {
            requests,
            keys,
            leaves,
        }
    }

    /// The leaves, in order.
    #[must_use]
    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// The count witness these leaves make, or `None` where nothing is
    /// owed.
    #[must_use]
    pub fn count(&self) -> Option<ProvisionCount> {
        (!self.leaves.is_empty()).then(|| ProvisionCount::over(&self.leaves))
    }

    /// The root these leaves make, or `None` where nothing is owed: what
    /// the source header's entry for the target must be.
    #[must_use]
    pub fn root(&self) -> Option<ProvisionTxRoot> {
        self.count().map(|count| count.root())
    }
}

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

/// Build the parts `requests` owe `target_shard` whose leaf index
/// `wanted` names, in index order, out of `view`.
///
/// `view` is anchored at the source block itself, whose height every
/// part names; nothing is built where it does not hold its anchor's
/// state. No root is consulted, so nothing holds what this builds to
/// what the source header committed: a fixture for tests of the parts
/// themselves. A sender builds through [`build_owed_until`] once the
/// leaves it owes walk to its header's root.
#[cfg(feature = "test-utils")]
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
    let Some(state) = view.served_snapshot() else {
        return Vec::new();
    };
    let owed = Owed::of(&state, requests, target_shard);
    let mut parts = Vec::new();
    build_owed_until(
        view,
        &state,
        source_shard,
        target_shard,
        source_block_ts,
        &owed,
        |index, build| {
            if wanted(index) {
                parts.extend(build());
            }
            ControlFlow::Continue(())
        },
    );
    parts
}

/// Offer each leaf index of `owed` to `take`, in index order, with a
/// builder for its part, until `take` breaks.
///
/// The builder answers [`build_part`] for that index, or `None` where it
/// is unbuildable, and runs only if `take` calls it: a caller answering
/// within a budget builds what it takes and nothing past the point it
/// stops.
pub fn build_owed_until<S>(
    view: &SubstateView<S>,
    state: &impl Substates,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    owed: &Owed<'_>,
    mut take: impl FnMut(u32, &mut dyn FnMut() -> Option<Provision>) -> ControlFlow<()>,
) where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    for ((request, keys), path) in owed
        .requests
        .iter()
        .zip(&owed.keys)
        .zip(LeafPath::all(&owed.leaves))
    {
        let index = path.index;
        let mut path = Some(path);
        let mut build = || {
            build_part(
                view,
                state,
                source_shard,
                target_shard,
                source_block_ts,
                request,
                keys,
                path.take()?,
            )
        };
        if take(index, &mut build).is_break() {
            return;
        }
    }
}

/// `request`'s part at `path`, or `None` where it cannot be built.
///
/// It carries the request's clock, which its leaf binds, and serves `keys`, its [`served_keys`] out of `state`, the view's
/// reading at its anchor, and is proven through the view's tree. A proof
/// past a decode cap, an encoding past [`MAX_PROVISION_PART_BYTES`], or a
/// range naming an entry with no leaf leaves it unbuilt, which costs only
/// its own transaction.
#[allow(clippy::too_many_arguments)] // one part's coordinates beside the view it reads
pub fn build_part<S>(
    view: &SubstateView<S>,
    state: &impl Substates,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    request: &ProvisionsRequest,
    keys: &[SubstateKey],
    path: LeafPath,
) -> Option<Provision>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let source_block_height = view.anchor_height();
    let index = path.index;
    let part = read_served(state, source_shard, request, keys).and_then(|entries| {
        let proof = if entries.is_empty() {
            MerkleInclusionProof::new(Vec::new())
        } else {
            // The view is the proof walk's tree reader: pending
            // snapshots' nodes over the base store, one root lookup for
            // persisted and unpersisted heights alike. `None` — the root
            // or a node pruned mid-walk, or a proof past a decode cap —
            // leaves this part out, never a wrong proof.
            generate_proof(view, keys, source_block_height)?
        };
        let part = Provision::new(ProvisionParts {
            source_shard,
            target_shard,
            block_height: source_block_height,
            source_block_ts,
            clock: request.clock,
            tx_hash: request.tx_hash,
            entries: Capped::new(entries).ok()?,
            proof,
            leaf: path,
        });
        (encoded_len(&part) <= MAX_PROVISION_PART_BYTES).then_some(part)
    });
    if part.is_none() {
        warn!(
            source_shard = source_shard.inner(),
            target_shard = target_shard.inner(),
            block_height = source_block_height.inner(),
            tx_hash = %request.tx_hash,
            index,
            "build_provisions: part unbuildable"
        );
    }
    part
}

/// `keys`, one transaction's [`served_keys`], with the values `state`
/// holds at each, or `None` where a range names an entry with no leaf.
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
    keys: &[SubstateKey],
) -> Option<Vec<SubstateEntry>> {
    let mut declared = req.local_keys.clone();
    declared.sort_unstable();
    let mut entries = Vec::with_capacity(keys.len());
    for &key in keys {
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
