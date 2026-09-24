//! The producer's push of the crossing records a block wrote, as
//! self-proving claims at the block's own anchor.
//!
//! One push per target shard per block: each record's value is read at
//! the block's view, proved at the block's root, and carried as a held
//! reading. A push carries only presences the block wrote, never an
//! absence or a reading at another anchor.

use std::collections::{BTreeMap, HashMap};

use hyperscale_core::ActionContext;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_network::Network;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::notification::CrossingReadingsNotification;
use hyperscale_types::{
    Anchor, BlockHash, CrossingReadingsSenderMessage, MAX_PROOFS_PER_QUERY, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, ShardId, StateClaim, Stated, SubstateKey, ValidatorId,
    signed_bytes,
};
use tracing::warn;

/// Prove the records the block at `anchor` wrote for each target and
/// send them to the target's committee, one signed notification per
/// section.
pub fn push_crossing_readings<S, N>(
    ctx: &ActionContext<'_, S, N>,
    block_hash: BlockHash,
    anchor: Anchor,
    targets: &BTreeMap<ShardId, Vec<SubstateKey>>,
    shard_recipients: &HashMap<ShardId, Vec<ValidatorId>>,
) where
    S: ShardStorage,
    N: Network,
{
    let view = ctx.pending_chain.view_at(block_hash, anchor.height);
    for (target_shard, sections) in build_pushes(&view, anchor, targets) {
        let Some(recipients) = shard_recipients.get(&target_shard) else {
            continue;
        };
        for claims in sections {
            let msg = signed_bytes(
                &CrossingReadingsSenderMessage::new(target_shard, &claims),
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!("cannot sign crossing readings push; skipping");
                return;
            };
            let notification = CrossingReadingsNotification::new(claims, target_shard, ctx.me, sig);
            ctx.network.notify(recipients, &notification);
        }
    }
}

/// The claims to push to each target, each list cut into the sections
/// a consumer can carry: at most one block's claims, weighing at most
/// one block's section.
fn build_pushes<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    targets: &BTreeMap<ShardId, Vec<SubstateKey>>,
) -> Vec<(
    ShardId,
    Vec<Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>>,
)>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    targets
        .iter()
        .map(|(&target, keys)| {
            let mut claims = Vec::new();
            for chunk in keys.chunks(MAX_PROOFS_PER_QUERY) {
                prove_chunk(view, anchor, chunk, &mut claims);
            }
            (target, cut_to_sections(claims))
        })
        .filter(|(_, sections)| !sections.is_empty())
        .collect()
}

/// Prove `keys` present at the anchor as one claim, halving the chunk
/// where the proof would not fit its decoder's cap, and skipping a key
/// the view does not hold: a push carries only what the block wrote.
fn prove_chunk<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    keys: &[SubstateKey],
    out: &mut Vec<StateClaim>,
) where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut cells = Vec::with_capacity(keys.len());
    for &key in keys {
        let Some(Some(value)) = view.get_substate_at_height(key, anchor.height) else {
            warn!(
                shard = anchor.shard.inner(),
                height = anchor.height.inner(),
                "a record to push is not present at its own block"
            );
            continue;
        };
        let Ok(held) = Bytes::new(value) else {
            warn!(
                shard = anchor.shard.inner(),
                height = anchor.height.inner(),
                "a record to push is wider than a held value"
            );
            continue;
        };
        cells.push((key, Stated::Held(held)));
    }
    if cells.is_empty() {
        return;
    }
    let present: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
    match generate_proof(view, &present, anchor.height) {
        Some(proof) => out.push(StateClaim::new(anchor, cells, proof)),
        None if present.len() > 1 => {
            let (left, right) = present.split_at(present.len() / 2);
            prove_chunk(view, anchor, left, out);
            prove_chunk(view, anchor, right, out);
        }
        None => warn!(
            shard = anchor.shard.inner(),
            height = anchor.height.inner(),
            "a single record's proof cannot be built at its own block"
        ),
    }
}

/// Cut claims into sections a consumer can carry whole.
fn cut_to_sections(
    claims: Vec<StateClaim>,
) -> Vec<Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>> {
    let mut sections = Vec::new();
    let mut section: Vec<StateClaim> = Vec::new();
    let mut weight = 0usize;
    for claim in claims {
        let cost = claim.wire_weight();
        if !section.is_empty()
            && (section.len() >= MAX_STATE_CLAIMS_PER_BLOCK
                || weight + cost > MAX_STATE_CLAIMS_BYTES)
        {
            sections.push(Capped::new(std::mem::take(&mut section)).expect("cut under the cap"));
            weight = 0;
        }
        weight += cost;
        section.push(claim);
    }
    if !section.is_empty() {
        sections.push(Capped::new(section).expect("cut under the cap"));
    }
    sections
}
