//! Shared provision construction.
//!
//! Both the gossip emit path ([`fetch_and_broadcast_provision`]) and the
//! fetch serve path (`serve_provision_request` in the node crate) flow
//! through [`build_provisions`]. Keeping a single function means a
//! receiver absorbs byte-identical bundles regardless of which transport
//! delivered them — any future field-ordering leak gets caught in one
//! place rather than drifting between two near-identical loops.
//!
//! [`fetch_and_broadcast_provision`]: crate::action_handlers::fetch_and_broadcast_provision

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::{
    BlockHeight, EntryKey, MerkleInclusionProof, ProtocolHasher, ProvisionEntry, Provisions,
    ShardId, SubstateEntry, SubstateKey, TxHash, WeightedTimestamp, entry_leaf_key,
};
use tracing::warn;

/// Build a `Provisions` bundle for a single source → target shard pair.
///
/// Returns `None` if the JMT version at `source_block_height` is no
/// longer available for the cell reads or proof generation — callers
/// treat this as "block not found" and surface a fetch-side retry.
/// Returns `Some(Provisions { ... transactions: empty })` when no request
/// targets `target_shard`; receivers handle empty transactions in the
/// verify path.
///
/// `requests` may name several target shards. Only those naming
/// `target_shard` participate in this build.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
pub fn build_provisions<S>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_height: BlockHeight,
    source_block_ts: WeightedTimestamp,
    requests: &[ProvisionsRequest],
) -> Option<Arc<Provisions>>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut staged: Vec<(TxHash, Vec<SubstateEntry>)> = Vec::with_capacity(requests.len());
    let mut all_keys: Vec<SubstateKey> = Vec::new();

    for req in requests {
        if !req.targets.contains(&target_shard) {
            continue;
        }

        // Read the exact flat keys of the transaction's local read set at
        // the source height. No ownership walk — identity keying made
        // ownership maps structurally absent — and nothing naming what the
        // receiver needs: it re-derives that from the envelope. A keyless
        // request still stages its transaction: the payer shard's
        // empty-entry bundle is the engagement evidence.
        let mut entries = Vec::with_capacity(req.local_keys.len());
        for key in &req.local_keys {
            let Some(value) = view.get_substate_at_height(*key, source_block_height) else {
                warn!(
                    source_shard = source_shard.inner(),
                    target_shard = target_shard.inner(),
                    block_height = source_block_height.inner(),
                    tx_hash = %req.tx_hash,
                    "build_provisions: height unavailable for flat key"
                );
                return None;
            };
            if let Some(value) = value {
                all_keys.push(*key);
                entries.push(SubstateEntry::new(
                    *key,
                    Some(Bytes::new(value).expect("a list under the cap its source already met")),
                ));
            }
        }
        // A declared interval serves as the entry leaves it holds at the
        // source height: enumerate the orders from the versioned index,
        // then read each leaf like any other — the receiver re-derives
        // the interval from the self-describing leaf values, and every
        // leaf verifies against the source root like a cell's does.
        for range in &req.local_ranges {
            let Some(held) = view.get_entries_at_height(*range, source_block_height) else {
                warn!(
                    source_shard = source_shard.inner(),
                    target_shard = target_shard.inner(),
                    block_height = source_block_height.inner(),
                    tx_hash = %req.tx_hash,
                    "build_provisions: height unavailable for range"
                );
                return None;
            };
            for (order, _) in held {
                let leaf_key = entry_leaf_key(
                    &ProtocolHasher,
                    EntryKey {
                        owner: range.owner,
                        collection: range.collection,
                        order,
                    },
                );
                let Some(value) = view.get_substate_at_height(leaf_key, source_block_height) else {
                    warn!(
                        source_shard = source_shard.inner(),
                        target_shard = target_shard.inner(),
                        block_height = source_block_height.inner(),
                        tx_hash = %req.tx_hash,
                        "build_provisions: height unavailable for entry leaf"
                    );
                    return None;
                };
                let Some(value) = value else {
                    // The index enumerated this order at this height, so
                    // its leaf must exist — the "index ≡ leaves"
                    // invariant. Serving without it would ship an
                    // under-provisioned bundle whose failure surfaces as
                    // untraceable receipt divergence on the target shard;
                    // refusing keeps the defect at its source.
                    warn!(
                        source_shard = source_shard.inner(),
                        block_height = source_block_height.inner(),
                        tx_hash = %req.tx_hash,
                        order,
                        "build_provisions: entry index names an order with no leaf"
                    );
                    return None;
                };
                all_keys.push(leaf_key);
                entries.push(SubstateEntry::new(
                    leaf_key,
                    Some(Bytes::new(value).expect("a list under the cap its source already met")),
                ));
            }
        }
        staged.push((req.tx_hash, entries));
    }

    let proof = if all_keys.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else {
        // The view is the proof walk's tree reader: pending snapshots'
        // nodes over the base store, one root lookup for persisted and
        // unpersisted heights alike. `None` — the root or a node pruned
        // mid-walk — surfaces as the same fetch-side retry as any other
        // unavailable height, never as a wrong proof.
        generate_proof(view, &all_keys, source_block_height)?
    };

    // One entry per staged transaction, which the block's own cap
    // already bounded; a bundle past it is one no peer would decode, so
    // there is nothing to send.
    let transactions = Capped::new(
        staged
            .into_iter()
            .map(|(tx_hash, entries)| {
                ProvisionEntry::new(
                    tx_hash,
                    Capped::new(entries).expect("a transaction's reads divide its call budget"),
                )
            })
            .collect(),
    )
    .ok()?;

    Some(Arc::new(Provisions::new(
        source_shard,
        target_shard,
        source_block_height,
        source_block_ts,
        proof,
        transactions,
    )))
}
