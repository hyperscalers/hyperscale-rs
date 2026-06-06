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
use hyperscale_engine::fetch_state_entries;
use hyperscale_engine::sharding::expand_nodes_with_owned_at_height;
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_storage::{SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::{
    BlockHeight, MerkleInclusionProof, NodeId, ProvisionEntry, Provisions, ShardId, SubstateEntry,
    TxHash,
};
use tracing::warn;

/// Per-tx payload assembled before constructing [`ProvisionEntry`]s.
type StagedEntry = (
    TxHash,
    Vec<SubstateEntry>,
    Vec<NodeId>,
    Vec<(NodeId, NodeId)>,
);

/// Build a `Provisions` bundle for a single source → target shard pair.
///
/// Returns `None` if the JMT version at `source_block_height` is no
/// longer available for ownership expansion, entry fetch, or proof
/// generation — callers treat this as "block not found" and surface a
/// fetch-side retry. Returns `Some(Provisions { ... transactions: empty })`
/// when no request touches `target_shard`; receivers handle empty
/// transactions in the verify path.
///
/// `requests` may carry target-node entries for multiple shards. Only
/// entries matching `target_shard` participate in this build.
pub fn build_provisions<S>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_height: BlockHeight,
    requests: &[ProvisionsRequest],
) -> Option<Arc<Provisions>>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut staged: Vec<StagedEntry> = Vec::with_capacity(requests.len());
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for req in requests {
        let Some(target_nodes) = req
            .target_nodes
            .iter()
            .find(|(shard, _)| *shard == target_shard)
            .map(|(_, nodes)| nodes.clone())
        else {
            continue;
        };
        if target_nodes.is_empty() || req.local_nodes.is_empty() {
            continue;
        }

        let Some((expanded_nodes, ownership)) =
            expand_nodes_with_owned_at_height(view, &req.local_nodes, source_block_height)
        else {
            warn!(
                source_shard = source_shard.inner(),
                target_shard = target_shard.inner(),
                block_height = source_block_height.inner(),
                tx_hash = %req.tx_hash,
                "build_provisions: JMT version unavailable for ownership walk"
            );
            return None;
        };

        let Some(entries) = fetch_state_entries(view, &expanded_nodes, source_block_height) else {
            warn!(
                source_shard = source_shard.inner(),
                target_shard = target_shard.inner(),
                block_height = source_block_height.inner(),
                tx_hash = %req.tx_hash,
                "build_provisions: JMT version unavailable for state entries"
            );
            return None;
        };

        for e in &entries {
            all_storage_keys.push(e.storage_key.0.clone());
        }
        let owned_nodes: Vec<(NodeId, NodeId)> = ownership.into_iter().collect();
        staged.push((req.tx_hash, entries, target_nodes, owned_nodes));
    }

    let proof = if all_storage_keys.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else {
        view.generate_merkle_proofs_overlay(&all_storage_keys, source_block_height)?
    };

    let transactions = staged
        .into_iter()
        .map(|(tx_hash, entries, target_nodes, owned_nodes)| {
            ProvisionEntry::new(tx_hash, entries, target_nodes, owned_nodes)
        })
        .collect();

    Some(Arc::new(Provisions::new(
        source_shard,
        target_shard,
        source_block_height,
        proof,
        transactions,
    )))
}
