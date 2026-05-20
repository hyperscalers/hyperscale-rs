//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_engine::fetch_state_entries;
use hyperscale_storage::{ChainReader, SubstateStore};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    MerkleInclusionProof, ProvisionEntry, Provisions, ShardGroupId, SubstateEntry, TxHash,
    shard_for_node,
};
use tracing::warn;

/// Serve an inbound provision request from a target shard needing our state.
///
/// Looks up the block at the requested height, identifies transactions
/// that involve the requesting shard, collects the local state entries
/// and merkle proofs, and returns them as `Provisions` bundles.
///
/// Takes `local_shard` and `num_shards` instead of `&TopologyCoordinator`
/// to avoid topology dependency in the I/O layer.
pub fn serve_provision_request(
    storage: &(impl ChainReader + SubstateStore),
    local_shard: ShardGroupId,
    num_shards: u64,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let Some(certified) = storage.get_block(req.block_height) else {
        warn!(
            block_height = req.block_height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let (block, _qc) = certified.into_parts();

    let jmt_height = block.height();

    let all_txs = block.transactions().iter();

    // Phase 1: Fetch state entries for all matching transactions.
    let mut per_tx: Vec<(TxHash, Vec<SubstateEntry>)> = Vec::new();
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for tx in all_txs {
        // Check if this transaction involves the requesting target shard.
        let involves_target = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .any(|node_id| shard_for_node(node_id, num_shards) == req.target_shard);
        if !involves_target {
            continue;
        }

        let mut owned_nodes: Vec<_> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .filter(|&node_id| shard_for_node(node_id, num_shards) == local_shard)
            .copied()
            .collect();
        owned_nodes.sort();
        owned_nodes.dedup();

        if owned_nodes.is_empty() {
            continue;
        }

        let Some(entries) = fetch_state_entries(storage, &owned_nodes, jmt_height) else {
            warn!(
                block_height = req.block_height.inner(),
                jmt_height = jmt_height.inner(),
                "Provision request: historical JMT version unavailable"
            );
            return GetProvisionResponse { provisions: None };
        };
        for e in &entries {
            all_storage_keys.push(e.storage_key.0.clone());
        }
        per_tx.push((tx.hash(), entries));
    }

    // Phase 2: Generate ONE batched proof covering all entries.
    // `Jmt::prove` sorts and dedups its keys internally, so we hand it the
    // raw accumulated list.
    let proof = if per_tx.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else if let Some(p) = storage.generate_merkle_proofs(&all_storage_keys, jmt_height) {
        p
    } else {
        tracing::warn!(
            block_height = req.block_height.inner(),
            "Fallback provision: batched proof generation failed (version unavailable)"
        );
        return GetProvisionResponse { provisions: None };
    };

    // Phase 3: Build the bundle.
    let transactions = per_tx
        .into_iter()
        .map(|(tx_hash, entries)| ProvisionEntry::new(tx_hash, entries, vec![], vec![]))
        .collect();

    GetProvisionResponse {
        provisions: Some(Arc::new(Provisions::new(
            local_shard,
            req.target_shard,
            req.block_height,
            proof,
            transactions,
        ))),
    }
}
