//! Inbound provision-request handling for cross-shard fetches.

use hyperscale_messages::request::GetProvisionsRequest;
use hyperscale_messages::response::GetProvisionResponse;
use hyperscale_storage::{ChainReader, SubstateStore};
use hyperscale_types::ShardGroupId;
use tracing::warn;

/// Serve an inbound provision request from a target shard needing our state.
///
/// Looks up the block at the requested height, identifies transactions
/// that involve the requesting shard, collects the local state entries
/// and merkle proofs, and returns them as `StateProvision`s.
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
            block_height = req.block_height.0,
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let block = certified.block;

    let jmt_height = block.height();

    let all_txs = block.transactions().iter();

    // Phase 1: Fetch state entries for all matching transactions.
    let mut per_tx: Vec<(hyperscale_types::TxHash, Vec<hyperscale_types::StateEntry>)> = Vec::new();
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for tx in all_txs {
        // Check if this transaction involves the requesting target shard.
        let involves_target = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .any(|node_id| {
                hyperscale_types::shard_for_node(node_id, num_shards) == req.target_shard
            });
        if !involves_target {
            continue;
        }

        let mut owned_nodes: Vec<_> = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .filter(|&node_id| hyperscale_types::shard_for_node(node_id, num_shards) == local_shard)
            .copied()
            .collect();
        owned_nodes.sort();
        owned_nodes.dedup();

        if owned_nodes.is_empty() {
            continue;
        }

        let Some(entries) =
            hyperscale_engine::fetch_state_entries(storage, &owned_nodes, jmt_height)
        else {
            warn!(
                block_height = req.block_height.0,
                jmt_height = jmt_height.0,
                "Provision request: historical JMT version unavailable"
            );
            return GetProvisionResponse { provisions: None };
        };
        for e in &entries {
            all_storage_keys.push(e.storage_key.clone());
        }
        per_tx.push((tx.hash(), entries));
    }

    // Phase 2: Generate ONE batched proof covering all entries.
    all_storage_keys.sort();
    all_storage_keys.dedup();
    let proof = if per_tx.is_empty() {
        hyperscale_types::MerkleInclusionProof::dummy()
    } else if let Some(p) = storage.generate_merkle_proofs(&all_storage_keys, jmt_height) {
        p
    } else {
        tracing::warn!(
            block_height = req.block_height.0,
            "Fallback provision: batched proof generation failed (version unavailable)"
        );
        return GetProvisionResponse { provisions: None };
    };

    // Phase 3: Build the bundle.
    let transactions = per_tx
        .into_iter()
        .map(|(tx_hash, entries)| hyperscale_types::TxEntries {
            tx_hash,
            entries,
            target_nodes: vec![],
        })
        .collect();

    GetProvisionResponse {
        provisions: Some(hyperscale_types::Provisions::new(
            local_shard,
            req.target_shard,
            req.block_height,
            proof,
            transactions,
        )),
    }
}
