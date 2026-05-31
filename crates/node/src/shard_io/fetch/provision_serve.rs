//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{NodeId, ShardGroupId, shard_for_node};
use tracing::warn;

/// Serve an inbound provision request from a target shard needing our state.
///
/// Reads the source block through [`PendingChain`] so heights still inside
/// the shard-committed / JMT-persisted window are reachable; reconstructs
/// per-tx [`ProvisionsRequest`]s from the block's declared reads + writes;
/// then hands them to [`build_provisions`], which is the same function the
/// gossip emit path runs. Receivers therefore absorb byte-identical
/// `entries`, `target_nodes`, and `owned_nodes` regardless of which
/// transport delivered the provision — without this, fetched-provision
/// recipients would have empty `owned_nodes` maps and diverge on
/// `filter_updates_for_shard` downstream, breaking `local_receipt_root`
/// agreement.
///
/// Takes `local_shard` and `num_shards` instead of `&TopologyCoordinator`
/// to avoid topology dependency in the I/O layer.
pub fn serve_provision_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    local_shard: ShardGroupId,
    num_shards: u64,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let Some(certified) = pending_chain.certified_block(req.block_height) else {
        warn!(
            block_height = req.block_height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let block = certified.block();

    let mut requests: Vec<ProvisionsRequest> = Vec::new();
    for tx in block.transactions().iter() {
        let local_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .filter(|&n| shard_for_node(n, num_shards) == local_shard)
            .copied()
            .collect();
        if local_nodes.is_empty() {
            continue;
        }
        let target_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .filter(|&n| shard_for_node(n, num_shards) == req.target_shard)
            .copied()
            .collect();
        if target_nodes.is_empty() {
            continue;
        }
        requests.push(ProvisionsRequest {
            tx_hash: tx.hash(),
            local_nodes,
            target_nodes: vec![(req.target_shard, target_nodes)],
        });
    }

    let view = pending_chain.view_at_committed_tip();
    let provisions = build_provisions(
        &view,
        local_shard,
        req.target_shard,
        req.block_height,
        &requests,
    );

    if let Some(p) = &provisions {
        record_fetch_response_sent("provision", p.transactions().len());
    }
    GetProvisionResponse { provisions }
}
