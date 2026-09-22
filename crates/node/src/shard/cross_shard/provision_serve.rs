//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_execution::{
    crossing_requests, provision_request, record_requests, reoffer_requests,
};
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::{Anchored, GetProvisionsRequest};
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{ShardId, ShardTrie, SubstateKey};
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
/// Takes `local_shard` and the active `ShardTrie` instead of
/// `&TopologyCoordinator` to avoid a topology dependency in the I/O layer.
/// The caller loads the trie at serve time so routing always resolves
/// against the current partition.
pub fn serve_provision_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let height = match &req.asks {
        Anchored::Block(height) => *height,
        Anchored::Records(records) => {
            return serve_records(pending_chain, local_shard, shard_trie, req, records);
        }
    };
    let Some(certified) = pending_chain.certified_block(height) else {
        warn!(
            block_height = height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let block = certified.block();

    // The same derivation the gossip emit path runs, narrowed to the
    // requester: a transaction is served exactly when the requester is
    // among the targets the emit path would have broadcast to.
    let mut requests: Vec<ProvisionsRequest> = Vec::new();
    for tx in block.transactions().iter() {
        let Some(mut request) = provision_request(shard_trie, tx, local_shard) else {
            continue;
        };
        if !request.targets.contains(&req.target_shard) {
            continue;
        }
        request.targets = vec![req.target_shard];
        requests.push(request);
    }
    // The crossings the block's certificates commit, after its
    // transactions, and the ones it offers again after those — the
    // order the block's roots bucket them in.
    for mut request in crossing_requests(block.certificates(), local_shard)
        .into_iter()
        .chain(reoffer_requests(block.reoffers(), local_shard))
    {
        if !request.targets.contains(&req.target_shard) {
            continue;
        }
        request.targets = vec![req.target_shard];
        requests.push(request);
    }

    let view = pending_chain.view_at_committed_tip();
    let provisions = build_provisions(
        &view,
        local_shard,
        req.target_shard,
        height,
        block.header().parent_qc().weighted_timestamp(),
        &requests,
    );

    if let Some(p) = &provisions {
        record_fetch_response_sent("provision", p.transactions().len());
    }
    GetProvisionResponse { provisions }
}

/// Serve a pull: the record cells named, read at this shard's own
/// committed tip.
///
/// **No height is named and none is needed.** A record stands until its
/// producer disposes of it, so there is always a tip that holds one —
/// and once disposed there is no tip that does, so a bundle for it comes
/// back empty. That is what makes disposal stop the serving, where a
/// height-pinned read goes on serving a disposed record out of an old
/// version until its retention runs out.
///
/// The transaction each cell belongs to is read off the cell rather than
/// taken from the asker: a record names its own issuing transaction, and
/// a bundle is staged per transaction. An asker that named the wrong one
/// would have its entries filed under it.
///
/// Keys this shard does not hold the prefix for are passed over. They
/// are not this shard's records to answer for, and a bundle built from
/// one would prove nothing against this chain's root.
fn serve_records<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    req: &GetProvisionsRequest,
    records: &[SubstateKey],
) -> GetProvisionResponse {
    let view = pending_chain.view_at_committed_tip();
    let height = view.base().committed_height();
    let Some(anchor) = pending_chain.certified_header(height) else {
        warn!(
            height = height.inner(),
            "Provision pull: no certified header for our own tip"
        );
        return GetProvisionResponse { provisions: None };
    };

    let held: Vec<(SubstateKey, Vec<u8>)> = records
        .iter()
        .filter(|key| shard_trie.shard_for_prefix(key.owner) == local_shard)
        .filter_map(|&key| {
            view.base()
                .get_substate_at_height(key, height)
                .flatten()
                .map(|bytes| (key, bytes))
        })
        .collect();
    let requests = record_requests(&held, req.target_shard);

    let provisions = build_provisions(
        &view,
        local_shard,
        req.target_shard,
        height,
        anchor.header().parent_qc().weighted_timestamp(),
        &requests,
    );
    if let Some(p) = &provisions {
        record_fetch_response_sent("provision", p.transactions().len());
    }
    GetProvisionResponse { provisions }
}
