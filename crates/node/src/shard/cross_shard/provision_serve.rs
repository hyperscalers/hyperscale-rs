//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_execution::{crossing_requests, provision_request, record_requests};
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::{Anchored, GetProvisionsRequest};
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{BlockHeight, CROSSING_BUNDLE_WINDOW, ShardId, ShardTrie, SubstateKey};
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
        Anchored::Records { at, keys } => {
            return serve_records(pending_chain, local_shard, shard_trie, req, *at, keys);
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
    // transactions — the order the block's roots bucket them in.
    //
    // **Only while the block is inside the crossing-bundle window.** Past
    // it this path would serve a record from the height that issued it
    // however long ago its producer disposed of it, which is the one
    // channel that would still feed a replay — so a crossing wanted
    // later is pulled at a fresh anchor instead, where disposal has
    // already closed the serving. The whole request goes rather than the
    // crossing entries alone: a bundle short of what the block's
    // `provision_tx_roots` promised fails its own completeness check,
    // and a peer is better told there is nothing here.
    let block_ts = block.header().parent_qc().weighted_timestamp();
    let tip_ts = pending_chain
        .latest_qc()
        .map_or(block_ts, |qc| qc.weighted_timestamp());
    let crossings = crossing_requests(block.certificates(), local_shard);
    if !crossings.is_empty() && tip_ts.elapsed_since(block_ts) > CROSSING_BUNDLE_WINDOW {
        return GetProvisionResponse { provisions: None };
    }
    for mut request in crossings {
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

/// Serve a pull: the record cells named, read at the height the asker
/// named.
///
/// **The height is the asker's newest commit-proven anchor of this
/// shard, not this shard's tip.** A bundle is checked against a header,
/// and only a commit-proven one will do — a bare quorum certificate does
/// not establish that this shard canonicalized the block. An asker
/// cannot hold such a proof for a tip that only just happened, so it
/// names the freshest anchor it can actually verify. Nothing here is
/// pinned to the height that issued the crossing, which is the height
/// that ages out.
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
    height: BlockHeight,
    records: &[SubstateKey],
) -> GetProvisionResponse {
    let Some(anchor) = pending_chain.certified_header(height) else {
        warn!(
            height = height.inner(),
            "Provision pull: no certified header at the height asked"
        );
        return GetProvisionResponse { provisions: None };
    };
    let view = pending_chain.view_at_committed_tip();
    // **The store's own floor first, which is a depth and not a
    // clock.** A height this chain no longer keeps versions for is one
    // the read below would panic on rather than miss, and the two
    // floors do not imply each other: a successor seated at a cut has a
    // young store and a full clock, so an anchor fresh by every measure
    // below can still sit under everything it retains. Asked rather
    // than inferred, on the terms the state-proof server asks it.
    if !view.serves_at(height) {
        warn!(
            height = height.inner(),
            "Provision pull: the height asked is below this chain's retention floor"
        );
        return GetProvisionResponse { provisions: None };
    }
    // **A bundle is an execution input, so it is served fresh.** The
    // asker names a height it has commit-proven, which lags this tip by
    // a commit proof's depth and no more; anything older is a question
    // about the past, and the one thing that would ask it is a replay
    // of a delivery whose record this chain has since disposed of.
    //
    // A window rather than the horizon, and the difference is what the
    // consumer's answer cell has to outlive: past this no bundle
    // carrying the record can be admitted, so a record read gone is one
    // no replay can be fed, and one reading of it is the whole licence.
    let asked_ts = anchor.header().parent_qc().weighted_timestamp();
    let tip_ts = pending_chain
        .latest_qc()
        .map_or(asked_ts, |qc| qc.weighted_timestamp());
    if tip_ts.elapsed_since(asked_ts) > CROSSING_BUNDLE_WINDOW {
        warn!(
            height = height.inner(),
            "Provision pull: the height asked is past the crossing-bundle window"
        );
        return GetProvisionResponse { provisions: None };
    }

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
