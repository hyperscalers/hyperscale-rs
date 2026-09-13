//! Gathering the cells a preview needs from the shards that hold them.
//!
//! A preview runs against committed state, and a node serves only its
//! own shards' — so an envelope reaching further is answered by asking
//! whoever does hold it. One request per shard, all in flight together,
//! and nothing runs until every one has come back or failed.
//!
//! # Why this can block
//!
//! It runs on the caller's thread, which is an RPC blocking worker, so
//! waiting is free of anyone else's latency: no shard driver is held up
//! and no consensus step is behind it. That is also why the wait needs
//! no deadline bookkeeping of its own — the network calls back on
//! timeout as well as on success, so every request resolves exactly
//! once and the count is what says the gathering is done.
//!
//! # What makes a served answer trustworthy
//!
//! Nothing about who served it. A server picks the anchor and sends the
//! certified header for it; this node checks that header's quorum
//! certificate against the shard's committee — which it holds for every
//! shard, from its own topology snapshot — and then checks the proof
//! against that header's state root. A server answering for a chain its
//! committee never signed fails the first check; one answering with
//! cells that chain never held fails the second.
//!
//! A shard that fails either, or never answers, is simply absent from
//! the gathered anchors, and the preview refuses by naming it. There is
//! no arm in which an unverified cell reaches the run.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crossbeam::channel::bounded;
use hyperscale_engine::{DeclaredReads, FetchedCells};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_types::network::request::GetCellsRequest;
use hyperscale_types::network::response::GetCellsResponse;
use hyperscale_types::{
    CertifiedBlockHeader, EntryKey, ProtocolHasher, QcContext, ShardId, TopologySnapshot, Verified,
    Verifier, Verify, entry_leaf_key,
};

/// How long the whole gathering may take.
///
/// A ceiling on the caller's wait rather than on any one request — the
/// network applies its own per-request timeout and calls back either
/// way, so this only bounds the pathological case where a callback is
/// never delivered at all.
const GATHER_TIMEOUT: Duration = Duration::from_secs(10);

/// Check a served answer and fold what it attests into `into`.
///
/// Returns whether the answer stood up. Everything it carries is
/// dropped if any part of it fails, so a partial verification never
/// contributes a cell.
fn absorb(
    shard: ShardId,
    ask: &DeclaredReads,
    response: &GetCellsResponse,
    topology: &TopologySnapshot,
    verifier: &dyn Verifier,
    into: &mut FetchedCells,
) -> bool {
    let (Some(proof), Some(anchor)) = (&response.proof, &response.anchor) else {
        return false;
    };
    let Some(attested) = verify_anchor(shard, anchor, topology, verifier) else {
        return false;
    };
    // Every leaf the answer stands on, rebuilt from what it returned —
    // so the proof is checked against the keys this node derived and
    // never against a list the server chose.
    let mut leaves = ask.keys.clone();
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        leaves.extend(answer.entries.iter().map(|(order, _)| {
            entry_leaf_key(
                &ProtocolHasher,
                EntryKey {
                    owner: range.owner,
                    collection: range.collection,
                    order: *order,
                },
            )
        }));
    }
    if proof
        .inclusions(attested.header().state_root(), shard, &leaves)
        .is_err()
    {
        return false;
    }
    for (key, value) in &response.cells {
        into.cells.insert(*key, value.clone());
    }
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        into.entries
            .entry((range.owner, range.collection))
            .or_default()
            .extend(answer.entries.iter().cloned());
    }
    into.anchors.insert(shard, attested.header().height());
    true
}

/// The header, if its quorum certificate is `shard`'s committee's.
fn verify_anchor(
    shard: ShardId,
    anchor: &CertifiedBlockHeader,
    topology: &TopologySnapshot,
    verifier: &dyn Verifier,
) -> Option<Verified<CertifiedBlockHeader>> {
    let keys: Vec<_> = topology
        .consensus_committee_for_shard(shard)
        .iter()
        .filter_map(|validator| topology.public_key(*validator))
        .collect();
    if keys.is_empty() {
        return None;
    }
    let ctx = QcContext {
        verifier,
        network: topology.network(),
        public_keys: &keys,
        quorum_threshold: topology.quorum_threshold_for_shard(shard),
    };
    // SAFETY for `from_qc_attestation`: the committee that signed this
    // QC accepted the header before voting, and the check above is that
    // the signature is that committee's. Local per-root verification is
    // neither possible here — this node holds none of that shard's
    // tree — nor needed, since the QC's majority attests on its behalf.
    let verified_qc = anchor.qc().verify(&ctx).ok()?;
    Verified::<CertifiedBlockHeader>::from_qc_attestation(anchor.header().clone(), verified_qc).ok()
}

/// Ask each shard in `asks` for what it holds, and return what came
/// back verified.
///
/// A shard that fails to answer, or answers with something that does not
/// verify, is absent from the result's anchors — which is what makes the
/// preview refuse by naming it rather than read its silence as an empty
/// cell.
pub fn gather<N: Network>(
    asks: &BTreeMap<ShardId, DeclaredReads>,
    topology: &Arc<TopologySnapshot>,
    network: &N,
    verifier: &dyn Verifier,
) -> FetchedCells {
    let mut fetched = FetchedCells::default();
    if asks.is_empty() {
        return fetched;
    }
    let (tx, rx) = bounded(asks.len());
    for (shard, ask) in asks {
        let shard = *shard;
        let tx = tx.clone();
        network.request(
            shard,
            None,
            GetCellsRequest::new(ask.keys.clone(), ask.ranges.clone()),
            None,
            Box::new(move |result| {
                let served = result.is_ok();
                let _ = tx.send((shard, result.ok()));
                // A verdict about the peer, not about the preview: a
                // peer that could not serve is deprioritized for the
                // next asker, which is what the health tracker is for.
                if served {
                    ResponseVerdict::Accept
                } else {
                    ResponseVerdict::Reject
                }
            }),
        );
    }
    drop(tx);

    for _ in 0..asks.len() {
        let Ok((shard, response)) = rx.recv_timeout(GATHER_TIMEOUT) else {
            break;
        };
        if let (Some(response), Some(ask)) = (response, asks.get(&shard)) {
            absorb(shard, ask, &response, topology, verifier, &mut fetched);
        }
    }
    fetched
}
