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
use hyperscale_storage::entry_leaf_value;
use hyperscale_types::network::request::GetCellsRequest;
use hyperscale_types::network::response::GetCellsResponse;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, EntryKey, MerkleInclusionProof, ProtocolHasher, QcContext,
    ShardId, StateRoot, SubstateKey, TopologySnapshot, Verified, Verifier, Verify, entry_leaf_key,
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
/// Returns whether the answer stood up. Nothing is kept unless all of it
/// is: a partial verification contributes no cell.
///
/// The check is on the values, not merely on the keys. A multiproof
/// attests a *value hash* per leaf, so a server that returns the key set
/// it was asked for — which is the set that makes the proof
/// reconstruct — can otherwise carry whatever bytes it likes under
/// those keys. Every value is hashed and compared, the way a provisions
/// bundle's carried entries are.
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
    fold_attested(
        shard,
        ask,
        response,
        proof,
        attested.header().state_root(),
        attested.header().height(),
        into,
    )
}

/// Fold an answer whose anchor has already been verified, checking every
/// value against what `root` attests for its leaf.
///
/// Split from [`absorb`] because this half is the one that decides
/// whether a server can lie about *contents*, and it is checkable
/// against a root without a committee in hand.
fn fold_attested(
    shard: ShardId,
    ask: &DeclaredReads,
    response: &GetCellsResponse,
    proof: &MerkleInclusionProof,
    root: StateRoot,
    height: BlockHeight,
    into: &mut FetchedCells,
) -> bool {
    // Positional, so a short answer is not a partial one: an interval
    // the server dropped would otherwise go unasked-about, and the proof
    // over the leaves that remain still reconstructs.
    if response.ranges.len() != ask.ranges.len() {
        return false;
    }
    // Every leaf the answer stands on, with the value claimed for it,
    // rebuilt from what the server returned — so the proof is checked
    // against keys this node derived and never against a list the
    // server chose.
    let served: BTreeMap<SubstateKey, &Vec<u8>> = response
        .cells
        .iter()
        .map(|(key, value)| (*key, value))
        .collect();
    let mut leaves = Vec::with_capacity(ask.keys.len());
    // What the leaf holds, which for an entry is not the bare value: an
    // entry leaf carries its own collection and order beside it, so the
    // ordered index is derivable from the leaves alone. Hashing the
    // value would compare against a leaf nobody wrote.
    let mut claimed: Vec<Option<Vec<u8>>> = Vec::with_capacity(ask.keys.len());
    for key in &ask.keys {
        leaves.push(*key);
        claimed.push(served.get(key).map(|value| (*value).clone()));
    }
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        for (order, value) in &answer.entries {
            let entry = EntryKey {
                owner: range.owner,
                collection: range.collection,
                order: *order,
            };
            leaves.push(entry_leaf_key(&ProtocolHasher, entry));
            claimed.push(Some(entry_leaf_value(&entry, value)));
        }
    }

    let Ok(inclusions) = proof.inclusions(root, shard, &leaves) else {
        return false;
    };
    for (claim, (_, inclusion)) in claimed.iter().zip(&inclusions) {
        if claim.as_ref().map(|value| jmt_value_hash(value)) != inclusion.value_hash() {
            return false;
        }
    }

    // Keyed by what was asked, carrying what the root attested for it:
    // a pair the server volunteered under some other key was never a
    // leaf in `leaves` and so has nothing standing behind it.
    for (key, value) in ask.keys.iter().zip(claimed) {
        if let Some(value) = value {
            into.cells.insert(*key, value);
        }
    }
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        into.entries
            .entry((range.owner, range.collection))
            .or_default()
            .extend(answer.entries.iter().cloned());
    }
    into.anchors.insert(shard, height);
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

#[cfg(test)]
mod tests {
    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::{commit_writes, entry_key, make_settled_entries};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::CellRange;
    use hyperscale_types::test_utils::test_key;

    use super::*;
    use crate::shard::cross_shard::serve_cells_request;

    const OWNER_SEED: u8 = 0x11;
    const SHARD: ShardId = ShardId::ROOT;

    /// A store of eight entries, and the root its only commit produced.
    fn served(ask: &DeclaredReads) -> (GetCellsResponse, StateRoot) {
        let storage = Arc::new(SimShardStorage::default());
        let written: Vec<(u128, Option<Vec<u8>>)> = (0u128..8)
            .map(|order| {
                (
                    order,
                    Some(vec![u8::try_from(order).expect("eight entries"); 4]),
                )
            })
            .collect();
        let root = commit_writes(&*storage, &make_settled_entries(OWNER_SEED, &written));
        let chain = Arc::new(PendingChain::new(storage));
        let response = serve_cells_request(
            &chain,
            &GetCellsRequest::new(ask.keys.clone(), ask.ranges.clone()),
        );
        (response, root)
    }

    fn one_range() -> DeclaredReads {
        let key = entry_key(OWNER_SEED, 0);
        DeclaredReads {
            keys: Vec::new(),
            ranges: vec![CellRange {
                owner: key.owner,
                collection: key.collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            }],
        }
    }

    /// A served answer folds in, and the same answer with one byte moved
    /// does not.
    ///
    /// This is the whole of what verification buys. A multiproof attests
    /// a value *hash* per leaf, so a server returning the key set it was
    /// asked for — the set that makes the proof reconstruct — would
    /// otherwise be free to carry any bytes it liked under those keys.
    /// A preview is exactly the thing that must not be lied to: the
    /// ceilings a wallet signs off it are the compute its declaration is
    /// priced on, so a fabricated answer moves the payer's money.
    #[test]
    fn a_value_the_proof_does_not_attest_is_refused() {
        let ask = one_range();
        let (response, root) = served(&ask);
        let proof = response.proof.clone().expect("the tip is answerable");

        let mut into = FetchedCells::default();
        assert!(
            fold_attested(
                SHARD,
                &ask,
                &response,
                &proof,
                root,
                BlockHeight::new(1),
                &mut into
            ),
            "the shard's own answer stands under its own root"
        );
        assert_eq!(into.entries.len(), 1, "and the entries it carried are kept");

        let mut tampered = response.clone();
        tampered.ranges[0].entries[0].1 = vec![0xFF; 4];
        let mut nothing = FetchedCells::default();
        assert!(
            !fold_attested(
                SHARD,
                &ask,
                &tampered,
                &proof,
                root,
                BlockHeight::new(1),
                &mut nothing
            ),
            "a value the root never attested is refused"
        );
        assert!(
            nothing.cells.is_empty() && nothing.entries.is_empty() && nothing.anchors.is_empty(),
            "and nothing of a refused answer is kept, so a partial \
             verification contributes no cell"
        );
    }

    /// A cell the server volunteered under a key nobody asked for is
    /// not kept, even though the rest of the answer stands.
    ///
    /// A multiproof attests the leaves it was built over, and those are
    /// the ones this node derived from its own declaration. A pair
    /// carried under any other key is outside that set entirely — the
    /// proof neither attests nor contradicts it — so the answer is
    /// sound and the pair is still worthless. A server for one shard
    /// would otherwise seed the run with whatever it liked for another.
    #[test]
    fn a_cell_nobody_asked_for_is_not_kept() {
        let ask = one_range();
        let (response, root) = served(&ask);
        let proof = response.proof.clone().expect("the tip is answerable");

        let mut volunteered = response;
        volunteered.cells.push((test_key(0x5A), vec![0xAB; 8]));

        let mut into = FetchedCells::default();
        assert!(
            fold_attested(
                SHARD,
                &ask,
                &volunteered,
                &proof,
                root,
                BlockHeight::new(1),
                &mut into
            ),
            "the intervals that were asked for still stand under the root"
        );
        assert_eq!(into.entries.len(), 1, "so the answer's own content is kept");
        assert!(
            into.cells.is_empty(),
            "and the volunteered cell is not, having no leaf behind it"
        );
    }

    /// An interval the server simply left out is refused rather than
    /// read as an empty one.
    ///
    /// Positional, so a short answer would otherwise go unasked-about:
    /// the proof over the remaining leaves still reconstructs, the shard
    /// still lands in `anchors`, and the run reads the dropped interval
    /// as a collection holding nothing.
    #[test]
    fn a_dropped_interval_is_refused() {
        let ask = one_range();
        let (response, root) = served(&ask);
        let proof = response.proof.clone().expect("the tip is answerable");

        let mut short = response;
        short.ranges.clear();
        let mut nothing = FetchedCells::default();
        assert!(
            !fold_attested(
                SHARD,
                &ask,
                &short,
                &proof,
                root,
                BlockHeight::new(1),
                &mut nothing
            ),
            "an answer naming fewer intervals than were asked is not a partial answer"
        );
    }
}
