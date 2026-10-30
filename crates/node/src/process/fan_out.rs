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
//!
//! What is verified is presence, not completeness. Every point key is
//! proven present or absent, and every entry an interval returns is
//! proven under the root; but an entry's leaf is keyed by a digest of
//! its owner, collection and order, so the tree's order is not the
//! collection's and nothing proves the interval holds no entry the
//! server left out. A server can answer an interval narrower than it
//! holds, and the run reads the gap as empty. A range-derived read in a
//! preview is the serving peer's word on what is missing, so every
//! interval a peer answered is recorded in the gathering's `unproven`
//! set, which the report carries out to the caller — short of a single
//! order, which has one leaf to stand on: proven present when its entry
//! came back, or proven absent when it did not.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crossbeam::channel::{Sender, bounded};
use hyperscale_engine::{DeclaredReads, FetchedCells, UnprovenInterval};
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::entry_leaf_value;
use hyperscale_types::network::request::GetCellsRequest;
use hyperscale_types::network::response::GetCellsResponse;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, EntryKey, Inclusion, MerkleInclusionProof, ProtocolHasher,
    QcContext, ShardId, StateRoot, SubstateKey, TopologySnapshot, Verified, Verifier, Verify,
    entry_leaf_key,
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
    let Some(unproven) = fold_attested(
        shard,
        ask,
        response,
        proof,
        attested.header().state_root(),
        attested.header().height(),
        into,
    ) else {
        return false;
    };
    // Here and not in the fold, because the gap is about who answered:
    // this node's own store is no more a stranger's word than the
    // snapshot the run reads itself.
    into.unproven.extend(unproven);
    true
}

/// Fold an answer whose anchor has already been verified, checking every
/// value against what `root` attests for its leaf.
///
/// Returns the intervals the answer does not prove whole, or `None` when
/// it does not stand.
///
/// Split from [`absorb`] because this half is the one that decides
/// whether a server can lie about *contents*, and it is checkable
/// against a root without a committee in hand. An interval's entries are
/// each proven present, and the interval is proven whole only where it
/// is a single order: by its entry coming back, or by the proof claiming
/// that order's leaf absent. A server that carries no such claim has
/// answered the order on its word, as it has every wider interval.
fn fold_attested(
    shard: ShardId,
    ask: &DeclaredReads,
    response: &GetCellsResponse,
    proof: &MerkleInclusionProof,
    root: StateRoot,
    height: BlockHeight,
    into: &mut FetchedCells,
) -> Option<Vec<UnprovenInterval>> {
    // Positional, so a short answer is not a partial one: an interval
    // the server dropped would otherwise go unasked-about, and the proof
    // over the leaves that remain still reconstructs.
    if response.ranges.len() != ask.ranges.len() {
        return None;
    }
    // Every leaf the answer stands on, with the value claimed for it,
    // rebuilt from what the server returned — so the proof is checked
    // against keys this node derived and never against a list the
    // server chose.
    let served: BTreeMap<SubstateKey, &[u8]> = response
        .cells
        .iter()
        .map(|(key, value)| (*key, value.as_ref()))
        .collect();
    let mut leaves = Vec::with_capacity(ask.keys.len());
    // What the leaf holds, which for an entry is not the bare value: an
    // entry leaf carries its own collection and order beside it, so the
    // ordered index is derivable from the leaves alone. Hashing the
    // value would compare against a leaf nobody wrote.
    let mut claimed: Vec<Option<Vec<u8>>> = Vec::with_capacity(ask.keys.len());
    for key in &ask.keys {
        leaves.push(*key);
        claimed.push(served.get(key).map(|value| (*value).to_vec()));
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

    // Which intervals the answer proves whole. Only a single order can
    // be: by its entry coming back, proven above, or by the proof
    // claiming its leaf absent when nothing did. A proof may carry that
    // claim or not and stand either way, so its leaf is asked about
    // apart from the ones the answer stands on.
    let mut unproven = Vec::new();
    let mut empty_orders = Vec::new();
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        if range.lo != range.hi {
            unproven.push(UnprovenInterval::from(range));
        } else if answer.entries.is_empty() {
            empty_orders.push(range);
        } else if !answer.entries.iter().any(|(order, _)| *order == range.lo) {
            unproven.push(UnprovenInterval::from(range));
        }
    }
    let stated = leaves.len();
    leaves.extend(empty_orders.iter().map(|range| {
        entry_leaf_key(
            &ProtocolHasher,
            EntryKey {
                owner: range.owner,
                collection: range.collection,
                order: range.lo,
            },
        )
    }));

    let inclusions = proof.claimed_inclusions(root, shard, &leaves).ok()?;
    let (stated_inclusions, empty_inclusions) = inclusions.split_at(stated);
    for (claim, (_, inclusion)) in claimed.iter().zip(stated_inclusions) {
        let inclusion = (*inclusion)?;
        if claim.as_ref().map(|value| jmt_value_hash(value)) != inclusion.value_hash() {
            return None;
        }
    }
    unproven.extend(
        empty_orders
            .into_iter()
            .zip(empty_inclusions)
            .filter(|(_, (_, inclusion))| *inclusion != Some(Inclusion::Absent))
            .map(|(range, _)| UnprovenInterval::from(range)),
    );

    // Keyed by what was asked, carrying what the root attested for it:
    // a pair the server volunteered under some other key was never a
    // leaf in `leaves` and so has nothing standing behind it.
    for (key, value) in ask.keys.iter().zip(claimed) {
        if let Some(value) = value {
            into.cells.insert(*key, value);
        }
    }
    for (range, answer) in ask.ranges.iter().zip(&response.ranges) {
        into.merge_entries(
            range.owner,
            range.collection,
            answer
                .entries
                .iter()
                .map(|(order, value)| (*order, value.to_vec())),
        );
    }
    into.anchors.insert(shard, height);
    Some(unproven)
}

/// The header, if its quorum certificate is `shard`'s committee's.
fn verify_anchor(
    shard: ShardId,
    anchor: &CertifiedBlockHeader,
    topology: &TopologySnapshot,
    verifier: &dyn Verifier,
) -> Option<Verified<CertifiedBlockHeader>> {
    // Positionally, because the QC selects its signers by index into
    // this vector: a member the snapshot cannot resolve would shift
    // every key above it and reject a genuine quorum as a forged one.
    // The committee-resolving sites a shard runs on its own behalf
    // panic on a miss, which is right where the miss is a `BeaconState`
    // invariant break; here the question is about a remote shard on a
    // path a stranger drives, so an unresolvable committee refuses the
    // anchor rather than bringing the node down.
    let keys: Vec<_> = topology
        .consensus_committee_for_shard(shard)
        .iter()
        .map(|validator| topology.public_key(*validator))
        .collect::<Option<Vec<_>>>()?;
    if keys.is_empty() {
        return None;
    }
    let ctx = QcContext {
        verifier,
        network: topology.network(),
        public_keys: &keys,
        quorum_threshold: topology.quorum_threshold_for_shard(shard),
    };
    // Why `from_qc_attestation` holds: the committee that signed this
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
/// `locally` answers for the shards this node serves itself, which are
/// asked the same question in the same words and answered from their own
/// stores. They go through the value check all the same: what the check
/// establishes is that every cell stands under the root the report names
/// for its shard, and that is as much worth knowing about this node's
/// own answer as about a stranger's. The committee check is what they
/// are spared — a node needs no quorum's word for a block it committed.
///
/// A shard that fails to answer, or answers with something that does not
/// verify, is absent from the result's anchors — which is what makes the
/// preview refuse by naming it rather than read its silence as an empty
/// cell.
pub fn gather<N: Network>(
    asks: &BTreeMap<ShardId, DeclaredReads>,
    topology: &Arc<TopologySnapshot>,
    network: &N,
    verifier: &Arc<dyn Verifier>,
    locally: &dyn Fn(ShardId, &GetCellsRequest) -> Option<GetCellsResponse>,
) -> FetchedCells {
    let mut fetched = FetchedCells::default();
    let mut remote: BTreeMap<ShardId, &DeclaredReads> = BTreeMap::new();
    for (shard, ask) in asks {
        let request = GetCellsRequest::new(ask.keys.clone(), ask.ranges.clone());
        if let Some(response) = locally(*shard, &request) {
            absorb_own(*shard, ask, &response, &mut fetched);
        } else {
            remote.insert(*shard, ask);
        }
    }
    if remote.is_empty() {
        return fetched;
    }
    let (tx, rx) = bounded(remote.len());
    // Each request carries its own sender and a held one hands it back for
    // the retry, so the gathering keeps none: once every callback has run
    // or been dropped unrun, the channel disconnects and the wait ends.
    let ask_shard = |shard: ShardId, ask: &DeclaredReads, tx: Sender<Answer>| {
        let ask = ask.clone();
        let topology = Arc::clone(topology);
        let verifier = Arc::clone(verifier);
        network.request(
            shard,
            None,
            GetCellsRequest::new(ask.keys.clone(), ask.ranges.clone()),
            None,
            Box::new(move |result| {
                if let Err(RequestError::BackingOff { retry_in }) = result {
                    let _ = tx.send(Answer::Held {
                        shard,
                        retry_in,
                        tx: tx.clone(),
                    });
                    return ResponseVerdict::Accept;
                }
                // Verified here rather than on the gathering thread,
                // because the verdict is consumed the moment this
                // returns: a peer whose proof does not stand has served
                // nothing, and saying otherwise leaves it preferred for
                // the next asker and stops the request rotating to
                // anyone else. What a shard is worth is what verified.
                let mut one = FetchedCells::default();
                let answered = result.is_ok_and(|response| {
                    absorb(shard, &ask, &response, &topology, &*verifier, &mut one)
                });
                let _ = tx.send(Answer::Gathered(answered.then_some(one)));
                if answered {
                    ResponseVerdict::Accept
                } else {
                    ResponseVerdict::Reject
                }
            }),
        );
    };
    for (shard, ask) in &remote {
        ask_shard(*shard, ask, tx.clone());
    }
    drop(tx);

    // One deadline for the gathering, not one per answer: the shards are
    // asked together and waited on together, so a peer that never calls
    // back costs the caller the ceiling once however many were asked. A
    // shard whose every stream is backing off is asked again once the
    // soonest reopens, when that is still inside the deadline.
    let deadline = Instant::now() + GATHER_TIMEOUT;
    let mut outstanding = remote.len();
    while outstanding > 0 {
        let Ok(answer) = rx.recv_deadline(deadline) else {
            break;
        };
        match answer {
            Answer::Gathered(answered) => {
                outstanding -= 1;
                if let Some(one) = answered {
                    fetched.absorb_from(one);
                }
            }
            Answer::Held {
                shard,
                retry_in,
                tx,
            } => {
                if Instant::now() + retry_in < deadline {
                    sleep(retry_in);
                    ask_shard(shard, remote[&shard], tx);
                } else {
                    outstanding -= 1;
                }
            }
        }
    }
    fetched
}

/// What one shard's request came back with.
enum Answer {
    /// What verified, or `None` when nothing did.
    Gathered(Option<FetchedCells>),
    /// Every stream to the shard is backing off for `retry_in`; `tx` is
    /// the sender the retry carries.
    Held {
        shard: ShardId,
        retry_in: Duration,
        tx: Sender<Self>,
    },
}

/// Fold this node's own answer for a shard it serves.
///
/// The anchor is a header this node committed, so its quorum
/// certificate is one it already accepted and checking it again would
/// establish nothing. Everything below that is the ordinary check.
fn absorb_own(
    shard: ShardId,
    ask: &DeclaredReads,
    response: &GetCellsResponse,
    into: &mut FetchedCells,
) -> bool {
    let (Some(proof), Some(anchor)) = (&response.proof, &response.anchor) else {
        return false;
    };
    fold_attested(
        shard,
        ask,
        response,
        proof,
        anchor.header().state_root(),
        anchor.header().height(),
        into,
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU32, Ordering};

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_hbor::{Bytes, Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
    use hyperscale_network::{
        Answerers, GossipHandler, NotificationHandler, RequestError, RequestHandler,
    };
    use hyperscale_storage::test_helpers::{
        commit_settled_at, commit_writes, entry_key, make_settled_entries, make_test_certified,
    };
    use hyperscale_storage::{PendingChain, Substates};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::CellRange;
    use hyperscale_types::test_utils::{TestCommittee, test_key};
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeader, BlockHeaderParts,
        GossipMessage, MessageClass, NetworkMessage, Request, RoutingCommittees, ValidatorId,
        WeightedTimestamp, WitnessSources,
    };

    use super::*;
    use crate::shard::cross_shard::serve_cells_request;

    const OWNER_SEED: u8 = 0x11;
    const SHARD: ShardId = ShardId::ROOT;

    /// A network that refuses to be used, which is the assertion: a
    /// shard answered from this node's own store is asked of nobody.
    struct NoNetwork;

    impl Network for NoNetwork {
        fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {
            unreachable!("nothing is broadcast")
        }
        fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {
            unreachable!("nothing is broadcast")
        }
        fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
        fn register_host_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _: impl Fn(M) + Send + Sync + 'static,
        ) {
        }
        fn register_request_handler<R: Request + Send + 'static>(
            &self,
            _: ShardId,
            _: impl RequestHandler<R>,
        ) where
            R::Response: Send + 'static,
        {
        }
        fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {
            unreachable!("nothing is notified")
        }
        fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
            &self,
            _: impl NotificationHandler<M>,
        ) {
        }
        fn subscribe_shard(&self, _: ShardId) {}
        fn unsubscribe_shard(&self, _: ShardId) {}
        fn update_topology(&self, _: Arc<TopologySnapshot>) {}
        fn update_routing_committees(&self, _: Arc<RoutingCommittees>) {}
        fn request_from<R: Request + Clone + 'static>(
            &self,
            shard: ShardId,
            _: Answerers,
            _: Option<ValidatorId>,
            _: R,
            _: Option<MessageClass>,
            _: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
        ) {
            unreachable!("shard {shard:?} was answered from this node's own store")
        }
    }

    /// A store of eight entries, and the root its only commit produced.
    fn served(ask: &DeclaredReads) -> (GetCellsResponse, StateRoot) {
        served_over(0..8, ask)
    }

    /// [`served`], over a store holding `orders`.
    fn served_over(
        orders: impl IntoIterator<Item = u128>,
        ask: &DeclaredReads,
    ) -> (GetCellsResponse, StateRoot) {
        let storage = Arc::new(SimShardStorage::default());
        let written: Vec<(u128, Option<Vec<u8>>)> = orders
            .into_iter()
            .map(|order| {
                (
                    order,
                    Some(vec![u8::try_from(order).expect("a small order"); 4]),
                )
            })
            .collect();
        let root = commit_writes(&*storage, &make_settled_entries(OWNER_SEED, &written));
        let chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));
        let response = serve_cells_request(
            &chain,
            &GetCellsRequest::new(ask.keys.clone(), ask.ranges.clone()),
        );
        (response, root)
    }

    fn one_range() -> DeclaredReads {
        let key = entry_key(OWNER_SEED, 0);
        DeclaredReads {
            keys: Capped::empty(),
            ranges: Capped::from_array([CellRange {
                owner: key.owner,
                collection: key.collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            }]),
        }
    }

    /// `response`, re-anchored on a header `committee` signed over `root`
    /// so the stranger's path verifies it: the fixture store's own anchor
    /// carries a placeholder certificate no committee signed.
    fn signed_by(
        committee: &TestCommittee,
        mut response: GetCellsResponse,
        root: StateRoot,
    ) -> GetCellsResponse {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(1),
            state_root: root,
            ..Default::default()
        });
        let qc = committee.sign_qc(
            &header,
            &committee.quorum_indices(),
            WeightedTimestamp::ZERO,
        );
        response.anchor = Some(Box::new(CertifiedBlockHeader::new(header, qc)));
        response
    }

    /// A network that answers every request with `response` and keeps
    /// the verdict the caller returned about the peer.
    ///
    /// Round-tripped through the codec rather than downcast, because
    /// `R::Response` is not `'static` and both sides are `Hbor`.
    struct Answering {
        response: GetCellsResponse,
        verdict: std::sync::Mutex<Option<ResponseVerdict>>,
        /// Asks answered that every stream is backing off, before the
        /// fixture answers for real.
        held: AtomicU32,
        asked: AtomicU32,
        /// Drops each callback unrun once the holds are spent, as a
        /// transport torn down under a request does.
        drops: bool,
    }

    impl Answering {
        fn new(response: GetCellsResponse, held: u32) -> Self {
            Self {
                response,
                verdict: std::sync::Mutex::new(None),
                held: held.into(),
                asked: 0.into(),
                drops: false,
            }
        }
    }

    impl Network for Answering {
        fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {}
        fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {}
        fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
        fn register_host_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _: impl Fn(M) + Send + Sync + 'static,
        ) {
        }
        fn register_request_handler<R: Request + Send + 'static>(
            &self,
            _: ShardId,
            _: impl RequestHandler<R>,
        ) where
            R::Response: Send + 'static,
        {
        }
        fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {}
        fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
            &self,
            _: impl NotificationHandler<M>,
        ) {
        }
        fn subscribe_shard(&self, _: ShardId) {}
        fn unsubscribe_shard(&self, _: ShardId) {}
        fn update_topology(&self, _: Arc<TopologySnapshot>) {}
        fn update_routing_committees(&self, _: Arc<RoutingCommittees>) {}
        fn request_from<R: Request + Clone + 'static>(
            &self,
            _: ShardId,
            _: Answerers,
            _: Option<ValidatorId>,
            _: R,
            _: Option<MessageClass>,
            on_response: Box<
                dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send,
            >,
        ) {
            self.asked.fetch_add(1, Ordering::Relaxed);
            if self
                .held
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                let retry_in = Duration::from_millis(10);
                let _ = on_response(Err(RequestError::BackingOff { retry_in }));
                return;
            }
            if self.drops {
                drop(on_response);
                return;
            }
            let bytes = hbor_to_vec(&self.response).expect("the fixture answer encodes");
            let answer =
                hbor_from_slice::<R::Response>(&bytes).expect("the fixture only asks for cells");
            *self.verdict.lock().expect("no other thread holds it") = Some(on_response(Ok(answer)));
        }
    }

    /// A peer whose answer does not verify is told so, and a peer whose
    /// answer does is not.
    ///
    /// The verdict is what the health tracker ranks the next asker's
    /// peers by, and it is consumed the moment the callback returns — so
    /// deciding it on whether the bytes *decoded* rewards a committee
    /// member that answers every ask with a fabricated proof: it keeps a
    /// perfect score, stays preferred, and the request never rotates to
    /// anyone who would answer honestly.
    #[test]
    fn a_peer_whose_proof_does_not_stand_is_rejected() {
        let ask = one_range();
        let (mut tampered, _) = served(&ask);
        let asks = BTreeMap::from([(SHARD, ask)]);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);

        tampered.ranges[0].entries[0].1 = Bytes::from_array([0xFF; 4]);
        let lying = Answering::new(tampered, 0);
        let fetched = gather(&asks, &topology, &lying, &verifier, &|_, _| None);
        assert!(
            !fetched.anchors.contains_key(&SHARD),
            "a shard that did not verify is absent, so the preview refuses by naming it"
        );
        assert!(
            matches!(
                *lying.verdict.lock().expect("no other thread holds it"),
                Some(ResponseVerdict::Reject)
            ),
            "and the peer is told its answer was worth nothing"
        );
    }

    /// A shard whose every stream is backing off is asked again once the
    /// soonest reopens, rather than read as one that never answered.
    #[test]
    fn a_shard_backing_off_is_asked_again_after_the_wait() {
        let ask = one_range();
        let (response, _) = served(&ask);
        let asks = BTreeMap::from([(SHARD, ask)]);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);

        let held_twice = Answering::new(response, 2);
        gather(&asks, &topology, &held_twice, &verifier, &|_, _| None);
        assert_eq!(held_twice.asked.load(Ordering::Relaxed), 3);
        assert!(
            held_twice
                .verdict
                .lock()
                .expect("no other thread holds it")
                .is_some(),
            "the third ask is answered"
        );
    }

    /// A request whose callback is dropped unrun, after a hold or at once,
    /// ends the gathering when it drops rather than at the deadline.
    #[test]
    fn a_dropped_callback_ends_the_gathering_at_once() {
        let ask = one_range();
        let (response, _) = served(&ask);
        let asks = BTreeMap::from([(SHARD, ask)]);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);

        for held in [0, 1] {
            let dropping = Answering {
                drops: true,
                ..Answering::new(response.clone(), held)
            };
            let started = Instant::now();
            let fetched = gather(&asks, &topology, &dropping, &verifier, &|_, _| None);
            assert!(
                started.elapsed() < GATHER_TIMEOUT / 2,
                "the gathering waited out its deadline after {held} holds"
            );
            assert!(!fetched.anchors.contains_key(&SHARD));
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
            )
            .is_some(),
            "the shard's own answer stands under its own root"
        );
        assert_eq!(into.entries.len(), 1, "and the entries it carried are kept");

        let mut tampered = response.clone();
        tampered.ranges[0].entries[0].1 = Bytes::from_array([0xFF; 4]);
        let mut nothing = FetchedCells::default();
        assert!(
            fold_attested(
                SHARD,
                &ask,
                &tampered,
                &proof,
                root,
                BlockHeight::new(1),
                &mut nothing
            )
            .is_none(),
            "a value the root never attested is refused"
        );
        assert!(
            nothing.cells.is_empty() && nothing.entries.is_empty() && nothing.anchors.is_empty(),
            "and nothing of a refused answer is kept, so a partial \
             verification contributes no cell"
        );
    }

    /// A shard this node serves is gathered from its own store, and
    /// nothing is asked of anybody.
    ///
    /// A node hosting several shards holds a store apiece, and the
    /// snapshot a preview runs against spans one of them. The others
    /// have to be gathered like any shard the node does not hold, or
    /// their cells read back as absent — an absence a kernel cannot
    /// tell from an empty cell, so the report would name a verdict the
    /// chain never reaches.
    #[test]
    fn a_shard_this_node_serves_is_gathered_from_its_own_store() {
        let ask = one_range();
        let asks = BTreeMap::from([(SHARD, ask.clone())]);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));

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
        // A second block naming the root the first produced, since a
        // served answer stands on the anchor's stated root and the
        // block fixture above names none. Empty, so the root holds.
        let tip = Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: SHARD,
                height: BlockHeight::new(2),
                state_root: root,
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        commit_settled_at(
            &*storage,
            &make_test_certified(tip),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));

        let fetched = gather(
            &asks,
            &topology,
            &NoNetwork,
            &(Arc::new(BlsVerifier) as Arc<dyn Verifier>),
            &|shard, request| {
                assert_eq!(shard, SHARD);
                Some(serve_cells_request(&chain, request))
            },
        );

        assert_eq!(
            fetched.anchors.keys().copied().collect::<Vec<_>>(),
            vec![SHARD],
            "the shard stands in the anchors, so the preview does not refuse by naming it"
        );
        assert_eq!(
            fetched
                .entries_in_range(
                    ask.ranges[0].owner,
                    ask.ranges[0].collection,
                    0,
                    u128::MAX,
                    8
                )
                .len(),
            4,
            "with the entries its own store holds, up to the cap the declaration named"
        );
        assert!(
            fetched.unproven.is_empty(),
            "and an interval this node answered itself is not a stranger's word"
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
        volunteered
            .cells
            .push((test_key(0x5A), Bytes::from_array([0xAB; 8])))
            .expect("under the cell cap");

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
            )
            .is_some(),
            "the intervals that were asked for still stand under the root"
        );
        assert_eq!(into.entries.len(), 1, "so the answer's own content is kept");
        assert!(
            into.cells.is_empty(),
            "and the volunteered cell is not, having no leaf behind it"
        );
    }

    /// An interval a peer answered with an entry left out still verifies,
    /// and the gathering names it as resting on that peer's word.
    ///
    /// The peer answers `[0, MAX]` as though it were `[1, MAX]`: every
    /// entry it returns is a genuine leaf, so the proof reconstructs and
    /// the shard stands in the anchors, and the run would read order 0 as
    /// absent. Nothing in the answer can say otherwise, so the interval is
    /// reported rather than trusted.
    #[test]
    fn an_interval_a_peer_answered_short_is_named_unproven() {
        let ask = one_range();
        let key = entry_key(OWNER_SEED, 0);
        let mut narrower = ask.clone();
        narrower.ranges[0].lo = 1;
        let (response, root) = served(&narrower);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);

        let peer = Answering::new(signed_by(&committee, response, root), 0);
        let fetched = gather(
            &BTreeMap::from([(SHARD, ask.clone())]),
            &topology,
            &peer,
            &verifier,
            &|_, _| None,
        );
        assert!(
            fetched.anchors.contains_key(&SHARD),
            "every entry the peer returned stands under the root, so the answer verifies"
        );
        assert_eq!(
            fetched
                .entries_in_range(key.owner, key.collection, 0, u128::MAX, 8)
                .iter()
                .map(|(order, _)| *order)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4],
            "and the run would read order 0 as absent"
        );
        assert_eq!(
            fetched.unproven,
            BTreeSet::from([UnprovenInterval::from(&ask.ranges[0])]),
            "so the interval is named as the peer's word"
        );
    }

    /// Point reads a peer answered are proven present or absent, and a
    /// width-one interval whose entry came back has nothing left to omit:
    /// none of them is named unproven.
    #[test]
    fn proven_reads_a_peer_answered_are_not_named_unproven() {
        let key = entry_key(OWNER_SEED, 0);
        let ask = DeclaredReads {
            keys: Capped::from_array([test_key(0x5A)]),
            ranges: Capped::from_array([CellRange {
                owner: key.owner,
                collection: key.collection,
                lo: 2,
                hi: 2,
                cap: 1,
            }]),
        };
        let (response, root) = served(&ask);
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);

        let peer = Answering::new(signed_by(&committee, response, root), 0);
        let fetched = gather(
            &BTreeMap::from([(SHARD, ask)]),
            &topology,
            &peer,
            &verifier,
            &|_, _| None,
        );
        assert!(fetched.anchors.contains_key(&SHARD), "the answer verifies");
        assert!(
            fetched.unproven.is_empty(),
            "and every read in it is proven: {:?}",
            fetched.unproven
        );
    }

    /// A single order and an absent point key, so the proof is not empty
    /// once the order's own claim is cut out of it.
    fn one_order(order: u128) -> DeclaredReads {
        let key = entry_key(OWNER_SEED, 0);
        DeclaredReads {
            keys: Capped::from_array([test_key(0x5A)]),
            ranges: Capped::from_array([CellRange {
                owner: key.owner,
                collection: key.collection,
                lo: order,
                hi: order,
                cap: 1,
            }]),
        }
    }

    /// `ask` gathered from a peer answering with `response`, anchored on a
    /// header the committee signed over `root`.
    fn gathered_from(
        ask: &DeclaredReads,
        response: GetCellsResponse,
        root: StateRoot,
    ) -> (FetchedCells, Option<ResponseVerdict>) {
        let committee = TestCommittee::new(4, 7);
        let topology = Arc::new(committee.topology_snapshot(1));
        let verifier: Arc<dyn Verifier> = Arc::new(BlsVerifier);
        let peer = Answering::new(signed_by(&committee, response, root), 0);
        let fetched = gather(
            &BTreeMap::from([(SHARD, ask.clone())]),
            &topology,
            &peer,
            &verifier,
            &|_, _| None,
        );
        let verdict = peer
            .verdict
            .lock()
            .expect("no other thread holds it")
            .take();
        (fetched, verdict)
    }

    /// A single order a peer answered empty, with the proof claiming its
    /// leaf absent, has nothing left to omit and is not named unproven.
    #[test]
    fn a_single_order_proven_absent_is_not_named_unproven() {
        let ask = one_order(9);
        let (response, root) = served(&ask);
        assert!(
            response.ranges[0].entries.is_empty(),
            "order 9 was never written"
        );

        let (fetched, verdict) = gathered_from(&ask, response, root);
        assert!(fetched.anchors.contains_key(&SHARD), "the answer verifies");
        assert!(matches!(verdict, Some(ResponseVerdict::Accept)));
        assert!(
            fetched.unproven.is_empty(),
            "and the empty order is proven empty: {:?}",
            fetched.unproven
        );
    }

    /// A single order a peer answered empty with no claim on its leaf is
    /// the peer's word, as any wider interval is.
    ///
    /// The rest of the proof stands, so the answer is kept; it is only
    /// the order's emptiness that nothing attests.
    #[test]
    fn a_single_order_answered_empty_without_a_proof_is_named_unproven() {
        let ask = one_order(9);
        let (mut response, root) = served(&ask);
        let proof = response.proof.as_ref().expect("the tip is answerable");
        response.proof = Some(proof.restrict(&ask.keys).expect("the point key is claimed"));

        let (fetched, verdict) = gathered_from(&ask, response, root);
        assert!(
            fetched.anchors.contains_key(&SHARD),
            "the point key still stands under the root"
        );
        assert!(matches!(verdict, Some(ResponseVerdict::Accept)));
        assert_eq!(
            fetched.unproven,
            BTreeSet::from([UnprovenInterval::from(&ask.ranges[0])]),
            "and the order nothing proves empty is named"
        );
    }

    /// A single order a peer answered empty while it holds an entry is
    /// never read as proven empty.
    ///
    /// Two ways to try it. An absence claim taken from a tree without the
    /// entry does not reconstruct the root the committee signed, so the
    /// whole answer is refused and the peer told so. The honest proof
    /// with the entry dropped from the answer claims the leaf present,
    /// which proves nothing empty, so the order stays the peer's word.
    #[test]
    fn a_single_order_whose_entry_is_held_is_not_proven_empty() {
        let ask = one_order(2);
        let (honest, root) = served(&ask);
        assert_eq!(honest.ranges[0].entries.len(), 1, "order 2 is held");

        let (mut forged, _) = served_over((0..8).filter(|order| *order != 2), &ask);
        assert!(forged.ranges[0].entries.is_empty());
        forged.anchor = None;
        let (fetched, verdict) = gathered_from(&ask, forged, root);
        assert!(
            !fetched.anchors.contains_key(&SHARD),
            "an absence the signed root does not hold refuses the answer"
        );
        assert!(matches!(verdict, Some(ResponseVerdict::Reject)));

        let mut withheld = honest;
        withheld.ranges[0].entries = Capped::empty();
        let (fetched, verdict) = gathered_from(&ask, withheld, root);
        assert!(fetched.anchors.contains_key(&SHARD));
        assert!(matches!(verdict, Some(ResponseVerdict::Accept)));
        assert_eq!(
            fetched.unproven,
            BTreeSet::from([UnprovenInterval::from(&ask.ranges[0])]),
            "a leaf proven present proves the order anything but empty"
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
            fold_attested(
                SHARD,
                &ask,
                &short,
                &proof,
                root,
                BlockHeight::new(1),
                &mut nothing
            )
            .is_none(),
            "an answer naming fewer intervals than were asked is not a partial answer"
        );
    }
}
