//! Inbound state-proof handling.
//!
//! Answers a peer asking what this shard's state held at a committed
//! height for a set of keys — present or absent, one multiproof over
//! all of them. The requester holds the commit-proven header for the
//! height and checks the proof against its state root, so this server
//! is trusted for nothing: a proof against any other tree fails to
//! reconstruct that root and is rotated off.

use std::sync::Arc;

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{PendingChain, ShardStorage, Substates};
use hyperscale_types::network::request::{
    GetCellsRequest, GetRelayedStateProofRequest, GetStateProofRequest,
};
use hyperscale_types::network::response::{GetCellsResponse, GetStateProofResponse, RangeAnswer};
use hyperscale_types::{
    EntryKey, MAX_CELLS_PER_QUERY, MAX_CELLS_RESPONSE_BYTES, ProtocolHasher, ProvenCells,
    SubstateKey, entry_leaf_key,
};

/// Serve an inbound state-proof query from the committed chain.
///
/// Returns `not_found` when the height is one this shard no longer
/// answers for — below the retention floor — or when the JMT version it
/// names is not held at all, so the requester rotates rather than
/// reading an empty tree as an empty answer. The floor is asked rather
/// than inferred from whether the collector has run: the same bound the
/// provisions server serves under, so both refuse the same heights.
/// Nothing is asked of the keys: a key nothing ever wrote proves absent
/// like any other.
#[must_use]
pub fn serve_state_proof_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    req: &GetStateProofRequest,
) -> GetStateProofResponse {
    let view = pending_chain.view_at_committed_tip();
    if !view.serves_at(req.height) {
        record_fetch_response_sent("state_proof", 0);
        return GetStateProofResponse::not_found();
    }
    generate_proof(view.as_ref(), &req.keys, req.height).map_or_else(
        || {
            record_fetch_response_sent("state_proof", 0);
            GetStateProofResponse::not_found()
        },
        |proof| {
            record_fetch_response_sent("state_proof", req.keys.len());
            GetStateProofResponse::found(proof)
        },
    )
}

/// Serve an inbound cells query: the point cells and collection
/// intervals a declaration reaches, at this shard's committed tip.
///
/// What [`serve_state_proof_request`] does for named keys, in the terms
/// a declaration is written in — and at an anchor this server picks
/// rather than one the asker names, because the asker is assembling a
/// preview and holds no view of this chain to name a height from. The
/// certified header rides back with the answer so the proof is
/// checkable: the asker verifies that header against this shard's
/// committee, which it holds for every shard, and then the proof against
/// the header's own root.
///
/// Read off the base store at the tip's version rather than through the
/// committed tip's view, so no pending descendant this node happens to
/// hold leaks into an answer about committed state.
///
/// The proof covers the point keys asked, present or absent, and the
/// entry leaves the intervals actually returned. It does not attest that
/// an interval is complete, and cannot: an entry commits under a digest
/// of its owner, collection and order, so the tree's key order is not
/// the collection's and no non-inclusion proof over it says what lies
/// between two orders. A server may answer with a narrower collection
/// than it holds; it cannot answer with a value nobody wrote.
#[must_use]
pub fn serve_cells_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    req: &GetCellsRequest,
) -> GetCellsResponse {
    let view = pending_chain.view_at_committed_tip();
    let height = view.base().committed_height();
    // The header is what makes the answer checkable, so an anchor this
    // node cannot produce one for is no answer at all.
    let Some(anchor) = pending_chain.certified_header(height) else {
        record_fetch_response_sent("cells", 0);
        return GetCellsResponse::not_found();
    };
    let at = view.base().snapshot_at(height);

    // What the answer would cost before any of it is spent. Nothing
    // here is signed — a preview asks before there is a transaction to
    // sign — so the caps are the asker's word, and a query wider than
    // any declaration could be is refused rather than walked.
    let asked = req.ranges.iter().fold(req.keys.len() as u64, |sum, range| {
        sum.saturating_add(u64::from(range.cap))
    });
    if asked > MAX_CELLS_PER_QUERY {
        record_fetch_response_sent("cells", 0);
        return GetCellsResponse::not_found();
    }

    // What the values weigh, which the leaf cap says nothing about: a
    // leaf runs to the widest slot there is. Spent as the answer is
    // built, since only the walk knows what the leaves hold.
    let mut carried = 0usize;

    let cells: Vec<(SubstateKey, Vec<u8>)> = req
        .keys
        .iter()
        .filter_map(|key| at.cell(*key).map(|value| (*key, value)))
        .collect();
    for (_, value) in &cells {
        carried = carried.saturating_add(value.len());
    }
    if carried > MAX_CELLS_RESPONSE_BYTES {
        record_fetch_response_sent("cells", 0);
        return GetCellsResponse::not_found();
    }

    // Every leaf the answer stands on, so one multiproof covers the
    // whole of it: the keys as asked — an absent one is proven absent —
    // and an entry leaf per entry a range returned.
    let mut leaves = req.keys.clone();
    let mut ranges = Vec::with_capacity(req.ranges.len());
    for range in &req.ranges {
        let entries = at.entries_in_range(
            range.owner,
            range.collection,
            range.lo,
            range.hi,
            range.cap as usize,
        );
        for (_, value) in &entries {
            carried = carried.saturating_add(value.len());
        }
        if carried > MAX_CELLS_RESPONSE_BYTES {
            record_fetch_response_sent("cells", 0);
            return GetCellsResponse::not_found();
        }
        leaves.extend(entries.iter().map(|(order, _)| {
            entry_leaf_key(
                &ProtocolHasher,
                EntryKey {
                    owner: range.owner,
                    collection: range.collection,
                    order: *order,
                },
            )
        }));
        ranges.push(RangeAnswer { entries });
    }

    generate_proof(view.as_ref(), &leaves, height).map_or_else(
        || {
            record_fetch_response_sent("cells", 0);
            GetCellsResponse::not_found()
        },
        |proof| {
            record_fetch_response_sent("cells", leaves.len());
            GetCellsResponse::found(cells, ranges, proof, (*anchor).clone().into_inner())
        },
    )
}

/// Relay a proof of another shard's state that this node fetched for
/// itself, to a committee peer that could not obtain one.
///
/// Answers only from what is already held: this node has no copy of the
/// counterpart's tree and cannot construct a proof of it. So a peer
/// asking about an anchor this node never probed, or about keys no one
/// proof of it covers, is answered `not_found` and rotates to a member
/// whose probe did land there.
///
/// Passing the bytes on grants no trust. The requester checks them
/// against the state root of the header it commit-proved for the height,
/// so a relayed proof of any other tree fails there just as a
/// counterpart's would.
#[must_use]
pub fn serve_relayed_state_proof_request(
    proven_cells: &Arc<ProvenCells>,
    req: &GetRelayedStateProofRequest,
) -> GetStateProofResponse {
    proven_cells
        .relay(req.shard, req.height, &req.keys)
        .map_or_else(
            || {
                record_fetch_response_sent("relayed_state_proof", 0);
                GetStateProofResponse::not_found()
            },
            |proof| {
                record_fetch_response_sent("relayed_state_proof", req.keys.len());
                GetStateProofResponse::found(proof)
            },
        )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{
        commit_settled_at, commit_writes, entry_key, make_settled_entries, make_test_certified,
    };
    use hyperscale_storage::{
        PendingChain, SubstateStore, committed_tx_cell_key, committed_tx_cells,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::CellRange;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, Inclusion, ProposerTimestamp,
        QuorumCertificate, RETENTION_HORIZON, Round, ShardId, SignerBitfield, StateRoot,
        Transaction, Verifiable, WeightedTimestamp, WitnessSources,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    /// A chain committing `test_transaction(1)` in its first block, one
    /// block per entry of `stamps`, and the state root at that first
    /// height — the one a proof taken there reconstructs.
    fn chain_of(stamps: &[u64]) -> (Arc<PendingChain<SimShardStorage>>, StateRoot) {
        let storage = SimShardStorage::default();
        let mut first_root = StateRoot::ZERO;
        for (index, ts_ms) in stamps.iter().enumerate() {
            let height = u64::try_from(index).expect("small fixture") + 1;
            let parent_qc = QuorumCertificate::new(
                BlockHash::ZERO,
                SHARD,
                BlockHeight::new(height - 1),
                BlockHash::ZERO,
                Round::INITIAL,
                SignerBitfield::new(4),
                AggregateSignature::new([0u8; 96]),
                WeightedTimestamp::from_millis(*ts_ms),
            );
            let header = BlockHeader::new(BlockHeaderParts {
                shard_id: SHARD,
                height: BlockHeight::new(height),
                parent_block_hash: BlockHash::ZERO,
                parent_qc: parent_qc.into(),
                timestamp: ProposerTimestamp::from_millis(*ts_ms),
                provision_tx_roots: std::collections::BTreeMap::new(),
                ..Default::default()
            });
            let txs: Vec<Arc<Verifiable<Transaction>>> = if height == 1 {
                vec![Arc::new(Verifiable::from(test_transaction(1)))]
            } else {
                Vec::new()
            };
            let block = Block::Live {
                header,
                transactions: Arc::new(txs),
                certificates: Arc::new(Vec::new()),
                provisions: Arc::new(Vec::new()),
                abandonment_records: Arc::new(Vec::new()),
                state_claims: Arc::new(Vec::new()),
                witness_sources: Arc::new(WitnessSources::empty()),
            };
            let creations = committed_tx_cells(
                SHARD,
                block.transactions().iter().map(|tx| tx.as_unverified()),
            );
            commit_settled_at(
                &storage,
                &make_test_certified(block),
                &creations,
                &[],
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
            if height == 1 {
                first_root = storage.state_root();
            }
        }
        (Arc::new(PendingChain::new(Arc::new(storage))), first_root)
    }

    /// A one-block chain committing `test_transaction(1)`, and its state
    /// root at that height.
    fn chain() -> (Arc<PendingChain<SimShardStorage>>, StateRoot) {
        chain_of(&[1_000])
    }

    /// A height the shard no longer answers for is refused, and the
    /// refusal is the retention floor's rather than the collector's:
    /// nothing here depends on whether a sweep has run, so this server
    /// and the provisions server serve the same span.
    #[test]
    fn a_height_below_the_retention_floor_is_not_served() {
        let horizon = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        let (chain, _) = chain_of(&[1_000, 1_001 + horizon]);
        let key = committed_tx_cell_key(
            SHARD,
            test_transaction(1).hash(),
            test_transaction(1).validity_range().end_timestamp_exclusive,
        );

        let view = chain.view_at_committed_tip();
        assert!(
            !view.serves_at(BlockHeight::new(1)),
            "block one has aged out"
        );
        assert!(view.serves_at(BlockHeight::new(2)));

        let refused = serve_state_proof_request(
            &chain,
            &GetStateProofRequest::new(BlockHeight::new(1), vec![key]),
        );
        assert!(
            refused.proof.is_none(),
            "a height past the horizon is answered not-found, not proved",
        );
        let served = serve_state_proof_request(
            &chain,
            &GetStateProofRequest::new(BlockHeight::new(2), vec![key]),
        );
        assert!(served.proof.is_some(), "and the tip is still answered");
    }

    /// A declared interval comes back as the entries it holds, each
    /// proven under the height's root, and the points beside it answer
    /// as they would through the proof server.
    ///
    /// The entries are asked for in the collection's order space and
    /// proven in the tree's, which are not the same order — the leaf
    /// key is a digest of owner, collection and order — so what the
    /// answer has to carry is enough for the requester to rederive each
    /// leaf from the order it was handed.
    ///
    /// The retention floor is not re-pinned here: both arms ask
    /// `serves_at` before they read, and
    /// `a_height_below_the_retention_floor_is_not_served` is that one
    /// statement.
    /// A query asking for more leaves than any declaration could is
    /// refused before the tree is walked.
    ///
    /// This request is asked on behalf of a transaction that does not
    /// exist yet, so nothing in it is signed and `cap` is the asker's
    /// word. Unbounded, a handful of intervals at `u32::MAX` over the
    /// whole order space would have the server scan every collection it
    /// holds and build a multiproof over every leaf, for a reply the
    /// frame then discards.
    #[test]
    fn a_query_past_the_leaf_budget_is_refused() {
        const OWNER_SEED: u8 = 0x11;
        let storage = Arc::new(SimShardStorage::default());
        let written: Vec<(u128, Option<Vec<u8>>)> = (0u128..8)
            .map(|order| {
                (
                    order,
                    Some(vec![u8::try_from(order).expect("eight entries"); 4]),
                )
            })
            .collect();
        commit_writes(&*storage, &make_settled_entries(OWNER_SEED, &written));
        let chain = Arc::new(PendingChain::new(storage));
        let key = entry_key(OWNER_SEED, 0);
        let whole_space = |cap: u32| CellRange {
            owner: key.owner,
            collection: key.collection,
            lo: 0,
            hi: u128::MAX,
            cap,
        };

        let refused = serve_cells_request(
            &chain,
            &GetCellsRequest::new(Vec::new(), vec![whole_space(u32::MAX)]),
        );
        assert!(
            refused.proof.is_none(),
            "an interval no declaration could have bought is not answered"
        );

        // The budget is spent across the whole request, not per
        // interval: two halves of it asked separately would otherwise
        // buy twice what one asks for.
        let cap = u32::try_from(MAX_CELLS_PER_QUERY).expect("the budget fits a cap");
        let split = serve_cells_request(
            &chain,
            &GetCellsRequest::new(
                Vec::new(),
                vec![whole_space(cap / 2 + 1), whole_space(cap / 2 + 1)],
            ),
        );
        assert!(
            split.proof.is_none(),
            "two intervals summing past the budget are refused together"
        );

        // And what a declaration could have bought is still served.
        let served = serve_cells_request(
            &chain,
            &GetCellsRequest::new(Vec::new(), vec![whole_space(cap)]),
        );
        assert!(
            served.proof.is_some(),
            "a query inside the budget is answered as before"
        );
    }

    /// The leaf cap bounds how many leaves an answer stands on and says
    /// nothing about what they hold. A leaf runs to the widest slot
    /// there is, so a query well inside the cap can still name more
    /// bytes than the frame carries — and the transports drop an
    /// oversize message rather than truncating it, so building one is
    /// the whole walk and the whole proof for an answer nobody reads.
    #[test]
    fn an_answer_past_the_frame_is_refused_though_its_leaves_are_few() {
        const OWNER_SEED: u8 = 0x13;
        // Wide leaves, few of them: a count no leaf cap would stop.
        const WIDTH: usize = 16 * 1024;
        let count = MAX_CELLS_RESPONSE_BYTES / WIDTH + 1;
        assert!(
            (count as u64) < MAX_CELLS_PER_QUERY,
            "the leaf cap must not be what refuses this, or it proves nothing"
        );

        let storage = Arc::new(SimShardStorage::default());
        let written: Vec<(u128, Option<Vec<u8>>)> = (0..count as u128)
            .map(|order| (order, Some(vec![0xAB; WIDTH])))
            .collect();
        commit_writes(&*storage, &make_settled_entries(OWNER_SEED, &written));
        let chain = Arc::new(PendingChain::new(storage));
        let key = entry_key(OWNER_SEED, 0);
        let whole = |cap: u32| CellRange {
            owner: key.owner,
            collection: key.collection,
            lo: 0,
            hi: u128::MAX,
            cap,
        };

        let refused = serve_cells_request(
            &chain,
            &GetCellsRequest::new(
                Vec::new(),
                vec![whole(u32::try_from(count).expect("a small count"))],
            ),
        );
        assert!(
            refused.proof.is_none(),
            "an answer whose values outweigh the frame is refused, not built"
        );

        // And one leaf fewer is inside the budget and served, so what
        // refuses above is the budget and not the shape of the query.
        let served = serve_cells_request(
            &chain,
            &GetCellsRequest::new(
                Vec::new(),
                vec![whole(u32::try_from(count - 1).expect("a small count"))],
            ),
        );
        assert!(
            served.proof.is_some(),
            "the same query one leaf lighter is answered"
        );
    }

    #[test]
    fn an_interval_comes_back_proven_entry_by_entry() {
        const OWNER_SEED: u8 = 0x11;
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
        let height = BlockHeight::new(1);
        let owner = entry_key(OWNER_SEED, 0).owner;
        let collection = entry_key(OWNER_SEED, 0).collection;

        // A cap under what the interval holds: the declaration bought
        // three leaves and is answered with three, not with everything.
        let response = serve_cells_request(
            &chain,
            &GetCellsRequest::new(
                Vec::new(),
                vec![CellRange {
                    owner,
                    collection,
                    lo: 2,
                    hi: u128::MAX,
                    cap: 3,
                }],
            ),
        );
        let proof = response.proof.expect("the tip is answerable");
        let anchor = response
            .anchor
            .expect("an answer carries the header it stands on");
        assert_eq!(
            anchor.header().height(),
            height,
            "the server names the anchor it chose, which is the only thing that \
             makes the proof checkable to an asker holding no view of this chain"
        );
        let answered = &response.ranges[0].entries;
        assert_eq!(
            answered.iter().map(|(order, _)| *order).collect::<Vec<_>>(),
            vec![2, 3, 4],
            "the interval is answered from its low end, up to the cap the declaration signed"
        );

        // Every entry it named proves present, at the leaf the requester
        // rederives from the order alone.
        let leaves: Vec<SubstateKey> = answered
            .iter()
            .map(|(order, _)| {
                entry_leaf_key(
                    &ProtocolHasher,
                    EntryKey {
                        owner,
                        collection,
                        order: *order,
                    },
                )
            })
            .collect();
        let attested = proof.inclusions(root, SHARD, &leaves).unwrap();
        assert!(
            attested.iter().all(|(_, inclusion)| inclusion.is_present()),
            "every entry the answer carries stands under the height's root"
        );
    }

    /// The committed cell of a transaction the chain committed proves
    /// present under the height's root, one it never saw proves absent,
    /// and a height not held answers `not_found`.
    #[test]
    fn proves_the_committed_cell_present_or_absent_under_the_root() {
        let (chain, root) = chain();
        let cell = |tx: &Transaction| {
            committed_tx_cell_key(
                SHARD,
                tx.hash(),
                tx.validity_range().end_timestamp_exclusive,
            )
        };
        let committed = cell(&test_transaction(1));
        let never = cell(&test_transaction(99));
        let keys = vec![never, committed];

        let response = serve_state_proof_request(
            &chain,
            &GetStateProofRequest::new(BlockHeight::new(1), keys.clone()),
        );
        let proof = response.proof.expect("the height is held");
        let attested = proof.inclusions(root, SHARD, &keys).unwrap();
        assert_eq!(attested[0], (never, Inclusion::Absent));
        assert_eq!(attested[1].0, committed);
        assert!(attested[1].1.is_present());

        let unheld = serve_state_proof_request(
            &chain,
            &GetStateProofRequest::new(BlockHeight::new(7), keys),
        );
        assert!(
            unheld.proof.is_none(),
            "a height not held is not an empty tree"
        );
    }
}
