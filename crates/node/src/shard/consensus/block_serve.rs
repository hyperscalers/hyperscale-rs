//! Inbound block-sync request handling.
//!
//! Serves `GetBlockRequest`s from peers catching up via the sync protocol.
//! Reads the block through `PendingChain` so shard-committed-but-unpersisted
//! heights are served from memory — those blocks are already in their
//! `Block::Live` shape with provisions inline, so no cache lookup is
//! needed. Persisted blocks come back `Block::Sealed`; if the requester
//! will execute the block and the dedup horizon still binds, we re-attach
//! provisions from the local cache, and a miss is reported as `not_found`
//! so the requester rotates to a peer that has them.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_metrics::record_sync_response_error;
use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    ElidedCertifiedBlock, ProvisionHash, Provisions, RETENTION_HORIZON, Verifiable,
};
use tracing::{trace, warn};

/// Serve an inbound block sync request.
///
/// **What the block is for is the requester's fact, and it says so.** A
/// `BlockIntent::History` request records the block beneath a frontier it
/// already holds and never executes it, so it is served in its `Sealed`
/// shape whatever the body cache holds — a server that retired those
/// bodies still has everything the walk asks for, and refusing it would
/// wedge a joiner against a height no peer can ever answer.
///
/// For `BlockIntent::Execute`, whether the requester needs `Block::Live` is
/// a function of the block's own age against the dedup horizon: until
/// `block_ts + RETENTION_HORIZON` passes, every honest validator still keeps
/// the block's provision hashes in its `CommitDedupIndex`, so a peer that
/// commits this block via sync must learn those hashes too. Past the horizon,
/// the dedup entries are gone everywhere and the `Sealed` block is safe to
/// serve.
///
/// The horizon check is based on the block's `parent_qc` weighted timestamp
/// (hash-pinned in the header, so every peer reads the same value for a given
/// block — the same anchor the requester's commit path uses) and the serving
/// peer's own latest QC timestamp as the "now" reference. Neither depends on
/// the requester's view.
///
/// Inside the horizon for a `Sealed` block, a local cache miss returns
/// `not_found`. The invariant downstream commit hooks rely on —
/// `Block::Sealed` means no provision hashes remain load-bearing for
/// dedup — is preserved by refusing rather than silently downgrading the
/// response. The requester rotates to another peer who has the provisions
/// cached. Pending-window blocks never hit this path because their
/// provisions are inline.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
pub fn serve_block_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    provision_store: &ProvisionStore,
    req: &GetBlockRequest,
) -> GetBlockResponse {
    trace!(
        height = req.height.inner(),
        intent = ?req.intent,
        "Handling block sync request"
    );
    let Some(BlockForSync {
        block,
        qc,
        provision_hashes,
    }) = pending_chain.block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    if req.intent == BlockIntent::History {
        // Sealed regardless of what the cache holds: the walk writes the
        // metadata row, the transactions and the certificates, and no
        // provision body is in that set.
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &block.into_sealed(),
            qc,
            &req.inventory,
        ));
    }

    let block_ts = block.header().parent_qc().weighted_timestamp();
    let tip_ts = pending_chain
        .latest_qc()
        .map_or(block_ts, |q| q.weighted_timestamp());
    let inside_dedup_horizon = tip_ts.elapsed_since(block_ts) < RETENTION_HORIZON;

    if !inside_dedup_horizon {
        // Past the execution window — provisions are no longer load-bearing
        // for dedup or for executor tick state, so serve whatever shape we
        // already have. The receiver will commit `Sealed` and skip
        // execution; that's the correct outcome at this point.
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    // Pending-window blocks are already Live with provisions inline; no
    // cache round-trip needed. Persisted blocks come back Sealed and need
    // the upgrade even when the block consumed no provisions — the
    // variant tag itself is load-bearing on the requester so its commit
    // path runs the execution tick through `on_live_block_committed`.
    if block.is_live() {
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    let resolved: Vec<(ProvisionHash, Option<Arc<Provisions>>)> = provision_hashes
        .iter()
        .map(|h| (*h, provision_store.get(*h)))
        .collect();

    let missing: Vec<ProvisionHash> = resolved
        .iter()
        .filter_map(|(h, p)| p.is_none().then_some(*h))
        .collect();

    if !missing.is_empty() {
        warn!(
            height = req.height.inner(),
            requested = provision_hashes.len(),
            missing_count = missing.len(),
            missing = ?missing,
            "Cache miss for provisions inside dedup horizon — returning not_found so requester rotates"
        );
        record_sync_response_error("block", "provision_cache_miss");
        return GetBlockResponse::not_found();
    }

    // Sync responses ship raw provision bodies into the wire-typed
    // `Block::Live.provisions`; encoding lands at `Verifiable::Unverified`
    // on the receiver and verification proceeds from there. Missing
    // entries returned `not_found` above, so every body resolves here.
    let provisions: Vec<Arc<Verifiable<Provisions>>> = resolved
        .into_iter()
        .filter_map(|(_, p)| p.map(|raw| Arc::new((*raw).clone().into())))
        .collect();

    GetBlockResponse::found(ElidedCertifiedBlock::elide(
        &block.into_live(Arc::new(
            Capped::new(provisions).expect("a rebuilt block keeps the caps its source met"),
        )),
        qc,
        &req.inventory,
    ))
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::ChainEntry;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::tree::{CollectedWrites, JmtSnapshot};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::BlockIntent;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeight, ChainOrigin, Hash,
        MerkleInclusionProof, SettledWrites, ShardId, StateRoot, WeightedTimestamp,
    };

    use super::*;

    /// A chain of one committed block, `Sealed`, naming one provision
    /// body — and a provision cache that holds none. The block's own
    /// anchor sits a second below the tip's, so the dedup horizon binds.
    fn chain_with_a_retired_provision() -> PendingChain<SimShardStorage> {
        let storage = SimShardStorage::default();
        let hash = ProvisionHash::from_raw(Hash::from_bytes(b"a provision nobody kept"));
        let Block::Sealed {
            header,
            transactions,
            certificates,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } = make_test_block(BlockHeight::new(1)).into_sealed()
        else {
            unreachable!("into_sealed yields a sealed block")
        };
        let block = Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes: Arc::new(Capped::from_array([hash])),
            abandonment_records,
            state_claims,
            witness_sources,
        };
        commit_settled_at(
            &storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        PendingChain::new(Arc::new(storage), ChainOrigin::ROOT)
    }

    /// A `Live` block at `height` carrying one provisions bundle
    /// inline, as the pending window holds a block before it seals.
    fn live_block_with_a_provision(height: BlockHeight) -> Block {
        let bundle = Provisions::new(
            ShardId::ROOT,
            ShardId::ROOT,
            height,
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::new(vec![]),
            Capped::empty(),
        );
        let Block::Live {
            header,
            transactions,
            certificates,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } = make_test_block(height)
        else {
            unreachable!("the fixture builds a live block")
        };
        Block::Live {
            header,
            transactions,
            certificates,
            provisions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(bundle))])),
            abandonment_records,
            state_claims,
            witness_sources,
        }
    }

    /// The hazard this rule exists for: inside the dedup horizon a
    /// server that no longer holds a body cannot answer a requester
    /// that will execute the block, and every peer is in the same
    /// position once the bodies age out — so an execute request at such
    /// a height can never be answered by anyone.
    #[test]
    fn an_execute_request_is_refused_when_the_body_is_gone() {
        let chain = chain_with_a_retired_provision();
        let response = serve_block_request(
            &chain,
            &ProvisionStore::new(),
            &GetBlockRequest::new(BlockHeight::new(1), BlockIntent::Execute),
        );
        assert!(
            response.certified.is_none(),
            "a block whose provisions this peer cannot supply is not an answer to an executor",
        );
    }

    /// And the same height, asked for by a walk that will record it and
    /// never run it, is answered — sealed, and whole enough to
    /// rehydrate against a store that can resolve nothing.
    #[test]
    fn a_history_request_is_answered_from_the_same_store() {
        let chain = chain_with_a_retired_provision();
        let response = serve_block_request(
            &chain,
            &ProvisionStore::new(),
            &GetBlockRequest::new(BlockHeight::new(1), BlockIntent::History),
        );
        let elided = response
            .certified
            .as_ref()
            .expect("a history walk asks for nothing this peer has retired");
        let certified = elided
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect("a joiner resolves no body of its own");
        assert!(
            !certified.block().is_live(),
            "a history answer carries no provision bodies",
        );
        assert_eq!(certified.height(), BlockHeight::new(1));
    }

    /// A history walk that lands on a height still in the serving
    /// peer's pending window gets it sealed too. That block's bodies
    /// are inline and cost nothing to supply, and the walk discards
    /// them either way, so the answer says what it means.
    #[test]
    fn a_history_answer_sheds_bodies_the_walk_will_not_keep() {
        let storage = Arc::new(SimShardStorage::default());
        let chain = PendingChain::new(Arc::clone(&storage), ChainOrigin::ROOT);
        let block = live_block_with_a_provision(BlockHeight::new(1));
        let hash = block.hash();
        chain.insert(
            hash,
            ChainEntry {
                parent_block_hash: block.header().parent_block_hash(),
                height: BlockHeight::new(1),
                settled_txs: Vec::new(),
                jmt_snapshot: Arc::new(JmtSnapshot::from_collected_writes(
                    CollectedWrites::default(),
                    SettledWrites::default(),
                    StateRoot::ZERO,
                    BlockHeight::GENESIS,
                    StateRoot::ZERO,
                    BlockHeight::GENESIS,
                )),
                certified_block: Some(make_test_certified(block)),
                certified_uncommitted: None,
            },
        );

        let response = serve_block_request(
            &chain,
            &ProvisionStore::new(),
            &GetBlockRequest::new(BlockHeight::new(1), BlockIntent::History),
        );
        let certified = response
            .certified
            .as_ref()
            .expect("the pending window serves a history walk")
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect("a joiner resolves no body of its own");
        assert!(
            !certified.block().is_live(),
            "a history answer carries no provision bodies",
        );
    }
}
