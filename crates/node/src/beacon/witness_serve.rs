//! Inbound shard-witness fetch request handling.
//!
//! Beacon validators outside a shard's committee pull witnesses lifted
//! by that shard so they can verify proofs against the shard's
//! QC-attested [`BeaconWitnessRoot`](hyperscale_types::BeaconWitnessRoot).
//! This module is the responder side: read the anchor block's witness
//! window `[base, leaf_count)` from its header, rebuild that window from
//! the retained CF payloads, and answer with one contiguous run plus the
//! range proof lifting it to the window's root.

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::beacon::GetShardWitnessesRequest;
use hyperscale_types::network::response::beacon::GetShardWitnessesResponse;
use hyperscale_types::{Hash, MAX_WITNESSES_PER_SHARD, ShardWitnessPayload, compute_range_proof};
use tracing::{debug, warn};

/// Serve an inbound shard-witness fetch request.
///
/// Lookup proceeds as:
///
/// 1. Resolve the certified header at `req.block_height` through
///    [`PendingChain::certified_header`]. The pending-chain layer spans
///    both the shard-committed-but-unpersisted window and durable
///    storage, so a peer fetching against a freshly committed block
///    sees the same view a peer fetching against a long-persisted
///    block does.
/// 2. Cross-check `header.hash() == req.committed_block_hash`. Mismatch
///    is fork divergence — return empty so the requester falls through
///    to another peer rather than receiving proofs against the wrong
///    root.
/// 3. Resolve the run against the anchor's window: refuse a `lo` below
///    the window base (those leaves are unprovable under this root), and
///    cap `hi` at both the window's end and the fold's per-epoch budget.
/// 4. Read the window's retained payloads via
///    [`ShardChainReader::get_beacon_witness_payloads`](hyperscale_storage::ShardChainReader).
///    A retention-pruned anchor reads short — without the whole window no
///    root can be rebuilt, so the response is empty. Otherwise answer with
///    the run's payloads plus one range proof against the anchor's
///    witness root.
///
/// The proof is scoped to the run it names, so the response carries no
/// per-leaf positions: the requester knows `lo` from its own request and
/// the window from the anchor header it already holds. One pass over the
/// window serves any run, however wide.
pub fn serve_shard_witnesses_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    req: &GetShardWitnessesRequest,
) -> GetShardWitnessesResponse {
    let Some((payloads, range_proof)) = build_chunk(pending_chain, req) else {
        record_fetch_response_sent("shard_witness", 0);
        return GetShardWitnessesResponse::empty();
    };
    record_fetch_response_sent("shard_witness", payloads.len());
    GetShardWitnessesResponse::new(payloads, range_proof)
}

fn build_chunk<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    req: &GetShardWitnessesRequest,
) -> Option<(Vec<ShardWitnessPayload>, Vec<Hash>)> {
    let Some(certified_header) = pending_chain.certified_header(req.block_height) else {
        debug!(
            block_height = req.block_height.inner(),
            "Shard-witness request: block not found"
        );
        return None;
    };
    let header = certified_header.header();
    if header.hash() != req.committed_block_hash {
        warn!(
            block_height = req.block_height.inner(),
            requested = ?req.committed_block_hash,
            local = ?header.hash(),
            "Shard-witness request: anchor hash mismatch (fork divergence)"
        );
        return None;
    }

    // The anchor header's root commits its witness window only; the proof
    // builds over the window's hashes at window-relative positions.
    let base = header.beacon_witness_base().inner();
    let leaf_count_at_block_end = header.beacon_witness_leaf_count().inner();
    let window_len = leaf_count_at_block_end.saturating_sub(base);
    if window_len == 0 {
        return None;
    }

    // A run reaching below the window base names leaves this root cannot
    // prove. Refuse rather than clamp up to the base: the requester
    // verifies at the `lo` it asked for, so a relocated run could only be
    // rejected on arrival, and re-requesting it would spin.
    let lo = req.lo.inner();
    if lo < base {
        debug!(
            block_height = req.block_height.inner(),
            base,
            requested = lo,
            "Shard-witness request: run starts below the anchor's window base"
        );
        return None;
    }

    // Clamp the requested run to the window. The run is served whole —
    // the requester admits a chunk only when it covers exactly the range
    // the fold will apply, so truncating to a per-response page would
    // produce a response nobody can use.
    //
    // `hi` is unbounded on the wire, so the fold's per-epoch budget is
    // enforced here rather than taken on trust: the response's payload
    // array is bounded at that same width, and a wider run would overrun
    // it. An honest requester's `chunk_bounds` never asks for more.
    let hi = req
        .hi
        .inner()
        .min(leaf_count_at_block_end)
        .min(lo.saturating_add(MAX_WITNESSES_PER_SHARD as u64));
    if hi <= lo {
        return None;
    }

    let window = pending_chain.get_beacon_witness_payload_range(base, leaf_count_at_block_end);
    if window.len() as u64 != window_len {
        debug!(
            block_height = req.block_height.inner(),
            base,
            expected = leaf_count_at_block_end,
            retained = window.len(),
            "Shard-witness request: window leaves pruned past retention horizon"
        );
        return None;
    }
    let leaf_hashes: Vec<Hash> = window.iter().map(ShardWitnessPayload::leaf_hash).collect();

    let (Ok(from), Ok(to)) = (usize::try_from(lo - base), usize::try_from(hi - base)) else {
        return None;
    };
    let range_proof = compute_range_proof(&leaf_hashes, from, to);
    Some((window[from..to].to_vec(), range_proof))
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::commit_settled_at;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::beacon::GetShardWitnessesRequest;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block,
        BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, CertifiedBlock, ChainOrigin, Hash,
        LeafIndex, ProposerTimestamp, QuorumCertificate, Round, ShardId, ShardWitnessPayload,
        SignerBitfield, Stake, StakePoolId, Verified, WeightedTimestamp, WitnessSources,
        compute_merkle_root, verify_range_inclusion,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    fn deposit(amount: u64) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(1),
            amount: Stake::from_whole_tokens(amount),
        }
    }

    fn make_header(
        height: BlockHeight,
        beacon_witness_root: BeaconWitnessRoot,
        beacon_witness_leaf_count: BeaconWitnessLeafCount,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_000 * height.inner()),
            beacon_witness_root,
            beacon_witness_leaf_count,
            ..Default::default()
        })
    }

    fn make_qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            SHARD,
            block.height(),
            block.header().parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(block.header().timestamp().as_millis()),
        )
    }

    /// Commit a single block at `height` whose header advertises the
    /// accumulator state after appending `leaves`, with the leaves
    /// folded into the same atomic write.
    fn commit_block_with_witnesses(
        storage: &SimShardStorage,
        height: BlockHeight,
        leaves: &[ShardWitnessPayload],
        starting_leaf_index: BeaconWitnessLeafCount,
    ) -> (BlockHash, BeaconWitnessRoot, BeaconWitnessLeafCount) {
        let all_leaf_hashes: Vec<_> = leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
        let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&all_leaf_hashes));
        let leaf_count_at_block_end =
            BeaconWitnessLeafCount::new(starting_leaf_index.inner() + leaves.len() as u64);
        let header = make_header(height, root, leaf_count_at_block_end);
        let block = Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = make_qc_for(&block);
        let block_hash = block.hash();
        let witness = BeaconWitnessCommit {
            starting_leaf_index,
            leaves: leaves.to_vec(),
            leaf_count_at_block_end,
            prune_persisted_below: None,
        };
        // SAFETY: synthetic test fixture, no real signature.
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(qc);
        // SAFETY: synthetic test fixture; round-trip tests don't
        // exercise the `Verified<CertifiedBlock>` predicate.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            CertifiedBlock::new_unchecked(block, qc),
        ));
        commit_settled_at(storage, &certified, &[], &[], &witness);
        (block_hash, root, leaf_count_at_block_end)
    }

    /// A committed anchor whose witness window opens at leaf 4 and holds
    /// three leaves — the shape a boundary block takes once the beacon
    /// fold has advanced the shard's base past zero.
    fn windowed_anchor() -> (PendingChain<SimShardStorage>, BlockHash, BeaconWitnessRoot) {
        use hyperscale_storage::test_helpers::commit_block_with_witness_window;

        let storage = Arc::new(SimShardStorage::default());
        let window: Vec<_> = (1u64..=3).map(deposit).collect();
        let block_hash = commit_block_with_witness_window(
            storage.as_ref(),
            BlockHeight::new(1),
            4,
            &window,
            &window,
            None,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);
        let root = pending_chain
            .certified_header(BlockHeight::new(1))
            .expect("committed anchor resolves")
            .header()
            .beacon_witness_root();
        (pending_chain, block_hash, root)
    }

    /// The served run recomputes to the anchor's root through the same
    /// predicate the fold uses, so responder and verifier cannot drift.
    fn verify_against(
        resp: &GetShardWitnessesResponse,
        root: BeaconWitnessRoot,
        lo: usize,
        window_len: usize,
    ) -> bool {
        let leaves: Vec<Hash> = resp
            .payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        verify_range_inclusion(root.into_raw(), &leaves, lo, window_len, &resp.range_proof)
    }

    #[test]
    fn fetch_returns_a_run_that_verifies_against_the_anchor_root() {
        let storage = Arc::new(SimShardStorage::default());
        let leaves: Vec<_> = (1u64..=5).map(deposit).collect();
        let (block_hash, root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        // A strict sub-range: flanks are needed on the left, derived on
        // the right.
        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(1),
            LeafIndex::new(4),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert_eq!(resp.payloads.len(), 3);
        assert!(verify_against(&resp, root, 1, 5));

        // The full window needs no proof at all.
        let full = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(0),
            LeafIndex::new(5),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &full);
        assert_eq!(resp.payloads.len(), 5);
        assert!(resp.range_proof.is_empty());
        assert!(verify_against(&resp, root, 0, 5));
    }

    #[test]
    fn fetch_against_unknown_block_height_returns_empty() {
        let storage = Arc::new(SimShardStorage::default());
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);
        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(99),
            BlockHash::ZERO,
            LeafIndex::new(0),
            LeafIndex::new(1),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(resp.payloads.is_empty());
    }

    /// A windowed anchor whose root commits leaves 4..7: the served run
    /// verifies at the position the requester holds, which it derives as
    /// `req.lo - base` exactly as the fold's `window_position` does.
    #[test]
    fn fetch_serves_a_windowed_run() {
        let (pending_chain, block_hash, root) = windowed_anchor();

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(5),
            LeafIndex::new(7),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert_eq!(resp.payloads.len(), 2);
        // Window base is 4, so global leaf 5 sits at window position 1.
        assert!(verify_against(&resp, root, 1, 3));
    }

    /// A run reaching below the window base is refused outright. Clamping
    /// it up to the base would relocate the run away from the `lo` the
    /// requester verifies against, so the answer could only be rejected on
    /// arrival and re-requested forever.
    #[test]
    fn fetch_below_the_window_base_returns_empty() {
        let (pending_chain, block_hash, _root) = windowed_anchor();

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(2),
            LeafIndex::new(7),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(resp.payloads.is_empty());
        assert!(resp.range_proof.is_empty());
    }

    #[test]
    fn fetch_against_fork_divergent_hash_returns_empty() {
        let storage = Arc::new(SimShardStorage::default());
        let leaves: Vec<_> = (1u64..=3).map(deposit).collect();
        let (_block_hash, _root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"not_the_committed_hash")),
            LeafIndex::new(0),
            LeafIndex::new(1),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(
            resp.payloads.is_empty(),
            "fork-divergent anchor must yield no run"
        );
    }

    /// A run reaching past the anchor's leaf count is answered with the
    /// prefix that exists, proven for that shorter range.
    #[test]
    fn fetch_truncates_a_run_reaching_past_the_anchor() {
        let storage = Arc::new(SimShardStorage::default());
        let leaves: Vec<_> = (1u64..=3).map(deposit).collect();
        let (block_hash, root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(1),
            LeafIndex::new(99),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert_eq!(resp.payloads.len(), 2);
        assert!(verify_against(&resp, root, 1, 3));
    }

    /// `hi` is unbounded on the wire, but the response's payload array is
    /// bounded at the fold's per-epoch budget. A request naming the whole
    /// u64 range against a window wider than that budget is answered with
    /// the budget's worth of leaves — not refused, and not a panic on the
    /// bounded-array conversion.
    #[test]
    fn fetch_caps_an_unbounded_run_at_the_fold_budget() {
        let storage = Arc::new(SimShardStorage::default());
        let leaves: Vec<_> = (1u64..=(MAX_WITNESSES_PER_SHARD as u64 + 1))
            .map(deposit)
            .collect();
        let window_len = leaves.len();
        let (block_hash, root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(0),
            LeafIndex::new(u64::MAX),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert_eq!(resp.payloads.len(), MAX_WITNESSES_PER_SHARD);
        assert!(verify_against(&resp, root, 0, window_len));
    }

    #[test]
    fn fetch_returns_empty_when_anchor_has_zero_leaves() {
        let storage = Arc::new(SimShardStorage::default());
        let (block_hash, _root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &[],
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            LeafIndex::new(0),
            LeafIndex::new(1),
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(resp.payloads.is_empty());
    }
}
