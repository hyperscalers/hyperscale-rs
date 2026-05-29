//! Inbound shard-witness fetch request handling.
//!
//! Beacon validators outside a shard's committee pull witnesses lifted
//! by that shard so they can verify proofs against the shard's
//! QC-attested [`BeaconWitnessRoot`](hyperscale_types::BeaconWitnessRoot).
//! This module is the responder side: read the anchor block's leaf
//! count from its header, reconstruct the per-anchor accumulator from
//! the retained CF payloads, and return one inclusion proof per
//! requested leaf index.

use std::sync::Arc;

use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::beacon::GetShardWitnessesRequest;
use hyperscale_types::network::response::beacon::GetShardWitnessesResponse;
use hyperscale_types::{
    BoundedVec, ShardWitness, ShardWitnessPayload, ShardWitnessProof,
    compute_merkle_root_with_proof,
};
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
/// 3. Read retained leaf payloads via
///    [`ShardChainReader::get_beacon_witness_payloads`](hyperscale_storage::ShardChainReader)
///    up to `header.beacon_witness_leaf_count()`. A retention-pruned
///    anchor returns short — those leaves yield no proof and are
///    silently skipped.
/// 4. Generate one [`ShardWitness`] per requested leaf index by hashing
///    each payload and reconstructing the path against the leaf-hash
///    list. The proof's `committed_block_hash` matches the anchor the
///    requester named, so the requester verifies against the root they
///    already hold.
///
/// Requested indices that fall past `leaf_count_at_block_end` are
/// silently dropped from the response (the responder has no leaf at
/// that position to prove). Requesters detect missing indices by
/// pairing the response order against their request's order.
pub fn serve_shard_witnesses_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    req: &GetShardWitnessesRequest,
) -> GetShardWitnessesResponse {
    let Some(certified_header) = pending_chain.certified_header(req.block_height) else {
        debug!(
            block_height = req.block_height.inner(),
            "Shard-witness request: block not found"
        );
        return GetShardWitnessesResponse::empty();
    };
    let header = certified_header.header();
    if header.hash() != req.committed_block_hash {
        warn!(
            block_height = req.block_height.inner(),
            requested = ?req.committed_block_hash,
            local = ?header.hash(),
            "Shard-witness request: anchor hash mismatch (fork divergence)"
        );
        return GetShardWitnessesResponse::empty();
    }

    let leaf_count_at_block_end = header.beacon_witness_leaf_count();
    if leaf_count_at_block_end.inner() == 0 {
        return GetShardWitnessesResponse::empty();
    }

    let payloads = pending_chain.get_beacon_witness_payloads(leaf_count_at_block_end);
    if payloads.is_empty() {
        debug!(
            block_height = req.block_height.inner(),
            expected = leaf_count_at_block_end.inner(),
            "Shard-witness request: leaves pruned past retention horizon"
        );
        return GetShardWitnessesResponse::empty();
    }
    let leaf_hashes: Vec<_> = payloads
        .iter()
        .map(ShardWitnessPayload::leaf_hash)
        .collect();

    let mut witnesses: Vec<Arc<ShardWitness>> = Vec::with_capacity(req.leaf_indices.len());
    for leaf_index in req.leaf_indices.iter() {
        let raw_index = leaf_index.inner();
        if raw_index >= leaf_count_at_block_end.inner() {
            continue;
        }
        let Ok(position) = usize::try_from(raw_index) else {
            continue;
        };
        let Some(payload) = payloads.get(position).cloned() else {
            continue;
        };
        let (_root, siblings, _idx) = compute_merkle_root_with_proof(&leaf_hashes, position);
        let proof = ShardWitnessProof {
            shard_id: req.shard_id,
            committed_block_hash: req.committed_block_hash,
            leaf_index: *leaf_index,
            siblings: BoundedVec::from(siblings),
        };
        witnesses.push(Arc::new(ShardWitness { payload, proof }));
    }

    GetShardWitnessesResponse::new(witnesses)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_storage::{PendingChain, ShardChainWriter};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::beacon::GetShardWitnessesRequest;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash,
        BlockHeader, BlockHeight, BoundedVec, CertificateRoot, CertifiedBlock, Hash, InFlightCount,
        LeafIndex, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round,
        ShardGroupId, ShardWitnessPayload, SignerBitfield, Stake, StakePoolId, StateRoot,
        TransactionRoot, ValidatorId, Verified, WeightedTimestamp, compute_merkle_root,
        verify_merkle_inclusion, zero_bls_signature,
    };

    use super::*;

    const SHARD: ShardGroupId = ShardGroupId::new(0);

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
        BlockHeader::new(
            SHARD,
            height,
            BlockHash::ZERO,
            QuorumCertificate::genesis(SHARD),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000 * height.inner()),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            beacon_witness_root,
            beacon_witness_leaf_count,
        )
    }

    fn make_qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            SHARD,
            block.height(),
            block.header().parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
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
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = make_qc_for(&block);
        let block_hash = block.hash();
        let witness = BeaconWitnessCommit {
            starting_leaf_index,
            leaves: leaves.to_vec(),
            leaf_count_at_block_end,
        };
        // SAFETY: synthetic test fixture, no real signature.
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(qc);
        // SAFETY: synthetic test fixture; round-trip tests don't
        // exercise the `Verified<CertifiedBlock>` predicate.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            CertifiedBlock::new_unchecked(block, qc),
        ));
        storage.commit_block(&certified, &witness);
        (block_hash, root, leaf_count_at_block_end)
    }

    #[test]
    fn fetch_returns_proofs_that_verify_against_the_anchor_root() {
        let storage = Arc::new(SimShardStorage::new());
        let leaves: Vec<_> = (1u64..=5).map(deposit).collect();
        let (block_hash, root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            vec![LeafIndex::new(0), LeafIndex::new(2), LeafIndex::new(4)],
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert_eq!(resp.witnesses.len(), 3);

        for witness in resp.witnesses.iter() {
            assert_eq!(witness.proof.shard_id, SHARD);
            assert_eq!(witness.proof.committed_block_hash, block_hash);
            let leaf_hash = witness.payload.leaf_hash();
            let raw_index = u32::try_from(witness.proof.leaf_index.inner()).unwrap();
            assert!(
                verify_merkle_inclusion(
                    root.into_raw(),
                    leaf_hash,
                    &witness.proof.siblings,
                    raw_index,
                ),
                "proof must verify against anchor root"
            );
        }
    }

    #[test]
    fn fetch_against_unknown_block_height_returns_empty() {
        let storage = Arc::new(SimShardStorage::new());
        let pending_chain = PendingChain::new(storage);
        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(99),
            BlockHash::ZERO,
            vec![LeafIndex::new(0)],
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(resp.witnesses.is_empty());
    }

    #[test]
    fn fetch_against_fork_divergent_hash_returns_empty() {
        let storage = Arc::new(SimShardStorage::new());
        let leaves: Vec<_> = (1u64..=3).map(deposit).collect();
        let (_block_hash, _root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"not_the_committed_hash")),
            vec![LeafIndex::new(0)],
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(
            resp.witnesses.is_empty(),
            "fork-divergent anchor must yield no proofs"
        );
    }

    #[test]
    fn fetch_silently_drops_out_of_range_indices() {
        let storage = Arc::new(SimShardStorage::new());
        let leaves: Vec<_> = (1u64..=3).map(deposit).collect();
        let (block_hash, _root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &leaves,
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            vec![LeafIndex::new(1), LeafIndex::new(99)],
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        // Index 99 is past leaf_count_at_block_end (3) — only index 1 is served.
        assert_eq!(resp.witnesses.len(), 1);
        assert_eq!(resp.witnesses[0].proof.leaf_index, LeafIndex::new(1));
    }

    #[test]
    fn fetch_returns_empty_when_anchor_has_zero_leaves() {
        let storage = Arc::new(SimShardStorage::new());
        let (block_hash, _root, _count) = commit_block_with_witnesses(
            &storage,
            BlockHeight::new(1),
            &[],
            BeaconWitnessLeafCount::ZERO,
        );
        let pending_chain = PendingChain::new(storage);

        let req = GetShardWitnessesRequest::new(
            SHARD,
            BlockHeight::new(1),
            block_hash,
            vec![LeafIndex::new(0)],
        );
        let resp = serve_shard_witnesses_request(&pending_chain, &req);
        assert!(resp.witnesses.is_empty());
    }
}
