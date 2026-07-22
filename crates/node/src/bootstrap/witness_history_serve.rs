//! Inbound snap-sync witness-history serving.

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::MAX_WITNESSES_PER_FETCH;
use hyperscale_types::network::request::GetWitnessHistoryRequest;
use hyperscale_types::network::response::{GetWitnessHistoryResponse, WitnessHistoryChunk};
use tracing::{debug, warn};

/// Serve an inbound snap-sync witness-history request.
///
/// Resolves the boundary header the joiner's beacon-attested anchor
/// names, cross-checks its hash, and answers a page of the
/// accumulator's leaf payloads up to the header's leaf count. Every
/// degraded case — unknown height, fork-divergent hash, retention-pruned
/// leaves — answers `history: None` so the joiner rotates to another
/// peer rather than receiving something unverifiable.
pub fn serve_witness_history_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    req: &GetWitnessHistoryRequest,
) -> GetWitnessHistoryResponse {
    let unavailable = GetWitnessHistoryResponse { history: None };

    let Some(certified) = pending_chain.certified_header(req.height) else {
        debug!(
            height = req.height.inner(),
            "Witness-history request: block not found"
        );
        return unavailable;
    };
    let header = certified.header();
    if header.hash() != req.block_hash {
        warn!(
            height = req.height.inner(),
            requested = ?req.block_hash,
            local = ?header.hash(),
            "Witness-history request: anchor hash mismatch (fork divergence)"
        );
        return unavailable;
    }

    let count = header.beacon_witness_leaf_count().inner();
    // The header's commitment spans its window only; requests below the
    // base clamp up to it (a joiner opens at index 0 before it has the
    // header in hand).
    let base = header.beacon_witness_base().inner();
    let start = req.start_index.max(base);
    if start > count {
        return unavailable;
    }
    let limit = (req.limit as usize).clamp(1, MAX_WITNESSES_PER_FETCH) as u64;
    let end = count.min(start.saturating_add(limit));
    let payloads = pending_chain.get_beacon_witness_payload_range(start, end);
    if (payloads.len() as u64) < end - start {
        debug!(
            height = req.height.inner(),
            start,
            end,
            retained = payloads.len(),
            "Witness-history request: requested leaves pruned past retention horizon"
        );
        return unavailable;
    }

    record_fetch_response_sent("witness_history", payloads.len());
    GetWitnessHistoryResponse {
        history: Some(WitnessHistoryChunk {
            header: header.clone(),
            qc: certified.qc().clone(),
            payloads: payloads.into(),
            more: end < count,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::{commit_block_with_witnesses, stake_deposit};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{BlockHash, BlockHeight, Hash, ShardWitnessPayload};

    use super::*;

    fn request(
        height: u64,
        block_hash: BlockHash,
        start_index: u64,
        limit: u32,
    ) -> GetWitnessHistoryRequest {
        GetWitnessHistoryRequest {
            height: BlockHeight::new(height),
            block_hash,
            start_index,
            limit,
        }
    }

    #[test]
    fn serves_pages_that_assemble_to_the_header_commitment() {
        let storage = SimShardStorage::default();
        let leaves: Vec<_> = (1u64..=5).map(stake_deposit).collect();
        let block_hash = commit_block_with_witnesses(&storage, BlockHeight::new(1), &leaves);
        let pending_chain = PendingChain::new(Arc::new(storage));

        let mut assembled: Vec<Hash> = Vec::new();
        loop {
            let req = request(1, block_hash, assembled.len() as u64, 2);
            let chunk = serve_witness_history_request(&pending_chain, &req)
                .history
                .expect("committed anchor serves");
            assert_eq!(chunk.header.hash(), block_hash);
            assembled.extend(chunk.payloads.iter().map(ShardWitnessPayload::leaf_hash));
            if !chunk.more {
                break;
            }
        }
        let expected: Vec<Hash> = leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
        assert_eq!(assembled, expected);
    }

    #[test]
    fn unknown_height_and_divergent_hash_are_unavailable() {
        let storage = SimShardStorage::default();
        let leaves: Vec<_> = (1u64..=3).map(stake_deposit).collect();
        let block_hash = commit_block_with_witnesses(&storage, BlockHeight::new(1), &leaves);
        let pending_chain = PendingChain::new(Arc::new(storage));

        let unknown = request(99, block_hash, 0, 10);
        assert!(
            serve_witness_history_request(&pending_chain, &unknown)
                .history
                .is_none()
        );

        let divergent = request(
            1,
            BlockHash::from_raw(Hash::from_bytes(b"not_the_committed_hash")),
            0,
            10,
        );
        assert!(
            serve_witness_history_request(&pending_chain, &divergent)
                .history
                .is_none()
        );
    }

    #[test]
    fn out_of_range_start_is_unavailable() {
        let storage = SimShardStorage::default();
        let leaves: Vec<_> = (1u64..=3).map(stake_deposit).collect();
        let block_hash = commit_block_with_witnesses(&storage, BlockHeight::new(1), &leaves);
        let pending_chain = PendingChain::new(Arc::new(storage));

        let req = request(1, block_hash, 4, 10);
        assert!(
            serve_witness_history_request(&pending_chain, &req)
                .history
                .is_none()
        );
    }

    #[test]
    fn zero_leaf_history_serves_an_empty_final_page() {
        let storage = SimShardStorage::default();
        let block_hash = commit_block_with_witnesses(&storage, BlockHeight::new(1), &[]);
        let pending_chain = PendingChain::new(Arc::new(storage));

        let chunk = serve_witness_history_request(&pending_chain, &request(1, block_hash, 0, 10))
            .history
            .expect("zero-leaf anchor still serves its header");
        assert!(chunk.payloads.is_empty());
        assert!(!chunk.more);
    }
}
