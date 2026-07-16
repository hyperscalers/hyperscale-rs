//! Inbound settled-waves window request handling.
//!
//! Serves a terminated shard's complete settled-wave window list to a
//! surviving counterpart resolving cross-shard waves across a split
//! boundary. The request names the terminal block `B`; the server
//! reconstructs `S_P` off its committed chain over the window reaching
//! back to the terminating reshape's admission — the same set `B`'s
//! `settled_waves_root` commits — so the requester accepts the list
//! against the beacon-attested root. No
//! per-block QC: completeness is the merkle root, not block-by-block
//! verification.

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::network::request::GetSettledWavesRequest;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{
    BoundedVec, MAX_FINALIZED_TX_PER_BLOCK, WeightedTimestamp, local_settled_wave_ids,
};

/// Serve an inbound settled-waves window request from the local chain.
///
/// The served set is the **cross-shard** waves the terminated shard settled
/// in the window — the only ones a counterpart's fence can query (see
/// [`local_settled_wave_ids`]) — so it stays proportional to cross-shard
/// traffic, not total throughput.
///
/// `window_floor` is the shard's settled-window floor read off the serving
/// node's topology projection — the same value the terminal's proposer
/// floored the attested root at, so the recomputed list matches it. A
/// projection that no longer carries the floor serves a narrower window;
/// the requester's root check catches the mismatch and rotates peers.
///
/// Returns `not_found` when the terminal block isn't held or the stored
/// block's hash doesn't match the requested terminal — the requester
/// rotates peers. Returns `not_found` too when the window set exceeds the
/// wire cap (logged loudly; within-cap for any realistic cross-shard load).
#[must_use]
pub fn serve_settled_waves_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    window_floor: Option<WeightedTimestamp>,
    req: &GetSettledWavesRequest,
) -> GetSettledWavesResponse {
    let Some(BlockForSync { block, .. }) = pending_chain.block_for_sync(req.terminal_height) else {
        record_fetch_response_sent("settled_waves", 0);
        return GetSettledWavesResponse::not_found();
    };
    if block.hash() != req.terminal_block_hash {
        record_fetch_response_sent("settled_waves", 0);
        return GetSettledWavesResponse::not_found();
    }

    let shard = block.header().shard_id();
    let own = local_settled_wave_ids(block.certificates().iter(), shard);
    let Some(parent_height) = block.height().prev() else {
        // Genesis carries no certificates and never terminates a split.
        record_fetch_response_sent("settled_waves", 0);
        return GetSettledWavesResponse::not_found();
    };
    let set = pending_chain.settled_waves_in_window(
        shard,
        block.header().parent_block_hash(),
        parent_height,
        block.header().parent_qc().weighted_timestamp(),
        window_floor,
        own,
    );

    // `try_from_vec` is the genuinely fallible conversion: a window
    // exceeding the wire cap serves `not_found` rather than panicking on
    // the bound (`From<Vec>` would). The set is the cross-shard settled
    // waves only, so a within-cap window covers any realistic cross-shard
    // load; an overflow means cross-shard throughput outran the single-shot
    // transfer and the design must escalate to paged or JMT-absence-proof
    // delivery (c2). Log it loudly rather than letting the requester read
    // the overflow `not_found` as a plain "block not held" and rotate peers
    // forever.
    let window = set.len();
    BoundedVec::try_from_vec(set.into_iter().collect()).map_or_else(
        |_| {
            tracing::warn!(
                shard = ?shard,
                terminal_height = req.terminal_height.inner(),
                window,
                cap = MAX_FINALIZED_TX_PER_BLOCK,
                "settled-waves window exceeds the wire cap; serving not_found — \
                 cross-shard load outran the one-shot transfer (escalate to c2)"
            );
            record_fetch_response_sent("settled_waves", 0);
            GetSettledWavesResponse::not_found()
        },
        |bounded| {
            record_fetch_response_sent("settled_waves", 1);
            GetSettledWavesResponse::found(bounded)
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_storage::ShardChainWriter;
    use hyperscale_storage::test_helpers::make_test_certified;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash,
        BlockHeader, BlockHeight, Bls12381G2Signature, BoundedVec, CertificateRoot,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, RETENTION_HORIZON, Round, ShardId, SignerBitfield,
        StateRoot, TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable, Verified, VrfProof,
        WaveCertificate, WaveId, WeightedTimestamp, settled_waves_root_from_ids,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    fn finalized_wave(height: u64) -> Arc<Verifiable<FinalizedWave>> {
        // Cross-shard wave (non-empty `remote_shards`): the settled set
        // commits only cross-shard waves, so single-shard fixtures would be
        // filtered out before the merkle root.
        let wave = WaveId::new(
            SHARD,
            BlockHeight::new(height),
            BTreeSet::from([ShardId::from_heap_index(2)]),
        );
        let ec = ExecutionCertificate::new(
            wave.clone(),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from_raw(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        Arc::new(Verifiable::from(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave, vec![Arc::new(ec)])),
            vec![],
        )))
    }

    fn commit_block(
        storage: &SimShardStorage,
        height: u64,
        parent: BlockHash,
        pred_wt: u64,
        certs: &[Arc<Verifiable<FinalizedWave>>],
    ) -> BlockHash {
        let parent_qc = QuorumCertificate::new(
            parent,
            SHARD,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
            WeightedTimestamp::from_millis(pred_wt),
        );
        let header = BlockHeader::new(
            SHARD,
            BlockHeight::new(height),
            parent,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000 * height),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            *Verified::<CertificateRoot>::compute(certs).as_ref(),
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block = Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(certs.to_vec().into()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let hash = block.hash();
        storage.commit_block(
            &make_test_certified(block),
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        hash
    }

    /// The served window list recomputes to the terminal block's
    /// `settled_waves_root` — every block's settled wave over the window.
    #[test]
    fn serves_the_full_settled_window() {
        let storage = SimShardStorage::default();
        let mut parent = BlockHash::ZERO;
        for h in 1..=3 {
            parent = commit_block(&storage, h, parent, 1_000 * h, &[finalized_wave(h)]);
        }
        let terminal = parent;
        let pending_chain = PendingChain::new(Arc::new(storage));

        let req = GetSettledWavesRequest::new(BlockHeight::new(3), terminal);
        let response = serve_settled_waves_request(&pending_chain, None, &req);
        let waves = response.waves.expect("terminal block is held");

        let expected: BTreeSet<WaveId> = (1..=3)
            .map(|h| {
                WaveId::new(
                    SHARD,
                    BlockHeight::new(h),
                    BTreeSet::from([ShardId::from_heap_index(2)]),
                )
            })
            .collect();
        assert_eq!(waves.iter().cloned().collect::<BTreeSet<_>>(), expected);
        // The fence accepts iff the recomputed root equals the attested one.
        assert_eq!(
            settled_waves_root_from_ids(waves.iter()),
            settled_waves_root_from_ids(expected.iter()),
        );
    }

    /// A schedule-supplied floor reaches settlements older than the
    /// anchor-relative horizon: a wave settled early in the terminating
    /// shard's scheduled window — below `terminal − RETENTION_HORIZON` —
    /// is served only when the floor covers it.
    #[test]
    fn window_floor_serves_early_settlements() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let storage = SimShardStorage::default();
        let mut parent = commit_block(&storage, 1, BlockHash::ZERO, 1_000, &[finalized_wave(1)]);
        parent = commit_block(&storage, 2, parent, rh_ms + 10_000, &[finalized_wave(2)]);
        let terminal = commit_block(&storage, 3, parent, rh_ms + 11_000, &[finalized_wave(3)]);
        let pending_chain = PendingChain::new(Arc::new(storage));
        let req = GetSettledWavesRequest::new(BlockHeight::new(3), terminal);

        // Anchor-only floor: the early settlement falls outside the window.
        let narrow = serve_settled_waves_request(&pending_chain, None, &req)
            .waves
            .expect("terminal block is held");
        assert_eq!(narrow.len(), 2);

        // The floor reaches back past the early settlement.
        let wide = serve_settled_waves_request(
            &pending_chain,
            Some(WeightedTimestamp::from_millis(500)),
            &req,
        )
        .waves
        .expect("terminal block is held");
        assert_eq!(wide.len(), 3);
    }

    /// A hash mismatch against the stored block serves `not_found`.
    #[test]
    fn wrong_terminal_hash_serves_not_found() {
        let storage = SimShardStorage::default();
        let _ = commit_block(&storage, 1, BlockHash::ZERO, 1_000, &[finalized_wave(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage));
        let req = GetSettledWavesRequest::new(
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"other-chain")),
        );
        assert!(
            serve_settled_waves_request(&pending_chain, None, &req)
                .waves
                .is_none()
        );
    }

    /// An unheld height serves `not_found`.
    #[test]
    fn unheld_height_serves_not_found() {
        let storage = Arc::new(SimShardStorage::default());
        let pending_chain = PendingChain::new(storage);
        let req = GetSettledWavesRequest::new(BlockHeight::new(7), BlockHash::ZERO);
        assert!(
            serve_settled_waves_request(&pending_chain, None, &req)
                .waves
                .is_none()
        );
    }
}
