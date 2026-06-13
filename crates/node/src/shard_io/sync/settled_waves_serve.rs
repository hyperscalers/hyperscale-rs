//! Inbound settled-waves request handling.
//!
//! Serves one committed block's settled-wave reveal to a counterpart
//! reconstructing a terminated shard's settled set across a split
//! boundary (see [`SettledSetBuilder`]). Reads the block through
//! `PendingChain` so both pending and persisted heights answer; the
//! reveal carries only the block's certified header plus, per committed
//! certificate, its execution certificates' wave-ids — the minimal data
//! that reproduces the header's `certificate_root` and names each
//! settled wave.
//!
//! [`SettledSetBuilder`]: crate::bootstrap::settled_set::SettledSetBuilder

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::CertifiedBlockHeader;
use hyperscale_types::network::request::GetSettledWavesRequest;
use hyperscale_types::network::response::{GetSettledWavesResponse, SettledWavesReveal};

/// Serve an inbound settled-waves request from the local chain.
///
/// Returns `not_found` when the height isn't held, so the requester
/// rotates peers. Serves by height; the requester binds the served
/// block to the terminal chain via the header hash and rejects a
/// mismatch.
#[must_use]
pub fn serve_settled_waves_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    req: &GetSettledWavesRequest,
) -> GetSettledWavesResponse {
    let Some(BlockForSync { block, qc, .. }) = pending_chain.block_for_sync(req.height) else {
        record_fetch_response_sent("settled_waves", 0);
        return GetSettledWavesResponse::not_found();
    };

    let certs = block
        .certificates()
        .iter()
        .map(|fw| fw.certificate().ec_wave_ids().into())
        .collect::<Vec<_>>()
        .into();
    let certified_header = CertifiedBlockHeader::new(block.header().clone(), qc);
    record_fetch_response_sent("settled_waves", 1);
    GetSettledWavesResponse::found(SettledWavesReveal {
        certified_header,
        certs,
    })
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
        BlockHeader, BlockHeight, Bls12381G2Signature, BoundedVec, CertificateRoot, ChainOrigin,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardId, SignerBitfield, StateRoot,
        TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable, Verified, WaveCertificate,
        WaveId, WeightedTimestamp,
    };

    use super::*;
    use crate::bootstrap::settled_set::{SettledOutcome, SettledSetBuilder};

    fn finalized_wave(height: u64) -> Arc<Verifiable<FinalizedWave>> {
        let wave = WaveId::new(ShardId::ROOT, BlockHeight::new(height), BTreeSet::new());
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

    /// A committed block's settled waves serve and reconstruct end to
    /// end through the builder over the memory backend.
    #[test]
    fn serves_a_committed_blocks_settled_waves() {
        let storage = Arc::new(SimShardStorage::default());
        let certs = [finalized_wave(1)];
        let header = BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(1),
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            *Verified::<CertificateRoot>::compute(&certs).as_ref(),
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
        );
        let block = Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(certs.to_vec().into()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let terminal = block.hash();
        storage.commit_block(
            &make_test_certified(block),
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );

        let pending_chain = PendingChain::new(storage);

        let mut builder = SettledSetBuilder::new(
            ShardId::ROOT,
            BlockHeight::new(1),
            terminal,
            BlockHeight::new(1),
        );
        let req = builder.next_request().expect("first request");
        let response = serve_settled_waves_request(&pending_chain, &req);
        assert_eq!(builder.on_response(&response), SettledOutcome::Accepted);
        assert!(builder.is_complete());
        assert_eq!(
            builder.into_settled(),
            BTreeSet::from([WaveId::new(
                ShardId::ROOT,
                BlockHeight::new(1),
                BTreeSet::new()
            )]),
        );
    }

    /// An unheld height serves `not_found`.
    #[test]
    fn unheld_height_serves_not_found() {
        let storage = Arc::new(SimShardStorage::default());
        let pending_chain = PendingChain::new(storage);
        let req = GetSettledWavesRequest::new(BlockHeight::new(7), BlockHash::ZERO);
        assert!(
            serve_settled_waves_request(&pending_chain, &req)
                .reveal
                .is_none()
        );
    }
}
