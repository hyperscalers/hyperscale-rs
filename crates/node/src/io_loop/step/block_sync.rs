//! Block-sync I/O glue.
//!
//! Bridges `Sync<BlockSyncBinding>`'s scheduling decisions to the network
//! and BFT. This is where payload-specific concerns live:
//!
//! - building `GetBlockRequest`s with the right inventory bloom + force-full
//!   override
//! - rehydrating elided responses against local caches
//! - structurally validating the rehydrated block (off-thread on
//!   `ConsensusCrypto`): height + QC binding + every Merkle root the
//!   header commits to, plus per-wave receipt-vs-EC shape
//! - delivering valid blocks to BFT via `ProtocolEvent::BlockSyncReadyToApply`
//! - feeding scheduling events back to the FSM
//!
//! The FSM itself owns nothing about a `CertifiedBlock`'s shape — it just
//! tracks heights and emits `Fetch { from, count }` for the binding to
//! turn into a network round-trip.

use hyperscale_core::{FetchFailureKind, NodeInput, ProtocolEvent};
use hyperscale_network::RequestError;

/// Classify a transport-level request error for the sync FSM. `Exhausted`
/// already absorbed retries against rotated peers — re-queue immediately;
/// other variants reflect transport conditions where a brief deferral is
/// appropriate.
pub(in crate::io_loop) const fn classify_fetch_error(err: &RequestError) -> FetchFailureKind {
    match err {
        RequestError::Exhausted { .. } => FetchFailureKind::Exhausted,
        RequestError::NoPeers => FetchFailureKind::NoPeers,
        RequestError::Timeout
        | RequestError::PeerUnreachable(_)
        | RequestError::PeerError(_)
        | RequestError::Shutdown => FetchFailureKind::Transport,
    }
}
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::Engine;
use hyperscale_metrics::{
    record_sync_block_filtered, record_sync_response_error, record_sync_round_completed,
    record_sync_round_retried, record_sync_round_started,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::Storage;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    BlockHeight, CertifiedBlock, ElidedCertifiedBlock, Hash, Inventory, RehydrateError,
    StoredReceipt, compute_certificate_root, compute_local_receipt_root, compute_provision_root,
    compute_transaction_root,
};

use crate::io_loop::IoLoop;
use crate::io_loop::sync::SyncOutput;
use crate::io_loop::sync::block::{BlockSyncInput, BlockSyncOutput};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartBlockSync`: feed the FSM and dispatch any
    /// fetches it emits.
    pub(in crate::io_loop) fn process_start_block_sync(&mut self, target: BlockHeight) {
        let outputs = self
            .syncs
            .block
            .handle(BlockSyncInput::StartSync { scope: (), target });
        self.process_block_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Handle a sync block response: rehydrate the elided block against
    /// local caches, then dispatch structural validation off-thread on
    /// `ConsensusCrypto`. On rehydration miss, mark the height for full
    /// refetch and re-queue. The verdict returns as
    /// `NodeInput::SyncBlockValidated` / `SyncBlockValidationFailed` —
    /// see `IoLoop::event_sender` for the off-thread → pinned-thread
    /// routing convention.
    pub(in crate::io_loop) fn handle_block_sync_response_received(
        &mut self,
        height: BlockHeight,
        block: Option<Box<ElidedCertifiedBlock>>,
    ) {
        let Some(elided) = block else {
            // Peer didn't have the block — re-queue via fetch-failed.
            // Treat as exhausted so the FSM doesn't pile its own backoff on
            // top of the request manager's; we just want another attempt.
            self.feed_block_sync_fetch_failed(height, FetchFailureKind::Exhausted);
            return;
        };
        let cert = match self.rehydrate_elided_block(&elided) {
            Ok(c) => c,
            Err(err) => {
                let reason = match err {
                    RehydrateError::Missing(_) => "rehydration_miss",
                    RehydrateError::QcMismatch { .. } => "qc_hash_mismatch",
                };
                record_sync_response_error("block", reason);
                self.syncs.block.mark_force_full_refetch(height);
                // Rehydration is a local-data issue resolved by force-full
                // on the next attempt — re-queue immediately rather than
                // backing off.
                self.feed_block_sync_fetch_failed(height, FetchFailureKind::Exhausted);
                return;
            }
        };

        // Dispatch structural validation to ConsensusCrypto. The
        // `local_receipt_root` Merkle is the heavy step (SBOR-encode of
        // every receipt's `database_updates`); off-loading keeps the
        // pinned thread responsive during catch-up.
        let event_tx = self.event_sender.clone();
        self.dispatch.spawn(DispatchPool::ConsensusCrypto, move || {
            let event = match validate_synced_block(height, &cert) {
                Ok(()) => NodeInput::SyncBlockValidated {
                    height,
                    certified: Box::new(cert),
                },
                Err(reason) => NodeInput::SyncBlockValidationFailed { height, reason },
            };
            let _ = event_tx.send(event);
        });
    }

    /// Handle a sync block fetch failure (network error / not-found).
    pub(in crate::io_loop) fn handle_block_sync_fetch_failed(
        &mut self,
        height: BlockHeight,
        kind: FetchFailureKind,
    ) {
        record_sync_response_error("block", "fetch_failed");
        self.feed_block_sync_fetch_failed(height, kind);
    }

    /// Resume the post-validation delivery path after off-thread
    /// structural validation succeeded.
    pub(in crate::io_loop) fn handle_sync_block_validated(
        &mut self,
        height: BlockHeight,
        certified: CertifiedBlock,
    ) {
        self.deliver_validated_sync_block(height, certified);
    }

    /// Resume the failure path after off-thread structural validation
    /// rejected the response.
    pub(in crate::io_loop) fn handle_sync_block_validation_failed(
        &mut self,
        height: BlockHeight,
        reason: &'static str,
    ) {
        tracing::warn!(height = height.inner(), reason, "Sync: rejecting response");
        record_sync_block_filtered("block", reason);
        // Validation failure is a peer-content issue, not a transport
        // exhaustion — apply the standard backoff so we don't spin if a
        // peer keeps shipping malformed responses.
        self.feed_block_sync_fetch_failed(height, FetchFailureKind::Transport);
    }

    // ─── Sync output processing + helpers ───────────────────────────────

    /// Process FSM outputs: `Fetch` → network request, `Complete` →
    /// fed into the state machine as `BlockSyncComplete`.
    pub(in crate::io_loop) fn process_block_sync_outputs(&mut self, outputs: Vec<BlockSyncOutput>) {
        // Snapshot the sync inventory once per batch so every Fetch in
        // this tick shares a consistent view of mempool / cert-cache /
        // provision-store membership. Built lazily.
        let mut inventory_cache: Option<Inventory> = None;
        for output in outputs {
            match output {
                SyncOutput::Fetch { from: height, .. } => {
                    self.dispatch_block_sync_fetch(height, &mut inventory_cache);
                }
                SyncOutput::Complete { height, .. } => {
                    tracing::info!(
                        height = height.inner(),
                        "Sync protocol complete, resuming consensus"
                    );
                    self.feed_event(ProtocolEvent::BlockSyncComplete { height });
                }
            }
        }
    }

    /// Dispatch a single-height block fetch. Reads the current sync
    /// target and `force_full` flag from the FSM at dispatch time.
    fn dispatch_block_sync_fetch(
        &self,
        height: BlockHeight,
        inventory_cache: &mut Option<Inventory>,
    ) {
        use hyperscale_types::network::request::GetBlockRequest;

        let target_height = self.syncs.block.target(&()).unwrap_or(height);
        let force_full = self.syncs.block.force_full(height);

        // Heights flagged `force_full` were rehydration misses last time —
        // request with empty inventory so the responder cannot elide bodies.
        let inventory = if force_full {
            Inventory::empty()
        } else {
            inventory_cache
                .get_or_insert_with(|| self.build_sync_inventory())
                .clone()
        };
        let es = self.event_sender.clone();
        let peers = self.local_peers();
        record_sync_round_started("block");
        self.network.request(
            &peers,
            None,
            GetBlockRequest::new(height, target_height).with_inventory(inventory),
            None,
            Box::new(move |result: Result<GetBlockResponse, _>| {
                match result {
                    Ok(resp) => {
                        let block = resp.into_elided().map(Box::new);
                        let _ = es.send(NodeInput::BlockSyncResponseReceived { height, block });
                    }
                    Err(err) => {
                        let kind = classify_fetch_error(&err);
                        let _ = es.send(NodeInput::BlockSyncFetchFailed { height, kind });
                    }
                }
                // "Peer doesn't have this height" is ambiguous (peer may
                // simply be behind us) — never Reject.
                ResponseVerdict::Accept
            }),
        );
    }

    /// Snapshot local mempool / finalized-wave cache / provision store
    /// into an [`Inventory`] so the responder can elide bodies the
    /// requester already has.
    fn build_sync_inventory(&self) -> Inventory {
        Inventory {
            tx_have: self.caches.tx_store.tx_bloom_snapshot(),
            cert_have: self.vnodes[0].state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock`.
    fn rehydrate_elided_block(
        &self,
        elided: &ElidedCertifiedBlock,
    ) -> Result<CertifiedBlock, RehydrateError> {
        let state = &self.vnodes[0].state;
        let mempool = state.mempool();
        let execution = state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| mempool.get_transaction(h),
            |id| execution.get_finalized_wave(id),
            |h| provision_store.get(*h),
        )
    }

    /// Hand a validated synced block to BFT and advance the sync FSM.
    /// Structural validation runs off-thread; this is the
    /// post-verdict pinned-thread continuation.
    fn deliver_validated_sync_block(&mut self, height: BlockHeight, certified: CertifiedBlock) {
        record_sync_round_completed("block");

        // Hand the block off to BFT; tell the FSM the height was delivered.
        self.feed_event(ProtocolEvent::BlockSyncReadyToApply { certified });
        let outputs = self.syncs.block.handle(BlockSyncInput::FetchSucceeded {
            scope: (),
            from: height,
            count: 1,
            delivered_heights: vec![height],
            now: std::time::Instant::now(),
        });
        self.process_block_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    /// Common back-edge: re-queue a height via `FetchFailed`.
    fn feed_block_sync_fetch_failed(&mut self, height: BlockHeight, kind: FetchFailureKind) {
        record_sync_round_retried("block");
        let outputs = self.syncs.block.handle(BlockSyncInput::FetchFailed {
            scope: (),
            from: height,
            count: 1,
            kind,
            now: std::time::Instant::now(),
        });
        self.process_block_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }
}

/// Structural validation for a rehydrated synced block.
///
/// Confirms identity (height + QC binding) and that every Merkle root
/// the block header commits to is reproducible from the body the
/// requester now holds. Receipts ride inside `FinalizedWave`s, so
/// `local_receipt_root` is checked when certificates are present.
/// Provisions only ride on `Block::Live`, so `provision_root` is checked
/// only when the response carried provision bodies.
///
/// On `Err`, the returned `&'static str` is suitable for both the
/// metrics label and the warn message.
fn validate_synced_block(
    height: BlockHeight,
    certified: &CertifiedBlock,
) -> Result<(), &'static str> {
    if certified.block().height() != height {
        return Err("height_mismatch");
    }
    let block_hash = certified.block().hash();
    if certified.qc().block_hash() != block_hash {
        return Err("qc_hash_mismatch");
    }
    if certified.qc().height() != height {
        return Err("qc_height_mismatch");
    }

    let header = certified.block().header();

    if !certified.block().transactions().is_empty()
        && compute_transaction_root(certified.block().transactions()) != header.transaction_root()
    {
        return Err("transaction_root_mismatch");
    }

    if !certified.block().certificates().is_empty() {
        if compute_certificate_root(certified.block().certificates()) != header.certificate_root() {
            return Err("certificate_root_mismatch");
        }

        // Per-wave shape: receipts must match each wave's EC tx_outcomes
        // (one receipt per non-aborted outcome, canonical order, matching
        // success/failure). `local_receipt_root` below catches content
        // mismatches but doesn't enforce per-wave grouping.
        for fw in certified.block().certificates().iter() {
            if fw.validate_receipts_against_ec().is_err() {
                return Err("receipts_vs_ec_mismatch");
            }
        }

        let receipts: Vec<StoredReceipt> = certified
            .block()
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        if compute_local_receipt_root(&receipts) != header.local_receipt_root() {
            return Err("local_receipt_root_mismatch");
        }
    }

    if !certified.block().provisions().is_empty() {
        let provision_hashes: Vec<Hash> = certified
            .block()
            .provisions()
            .iter()
            .map(|p| p.hash().into_raw())
            .collect();
        if compute_provision_root(&provision_hashes) != header.provision_root() {
            return Err("provision_root_mismatch");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        Block, BlockHash, BlockHeader, Bls12381G2Signature, BoundedVec, CertificateRoot,
        ConsensusReceipt, ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot, TxHash,
        TxOutcome, ValidatorId, WaveCertificate, WaveId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    const HEIGHT: BlockHeight = BlockHeight::new(1);

    fn header() -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            HEIGHT,
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
        )
    }

    /// Rebuild a header with selected roots overridden.
    fn header_with_roots(
        h: &BlockHeader,
        transaction_root: Option<TransactionRoot>,
        certificate_root: Option<CertificateRoot>,
        local_receipt_root: Option<LocalReceiptRoot>,
    ) -> BlockHeader {
        BlockHeader::new(
            h.shard_group_id(),
            h.height(),
            h.parent_block_hash(),
            h.parent_qc().clone(),
            h.proposer(),
            h.timestamp(),
            h.round(),
            h.is_fallback(),
            h.state_root(),
            transaction_root.unwrap_or_else(|| h.transaction_root()),
            certificate_root.unwrap_or_else(|| h.certificate_root()),
            local_receipt_root.unwrap_or_else(|| h.local_receipt_root()),
            h.provision_root(),
            h.waves().clone().into_inner(),
            h.provision_tx_roots().clone().into_inner(),
            h.in_flight(),
        )
    }

    fn qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            block.height(),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    /// Build a single-tx, single-wave wave with consistent EC + receipt.
    /// Returns the wave plus the populated `local_receipt_root` and
    /// `certificate_root` so the caller can construct a self-consistent
    /// header.
    fn make_wave(success: bool) -> (Arc<FinalizedWave>, LocalReceiptRoot, CertificateRoot) {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let wave_id = WaveId::new(
            ShardGroupId::new(0),
            HEIGHT,
            std::collections::BTreeSet::new(),
        );
        let outcome = TxOutcome::new(
            tx_hash,
            if success {
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                }
            } else {
                ExecutionOutcome::Failed
            },
        );
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![outcome],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            consensus: Arc::new(if success {
                ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    #[allow(clippy::default_trait_access)]
                    database_updates: Default::default(),
                    application_events: vec![],
                }
            } else {
                ConsensusReceipt::Failed
            }),
            metadata: None,
        };
        let fw = Arc::new(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![Arc::new(ec)])),
            vec![receipt.clone()],
        ));
        let lrr = compute_local_receipt_root(&[receipt]);
        let cr = compute_certificate_root(std::slice::from_ref(&fw));
        (fw, lrr, cr)
    }

    #[test]
    fn validate_passes_for_canonical_block() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    #[test]
    fn validate_rejects_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(BlockHeight::new(99), &certified).unwrap_err(),
            "height_mismatch"
        );
    }

    #[test]
    #[should_panic(expected = "CertifiedBlock pairing invariant")]
    fn certified_block_rejects_qc_hash_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardGroupId::new(0),
            block.height(),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        let _ = CertifiedBlock::new_unchecked(block, qc);
    }

    #[test]
    fn validate_rejects_qc_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            BlockHeight::new(99),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "qc_height_mismatch"
        );
    }

    #[test]
    fn validate_rejects_transaction_root_mismatch() {
        let tx = Arc::new(test_transaction(1));
        let h = header_with_roots(&header(), Some(TransactionRoot::ZERO), None, None); // canonical would be non-zero
        let block = Block::Live {
            header: h,
            transactions: Arc::new(vec![tx].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "transaction_root_mismatch"
        );
    }

    #[test]
    fn validate_passes_when_transaction_root_matches() {
        let tx = Arc::new(test_transaction(1));
        let h = header_with_roots(
            &header(),
            Some(compute_transaction_root(std::slice::from_ref(&tx))),
            None,
            None,
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(vec![tx].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    #[test]
    fn validate_rejects_certificate_root_mismatch() {
        let (fw, lrr, _cr) = make_wave(true);
        let h = header_with_roots(
            &header(),
            None,
            Some(CertificateRoot::from_raw(Hash::from_bytes(b"wrong"))),
            Some(lrr),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![fw].into()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "certificate_root_mismatch"
        );
    }

    #[test]
    fn validate_rejects_receipts_inconsistent_with_ec() {
        // Wave whose EC attests Success but whose receipt reports Failure.
        // `validate_receipts_against_ec` catches this even when both
        // certificate_root and local_receipt_root are computed off the
        // (corrupted) body and would tautologically match.
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx_divergent"));
        let wave_id = WaveId::new(
            ShardGroupId::new(0),
            HEIGHT,
            std::collections::BTreeSet::new(),
        );
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            // ConsensusReceipt::Failed but EC said Succeeded — mismatch test.
            consensus: Arc::new(ConsensusReceipt::Failed),
            metadata: None,
        };
        let fw = Arc::new(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![Arc::new(ec)])),
            vec![receipt.clone()],
        ));
        let h = header_with_roots(
            &header(),
            None,
            Some(compute_certificate_root(std::slice::from_ref(&fw))),
            Some(compute_local_receipt_root(&[receipt])),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![fw].into()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "receipts_vs_ec_mismatch"
        );
    }

    #[test]
    fn validate_rejects_local_receipt_root_mismatch() {
        // Self-consistent wave (EC matches receipts), but the header's
        // `local_receipt_root` is wrong. Catches a peer that ships a
        // receipt body with `database_updates` content that doesn't
        // hash to the QC'd root.
        let (fw, _lrr, cr) = make_wave(true);
        let h = header_with_roots(
            &header(),
            None,
            Some(cr),
            Some(LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong"))),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![fw].into()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "local_receipt_root_mismatch"
        );
    }

    #[test]
    fn validate_passes_for_canonical_certificate_block() {
        let (fw, lrr, cr) = make_wave(true);
        let h = header_with_roots(&header(), None, Some(cr), Some(lrr));
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![fw].into()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }
}
