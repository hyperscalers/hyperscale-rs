//! Block-sync I/O glue.
//!
//! Bridges `Sync<BlockSyncBinding>`'s scheduling decisions to the network
//! and shard consensus. This is where payload-specific concerns live:
//!
//! - building `GetBlockRequest`s with the right inventory bloom + force-full
//!   override
//! - rehydrating elided responses against local caches
//! - structurally validating the rehydrated block (off-thread on
//!   `ConsensusCrypto`): height + QC binding + every Merkle root the
//!   header commits to, plus per-wave receipt-vs-EC shape
//! - delivering valid blocks to shard consensus via `ProtocolEvent::BlockSyncReadyToApply`
//! - feeding scheduling events back to the FSM
//!
//! The FSM itself owns nothing about a `CertifiedBlock`'s shape — it just
//! tracks heights and emits `Fetch { from, count }` for the binding to
//! turn into a network round-trip.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::{
    record_sync_block_filtered, record_sync_response_error, record_sync_round_completed,
    record_sync_round_retried, record_sync_round_started,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    BlockHeight, CertificateRoot, CertifiedBlock, ElidedCertifiedBlock, Hash, Inventory,
    LocalReceiptRoot, ProvisionsRoot, RehydrateError, StoredReceipt, TransactionRoot, Verifiable,
    Verified,
};

use crate::event::classify_fetch_error;
use crate::shard::consensus::{BlockSyncInput, BlockSyncOutput};
use crate::shard_loop::{FetchFailureKind, ShardLoop, ShardScopedInput, push_shard_input};
use crate::sync::SyncOutput;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartBlockSync`: feed this shard's FSM and dispatch
    /// any fetches it emits.
    pub(crate) fn process_start_block_sync(&mut self, target: BlockHeight) {
        let outputs = self
            .io
            .syncs
            .block
            .handle(BlockSyncInput::StartSync { scope: (), target });
        self.process_block_sync_outputs(outputs);
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Handle a sync block response: rehydrate the elided block against
    /// local caches, then dispatch structural validation off-thread on
    /// `ConsensusCrypto`. On rehydration miss, mark the height for full
    /// refetch and re-queue. The verdict returns as
    /// `ShardScopedInput::SyncBlockValidated` / `SyncBlockValidationFailed`.
    pub(crate) fn handle_block_sync_response_received(
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
                self.io.syncs.block.mark_force_full_refetch(height);
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
        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let input = match validate_synced_block(height, &cert) {
                    Ok(()) => ShardScopedInput::SyncBlockValidated {
                        height,
                        certified: Box::new(cert),
                    },
                    Err(reason) => ShardScopedInput::SyncBlockValidationFailed { height, reason },
                };
                push_shard_input(&event_tx, local_shard, input);
            });
    }

    /// Handle a sync block fetch failure (network error / not-found).
    pub(crate) fn handle_block_sync_fetch_failed(
        &mut self,
        height: BlockHeight,
        kind: FetchFailureKind,
    ) {
        record_sync_response_error("block", "fetch_failed");
        self.feed_block_sync_fetch_failed(height, kind);
    }

    /// Resume the post-validation delivery path after off-thread
    /// structural validation succeeded.
    pub(crate) fn handle_sync_block_validated(
        &mut self,
        height: BlockHeight,
        certified: CertifiedBlock,
    ) {
        self.deliver_validated_sync_block(height, certified);
    }

    /// Resume the failure path after off-thread structural validation
    /// rejected the response.
    ///
    /// Root-mismatch reasons inspect body components that ride inside
    /// elidable wave/tx/provision blobs. When rehydration filled those
    /// from a poisoned local cache (e.g. a `FinalizedWave` holding
    /// locally-divergent receipts under a canonical wave id), every
    /// rehydrated retry would reject the same bytes. Mark the height for
    /// force-full so the next attempt asks for a non-elided body and
    /// bypasses the cache, then re-queue immediately like the rehydration
    /// miss path. Header / QC identity mismatches inspect non-elidable
    /// fields and are genuine peer-content issues — keep the backoff.
    pub(crate) fn handle_sync_block_validation_failed(
        &mut self,
        height: BlockHeight,
        reason: &'static str,
    ) {
        tracing::warn!(height = height.inner(), reason, "Sync: rejecting response");
        record_sync_block_filtered("block", reason);
        if cache_sensitive_validation_failure(reason) {
            self.io.syncs.block.mark_force_full_refetch(height);
            self.feed_block_sync_fetch_failed(height, FetchFailureKind::Exhausted);
        } else {
            self.feed_block_sync_fetch_failed(height, FetchFailureKind::Transport);
        }
    }

    // ─── Sync output processing + helpers ───────────────────────────────

    /// Process FSM outputs: `Fetch` → network request, `Complete` →
    /// fed into the state machine as `BlockSyncComplete`.
    pub(crate) fn process_block_sync_outputs(&mut self, outputs: Vec<BlockSyncOutput>) {
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
                    self.dispatch_event(ProtocolEvent::BlockSyncComplete { height });
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

        let target_height = self.io.syncs.block.target(&()).unwrap_or(height);
        let force_full = self.io.syncs.block.force_full(height);

        // Heights flagged `force_full` were rehydration misses last time —
        // request with empty inventory so the responder cannot elide bodies.
        let inventory = if force_full {
            Inventory::empty()
        } else {
            inventory_cache
                .get_or_insert_with(|| self.build_sync_inventory())
                .clone()
        };
        let es = self.event_sender().clone();
        let local_shard = self.shard;
        record_sync_round_started("block");
        self.process.network.request(
            self.shard,
            None,
            GetBlockRequest::new(height, target_height).with_inventory(inventory),
            None,
            Box::new(move |result: Result<GetBlockResponse, _>| {
                match result {
                    Ok(resp) => {
                        let block = resp.into_elided().map(Box::new);
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BlockSyncResponseReceived { height, block },
                        );
                    }
                    Err(err) => {
                        let kind = classify_fetch_error(&err);
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BlockSyncFetchFailed { height, kind },
                        );
                    }
                }
                // "Peer doesn't have this height" is ambiguous (peer may
                // simply be behind us) — never Reject.
                ResponseVerdict::Accept
            }),
        );
    }

    /// Snapshot local mempool / finalized-wave / provision store into
    /// an [`Inventory`] so the responder can elide bodies the requester
    /// already has.
    fn build_sync_inventory(&self) -> Inventory {
        let caches = &self.io.caches;
        Inventory {
            tx_have: caches.tx_store.tx_bloom_snapshot(),
            cert_have: caches.finalized_wave_store.cert_bloom_snapshot(),
            provision_have: caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock`.
    fn rehydrate_elided_block(
        &self,
        elided: &ElidedCertifiedBlock,
    ) -> Result<CertifiedBlock, RehydrateError> {
        let caches = &self.io.caches;
        elided.try_rehydrate(
            |h| {
                caches
                    .tx_store
                    .get(h)
                    .map(|tx| Arc::new(Verifiable::from((*tx).clone())))
            },
            |id| caches.finalized_wave_store.get(id),
            // `provision_store` holds raw bodies; lift into the unverified
            // transport shape — the wave-cert linkage gates trust on the
            // rehydrated block.
            |h| {
                caches
                    .provision_store
                    .get(*h)
                    .map(|p| Arc::new((*p).clone().into()))
            },
        )
    }

    /// Hand a validated synced block to shard consensus and advance the sync FSM.
    /// Structural validation runs off-thread; this is the
    /// post-verdict pinned-thread continuation.
    fn deliver_validated_sync_block(&mut self, height: BlockHeight, certified: CertifiedBlock) {
        record_sync_round_completed("block");

        // Hand the block off to shard consensus; tell the FSM the height was delivered.
        let certified = Arc::new(certified);
        self.dispatch_event(ProtocolEvent::BlockSyncReadyToApply { certified });
        let outputs = self.io.syncs.block.handle(BlockSyncInput::FetchSucceeded {
            scope: (),
            from: height,
            count: 1,
            delivered_heights: vec![height],
            now: std::time::Instant::now(),
        });
        self.process_block_sync_outputs(outputs);
    }

    /// Common back-edge: re-queue a height via `FetchFailed`.
    fn feed_block_sync_fetch_failed(&mut self, height: BlockHeight, kind: FetchFailureKind) {
        record_sync_round_retried("block");
        let outputs = self.io.syncs.block.handle(BlockSyncInput::FetchFailed {
            scope: (),
            from: height,
            count: 1,
            kind,
            now: std::time::Instant::now(),
        });
        self.process_block_sync_outputs(outputs);
    }
}

/// True for [`validate_synced_block`] failure reasons whose bytes can
/// originate in local rehydration caches (transaction store, finalized
/// wave store, provision store). A repeat from the same cache would
/// reject identically; force-full bypasses elision on the next attempt.
/// Header / QC identity mismatches (`height_mismatch`, `qc_hash_mismatch`,
/// `qc_height_mismatch`) inspect non-elidable fields and are excluded.
fn cache_sensitive_validation_failure(reason: &str) -> bool {
    matches!(
        reason,
        "transaction_root_mismatch"
            | "certificate_root_mismatch"
            | "receipts_vs_ec_mismatch"
            | "local_receipt_root_mismatch"
            | "provision_root_mismatch"
    )
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
        && Verified::<TransactionRoot>::compute(certified.block().transactions()).into_inner()
            != header.transaction_root()
    {
        return Err("transaction_root_mismatch");
    }

    if !certified.block().certificates().is_empty() {
        if Verified::<CertificateRoot>::compute(certified.block().certificates()).into_inner()
            != header.certificate_root()
        {
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
        if Verified::<LocalReceiptRoot>::compute(&receipts).into_inner()
            != header.local_receipt_root()
        {
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
        if Verified::<ProvisionsRoot>::compute(&provision_hashes).into_inner()
            != header.provision_root()
        {
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
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader,
        Bls12381G2Signature, BoundedVec, CertificateRoot, ChainOrigin, ConsensusReceipt,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardId, SignerBitfield, StateRoot, TransactionRoot, TxHash,
        TxOutcome, ValidatorId, Verifiable, WaveCertificate, WaveId, WeightedTimestamp,
        zero_bls_signature,
    };

    use super::*;

    const HEIGHT: BlockHeight = BlockHeight::new(1);

    fn header() -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            HEIGHT,
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
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
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
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
            h.shard_id(),
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
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    fn qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
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
    fn make_wave(
        success: bool,
    ) -> (
        Arc<Verifiable<FinalizedWave>>,
        LocalReceiptRoot,
        CertificateRoot,
    ) {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let wave_id = WaveId::new(ShardId::ROOT, HEIGHT, std::collections::BTreeSet::new());
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
                    owned_nodes: BoundedVec::new(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }
            } else {
                ConsensusReceipt::Failed
            }),
            metadata: None,
        };
        let fw = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id, vec![Arc::new(ec)])),
                vec![receipt.clone()],
            )
            .into(),
        );
        let lrr = Verified::<LocalReceiptRoot>::compute(&[receipt]).into_inner();
        let cr = Verified::<CertificateRoot>::compute(std::slice::from_ref(&fw)).into_inner();
        (fw, lrr, cr)
    }

    #[test]
    fn validate_passes_for_canonical_block() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
        };
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardId::ROOT,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
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
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with_roots(&header(), Some(TransactionRoot::ZERO), None, None); // canonical would be non-zero
        let block = Block::Live {
            header: h,
            transactions: Arc::new(vec![tx].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with_roots(
            &header(),
            Some(Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx)).into_inner()),
            None,
            None,
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(vec![tx].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
        let wave_id = WaveId::new(ShardId::ROOT, HEIGHT, std::collections::BTreeSet::new());
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
        let fw = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id, vec![Arc::new(ec)])),
                vec![receipt.clone()],
            )
            .into(),
        );
        let h = header_with_roots(
            &header(),
            None,
            Some(Verified::<CertificateRoot>::compute(std::slice::from_ref(&fw)).into_inner()),
            Some(Verified::<LocalReceiptRoot>::compute(&[receipt]).into_inner()),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![fw].into()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "local_receipt_root_mismatch"
        );
    }

    #[test]
    fn cache_sensitive_classification_matches_validate_synced_block_reasons() {
        // The classifier gates `mark_force_full_refetch` after a rehydrated
        // response fails `validate_synced_block`. Each cache-sensitive
        // reason inspects bytes that ride inside elidable bodies
        // (transactions, finalized waves, provisions). Each non-sensitive
        // reason inspects non-elidable header / QC identity fields. If a
        // new failure reason is added to `validate_synced_block`, decide
        // which bucket it belongs in and add it here.
        for reason in [
            "transaction_root_mismatch",
            "certificate_root_mismatch",
            "receipts_vs_ec_mismatch",
            "local_receipt_root_mismatch",
            "provision_root_mismatch",
        ] {
            assert!(
                cache_sensitive_validation_failure(reason),
                "{reason} should be classified as cache-sensitive"
            );
        }
        for reason in ["height_mismatch", "qc_hash_mismatch", "qc_height_mismatch"] {
            assert!(
                !cache_sensitive_validation_failure(reason),
                "{reason} should not be classified as cache-sensitive"
            );
        }
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }
}
