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
//!   header commits to, plus per-tick receipt-vs-EC shape
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
    AbandonmentRoot, BlockHeight, CertificateRoot, CertifiedBlock, ElidedCertifiedBlock, Hash,
    Inventory, LocalReceiptRoot, ProvisionHash, ProvisionsRoot, RehydrateError, StateClaimsRoot,
    StoredReceipt, TransactionRoot, Verifiable, Verified,
};

use crate::event::classify_fetch_error;
use crate::shard::consensus::{BlockSyncInput, BlockSyncOutput};
use crate::shard::{FetchFailureKind, ShardLoop, ShardScopedInput, push_shard_input};
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
            .consensus
            .block_sync
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
                self.io.consensus.block_sync.mark_force_full_refetch(height);
                // Rehydration is a local-data issue resolved by force-full
                // on the next attempt — re-queue immediately rather than
                // backing off.
                self.feed_block_sync_fetch_failed(height, FetchFailureKind::Exhausted);
                return;
            }
        };

        // Dispatch structural validation to ConsensusCrypto. The
        // `local_receipt_root` Merkle is the heavy step (wire encode of
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
    /// elidable tick/tx/provision blobs. When rehydration filled those
    /// from a poisoned local cache (e.g. a `Finalization` holding
    /// locally-divergent receipts under a canonical tick id), every
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
            self.io.consensus.block_sync.mark_force_full_refetch(height);
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

        let target_height = self.io.consensus.block_sync.target(&()).unwrap_or(height);
        let force_full = self.io.consensus.block_sync.force_full(height);

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

    /// Snapshot local mempool / finalization / provision store into
    /// an [`Inventory`] so the responder can elide bodies the requester
    /// already has.
    fn build_sync_inventory(&self) -> Inventory {
        let caches = &self.io.caches;
        Inventory {
            tx_have: caches.tx_store.tx_bloom_snapshot(),
            cert_have: caches.finalization_store.cert_bloom_snapshot(),
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
            |id| caches.finalization_store.get(id),
            // `provision_store` holds raw bodies; lift into the unverified
            // transport shape — the tick-cert linkage gates trust on the
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
        let outputs = self
            .io
            .consensus
            .block_sync
            .handle(BlockSyncInput::FetchSucceeded {
                scope: (),
                from: height,
                count: 1,
                delivered_heights: vec![height],
                now: self.now,
            });
        self.process_block_sync_outputs(outputs);
    }

    /// Common back-edge: re-queue a height via `FetchFailed`.
    fn feed_block_sync_fetch_failed(&mut self, height: BlockHeight, kind: FetchFailureKind) {
        record_sync_round_retried("block");
        let outputs = self
            .io
            .consensus
            .block_sync
            .handle(BlockSyncInput::FetchFailed {
                scope: (),
                from: height,
                count: 1,
                kind,
                now: self.now,
            });
        self.process_block_sync_outputs(outputs);
    }
}

/// True for [`validate_synced_block`] failure reasons whose bytes can
/// originate in local rehydration caches (transaction store, finalized
/// tick store, provision store). A repeat from the same cache would
/// reject identically; force-full bypasses elision on the next attempt.
/// Header / QC identity mismatches (`height_mismatch`, `qc_hash_mismatch`,
/// `qc_height_mismatch`) inspect non-elidable fields and are excluded, as
/// is `abandonment_root_mismatch` — the records ride inline whatever
/// inventory the requester offers, so refetching without elision would ask
/// the same peer for the same bytes.
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
/// Confirms identity (height + QC binding) and that every Merkle root the
/// block header commits to is reproducible from the body the requester now
/// holds.
///
/// Every root is checked whatever the body carries, because an empty list
/// has a root of its own — `ZERO`, the empty-input compute — rather than no
/// root: a header claiming content the body does not carry is as much a
/// mismatch as the reverse. A root left unchecked because its list came
/// back empty is a serving peer's licence to strip the body off an
/// otherwise genuine, QC-signed header. Nothing downstream would catch it:
/// a synced block is admitted on QC attestation and its state root is never
/// verified locally, so the stripped body reaches the inline JMT prep at
/// commit and diverges there, which is fatal to the node rather than fatal
/// to the response.
///
/// Provisions are read as hashes rather than bodies, since a `Sealed` block
/// drops the bodies and retains the list, and `Block::provision_hashes`
/// derives the `Live` list by hashing the same bodies the root is computed
/// over. One expression therefore binds both variants.
///
/// The abandonment records are the one body list no hash in the
/// manifest binds — they ride inline rather than by reference — so this is
/// the only place a serving peer's copy is held to the header the committee
/// actually signed.
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

    if Verified::<AbandonmentRoot>::compute(certified.block().abandonment_records()).into_inner()
        != header.abandonment_root()
    {
        return Err("abandonment_root_mismatch");
    }

    if Verified::<StateClaimsRoot>::compute(certified.block().state_claims()).into_inner()
        != header.state_claims_root()
    {
        return Err("state_claims_root_mismatch");
    }

    if Verified::<TransactionRoot>::compute(certified.block().transactions()).into_inner()
        != header.transaction_root()
    {
        return Err("transaction_root_mismatch");
    }

    if Verified::<CertificateRoot>::compute(certified.block().certificates()).into_inner()
        != header.certificate_root()
    {
        return Err("certificate_root_mismatch");
    }

    // Per-tick shape: receipts must match each tick's EC tx_outcomes
    // (one receipt per non-aborted outcome, canonical order, matching
    // success/failure). `local_receipt_root` below catches content
    // mismatches but doesn't enforce per-tick grouping.
    for fw in certified.block().certificates().iter() {
        if fw.validate_against_certificates().is_err() {
            return Err("receipts_vs_ec_mismatch");
        }
    }

    let receipts: Vec<StoredReceipt> = certified
        .block()
        .certificates()
        .iter()
        .flat_map(|fw| fw.receipts().iter().cloned())
        .collect();
    if Verified::<LocalReceiptRoot>::compute(&receipts).into_inner() != header.local_receipt_root()
    {
        return Err("local_receipt_root_mismatch");
    }

    let provision_hashes: Vec<Hash> = certified
        .block()
        .provision_hashes()
        .into_iter()
        .map(ProvisionHash::into_raw)
        .collect();
    if Verified::<ProvisionsRoot>::compute(&provision_hashes).into_inner()
        != header.provision_root()
    {
        return Err("provision_root_mismatch");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::test_utils::{stub_abort_charge, test_transaction};
    use hyperscale_types::{
        AbandonmentRecord, AggregateSignature, Block, BlockHash, BlockHeader, BlockHeaderParts,
        BlockHeight, CertificateRoot, ChainOrigin, CommittedAt, ConsensusReceipt, Deadline,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, GlobalReceiptRoot,
        LocalReceiptRoot, ProposerTimestamp, QuorumCertificate, Round, ShardId, SignerBitfield,
        TickHalf, TickId, TransactionRoot, TxHash, TxOutcome, UnsettledTx, Verifiable,
        WeightedTimestamp, WitnessSources,
    };

    use super::*;

    const HEIGHT: BlockHeight = BlockHeight::new(1);

    fn header() -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height: HEIGHT,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_000),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        })
    }

    /// Rebuild a header with selected roots overridden.
    fn header_with_roots(
        h: &BlockHeader,
        transaction_root: Option<TransactionRoot>,
        certificate_root: Option<CertificateRoot>,
        local_receipt_root: Option<LocalReceiptRoot>,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: h.shard_id(),
            height: h.height(),
            parent_block_hash: h.parent_block_hash(),
            parent_qc: h.parent_qc().clone().into(),
            proposer: h.proposer(),
            timestamp: h.timestamp(),
            round: h.round(),
            is_fallback: h.is_fallback(),
            state_root: h.state_root(),
            transaction_root: transaction_root.unwrap_or_else(|| h.transaction_root()),
            certificate_root: certificate_root.unwrap_or_else(|| h.certificate_root()),
            local_receipt_root: local_receipt_root.unwrap_or_else(|| h.local_receipt_root()),
            provision_root: h.provision_root(),
            provision_tx_roots: h.provision_tx_roots().clone(),
            work_in_flight: h.work_in_flight(),
            ..Default::default()
        })
    }

    fn qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            block.height(),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    /// Build a single-tx, single-tick tick with consistent EC + receipt.
    /// Returns the tick plus the populated `local_receipt_root` and
    /// `certificate_root` so the caller can construct a self-consistent
    /// header.
    fn make_tick(
        success: bool,
    ) -> (
        Arc<Verifiable<Finalization>>,
        LocalReceiptRoot,
        CertificateRoot,
    ) {
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx"));
        let tick_id = TickId::new(ShardId::ROOT, HEIGHT);
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
            tick_id,
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![outcome],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            consensus: Arc::new(if success {
                ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    #[allow(clippy::default_trait_access)]
                    writes: Default::default(),
                    beacon_witness_events: Vec::new(),
                    events: Vec::new(),
                }
            } else {
                ConsensusReceipt::Failed
            }),
            metadata: None,
        };
        let fw = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                vec![Arc::new(ec)],
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    #[test]
    fn validate_rejects_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardId::ROOT,
            block.height(),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let _ = CertifiedBlock::new_unchecked(block, qc);
    }

    #[test]
    fn validate_rejects_qc_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            BlockHeight::new(99),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(0),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "qc_height_mismatch"
        );
    }

    /// [`header`] with `abandonment_root` overridden.
    fn header_committing(root: AbandonmentRoot) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height: HEIGHT,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_000),
            provision_tx_roots: std::collections::BTreeMap::new(),
            abandonment_root: root,
            ..Default::default()
        })
    }

    /// A block's state claims are the one body list beside the records
    /// that a manifest holds by value, and every replica folds them at
    /// commit; a serving peer that drops or forges them hands back a
    /// block whose answers are not the chain's.
    #[test]
    fn validate_binds_state_claims_in_both_directions() {
        use hyperscale_types::{Anchor, Inclusion, StateClaim, StateRoot};
        let bundles = vec![StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 0),
                height: BlockHeight::new(3),
                state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
                ts: WeightedTimestamp::from_millis(3_000),
            },
            [(stub_abort_charge(1).vault, Inclusion::Absent)],
        )];
        let root = Verified::<StateClaimsRoot>::compute(&bundles).into_inner();
        let live = |state_claims: Vec<StateClaim>| Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: HEIGHT,
                parent_block_hash: BlockHash::ZERO,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                timestamp: ProposerTimestamp::from_millis(1_000),
                provision_tx_roots: std::collections::BTreeMap::new(),
                state_claims_root: root,
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(state_claims),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let dropped = live(Vec::new());
        let qc = qc_for(&dropped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(dropped, qc)).unwrap_err(),
            "state_claims_root_mismatch"
        );

        let carried = live(bundles);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the proofs the header commits are the ones it accepts"
        );
    }

    fn boundary_record() -> AbandonmentRecord {
        AbandonmentRecord::new(
            ShardId::leaf(1, 0),
            WeightedTimestamp::from_millis(2_000),
            [UnsettledTx {
                tx_hash: TxHash::from(Hash::from_bytes(b"stranded")),
                deadline: Deadline::of(WeightedTimestamp::from_millis(1_500)),
                declared_work: 7,
                charge: stub_abort_charge(7),
                committed: CommittedAt {
                    height: BlockHeight::new(1),
                    anchor: WeightedTimestamp::from_millis(500),
                },
                reach: Vec::new(),
            }],
        )
    }

    /// A boundary record licenses abandoning a transaction and carries the
    /// terms of the abort, and it is the one body list a manifest holds by
    /// value rather than by hash. So a serving peer that attaches records
    /// to a header committing none is refused here — the vote path that
    /// would otherwise catch it never runs on a synced block.
    #[test]
    fn validate_rejects_abandonment_records_the_header_does_not_commit() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(vec![boundary_record()]),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "abandonment_root_mismatch"
        );
    }

    /// And the reverse. A hop that dropped the records would hand back a
    /// block that cannot answer for itself, so an empty list against a
    /// header committing records is a mismatch rather than a lighter
    /// answer — which is why the check runs whatever the body carries.
    #[test]
    fn validate_binds_abandonment_records_in_both_directions() {
        let records = vec![boundary_record()];
        let root = Verified::<AbandonmentRoot>::compute(&records).into_inner();
        let live = |abandonment_records: Vec<AbandonmentRecord>| Block::Live {
            header: header_committing(root),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(abandonment_records),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let dropped = live(Vec::new());
        let qc = qc_for(&dropped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(dropped, qc)).unwrap_err(),
            "abandonment_root_mismatch"
        );

        let carried = live(records);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the records the header commits are the ones it accepts"
        );
    }

    #[test]
    fn validate_rejects_transaction_root_mismatch() {
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with_roots(&header(), Some(TransactionRoot::ZERO), None, None); // canonical would be non-zero
        let block = Block::Live {
            header: h,
            transactions: Arc::new(vec![tx]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
            transactions: Arc::new(vec![tx]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    /// A serving peer keeps the genuine, QC-signed header and returns an
    /// empty transaction list. The header's root is what the committee
    /// signed over, so the empty body is the mismatch — the check cannot
    /// be conditioned on the list the peer chose to send.
    #[test]
    fn validate_rejects_stripped_transactions() {
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with_roots(
            &header(),
            Some(Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx)).into_inner()),
            None,
            None,
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "transaction_root_mismatch"
        );
    }

    /// And the same for the certificates, which carry the receipts the
    /// state root is computed over.
    #[test]
    fn validate_rejects_stripped_certificates() {
        let (_fw, lrr, cr) = make_tick(true);
        let h = header_with_roots(&header(), None, Some(cr), Some(lrr));
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "certificate_root_mismatch"
        );
    }

    /// A `Sealed` block drops the provision bodies and keeps their hashes,
    /// so the root binds against the retained list. Both directions: the
    /// hashes the header commits pass, a stripped list does not.
    #[test]
    fn validate_binds_provision_root_on_sealed_block() {
        let hashes = vec![ProvisionHash::from_raw(Hash::from_bytes(b"batch"))];
        let root = Verified::<ProvisionsRoot>::compute(
            &hashes.iter().map(|h| h.into_raw()).collect::<Vec<_>>(),
        )
        .into_inner();
        let sealed = |provision_hashes: Vec<ProvisionHash>| Block::Sealed {
            header: BlockHeader::new(BlockHeaderParts {
                height: HEIGHT,
                parent_block_hash: BlockHash::ZERO,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                timestamp: ProposerTimestamp::from_millis(1_000),
                provision_tx_roots: std::collections::BTreeMap::new(),
                provision_root: root,
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provision_hashes: Arc::new(provision_hashes),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let stripped = sealed(Vec::new());
        let qc = qc_for(&stripped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(stripped, qc))
                .unwrap_err(),
            "provision_root_mismatch"
        );

        let carried = sealed(hashes);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the batches the header commits are the ones it accepts"
        );
    }

    #[test]
    fn validate_rejects_certificate_root_mismatch() {
        let (fw, lrr, _cr) = make_tick(true);
        let h = header_with_roots(
            &header(),
            None,
            Some(CertificateRoot::from_raw(Hash::from_bytes(b"wrong"))),
            Some(lrr),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![fw]),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
        // Tick whose EC attests Success but whose receipt reports Failure.
        // `validate_against_certificates` catches this even when both
        // certificate_root and local_receipt_root are computed off the
        // (corrupted) body and would tautologically match.
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx_divergent"));
        let tick_id = TickId::new(ShardId::ROOT, HEIGHT);
        let ec = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            // ConsensusReceipt::Failed but EC said Succeeded — mismatch test.
            consensus: Arc::new(ConsensusReceipt::Failed),
            metadata: None,
        };
        let fw = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                vec![Arc::new(ec)],
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![fw]),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
        // Self-consistent tick (EC matches receipts), but the header's
        // `local_receipt_root` is wrong. Catches a peer that ships a
        // receipt body with `database_updates` content that doesn't
        // hash to the QC'd root.
        let (fw, _lrr, cr) = make_tick(true);
        let h = header_with_roots(
            &header(),
            None,
            Some(cr),
            Some(LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong"))),
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![fw]),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
        // (transactions, finalizations, provisions). Each non-sensitive
        // reason inspects something no inventory can elide — a header / QC
        // identity field, or a body list that always rides inline. If a
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
        for reason in [
            "height_mismatch",
            "qc_hash_mismatch",
            "qc_height_mismatch",
            "abandonment_root_mismatch",
        ] {
            assert!(
                !cache_sensitive_validation_failure(reason),
                "{reason} should not be classified as cache-sensitive"
            );
        }
    }

    #[test]
    fn validate_passes_for_canonical_certificate_block() {
        let (fw, lrr, cr) = make_tick(true);
        let h = header_with_roots(&header(), None, Some(cr), Some(lrr));
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![fw]),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }
}
