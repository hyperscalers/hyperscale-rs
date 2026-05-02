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

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::block_sync::{BlockSyncInput, BlockSyncOutput};
use crate::io_loop::protocol::sync::SyncOutput;
use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::Engine;
use hyperscale_messages::request::Inventory;
use hyperscale_messages::response::{ElidedCertifiedBlock, GetBlockResponse, RehydrateError};
use hyperscale_metrics as metrics;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHeight, CertifiedBlock};

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
            .protocols
            .block_sync
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
            self.feed_block_sync_fetch_failed(height);
            return;
        };
        let cert = match self.rehydrate_elided_block(&elided) {
            Ok(c) => c,
            Err(err) => {
                let reason = match err {
                    RehydrateError::Missing(_) => "rehydration_miss",
                    RehydrateError::QcMismatch { .. } => "qc_hash_mismatch",
                };
                metrics::record_sync_response_error("block", reason);
                self.protocols.block_sync.mark_force_full_refetch(height);
                self.feed_block_sync_fetch_failed(height);
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
    pub(in crate::io_loop) fn handle_block_sync_fetch_failed(&mut self, height: BlockHeight) {
        metrics::record_sync_response_error("block", "fetch_failed");
        self.feed_block_sync_fetch_failed(height);
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
        tracing::warn!(height = height.0, reason, "Sync: rejecting response");
        metrics::record_sync_block_filtered("block", reason);
        self.feed_block_sync_fetch_failed(height);
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
                        height = height.0,
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
        use hyperscale_messages::request::GetBlockRequest;

        let target_height = self.protocols.block_sync.target(&()).unwrap_or(height);
        let force_full = self.protocols.block_sync.force_full(height);

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
        metrics::record_sync_round_started("block");
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
                    Err(_) => {
                        let _ = es.send(NodeInput::BlockSyncFetchFailed { height });
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
            cert_have: self.state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock`.
    fn rehydrate_elided_block(
        &self,
        elided: &ElidedCertifiedBlock,
    ) -> Result<CertifiedBlock, RehydrateError> {
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| mempool.get_transaction(h),
            |h| execution.get_finalized_wave_by_hash(h),
            |h| provision_store.get(h),
        )
    }

    /// Hand a validated synced block to BFT and advance the sync FSM.
    /// Structural validation runs off-thread; this is the
    /// post-verdict pinned-thread continuation.
    fn deliver_validated_sync_block(&mut self, height: BlockHeight, certified: CertifiedBlock) {
        metrics::record_sync_round_completed("block");

        // Hand the block off to BFT; tell the FSM the height was delivered.
        self.feed_event(ProtocolEvent::BlockSyncReadyToApply { certified });
        let outputs = self
            .protocols
            .block_sync
            .handle(BlockSyncInput::FetchSucceeded {
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
    fn feed_block_sync_fetch_failed(&mut self, height: BlockHeight) {
        metrics::record_sync_round_retried("block");
        let outputs = self
            .protocols
            .block_sync
            .handle(BlockSyncInput::FetchFailed {
                scope: (),
                from: height,
                count: 1,
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
    if certified.block.height() != height {
        return Err("height_mismatch");
    }
    let block_hash = certified.block.hash();
    if certified.qc.block_hash != block_hash {
        return Err("qc_hash_mismatch");
    }
    if certified.qc.height != height {
        return Err("qc_height_mismatch");
    }

    let header = certified.block.header();

    if !certified.block.transactions().is_empty()
        && hyperscale_types::compute_transaction_root(certified.block.transactions())
            != header.transaction_root
    {
        return Err("transaction_root_mismatch");
    }

    if !certified.block.certificates().is_empty() {
        if hyperscale_types::compute_certificate_root(certified.block.certificates())
            != header.certificate_root
        {
            return Err("certificate_root_mismatch");
        }

        // Per-wave shape: receipts must match each wave's EC tx_outcomes
        // (one receipt per non-aborted outcome, canonical order, matching
        // success/failure). `local_receipt_root` below catches content
        // mismatches but doesn't enforce per-wave grouping.
        for fw in certified.block.certificates() {
            if fw.validate_receipts_against_ec().is_err() {
                return Err("receipts_vs_ec_mismatch");
            }
        }

        let receipts: Vec<hyperscale_types::StoredReceipt> = certified
            .block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts.iter().cloned())
            .collect();
        if hyperscale_types::compute_local_receipt_root(&receipts) != header.local_receipt_root {
            return Err("local_receipt_root_mismatch");
        }
    }

    if !certified.block.provisions().is_empty() {
        let provision_hashes: Vec<hyperscale_types::Hash> = certified
            .block
            .provisions()
            .iter()
            .map(|p| p.hash().into_raw())
            .collect();
        if hyperscale_types::compute_provision_root(&provision_hashes) != header.provision_root {
            return Err("provision_root_mismatch");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        Block, BlockHash, BlockHeader, Bls12381G2Signature, CertificateRoot, ExecutionCertificate,
        ExecutionOutcome, FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, Hash,
        LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round,
        ShardGroupId, SignerBitfield, StateRoot, StoredReceipt, TransactionRoot, TxHash, TxOutcome,
        ValidatorId, WaveCertificate, WaveId, WeightedTimestamp, compute_certificate_root,
        compute_local_receipt_root, compute_transaction_root, test_utils::test_transaction,
        zero_bls_signature,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const HEIGHT: BlockHeight = BlockHeight(1);

    fn header() -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: HEIGHT,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(1_000),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    fn qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            shard_group_id: ShardGroupId(0),
            height: block.height(),
            parent_block_hash: BlockHash::ZERO,
            round: Round::INITIAL,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(0),
            weighted_timestamp: WeightedTimestamp::ZERO,
        }
    }

    /// Build a single-tx, single-wave wave with consistent EC + receipt.
    /// Returns the wave plus the populated `local_receipt_root` and
    /// `certificate_root` so the caller can construct a self-consistent
    /// header.
    fn make_wave(success: bool) -> (Arc<FinalizedWave>, LocalReceiptRoot, CertificateRoot) {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let wave_id = WaveId::new(ShardGroupId(0), HEIGHT, std::collections::BTreeSet::new());
        let outcome = TxOutcome {
            tx_hash,
            outcome: if success {
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                }
            } else {
                ExecutionOutcome::Failed
            },
        };
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp(1),
            GlobalReceiptRoot::ZERO,
            vec![outcome],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            consensus: Arc::new(if success {
                hyperscale_types::ConsensusReceipt::Succeeded {
                    receipt_hash: hyperscale_types::GlobalReceiptHash::ZERO,
                    #[allow(clippy::default_trait_access)]
                    database_updates: Default::default(),
                    application_events: vec![],
                }
            } else {
                hyperscale_types::ConsensusReceipt::Failed
            }),
            metadata: None,
        };
        let fw = Arc::new(FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![Arc::new(ec)],
            }),
            receipts: vec![receipt.clone()],
        });
        let lrr = compute_local_receipt_root(&[receipt]);
        let cr = compute_certificate_root(std::slice::from_ref(&fw));
        (fw, lrr, cr)
    }

    #[test]
    fn validate_passes_for_canonical_block() {
        let block = Block::Live {
            header: header(),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    #[test]
    fn validate_rejects_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(BlockHeight(99), &certified).unwrap_err(),
            "height_mismatch"
        );
    }

    #[test]
    #[should_panic(expected = "CertifiedBlock pairing invariant")]
    fn certified_block_rejects_qc_hash_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let mut qc = qc_for(&block);
        qc.block_hash = BlockHash::from_raw(Hash::from_bytes(b"wrong"));
        let _ = CertifiedBlock::new_unchecked(block, qc);
    }

    #[test]
    fn validate_rejects_qc_height_mismatch() {
        let block = Block::Live {
            header: header(),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let mut qc = qc_for(&block);
        qc.height = BlockHeight(99);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "qc_height_mismatch"
        );
    }

    #[test]
    fn validate_rejects_transaction_root_mismatch() {
        let tx = Arc::new(test_transaction(1));
        let mut h = header();
        h.transaction_root = TransactionRoot::ZERO; // canonical would be non-zero
        let block = Block::Live {
            header: h,
            transactions: vec![tx],
            certificates: vec![],
            provisions: vec![],
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
        let mut h = header();
        h.transaction_root = compute_transaction_root(std::slice::from_ref(&tx));
        let block = Block::Live {
            header: h,
            transactions: vec![tx],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    #[test]
    fn validate_rejects_certificate_root_mismatch() {
        let (fw, lrr, _cr) = make_wave(true);
        let mut h = header();
        h.certificate_root = CertificateRoot::from_raw(Hash::from_bytes(b"wrong"));
        h.local_receipt_root = lrr;
        let block = Block::Live {
            header: h,
            transactions: vec![],
            certificates: vec![fw],
            provisions: vec![],
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
        let wave_id = WaveId::new(ShardGroupId(0), HEIGHT, std::collections::BTreeSet::new());
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            }],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            // ConsensusReceipt::Failed but EC said Succeeded — mismatch test.
            consensus: std::sync::Arc::new(hyperscale_types::ConsensusReceipt::Failed),
            metadata: None,
        };
        let fw = Arc::new(FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![Arc::new(ec)],
            }),
            receipts: vec![receipt.clone()],
        });
        let mut h = header();
        h.certificate_root = compute_certificate_root(std::slice::from_ref(&fw));
        h.local_receipt_root = compute_local_receipt_root(&[receipt]);
        let block = Block::Live {
            header: h,
            transactions: vec![],
            certificates: vec![fw],
            provisions: vec![],
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
        let mut h = header();
        h.certificate_root = cr;
        h.local_receipt_root = LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong"));
        let block = Block::Live {
            header: h,
            transactions: vec![],
            certificates: vec![fw],
            provisions: vec![],
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
        let mut h = header();
        h.certificate_root = cr;
        h.local_receipt_root = lrr;
        let block = Block::Live {
            header: h,
            transactions: vec![],
            certificates: vec![fw],
            provisions: vec![],
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }
}
