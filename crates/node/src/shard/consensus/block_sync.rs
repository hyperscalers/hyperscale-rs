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
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, ElidedCertifiedBlock, Inventory, RehydrateError,
    UnboundBody, Verifiable,
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

    /// Handle `Action::SyncBlockApplied`: the height is in the chain
    /// state of the vnode at `vnode_idx`, with its commit pending. Once
    /// every seat holds it, the FSM holds it out of the window and may
    /// report the sync complete.
    pub(crate) fn process_sync_block_applied(&mut self, vnode_idx: usize, height: BlockHeight) {
        let seat = self.vnode(vnode_idx).validator_id;
        self.io.consensus.seat_frontiers.applied(seat, height);
        self.follow_slowest_block_sync_seat();
    }

    /// Handle `Action::ReopenSyncHeight`: the block the vnode at
    /// `vnode_idx` applied at `height` has a certified sibling, `hash`,
    /// that is committing instead. The FSM fetches the height again, and
    /// the fetch names `hash`: this host's own store still answers the
    /// height with the block it applied.
    pub(crate) fn process_reopen_sync_height(
        &mut self,
        vnode_idx: usize,
        height: BlockHeight,
        hash: BlockHash,
    ) {
        let seat = self.vnode(vnode_idx).validator_id;
        self.io.consensus.seat_frontiers.reopened(seat, height);
        self.io.consensus.block_sync.name_block(height, hash);
        let outputs = self
            .io
            .consensus
            .block_sync
            .handle(BlockSyncInput::Reopen { scope: (), height });
        self.process_block_sync_outputs(outputs);
    }

    /// Handle `Action::SettleBlockSync`: the target is served by nobody
    /// reachable. The FSM completes at its frontier.
    pub(crate) fn process_settle_block_sync(&mut self) {
        let outputs = self
            .io
            .consensus
            .block_sync
            .handle(BlockSyncInput::Settle { scope: () });
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
            // No peer the request asked had the block — re-queue via
            // fetch-failed. Treat as exhausted so the FSM doesn't pile its
            // own backoff on top of the request manager's; we just want
            // another attempt.
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

        // Dispatch structural validation to ConsensusCrypto. The body
        // root's receipt leaves are the heavy step (wire encode of every
        // receipt's writes); off-loading keeps the pinned thread
        // responsive during catch-up.
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

    /// Handle every peer a fetch reached answering that `height` lies
    /// beneath its chain floor.
    ///
    /// The transport moves past a peer that answers without the block
    /// and answers empty only once every peer it asked has, so a floor
    /// coming back says nobody reachable holds the height. The floor is
    /// one peer's word, and [`block_sync_answer`] lets through only a
    /// floor an honest store can hold, at or beneath the attested
    /// boundary: the re-seat it asks for lands on a height that floor
    /// says is still served. When `height` is the next one this store
    /// needs, block sync cannot carry the store forward from where it
    /// stands: the loop asks the runner to re-seat the shard at its
    /// attested anchor, and the height backs off while the rebuild runs
    /// rather than asking again at once. A height further up is only a
    /// gap the next height's answer settles.
    pub(crate) fn handle_block_sync_below_floor(
        &mut self,
        height: BlockHeight,
        floor: BlockHeight,
    ) {
        record_sync_response_error("block", "below_floor");
        let next = self
            .io
            .consensus
            .block_sync
            .frontier(&())
            .unwrap_or(BlockHeight::GENESIS)
            .next();
        if height == next {
            tracing::warn!(
                height = height.inner(),
                floor = floor.inner(),
                "Sync: next height lies beneath every peer's chain floor; re-seating the shard"
            );
            self.reseat = true;
        }
        self.feed_block_sync_fetch_failed(height, FetchFailureKind::Transport);
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

    /// Dispatch a single-height block fetch. This node syncs to
    /// execute, so every fetch states that intent; the `force_full`
    /// flag and the named block, if any, come from the FSM at dispatch
    /// time.
    fn dispatch_block_sync_fetch(
        &self,
        height: BlockHeight,
        inventory_cache: &mut Option<Inventory>,
    ) {
        use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};

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
        let mut request =
            GetBlockRequest::new(height, BlockIntent::Execute).with_inventory(inventory.clone());
        if let Some(hash) = self.io.consensus.block_sync.named_block(height) {
            request = request.naming(hash);
        }
        let named = request.hash;
        let floor_ceiling = self.honest_floor_ceiling();
        let es = self.event_sender().clone();
        let local_shard = self.shard;
        record_sync_round_started("block");
        self.process.network.request(
            self.shard,
            None,
            request,
            None,
            Box::new(move |result: Result<GetBlockResponse, _>| {
                let (input, verdict) =
                    block_sync_answer(height, named, &inventory, floor_ceiling, result);
                push_shard_input(&es, local_shard, input);
                verdict
            }),
        );
    }

    /// The highest chain floor an honest peer's store answers with.
    ///
    /// A store's floor never passes the boundary the beacon attests for
    /// its shard: the floor is measured down from the oldest pin the
    /// store keeps, and the attested boundary is always among them. A
    /// chain with no attested boundary prunes nothing, so its floor is
    /// the block its genesis follows.
    fn honest_floor_ceiling(&self) -> BlockHeight {
        let attested = self
            .process
            .topology_snapshot()
            .load()
            .boundary(self.shard)
            .map(|anchor| anchor.height);
        attested.unwrap_or_else(|| {
            self.vnodes
                .first()
                .and_then(|vnode| {
                    let origin = vnode.state.shard_coordinator().chain_origin();
                    origin.genesis_height.prev()
                })
                .unwrap_or(BlockHeight::GENESIS)
        })
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

/// What a block fetch at `height` feeds the shard, and what it says of
/// the peer that served it.
///
/// When the fetch named a block, any other block is dropped and the peer
/// rejected: the request said which block answers, and serving another
/// is not an answer. A named fetch that comes back empty is an honest
/// answer from peers without the block and is not rejected. Either way
/// the height backs off, so with no reachable holder of the named block
/// the refetches are paced rather than back to back, and neither counts
/// toward an unfounded target: the named block is certified, so the
/// height exists. An unnamed "no peer asked has this height" is ambiguous
/// (the peers may simply be behind), never rejects, and re-queues at once.
/// The transport answers empty only once every peer it asked lacked the
/// block.
///
/// A block the peer was not entitled to send in that shape — a QC over
/// another block, or a body elided that `inventory` never claimed — is
/// dropped and the peer rejected here, at the only point its answer can
/// still be scored. A body the inventory did claim and this host cannot
/// resolve is this host's miss, found after the verdict, and costs the
/// peer nothing.
///
/// A chain floor is the word of the one peer the transport asked last,
/// and the shard acts on it by rebuilding its store. `floor_ceiling` is
/// the highest floor an honest store can hold, so a floor above it is
/// no store's floor: it is dropped as a failed fetch and the peer
/// rejected.
fn block_sync_answer(
    height: BlockHeight,
    named: Option<BlockHash>,
    inventory: &Inventory,
    floor_ceiling: BlockHeight,
    result: Result<GetBlockResponse, RequestError>,
) -> (ShardScopedInput, ResponseVerdict) {
    match result {
        // A floor at or beneath the height says nothing about it, and
        // one above the ceiling is not a floor any honest store holds.
        Ok(GetBlockResponse::BelowFloor { floor }) if floor <= height || floor > floor_ceiling => (
            ShardScopedInput::BlockSyncFetchFailed {
                height,
                kind: FetchFailureKind::Transport,
            },
            ResponseVerdict::Reject,
        ),
        Ok(GetBlockResponse::BelowFloor { floor }) => (
            ShardScopedInput::BlockSyncBelowFloor { height, floor },
            ResponseVerdict::Accept,
        ),
        Ok(resp) => {
            let block = resp.into_elided();
            if let (Some(named), Some(served)) = (named, &block)
                && served.header().hash() != named
            {
                record_sync_block_filtered("block", "unnamed_block");
                return (
                    ShardScopedInput::BlockSyncFetchFailed {
                        height,
                        kind: FetchFailureKind::Transport,
                    },
                    ResponseVerdict::Reject,
                );
            }
            if let Some(served) = &block
                && let Err(reason) = served.screen(inventory)
            {
                record_sync_block_filtered("block", reason);
                return (
                    ShardScopedInput::BlockSyncFetchFailed {
                        height,
                        kind: FetchFailureKind::Transport,
                    },
                    ResponseVerdict::Reject,
                );
            }
            if named.is_some() && block.is_none() {
                return (
                    ShardScopedInput::BlockSyncFetchFailed {
                        height,
                        kind: FetchFailureKind::Transport,
                    },
                    ResponseVerdict::Accept,
                );
            }
            (
                ShardScopedInput::BlockSyncResponseReceived { height, block },
                ResponseVerdict::Accept,
            )
        }
        Err(err) => (
            ShardScopedInput::BlockSyncFetchFailed {
                height,
                kind: classify_fetch_error(&err),
            },
            ResponseVerdict::Accept,
        ),
    }
}

/// True for [`validate_synced_block`] failure reasons whose bytes can
/// originate in local rehydration caches (transaction store, finalized
/// tick store, provision store). A repeat from the same cache would
/// reject identically; force-full bypasses elision on the next attempt.
/// Header / QC identity mismatches (`height_mismatch`, `qc_hash_mismatch`,
/// `qc_height_mismatch`) inspect non-elidable fields and are excluded. A
/// body root mismatch counts: one root covers the elidable sections with
/// the inline ones, and a refetch without elision is what tells the two
/// apart.
fn cache_sensitive_validation_failure(reason: &str) -> bool {
    matches!(reason, "receipts_vs_ec_mismatch" | "body_root_mismatch")
}

/// Structural validation for a rehydrated synced block.
///
/// Confirms identity (height + QC binding) and that the body root the
/// block header commits to is reproducible from the body the requester now
/// holds.
///
/// Every section is rooted whatever the body carries, because an empty
/// list has a root of its own — `ZERO`, the empty-input compute — rather
/// than no root: a header claiming content the body does not carry is as
/// much a mismatch as the reverse. A section left out because its list
/// came back empty is a serving peer's licence to strip the body off an
/// otherwise genuine, QC-signed header. Nothing downstream would catch it:
/// a synced block is admitted on QC attestation and its state root is never
/// verified locally, so the stripped body reaches the inline JMT prep at
/// commit and diverges there, which is fatal to the node rather than fatal
/// to the response.
///
/// Provisions are read as hashes rather than bodies, since a `Sealed` block
/// drops the bodies and retains the list, and `Block::provision_hashes`
/// derives the `Live` list by hashing the same bodies the section root is
/// computed over. One expression therefore binds both variants.
///
/// The abandonment records and a sealed block's engagements are the body
/// lists no hash in the manifest binds — they ride inline rather than by
/// reference — so this is the only place a serving peer's copy is held to
/// the header the committee actually signed. A live block's engagements
/// are derived from its provision bodies, which the provisions section
/// binds.
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

    certified
        .block()
        .check_body_bound()
        .map_err(UnboundBody::label)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::{stub_abort_charge, test_transaction};
    use hyperscale_types::{
        AbandonmentRecord, AbandonmentRoot, AggregateSignature, Block, BlockHash, BlockHeader,
        BlockHeaderParts, BlockHeight, CertificateRoot, ChainOrigin, CommittedAt, ConsensusReceipt,
        Deadline, Engagement, EngagementRoot, ExecutionCertificate, ExecutionOutcome, Finalization,
        GlobalReceiptHash, GlobalReceiptRoot, Hash, LocalReceiptRoot, ProposerTimestamp,
        ProvisionHash, ProvisionsRoot, QuorumCertificate, Round, SectionRoots, SetRoot, ShardId,
        SignerBitfield, StateClaimsRoot, StoredReceipt, TickHalf, TickId, TransactionRoot, TxHash,
        TxOutcome, UnsettledTx, Verifiable, Verified, WeightedTimestamp, WitnessSources,
    };

    use super::*;

    const HEIGHT: BlockHeight = BlockHeight::new(1);

    /// A ceiling every floor these answers carry sits beneath.
    const CEILING: BlockHeight = BlockHeight::new(100);

    fn header() -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height: HEIGHT,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_000),
            provision_tx_roots: Capped::default(),
            ..Default::default()
        })
    }

    /// Rebuild a header committing `sections`.
    fn header_with(h: &BlockHeader, sections: SectionRoots) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            body_root: sections.root(),
            ..h.clone().into_parts()
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
    /// Returns the tick plus its local receipts and certificates section
    /// roots so the caller can construct a self-consistent
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
            Capped::from_array([outcome]),
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
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }
            } else {
                ConsensusReceipt::Failed
            }),
        };
        let fw = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([Arc::new(ec)]),
                Capped::from_array([receipt.clone()]),
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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

    /// [`header`] committing the abandonment section `root`.
    fn header_committing(root: AbandonmentRoot) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height: HEIGHT,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_000),
            provision_tx_roots: Capped::default(),
            body_root: SectionRoots {
                abandonment: root,
                ..SectionRoots::EMPTY
            }
            .root(),
            ..Default::default()
        })
    }

    /// A block's state claims are the one body list beside the records
    /// that a manifest holds by value, and every replica checks and
    /// folds them at commit; a serving peer that drops or forges them,
    /// proof included, hands back a block whose answers are not the
    /// chain's. The sealed form carries the same claims under the same
    /// root.
    #[test]
    fn validate_binds_state_claims_in_both_directions() {
        use hyperscale_types::{Anchor, Inclusion, MerkleInclusionProof, StateClaim, StateRoot};
        let bundles = vec![StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 0),
                height: BlockHeight::new(3),
                state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
                ts: WeightedTimestamp::from_millis(3_000),
            },
            [(stub_abort_charge(1).vault, Inclusion::Absent)],
            MerkleInclusionProof::new(b"proof".to_vec()),
        )];
        let root = Verified::<StateClaimsRoot>::compute(&bundles).into_inner();
        let live = |state_claims: Vec<StateClaim>| Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: HEIGHT,
                parent_block_hash: BlockHash::ZERO,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                timestamp: ProposerTimestamp::from_millis(1_000),
                provision_tx_roots: Capped::default(),
                body_root: SectionRoots {
                    state_claims: root,
                    ..SectionRoots::EMPTY
                }
                .root(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(
                Capped::new(state_claims).expect("a rebuilt block keeps the caps its source met"),
            ),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let dropped = live(Vec::new());
        let qc = qc_for(&dropped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(dropped, qc)).unwrap_err(),
            "body_root_mismatch"
        );

        let mut forged = bundles.clone();
        forged[0].proof = MerkleInclusionProof::new(b"other".to_vec());
        let forged = live(forged);
        let qc = qc_for(&forged);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(forged, qc)).unwrap_err(),
            "body_root_mismatch",
            "a proof altered in flight fails the root"
        );

        let carried = live(bundles);
        let qc = qc_for(&carried);
        let sealed = carried.clone().into_sealed();
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc.clone()))
                .is_ok(),
            "the claims the header commits are the ones it accepts"
        );
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(sealed, qc)).is_ok(),
            "and the sealed form recomputes the same root"
        );
    }

    fn boundary_record() -> AbandonmentRecord {
        AbandonmentRecord::new(
            ShardId::leaf(1, 0),
            WeightedTimestamp::from_millis(2_000),
            [UnsettledTx {
                tx_hash: TxHash::from(Hash::from_bytes(b"stranded")),
                deadline: Deadline::of(WeightedTimestamp::from_millis(1_500)),
                charged: 7,
                charge: stub_abort_charge(7),
                committed: CommittedAt {
                    height: BlockHeight::new(1),
                    anchor: WeightedTimestamp::from_millis(500),
                    committee_anchor: WeightedTimestamp::from_millis(500),
                },
                reach: Capped::empty(),
                escrowed: Capped::empty(),
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::from_array([boundary_record()])),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(
                Capped::new(abandonment_records)
                    .expect("a rebuilt block keeps the caps its source met"),
            ),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let dropped = live(Vec::new());
        let qc = qc_for(&dropped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(dropped, qc)).unwrap_err(),
            "body_root_mismatch"
        );

        let carried = live(records);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the records the header commits are the ones it accepts"
        );
    }

    #[test]
    fn validate_rejects_a_transactions_section_mismatch() {
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with(
            &header(),
            SectionRoots {
                transactions: TransactionRoot::ZERO,
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::from_array([tx])),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
        );
    }

    #[test]
    fn validate_passes_when_the_transactions_section_matches() {
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let h = header_with(
            &header(),
            SectionRoots {
                transactions: Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx))
                    .into_inner(),
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::from_array([tx])),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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
        let h = header_with(
            &header(),
            SectionRoots {
                transactions: Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx))
                    .into_inner(),
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
        );
    }

    /// And the same for the certificates, which carry the receipts the
    /// state root is computed over.
    #[test]
    fn validate_rejects_stripped_certificates() {
        let (_fw, lrr, cr) = make_tick(true);
        let h = header_with(
            &header(),
            SectionRoots {
                certificates: cr,
                local_receipts: lrr,
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
        );
    }

    /// A `Sealed` block drops the provision bodies and keeps their hashes,
    /// so the root binds against the retained list. Both directions: the
    /// hashes the header commits pass, a stripped list does not.
    #[test]
    fn validate_binds_the_provisions_section_on_a_sealed_block() {
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
                provision_tx_roots: Capped::default(),
                body_root: SectionRoots {
                    provisions: root,
                    ..SectionRoots::EMPTY
                }
                .root(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provision_hashes: Arc::new(
                Capped::new(provision_hashes)
                    .expect("a rebuilt block keeps the caps its source met"),
            ),
            engagements: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        let stripped = sealed(Vec::new());
        let qc = qc_for(&stripped);
        assert_eq!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(stripped, qc))
                .unwrap_err(),
            "body_root_mismatch"
        );

        let carried = sealed(hashes);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the batches the header commits are the ones it accepts"
        );
    }

    /// A `Sealed` block keeps the engagements its dropped bodies named,
    /// and no manifest hash binds that inline list: the header's root is
    /// the only thing holding a serving peer's copy to what the committee
    /// signed. A stripped or altered list fails; the committed one passes.
    #[test]
    fn a_synced_block_whose_list_misses_its_root_is_refused() {
        let entry = |seed: u8| Engagement {
            source: ShardId::leaf(1, 1),
            tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
            source_height: BlockHeight::new(3),
        };
        let committed = vec![entry(1), entry(2)];
        let root = EngagementRoot::over(&committed);
        let sealed = |engagements: Vec<Engagement>| Block::Sealed {
            header: BlockHeader::new(BlockHeaderParts {
                height: HEIGHT,
                parent_block_hash: BlockHash::ZERO,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                timestamp: ProposerTimestamp::from_millis(1_000),
                provision_tx_roots: Capped::default(),
                body_root: SectionRoots {
                    engagements: root,
                    ..SectionRoots::EMPTY
                }
                .root(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provision_hashes: Arc::new(Capped::empty()),
            engagements: Arc::new(Capped::new(engagements).expect("a list written out in a test")),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        for served in [Vec::new(), vec![entry(1)], vec![entry(1), entry(3)]] {
            let block = sealed(served);
            let qc = qc_for(&block);
            assert_eq!(
                validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(block, qc))
                    .unwrap_err(),
                "body_root_mismatch"
            );
        }

        let carried = sealed(committed);
        let qc = qc_for(&carried);
        assert!(
            validate_synced_block(HEIGHT, &CertifiedBlock::new_unchecked(carried, qc)).is_ok(),
            "the list the header commits is the one it accepts"
        );
    }

    #[test]
    fn validate_rejects_a_certificates_section_mismatch() {
        let (fw, lrr, _cr) = make_tick(true);
        let h = header_with(
            &header(),
            SectionRoots {
                certificates: CertificateRoot::from_raw(Hash::from_bytes(b"wrong")),
                local_receipts: lrr,
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::from_array([fw])),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
        );
    }

    #[test]
    fn validate_rejects_receipts_inconsistent_with_ec() {
        // Tick whose EC attests Success but whose receipt reports Failure.
        // `validate_against_certificates` catches this even when both
        // the certificates and local receipts sections are computed off the
        // (corrupted) body and would tautologically match.
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx_divergent"));
        let tick_id = TickId::new(ShardId::ROOT, HEIGHT);
        let ec = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )]),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        );
        let receipt = StoredReceipt {
            tx_hash,
            // ConsensusReceipt::Failed but EC said Succeeded — mismatch test.
            consensus: Arc::new(ConsensusReceipt::Failed),
        };
        let fw = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([Arc::new(ec)]),
                Capped::from_array([receipt.clone()]),
            )
            .into(),
        );
        let h = header_with(
            &header(),
            SectionRoots {
                certificates: Verified::<CertificateRoot>::compute(std::slice::from_ref(&fw))
                    .into_inner(),
                local_receipts: Verified::<LocalReceiptRoot>::compute(&[receipt]).into_inner(),
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::from_array([fw])),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
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
    fn validate_rejects_a_local_receipts_section_mismatch() {
        // Self-consistent tick (EC matches receipts), but the header's
        // local receipts section is wrong. Catches a peer that ships a
        // receipt body with `database_updates` content that doesn't
        // hash to the QC'd root.
        let (fw, _lrr, cr) = make_tick(true);
        let h = header_with(
            &header(),
            SectionRoots {
                certificates: cr,
                local_receipts: LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong")),
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::from_array([fw])),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert_eq!(
            validate_synced_block(HEIGHT, &certified).unwrap_err(),
            "body_root_mismatch"
        );
    }

    #[test]
    fn cache_sensitive_classification_matches_validate_synced_block_reasons() {
        // The classifier gates `mark_force_full_refetch` after a rehydrated
        // response fails `validate_synced_block`. A cache-sensitive reason
        // inspects bytes that can ride inside elidable bodies
        // (transactions, finalizations, provisions); a non-sensitive one
        // inspects a header / QC identity field no inventory can elide. If
        // a new failure reason is added to `validate_synced_block`, decide
        // which bucket it belongs in and add it here.
        for reason in ["receipts_vs_ec_mismatch", "body_root_mismatch"] {
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
        let (fw, lrr, cr) = make_tick(true);
        let h = header_with(
            &header(),
            SectionRoots {
                certificates: cr,
                local_receipts: lrr,
                ..SectionRoots::EMPTY
            },
        );
        let block = Block::Live {
            header: h,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::from_array([fw])),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        assert!(validate_synced_block(HEIGHT, &certified).is_ok());
    }

    /// A peer without the named block says so honestly: the peer is not
    /// marked, and the height backs off as a failed fetch rather than
    /// re-queueing at once, without counting as a not-found answer.
    #[test]
    fn a_named_fetch_answered_empty_backs_off() {
        let winner = BlockHash::from_raw(Hash::from_bytes(b"winner"));
        let (input, verdict) = block_sync_answer(
            HEIGHT,
            Some(winner),
            &Inventory::empty(),
            CEILING,
            Ok(GetBlockResponse::not_found()),
        );
        assert!(matches!(
            input,
            ShardScopedInput::BlockSyncFetchFailed {
                height,
                kind: FetchFailureKind::Transport,
            } if height == HEIGHT
        ));
        assert_eq!(verdict, ResponseVerdict::Accept);
    }

    /// A floor above the height reaches the shard as the floor it is,
    /// named fetch or not; a floor at or beneath the height is no answer
    /// about it, and the peer is marked.
    #[test]
    fn a_below_floor_answer_carries_its_floor_only_when_it_lies_above() {
        let winner = BlockHash::from_raw(Hash::from_bytes(b"winner"));
        let above = HEIGHT.next();
        for named in [None, Some(winner)] {
            let (input, verdict) = block_sync_answer(
                HEIGHT,
                named,
                &Inventory::empty(),
                CEILING,
                Ok(GetBlockResponse::below_floor(above)),
            );
            assert!(
                matches!(
                    input,
                    ShardScopedInput::BlockSyncBelowFloor { height, floor }
                        if height == HEIGHT && floor == above
                ),
                "named {named:?}: got {input:?}",
            );
            assert_eq!(verdict, ResponseVerdict::Accept);
        }
        let (input, verdict) = block_sync_answer(
            HEIGHT,
            None,
            &Inventory::empty(),
            CEILING,
            Ok(GetBlockResponse::below_floor(HEIGHT)),
        );
        assert!(matches!(
            input,
            ShardScopedInput::BlockSyncFetchFailed {
                kind: FetchFailureKind::Transport,
                ..
            }
        ));
        assert_eq!(verdict, ResponseVerdict::Reject);
    }

    /// A floor is one peer's word, and the shard rebuilds its store on
    /// it. One above the highest floor an honest store holds is dropped
    /// as a failed fetch and the peer marked, so it never reaches the
    /// re-seat; one at that ceiling, or beneath it and above the height,
    /// still does.
    #[test]
    fn a_floor_above_the_honest_ceiling_is_a_failed_fetch() {
        let ceiling = BlockHeight::new(HEIGHT.inner() + 5);
        let answer = |floor: BlockHeight| {
            block_sync_answer(
                HEIGHT,
                None,
                &Inventory::empty(),
                ceiling,
                Ok(GetBlockResponse::below_floor(floor)),
            )
        };

        for lie in [ceiling.next(), BlockHeight::new(u64::MAX)] {
            let (input, verdict) = answer(lie);
            assert!(
                matches!(
                    input,
                    ShardScopedInput::BlockSyncFetchFailed {
                        height,
                        kind: FetchFailureKind::Transport,
                    } if height == HEIGHT
                ),
                "floor {lie:?}: got {input:?}",
            );
            assert_eq!(verdict, ResponseVerdict::Reject);
        }

        for honest in [HEIGHT.next(), ceiling] {
            let (input, verdict) = answer(honest);
            assert!(
                matches!(
                    input,
                    ShardScopedInput::BlockSyncBelowFloor { height, floor }
                        if height == HEIGHT && floor == honest
                ),
                "floor {honest:?}: got {input:?}",
            );
            assert_eq!(verdict, ResponseVerdict::Accept);
        }
    }

    /// A peer answering a fetch that names the winner with the loser it
    /// also holds has not answered: the block is dropped before it
    /// reaches consensus, the height backs off, and the peer is marked.
    #[test]
    fn a_fetch_naming_a_block_drops_any_other() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let served = block.hash();
        let qc = qc_for(&block);
        let response = || {
            Ok(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                &block,
                qc.clone(),
                &Inventory::empty(),
            )))
        };
        let winner = BlockHash::from_raw(Hash::from_bytes(b"winner"));

        let (input, verdict) = block_sync_answer(
            HEIGHT,
            Some(winner),
            &Inventory::empty(),
            CEILING,
            response(),
        );
        assert!(matches!(
            input,
            ShardScopedInput::BlockSyncFetchFailed {
                height,
                kind: FetchFailureKind::Transport,
            } if height == HEIGHT
        ));
        assert_eq!(verdict, ResponseVerdict::Reject);

        for named in [Some(served), None] {
            let (input, verdict) =
                block_sync_answer(HEIGHT, named, &Inventory::empty(), CEILING, response());
            assert!(
                matches!(
                    &input,
                    ShardScopedInput::BlockSyncResponseReceived { block: Some(b), .. }
                        if b.header().hash() == served
                ),
                "named {named:?}: got {input:?}",
            );
            assert_eq!(verdict, ResponseVerdict::Accept);
        }

        let (input, verdict) = block_sync_answer(
            HEIGHT,
            None,
            &Inventory::empty(),
            CEILING,
            Ok(GetBlockResponse::not_found()),
        );
        assert!(matches!(
            input,
            ShardScopedInput::BlockSyncResponseReceived { block: None, .. }
        ));
        assert_eq!(verdict, ResponseVerdict::Accept);
    }

    /// A block whose QC certifies another block is the serving peer's
    /// fault, visible from the answer alone: it is dropped before it
    /// reaches the shard and the peer is marked.
    #[test]
    fn a_block_under_a_foreign_qc_is_rejected_at_the_boundary() {
        let block = Block::Live {
            header: header(),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = qc_for(&block);
        let foreign = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"another block")),
            qc.shard_id(),
            qc.height(),
            qc.parent_block_hash(),
            qc.round(),
            qc.signers().clone(),
            qc.aggregated_signature(),
            qc.weighted_timestamp(),
        );
        let response = Ok(GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &block,
            foreign,
            &Inventory::empty(),
        )));

        let (input, verdict) =
            block_sync_answer(HEIGHT, None, &Inventory::empty(), CEILING, response);
        assert!(matches!(
            input,
            ShardScopedInput::BlockSyncFetchFailed {
                height,
                kind: FetchFailureKind::Transport,
            } if height == HEIGHT
        ));
        assert_eq!(verdict, ResponseVerdict::Reject);
    }
}
