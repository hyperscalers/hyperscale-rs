//! Block-sync I/O glue.
//!
//! Bridges `Sync<BlockSyncBinding>`'s scheduling decisions to the network
//! and BFT. This is where payload-specific concerns live:
//!
//! - building `GetBlockRequest`s with the right inventory bloom + force-full
//!   override
//! - rehydrating elided responses against local caches
//! - validating block / QC shape (height match, QC hash match, QC height
//!   match, certificate-root match)
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
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_messages::request::Inventory;
use hyperscale_messages::response::{ElidedCertifiedBlock, RehydrationMiss};
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
    /// local caches; on a miss, mark the height for a full refetch and
    /// signal the FSM to re-queue.
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
            Err(_miss) => {
                // Inventory bloom said we had bodies we couldn't resolve.
                // Mark for full refetch and re-queue.
                metrics::record_sync_response_error("rehydration_miss");
                self.protocols.block_sync.mark_force_full_refetch(height);
                self.feed_block_sync_fetch_failed(height);
                return;
            }
        };
        self.deliver_sync_block(height, cert);
    }

    /// Handle a sync block fetch failure (network error / not-found).
    pub(in crate::io_loop) fn handle_block_sync_fetch_failed(&mut self, height: BlockHeight) {
        metrics::record_sync_response_error("fetch_failed");
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
        self.network.request(
            &peers,
            None,
            GetBlockRequest::new(height, target_height).with_inventory(inventory),
            Box::new(move |result| {
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
            tx_have: self.state.mempool().tx_bloom_snapshot(),
            cert_have: self.state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock`.
    fn rehydrate_elided_block(
        &self,
        elided: &ElidedCertifiedBlock,
    ) -> Result<CertifiedBlock, RehydrationMiss> {
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| mempool.get_transaction(h),
            |h| execution.get_finalized_wave_by_hash(h),
            |h| provision_store.get(h),
        )
    }

    /// Validate a rehydrated block and either deliver it to BFT or
    /// re-queue via fetch-failed.
    fn deliver_sync_block(&mut self, height: BlockHeight, certified: CertifiedBlock) {
        // ── Shape validation that used to live in the FSM ──
        if certified.block.height() != height {
            tracing::warn!(
                expected = height.0,
                got = certified.block.height().0,
                "Height mismatch in sync response"
            );
            metrics::record_sync_block_filtered("height_mismatch");
            self.feed_block_sync_fetch_failed(height);
            return;
        }
        let block_hash = certified.block.hash();
        if certified.qc.block_hash != block_hash {
            tracing::warn!(height = height.0, "QC block hash mismatch in sync response");
            metrics::record_sync_block_filtered("qc_hash_mismatch");
            self.feed_block_sync_fetch_failed(height);
            return;
        }
        if certified.qc.height != height {
            tracing::warn!(height = height.0, "QC height mismatch in sync response");
            metrics::record_sync_block_filtered("qc_height_mismatch");
            self.feed_block_sync_fetch_failed(height);
            return;
        }
        // Certificate-root match (only needed when block carries certs).
        if !certified.block.certificates().is_empty() {
            let computed =
                hyperscale_types::compute_certificate_root(certified.block.certificates());
            if computed != certified.block.header().certificate_root {
                tracing::warn!(
                    height = height.0,
                    ?computed,
                    expected = ?certified.block.header().certificate_root,
                    "Sync: certificate_root mismatch — rejecting response"
                );
                self.feed_block_sync_fetch_failed(height);
                return;
            }
        }

        metrics::record_sync_block_downloaded();
        metrics::record_sync_block_verified();
        metrics::record_sync_block_received_by_bft();
        metrics::record_sync_block_submitted_for_verification();

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
