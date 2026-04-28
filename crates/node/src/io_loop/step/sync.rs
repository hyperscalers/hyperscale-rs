//! Sync-protocol step handlers.
//!
//! The block-sync protocol's I/O glue: rehydrate elided block responses
//! against local caches, fall back to a top-up request on a partial miss,
//! and recursively retry from scratch on residual failure.
//!
//! Four `step()` arms route here:
//! - `SyncBlockResponseReceived` — first-pass rehydration of the elided block;
//! - `SyncBlockFetchFailed` — drop topup state, signal failure to the sync FSM;
//! - `SyncBlockTopUpReceived` — second-pass rehydration with topup bodies;
//! - `SyncBlockTopUpFailed` — drop topup state, retry from scratch.
//!
//! The sync FSM (`super::super::protocol::sync::SyncProtocol`) is owned by
//! `ProtocolHost`. This module bridges its outputs to the network and
//! threads `NodeInput::SyncBlock*` callbacks back through the event sender.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::sync::{SyncInput, SyncOutput};
use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_messages::request::Inventory;
use hyperscale_messages::response::{ElidedCertifiedBlock, GetBlockTopUpResponse, RehydrationMiss};
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
    // ─── step() handlers ────────────────────────────────────────────────

    /// Handle a sync block response: rehydrate the elided block against
    /// local caches; on a miss, buffer it and fire a top-up request.
    pub(in crate::io_loop) fn handle_sync_block_response_received(
        &mut self,
        height: BlockHeight,
        block: Option<Box<ElidedCertifiedBlock>>,
    ) {
        let Some(elided) = block else {
            // Peer didn't have the block — pass `None` through to the sync
            // state machine, which re-queues the height.
            self.deliver_sync_block(height, None);
            return;
        };
        match self.rehydrate_elided_block(&elided) {
            Ok(cert) => self.deliver_sync_block(height, Some(Box::new(cert))),
            Err(miss) => {
                // Inventory bloom said we had bodies we couldn't resolve.
                // Buffer the elided block, fire a top-up for just the
                // missing hashes. If the topup response covers the miss we
                // rehydrate and proceed normally; if it fails, the buffered
                // state is dropped and we refetch from scratch via the
                // existing retry path.
                metrics::record_sync_response_error("rehydration_miss");
                self.issue_sync_topup(height, elided, miss);
            }
        }
    }

    /// Handle a sync block fetch failure: evict any buffered topup state
    /// for this height (the outer fetch is being re-attempted) and signal
    /// the sync state machine.
    pub(in crate::io_loop) fn handle_sync_block_fetch_failed(&mut self, height: BlockHeight) {
        self.protocols.pending_block_topups.remove(&height);
        let outputs = self.protocols.sync.handle(SyncInput::BlockFetchFailed {
            height,
            now: std::time::Instant::now(),
        });
        self.process_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    /// Handle a sync top-up response: second-pass rehydrate the buffered
    /// elided block with the topup bodies.
    pub(in crate::io_loop) fn handle_sync_block_topup_received(
        &mut self,
        height: BlockHeight,
        response: Option<Box<GetBlockTopUpResponse>>,
    ) {
        let Some(elided) = self.protocols.pending_block_topups.remove(&height) else {
            // Topup arrived after the pending state was already evicted
            // (e.g. the outer fetch was retried and delivered first).
            // Silently drop.
            return;
        };
        let topup = response.map_or_else(GetBlockTopUpResponse::empty, |b| *b);
        match self.rehydrate_with_topup(&elided, topup) {
            Ok(cert) => self.deliver_sync_block(height, Some(Box::new(cert))),
            Err(miss) => {
                tracing::warn!(
                    height = height.0,
                    missing_total = miss.total(),
                    "Sync: topup still short of bodies, refetching block"
                );
                metrics::record_sync_response_error("topup_short");
                let _ = self
                    .event_sender
                    .send(NodeInput::SyncBlockFetchFailed { height });
            }
        }
    }

    /// Handle a sync top-up fetch failure: drop the buffered state and
    /// schedule a fresh fetch.
    pub(in crate::io_loop) fn handle_sync_block_topup_failed(&mut self, height: BlockHeight) {
        self.protocols.pending_block_topups.remove(&height);
        tracing::warn!(
            height = height.0,
            "Sync: topup request failed, refetching block"
        );
        metrics::record_sync_response_error("topup_failed");
        let _ = self
            .event_sender
            .send(NodeInput::SyncBlockFetchFailed { height });
    }

    // ─── Sync output processing + helpers ───────────────────────────────

    /// Process `SyncProtocol` outputs internally.
    ///
    /// `DeliverBlock` and `SyncComplete` are fed directly to the state
    /// machine (no round-trip through the runner). `FetchBlock` uses the
    /// `Network` trait.
    pub(in crate::io_loop) fn process_sync_outputs(&mut self, outputs: Vec<SyncOutput>) {
        // Snapshot the sync inventory once per batch so every FetchBlock in
        // this tick shares a consistent view of mempool / cert-cache /
        // provision-store membership. Built lazily: skipped entirely if
        // the batch contains no FetchBlock outputs.
        let mut inventory_cache: Option<Inventory> = None;
        for output in outputs {
            match output {
                SyncOutput::FetchBlock {
                    height,
                    target_height,
                } => {
                    use hyperscale_messages::request::GetBlockRequest;
                    let inventory = inventory_cache
                        .get_or_insert_with(|| self.build_sync_inventory())
                        .clone();
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
                                    let _ = es.send(NodeInput::SyncBlockResponseReceived {
                                        height,
                                        block,
                                    });
                                }
                                Err(_) => {
                                    let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                                }
                            }
                            // Sync's "peer doesn't have this height" is
                            // ambiguous (peer may simply be behind us) —
                            // never Reject.
                            ResponseVerdict::Accept
                        }),
                    );
                }
                SyncOutput::DeliverBlock { certified } => {
                    metrics::record_sync_block_received_by_bft();
                    metrics::record_sync_block_submitted_for_verification();
                    self.feed_event(ProtocolEvent::SyncBlockReadyToApply {
                        certified: *certified,
                    });
                }
                SyncOutput::SyncComplete { height } => {
                    tracing::info!(
                        height = height.0,
                        "Sync protocol complete, resuming consensus"
                    );
                    // Tell BftCoordinator to exit sync mode. The previous
                    // BlockPersisted → on_block_persisted path was unreliable
                    // because BlockPersisted requires PreparedCommit which
                    // may not be available yet for synced blocks.
                    self.feed_event(ProtocolEvent::SyncProtocolComplete { height });
                }
            }
        }
    }

    /// Snapshot local mempool / finalized-wave cache / provision store
    /// into an [`Inventory`] so sync requests can tell the responder which
    /// bodies to elide.
    ///
    /// Each category degrades independently to `None` when the cached set
    /// exceeds the filter size cap — the responder treats absence as
    /// "send everything for this category."
    fn build_sync_inventory(&self) -> Inventory {
        Inventory {
            tx_have: self.state.mempool().tx_bloom_snapshot(),
            cert_have: self.state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock` by
    /// resolving any omitted body against local caches. On miss returns
    /// the list of hashes the lookups couldn't resolve — the caller uses
    /// that list to issue a top-up request and retry.
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

    /// Second-pass rehydration after a `GetBlockTopUpResponse` arrives:
    /// augment local-cache lookups with the topup bodies so hashes that
    /// missed the first pass can be resolved. On any residual miss the
    /// block is dropped — the sync retry machinery refetches from scratch
    /// (losing the inventory win for this block but making forward progress).
    fn rehydrate_with_topup(
        &self,
        elided: &ElidedCertifiedBlock,
        topup: GetBlockTopUpResponse,
    ) -> Result<CertifiedBlock, RehydrationMiss> {
        use std::collections::HashMap;

        let mut topup_tx: HashMap<_, _> = topup.transactions.into_iter().collect();
        let mut topup_cert: HashMap<_, _> = topup.certificates.into_iter().collect();
        let mut topup_prov: HashMap<_, _> = topup.provisions.into_iter().collect();
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| topup_tx.remove(h).or_else(|| mempool.get_transaction(h)),
            |h| {
                topup_cert
                    .remove(h)
                    .or_else(|| execution.get_finalized_wave_by_hash(h))
            },
            |h| topup_prov.remove(h).or_else(|| provision_store.get(h)),
        )
    }

    /// Fire off a `GetBlockTopUpRequest` targeting `miss`, stashing
    /// `elided` for rehydration when the response arrives. The closure
    /// translates the network callback into `NodeInput::SyncBlockTopUpReceived`
    /// / `SyncBlockTopUpFailed` so the state handler does the actual
    /// rehydration on the main thread.
    fn issue_sync_topup(
        &mut self,
        height: BlockHeight,
        elided: Box<ElidedCertifiedBlock>,
        miss: RehydrationMiss,
    ) {
        use hyperscale_messages::request::GetBlockTopUpRequest;

        self.protocols.pending_block_topups.insert(height, elided);

        let req = GetBlockTopUpRequest::new(
            height,
            miss.missing_tx,
            miss.missing_cert,
            miss.missing_provision,
        );
        let es = self.event_sender.clone();
        let peers = self.local_peers();
        self.network.request(
            &peers,
            None,
            req,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let _ = es.send(NodeInput::SyncBlockTopUpReceived {
                        height,
                        response: Some(Box::new(resp)),
                    });
                } else {
                    let _ = es.send(NodeInput::SyncBlockTopUpFailed { height });
                }
                ResponseVerdict::Accept
            }),
        );
    }

    /// Run the post-rehydration sync pipeline: certificate-root check,
    /// then feed the block into the sync state machine (or pass through
    /// `None` for not-found). Shared between the main-response path and
    /// the top-up completion path.
    fn deliver_sync_block(&mut self, height: BlockHeight, block: Option<Box<CertifiedBlock>>) {
        let certificate_root_valid = match block.as_deref() {
            Some(fetched) if !fetched.block.certificates().is_empty() => {
                let computed =
                    hyperscale_types::compute_certificate_root(fetched.block.certificates());
                let matches = computed == fetched.block.header().certificate_root;
                if !matches {
                    tracing::warn!(
                        height = height.0,
                        ?computed,
                        expected = ?fetched.block.header().certificate_root,
                        "Sync: certificate_root mismatch — rejecting response"
                    );
                }
                matches
            }
            _ => true, // Empty block or no block — no root to check
        };

        if certificate_root_valid {
            let outputs = self
                .protocols
                .sync
                .handle(SyncInput::BlockResponseReceived {
                    height,
                    block,
                    now: std::time::Instant::now(),
                });
            self.process_sync_outputs(outputs);
        } else {
            let _ = self
                .event_sender
                .send(NodeInput::SyncBlockFetchFailed { height });
        }
    }
}
