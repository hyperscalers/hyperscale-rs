//! Sync and fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::io_loop::protocol::binding::FetchBinding;
use crate::io_loop::protocol::sync::{SyncInput, SyncOutput};
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::Storage;
use std::time::Duration;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Process `SyncProtocol` outputs internally.
    ///
    /// `DeliverBlock` and `SyncComplete` are fed directly to the state machine
    /// (no round-trip through the runner). `FetchBlock` uses the `Network` trait.
    pub(super) fn process_sync_outputs(&mut self, outputs: Vec<SyncOutput>) {
        // Snapshot the sync inventory once per batch so every FetchBlock in
        // this tick shares a consistent view of mempool / cert-cache /
        // provision-store membership. Built lazily: if the batch contains
        // no FetchBlock outputs the snapshot is skipped entirely.
        let mut inventory_cache: Option<hyperscale_messages::request::Inventory> = None;
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
                            // Sync's "peer doesn't have this height" is ambiguous
                            // (peer may simply be behind us) — never Reject.
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
    /// into an [`Inventory`](hyperscale_messages::request::Inventory) so
    /// sync requests can tell the responder which bodies to elide.
    ///
    /// Each category degrades independently to `None` when the cached set
    /// exceeds the filter size cap — the responder treats absence as
    /// "send everything for this category."
    fn build_sync_inventory(&self) -> hyperscale_messages::request::Inventory {
        hyperscale_messages::request::Inventory {
            tx_have: self.state.mempool().tx_bloom_snapshot(),
            cert_have: self.state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock` by
    /// resolving any omitted body against local caches. On miss returns
    /// the list of hashes the lookups couldn't resolve — the caller uses
    /// that list to issue a [`GetBlockTopUpRequest`] and retry.
    pub(super) fn rehydrate_elided_block(
        &self,
        elided: &hyperscale_messages::response::ElidedCertifiedBlock,
    ) -> Result<hyperscale_types::CertifiedBlock, hyperscale_messages::response::RehydrationMiss>
    {
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| mempool.get_transaction(h),
            |h| execution.get_finalized_wave_by_hash(h),
            |h| provision_store.get(h),
        )
    }

    /// Second-pass rehydration after a [`GetBlockTopUpResponse`] arrives:
    /// augment the local-cache lookups with the topup bodies so hashes
    /// that missed the first pass can be resolved. On any residual miss
    /// the block is dropped — the sync retry machinery refetches it from
    /// scratch (losing the inventory win for this block but making
    /// forward progress).
    pub(super) fn rehydrate_with_topup(
        &self,
        elided: &hyperscale_messages::response::ElidedCertifiedBlock,
        topup: hyperscale_messages::response::GetBlockTopUpResponse,
    ) -> Result<hyperscale_types::CertifiedBlock, hyperscale_messages::response::RehydrationMiss>
    {
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

    /// Fire off a [`GetBlockTopUpRequest`] targeting `miss`, stashing
    /// `elided` for rehydration when the response arrives. The closure
    /// translates the network callback into
    /// [`NodeInput::SyncBlockTopUpReceived`] / [`SyncBlockTopUpFailed`]
    /// so the state handler does the actual rehydration on the main
    /// thread.
    pub(super) fn issue_sync_topup(
        &mut self,
        height: hyperscale_types::BlockHeight,
        elided: Box<hyperscale_messages::response::ElidedCertifiedBlock>,
        miss: hyperscale_messages::response::RehydrationMiss,
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
    pub(super) fn deliver_sync_block(
        &mut self,
        height: hyperscale_types::BlockHeight,
        block: Option<Box<hyperscale_types::CertifiedBlock>>,
    ) {
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

    /// Dispatch outputs from any [`FetchBinding`]'s state machine: emit one
    /// network request per chunk (or per id, for `PER_ID` bindings) and
    /// route the response through the binding's callback.
    pub(super) fn process_fetch_outputs<B: FetchBinding>(
        &self,
        outputs: Vec<crate::io_loop::protocol::fetch::FetchOutput<B::Id>>,
    ) {
        use crate::io_loop::protocol::fetch::FetchOutput;

        for FetchOutput::Send { ids, peers } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(
                        vec![id],
                        &peers,
                        self.local_shard,
                        &*self.network,
                        &self.event_sender,
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    &peers,
                    self.local_shard,
                    &*self.network,
                    &self.event_sender,
                );
            }
        }
    }

    /// Drive a single fetch binding: feed a `Request`, drain the resulting
    /// `Tick` outputs through `process_fetch_outputs`. Used by both the
    /// `Action::Fetch` arms and the `*FetchFailed` step arms.
    pub(super) fn drive_fetch<B: FetchBinding>(
        &mut self,
        input: crate::io_loop::protocol::fetch::FetchInput<B::Id>,
    ) {
        use crate::io_loop::protocol::fetch::FetchInput;
        if let FetchInput::Request { ids, peers } = &input {
            tracing::trace!(
                binding = B::NAME,
                ids = ids.len(),
                peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                "Dispatching fetch request"
            );
        }
        let outputs = {
            let fetch = B::fetch_mut(&mut self.protocols);
            fetch.handle(input);
            fetch.handle(FetchInput::Tick)
        };
        self.process_fetch_outputs::<B>(outputs);
    }

    pub(super) fn update_fetch_tick_timer(&mut self) {
        let op = if self.protocols.has_any_pending() {
            TimerOp::Set {
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            }
        } else {
            TimerOp::Cancel {
                id: TimerId::FetchTick,
            }
        };
        self.pending_timer_ops.push(op);
    }
}
