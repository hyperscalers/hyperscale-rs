//! Beacon-block-sync I/O glue.
//!
//! Bridges `Sync<BeaconBlockSyncBinding>`'s serial scheduling to the
//! network and the beacon coordinator. Far thinner than shard
//! `block_sync`: a `CertifiedBeaconBlock` is self-contained, so there's
//! no inventory bloom, no rehydration, and no off-thread structural
//! validation — the block is delivered straight to the coordinator,
//! which runs the same cert verification + adoption as a gossiped block.
//!
//! The generic is keyed by [`BlockHeight`]; the beacon chain's key is
//! [`Epoch`]. They convert 1:1 (`u64` newtypes, one block per epoch) at
//! this boundary.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{BlockHeight, CertifiedBeaconBlock, Epoch, Verifiable};

use crate::shard_io::sync::SyncOutput;
use crate::shard_io::sync::beacon_block::{BeaconBlockSyncInput, BeaconBlockSyncOutput};
use crate::shard_loop::step::block_sync::classify_fetch_error;
use crate::shard_loop::{FetchFailureKind, ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Handle `Action::StartBeaconBlockSync`: feed the FSM and dispatch
    /// any fetch it emits.
    pub(in crate::shard_loop) fn process_start_beacon_block_sync(&mut self, target: Epoch) {
        // Seed the FSM's committed watermark to the local beacon tip
        // before the first fetch. `Admitted` creates and seeds the scope
        // even ahead of `StartSync`, so a serial (`window_size = 1`) sync
        // starts from `tip + 1` rather than `genesis + 1`. This is
        // idempotent with the `Admitted`-on-commit stream and only
        // load-bearing right after a restart, when this session hasn't
        // committed anything yet — without it the window would pin at
        // `genesis + 1`, a block the coordinator drops as past-tip and
        // never admits, so `committed` never advances and sync wedges.
        if let Some(tip) = self.process.beacon_storage.latest_committed_epoch() {
            let _ = self
                .io
                .syncs
                .beacon_block
                .handle(BeaconBlockSyncInput::Admitted {
                    scope: (),
                    height: BlockHeight::new(tip.inner()),
                });
        }
        let outputs = self
            .io
            .syncs
            .beacon_block
            .handle(BeaconBlockSyncInput::StartSync {
                scope: (),
                target: BlockHeight::new(target.inner()),
            });
        self.process_beacon_block_sync_outputs(outputs);
    }

    /// A beacon-block sync response landed. `None` (peer didn't have the
    /// epoch) re-queues via fetch-failed. Otherwise deliver the block to
    /// the beacon coordinator and tell the FSM the epoch was delivered;
    /// the FSM holds it in `pending_admission` until the block commits,
    /// which feeds `Admitted` from the commit action handler.
    pub(in crate::shard_loop) fn handle_beacon_block_sync_response_received(
        &mut self,
        epoch: Epoch,
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    ) {
        let Some(block) = block else {
            // Treat a missing block as exhausted so the FSM re-queues
            // without piling its own backoff on the request manager's.
            self.feed_beacon_block_sync_fetch_failed(epoch, FetchFailureKind::Exhausted);
            return;
        };
        self.dispatch_event(ProtocolEvent::BeaconBlockSyncReadyToApply { block });
        let height = BlockHeight::new(epoch.inner());
        let outputs = self
            .io
            .syncs
            .beacon_block
            .handle(BeaconBlockSyncInput::FetchSucceeded {
                scope: (),
                from: height,
                count: 1,
                delivered_heights: vec![height],
                now: std::time::Instant::now(),
            });
        self.process_beacon_block_sync_outputs(outputs);
    }

    /// A beacon-block sync fetch failed at the transport layer.
    pub(in crate::shard_loop) fn handle_beacon_block_sync_fetch_failed(
        &mut self,
        epoch: Epoch,
        kind: FetchFailureKind,
    ) {
        self.feed_beacon_block_sync_fetch_failed(epoch, kind);
    }

    /// Process FSM outputs: `Fetch` → network request; `Complete` → log.
    /// Beacon has no "sync mode" to exit — each adopted block already
    /// re-arms the coordinator's timers — so completion is informational.
    pub(in crate::shard_loop) fn process_beacon_block_sync_outputs(
        &self,
        outputs: Vec<BeaconBlockSyncOutput>,
    ) {
        for output in outputs {
            match output {
                SyncOutput::Fetch { from, .. } => {
                    self.dispatch_beacon_block_sync_fetch(Epoch::new(from.inner()));
                }
                SyncOutput::Complete { height, .. } => {
                    tracing::info!(epoch = height.inner(), "Beacon block sync complete");
                }
            }
        }
    }

    /// Dispatch a single-epoch beacon block fetch. The callback pushes
    /// the response (or failure) back as a `ShardScopedInput`.
    fn dispatch_beacon_block_sync_fetch(&self, epoch: Epoch) {
        let es = self.event_sender().clone();
        let local_shard = self.shard;
        self.process.network.request(
            self.shard,
            None,
            GetBeaconBlockRequest::new(epoch),
            None,
            Box::new(
                move |result: Result<GetBeaconBlockResponse, RequestError>| {
                    match result {
                        Ok(resp) => push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BeaconBlockSyncResponseReceived {
                                epoch,
                                block: resp.block,
                            },
                        ),
                        Err(err) => push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BeaconBlockSyncFetchFailed {
                                epoch,
                                kind: classify_fetch_error(&err),
                            },
                        ),
                    }
                    // "Peer doesn't have this epoch" is ambiguous (the peer
                    // may simply be behind us) — never Reject.
                    ResponseVerdict::Accept
                },
            ),
        );
    }

    /// Re-queue an epoch via `FetchFailed`.
    fn feed_beacon_block_sync_fetch_failed(&mut self, epoch: Epoch, kind: FetchFailureKind) {
        let outputs = self
            .io
            .syncs
            .beacon_block
            .handle(BeaconBlockSyncInput::FetchFailed {
                scope: (),
                from: BlockHeight::new(epoch.inner()),
                count: 1,
                kind,
                now: std::time::Instant::now(),
            });
        self.process_beacon_block_sync_outputs(outputs);
    }
}
