//! The beacon-block catch-up sync: the loop feeds its FSM and turns the
//! FSM's fetches into requests past the host.

use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{CertifiedBeaconBlock, Epoch, ValidatorId, Verifiable};
use tracing::warn;

use super::BeaconLoop;
use crate::beacon::{BeaconBlockSyncInput, BeaconBlockSyncOutput};
use crate::event::{BeaconScopedInput, FetchFailureKind, HostEvent, classify_fetch_error};
use crate::sync::SyncOutput;

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Begin (or extend) a catch-up sync toward `target`, fetching above
    /// the committed watermark.
    pub(super) fn start_sync(&mut self, target: Epoch) {
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::StartSync { scope: (), target });
        self.drive_sync(outputs);
    }

    /// A beacon-block sync response landed, for the epoch it was asked
    /// for: the response boundary drops a block naming any other. `None`
    /// (the peer does not hold the epoch) re-queues through the failure
    /// path. Otherwise the block
    /// goes to the fold and the FSM learns the epoch's bytes arrived.
    ///
    /// `FetchSucceeded` means "the bytes arrived", not "the block is
    /// valid": the fold verifies against the committee it owns. The FSM
    /// parks the epoch in `pending_admission`; a valid block commits and
    /// feeds `Admitted`, while one that fails verification is never
    /// admitted, so the FSM re-fetches it from another peer after
    /// `PENDING_ADMISSION_TIMEOUT` rather than this path duplicating
    /// committee-aware verification.
    pub(super) fn on_sync_response(
        &mut self,
        epoch: Epoch,
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    ) {
        let Some(block) = block else {
            // Back off rather than re-queue immediately: the sync target
            // comes from an unverified gossip block, so a bogus far-future
            // epoch would otherwise busy-loop the network fetching an epoch
            // nobody has produced.
            self.on_sync_fetch_failed(epoch, FetchFailureKind::NotFound);
            return;
        };
        let actions = self.fold.on_beacon_block_received(block);
        self.run_fold_actions(actions);
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::FetchSucceeded {
                scope: (),
                from: epoch,
                count: 1,
                delivered_heights: vec![epoch],
                now: self.now,
            });
        self.drive_sync(outputs);
    }

    /// Re-queue an epoch through `FetchFailed`, under the FSM's deferral
    /// for `kind`.
    pub(super) fn on_sync_fetch_failed(&mut self, epoch: Epoch, kind: FetchFailureKind) {
        let outputs = self.beacon_block.handle(BeaconBlockSyncInput::FetchFailed {
            scope: (),
            from: epoch,
            count: 1,
            kind,
            now: self.now,
        });
        self.drive_sync(outputs);
    }

    /// Advance the FSM's committed watermark to `epoch` on a beacon commit
    /// (gossip or sync), so a serial catch-up unblocks the next epoch's
    /// fetch.
    pub(super) fn on_sync_admitted(&mut self, epoch: Epoch) {
        let outputs = self.beacon_block.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: epoch,
        });
        self.drive_sync(outputs);
    }

    /// Re-dispatch any deferred fetch whose backoff has expired.
    pub(super) fn on_sync_tick(&mut self) {
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::Tick { now: self.now });
        self.drive_sync(outputs);
    }

    /// Turn the FSM's scheduling outputs into network fetches. A fetch no
    /// live shard can answer goes back to the FSM as `NoPeers`, so its
    /// slot frees and the backoff retries it on a later tick. The beacon
    /// has no sync mode to exit (each adopted block already re-arms the
    /// participants' timers), so completion is informational.
    fn drive_sync(&mut self, outputs: Vec<BeaconBlockSyncOutput>) {
        for output in outputs {
            match output {
                SyncOutput::Fetch { from, .. } => {
                    if !self.dispatch_sync_fetch(from) {
                        self.on_sync_fetch_failed(from, FetchFailureKind::NoPeers);
                    }
                }
                SyncOutput::Complete { height, .. } => {
                    tracing::info!(epoch = height.inner(), "Beacon block sync complete");
                }
            }
        }
    }

    /// Ask past the host for `epoch`: its own beacon store is filled by
    /// the same commits the sync is waiting on. Whether a live shard with
    /// a committee took the ask. The leaf asked moves with every ask,
    /// spread by the host's lowest identity and [`Self::sync_spread`].
    fn dispatch_sync_fetch(&mut self, epoch: Epoch) -> bool {
        let lowest = self.validators().next().map_or(0, ValidatorId::inner);
        self.sync_spread = self.sync_spread.wrapping_add(1);
        let Some(shard) = self.fetch_shard(lowest.wrapping_add(self.sync_spread)) else {
            warn!("BeaconLoop: no live shard to fetch beacon blocks from; deferring");
            return false;
        };
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process.network.request_from(
            shard,
            Answerers::PeersOnly,
            None,
            GetBeaconBlockRequest::new(epoch),
            None,
            Box::new(
                move |result: Result<GetBeaconBlockResponse, RequestError>| {
                    let (input, verdict) = match result {
                        // A block for another epoch is no answer for this
                        // one, and only a peer making it up gives it.
                        Ok(resp) if resp.block.as_ref().is_some_and(|b| b.epoch() != epoch) => {
                            warn!(
                                epoch = epoch.inner(),
                                "beacon sync answer names another epoch — dropping"
                            );
                            (
                                BeaconScopedInput::BeaconBlockSyncFetchFailed {
                                    epoch,
                                    kind: FetchFailureKind::NotFound,
                                },
                                ResponseVerdict::Reject,
                            )
                        }
                        // "Peer doesn't have this epoch" is ambiguous (it
                        // may be behind us) — never Reject.
                        Ok(resp) => (
                            BeaconScopedInput::BeaconBlockSyncResponseReceived {
                                epoch,
                                block: resp.block,
                            },
                            ResponseVerdict::Accept,
                        ),
                        Err(err) => (
                            BeaconScopedInput::BeaconBlockSyncFetchFailed {
                                epoch,
                                kind: classify_fetch_error(&err),
                            },
                            ResponseVerdict::Accept,
                        ),
                    };
                    let _ = beacon_tx.send(HostEvent::Beacon(input));
                    verdict
                },
            ),
        );
        true
    }
}
