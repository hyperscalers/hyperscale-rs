//! Beacon-block catch-up sync: the binding, its serial config, and the
//! loop glue that feeds the FSM and turns its fetches into requests past
//! the host.
//!
//! The beacon chain is host-global — one chain per host, `Scope = ()` —
//! and the host's [`BeaconLoop`](crate::beacon::BeaconLoop) drives
//! the FSM, delivering synced blocks to its fold and routing the fetches.
//!
//! The sync is strictly serial: the config sets
//! `window_size = 1`, so the generic queues only `committed + 1` and
//! advances `committed` on `Admitted` (fed from the beacon commit) — the
//! next epoch isn't fetched until the current one commits. That matches the
//! fold's `epoch == tip + 1` adoption guard, so no consumer-side ordering
//! buffer is needed. The binding sets `Key = Epoch`, so the generic
//! schedules over epochs directly.

use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{CertifiedBeaconBlock, Epoch, ValidatorId, Verifiable};
use tracing::warn;

use super::BeaconLoop;
use crate::event::{BeaconScopedInput, FetchFailureKind, HostEvent, classify_fetch_error};
use crate::sync::{Sync, SyncBinding, SyncConfig, SyncInput, SyncOutput};

/// Marker type implementing [`SyncBinding`] for beacon-block-sync.
pub struct BeaconBlockSyncBinding;

/// Type alias: beacon-block-sync is `Sync<BeaconBlockSyncBinding>`.
pub type BeaconBlockSync = Sync<BeaconBlockSyncBinding>;

/// Type alias for beacon-block-sync inputs.
pub type BeaconBlockSyncInput = SyncInput<BeaconBlockSyncBinding>;

/// Type alias for beacon-block-sync outputs.
pub type BeaconBlockSyncOutput = SyncOutput<BeaconBlockSyncBinding>;

impl SyncBinding for BeaconBlockSyncBinding {
    type Scope = ();
    type Key = Epoch;
    type State = ();
    const NAME: &'static str = "beacon_block_sync";
}

/// Serial, admission-gated config: one epoch fetched at a time, the next
/// gated on the prior committing.
///
/// `window_size = 1` is load-bearing, not a tuning knob: it's what makes
/// the fold's delivery handler able to reuse the gossip
/// verify+adopt path unchanged. Delivery stays in order, so every synced
/// block arrives at `epoch == tip + 1` and clears the `adopt_block`
/// regression guard. Widening the window would let blocks arrive out of
/// order — the fold would drop the early ones as past/future-tip
/// — so it can't be raised without first giving the fold a
/// reorder buffer.
const fn beacon_block_sync_config() -> SyncConfig {
    SyncConfig {
        max_per_request: 1,
        window_size: 1,
        max_concurrent_per_scope: 1,
    }
}

/// The sync FSM for a fold resumed at `tip`, its committed watermark
/// seeded there.
///
/// A fresh FSM's watermark sits at genesis, so without the seed the
/// first sync after a restart would fetch `genesis + 1`, a block the fold
/// drops as past its tip and never admits, and the serial window would
/// wedge there.
#[must_use]
pub fn resumed_at(tip: Epoch) -> BeaconBlockSync {
    let mut fsm = BeaconBlockSync::new(beacon_block_sync_config());
    let _ = fsm.handle(BeaconBlockSyncInput::Admitted {
        scope: (),
        height: tip,
    });
    fsm
}

/// Whether a catch-up is in flight — actively fetching or holding epochs
/// deferred behind a backoff. The loop ticks while true and idles
/// otherwise.
#[must_use]
pub fn has_pending(fsm: &BeaconBlockSync) -> bool {
    fsm.is_syncing() || fsm.has_deferred()
}

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

#[cfg(test)]
mod tests {
    use hyperscale_types::LocalTimestamp;

    use super::*;

    fn h(n: u64) -> Epoch {
        Epoch::new(n)
    }

    fn fetch_targets(outputs: &[BeaconBlockSyncOutput]) -> Vec<u64> {
        outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::Fetch { from, .. } => Some(from.inner()),
                SyncOutput::Complete { .. } => None,
            })
            .collect()
    }

    fn deliver(sync: &mut BeaconBlockSync, epoch: u64) {
        let _ = sync.handle(BeaconBlockSyncInput::FetchSucceeded {
            scope: (),
            from: h(epoch),
            count: 1,
            delivered_heights: vec![h(epoch)],
            now: LocalTimestamp::from_millis(0),
        });
    }

    /// Seeded at tip 5, serial sync fetches 6 first (never genesis+1),
    /// advances exactly one epoch per admission, and emits `Complete`
    /// once it catches up to the target.
    #[test]
    fn serial_window_fetches_one_epoch_gated_on_admission() {
        let mut sync = resumed_at(h(5));

        // Target a future epoch → fetch tip+1, not genesis+1.
        let out = sync.handle(BeaconBlockSyncInput::StartSync {
            scope: (),
            target: h(8),
        });
        assert_eq!(fetch_targets(&out), vec![6]);

        // Delivered but not yet admitted: window=1 holds — no new fetch.
        deliver(&mut sync, 6);
        let out = sync.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: h(6),
        });
        assert_eq!(fetch_targets(&out), vec![7]);

        deliver(&mut sync, 7);
        let out = sync.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: h(7),
        });
        assert_eq!(fetch_targets(&out), vec![8]);

        // Final epoch admitted → caught up.
        deliver(&mut sync, 8);
        let out = sync.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: h(8),
        });
        assert!(fetch_targets(&out).is_empty());
        assert!(
            out.iter()
                .any(|o| matches!(o, SyncOutput::Complete { height, .. } if height.inner() == 8))
        );
        assert!(!sync.is_syncing());
    }
}
