//! Beacon-block catch-up sync: binding, sink, and the single driving body.
//!
//! The beacon chain is host-global — one chain per host, `Scope = ()` — so
//! the catch-up logic has one home here rather than a copy per driver. Both
//! the per-shard [`ShardLoop`](crate::shard::ShardLoop) and the
//! shard-less [`PoolLoop`](crate::pool_loop::PoolLoop) drive the same FSM
//! through [`BeaconSyncSink`]; only block delivery, fetch routing, and the
//! FSM instance differ per driver. The FSM *instance* stays per-driver
//! (a deliberate lock-free per-thread trade-off); only the driving *logic*
//! is shared.
//!
//! Unlike shard block-sync this is strictly serial: [`beacon_block_sync_config`]
//! sets `window_size = 1`, so the generic queues only `committed + 1` and
//! advances `committed` on `Admitted` (fed from the beacon commit) — the
//! next epoch isn't fetched until the current one commits. That matches the
//! beacon coordinator's `epoch == tip + 1` adoption guard, so no
//! consumer-side ordering buffer is needed. The binding sets `Key = Epoch`,
//! so the generic schedules over epochs directly — no `BlockHeight` pun.

use std::sync::Arc;

use hyperscale_types::{CertifiedBeaconBlock, Epoch, LocalTimestamp, Verifiable};

use crate::event::FetchFailureKind;
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
/// the coordinator's delivery handler able to reuse the gossip
/// verify+adopt path unchanged. Delivery stays in order, so every synced
/// block arrives at `epoch == tip + 1` and clears the `adopt_block`
/// regression guard. Widening the window would let blocks arrive out of
/// order — the coordinator would drop the early ones as past/future-tip
/// — so it can't be raised without first giving the coordinator a
/// reorder buffer.
#[must_use]
pub const fn beacon_block_sync_config() -> SyncConfig {
    SyncConfig {
        max_per_request: 1,
        window_size: 1,
        max_concurrent_per_scope: 1,
    }
}

/// The per-driver hooks the shared driving body routes through.
///
/// A driver owns its own [`BeaconBlockSync`] instance and supplies block
/// delivery + fetch routing; everything else (the FSM scheduling) lives in
/// the free functions below.
pub trait BeaconSyncSink {
    /// This driver's beacon-block-sync FSM instance.
    fn beacon_fsm(&mut self) -> &mut BeaconBlockSync;

    /// Fan a synced block to this driver's vnodes — the shard posts it to
    /// its event channel; the pool runs the verify/adopt/commit cascade
    /// inline.
    fn deliver_block(&mut self, block: Arc<Verifiable<CertifiedBeaconBlock>>);

    /// Dispatch a single-epoch fetch over this driver's routing, wrapping
    /// the reply as the driver's scoped input. Owns the `network.request`
    /// closure: that callback is `'static + Send`, so it can't borrow the
    /// driver — each side captures its own cloned sender/target instead.
    fn dispatch_fetch(&self, epoch: Epoch);

    /// This driver's current consensus clock — the deterministic time the
    /// FSM anchors its `pending_admission` and retry-backoff deadlines on,
    /// matching every other `self.now` site (set via `set_time`).
    fn now(&self) -> LocalTimestamp;

    /// The lowest beacon tip among the coordinators this driver hosts, or
    /// `None` while it hosts none.
    fn lowest_tip(&self) -> Option<Epoch>;
}

/// Begin (or extend) a catch-up sync toward `target`.
///
/// Seeds the FSM's committed watermark before the first fetch (see
/// [`admit_lowest_tip`]). `Admitted` creates and seeds the scope even
/// ahead of `StartSync`, so a serial (`window_size = 1`) sync starts above
/// the hosted tips rather than at `genesis + 1`; without the seed right
/// after a restart, when this session has committed nothing yet, the
/// window would pin at `genesis + 1`, a block every coordinator drops as
/// past-tip and never admits, so `committed` never advances and sync
/// wedges.
pub fn start<K: BeaconSyncSink>(sink: &mut K, target: Epoch) {
    admit_lowest_tip(sink);
    let outputs = sink
        .beacon_fsm()
        .handle(BeaconBlockSyncInput::StartSync { scope: (), target });
    drive_outputs(sink, outputs);
}

/// A beacon-block sync response landed. `None` (peer didn't have the epoch)
/// re-queues via fetch-failed. Otherwise deliver the block and tell the FSM
/// the epoch's bytes arrived.
///
/// `FetchSucceeded` means "the bytes arrived," not "the block is valid" —
/// verification happens coordinator-side (it owns the committee). The FSM
/// parks the epoch in `pending_admission`; a valid block commits and feeds
/// `Admitted`, while a block that fails verification is simply never admitted,
/// so the FSM re-fetches it after `PENDING_ADMISSION_TIMEOUT` (rotating to
/// another peer). Relying on that timeout is the deliberate trade-off for not
/// duplicating committee-aware verification here.
pub fn on_response<K: BeaconSyncSink>(
    sink: &mut K,
    epoch: Epoch,
    block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
) {
    let Some(block) = block else {
        // Back off rather than re-queue immediately: the sync target comes
        // from an unverified gossip block, so a bogus far-future epoch would
        // otherwise busy-loop the network fetching an epoch nobody has
        // produced yet.
        on_fetch_failed(sink, epoch, FetchFailureKind::NotFound);
        return;
    };
    sink.deliver_block(block);
    let now = sink.now();
    let outputs = sink
        .beacon_fsm()
        .handle(BeaconBlockSyncInput::FetchSucceeded {
            scope: (),
            from: epoch,
            count: 1,
            delivered_heights: vec![epoch],
            now,
        });
    drive_outputs(sink, outputs);
}

/// Re-queue an epoch via `FetchFailed`, applying the FSM's deferral.
pub fn on_fetch_failed<K: BeaconSyncSink>(sink: &mut K, epoch: Epoch, kind: FetchFailureKind) {
    let now = sink.now();
    let outputs = sink.beacon_fsm().handle(BeaconBlockSyncInput::FetchFailed {
        scope: (),
        from: epoch,
        count: 1,
        kind,
        now,
    });
    drive_outputs(sink, outputs);
}

/// Advance the FSM's committed watermark on a beacon commit (gossip or sync)
/// so a serial catch-up unblocks the next epoch's fetch and a later sync
/// starts above every hosted tip.
pub fn on_admitted<K: BeaconSyncSink>(sink: &mut K) {
    let outputs = admit_lowest_tip(sink);
    drive_outputs(sink, outputs);
}

/// Feed the FSM the lowest tip among the hosted coordinators as its
/// committed watermark.
///
/// One FSM serves every coordinator the driver hosts, and each adopts
/// what it delivers, so it fetches above the one furthest behind. The
/// watermark only rises, so it is never fed a higher tip: a co-hosted
/// coordinator that commits an epoch first would otherwise read the
/// others as caught up, and one still short of that epoch would fetch
/// nothing it lacks. Nor is it fed the host's beacon storage, which a
/// coordinator on another driver writes as it commits.
fn admit_lowest_tip<K: BeaconSyncSink>(sink: &mut K) -> Vec<BeaconBlockSyncOutput> {
    let Some(tip) = sink.lowest_tip() else {
        return Vec::new();
    };
    sink.beacon_fsm().handle(BeaconBlockSyncInput::Admitted {
        scope: (),
        height: tip,
    })
}

/// Drive the periodic tick, re-dispatching any deferred fetch whose backoff
/// has expired.
pub fn on_tick<K: BeaconSyncSink>(sink: &mut K) {
    let now = sink.now();
    let outputs = sink.beacon_fsm().handle(BeaconBlockSyncInput::Tick { now });
    drive_outputs(sink, outputs);
}

/// Whether a catch-up is in flight — actively fetching or holding epochs
/// deferred behind a backoff. Drivers tick while true and idle otherwise.
#[must_use]
pub fn has_pending(fsm: &BeaconBlockSync) -> bool {
    fsm.is_syncing() || fsm.has_deferred()
}

/// Turn the FSM's scheduling outputs into network fetches. Beacon has no
/// "sync mode" to exit — each adopted block already re-arms the coordinator's
/// timers — so completion is informational.
fn drive_outputs<K: BeaconSyncSink>(sink: &K, outputs: Vec<BeaconBlockSyncOutput>) {
    for output in outputs {
        match output {
            SyncOutput::Fetch { from, .. } => sink.dispatch_fetch(from),
            SyncOutput::Complete { height, .. } => {
                tracing::info!(epoch = height.inner(), "Beacon block sync complete");
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        let mut sync = BeaconBlockSync::new(beacon_block_sync_config());

        // Seed committed to the local tip (the `Admitted`-on-commit seed)
        // before any StartSync — creates and seeds the scope.
        let seeded = sync.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: h(5),
        });
        assert!(fetch_targets(&seeded).is_empty());

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

    /// A driver hosting coordinators at `tips` while it records the
    /// fetches its FSM dispatches.
    struct RecordingSink {
        fsm: BeaconBlockSync,
        tips: Vec<u64>,
        fetched: std::cell::RefCell<Vec<u64>>,
    }

    impl RecordingSink {
        fn hosting(tips: &[u64]) -> Self {
            Self {
                fsm: BeaconBlockSync::new(beacon_block_sync_config()),
                tips: tips.to_vec(),
                fetched: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl BeaconSyncSink for RecordingSink {
        fn beacon_fsm(&mut self) -> &mut BeaconBlockSync {
            &mut self.fsm
        }

        fn deliver_block(&mut self, _block: Arc<Verifiable<CertifiedBeaconBlock>>) {}

        fn dispatch_fetch(&self, epoch: Epoch) {
            self.fetched.borrow_mut().push(epoch.inner());
        }

        fn now(&self) -> LocalTimestamp {
            LocalTimestamp::from_millis(0)
        }

        fn lowest_tip(&self) -> Option<Epoch> {
            self.tips.iter().copied().min().map(h)
        }
    }

    /// A coordinator one epoch behind asks for the epoch above its own
    /// tip, whatever else the host has committed.
    #[test]
    fn start_fetches_above_the_requesting_coordinators_tip() {
        let mut sink = RecordingSink::hosting(&[16]);
        start(&mut sink, h(17));
        assert_eq!(*sink.fetched.borrow(), vec![17]);
    }

    /// A co-hosted coordinator that commits an epoch first leaves the one
    /// behind it the fetch of that epoch: the watermark stays at the
    /// lowest hosted tip, not the tip of whichever coordinator committed.
    #[test]
    fn a_co_hosted_commit_leaves_the_lagging_coordinator_its_fetch() {
        let mut sink = RecordingSink::hosting(&[16, 17]);
        start(&mut sink, h(17));
        assert_eq!(*sink.fetched.borrow(), vec![17]);

        // The coordinator ahead commits 18 off gossip.
        sink.tips = vec![16, 18];
        on_admitted(&mut sink);
        // The one behind adopts the 17 the sync delivered.
        deliver(&mut sink.fsm, 17);
        sink.tips = vec![17, 18];
        on_admitted(&mut sink);

        // 18 reaches it only by gossip, already gone, so it asks.
        start(&mut sink, h(18));
        assert_eq!(*sink.fetched.borrow(), vec![17, 18]);
    }
}
