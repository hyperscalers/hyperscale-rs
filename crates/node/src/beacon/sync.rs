//! Beacon-block catch-up sync: binding, sink, and the single driving body.
//!
//! The beacon chain is host-global — one chain per host, `Scope = ()` — so
//! the catch-up logic has one home here rather than a copy per driver. Both
//! the per-shard [`ShardLoop`](crate::shard_loop::ShardLoop) and the
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

use hyperscale_types::{CertifiedBeaconBlock, Epoch, Verifiable};

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

    /// Local beacon tip, for the restart seed (identical logic both sides).
    fn beacon_tip(&self) -> Option<Epoch>;
}

/// Begin (or extend) a catch-up sync toward `target`.
///
/// Seeds the FSM's committed watermark from the local beacon tip before the
/// first fetch. `Admitted` creates and seeds the scope even ahead of
/// `StartSync`, so a serial (`window_size = 1`) sync starts from `tip + 1`
/// rather than `genesis + 1`. This is idempotent with the `Admitted`-on-commit
/// stream and only load-bearing right after a restart, when this session
/// hasn't committed anything yet — without it the window would pin at
/// `genesis + 1`, a block the coordinator drops as past-tip and never admits,
/// so `committed` never advances and sync wedges.
pub fn start<K: BeaconSyncSink>(sink: &mut K, target: Epoch) {
    if let Some(tip) = sink.beacon_tip() {
        let _ = sink.beacon_fsm().handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: tip,
        });
    }
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
    let outputs = sink
        .beacon_fsm()
        .handle(BeaconBlockSyncInput::FetchSucceeded {
            scope: (),
            from: epoch,
            count: 1,
            delivered_heights: vec![epoch],
            now: std::time::Instant::now(),
        });
    drive_outputs(sink, outputs);
}

/// Re-queue an epoch via `FetchFailed`, applying the FSM's deferral.
pub fn on_fetch_failed<K: BeaconSyncSink>(sink: &mut K, epoch: Epoch, kind: FetchFailureKind) {
    let outputs = sink.beacon_fsm().handle(BeaconBlockSyncInput::FetchFailed {
        scope: (),
        from: epoch,
        count: 1,
        kind,
        now: std::time::Instant::now(),
    });
    drive_outputs(sink, outputs);
}

/// Advance the FSM's committed watermark on a beacon commit (gossip or sync)
/// so a serial catch-up unblocks the next epoch's fetch and a later sync
/// starts from current+1.
pub fn on_admitted<K: BeaconSyncSink>(sink: &mut K, epoch: Epoch) {
    let outputs = sink.beacon_fsm().handle(BeaconBlockSyncInput::Admitted {
        scope: (),
        height: epoch,
    });
    drive_outputs(sink, outputs);
}

/// Drive the periodic tick, re-dispatching any deferred fetch whose backoff
/// has expired.
pub fn on_tick<K: BeaconSyncSink>(sink: &mut K) {
    let outputs = sink.beacon_fsm().handle(BeaconBlockSyncInput::Tick {
        now: std::time::Instant::now(),
    });
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
    use std::time::Instant;

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
            now: Instant::now(),
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
}
