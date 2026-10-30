//! Beacon-block catch-up sync: the binding and its serial config.
//!
//! The beacon chain is host-global — one chain per host, `Scope = ()` —
//! and the host's [`BeaconLoop`](crate::beacon_loop::BeaconLoop) drives
//! the FSM, delivering synced blocks to its fold and routing the fetches.
//!
//! The sync is strictly serial: the config sets
//! `window_size = 1`, so the generic queues only `committed + 1` and
//! advances `committed` on `Admitted` (fed from the beacon commit) — the
//! next epoch isn't fetched until the current one commits. That matches the
//! fold's `epoch == tip + 1` adoption guard, so no consumer-side ordering
//! buffer is needed. The binding sets `Key = Epoch`, so the generic
//! schedules over epochs directly.

use hyperscale_types::Epoch;

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
