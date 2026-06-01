//! Beacon-block-sync binding for the generic [`Sync`] state machine.
//!
//! Gap-fill sync for the beacon chain. Unlike shard block-sync this is
//! strictly serial: [`beacon_block_sync_config`] sets `window_size = 1`,
//! so the generic queues only `committed + 1`, and it advances
//! `committed` on `Admitted` (fed from the beacon commit) — the next
//! epoch isn't fetched until the current one commits. That matches the
//! beacon coordinator's `epoch == tip + 1` adoption guard, so no
//! consumer-side ordering buffer is needed.
//!
//! The beacon chain commits one block per epoch and `Epoch` is a `u64`
//! newtype, so the generic's [`BlockHeight`](hyperscale_types::BlockHeight)
//! key stands in for the epoch number. Conversions live at the io-loop
//! boundary (`step::beacon_block_sync`); this binding only names the
//! per-binding type info and config.

use super::{Sync, SyncBinding, SyncConfig, SyncInput, SyncOutput};

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
    type State = ();
    const NAME: &'static str = "beacon_block_sync";
}

/// Serial, admission-gated config: one epoch fetched at a time, the next
/// gated on the prior committing.
#[must_use]
pub const fn beacon_block_sync_config() -> SyncConfig {
    SyncConfig {
        max_per_request: 1,
        window_size: 1,
        max_concurrent_per_scope: 1,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hyperscale_types::BlockHeight;

    use super::*;

    fn h(n: u64) -> BlockHeight {
        BlockHeight::new(n)
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
