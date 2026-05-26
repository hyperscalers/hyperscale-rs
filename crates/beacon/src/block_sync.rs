//! Gap-fill sync for the beacon chain.
//!
//! Drives the catch-up flow when the local coordinator is behind the
//! live tip — restart with a stale snapshot, recovery from a network
//! partition, or any other gap. Owns the buffer of fetched blocks
//! awaiting their turn through verification + `apply_epoch`, and the
//! in-flight fetch tracking so the coordinator doesn't redispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{CertifiedBeaconBlock, Epoch};

/// Sync orchestration state.
///
/// Active when [`Self::start_sync_to`] sets a target ahead of the
/// local committed epoch. The coordinator pulls fetch epochs via
/// [`Self::next_fetch_to_dispatch`], submits fetched blocks via
/// [`Self::on_synced_block_received`], and drains the next applicable
/// block via [`Self::take_next_applicable`] after each `apply_epoch`.
#[derive(Debug, Default)]
pub struct BeaconBlockSyncManager {
    target: Option<Epoch>,
    buffered: BTreeMap<Epoch, Arc<CertifiedBeaconBlock>>,
    in_flight: BTreeSet<Epoch>,
}

impl BeaconBlockSyncManager {
    /// Empty manager (not syncing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin syncing up to `target_epoch`. If sync is already active
    /// with a higher target, the request is dropped — sync only ever
    /// extends forward.
    pub fn start_sync_to(&mut self, target_epoch: Epoch) {
        match self.target {
            Some(existing) if existing >= target_epoch => {}
            _ => self.target = Some(target_epoch),
        }
    }

    /// Tear down sync state — coordinator calls this once `apply_epoch`
    /// has caught the chain up to (or past) the target.
    pub fn stop_syncing(&mut self) {
        self.target = None;
        self.buffered.clear();
        self.in_flight.clear();
    }

    /// Next epoch to dispatch a fetch for, scanning from
    /// `committed_epoch + 1` up to (and including) `target`. Returns
    /// `None` when nothing's needed — not syncing, all relevant
    /// epochs already buffered or in-flight, or `committed_epoch` has
    /// reached `target`.
    ///
    /// Marks the returned epoch as in-flight so the next call skips
    /// it. The coordinator clears it via
    /// [`Self::on_synced_block_received`] on receipt.
    pub fn next_fetch_to_dispatch(&mut self, committed_epoch: Epoch) -> Option<Epoch> {
        let target = self.target?;
        let mut epoch = committed_epoch.next();
        while epoch <= target {
            if !self.buffered.contains_key(&epoch) && !self.in_flight.contains(&epoch) {
                self.in_flight.insert(epoch);
                return Some(epoch);
            }
            epoch = epoch.next();
        }
        None
    }

    /// Buffer a fetched block. Clears the in-flight marker for its
    /// epoch. Silently overwrites any prior buffered entry at the
    /// same epoch — under honest sync there's one canonical block
    /// per epoch.
    pub fn on_synced_block_received(&mut self, block: Arc<CertifiedBeaconBlock>) {
        let epoch = block.epoch();
        self.in_flight.remove(&epoch);
        self.buffered.insert(epoch, block);
    }

    /// Take the next-applicable buffered block — the one at
    /// `committed_epoch + 1`. The coordinator runs it through
    /// verification + `apply_epoch`, then calls this again to drain
    /// the next.
    pub fn take_next_applicable(
        &mut self,
        committed_epoch: Epoch,
    ) -> Option<Arc<CertifiedBeaconBlock>> {
        self.buffered.remove(&committed_epoch.next())
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl BeaconBlockSyncManager {
    #[must_use]
    pub const fn is_syncing(&self) -> bool {
        self.target.is_some()
    }

    #[must_use]
    pub const fn target(&self) -> Option<Epoch> {
        self.target
    }

    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.buffered.len()
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
}

// Tests temporarily removed during cert-as-authenticator refactor; restore in follow-up.

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlock, BeaconBlockHash, BeaconCert, Bls12381G2Signature, Epoch, Hash, SignerBitfield,
        SkipEpochCert,
    };

    use super::*;

    fn block_at(epoch: u64) -> Arc<CertifiedBeaconBlock> {
        // Tests don't exercise cert verification — Skip-shaped is the
        // cheapest cert+body to construct.
        let block = BeaconBlock::skip(
            Epoch::new(epoch),
            BeaconBlockHash::from_raw(Hash::from_bytes(format!("prev-{epoch}").as_bytes())),
        );
        let cert = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(epoch),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        );
        Arc::new(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Skip(cert),
        ))
    }

    #[test]
    fn empty_after_new() {
        let m = BeaconBlockSyncManager::new();
        assert!(!m.is_syncing());
        assert!(m.target().is_none());
        assert_eq!(m.buffered_count(), 0);
        assert_eq!(m.in_flight_count(), 0);
    }

    #[test]
    fn start_sync_to_sets_target_and_marks_syncing() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(10));
        assert!(m.is_syncing());
        assert_eq!(m.target(), Some(Epoch::new(10)));
    }

    #[test]
    fn start_sync_to_extends_forward_never_backward() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(10));
        m.start_sync_to(Epoch::new(5));
        assert_eq!(m.target(), Some(Epoch::new(10)));
        m.start_sync_to(Epoch::new(15));
        assert_eq!(m.target(), Some(Epoch::new(15)));
    }

    #[test]
    fn next_fetch_to_dispatch_walks_committed_plus_one_up_to_target() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        let committed = Epoch::new(0);
        let mut emitted = Vec::new();
        while let Some(e) = m.next_fetch_to_dispatch(committed) {
            emitted.push(e);
        }
        assert_eq!(emitted, vec![Epoch::new(1), Epoch::new(2), Epoch::new(3)]);
    }

    #[test]
    fn next_fetch_to_dispatch_skips_buffered_epochs() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        m.on_synced_block_received(block_at(2));
        let mut emitted = Vec::new();
        while let Some(e) = m.next_fetch_to_dispatch(Epoch::new(0)) {
            emitted.push(e);
        }
        assert_eq!(emitted, vec![Epoch::new(1), Epoch::new(3)]);
    }

    #[test]
    fn next_fetch_to_dispatch_returns_none_when_committed_past_target() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        assert!(m.next_fetch_to_dispatch(Epoch::new(5)).is_none());
    }

    #[test]
    fn next_fetch_to_dispatch_returns_none_when_not_syncing() {
        let mut m = BeaconBlockSyncManager::new();
        assert!(m.next_fetch_to_dispatch(Epoch::new(0)).is_none());
    }

    #[test]
    fn on_synced_block_received_clears_in_flight_and_buffers() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        let dispatched = m.next_fetch_to_dispatch(Epoch::new(0)).unwrap();
        assert_eq!(m.in_flight_count(), 1);
        m.on_synced_block_received(block_at(dispatched.inner()));
        assert_eq!(m.in_flight_count(), 0);
        assert_eq!(m.buffered_count(), 1);
    }

    #[test]
    fn take_next_applicable_returns_committed_plus_one_when_buffered() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        m.on_synced_block_received(block_at(1));
        let b = m.take_next_applicable(Epoch::new(0)).unwrap();
        assert_eq!(b.epoch(), Epoch::new(1));
        assert_eq!(m.buffered_count(), 0);
    }

    #[test]
    fn take_next_applicable_returns_none_when_next_not_buffered() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        m.on_synced_block_received(block_at(3));
        assert!(m.take_next_applicable(Epoch::new(0)).is_none());
        assert_eq!(m.buffered_count(), 1);
    }

    #[test]
    fn stop_syncing_clears_everything() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));
        m.next_fetch_to_dispatch(Epoch::new(0));
        m.on_synced_block_received(block_at(2));
        m.stop_syncing();
        assert!(!m.is_syncing());
        assert_eq!(m.buffered_count(), 0);
        assert_eq!(m.in_flight_count(), 0);
    }

    /// Walks a full sync cycle: start, dispatch fetches, receive
    /// out-of-order, drain in order.
    #[test]
    fn full_sync_cycle_drains_in_epoch_order() {
        let mut m = BeaconBlockSyncManager::new();
        m.start_sync_to(Epoch::new(3));

        for _ in 0..3 {
            m.next_fetch_to_dispatch(Epoch::new(0));
        }
        assert_eq!(m.in_flight_count(), 3);

        m.on_synced_block_received(block_at(3));
        m.on_synced_block_received(block_at(1));
        m.on_synced_block_received(block_at(2));
        assert_eq!(m.in_flight_count(), 0);
        assert_eq!(m.buffered_count(), 3);

        let mut committed = Epoch::new(0);
        let mut drained = Vec::new();
        while let Some(b) = m.take_next_applicable(committed) {
            drained.push(b.epoch());
            committed = b.epoch();
        }
        assert_eq!(drained, vec![Epoch::new(1), Epoch::new(2), Epoch::new(3)]);
    }
}
