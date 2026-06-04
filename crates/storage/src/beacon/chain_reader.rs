//! Read interface for committed beacon blocks and their resulting state.

use std::sync::Arc;

use hyperscale_types::{BeaconBlockHash, BeaconState, CertifiedBeaconBlock, Epoch, Verified};

/// Read access to the process-level beacon chain.
///
/// All methods are synchronous; backends may serialize internally
/// (e.g., `RocksDB` snapshot reads) but expose a thread-safe interface
/// so multiple `BeaconCoordinator`s (one per vnode) can read
/// concurrently against a single `Arc<dyn BeaconChainReader>`.
///
/// Committed blocks come back as [`Verified<CertifiedBeaconBlock>`]: the
/// write path admits only verified blocks, so the store lifts each
/// decoded block through [`Verified::<CertifiedBeaconBlock>::from_persisted`]
/// at the read boundary.
pub trait BeaconChainReader: Send + Sync {
    /// Block committed at `epoch`, or `None` if absent.
    fn get_beacon_block_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<Arc<Verified<CertifiedBeaconBlock>>>;

    /// Block whose inner header hashes to `hash`, or `None` if absent.
    ///
    /// Implementations typically maintain a secondary `hash → epoch`
    /// index and delegate to [`Self::get_beacon_block_by_epoch`].
    fn get_beacon_block_by_hash(
        &self,
        hash: BeaconBlockHash,
    ) -> Option<Arc<Verified<CertifiedBeaconBlock>>>;

    /// `BeaconState` committed at `epoch`, or `None` if absent.
    ///
    /// `commit_beacon_block` writes the block and state atomically, so
    /// the pair is internally consistent for any epoch where both
    /// lookups return `Some`.
    fn get_state_by_epoch(&self, epoch: Epoch) -> Option<Arc<BeaconState>>;

    /// Highest epoch that has a committed block, or `None` if the chain
    /// is empty (no genesis yet).
    fn latest_committed_epoch(&self) -> Option<Epoch>;

    /// Most-recent `(block, state)` pair. `None` before genesis is
    /// committed. Single read; the coordinator uses this on restart to
    /// resume live without walking the chain.
    fn latest_committed(&self) -> Option<(Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>)>;

    /// Up to `count` most-recently-committed states, oldest first — the
    /// boot-time topology history the runner threads into
    /// `BeaconCoordinator::new` so the schedule resumes with its full
    /// retention window of committee snapshots. Walks back from
    /// [`latest_committed_epoch`](Self::latest_committed_epoch); empty if
    /// the chain has no genesis yet. Missing epochs in the range are
    /// skipped rather than truncating the walk.
    fn recent_states(&self, count: u64) -> Vec<Arc<BeaconState>> {
        let Some(latest) = self.latest_committed_epoch() else {
            return Vec::new();
        };
        let oldest = Epoch::new(latest.inner().saturating_sub(count.saturating_sub(1)));
        let mut states = Vec::new();
        let mut epoch = oldest;
        while epoch <= latest {
            if let Some(state) = self.get_state_by_epoch(epoch) {
                states.push(state);
            }
            epoch = epoch.next();
        }
        states
    }
}
