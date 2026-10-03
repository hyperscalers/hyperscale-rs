//! Per-shard consensus subsystem.
//!
//! Colocates everything block-consensus the shard driver touches: the
//! per-shard [`ConsensusState`] (block-sync FSM + certified-header
//! verification batch), the block-sync FSM [`binding`](block), its inbound
//! [`serve`](block_serve) responder, the `impl ShardLoop` [`glue`](block_sync)
//! that drives fetches and delivers synced blocks to consensus, and the
//! certified-header [`gossip`] handler that feeds cross-shard provisioning.

mod block;
mod block_serve;
mod block_sync;
mod gossip;
mod proposal;

use std::collections::BTreeMap;
use std::sync::Arc;

pub use block::{
    BlockSync, BlockSyncConfig, BlockSyncInput, BlockSyncOutput, BlockSyncStateKind,
    BlockSyncStatus,
};
pub use block_serve::serve_block_request;
use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, ConsensusPublicKey, ConsensusSignature, LocalTimestamp,
    ValidatorId, Verifiable,
};
pub use proposal::{ProposalBinding, ProposalFetch, ProposalStore};

use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;

/// A certified header pending sender-signature verification, queued in
/// [`ConsensusState::certified_header_batch`] and drained on the crypto pool.
///
/// The wrapper carries verification state across the in-process gossip
/// boundary — wire arrivals land as `Verifiable::Unverified` by decode
/// rules, local-dispatched arrivals from a colocated proposer ride as
/// `Verifiable::Verified` so the flush step can fast-path them past the
/// sender-signature batch.
pub type CertifiedHeaderVerificationItem = (
    Arc<Verifiable<CertifiedBlockHeader>>,
    ValidatorId,
    ConsensusPublicKey,
    ConsensusSignature,
);

/// Per-shard consensus subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct ConsensusState {
    /// Block-sync state machine: catch the shard chain up to a target
    /// height by fetching and committing missing blocks.
    pub(crate) block_sync: BlockSync,

    /// What each seated vnode holds of the sync, so `block_sync` hears a
    /// height applied only once every seat has applied it.
    pub(crate) seat_frontiers: SeatFrontiers,

    /// Pending remote-certified header gossip awaiting batched
    /// sender-signature verification on the crypto pool.
    pub(crate) certified_header_batch: BatchAccumulator<CertifiedHeaderVerificationItem>,

    /// Proposals a committee member's vote named and no vnode here holds.
    pub(crate) proposal: ProposalFetch,

    /// The proposals this shard's vnodes admitted, served to members the
    /// proposer's broadcast missed.
    pub(crate) proposals: Arc<ProposalStore>,
}

impl ConsensusState {
    /// Build consensus state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        let b = &config.batch;
        Self {
            block_sync: BlockSync::new(config.block_sync.clone()),
            seat_frontiers: SeatFrontiers::default(),
            certified_header_batch: BatchAccumulator::new(
                b.certified_header_max,
                b.certified_header_window,
            ),
            proposal: ProposalFetch::new("proposal", config.beacon_proposal_fetch.clone()),
            proposals: Arc::new(ProposalStore::default()),
        }
    }

    /// True if block-sync has heights parked behind a backoff or is
    /// actively syncing. Keeps the `FetchTick` timer alive so deferred
    /// heights eventually retry and an active sync keeps emitting fetches
    /// even if its consumer is slow to admit.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.block_sync.has_deferred()
            || self.block_sync.is_syncing()
            || self.proposal.has_pending()
    }

    /// Drive the block-sync FSM's periodic tick. Returns the outputs the
    /// I/O loop should dispatch (block fetches, deliveries, sync-complete).
    pub(crate) fn block_tick(&mut self, now: LocalTimestamp) -> Vec<BlockSyncOutput> {
        self.block_sync.handle(BlockSyncInput::Tick { now })
    }
}

/// The highest synced height each seated vnode holds in chain state.
///
/// A loop runs one sync FSM for all its seats, and the FSM's completion
/// reaches every one of them, but each vnode verifies and applies the
/// blocks it is handed on its own. A vnode told the sync is complete while
/// its own verification of the tip is still in flight reads the sync as
/// having ended short of that tip and discards it. The FSM therefore
/// counts a height applied only once every seat holds it.
#[derive(Debug, Default)]
pub struct SeatFrontiers {
    applied: BTreeMap<ValidatorId, BlockHeight>,
    /// A seat left since the FSM last heard the held height, which may
    /// have raised it.
    released: bool,
}

impl SeatFrontiers {
    /// `seat` holds `height` in chain state.
    pub(crate) fn applied(&mut self, seat: ValidatorId, height: BlockHeight) {
        let held = self.applied.entry(seat).or_insert(height);
        *held = (*held).max(height);
    }

    /// `seat` gave up the block it applied at `height` for a certified
    /// sibling it has yet to fetch.
    pub(crate) fn reopened(&mut self, seat: ValidatorId, height: BlockHeight) {
        if let Some(held) = self.applied.get_mut(&seat)
            && *held >= height
        {
            *held = height.prev().unwrap_or(BlockHeight::GENESIS);
        }
    }

    /// `seat` joins holding the committed tip it restored at, and
    /// nothing its siblings applied above it.
    pub(crate) fn seated(&mut self, seat: ValidatorId, restored: BlockHeight) {
        self.applied.insert(seat, restored);
    }

    /// `seat` left the loop.
    pub(crate) fn released(&mut self, seat: ValidatorId) {
        self.released |= self.applied.remove(&seat).is_some();
    }

    /// Whether a seat left since the last call.
    pub(crate) const fn take_released(&mut self) -> bool {
        std::mem::replace(&mut self.released, false)
    }

    /// The height every one of `seats` holds, never below `committed`,
    /// which every seat holds through the loop's shared commits.
    pub(crate) fn held(
        &self,
        seats: impl IntoIterator<Item = ValidatorId>,
        committed: BlockHeight,
    ) -> BlockHeight {
        seats
            .into_iter()
            .map(|seat| {
                self.applied
                    .get(&seat)
                    .copied()
                    .unwrap_or(BlockHeight::GENESIS)
                    .max(committed)
            })
            .min()
            .unwrap_or(committed)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, ValidatorId};

    use super::SeatFrontiers;

    const A: ValidatorId = ValidatorId::new(1);
    const B: ValidatorId = ValidatorId::new(2);

    fn h(n: u64) -> BlockHeight {
        BlockHeight::new(n)
    }

    #[test]
    fn a_height_is_held_once_every_seat_applied_it() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        frontiers.applied(B, h(11));
        assert_eq!(frontiers.held([A, B], h(10)), h(11));

        frontiers.applied(B, h(12));
        assert_eq!(frontiers.held([A, B], h(10)), h(12));
    }

    #[test]
    fn a_seat_that_applied_nothing_holds_the_committed_height() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        assert_eq!(frontiers.held([A, B], h(10)), h(10));
        assert_eq!(
            frontiers.held([A], h(13)),
            h(13),
            "a commit past what a seat applied holds it"
        );
    }

    #[test]
    fn a_reopened_height_is_no_longer_held_by_its_seat() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        frontiers.reopened(A, h(12));
        assert_eq!(frontiers.held([A], h(10)), h(11));

        frontiers.reopened(A, h(15));
        assert_eq!(
            frontiers.held([A], h(10)),
            h(11),
            "a height above it changes nothing"
        );
    }

    #[test]
    fn a_seat_that_leaves_stops_holding_the_loop_back() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        frontiers.seated(B, h(10));
        assert_eq!(frontiers.held([A, B], h(10)), h(10));
        assert!(!frontiers.take_released());

        frontiers.released(B);
        assert!(frontiers.take_released());
        assert!(!frontiers.take_released(), "the release is reported once");
        assert_eq!(frontiers.held([A], h(10)), h(12));
    }
}
