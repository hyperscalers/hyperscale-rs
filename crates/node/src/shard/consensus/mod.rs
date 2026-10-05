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

/// What each seated vnode holds of the shard chain.
///
/// A loop runs one block sync for all its seats, but each vnode verifies,
/// applies and commits the blocks it is handed on its own, so seats sit at
/// different heights: a joiner restores at the store's committed tip while
/// its siblings hold synced blocks above it, and a seat's own verification
/// can trail a sibling's. The sync follows the slowest seat: it counts a
/// height held only once every seat holds it, and a seat that joins below
/// what it counts rewinds it.
#[derive(Debug, Default)]
pub struct SeatFrontiers {
    /// The top synced block each seat applied above its committed tip.
    applied: BTreeMap<ValidatorId, BlockHeight>,
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

    /// `seat` left the loop, or joins it holding nothing it applied.
    pub(crate) fn forget(&mut self, seat: ValidatorId) {
        self.applied.remove(&seat);
    }

    /// The height every seat holds, given each seat's own committed
    /// height; `None` for a loop with no seats.
    pub(crate) fn held(
        &self,
        seats: impl IntoIterator<Item = (ValidatorId, BlockHeight)>,
    ) -> Option<BlockHeight> {
        seats
            .into_iter()
            .map(|(seat, committed)| {
                self.applied
                    .get(&seat)
                    .map_or(committed, |&applied| applied.max(committed))
            })
            .min()
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
        assert_eq!(frontiers.held([(A, h(10)), (B, h(10))]), Some(h(11)));

        frontiers.applied(B, h(12));
        assert_eq!(frontiers.held([(A, h(10)), (B, h(10))]), Some(h(12)));
    }

    #[test]
    fn a_seat_holds_its_own_committed_height_not_a_siblings() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        assert_eq!(
            frontiers.held([(A, h(10)), (B, h(4))]),
            Some(h(4)),
            "a seat that applied nothing holds only what it committed"
        );
        assert_eq!(
            frontiers.held([(A, h(13))]),
            Some(h(13)),
            "a commit past what a seat applied holds it"
        );
        assert_eq!(frontiers.held([]), None);
    }

    #[test]
    fn a_reopened_height_is_no_longer_held_by_its_seat() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        frontiers.reopened(A, h(12));
        assert_eq!(frontiers.held([(A, h(10))]), Some(h(11)));

        frontiers.reopened(A, h(15));
        assert_eq!(
            frontiers.held([(A, h(10))]),
            Some(h(11)),
            "a height above it changes nothing"
        );
    }

    #[test]
    fn a_forgotten_seat_holds_only_what_it_committed() {
        let mut frontiers = SeatFrontiers::default();
        frontiers.applied(A, h(12));
        frontiers.forget(A);
        assert_eq!(frontiers.held([(A, h(10))]), Some(h(10)));
    }
}
