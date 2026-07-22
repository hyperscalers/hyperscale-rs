//! [`ForkFence`] — the gossip-timed per-shard fork fence every cross-shard
//! consumer engages against a provably-forked shard.

use std::collections::BTreeMap;

use crate::{BlockHeight, CompletedRecovery, Epoch, ShardId};

/// Gossip-timed local fork fences, one per provably-forked shard.
///
/// A verified [`ShardForkProof`](crate::ShardForkProof) engages a fence at
/// `fork_height − 1`: content from the shard *at or above* the forked height
/// (both conflicting blocks live there) is quiesced locally until the
/// recovery the proof arms completes. The fence is gossip-timed —
/// replicas hear the proof at different times — so it must never touch
/// block validity: it only quiesces the local node. Every consumer
/// coordinator owns one and shares this lifecycle:
///
/// - **Engage** on a verified proof ([`Self::engage`]), tightening only.
///   A proof at or below the shard's last completed recovery frontier is
///   refused: the beacon fold treats it as a replay of already-recovered
///   history, so no recovery would ever fold to clear the fence it engaged.
/// - **Hold** through the recovery fold. Between the recovery entering
///   `pending_recoveries` and the fresh committee's first crossing, the
///   fence keeps quiescing locally while the beacon-attested
///   [`recovery_fences`](crate::TopologySnapshot::recovery_fences) govern
///   validity over the same interval.
/// - **Clear** when the recovery completes ([`Self::clear_completed`]):
///   the shard's completed-recovery record is newer than the one the
///   fence engaged over.
///
/// Empty under honest operation.
#[derive(Debug, Clone, Default)]
pub struct ForkFence {
    fences: BTreeMap<ShardId, Fence>,
}

#[derive(Debug, Clone, Copy)]
struct Fence {
    /// Last unfenced height, `fork_height − 1`: [`ForkFence::is_fenced`]
    /// is `height > frontier`, covering the forked height itself.
    frontier: BlockHeight,
    /// The seating epoch of the shard's completed-recovery record when the
    /// fence engaged (`None` if the shard had never recovered). A completed
    /// record newer than this is the recovery this fence's fork armed —
    /// the clear edge.
    engaged_over: Option<Epoch>,
}

impl ForkFence {
    /// No fences engaged.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fences: BTreeMap::new(),
        }
    }

    /// Whether a proof forking `shard` at `fork_height` would engage a
    /// fence — read-only twin of [`Self::engage`]. Callers use it to dedup
    /// a gossiped proof before spending verification on it.
    #[must_use]
    pub fn engages(
        &self,
        shard: ShardId,
        fork_height: BlockHeight,
        completed: &BTreeMap<ShardId, CompletedRecovery>,
    ) -> bool {
        // The beacon fold drops a proof at or below the last completed
        // recovery's frontier as already-answered history, so no recovery
        // would ever fold to clear a fence it engaged — refuse it here for
        // the same reason.
        if completed
            .get(&shard)
            .is_some_and(|record| fork_height <= record.attested_frontier)
        {
            return false;
        }
        // Never loosen: only a strictly lower fork tightens an engaged fence.
        let frontier = frontier_below(fork_height);
        self.fences
            .get(&shard)
            .is_none_or(|fence| frontier < fence.frontier)
    }

    /// Engage (or tighten) the fence for `shard` at `fork_height`. Returns
    /// the engaged frontier (`fork_height − 1`) exactly when the fence
    /// changed, so the caller runs its purge side effects once; `None` for
    /// a duplicate, looser, or already-recovered proof.
    pub fn engage(
        &mut self,
        shard: ShardId,
        fork_height: BlockHeight,
        completed: &BTreeMap<ShardId, CompletedRecovery>,
    ) -> Option<BlockHeight> {
        if !self.engages(shard, fork_height, completed) {
            return None;
        }
        let frontier = frontier_below(fork_height);
        self.fences.insert(
            shard,
            Fence {
                frontier,
                engaged_over: completed.get(&shard).map(|record| record.rotated_at),
            },
        );
        Some(frontier)
    }

    /// Clear every fence whose recovery has completed — the shard's
    /// completed-recovery record is newer than the one the fence engaged
    /// over. Returns the cleared shards so consumers can release work they
    /// withheld while fenced.
    pub fn clear_completed(
        &mut self,
        completed: &BTreeMap<ShardId, CompletedRecovery>,
    ) -> Vec<ShardId> {
        let mut cleared = Vec::new();
        self.fences.retain(|&shard, fence| {
            let done = completed.get(&shard).map(|record| record.rotated_at) > fence.engaged_over;
            if done {
                cleared.push(shard);
            }
            !done
        });
        cleared
    }

    /// Whether `(shard, height)` is fenced — at or above a fenced shard's
    /// forked height.
    #[must_use]
    pub fn is_fenced(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.fences
            .get(&shard)
            .is_some_and(|fence| height > fence.frontier)
    }

    /// Whether any fence is engaged for `shard`, regardless of height.
    #[must_use]
    pub fn is_engaged(&self, shard: ShardId) -> bool {
        self.fences.contains_key(&shard)
    }

    /// Whether no fence is engaged — the ordinary case, kept cheap so
    /// hot paths can skip per-item fence checks entirely.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fences.is_empty()
    }

    /// The engaged fences as `(shard, frontier)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (ShardId, BlockHeight)> + '_ {
        self.fences
            .iter()
            .map(|(&shard, fence)| (shard, fence.frontier))
    }
}

/// The stored frontier for a fork at `fork_height`: one below it, so the
/// shared `height > frontier` check rejects the forked height itself.
const fn frontier_below(fork_height: BlockHeight) -> BlockHeight {
    BlockHeight::new(fork_height.inner().saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed(
        shard: ShardId,
        rotated_at: u64,
        frontier: u64,
    ) -> BTreeMap<ShardId, CompletedRecovery> {
        std::iter::once((
            shard,
            CompletedRecovery {
                rotated_at: Epoch::new(rotated_at),
                attested_frontier: BlockHeight::new(frontier),
            },
        ))
        .collect()
    }

    #[test]
    fn engage_fences_at_and_above_the_fork_height() {
        let shard = ShardId::leaf(1, 0);
        let mut fence = ForkFence::new();
        assert_eq!(
            fence.engage(shard, BlockHeight::new(5), &BTreeMap::new()),
            Some(BlockHeight::new(4)),
        );
        assert!(fence.is_fenced(shard, BlockHeight::new(5)));
        assert!(fence.is_fenced(shard, BlockHeight::new(9)));
        assert!(!fence.is_fenced(shard, BlockHeight::new(4)));
        assert!(!fence.is_fenced(ShardId::leaf(1, 1), BlockHeight::new(9)));
    }

    #[test]
    fn engage_never_loosens() {
        let shard = ShardId::leaf(1, 0);
        let none = BTreeMap::new();
        let mut fence = ForkFence::new();
        fence.engage(shard, BlockHeight::new(5), &none);

        // Same or higher fork height: no-op.
        assert_eq!(fence.engage(shard, BlockHeight::new(5), &none), None);
        assert_eq!(fence.engage(shard, BlockHeight::new(8), &none), None);
        assert!(!fence.is_fenced(shard, BlockHeight::new(4)));

        // A strictly lower fork tightens.
        assert_eq!(
            fence.engage(shard, BlockHeight::new(3), &none),
            Some(BlockHeight::new(2)),
        );
        assert!(fence.is_fenced(shard, BlockHeight::new(3)));
    }

    #[test]
    fn already_recovered_forks_do_not_engage() {
        let shard = ShardId::leaf(1, 0);
        let recovered = completed(shard, 7, 10);
        let mut fence = ForkFence::new();

        // At and below the completed frontier: a replay, refused.
        assert!(!fence.engages(shard, BlockHeight::new(10), &recovered));
        assert_eq!(fence.engage(shard, BlockHeight::new(4), &recovered), None);
        assert!(fence.is_empty());

        // Above the frontier: a genuine re-fork, engages.
        assert!(fence.engages(shard, BlockHeight::new(11), &recovered));
        assert!(
            fence
                .engage(shard, BlockHeight::new(11), &recovered)
                .is_some()
        );
    }

    #[test]
    fn clears_on_recovery_completion_not_before() {
        let shard = ShardId::leaf(1, 0);
        let mut fence = ForkFence::new();
        fence.engage(shard, BlockHeight::new(5), &BTreeMap::new());

        // No completed record (the recovery is at most pending): held.
        assert!(fence.clear_completed(&BTreeMap::new()).is_empty());
        assert!(fence.is_engaged(shard));

        // The recovery completes: cleared, and the cleared shard reported.
        assert_eq!(fence.clear_completed(&completed(shard, 3, 4)), vec![shard]);
        assert!(fence.is_empty());
    }

    #[test]
    fn a_stale_completed_record_does_not_clear_a_refork() {
        let shard = ShardId::leaf(1, 0);
        let old = completed(shard, 3, 10);
        let mut fence = ForkFence::new();

        // A re-fork above the old recovery's frontier engages over it.
        fence.engage(shard, BlockHeight::new(20), &old);

        // The same stale record must not clear the new fence.
        assert!(fence.clear_completed(&old).is_empty());
        assert!(fence.is_engaged(shard));

        // Only the re-fork's own (newer) recovery clears it.
        assert_eq!(fence.clear_completed(&completed(shard, 9, 19)), vec![shard],);
        assert!(fence.is_empty());
    }
}
