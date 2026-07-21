//! Shard fork proofs the local coordinator has verified but not yet
//! carried into a beacon proposal.
//!
//! A proof arrives from the shard layer already verified — assembled
//! locally from conflicting certified headers, or received over gossip
//! and checked off-thread. The node feeds it here; the proposer drains
//! the buffer into its next proposal, and `apply_epoch` stamps a
//! fork-caused [`ShardRecovery`](hyperscale_types::ShardRecovery) for
//! every shard named.
//!
//! Keyed by [`ShardId`] with first-wins semantics — one proof per shard
//! is enough to flush and re-draw its committee, so a second proof for a
//! shard already buffered is dropped.

use std::collections::BTreeMap;

use hyperscale_types::{ShardForkProof, ShardId};

/// Buffered fork proofs awaiting inclusion in a beacon proposal.
#[derive(Debug, Default)]
pub struct ForkProofObservations {
    by_shard: BTreeMap<ShardId, Box<ShardForkProof>>,
}

impl ForkProofObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified fork proof. Returns `true` if newly recorded;
    /// `false` if a proof for this shard was already buffered.
    pub fn observe(&mut self, proof: ShardForkProof) -> bool {
        let shard = proof.shard();
        if self.by_shard.contains_key(&shard) {
            return false;
        }
        self.by_shard.insert(shard, Box::new(proof));
        true
    }

    /// Drain every buffered proof, keyed by shard, and empty the buffer.
    /// The per-shard map caps at `MAX_SHARDS` on the wire, so there is no
    /// per-proposer overflow to re-record.
    pub fn drain_for_proposal(&mut self) -> BTreeMap<ShardId, ShardForkProof> {
        std::mem::take(&mut self.by_shard)
            .into_iter()
            .map(|(shard, boxed)| (shard, *boxed))
            .collect()
    }

    /// Drop every buffered proof whose shard `obsolete` matches. The
    /// coordinator calls this after each `apply_epoch` for any shard whose
    /// fold now holds a fork-caused recovery — once the funnel has flushed
    /// the committee, re-proposing the proof only wastes proposal space.
    pub fn prune(&mut self, mut obsolete: impl FnMut(ShardId) -> bool) {
        self.by_shard.retain(|shard, _| !obsolete(*shard));
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl ForkProofObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_shard.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_shard.is_empty()
    }

    #[must_use]
    pub fn contains(&self, shard: ShardId) -> bool {
        self.by_shard.contains_key(&shard)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};
    use hyperscale_types::{BlockHeight, TopologySchedule};

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    /// A verified `ConflictingCommits` for `SHARD` at height 9, signed with
    /// real BLS so the buffer holds a genuine proof.
    fn fork_proof(committee: &TestCommittee) -> ShardForkProof {
        shard_fork_proof(committee, SHARD, BlockHeight::new(9))
    }

    #[test]
    fn empty_after_new() {
        let f = ForkProofObservations::new();
        assert_eq!(f.len(), 0);
        assert!(f.is_empty());
        assert!(!f.contains(SHARD));
    }

    #[test]
    fn observe_then_query_round_trips() {
        let committee = TestCommittee::new(4, 1);
        let mut f = ForkProofObservations::new();
        assert!(f.observe(fork_proof(&committee)));
        assert!(f.contains(SHARD));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn first_wins_when_same_shard_observed_twice() {
        let committee = TestCommittee::new(4, 2);
        let mut f = ForkProofObservations::new();
        assert!(f.observe(fork_proof(&committee)));
        assert!(!f.observe(fork_proof(&committee)));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn drain_returns_verified_proof_keyed_by_shard_and_empties() {
        let committee = TestCommittee::new(4, 3);
        let mut f = ForkProofObservations::new();
        f.observe(fork_proof(&committee));
        let drained = f.drain_for_proposal();
        assert_eq!(drained.len(), 1);
        // The drained proof still verifies against the committee's schedule.
        let schedule = TopologySchedule::single(Arc::new(committee.topology_snapshot(1)));
        assert!(drained[&SHARD].verify(&schedule).is_ok());
        assert!(f.is_empty());
    }

    #[test]
    fn prune_drops_matching_shards_only() {
        let committee = TestCommittee::new(4, 4);
        let mut f = ForkProofObservations::new();
        f.observe(fork_proof(&committee));
        f.prune(|shard| shard == SHARD);
        assert!(!f.contains(SHARD));
        assert_eq!(f.len(), 0);
        // A non-matching predicate leaves the buffer intact.
        f.observe(fork_proof(&committee));
        f.prune(|shard| shard != SHARD);
        assert!(f.contains(SHARD));
    }
}
