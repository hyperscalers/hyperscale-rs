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
//!
//! A drained proof is not gone: it moves to an in-flight buffer until the
//! fold confirms the fork registered (the shard gains a durable flag or a
//! fork-caused recovery). A proposal lost to a Skip epoch — which
//! discards every committee member's drained copy at once — restores its
//! proofs for the next proposal instead of dropping the fork on the
//! floor.

use std::collections::BTreeMap;

use hyperscale_types::{ShardForkProof, ShardId};

/// Buffered fork proofs awaiting inclusion in a beacon proposal.
#[derive(Debug, Default)]
pub struct ForkProofObservations {
    /// Proofs awaiting the next proposal build.
    by_shard: BTreeMap<ShardId, Box<ShardForkProof>>,
    /// Proofs drained into a proposal whose fold hasn't yet confirmed
    /// the fork registered. Restored by
    /// [`restore_undelivered`](Self::restore_undelivered) after each
    /// fold's prune.
    in_flight: BTreeMap<ShardId, Box<ShardForkProof>>,
}

impl ForkProofObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified fork proof. Returns `true` if newly recorded;
    /// `false` if a proof for this shard is already buffered or riding an
    /// unconfirmed proposal.
    pub fn observe(&mut self, proof: ShardForkProof) -> bool {
        let shard = proof.shard();
        if self.by_shard.contains_key(&shard) || self.in_flight.contains_key(&shard) {
            return false;
        }
        self.by_shard.insert(shard, Box::new(proof));
        true
    }

    /// Drain every buffered proof for a proposal build, keyed by shard,
    /// moving each into the in-flight buffer until a fold confirms it.
    /// The per-shard map caps at `MAX_SHARDS` on the wire, so there is no
    /// per-proposer overflow to re-record.
    pub fn drain_for_proposal(&mut self) -> BTreeMap<ShardId, ShardForkProof> {
        std::mem::take(&mut self.by_shard)
            .into_iter()
            .map(|(shard, boxed)| {
                let proof = *boxed.clone();
                self.in_flight.insert(shard, boxed);
                (shard, proof)
            })
            .collect()
    }

    /// Drop every buffered or in-flight proof whose shard `obsolete`
    /// matches. The coordinator calls this after each `apply_epoch` for
    /// any shard whose fold now holds the durable fork flag or a
    /// fork-caused recovery — the beacon's own state is the record from
    /// there, so re-proposing the proof only wastes proposal space.
    pub fn prune(&mut self, mut obsolete: impl FnMut(ShardId) -> bool) {
        self.by_shard.retain(|shard, _| !obsolete(*shard));
        self.in_flight.retain(|shard, _| !obsolete(*shard));
    }

    /// Restore every in-flight proof that survived the fold's prune: its
    /// proposal was discarded (a Skip epoch, or lost to admission), so
    /// the fork never registered and the proof re-enters the next
    /// proposal build.
    pub fn restore_undelivered(&mut self) {
        let undelivered = std::mem::take(&mut self.in_flight);
        self.by_shard.extend(undelivered);
    }
}

// Flat accessors over both buffers; names are the documentation.
#[allow(missing_docs)]
impl ForkProofObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_shard.len() + self.in_flight.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_shard.is_empty() && self.in_flight.is_empty()
    }

    #[must_use]
    pub fn contains(&self, shard: ShardId) -> bool {
        self.by_shard.contains_key(&shard) || self.in_flight.contains_key(&shard)
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
    fn drain_returns_verified_proof_and_holds_it_in_flight() {
        let committee = TestCommittee::new(4, 3);
        let mut f = ForkProofObservations::new();
        f.observe(fork_proof(&committee));
        let drained = f.drain_for_proposal();
        assert_eq!(drained.len(), 1);
        // The drained proof still verifies against the committee's schedule.
        let schedule = TopologySchedule::single(Arc::new(committee.topology_snapshot(1)));
        assert!(drained[&SHARD].verify(&schedule).is_ok());
        // Drained but unconfirmed: held in flight (deduping re-observation),
        // out of the next build until restored.
        assert!(f.contains(SHARD));
        assert!(!f.observe(fork_proof(&committee)));
        assert!(f.drain_for_proposal().is_empty());
    }

    /// The Skip-epoch shape: a drained proof whose proposal never folds is
    /// restored and rides the next build; a fold that registers the fork
    /// prunes it out of flight for good.
    #[test]
    fn undelivered_drain_restores_and_a_registered_fork_prunes() {
        let committee = TestCommittee::new(4, 5);
        let mut f = ForkProofObservations::new();
        f.observe(fork_proof(&committee));
        assert_eq!(f.drain_for_proposal().len(), 1);

        // The proposal was discarded (Skip): nothing registered, restore.
        f.prune(|_| false);
        f.restore_undelivered();
        assert_eq!(f.drain_for_proposal().len(), 1, "restored for re-proposal");

        // This time the fold registered the fork: pruned from flight.
        f.prune(|shard| shard == SHARD);
        f.restore_undelivered();
        assert!(f.is_empty());
        assert!(f.drain_for_proposal().is_empty());
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
