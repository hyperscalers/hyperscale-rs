//! Buffered shard double-vote evidence awaiting inclusion in a beacon
//! proposal.
//!
//! Two-staged like the fork-proof observer
//! ([`ForkProofObservations`](crate::fork_observations::ForkProofObservations)),
//! and for the same reason: a drain is not a delivery. A proposal lost
//! to a skip epoch or to admission never folds, and evidence taken for
//! it and not restored is gone from this node for good — a double-vote
//! nobody can be convicted of.

use std::collections::BTreeMap;

use hyperscale_types::{ShardVoteEquivocation, ValidatorId};

/// Locally verified [`ShardVoteEquivocation`] pairs, keyed by the
/// accused validator — first observation wins, since one pair per key
/// is enough to convict and later copies add nothing.
#[derive(Debug, Default)]
pub struct VoteEquivocationObservations {
    /// Evidence awaiting the next proposal build.
    by_validator: BTreeMap<ValidatorId, Box<ShardVoteEquivocation>>,
    /// Evidence drained into a proposal whose fold has not yet revoked
    /// the accused. Restored by
    /// [`restore_undelivered`](Self::restore_undelivered) after each
    /// fold's prune.
    in_flight: BTreeMap<ValidatorId, Box<ShardVoteEquivocation>>,
}

impl VoteEquivocationObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one verified pair. Returns `true` if it was newly
    /// recorded, `false` if evidence for the validator is already held
    /// or riding an unconfirmed proposal.
    pub fn record(&mut self, evidence: ShardVoteEquivocation) -> bool {
        use std::collections::btree_map::Entry;
        if self.in_flight.contains_key(&evidence.validator) {
            return false;
        }
        match self.by_validator.entry(evidence.validator) {
            Entry::Vacant(slot) => {
                slot.insert(Box::new(evidence));
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Drain all observed evidence for a proposal build, moving each
    /// entry into the in-flight buffer until a fold confirms it.
    ///
    /// The proposer caps the returned slice against its per-proposer
    /// limit and hands the overflow back through
    /// [`retain_overflow`](Self::retain_overflow), which puts it where
    /// the next build will find it — `record` would refuse it, since a
    /// drained entry is in flight.
    pub fn drain_for_proposal(&mut self) -> Vec<ShardVoteEquivocation> {
        let drained = std::mem::take(&mut self.by_validator);
        let out = drained.values().map(|boxed| (**boxed).clone()).collect();
        self.in_flight.extend(drained);
        out
    }

    /// Put evidence the proposer's cap left out of this build back where
    /// the next one will find it.
    pub fn retain_overflow(&mut self, evidence: ShardVoteEquivocation) {
        let v = evidence.validator;
        self.in_flight.remove(&v);
        self.by_validator.insert(v, Box::new(evidence));
    }

    /// Drop every buffered or in-flight entry whose validator `obsolete`
    /// matches. The coordinator calls this after each `apply_epoch` with
    /// "key already revoked" — once the fold holds that status,
    /// re-proposing the evidence can't change anything.
    pub fn prune(&mut self, mut obsolete: impl FnMut(ValidatorId) -> bool) {
        self.by_validator.retain(|v, _| !obsolete(*v));
        self.in_flight.retain(|v, _| !obsolete(*v));
    }

    /// Restore every in-flight entry that survived the fold's prune: its
    /// proposal was discarded (a skip epoch, or lost to admission), so
    /// the accused was never revoked and the evidence re-enters the next
    /// proposal build.
    pub fn restore_undelivered(&mut self) {
        let undelivered = std::mem::take(&mut self.in_flight);
        self.by_validator.extend(undelivered);
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl VoteEquivocationObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_validator.len() + self.in_flight.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_validator.is_empty() && self.in_flight.is_empty()
    }

    #[must_use]
    pub fn contains(&self, validator: ValidatorId) -> bool {
        self.by_validator.contains_key(&validator) || self.in_flight.contains_key(&validator)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHash, BlockHeight, ConsensusSignature, Hash, Round, ShardId};

    use super::*;

    fn pair(v: u64) -> ShardVoteEquivocation {
        ShardVoteEquivocation {
            validator: ValidatorId::new(v),
            shard: ShardId::ROOT,
            height: BlockHeight::new(5),
            round: Round::new(2),
            block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"a")),
            parent_block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"pa")),
            sig_a: ConsensusSignature::ZERO,
            block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"b")),
            parent_block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"pb")),
            sig_b: ConsensusSignature::ZERO,
        }
    }

    #[test]
    fn first_observation_wins() {
        let mut buf = VoteEquivocationObservations::new();
        assert!(buf.record(pair(1)));
        assert!(!buf.record(pair(1)));
        assert_eq!(buf.len(), 1);
    }

    /// A drain is not a delivery. What it takes rides the proposal and
    /// stays held until a fold either revokes the accused or the prune
    /// hands it back — a proposal lost to a skip epoch would otherwise
    /// take the evidence with it, and nobody could be convicted.
    #[test]
    fn a_drain_holds_its_evidence_until_the_fold_answers() {
        let mut buf = VoteEquivocationObservations::new();
        buf.record(pair(1));
        buf.record(pair(2));

        let drained = buf.drain_for_proposal();
        assert_eq!(drained.len(), 2);
        assert_eq!(buf.len(), 2, "still held, in flight");
        assert!(
            !buf.record(pair(1)),
            "a re-observation adds nothing to evidence already riding a proposal"
        );

        // The proposal never folded, so the evidence comes back.
        buf.restore_undelivered();
        assert_eq!(buf.drain_for_proposal().len(), 2);

        // And a fold that revoked the accused takes it for good.
        buf.prune(|_| true);
        buf.restore_undelivered();
        assert!(buf.is_empty());
    }

    /// Evidence the proposer's cap left out of a build goes back where
    /// the next build looks, which `record` would refuse: the entry is
    /// in flight from the drain that produced it.
    #[test]
    fn overflow_returns_to_the_next_build() {
        let mut buf = VoteEquivocationObservations::new();
        buf.record(pair(1));
        let mut drained = buf.drain_for_proposal();

        buf.retain_overflow(drained.pop().expect("one pair was drained"));
        assert_eq!(buf.drain_for_proposal().len(), 1);
    }

    #[test]
    fn prune_drops_obsolete_validators() {
        let mut buf = VoteEquivocationObservations::new();
        buf.record(pair(1));
        buf.record(pair(2));
        buf.prune(|v| v == ValidatorId::new(1));
        assert!(!buf.contains(ValidatorId::new(1)));
        assert!(buf.contains(ValidatorId::new(2)));
    }
}
