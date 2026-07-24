//! Buffered shard double-vote evidence awaiting inclusion in a beacon
//! proposal.

use std::collections::BTreeMap;

use hyperscale_types::{ShardVoteEquivocation, ValidatorId};

/// Locally verified [`ShardVoteEquivocation`] pairs, keyed by the
/// accused validator — first observation wins, since one pair per key
/// is enough to convict and later copies add nothing.
#[derive(Debug, Default)]
pub struct VoteEquivocationObservations {
    by_validator: BTreeMap<ValidatorId, Box<ShardVoteEquivocation>>,
}

impl VoteEquivocationObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one verified pair. Returns `true` if it was newly
    /// recorded, `false` if evidence for the validator is already held.
    pub fn record(&mut self, evidence: ShardVoteEquivocation) -> bool {
        use std::collections::btree_map::Entry;
        match self.by_validator.entry(evidence.validator) {
            Entry::Vacant(slot) => {
                slot.insert(Box::new(evidence));
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Drain all observed evidence and empty the buffer. The proposer
    /// caps the returned slice against its per-proposer limit and
    /// re-records anything it dropped for the next epoch.
    pub fn drain_for_proposal(&mut self) -> Vec<ShardVoteEquivocation> {
        std::mem::take(&mut self.by_validator)
            .into_values()
            .map(|boxed| *boxed)
            .collect()
    }

    /// Drop every buffered entry whose validator `obsolete` matches.
    /// The coordinator calls this after each `apply_epoch` with "key
    /// already revoked" — once the fold holds that status, re-proposing
    /// the evidence can't change anything.
    pub fn prune(&mut self, mut obsolete: impl FnMut(ValidatorId) -> bool) {
        self.by_validator.retain(|v, _| !obsolete(*v));
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl VoteEquivocationObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_validator.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_validator.is_empty()
    }

    #[must_use]
    pub fn contains(&self, validator: ValidatorId) -> bool {
        self.by_validator.contains_key(&validator)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHash, BlockHeight, Hash, Round, ShardId, zero_bls_signature};

    use super::*;

    fn pair(v: u64) -> ShardVoteEquivocation {
        ShardVoteEquivocation {
            validator: ValidatorId::new(v),
            shard: ShardId::ROOT,
            height: BlockHeight::new(5),
            round: Round::new(2),
            block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"a")),
            parent_block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"pa")),
            sig_a: zero_bls_signature(),
            block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"b")),
            parent_block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"pb")),
            sig_b: zero_bls_signature(),
        }
    }

    #[test]
    fn first_observation_wins() {
        let mut buf = VoteEquivocationObservations::new();
        assert!(buf.record(pair(1)));
        assert!(!buf.record(pair(1)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn drain_empties_and_reobserves() {
        let mut buf = VoteEquivocationObservations::new();
        buf.record(pair(1));
        buf.record(pair(2));
        let drained = buf.drain_for_proposal();
        assert_eq!(drained.len(), 2);
        assert!(buf.is_empty());
        // A re-observation after the drain records again — the
        // coordinator re-records overflow this way.
        assert!(buf.record(pair(1)));
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
