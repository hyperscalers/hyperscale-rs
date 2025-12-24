//! Vote tracker for cross-shard execution voting.
//!
//! Tracks the collection of execution votes during Phase 4 of the
//! cross-shard 2PC protocol.

use hyperscale_types::{Hash, NodeId, ShardGroupId, StateVoteBlock};
use std::collections::BTreeMap;
use tracing::instrument;

/// Tracks votes for a cross-shard transaction.
///
/// After executing a transaction with provisioned state, validators create
/// votes on the execution result (merkle root). This tracker collects votes
/// and determines when quorum is reached.
#[derive(Debug)]
pub struct VoteTracker {
    /// Transaction hash.
    tx_hash: Hash,
    /// Participating shards (for broadcasting certificate).
    participating_shards: Vec<ShardGroupId>,
    /// Read nodes from transaction.
    read_nodes: Vec<NodeId>,
    /// Votes grouped by merkle root.
    votes_by_root: BTreeMap<Hash, Vec<StateVoteBlock>>,
    /// Voting power per merkle root.
    power_by_root: BTreeMap<Hash, u64>,
    /// Quorum threshold (2f+1).
    quorum: u64,
}

impl VoteTracker {
    /// Create a new vote tracker.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction being tracked
    /// * `participating_shards` - All shards involved in this transaction
    /// * `read_nodes` - Nodes read by this transaction
    /// * `quorum` - Voting power required for quorum
    pub fn new(
        tx_hash: Hash,
        participating_shards: Vec<ShardGroupId>,
        read_nodes: Vec<NodeId>,
        quorum: u64,
    ) -> Self {
        Self {
            tx_hash,
            participating_shards,
            read_nodes,
            votes_by_root: BTreeMap::new(),
            power_by_root: BTreeMap::new(),
            quorum,
        }
    }

    /// Get the participating shards.
    pub fn participating_shards(&self) -> &[ShardGroupId] {
        &self.participating_shards
    }

    /// Get the read nodes.
    pub fn read_nodes(&self) -> &[NodeId] {
        &self.read_nodes
    }

    /// Add a vote and its voting power.
    #[instrument(level = "debug", skip(self, vote), fields(
        tx_hash = %self.tx_hash,
        validator = vote.validator.0,
        power = power,
        quorum = self.quorum,
    ))]
    pub fn add_vote(&mut self, vote: StateVoteBlock, power: u64) {
        let state_root = vote.state_root;
        self.votes_by_root.entry(state_root).or_default().push(vote);
        *self.power_by_root.entry(state_root).or_insert(0) += power;
    }

    /// Check if quorum is reached for any merkle root.
    ///
    /// Returns `Some((merkle_root, total_power))` if quorum is reached, `None` otherwise.
    /// Use `votes_for_root()` to get the actual votes after checking quorum.
    pub fn check_quorum(&self) -> Option<(Hash, u64)> {
        for (merkle_root, power) in &self.power_by_root {
            if *power >= self.quorum {
                return Some((*merkle_root, *power));
            }
        }
        None
    }

    /// Get votes for a specific merkle root (reference).
    #[cfg(test)]
    pub fn votes_for_root(&self, merkle_root: &Hash) -> &[StateVoteBlock] {
        self.votes_by_root
            .get(merkle_root)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Take votes for a specific merkle root (ownership transfer, avoids clone).
    pub fn take_votes_for_root(&mut self, merkle_root: &Hash) -> Vec<StateVoteBlock> {
        self.votes_by_root.remove(merkle_root).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Signature, ValidatorId};

    #[test]
    fn test_vote_tracker_quorum() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");

        let mut tracker = VoteTracker::new(
            tx_hash,
            vec![ShardGroupId(0)],
            vec![],
            3, // quorum = 3
        );

        let vote = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            validator: ValidatorId(0),
            signature: Signature::zero(),
        };

        // Not quorum yet
        tracker.add_vote(vote.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_vote(vote.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_vote(vote.clone(), 1);

        // Now quorum
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (root, power) = result.unwrap();
        assert_eq!(root, merkle_root);
        assert_eq!(tracker.votes_for_root(&root).len(), 3);
        assert_eq!(power, 3);
    }

    #[test]
    fn test_vote_tracker_multiple_roots() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let root_a = Hash::from_bytes(b"root_a");
        let root_b = Hash::from_bytes(b"root_b");

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        let vote_a = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: root_a,
            success: true,
            validator: ValidatorId(0),
            signature: Signature::zero(),
        };

        let vote_b = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: root_b,
            success: true,
            validator: ValidatorId(1),
            signature: Signature::zero(),
        };

        // Split votes - no quorum
        tracker.add_vote(vote_a.clone(), 1);
        tracker.add_vote(vote_b.clone(), 1);
        tracker.add_vote(vote_a.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        // Third vote for root_a reaches quorum
        tracker.add_vote(vote_a.clone(), 1);
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (root, _power) = result.unwrap();
        assert_eq!(root, root_a);
    }
}
