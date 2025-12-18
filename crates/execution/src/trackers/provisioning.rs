//! Provisioning tracker for cross-shard state coordination.
//!
//! Tracks the collection of state provisions from source shards during
//! Phase 1-2 of the cross-shard 2PC protocol.

use hyperscale_types::{Hash, ShardGroupId, StateProvision};
use std::collections::{BTreeSet, HashMap};

/// Tracks provisioning state for a cross-shard transaction.
///
/// During cross-shard execution, validators need to collect state from
/// all shards that own data accessed by the transaction. This tracker
/// monitors provision reception and determines when quorum is reached
/// for each source shard.
#[derive(Debug)]
pub struct ProvisioningTracker {
    /// Transaction hash.
    tx_hash: Hash,
    /// Shards we need provisions from (source shards that own state we read/write).
    required_shards: BTreeSet<ShardGroupId>,
    /// Provisions received, grouped by source shard.
    provisions_by_shard: HashMap<ShardGroupId, Vec<StateProvision>>,
    /// Quorum threshold per shard: (2n+1)/3.
    quorum_thresholds: HashMap<ShardGroupId, usize>,
}

impl ProvisioningTracker {
    /// Create a new provisioning tracker.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction being tracked
    /// * `required_shards` - Set of shards we need provisions from
    /// * `quorum_thresholds` - Required provision count per shard for quorum
    pub fn new(
        tx_hash: Hash,
        required_shards: BTreeSet<ShardGroupId>,
        quorum_thresholds: HashMap<ShardGroupId, usize>,
    ) -> Self {
        Self {
            tx_hash,
            required_shards,
            provisions_by_shard: HashMap::new(),
            quorum_thresholds,
        }
    }

    /// Get the transaction hash this tracker is for.
    pub fn tx_hash(&self) -> Hash {
        self.tx_hash
    }

    /// Add a provision. Returns true if provisioning is now complete.
    pub fn add_provision(&mut self, provision: StateProvision) -> bool {
        let source_shard = provision.source_shard;

        if !self.required_shards.contains(&source_shard) {
            return false;
        }

        self.provisions_by_shard
            .entry(source_shard)
            .or_default()
            .push(provision);

        self.is_complete()
    }

    /// Check if we have quorum from all required shards.
    pub fn is_complete(&self) -> bool {
        for shard in &self.required_shards {
            let count = self
                .provisions_by_shard
                .get(shard)
                .map(|p| p.len())
                .unwrap_or(0);
            let threshold = self.quorum_thresholds.get(shard).copied().unwrap_or(1);
            if count < threshold {
                return false;
            }
        }
        true
    }

    /// Get the provisioned state (one provision per shard, using majority).
    ///
    /// Returns `Some` with provisions from all required shards if quorum is
    /// reached, with majority-selected provision for each shard. Returns
    /// `None` if not all shards have reached quorum yet.
    pub fn get_provisioned_state(&self) -> Option<Vec<StateProvision>> {
        let mut result = Vec::new();

        for shard in &self.required_shards {
            let provisions = self.provisions_by_shard.get(shard)?;

            // Compute entries_hash once per provision and cache with index
            let hashed: Vec<_> = provisions
                .iter()
                .enumerate()
                .map(|(i, p)| (p.entries_hash(), i))
                .collect();

            // Count occurrences of each hash
            let mut counts: HashMap<Hash, usize> = HashMap::new();
            for (hash, _) in &hashed {
                *counts.entry(*hash).or_default() += 1;
            }

            let threshold = self.quorum_thresholds.get(shard).copied().unwrap_or(1);

            // Find a provision with quorum (using cached hash)
            for (hash, idx) in hashed {
                if counts.get(&hash).copied().unwrap_or(0) >= threshold {
                    result.push(provisions[idx].clone());
                    break;
                }
            }
        }

        if result.len() == self.required_shards.len() {
            Some(result)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, Signature, ValidatorId};

    #[test]
    fn test_provisioning_tracker_basic() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);

        let mut thresholds = HashMap::new();
        thresholds.insert(shard0, 2);
        thresholds.insert(shard1, 2);

        let required = [shard0, shard1].into_iter().collect();
        let mut tracker = ProvisioningTracker::new(tx_hash, required, thresholds);

        // Not complete yet
        assert!(!tracker.is_complete());

        // Add provisions from shard0
        let p0a = StateProvision {
            transaction_hash: tx_hash,
            target_shard: ShardGroupId(2),
            source_shard: shard0,
            block_height: BlockHeight(1),
            entries: vec![],
            validator_id: ValidatorId(0),
            signature: Signature::zero(),
        };
        let p0b = p0a.clone();

        assert!(!tracker.add_provision(p0a));
        assert!(!tracker.add_provision(p0b)); // Still not complete, missing shard1

        // Add provisions from shard1
        let p1a = StateProvision {
            transaction_hash: tx_hash,
            target_shard: ShardGroupId(2),
            source_shard: shard1,
            block_height: BlockHeight(1),
            entries: vec![],
            validator_id: ValidatorId(1),
            signature: Signature::zero(),
        };
        let p1b = p1a.clone();

        assert!(!tracker.add_provision(p1a));
        assert!(tracker.add_provision(p1b)); // Now complete
    }

    #[test]
    fn test_ignores_unknown_shard() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);

        let mut thresholds = HashMap::new();
        thresholds.insert(shard0, 1);

        let required = [shard0].into_iter().collect();
        let mut tracker = ProvisioningTracker::new(tx_hash, required, thresholds);

        // Provision from unknown shard
        let provision = StateProvision {
            transaction_hash: tx_hash,
            target_shard: ShardGroupId(2),
            source_shard: ShardGroupId(99), // Unknown
            block_height: BlockHeight(1),
            entries: vec![],
            validator_id: ValidatorId(0),
            signature: Signature::zero(),
        };

        assert!(!tracker.add_provision(provision));
        assert!(!tracker.is_complete());
    }
}
