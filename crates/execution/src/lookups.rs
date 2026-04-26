//! Pure topology-derived helpers used by the execution coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use hyperscale_types::{Bls12381G1PublicKey, ShardGroupId, TopologySnapshot, ValidatorId};

/// Committee members of `shard` with the local validator filtered out.
///
/// Used for broadcast-style actions (e.g. `BroadcastExecutionCertificate`,
/// provision fetch) that fan out to every other member of a committee. Works
/// for both the local shard (self is always a member, filter removes exactly
/// one entry) and remote shards (filter is a no-op when self isn't a member).
pub fn peers_excluding_self(topology: &TopologySnapshot, shard: ShardGroupId) -> Vec<ValidatorId> {
    let self_id = topology.local_validator_id();
    topology
        .committee_for_shard(shard)
        .iter()
        .copied()
        .filter(|&v| v != self_id)
        .collect()
}

/// Public keys for a shard's committee, in canonical committee order.
///
/// Returns `None` if any committee member's public key is missing from the
/// topology — a signal the snapshot is corrupt and verification should not
/// proceed with a partial key set.
pub fn committee_public_keys_for_shard(
    topology: &TopologySnapshot,
    shard: ShardGroupId,
) -> Option<Vec<Bls12381G1PublicKey>> {
    let committee = topology.committee_for_shard(shard);
    let mut pubkeys = Vec::with_capacity(committee.len());
    for &vid in committee {
        pubkeys.push(topology.public_key(vid)?);
    }
    Some(pubkeys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{ValidatorInfo, ValidatorSet};

    fn single_shard_topology(local_idx: usize, committee: &TestCommittee) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(committee.validator_id(local_idx), 1, validator_set)
    }

    // ─── peers_excluding_self ───────────────────────────────────────────

    #[test]
    fn peers_excluding_self_drops_local_validator() {
        let committee = TestCommittee::new(4, 42);
        let topology = single_shard_topology(0, &committee);

        let peers = peers_excluding_self(&topology, topology.local_shard());
        assert_eq!(peers.len(), 3);
        assert!(!peers.contains(&ValidatorId(0)));
        assert!(peers.contains(&ValidatorId(1)));
        assert!(peers.contains(&ValidatorId(2)));
        assert!(peers.contains(&ValidatorId(3)));
    }

    #[test]
    fn peers_excluding_self_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology = single_shard_topology(0, &committee);

        // Shard 99 has no committee — filter returns an empty vec regardless
        // of who the local validator is.
        let peers = peers_excluding_self(&topology, ShardGroupId(99));
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_excluding_self_empty_when_solo_validator() {
        let committee = TestCommittee::new(1, 42);
        let topology = single_shard_topology(0, &committee);

        let peers = peers_excluding_self(&topology, topology.local_shard());
        assert!(peers.is_empty());
    }

    // ─── committee_public_keys_for_shard ────────────────────────────────

    #[test]
    fn committee_public_keys_for_shard_returns_keys_in_order() {
        let committee = TestCommittee::new(4, 42);
        let topology = single_shard_topology(0, &committee);

        let keys = committee_public_keys_for_shard(&topology, topology.local_shard())
            .expect("well-formed topology resolves every key");
        assert_eq!(keys.len(), 4);

        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key, committee.public_key(i));
        }
    }

    #[test]
    fn committee_public_keys_for_shard_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology = single_shard_topology(0, &committee);

        // An unknown shard has an empty committee, so the result is
        // `Some(vec![])` — not `None` (which is reserved for corruption).
        let keys = committee_public_keys_for_shard(&topology, ShardGroupId(99))
            .expect("empty committee is not corruption");
        assert!(keys.is_empty());
    }
}
