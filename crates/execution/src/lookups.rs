//! Pure topology-derived helpers used by the execution coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, ExecutionCertificate, NodeId, RoutableTransaction, ShardId,
    TopologySnapshot, ValidatorId, Verifiable, VoteCount, WaveId,
};

/// Per-shard recipient lists for provision broadcasting.
pub type ShardRecipients = HashMap<ShardId, Vec<ValidatorId>>;

/// A single tx's layout within a wave: the transaction plus the set of shards
/// that participate in its execution (local + any remote provision sources).
pub type WaveTxEntry = (Arc<Verifiable<RoutableTransaction>>, BTreeSet<ShardId>);

/// Deterministic grouping of a block's transactions into waves.
pub type WaveAssignments = BTreeMap<WaveId, Vec<WaveTxEntry>>;

/// Committee members of `shard` with the local validator filtered out.
///
/// Used for broadcast-style actions (e.g. `BroadcastExecutionCertificate`,
/// provision fetch) that fan out to every other member of a committee. Works
/// for both the local shard (self is always a member, filter removes exactly
/// one entry) and remote shards (filter is a no-op when self isn't a member).
pub fn peers_excluding_self(
    topology_snapshot: &TopologySnapshot,
    me: ValidatorId,
    shard: ShardId,
) -> Vec<ValidatorId> {
    topology_snapshot
        .committee_for_shard(shard)
        .iter()
        .copied()
        .filter(|&v| v != me)
        .collect()
}

/// True if `ec.signers()` represents at least 2f+1 of the voting power on
/// `ec.shard_id()`. Mirrors `qc_has_local_quorum_power` (in the shard consensus
/// crate) but resolves committee + voting power for the EC's own shard,
/// since cross-shard ECs are signed by remote committees.
#[must_use]
pub fn ec_has_shard_quorum_power(
    topology_sbapshot: &TopologySnapshot,
    ec: &ExecutionCertificate,
) -> bool {
    let shard = ec.shard_id();
    let committee = topology_sbapshot.consensus_committee_for_shard(shard);
    let signers_power: VoteCount = ec
        .signers()
        .set_indices()
        .filter_map(|i| committee.get(i))
        .map(|&vid| {
            topology_sbapshot
                .vote_of(vid)
                .expect("committee member has voting power (TopologySnapshot invariant)")
        })
        .sum();
    VoteCount::has_quorum(signers_power, topology_sbapshot.committee_votes(shard))
}

/// Public keys for a shard's consensus committee, in canonical order —
/// the positions EC signer bitfields index into.
///
/// Returns `None` if any committee member's public key is missing from the
/// topology — a signal the snapshot is corrupt and verification should not
/// proceed with a partial key set.
pub fn committee_public_keys_for_shard(
    topology_snapshot: &TopologySnapshot,
    shard: ShardId,
) -> Option<Vec<Bls12381G1PublicKey>> {
    let committee = topology_snapshot.consensus_committee_for_shard(shard);
    let mut pubkeys = Vec::with_capacity(committee.len());
    for &vid in committee {
        pubkeys.push(topology_snapshot.public_key(vid)?);
    }
    Some(pubkeys)
}

/// Compute deterministic wave assignments for a block's transactions.
///
/// Partitions transactions by their provision dependency set (remote shards
/// needed). All validators compute identical assignments from the same block.
///
/// Returns a map from `WaveId` to list of (tx, `participating_shards`) in
/// block order within each wave.
pub fn assign_waves(
    topology_snapshot: &TopologySnapshot,
    local_shard: ShardId,
    block_height: BlockHeight,
    transactions: &[Arc<Verifiable<RoutableTransaction>>],
) -> WaveAssignments {
    let mut waves: WaveAssignments = BTreeMap::new();

    for tx in transactions {
        // Compute provision dependency set = remote shards needed
        let all_shards: BTreeSet<ShardId> = topology_snapshot
            .all_shards_for_transaction(tx)
            .into_iter()
            .collect();

        let remote_shards: BTreeSet<ShardId> = all_shards
            .iter()
            .filter(|&&s| s != local_shard)
            .copied()
            .collect();

        let wave_id = WaveId::new(local_shard, block_height, remote_shards);

        waves
            .entry(wave_id)
            .or_default()
            .push((Arc::clone(tx), all_shards));
    }

    waves
}

/// Build provision requests and shard recipients for cross-shard transactions.
///
/// Returns `None` if there are no cross-shard transactions needing provisions.
pub fn build_provision_requests(
    topology_snapshot: &TopologySnapshot,
    transactions: &[Arc<Verifiable<RoutableTransaction>>],
    me: ValidatorId,
    local_shard: ShardId,
) -> Option<(Vec<ProvisionsRequest>, ShardRecipients)> {
    let local_vid = me;

    let mut provision_requests = Vec::new();
    for tx in transactions {
        if topology_snapshot.is_single_shard_transaction(tx) {
            continue;
        }
        let all_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .copied()
            .collect();

        let mut owned_nodes: Vec<NodeId> = all_nodes
            .iter()
            .copied()
            .filter(|n| topology_snapshot.shard_for_node_id(n) == local_shard)
            .collect();
        owned_nodes.sort();
        owned_nodes.dedup();

        if owned_nodes.is_empty() {
            continue;
        }

        // Per-target-shard node needs for conflict detection on the remote side.
        let mut target_nodes: Vec<(ShardId, Vec<NodeId>)> = Vec::new();
        for target_shard in topology_snapshot
            .all_shards_for_transaction(tx)
            .into_iter()
            .filter(|&s| s != local_shard)
        {
            let mut needed: Vec<NodeId> = all_nodes
                .iter()
                .copied()
                .filter(|n| topology_snapshot.shard_for_node_id(n) == target_shard)
                .collect();
            // Canonicalise so gossip-emitted and fetch-served `ProvisionEntry`s
            // hash identically — `serve_provision_request` sorts and dedups too.
            needed.sort();
            needed.dedup();
            target_nodes.push((target_shard, needed));
        }

        if !target_nodes.is_empty() {
            provision_requests.push(ProvisionsRequest {
                tx_hash: tx.hash(),
                local_nodes: owned_nodes,
                target_nodes,
            });
        }
    }

    if provision_requests.is_empty() {
        return None;
    }

    let mut shard_recipients = HashMap::new();
    for req in &provision_requests {
        for &(target_shard, _) in &req.target_nodes {
            shard_recipients.entry(target_shard).or_insert_with(|| {
                topology_snapshot
                    .committee_for_shard(target_shard)
                    .iter()
                    .copied()
                    .filter(|&v| v != local_vid)
                    .collect()
            });
        }
    }

    Some((provision_requests, shard_recipients))
}

#[cfg(test)]
mod tests {
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{NetworkDefinition, ValidatorInfo, ValidatorSet};

    use super::*;

    fn single_shard_topology(committee: &TestCommittee) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set)
    }

    // ─── peers_excluding_self ───────────────────────────────────────────

    #[test]
    fn peers_excluding_self_drops_local_validator() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let peers = peers_excluding_self(&topology_snapshot, ValidatorId::new(0), ShardId::ROOT);
        assert_eq!(peers.len(), 3);
        assert!(!peers.contains(&ValidatorId::new(0)));
        assert!(peers.contains(&ValidatorId::new(1)));
        assert!(peers.contains(&ValidatorId::new(2)));
        assert!(peers.contains(&ValidatorId::new(3)));
    }

    #[test]
    fn peers_excluding_self_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        // Shard 99 has no committee — filter returns an empty vec regardless
        // of who the local validator is.
        let peers = peers_excluding_self(
            &topology_snapshot,
            ValidatorId::new(0),
            ShardId::leaf(8, 99),
        );
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_excluding_self_empty_when_solo_validator() {
        let committee = TestCommittee::new(1, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let peers = peers_excluding_self(&topology_snapshot, ValidatorId::new(0), ShardId::ROOT);
        assert!(peers.is_empty());
    }

    // ─── committee_public_keys_for_shard ────────────────────────────────

    #[test]
    fn committee_public_keys_for_shard_returns_keys_in_order() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let keys = committee_public_keys_for_shard(&topology_snapshot, ShardId::ROOT)
            .expect("well-formed topology resolves every key");
        assert_eq!(keys.len(), 4);

        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key, committee.public_key(i));
        }
    }

    #[test]
    fn committee_public_keys_for_shard_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        // An unknown shard has an empty committee, so the result is
        // `Some(vec![])` — not `None` (which is reserved for corruption).
        let keys = committee_public_keys_for_shard(&topology_snapshot, ShardId::leaf(8, 99))
            .expect("empty committee is not corruption");
        assert!(keys.is_empty());
    }
}
