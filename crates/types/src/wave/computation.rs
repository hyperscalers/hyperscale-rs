//! Block-derived helpers: wave assignment, per-target provision merkle roots,
//! and wave-leader selection.

use crate::{
    Attempt, BlockHeight, Hash, ProvisionTxRoot, RoutableTransaction, ShardGroupId,
    TopologySnapshot, ValidatorId, WaveId, compute_padded_merkle_root,
};
use sbor::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Compute the set of cross-shard waves for a block's transactions.
///
/// Each transaction's remote shard set (shards it touches minus local shard)
/// defines its wave. Transactions with identical remote shard sets belong to
/// the same wave. Wave-zero (single-shard txs) is excluded.
///
/// Returns a sorted `Vec<WaveId>` with fully populated shard + height fields.
/// (Deterministic via `BTreeSet` ordering.)
/// Used in both block proposal (to populate `BlockHeader::waves`) and
/// validation (to verify the header's waves field).
pub fn compute_waves(
    topology: &TopologySnapshot,
    block_height: BlockHeight,
    transactions: &[Arc<RoutableTransaction>],
) -> Vec<WaveId> {
    let local_shard = topology.local_shard();
    let mut remote_shard_sets: BTreeSet<BTreeSet<ShardGroupId>> = BTreeSet::new();

    for tx in transactions {
        if topology.is_single_shard_transaction(tx) {
            continue;
        }
        let remote_shards: BTreeSet<ShardGroupId> = topology
            .all_shards_for_transaction(tx)
            .into_iter()
            .filter(|&s| s != local_shard)
            .collect();
        if !remote_shards.is_empty() {
            remote_shard_sets.insert(remote_shards);
        }
    }

    remote_shard_sets
        .into_iter()
        .map(|remote_shards| WaveId {
            shard_group_id: local_shard,
            block_height,
            remote_shards,
        })
        .collect()
}

/// Per-target-shard merkle commitment over the tx hashes destined for each
/// target shard in a block's cross-shard provisions.
///
/// For each cross-shard tx, emit the tx hash into the bucket of every remote
/// shard that tx touches. The resulting per-target leaves are merkle-committed
/// in block order (already hash-ascending) so the target shard can verify a
/// received `Provisions` contains the full set it was meant to receive.
///
/// Only emits an entry for targets with ≥1 tx. Empty for blocks with no
/// cross-shard txs.
pub fn compute_provision_tx_roots(
    topology: &TopologySnapshot,
    transactions: &[Arc<RoutableTransaction>],
) -> BTreeMap<ShardGroupId, ProvisionTxRoot> {
    let local_shard = topology.local_shard();
    let mut per_target: BTreeMap<ShardGroupId, Vec<Hash>> = BTreeMap::new();

    for tx in transactions {
        if topology.is_single_shard_transaction(tx) {
            continue;
        }
        for shard in topology.all_shards_for_transaction(tx) {
            if shard == local_shard {
                continue;
            }
            per_target
                .entry(shard)
                .or_default()
                .push(tx.hash().into_raw());
        }
    }

    per_target
        .into_iter()
        .map(|(shard, hashes)| {
            (
                shard,
                ProvisionTxRoot::from_raw(compute_padded_merkle_root(&hashes)),
            )
        })
        .collect()
}

/// Deterministically select the wave leader for a wave (attempt 0).
///
/// The wave leader collects execution votes, aggregates the EC, and
/// broadcasts it to local peers and remote shards. Convenience wrapper
/// for `wave_leader_at(wave_id, 0, committee)`.
#[must_use]
pub fn wave_leader(wave_id: &WaveId, committee: &[ValidatorId]) -> ValidatorId {
    wave_leader_at(wave_id, Attempt::INITIAL, committee)
}

/// Deterministically select the wave leader with rotation for fallback.
///
/// Each `attempt` selects a different validator from the committee, enabling
/// leader rotation when the primary leader (attempt=0) fails. Validators
/// re-send their vote to `wave_leader_at(wave_id, attempt+1, committee)`
/// after a timeout.
///
/// Uses `Hash(sbor_encode(wave_id) ++ attempt.to_le_bytes()) % committee_size`
/// for deterministic selection. All validators compute the same result.
///
/// # Panics
///
/// Panics if `committee` is empty.
#[must_use]
pub fn wave_leader_at(
    wave_id: &WaveId,
    attempt: Attempt,
    committee: &[ValidatorId],
) -> ValidatorId {
    assert!(!committee.is_empty(), "committee must not be empty");
    let mut buf = basic_encode(wave_id).expect("WaveId serialization should never fail");
    buf.extend_from_slice(&attempt.to_le_bytes());
    let selection_hash = Hash::from_bytes(&buf);
    let bytes = selection_hash.as_bytes();
    let index_val = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let index = usize::try_from(index_val % committee.len() as u64)
        .expect("modulo of usize len fits in usize");
    committee[index]
}
