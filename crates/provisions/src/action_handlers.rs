//! Pure provision functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the source-side work for `FetchAndBroadcastProvisions`:
//! reading state entries at a committed block height (via the JMT history) and
//! grouping them by target shard with merkle inclusion proofs. They are kept
//! free of node/runner concerns so the dispatcher only handles event plumbing.

use hyperscale_core::ProvisionsRequest;
use hyperscale_engine::{Engine, sharding::expand_nodes_with_owned_at_height};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_storage::{SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::{
    BlockHeight, NodeId, Provisions, ShardGroupId, StateEntry, TxEntries, TxHash, ValidatorId,
};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::Arc;
use tracing::warn;

/// Per-tx fetched entries: (`tx_hash`, `target_shards_with_nodes`, `state_entries`).
type FetchedTxEntries = (
    TxHash,
    Vec<(ShardGroupId, Vec<NodeId>)>,
    Arc<Vec<StateEntry>>,
);

/// One outbound provision batch destined for a single target shard.
pub type ProvisionBatch = (Provisions, Vec<ValidatorId>);

/// Fetch state entries and assemble per-shard provision batches with merkle proofs.
///
/// Returns an empty `Vec` when no entries could be fetched (e.g. JMT version
/// unavailable for `block_height`); callers still emit a `ProvisionsReady` event
/// so the state machine can mark the action complete.
pub fn fetch_and_broadcast_provision<S, E, H>(
    executor: &E,
    view: &SubstateView<S>,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    requests: &[ProvisionsRequest],
    shard_recipients: &HashMap<ShardGroupId, Vec<ValidatorId>, H>,
) -> Vec<ProvisionBatch>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
    E: Engine,
    H: BuildHasher,
{
    let per_tx = fetch_entries_for_requests(executor, view, requests, source_shard, block_height);
    if per_tx.is_empty() {
        warn!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            request_count = requests.len(),
            "All fetch_state_entries failed — no provisions to broadcast"
        );
        return Vec::new();
    }
    build_provision_groups(view, per_tx, source_shard, block_height, shard_recipients)
}

/// Fetch state entries for each provision request at the committed block height.
///
/// Expands declared account `NodeId`s to include their owned vaults before
/// fetching. The remote shard needs vault substates (balances) to execute
/// transfers, not just the account's own substates.
fn fetch_entries_for_requests<S, E>(
    executor: &E,
    view: &SubstateView<S>,
    requests: &[ProvisionsRequest],
    source_shard: ShardGroupId,
    block_height: BlockHeight,
) -> Vec<FetchedTxEntries>
where
    S: SubstateStore + VersionedStore,
    E: Engine,
{
    let mut per_tx = Vec::with_capacity(requests.len());
    for req in requests {
        // Must use historical reads — current state may have new vaults that don't
        // exist at block_height, causing the merkle proof to fail on the remote shard.
        let Some(expanded_nodes) =
            expand_nodes_with_owned_at_height(view, &req.nodes, block_height)
        else {
            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                tx_hash = %req.tx_hash,
                "expand_nodes_with_owned_at_height: JMT version unavailable"
            );
            continue;
        };
        let Some(entries) = executor.fetch_state_entries(view, &expanded_nodes, block_height)
        else {
            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                tx_hash = %req.tx_hash,
                node_count = expanded_nodes.len(),
                "fetch_state_entries returned None — JMT version unavailable"
            );
            continue;
        };
        per_tx.push((req.tx_hash, req.targets.clone(), Arc::new(entries)));
    }
    per_tx
}

/// Group fetched entries by target shard and generate one merkle proof per shard.
fn build_provision_groups<S, H>(
    view: &SubstateView<S>,
    per_tx: Vec<FetchedTxEntries>,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    shard_recipients: &HashMap<ShardGroupId, Vec<ValidatorId>, H>,
) -> Vec<ProvisionBatch>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
    H: BuildHasher,
{
    let mut shard_tx_entries: HashMap<ShardGroupId, Vec<TxEntries>> = HashMap::new();
    for (tx_hash, targets, entries) in per_tx {
        for (target_shard, target_nodes) in targets {
            shard_tx_entries
                .entry(target_shard)
                .or_default()
                .push(TxEntries {
                    tx_hash,
                    entries: (*entries).clone(),
                    target_nodes,
                });
        }
    }

    let mut sorted_shard_entries: Vec<_> = shard_tx_entries.into_iter().collect();
    sorted_shard_entries.sort_by_key(|(shard, _)| *shard);
    let mut batches = Vec::with_capacity(sorted_shard_entries.len());
    for (shard, transactions) in sorted_shard_entries {
        let mut shard_keys: Vec<Vec<u8>> = transactions
            .iter()
            .flat_map(|te| te.entries.iter().map(|e| e.storage_key.clone()))
            .collect();
        shard_keys.sort();
        shard_keys.dedup();

        let Some(proof) = view.generate_merkle_proofs_overlay(&shard_keys, block_height) else {
            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                target_shard = shard.0,
                key_count = shard_keys.len(),
                "generate_merkle_proofs returned None — JMT version unavailable"
            );
            continue;
        };

        let recipients = shard_recipients.get(&shard).cloned().unwrap_or_default();
        let provisions = Provisions::new(source_shard, shard, block_height, proof, transactions);
        batches.push((provisions, recipients));
    }
    batches
}
