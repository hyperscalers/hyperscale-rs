//! Shard assignment and write filtering for Radix Engine DatabaseUpdates.
//!
//! # The Problem
//!
//! The Radix Engine's object model doesn't align with our sharding model:
//!
//! - **Accounts** (`0x51`) are global entities assigned to shards by hash.
//! - **Vaults** (`0x58`) are internal entities whose NodeIds are random hashes
//!   (`hash(creating_tx_hash, counter)`) with NO structural relationship to their
//!   owning account. A vault's `outer_object` points to its **resource manager**
//!   (`0x5d`), not the account — because vaults are "inner objects" of the
//!   resource blueprint, not the account blueprint.
//! - A simple XRD transfer writes to vault nodes only — the account node itself
//!   is read-only (the KV store entry holding the `Own(vault_id)` doesn't change).
//! - The account→vault relationship is stored as `Own(vault_id)` in the account's
//!   KV store. There is NO back-pointer from vault to account.
//!
//! This means:
//! 1. We can't determine a vault's shard from its NodeId alone.
//! 2. We can't walk UP from vault to account (no back-pointer exists).
//! 3. We must walk DOWN from declared accounts to discover their vaults.
//!
//! # Current Scope: Proof of Concept for Simple Transfers
//!
//! This implementation handles the basic case where:
//! - Transactions are simple account-to-account transfers.
//! - The transaction manifest declares the involved **account NodeIds** as
//!   `declared_reads`/`declared_writes`.
//! - Each account's vaults are discovered by scanning account substates for
//!   SBOR-encoded `Own(NodeId)` references.
//!
//! **This is NOT a general solution.** A full implementation would require:
//! - **Transaction preview/simulation** before submission to discover the
//!   complete read/write set (all NodeIds actually touched by the Radix Engine,
//!   including vaults, KV stores, proofs, buckets, etc.).
//! - The preview would provide vault NodeIds directly, eliminating the need
//!   for the walk-down heuristic.
//! - Complex transactions (DEX swaps, multi-component calls) touch entities
//!   beyond simple account vaults and would need preview to correctly declare
//!   their full dependency set.
//!
//! # Approach
//!
//! Filtering happens in two stages:
//!
//! **Stage 1: Ownership resolution** ([`resolve_owned_nodes`])
//! Scans declared accounts' substates to discover which vault NodeIds they own.
//! Uses SBOR byte scanning to find `Own(NodeId)` references (tag `0x90` + 30 bytes).
//! Builds a map from each internal NodeId to its owning account.
//!
//! **Stage 2: Shard filtering** ([`filter_updates_for_shard`])
//! Applies three filters:
//! - System entities (ConsensusManager, TransactionTracker, Validator) are dropped.
//! - Nodes not owned by any declared account are dropped (prevents non-deterministic
//!   writes from undeclared entities like fee vaults).
//! - Nodes assigned to other shards (based on owning account's hash) are dropped.
//!
//! # Why filter undeclared writes?
//!
//! The mempool prevents concurrent access to declared accounts. But the Radix
//! Engine also writes to undeclared entities (e.g. fee/royalty vaults owned by
//! the resource manager). These writes are invisible to the mempool's conflict
//! detection. If two transactions both touch the same fee vault, validators
//! that execute at different committed heights see different vault balances,
//! producing different DatabaseUpdates and divergent state roots.

use hyperscale_storage::{DatabaseUpdates, DbPartitionKey, SubstateDatabase};
use hyperscale_types::{BlockHeight, NodeId, ShardGroupId};
use std::collections::{HashMap, HashSet};

/// System entity type bytes that should be filtered from DatabaseUpdates.
///
/// These are global system components whose state is replicated to all shards
/// and not yet set up for sharded consensus. Writes to these nodes must be
/// excluded from the per-shard state_root computation.
const SYSTEM_ENTITY_TYPES: &[u8] = &[
    0x86, // GlobalConsensusManager
    0x82, // GlobalTransactionTracker
    0x83, // GlobalValidator
];

/// Internal entity type bytes (children of a global entity).
const INTERNAL_ENTITY_TYPES: &[u8] = &[
    0x58, // InternalFungibleVault
    0x98, // InternalNonFungibleVault
    0xb0, // InternalKeyValueStore
    0x80, // InternalGenericComponent
];

/// SBOR custom value kind tag for `Own(NodeId)` references.
const SBOR_OWN_TAG: u8 = 0x90;

// ============================================================================
// Stage 1: Ownership Resolution
// ============================================================================

/// Maps internal NodeIds (vaults, KV stores) to their owning declared account.
///
/// For each declared account, scans all partition substates looking for
/// SBOR-encoded `Own(NodeId)` references. Returns a map from internal NodeId
/// to the account that owns it.
///
/// This is the "walk down" from accounts to vaults. It's necessary because
/// vaults have no back-pointer to their owning account — `outer_object` points
/// to the resource manager, not the account.
fn resolve_owned_nodes<S: SubstateDatabase>(
    storage: &S,
    declared_nodes: &[NodeId],
) -> HashMap<NodeId, NodeId> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut ownership: HashMap<NodeId, NodeId> = HashMap::new();

    for account in declared_nodes {
        let radix_node_id = radix_common::types::NodeId(account.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        // Scan all 256 partitions. Global entities use:
        //   0..63 — module partitions (metadata, royalties, etc.)
        //   64+   — main state partitions (fields, KV stores)
        for partition_num in 0..=255u8 {
            let pk = DbPartitionKey {
                node_key: db_node_key.clone(),
                partition_num,
            };
            for (_sort_key, value) in storage.list_raw_values_from_db_key(&pk, None) {
                extract_owned_node_ids(&value, *account, &mut ownership);
            }
        }
    }

    ownership
}

/// Scan raw SBOR bytes for `Own(NodeId)` references to internal entities.
///
/// SBOR encodes `Own` as: `[0x90, <30 bytes NodeId>]`.
/// We look for this tag followed by a known internal entity type byte.
/// False positives are near-impossible since NodeIds are random hashes.
fn extract_owned_node_ids(value: &[u8], owner: NodeId, ownership: &mut HashMap<NodeId, NodeId>) {
    if value.len() < 31 {
        return;
    }
    for i in 0..value.len() - 30 {
        if value[i] == SBOR_OWN_TAG && INTERNAL_ENTITY_TYPES.contains(&value[i + 1]) {
            let mut id = [0u8; 30];
            id.copy_from_slice(&value[i + 1..i + 31]);
            ownership.entry(NodeId(id)).or_insert(owner);
        }
    }
}

/// Expand declared NodeIds to include owned internal nodes (vaults) at a
/// specific block height.
///
/// Reads substates via JMT historical traversal. This is critical for provision
/// generation:
/// the expanded node list must match the state at the committed block height,
/// not the current tip, otherwise the merkle proof will cover keys that don't
/// exist at the proof's version and verification will fail on the remote shard.
pub fn expand_nodes_with_owned_at_height<S: hyperscale_storage::SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    block_height: BlockHeight,
) -> Option<Vec<NodeId>> {
    let ownership = resolve_owned_nodes_at_height(storage, nodes, block_height)?;
    let mut expanded: Vec<NodeId> = nodes.to_vec();
    for internal_id in ownership.keys() {
        if !expanded.contains(internal_id) {
            expanded.push(*internal_id);
        }
    }
    expanded.sort();
    expanded.dedup();
    Some(expanded)
}

/// Historical version of [`resolve_owned_nodes`].
///
/// Reads substates at `block_height` using `list_substates_for_node_at_height`.
/// Returns `None` if the version is unavailable (GC'd or not yet committed).
fn resolve_owned_nodes_at_height<S: hyperscale_storage::SubstateStore>(
    storage: &S,
    declared_nodes: &[NodeId],
    block_height: BlockHeight,
) -> Option<HashMap<NodeId, NodeId>> {
    let mut ownership: HashMap<NodeId, NodeId> = HashMap::new();

    for account in declared_nodes {
        let substates = storage.list_substates_for_node_at_height(account, block_height)?;
        for (_partition_num, _sort_key, value) in substates {
            extract_owned_node_ids(&value, *account, &mut ownership);
        }
    }

    Some(ownership)
}

// ============================================================================
// Stage 2: Shard Filtering
// ============================================================================

/// Filter DatabaseUpdates for a single shard.
///
/// Keeps only writes that:
/// 1. Are not system entities (ConsensusManager, TransactionTracker, Validator)
/// 2. Belong to a declared account (directly or as an owned internal node)
/// 3. Are assigned to `local_shard` based on the owning account's hash
///
/// The `declared_nodes` parameter contains account NodeIds from the transaction
/// manifest's declared reads/writes. The function scans their substates to
/// discover owned vaults, then filters accordingly.
pub fn filter_updates_for_shard<S: SubstateDatabase>(
    updates: &DatabaseUpdates,
    local_shard: ShardGroupId,
    num_shards: u64,
    storage: &S,
    declared_nodes: &[NodeId],
) -> DatabaseUpdates {
    let declared_set: HashSet<NodeId> = declared_nodes.iter().copied().collect();
    let ownership = resolve_owned_nodes(storage, declared_nodes);

    let mut filtered = DatabaseUpdates::default();

    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(node_id) = db_node_key_to_node_id(db_node_key) else {
            continue;
        };

        let entity_type = node_id.0[0];

        // Drop system entities.
        if SYSTEM_ENTITY_TYPES.contains(&entity_type) {
            continue;
        }

        // Determine which account this node belongs to, for both
        // ownership checking and shard assignment.
        let shard_node_id = if declared_set.contains(&node_id) {
            // This IS a declared account — use itself for shard assignment.
            node_id
        } else if let Some(&owner) = ownership.get(&node_id) {
            // Internal node owned by a declared account — use the owner.
            owner
        } else {
            // Not declared, not owned by any declared account.
            // This is an undeclared write (fee vault, etc.) — drop it.
            continue;
        };

        // Shard assignment based on the owning account.
        let node_shard = hyperscale_types::shard_for_node(&shard_node_id, num_shards);
        if node_shard != local_shard {
            continue;
        }

        filtered
            .node_updates
            .insert(db_node_key.clone(), node_updates.clone());
    }

    filtered
}

// ============================================================================
// Stage 3: Global Receipt Filtering
// ============================================================================

/// Filter DatabaseUpdates for cross-shard agreement (GlobalReceipt).
///
/// Like [`filter_updates_for_shard`] but WITHOUT shard assignment — keeps
/// declared writes across ALL shards. This produces a deterministic set of
/// writes that is identical on every shard executing the same transaction,
/// enabling cross-shard agreement via `writes_root` in the GlobalReceipt.
///
/// Filters applied:
/// 1. Drop system entities (ConsensusManager, TransactionTracker, Validator)
/// 2. Drop undeclared writes (not in declared_reads/declared_writes or their owned vaults)
/// 3. [OMITTED] No shard filtering — keep writes for all shards
pub fn filter_updates_for_global_receipt<S: SubstateDatabase>(
    updates: &DatabaseUpdates,
    storage: &S,
    declared_nodes: &[NodeId],
) -> DatabaseUpdates {
    let declared_set: HashSet<NodeId> = declared_nodes.iter().copied().collect();
    let ownership = resolve_owned_nodes(storage, declared_nodes);

    let mut filtered = DatabaseUpdates::default();

    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(node_id) = db_node_key_to_node_id(db_node_key) else {
            continue;
        };

        let entity_type = node_id.0[0];

        // Drop system entities.
        if SYSTEM_ENTITY_TYPES.contains(&entity_type) {
            continue;
        }

        // Drop undeclared writes.
        if !declared_set.contains(&node_id) && !ownership.contains_key(&node_id) {
            continue;
        }

        // No shard filtering — keep writes for all shards.
        filtered
            .node_updates
            .insert(db_node_key.clone(), node_updates.clone());
    }

    filtered
}

/// Compute the `writes_root` for a GlobalReceipt from filtered DatabaseUpdates.
///
/// SBOR-encodes the entire DatabaseUpdates (which uses BTreeMap for deterministic
/// iteration order) and hashes to produce a single root. All validators executing
/// the same transaction with the same declared nodes will produce identical output.
pub fn compute_writes_root(updates: &DatabaseUpdates) -> hyperscale_types::WritesRoot {
    use hyperscale_types::{Hash, WritesRoot};

    if updates.node_updates.is_empty() {
        return WritesRoot::ZERO;
    }

    // DatabaseUpdates uses BTreeMap internally, so SBOR encoding is
    // deterministic across validators.
    let encoded = radix_common::prelude::basic_encode(updates)
        .expect("DatabaseUpdates encoding should not fail");
    WritesRoot::from_raw(Hash::from_bytes(&encoded))
}

// ============================================================================
// Utilities
// ============================================================================

/// Extract the NodeId from a SpreadPrefixKeyMapper db_node_key.
///
/// DbNodeKey format: 20-byte hash prefix + 30-byte NodeId = 50 bytes.
/// Returns None if the key is too short.
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    const HASH_PREFIX_LEN: usize = 20;
    const NODE_ID_LEN: usize = 30;
    if db_node_key.len() < HASH_PREFIX_LEN + NODE_ID_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
    Some(NodeId(id))
}

/// Check if an entity type byte is an internal (child) entity.
pub fn is_internal_entity(entity_type: u8) -> bool {
    INTERNAL_ENTITY_TYPES.contains(&entity_type)
}

/// Compute the SpreadPrefixKeyMapper db_node_key for a NodeId.
///
/// Returns the 50-byte key: 20-byte hash prefix + 30-byte NodeId.
pub fn node_entity_key(node_id: &NodeId) -> Vec<u8> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    let radix_node_id = radix_common::types::NodeId(node_id.0);
    SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id)
}
