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
//! **Stage 1: Ownership resolution** (`resolve_owned_nodes`)
//! Scans declared accounts' substates to discover which vault NodeIds they own.
//! Uses SBOR byte scanning to find `Own(NodeId)` references (tag `0x90` + 30 bytes).
//! Builds a map from each internal NodeId to its owning account.
//!
//! **Stage 2: Shard filtering** (`filter_updates_for_shard`)
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

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use hyperscale_storage::{
    DatabaseUpdates, DbPartitionKey, PartitionDatabaseUpdates, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{BlockHeight, NodeId, ShardGroupId, WritesRoot, shard_for_node};
use radix_common::prelude::basic_encode;
use radix_common::types::NodeId as RadixNodeId;

/// System entity type bytes that should be filtered from `DatabaseUpdates`.
///
/// These are global system components whose state is replicated to all shards
/// and not yet set up for sharded consensus. Writes to these nodes must be
/// excluded from the per-shard `state_root` computation.
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

/// Maps internal `NodeId`s (vaults, KV stores) to their owning declared account.
///
/// For each declared account, scans all partition substates looking for
/// SBOR-encoded `Own(NodeId)` references. Returns a map from internal `NodeId`
/// to the account that owns it.
///
/// This is the "walk down" from accounts to vaults. It's necessary because
/// vaults have no back-pointer to their owning account — `outer_object` points
/// to the resource manager, not the account.
pub fn resolve_owned_nodes<S: SubstateDatabase>(
    storage: &S,
    declared_nodes: &[NodeId],
) -> HashMap<NodeId, NodeId> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut ownership: HashMap<NodeId, NodeId> = HashMap::new();

    for account in declared_nodes {
        let radix_node_id = RadixNodeId(account.0);
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
/// False positives are near-impossible since `NodeId`s are random hashes.
fn extract_owned_node_ids(value: &[u8], owner: NodeId, ownership: &mut HashMap<NodeId, NodeId>) {
    for window in value.windows(31) {
        if window[0] == SBOR_OWN_TAG && INTERNAL_ENTITY_TYPES.contains(&window[1]) {
            let id: [u8; 30] = window[1..31].try_into().expect("window len is 31");
            ownership.entry(NodeId(id)).or_insert(owner);
        }
    }
}

/// Expand declared `NodeId`s to include owned internal nodes (vaults) at a
/// specific block height, returning both the expanded list and the
/// `vault → owner` map that produced it.
///
/// Reads substates via JMT historical traversal. This is critical for provision
/// generation:
/// the expanded node list must match the state at the committed block height,
/// not the current tip, otherwise the merkle proof will cover keys that don't
/// exist at the proof's version and verification will fail on the remote shard.
///
/// The returned ownership map is what the source shard authoritatively knows
/// about its own declared accounts. It is shipped alongside the substate
/// entries so the receiver doesn't have to rediscover ownership by walking
/// a partial view (which would diverge whenever the source shipped only a
/// subset of the account's partitions).
pub fn expand_nodes_with_owned_at_height<S: SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    block_height: BlockHeight,
) -> Option<(Vec<NodeId>, HashMap<NodeId, NodeId>)> {
    let ownership = resolve_owned_nodes_at_height(storage, nodes, block_height)?;
    let mut expanded: Vec<NodeId> = nodes.to_vec();
    for internal_id in ownership.keys() {
        if !expanded.contains(internal_id) {
            expanded.push(*internal_id);
        }
    }
    expanded.sort();
    expanded.dedup();
    Some((expanded, ownership))
}

/// Historical version of [`resolve_owned_nodes`].
///
/// Reads substates at `block_height` using `list_substates_for_node_at_height`.
/// Returns `None` if the version is unavailable (GC'd or not yet committed).
pub fn resolve_owned_nodes_at_height<S: SubstateStore>(
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

/// Filter `DatabaseUpdates` for a single shard.
///
/// Keeps only writes that:
/// 1. Are not system entities (`ConsensusManager`, `TransactionTracker`, Validator)
/// 2. Belong to a declared account (directly or as an owned internal node)
/// 3. Are assigned to `local_shard` based on the owning account's hash
///
/// `declared_set` carries the transaction's declared reads/writes; `ownership`
/// maps each internal node discovered under those accounts to its owner. Both
/// are produced once per build via [`resolve_owned_nodes`] and shared with
/// [`filter_updates_for_global_receipt`].
#[must_use]
pub fn filter_updates_for_shard<H1: BuildHasher, H2: BuildHasher>(
    updates: &DatabaseUpdates,
    local_shard: ShardGroupId,
    num_shards: u64,
    declared_set: &HashSet<NodeId, H1>,
    ownership: &HashMap<NodeId, NodeId, H2>,
) -> DatabaseUpdates {
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
        let node_shard = shard_for_node(&shard_node_id, num_shards);
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

/// Filter `DatabaseUpdates` for cross-shard agreement (`GlobalReceipt`).
///
/// Like [`filter_updates_for_shard`] but WITHOUT shard assignment — keeps
/// declared writes across ALL shards. This produces a deterministic set of
/// writes that is identical on every shard executing the same transaction,
/// enabling cross-shard agreement via `writes_root` in the `GlobalReceipt`.
///
/// Filters applied:
/// 1. Drop system entities (`ConsensusManager`, `TransactionTracker`, Validator)
/// 2. Drop undeclared writes (not in `declared_reads`/`declared_writes` or their owned vaults)
/// 3. (Omitted: no shard filtering — keep writes for all shards.)
///
/// Shares `declared_set` and `ownership` with [`filter_updates_for_shard`];
/// see that function's docs for how the inputs are produced.
#[must_use]
pub fn filter_updates_for_global_receipt<H1: BuildHasher, H2: BuildHasher>(
    updates: &DatabaseUpdates,
    declared_set: &HashSet<NodeId, H1>,
    ownership: &HashMap<NodeId, NodeId, H2>,
) -> DatabaseUpdates {
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

/// Compute the `writes_root` for a `GlobalReceipt` from filtered `DatabaseUpdates`.
///
/// `DatabaseUpdates` is built from `IndexMap`s at every level — Radix's
/// `StateUpdates` documents itself as "not 100% canonical form" because the
/// `by_node` order reflects engine touch order rather than a content-derived
/// order. To make `writes_root` a pure function of the *content* of the
/// updates (independent of how the maps were populated), we sort all
/// `IndexMap`s by key before SBOR-encoding.
///
/// # Panics
///
/// Panics if SBOR encoding of [`DatabaseUpdates`] fails. The Radix SBOR encoder
/// is infallible for these structures, so this is unreachable in practice.
#[must_use]
pub fn compute_writes_root(updates: &DatabaseUpdates) -> WritesRoot {
    use hyperscale_types::{Hash, WritesRoot};

    if updates.node_updates.is_empty() {
        return WritesRoot::ZERO;
    }

    let mut canonical = updates.clone();
    sort_database_updates(&mut canonical);
    let encoded = basic_encode(&canonical).expect("DatabaseUpdates encoding should not fail");
    WritesRoot::from_raw(Hash::from_bytes(&encoded))
}

/// Sort every `IndexMap` inside `updates` by key, in-place.
fn sort_database_updates(updates: &mut DatabaseUpdates) {
    updates.node_updates.sort_keys();
    for node_updates in updates.node_updates.values_mut() {
        node_updates.partition_updates.sort_keys();
        for partition_updates in node_updates.partition_updates.values_mut() {
            match partition_updates {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    substate_updates.sort_keys();
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    new_substate_values.sort_keys();
                }
            }
        }
    }
}

// ============================================================================
// Utilities
// ============================================================================

/// Extract the `NodeId` from a `SpreadPrefixKeyMapper` `db_node_key`.
///
/// `DbNodeKey` format: 20-byte hash prefix + 30-byte `NodeId` = 50 bytes.
/// Returns None if the key is too short.
#[must_use]
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
#[must_use]
pub fn is_internal_entity(entity_type: u8) -> bool {
    INTERNAL_ENTITY_TYPES.contains(&entity_type)
}

/// Compute the `SpreadPrefixKeyMapper` `db_node_key` for a `NodeId`.
///
/// Returns the 50-byte key: 20-byte hash prefix + 30-byte `NodeId`.
#[must_use]
pub fn node_entity_key(node_id: &NodeId) -> Vec<u8> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    let radix_node_id = RadixNodeId(node_id.0);
    SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id)
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::{
        DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
        PartitionDatabaseUpdates, SubstateDatabase, SubstateStore,
    };
    use hyperscale_types::{
        BlockHeight, MerkleInclusionProof, NodeId, StateRoot, WritesRoot, shard_for_node,
    };
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn id_with_type(type_byte: u8, seed: u8) -> NodeId {
        let mut id = [seed; 30];
        id[0] = type_byte;
        NodeId(id)
    }

    fn account_id(seed: u8) -> NodeId {
        // 0x51 is a global account entity type — not in SYSTEM_ENTITY_TYPES
        // and not in INTERNAL_ENTITY_TYPES, matching production usage.
        id_with_type(0x51, seed)
    }

    fn fungible_vault_id(seed: u8) -> NodeId {
        id_with_type(0x58, seed)
    }

    fn nonfungible_vault_id(seed: u8) -> NodeId {
        id_with_type(0x98, seed)
    }

    /// SBOR-encoded `Own(node)` reference: [`SBOR_OWN_TAG`] followed by the
    /// 30-byte `NodeId`.
    fn own_bytes(node: &NodeId) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(31);
        bytes.push(SBOR_OWN_TAG);
        bytes.extend_from_slice(&node.0);
        bytes
    }

    /// Pick a second seed whose account hashes to a different shard than `a`.
    fn pick_other_shard_seed(a: NodeId, num_shards: u64) -> NodeId {
        let target = shard_for_node(&a, num_shards);
        for seed in 2u8..=255 {
            let candidate = account_id(seed);
            if candidate != a && shard_for_node(&candidate, num_shards) != target {
                return candidate;
            }
        }
        panic!("no other-shard seed found for num_shards={num_shards}");
    }

    fn make_set_update(
        node: NodeId,
        partition: u8,
        sort: Vec<u8>,
        value: Vec<u8>,
    ) -> DatabaseUpdates {
        let radix_node_id = RadixNodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
        let mut updates = DatabaseUpdates::default();
        let nu = updates
            .node_updates
            .entry(db_node_key)
            .or_insert_with(NodeDatabaseUpdates::default);
        nu.partition_updates.insert(
            partition,
            PartitionDatabaseUpdates::Delta {
                substate_updates: std::iter::once((DbSortKey(sort), DatabaseUpdate::Set(value)))
                    .collect(),
            },
        );
        updates
    }

    fn merge(mut a: DatabaseUpdates, b: DatabaseUpdates) -> DatabaseUpdates {
        for (k, v) in b.node_updates {
            a.node_updates.insert(k, v);
        }
        a
    }

    /// Build the `(declared_set, ownership)` pair the filters require,
    /// matching what `build_executed_tx` does at the real call site.
    fn filter_inputs<S: SubstateDatabase>(
        storage: &S,
        declared: &[NodeId],
    ) -> (HashSet<NodeId>, HashMap<NodeId, NodeId>) {
        let set = declared.iter().copied().collect();
        let ownership = resolve_owned_nodes(storage, declared);
        (set, ownership)
    }

    // ── MockDb: SubstateDatabase backed by an in-memory map ─────────────────

    type PartitionEntries = Vec<(DbSortKey, Vec<u8>)>;
    type PartitionMap = HashMap<(Vec<u8>, u8), PartitionEntries>;

    #[derive(Clone, Default)]
    struct MockDb {
        partitions: PartitionMap,
    }

    impl MockDb {
        fn insert(&mut self, owner: &NodeId, partition: u8, sort: Vec<u8>, value: Vec<u8>) {
            let radix_node_id = RadixNodeId(owner.0);
            let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
            self.partitions
                .entry((db_node_key, partition))
                .or_default()
                .push((DbSortKey(sort), value));
        }
    }

    impl SubstateDatabase for MockDb {
        fn get_raw_substate_by_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            None
        }

        fn list_raw_values_from_db_key(
            &self,
            partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            let key = (partition_key.node_key.clone(), partition_key.partition_num);
            match self.partitions.get(&key) {
                Some(values) => Box::new(values.clone().into_iter()),
                None => Box::new(std::iter::empty()),
            }
        }
    }

    // ── extract_owned_node_ids ───────────────────────────────────────────────

    #[test]
    fn extract_owned_short_value_is_noop() {
        let mut ownership = HashMap::new();
        extract_owned_node_ids(&[0x90; 5], account_id(1), &mut ownership);
        assert!(ownership.is_empty());
    }

    #[test]
    fn extract_owned_captures_internal_reference() {
        let owner = account_id(1);
        let vault = fungible_vault_id(2);
        let mut ownership = HashMap::new();
        extract_owned_node_ids(&own_bytes(&vault), owner, &mut ownership);
        assert_eq!(ownership.get(&vault), Some(&owner));
    }

    #[test]
    fn extract_owned_skips_non_internal_targets() {
        // An Own pointing at another account (0x51) should be ignored —
        // accounts are global, not internal entities.
        let owner = account_id(1);
        let other_account = account_id(2);
        let mut ownership = HashMap::new();
        extract_owned_node_ids(&own_bytes(&other_account), owner, &mut ownership);
        assert!(ownership.is_empty());
    }

    #[test]
    fn extract_owned_handles_each_internal_type() {
        let owner = account_id(1);
        for (i, &type_byte) in INTERNAL_ENTITY_TYPES.iter().enumerate() {
            let seed = u8::try_from(i).expect("internal entity table fits in u8") + 10;
            let target = id_with_type(type_byte, seed);
            let mut ownership = HashMap::new();
            extract_owned_node_ids(&own_bytes(&target), owner, &mut ownership);
            assert_eq!(
                ownership.get(&target),
                Some(&owner),
                "type 0x{type_byte:02x} should be captured"
            );
        }
    }

    #[test]
    fn extract_owned_finds_multiple_in_one_value() {
        let owner = account_id(1);
        let v1 = fungible_vault_id(2);
        let v2 = nonfungible_vault_id(3);
        let mut value = own_bytes(&v1);
        value.extend_from_slice(&own_bytes(&v2));
        let mut ownership = HashMap::new();
        extract_owned_node_ids(&value, owner, &mut ownership);
        assert_eq!(ownership.len(), 2);
        assert_eq!(ownership[&v1], owner);
        assert_eq!(ownership[&v2], owner);
    }

    #[test]
    fn extract_owned_first_owner_wins() {
        // entry().or_insert means if the same vault is referenced twice
        // by different owners, the first owner sticks.
        let first = account_id(1);
        let second = account_id(2);
        let vault = fungible_vault_id(3);
        let value = own_bytes(&vault);
        let mut ownership = HashMap::new();
        extract_owned_node_ids(&value, first, &mut ownership);
        extract_owned_node_ids(&value, second, &mut ownership);
        assert_eq!(ownership[&vault], first);
    }

    // ── db_node_key_to_node_id ───────────────────────────────────────────────

    #[test]
    fn db_node_key_short_returns_none() {
        assert!(db_node_key_to_node_id(&[]).is_none());
        assert!(db_node_key_to_node_id(&[0u8; 49]).is_none());
    }

    #[test]
    fn db_node_key_round_trips_through_node_entity_key() {
        let node = fungible_vault_id(42);
        let key = node_entity_key(&node);
        assert_eq!(key.len(), 50);
        assert_eq!(db_node_key_to_node_id(&key), Some(node));
    }

    // ── is_internal_entity ───────────────────────────────────────────────────

    #[test]
    fn is_internal_entity_matches_internal_table() {
        for &b in INTERNAL_ENTITY_TYPES {
            assert!(is_internal_entity(b));
        }
        assert!(!is_internal_entity(0x51));
        for &b in SYSTEM_ENTITY_TYPES {
            assert!(!is_internal_entity(b));
        }
    }

    // ── node_entity_key ──────────────────────────────────────────────────────

    #[test]
    fn node_entity_key_has_node_id_suffix() {
        let node = fungible_vault_id(7);
        let key = node_entity_key(&node);
        assert_eq!(key.len(), 50);
        assert_eq!(&key[20..], &node.0);
    }

    // ── compute_writes_root ──────────────────────────────────────────────────

    #[test]
    fn compute_writes_root_empty_is_zero() {
        assert_eq!(
            compute_writes_root(&DatabaseUpdates::default()),
            WritesRoot::ZERO
        );
    }

    #[test]
    fn compute_writes_root_is_insertion_order_independent() {
        // The cross-shard agreement contract requires that two validators which
        // build the same logical `DatabaseUpdates` produce the same root
        // regardless of how their underlying `IndexMap`s were populated. If
        // this fails, validators executing the same transaction can disagree
        // on `writes_root` and break global-receipt consensus.
        let a = account_id(1);
        let b = account_id(2);
        let forward = merge(
            make_set_update(a, 64, vec![0], vec![1]),
            make_set_update(b, 64, vec![0], vec![1]),
        );
        let reverse = merge(
            make_set_update(b, 64, vec![0], vec![1]),
            make_set_update(a, 64, vec![0], vec![1]),
        );
        assert_eq!(compute_writes_root(&forward), compute_writes_root(&reverse));
    }

    #[test]
    fn compute_writes_root_distinguishes_inputs() {
        let a = make_set_update(account_id(1), 64, vec![0], vec![1]);
        let b = make_set_update(account_id(2), 64, vec![0], vec![1]);
        assert_ne!(compute_writes_root(&a), compute_writes_root(&b));
    }

    // ── resolve_owned_nodes ──────────────────────────────────────────────────

    #[test]
    fn resolve_owned_walks_account_to_vault() {
        let account = account_id(1);
        let vault = fungible_vault_id(2);
        let mut db = MockDb::default();
        db.insert(&account, 64, vec![0], own_bytes(&vault));
        let ownership = resolve_owned_nodes(&db, &[account]);
        assert_eq!(ownership.get(&vault), Some(&account));
    }

    #[test]
    fn resolve_owned_empty_when_no_substates() {
        let db = MockDb::default();
        let ownership = resolve_owned_nodes(&db, &[account_id(1)]);
        assert!(ownership.is_empty());
    }

    #[test]
    fn resolve_owned_scans_all_partitions() {
        // Substate placed in a non-default partition is still discovered —
        // the scan covers 0..=255.
        let account = account_id(1);
        let vault = fungible_vault_id(2);
        let mut db = MockDb::default();
        db.insert(&account, 200, vec![0], own_bytes(&vault));
        let ownership = resolve_owned_nodes(&db, &[account]);
        assert_eq!(ownership.get(&vault), Some(&account));
    }

    // ── filter_updates_for_shard ─────────────────────────────────────────────

    #[test]
    fn filter_for_shard_drops_system_entities() {
        let account = account_id(1);
        let consensus = id_with_type(0x86, 7);
        let updates = merge(
            make_set_update(account, 64, vec![0], vec![1]),
            make_set_update(consensus, 64, vec![0], vec![1]),
        );
        let local = shard_for_node(&account, 4);
        let (set, own) = filter_inputs(&MockDb::default(), &[account]);
        let filtered = filter_updates_for_shard(&updates, local, 4, &set, &own);
        assert_eq!(filtered.node_updates.len(), 1);
        let only = filtered.node_updates.keys().next().unwrap();
        assert_eq!(db_node_key_to_node_id(only), Some(account));
    }

    #[test]
    fn filter_for_shard_drops_undeclared_writes() {
        // num_shards=1 isolates this from shard-routing concerns.
        let account = account_id(1);
        let stranger = account_id(2);
        let updates = merge(
            make_set_update(account, 64, vec![0], vec![1]),
            make_set_update(stranger, 64, vec![0], vec![1]),
        );
        let local = shard_for_node(&account, 1);
        let (set, own) = filter_inputs(&MockDb::default(), &[account]);
        let filtered = filter_updates_for_shard(&updates, local, 1, &set, &own);
        assert_eq!(filtered.node_updates.len(), 1);
    }

    #[test]
    fn filter_for_shard_drops_other_shard_writes() {
        let a = account_id(1);
        let b = pick_other_shard_seed(a, 4);
        let local = shard_for_node(&a, 4);
        let updates = merge(
            make_set_update(a, 64, vec![0], vec![1]),
            make_set_update(b, 64, vec![0], vec![1]),
        );
        let (set, own) = filter_inputs(&MockDb::default(), &[a, b]);
        let filtered = filter_updates_for_shard(&updates, local, 4, &set, &own);
        assert_eq!(filtered.node_updates.len(), 1);
        let only = filtered.node_updates.keys().next().unwrap();
        assert_eq!(db_node_key_to_node_id(only), Some(a));
    }

    #[test]
    fn filter_for_shard_keeps_owned_vault_with_owner() {
        let account = account_id(1);
        let vault = fungible_vault_id(2);
        let mut db = MockDb::default();
        db.insert(&account, 64, vec![0], own_bytes(&vault));
        let updates = merge(
            make_set_update(account, 64, vec![0], vec![1]),
            make_set_update(vault, 0, vec![0], vec![1]),
        );
        let local = shard_for_node(&account, 1);
        let (set, own) = filter_inputs(&db, &[account]);
        let filtered = filter_updates_for_shard(&updates, local, 1, &set, &own);
        assert_eq!(filtered.node_updates.len(), 2);
    }

    #[test]
    fn filter_for_shard_routes_owned_vault_by_owner_shard() {
        // The vault hashes to whatever shard its random NodeId points at,
        // but for routing we use the owning account's shard. Pick a vault
        // whose own hash differs from its owner's shard, then verify the
        // vault is kept iff we filter for the owner's shard.
        let account = account_id(1);
        let owner_shard = shard_for_node(&account, 4);
        let mut vault_seed = 2u8;
        let mut vault = fungible_vault_id(vault_seed);
        while shard_for_node(&vault, 4) == owner_shard {
            vault_seed = vault_seed.wrapping_add(1);
            vault = fungible_vault_id(vault_seed);
            assert_ne!(vault_seed, 1, "no diverging vault seed found");
        }
        let mut db = MockDb::default();
        db.insert(&account, 64, vec![0], own_bytes(&vault));
        let updates = make_set_update(vault, 0, vec![0], vec![1]);
        let (set, own) = filter_inputs(&db, &[account]);
        // Filter at owner's shard — vault must be kept.
        let kept = filter_updates_for_shard(&updates, owner_shard, 4, &set, &own);
        assert_eq!(kept.node_updates.len(), 1);
        // Filter at the vault's "natural" shard — must drop.
        let dropped = filter_updates_for_shard(&updates, shard_for_node(&vault, 4), 4, &set, &own);
        assert!(dropped.node_updates.is_empty());
    }

    // ── filter_updates_for_global_receipt ────────────────────────────────────

    #[test]
    fn filter_for_global_receipt_keeps_writes_across_shards() {
        let a = account_id(1);
        let b = pick_other_shard_seed(a, 4);
        let updates = merge(
            make_set_update(a, 64, vec![0], vec![1]),
            make_set_update(b, 64, vec![0], vec![1]),
        );
        let (set, own) = filter_inputs(&MockDb::default(), &[a, b]);
        let filtered = filter_updates_for_global_receipt(&updates, &set, &own);
        assert_eq!(filtered.node_updates.len(), 2);
    }

    #[test]
    fn filter_for_global_receipt_drops_system_and_undeclared() {
        let account = account_id(1);
        let stranger = account_id(2);
        let consensus = id_with_type(0x86, 7);
        let updates = merge(
            merge(
                make_set_update(account, 64, vec![0], vec![1]),
                make_set_update(stranger, 64, vec![0], vec![1]),
            ),
            make_set_update(consensus, 64, vec![0], vec![1]),
        );
        let (set, own) = filter_inputs(&MockDb::default(), &[account]);
        let filtered = filter_updates_for_global_receipt(&updates, &set, &own);
        assert_eq!(filtered.node_updates.len(), 1);
        let only = filtered.node_updates.keys().next().unwrap();
        assert_eq!(db_node_key_to_node_id(only), Some(account));
    }

    #[test]
    fn filter_for_global_receipt_keeps_owned_vault() {
        let account = account_id(1);
        let vault = fungible_vault_id(2);
        let mut db = MockDb::default();
        db.insert(&account, 64, vec![0], own_bytes(&vault));
        let updates = merge(
            make_set_update(account, 64, vec![0], vec![1]),
            make_set_update(vault, 0, vec![0], vec![1]),
        );
        let (set, own) = filter_inputs(&db, &[account]);
        let filtered = filter_updates_for_global_receipt(&updates, &set, &own);
        assert_eq!(filtered.node_updates.len(), 2);
    }

    // ── expand_nodes_with_owned_at_height ────────────────────────────────────

    type HeightSubstates = Vec<(u8, DbSortKey, Vec<u8>)>;
    type SubstateHistory = HashMap<(NodeId, BlockHeight), HeightSubstates>;

    #[derive(Clone, Default)]
    struct MockStore {
        substates_at_height: SubstateHistory,
        missing_height: bool,
    }

    impl SubstateDatabase for MockStore {
        fn get_raw_substate_by_db_key(&self, _: &DbPartitionKey, _: &DbSortKey) -> Option<Vec<u8>> {
            None
        }
        fn list_raw_values_from_db_key(
            &self,
            _: &DbPartitionKey,
            _: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }

    impl SubstateStore for MockStore {
        type Snapshot<'a> = Self;
        fn snapshot(&self) -> Self::Snapshot<'_> {
            self.clone()
        }
        fn jmt_height(&self) -> BlockHeight {
            BlockHeight::GENESIS
        }
        fn state_root(&self) -> StateRoot {
            StateRoot::ZERO
        }
        fn list_substates_for_node_at_height(
            &self,
            node_id: &NodeId,
            block_height: BlockHeight,
        ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
            if self.missing_height {
                return None;
            }
            Some(
                self.substates_at_height
                    .get(&(*node_id, block_height))
                    .cloned()
                    .unwrap_or_default(),
            )
        }
        fn generate_merkle_proofs(
            &self,
            _: &[Vec<u8>],
            _: BlockHeight,
        ) -> Option<MerkleInclusionProof> {
            None
        }
    }

    #[test]
    fn expand_at_height_returns_none_when_unavailable() {
        let store = MockStore {
            missing_height: true,
            ..Default::default()
        };
        assert!(
            expand_nodes_with_owned_at_height(&store, &[account_id(1)], BlockHeight::new(5))
                .is_none()
        );
    }

    #[test]
    fn expand_at_height_includes_owned_vaults_sorted_dedup() {
        let account = account_id(1);
        let vault = fungible_vault_id(2);
        let height = BlockHeight::new(5);
        let mut store = MockStore::default();
        store.substates_at_height.insert(
            (account, height),
            vec![(64, DbSortKey(vec![0]), own_bytes(&vault))],
        );

        // Pass `vault` in declared list too — must not duplicate after dedup.
        let (expanded, ownership) =
            expand_nodes_with_owned_at_height(&store, &[account, vault], height).expect("present");
        let mut expected = vec![account, vault];
        expected.sort();
        assert_eq!(expanded, expected);
        assert_eq!(ownership.get(&vault), Some(&account));
    }

    #[test]
    fn expand_at_height_returns_declared_when_no_ownership() {
        let account = account_id(1);
        let store = MockStore::default(); // no substates at any height
        let (expanded, ownership) =
            expand_nodes_with_owned_at_height(&store, &[account], BlockHeight::new(5))
                .expect("present");
        assert_eq!(expanded, vec![account]);
        assert!(ownership.is_empty());
    }

    // ── Cross-shard merged-view invariance ───────────────────────────────────
    //
    // `compute_vm_output` advertises shard-invariance: the same `(tx, vm_receipt)`
    // must produce a byte-equal `CachedVmOutput` regardless of which shard
    // constructed the merged view. That guarantee propagates down to
    // `writes_root` (and therefore `GlobalReceiptHash`), which is the
    // proper consensus surface.
    //
    // The walking ownership resolver runs at this layer, so the contract is
    // statable here without dragging in a real VM receipt: equivalent merged
    // views must produce equivalent `(ownership, global_updates, writes_root)`.
    //
    // This test pins the contract. It fails when cross-shard provisions
    // ship only the partitions a tx reads — a declared account's `Own(_)`
    // refs in unshipped partitions are visible to the side that holds the
    // account locally and invisible to the side that sees it via
    // provisions. The downstream `writes_root` then drifts between
    // validators on different co-hosted shards.

    #[test]
    #[ignore = "demonstrates bug; un-ignore once provisions carry authoritative ownership"]
    fn writes_root_is_shard_invariant_across_equivalent_merged_views() {
        use hyperscale_storage::keys;
        use hyperscale_types::SubstateEntry;

        use crate::provisioned_snapshot::ProvisionedSnapshot;

        // Cross-shard tx declares one account; that account owns two
        // vaults via `Own(_)` refs in two different partitions.
        let a_0 = account_id(1);
        let v_main = fungible_vault_id(2); // referenced from partition 64
        let v_meta = nonfungible_vault_id(3); // referenced from partition 0

        // Shard 0 holds A_0 locally with the full substate set.
        let mut shard_0_local = MockDb::default();
        shard_0_local.insert(&a_0, 0, vec![0], own_bytes(&v_meta));
        shard_0_local.insert(&a_0, 64, vec![0], own_bytes(&v_main));

        // Shard 1 doesn't hold A_0; it sees A_0 only through provisions.
        let shard_1_local = MockDb::default();

        // Shard 0 ships only the partition the tx declared a read
        // against — the minimal-shipping case. Partition 0's `Own(v_meta)`
        // never crosses the wire.
        let a_0_db_node_key = node_entity_key(&a_0);
        let partition_shipped = DbPartitionKey {
            node_key: a_0_db_node_key,
            partition_num: 64,
        };
        let shard_0_provisions = vec![SubstateEntry::new(
            keys::to_storage_key(&partition_shipped, &DbSortKey(vec![0])),
            Some(own_bytes(&v_main)),
        )];

        // Build the same merged-view shape both validators use at
        // execution time.
        let view_from_shard_0 = ProvisionedSnapshot::from_provisions(&shard_0_local, &[]);
        let view_from_shard_1 =
            ProvisionedSnapshot::from_provisions(&shard_1_local, &[shard_0_provisions.as_slice()]);

        let ownership_0 = resolve_owned_nodes(&view_from_shard_0, &[a_0]);
        let ownership_1 = resolve_owned_nodes(&view_from_shard_1, &[a_0]);

        // Same VM-produced raw writes on both sides — what the VM would
        // have emitted given identical inputs.
        let raw_updates = merge(
            merge(
                make_set_update(a_0, 64, vec![0], vec![1]),
                make_set_update(v_main, 0, vec![0], vec![1]),
            ),
            make_set_update(v_meta, 0, vec![0], vec![1]),
        );

        let declared_set: HashSet<NodeId> = std::iter::once(a_0).collect();
        let global_0 = filter_updates_for_global_receipt(&raw_updates, &declared_set, &ownership_0);
        let global_1 = filter_updates_for_global_receipt(&raw_updates, &declared_set, &ownership_1);

        let writes_root_0 = compute_writes_root(&global_0);
        let writes_root_1 = compute_writes_root(&global_1);

        assert_eq!(
            writes_root_0, writes_root_1,
            "writes_root must be shard-invariant; ownership maps differed: \
             shard-0={ownership_0:?}, shard-1={ownership_1:?}. The \
             GlobalReceiptHash baked from these will diverge between \
             validators on different co-hosted shards, causing the \
             dissenter to reject the wave's EC at admission.",
        );
    }
}
