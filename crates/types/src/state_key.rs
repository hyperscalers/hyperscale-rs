//! Canonical state-keying.
//!
//! The single definition of how a substate's flat storage key becomes a JMT
//! leaf, and how a `db_node_key` prefix decodes back to its [`NodeId`]. The
//! storage backend (JMT construction and merkle proof generation) and the
//! cross-shard provision proof verifier both derive leaves through these
//! functions, so the proving and verifying sides commit to one identical key,
//! value, and `NodeId` byte layout.

use blake3::hash as blake3_hash;

use crate::NodeId;

/// Length of the `SpreadPrefixKeyMapper` hash prefix that precedes the `NodeId`
/// in a `db_node_key`.
pub const DB_NODE_KEY_HASH_PREFIX_LEN: usize = 20;

/// Length of a `NodeId` in bytes.
pub const NODE_ID_LEN: usize = 30;

/// Length of a full `db_node_key`: hash prefix followed by the `NodeId`.
pub const DB_NODE_KEY_LEN: usize = DB_NODE_KEY_HASH_PREFIX_LEN + NODE_ID_LEN;

/// Decode cap on a raw substate storage key.
///
/// Applied by every wire object carrying one (provisioned
/// `SubstateEntry`s and snap-sync `StateRangeLeaf`s alike) — one limit,
/// so anything that can be committed can also be provisioned and
/// served.
///
/// Real keys are `db_node_key` (50 bytes) + partition (1) + `sort_key`
/// (≤ a few hundred bytes for any realistic substate). 4 KiB is well
/// above any legitimate Radix substate key and rejects obviously
/// oversized arrivals before allocation.
pub const MAX_STATE_ENTRY_KEY_LEN: usize = 4 * 1024;

/// Decode cap on a raw substate value, shared by the same wire objects
/// as [`MAX_STATE_ENTRY_KEY_LEN`].
///
/// Radix substates have an engine-side ceiling well below this; the cap
/// exists to bound the SBOR `Vec<u8>` pre-allocation a peer can force on
/// a single `value` field.
pub const MAX_STATE_ENTRY_VALUE_LEN: usize = 1024 * 1024;

/// Hash a flat storage key (`db_node_key || partition_num || sort_key`) to its
/// 32-byte JMT leaf key.
///
/// The key is owner-major: the high 16 bytes are `blake3(routing_node)`, where
/// `routing_node` is `owner` for an internal/owned node (vault, KV store) and
/// the node itself for a globally-addressed entity (`owner == None`). The low
/// 16 bytes are `blake3(storage_key)` over the *whole* key, which embeds the
/// node's own id and so disambiguates sibling internal nodes that share an
/// owner prefix. Every substate of one owner — the account and the vaults/KV
/// stores it owns — shares the high half, so an account's full footprint forms
/// a contiguous JMT subtree under one shard prefix.
///
/// Internal nodes have random `NodeId`s unrelated to their owner; without
/// owner-prefixing they would scatter across shard prefixes and break the
/// prefix-subtree invariant. The owner is the node's global ancestor, resolved
/// from the ownership map the executor already computes (and ships in the
/// receipt) — see [`crate::ConsensusReceipt`].
///
/// `storage_key` must begin with a `db_node_key` — every key the engine commits
/// and every key proof generation reads is `SpreadPrefixKeyMapper` encoded, so
/// this holds by construction. The one path taking untrusted keys (provision
/// proof verification) rejects malformed entries before keying.
///
/// # Panics
///
/// Panics if `storage_key` is shorter than a `db_node_key`.
#[must_use]
pub fn jmt_leaf_key(storage_key: &[u8], owner: Option<NodeId>) -> [u8; 32] {
    let node_id = db_node_key_to_node_id(storage_key)
        .expect("jmt_leaf_key requires a db_node_key-prefixed storage key");
    let routing_node = owner.unwrap_or(node_id);
    let node_hash = node_routing_hash(&routing_node);
    let substate_hash = blake3_hash(storage_key);
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&node_hash[..16]);
    key[16..].copy_from_slice(&substate_hash.as_bytes()[..16]);
    key
}

/// The owner-major routing hash whose leading bytes form a leaf key's
/// high half — the bits a shard prefix routes and partitions on.
///
/// Every substate of one routing node (the entity itself, or the global
/// owner of an internal node) shares it, so "which shard prefix does
/// this entity's state sit under" is a test against this hash alone.
#[must_use]
pub fn node_routing_hash(routing_node: &NodeId) -> [u8; 32] {
    *blake3_hash(&routing_node.0).as_bytes()
}

/// Hash a substate value to the 32-byte value hash held in its JMT leaf.
#[must_use]
pub fn jmt_value_hash(value: &[u8]) -> [u8; 32] {
    *blake3_hash(value).as_bytes()
}

/// Whether `leaf_key` binds `storage_key`: its low half equals
/// `blake3(storage_key)`'s.
///
/// The high (owner-routing) half is positional — attested by whatever
/// proof the leaf arrives under — so a verifier without the ownership
/// map checks exactly this half to tie a shipped raw key to a proven
/// leaf (snap-sync chunk verification).
#[must_use]
pub fn leaf_key_binds_storage_key(leaf_key: &[u8; 32], storage_key: &[u8]) -> bool {
    leaf_key[16..] == blake3_hash(storage_key).as_bytes()[..16]
}

/// Decode the [`NodeId`] embedded in a `db_node_key` (or any storage key that
/// begins with one). Returns `None` when the slice is shorter than a full
/// `db_node_key`.
///
/// Layout: `[hash prefix: DB_NODE_KEY_HASH_PREFIX_LEN][NodeId: NODE_ID_LEN]`.
#[must_use]
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    if db_node_key.len() < DB_NODE_KEY_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[DB_NODE_KEY_HASH_PREFIX_LEN..DB_NODE_KEY_LEN]);
    Some(NodeId(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed storage key: zeroed hash prefix, then the node id,
    /// then a partition byte and sort key.
    fn storage_key(node: NodeId, partition: u8, sort: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; DB_NODE_KEY_HASH_PREFIX_LEN];
        key.extend_from_slice(&node.0);
        key.push(partition);
        key.extend_from_slice(sort);
        key
    }

    #[test]
    fn db_node_key_to_node_id_extracts_embedded_id() {
        let node = NodeId([7u8; NODE_ID_LEN]);
        assert_eq!(
            db_node_key_to_node_id(&storage_key(node, 0, b"sort")),
            Some(node)
        );
    }

    #[test]
    fn db_node_key_to_node_id_rejects_short_key() {
        assert_eq!(db_node_key_to_node_id(&[]), None);
        assert_eq!(db_node_key_to_node_id(&[0u8; DB_NODE_KEY_LEN - 1]), None);
    }

    #[test]
    fn jmt_leaf_key_is_node_major() {
        let a = NodeId([1u8; NODE_ID_LEN]);
        let b = NodeId([2u8; NODE_ID_LEN]);
        let a0 = jmt_leaf_key(&storage_key(a, 0, b"x"), None);
        let a1 = jmt_leaf_key(&storage_key(a, 7, b"yy"), None);
        // Two substates of one node share the node-major prefix but differ in
        // the substate half.
        assert_eq!(a0[..16], a1[..16]);
        assert_ne!(a0[16..], a1[16..]);
        // A different node lands under a different prefix.
        let b0 = jmt_leaf_key(&storage_key(b, 0, b"x"), None);
        assert_ne!(a0[..16], b0[..16]);
    }

    #[test]
    fn jmt_leaf_key_is_deterministic() {
        let key = storage_key(NodeId([9u8; NODE_ID_LEN]), 3, b"sort");
        assert_eq!(jmt_leaf_key(&key, None), jmt_leaf_key(&key, None));
    }

    #[test]
    fn owner_prefixing_folds_internal_node_under_owner() {
        let owner = NodeId([1u8; NODE_ID_LEN]);
        let vault = NodeId([200u8; NODE_ID_LEN]);
        // The account's own substate (owner = self) and the vault keyed under
        // its owner share the high-half owner prefix.
        let account_key = jmt_leaf_key(&storage_key(owner, 0, b"x"), None);
        let vault_key = jmt_leaf_key(&storage_key(vault, 0, b"x"), Some(owner));
        assert_eq!(account_key[..16], vault_key[..16]);
        // Unprefixed, the vault would land under its own (unrelated) prefix.
        let vault_unprefixed = jmt_leaf_key(&storage_key(vault, 0, b"x"), None);
        assert_ne!(account_key[..16], vault_unprefixed[..16]);
    }

    #[test]
    fn sibling_internal_nodes_share_prefix_but_disambiguate() {
        // Two vaults owned by the same account share the owner prefix yet must
        // not collide even when their substate (partition + sort key) matches —
        // the low half hashes the full key, which embeds each vault's own id.
        let owner = NodeId([1u8; NODE_ID_LEN]);
        let v1 = NodeId([10u8; NODE_ID_LEN]);
        let v2 = NodeId([20u8; NODE_ID_LEN]);
        let k1 = jmt_leaf_key(&storage_key(v1, 0, b"balance"), Some(owner));
        let k2 = jmt_leaf_key(&storage_key(v2, 0, b"balance"), Some(owner));
        assert_eq!(k1[..16], k2[..16]);
        assert_ne!(k1, k2);
    }
}
