//! Per-provision wire limits.
//!
//! Hard caps applied at decode time on peer-supplied provision payloads.
//! Bound the SBOR pre-allocation a single state entry or merkle proof
//! can claim — independent of how many transactions a block carries
//! (which is governed by [`crate::block::limits`]).

/// Cap on `StateEntry.storage_key` length at decode time.
///
/// Real keys are `db_node_key` (50 bytes) + partition (1) + `sort_key`
/// (≤ a few hundred bytes for any realistic substate). 4 KiB is well
/// above any legitimate Radix substate key and rejects obviously
/// oversized arrivals before allocation.
pub const MAX_STATE_ENTRY_KEY_LEN: usize = 4 * 1024;

/// Cap on `StateEntry.value` length at decode time.
///
/// Radix substates have an engine-side ceiling well below this; the cap
/// exists to bound the SBOR `Vec<u8>` pre-allocation a peer can force on
/// a single `value` field.
pub const MAX_STATE_ENTRY_VALUE_LEN: usize = 1024 * 1024;

/// Cap on a serialized merkle proof at decode time.
///
/// The proof grows roughly with `claim_count × tree_depth × hash_size`.
/// With JMT decode-time caps of `10_000` claims and `100_000` sibling
/// hashes (32 bytes each), legitimate proofs sit well under 4 MiB; we
/// cap a touch above for headroom.
pub const MAX_MERKLE_PROOF_LEN: usize = 4 * 1024 * 1024;

/// Cap on `TxEntries.entries` length at decode time.
///
/// Each entry is one substate the transaction touched on the source
/// shard. A transaction's substate footprint is bounded by its declared
/// node access ([`MAX_DECLARED_NODES_PER_TX`](crate::MAX_DECLARED_NODES_PER_TX))
/// times a small per-node substate count; `16_384` leaves comfortable
/// headroom for any realistic Radix tx and rejects obviously oversized
/// arrivals before allocation.
pub const MAX_STATE_ENTRIES_PER_TX: usize = 16_384;
