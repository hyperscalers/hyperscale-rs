//! Per-provision wire limits.
//!
//! Hard caps applied at decode time on peer-supplied provision payloads.
//! Bound the SBOR pre-allocation a single merkle proof or per-tx entry
//! list can claim — independent of how many transactions a block
//! carries (which is governed by [`crate::shard::limits`]). Caps on the
//! substate key and value bytes themselves live with the canonical key
//! layout in [`crate::state_key`].

/// Cap on a serialized merkle proof at decode time.
///
/// The proof grows roughly with `claim_count × tree_depth × hash_size`.
/// With JMT decode-time caps of `10_000` claims and `100_000` sibling
/// hashes (32 bytes each), legitimate proofs sit well under 4 MiB; we
/// cap a touch above for headroom.
pub const MAX_MERKLE_PROOF_LEN: usize = 4 * 1024 * 1024;

/// Cap on `ProvisionEntry.entries` length at decode time.
///
/// Each entry is one substate the transaction touched on the source
/// shard. A transaction's substate footprint is bounded by its declared
/// node access ([`MAX_DECLARED_NODES_PER_TX`](crate::MAX_DECLARED_NODES_PER_TX))
/// times a small per-node substate count; `16_384` leaves comfortable
/// headroom for any realistic Radix tx and rejects obviously oversized
/// arrivals before allocation.
pub const MAX_STATE_ENTRIES_PER_TX: usize = 16_384;

/// Cap on `ProvisionEntry.owned_nodes` length at decode time.
///
/// One entry per `(internal_node, owning_account)` pair the source shard
/// authoritatively resolved. Bounded by the number of internal nodes a
/// tx's declared accounts can own — comfortably under
/// [`MAX_STATE_ENTRIES_PER_TX`](MAX_STATE_ENTRIES_PER_TX), reused here for
/// simplicity.
pub const MAX_OWNED_NODES_PER_TX: usize = MAX_STATE_ENTRIES_PER_TX;
