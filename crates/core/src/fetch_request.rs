//! Typed dispatch into the unified fetch protocols.
//!
//! Coordinators emit [`crate::Action::Fetch`] wrapping one of these variants
//! when they need the runner to issue a network fetch. `io_loop`'s dispatcher
//! has a single `Action::Fetch(req)` arm that matches on the inner enum and
//! calls into the corresponding `instances/*.rs` module.

use hyperscale_types::{
    BlockHash, BlockHeight, ProvisionHash, ShardGroupId, TxHash, ValidatorId, WaveId, WaveIdHash,
};

/// Fetch family — one variant per payload type.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Per-block transaction fetch (`HashSetFetch` keyed by `BlockHash`,
    /// id = `TxHash`). Pinned to the proposer.
    Transactions {
        /// Pending block waiting on these transactions.
        block_hash: BlockHash,
        /// Block proposer (single fetch target — no peer rotation).
        proposer: ValidatorId,
        /// Transaction hashes to fetch.
        ids: Vec<TxHash>,
    },
    /// Per-block local-provision fetch (`HashSetFetch` keyed by `BlockHash`,
    /// id = `ProvisionHash`). Pinned to the proposer.
    LocalProvisions {
        /// Pending block waiting on these provisions.
        block_hash: BlockHash,
        /// Block proposer (single fetch target).
        proposer: ValidatorId,
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
    },
    /// Per-block finalized-wave fetch (`HashSetFetch` keyed by `BlockHash`,
    /// id = `WaveIdHash`). Rotates from the proposer through local-committee
    /// peers.
    FinalizedWaves {
        /// Pending block waiting on these waves.
        block_hash: BlockHash,
        /// Block proposer (tried first).
        proposer: ValidatorId,
        /// Wave-id hashes to fetch.
        ids: Vec<WaveIdHash>,
        /// Local-committee fallback peers.
        peers: Vec<ValidatorId>,
    },
    /// Cross-shard provisions fetch (`ScopeFetch` keyed by
    /// `(ShardGroupId, BlockHeight)`). Falls back to source-shard peers.
    RemoteProvisions {
        /// Source shard whose provisions are missing.
        source_shard: ShardGroupId,
        /// Source-shard block height for the missing provisions.
        block_height: BlockHeight,
        /// Source-shard block proposer (tried first).
        proposer: ValidatorId,
        /// Source-shard committee (fallback peers).
        peers: Vec<ValidatorId>,
    },
    /// Cross-shard execution-cert fetch (`HashSetFetch` keyed by
    /// `(ShardGroupId, BlockHeight)`, id = `WaveId`). Rotates through
    /// source-shard committee.
    ExecutionCerts {
        /// Source shard whose EC is missing.
        source_shard: ShardGroupId,
        /// Source-shard block height for the missing EC.
        block_height: BlockHeight,
        /// Wave whose EC is missing.
        wave_id: WaveId,
        /// Source-shard committee (candidate peers).
        peers: Vec<ValidatorId>,
    },
    /// Cross-shard committed-block-header fetch (`ScopeFetch` keyed by
    /// `(ShardGroupId, BlockHeight)`).
    RemoteHeader {
        /// Source shard whose headers are missing.
        source_shard: ShardGroupId,
        /// First missing height (fetch starts from here).
        from_height: BlockHeight,
        /// Source-shard committee (candidate peers).
        peers: Vec<ValidatorId>,
    },
}
