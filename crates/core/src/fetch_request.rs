//! Typed dispatch into the unified fetch protocols.
//!
//! Coordinators emit [`crate::Action::Fetch`] wrapping one of these variants
//! when they need the runner to issue a network fetch. `io_loop`'s dispatcher
//! has a single `Action::Fetch(req)` arm that matches on the inner enum and
//! calls into the corresponding `instances/*.rs` module.
//!
//! Per-payload variants are keyless (just `ids + peers`); admission events
//! drive cancellation rather than scope-keyed eviction. Cross-shard variants
//! retain `(source_shard, block_height)` because that scope IS the fetch
//! key (no id-set to enumerate).

use hyperscale_types::{
    BlockHeight, ProvisionHash, ShardGroupId, TxHash, ValidatorId, WaveId, WaveIdHash,
};

/// Fetch family — one variant per payload type.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Transaction fetch by id. Pinned to the proposer (no rotation).
    Transactions {
        /// Transaction hashes to fetch.
        ids: Vec<TxHash>,
        /// Block proposer (single fetch target — no peer rotation).
        proposer: ValidatorId,
    },
    /// Local-provision fetch by id. Pinned to the proposer.
    LocalProvisions {
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
        /// Block proposer (single fetch target).
        proposer: ValidatorId,
    },
    /// Finalized-wave fetch by id. Rotates from the proposer through
    /// local-committee peers.
    FinalizedWaves {
        /// Wave-id hashes to fetch.
        ids: Vec<WaveIdHash>,
        /// Block proposer (tried first).
        proposer: ValidatorId,
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
    /// Cross-shard execution-cert fetch by `WaveId`. Rotates through
    /// source-shard committee.
    ExecutionCerts {
        /// Wave whose EC is missing.
        wave_id: WaveId,
        /// Source-shard committee (rotation pool).
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
