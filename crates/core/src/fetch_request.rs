//! Typed dispatch into the unified fetch protocols.
//!
//! Coordinators emit [`crate::Action::Fetch`] wrapping one of these variants
//! when they need the runner to issue a network fetch. `io_loop`'s dispatcher
//! has a single `Action::Fetch(req)` arm that matches on the inner enum and
//! calls into the corresponding `instances/*.rs` module.
//!
//! Peer selection is the network layer's job: the runner derives the
//! `ShardGroupId` from the variant (local shard for intra-shard variants;
//! `source_shard` or `wave_id.shard_group_id()` for cross-shard variants)
//! and hands it to `Network::request` along with `preferred`. Coordinators
//! never reach into the topology for committee membership when emitting
//! fetches.
//!
//! Per-payload variants are keyless (just `ids + preferred`); admission
//! events drive cancellation rather than scope-keyed eviction. Cross-shard
//! variants retain `(source_shard, block_height)` because that scope IS
//! the fetch key (no id-set to enumerate).

use hyperscale_types::{
    BlockHeight, MessageClass, ProvisionHash, ShardGroupId, TxHash, ValidatorId, WaveId,
};

/// Fetch family — one variant per payload type.
///
/// Each variant carries:
/// - `shard: ShardGroupId` — the shard whose committee serves the
///   request. Pending-block / intra-shard fetches use the local shard;
///   cross-shard DA paths use the source shard.
/// - `preferred: Option<ValidatorId>` — canonical-source hint passed to
///   `Network::request`. `Some(proposer)` for BFT-path fetches;
///   `None` for catch-up / DA paths.
/// - `class: Option<MessageClass>` — class override forwarded to
///   `Network::request`. `None` keeps the wire type's static
///   `NetworkMessage::class()`; `Some` demotes to a less-urgent class
///   for catch-up / best-effort traffic (typically `Recovery`).
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Transaction fetch by id.
    Transactions {
        /// Transaction hashes to fetch.
        ids: Vec<TxHash>,
        /// Shard whose committee serves the request (local for BFT-path
        /// fetches, source shard for the mempool's cross-shard DA path).
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// Local-provision fetch by id.
    LocalProvisions {
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
        /// Shard whose committee serves the request (always local — the
        /// payload is intra-shard DA).
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// Finalized-wave fetch by id.
    FinalizedWaves {
        /// Wave ids to fetch.
        ids: Vec<WaveId>,
        /// Shard whose committee serves the request (always local — the
        /// payload is intra-shard DA).
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// Cross-shard provisions fetch keyed by `(source_shard, block_height)`.
    /// Routing shard is `source_shard`.
    RemoteProvisions {
        /// Source shard whose provisions are missing.
        source_shard: ShardGroupId,
        /// Source-shard block height for the missing provisions.
        block_height: BlockHeight,
        /// Canonical-source hint — `Some(source-block proposer)`; they
        /// originated the provisions.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// Cross-shard execution-cert fetch by `WaveId`. Routing shard is
    /// `wave_id.shard_group_id()` (the shard that committed the source
    /// block).
    ExecutionCerts {
        /// Wave whose EC is missing.
        wave_id: WaveId,
        /// No canonical preferred — the wave's designated broadcaster
        /// role is computable but the network's health-weighted
        /// selection works equally well empirically.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
}
