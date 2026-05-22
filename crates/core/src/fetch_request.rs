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
/// Common field semantics across variants:
///
/// - `shard` — committee whose members will serve the request. Local for
///   intra-shard fetches; source shard for cross-shard DA fetches.
/// - `preferred` — canonical-source hint passed straight to
///   `Network::request`. `Some(proposer)` on shard-path fetches where one
///   peer is authoritative; `None` on catch-up / DA paths that fan out.
/// - `class` — overrides the wire type's static `NetworkMessage::class()`.
///   `None` keeps the default; `Some` demotes to a less-urgent class
///   (typically `Recovery`) for catch-up / best-effort traffic.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Transaction bodies by `TxHash` — shard-path fetches against the
    /// local shard's committee.
    Transactions {
        /// Transaction hashes to fetch.
        ids: Vec<TxHash>,
        /// Committee shard serving the request.
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// Intra-shard DA payload — `shard` is always local.
    LocalProvisions {
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
        /// Always the local shard for this variant.
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// Intra-shard DA payload — `shard` is always local.
    FinalizedWaves {
        /// Wave ids whose finalized waves are missing.
        ids: Vec<WaveId>,
        /// Always the local shard for this variant.
        shard: ShardGroupId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// Cross-shard provisions fetch keyed by `(source_shard, block_height)`.
    /// Routing shard is `source_shard`; `preferred` is the source-block
    /// proposer that originated the provisions.
    RemoteProvisions {
        /// Source shard whose provisions are missing.
        source_shard: ShardGroupId,
        /// Source-shard block height the missing provisions are anchored to.
        block_height: BlockHeight,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// Cross-shard execution-cert fetch by `WaveId`. Routing shard is
    /// `wave_id.shard_group_id()` (the shard that committed the source
    /// block). `preferred` is `None` — the wave's designated broadcaster
    /// role is computable but health-weighted selection works equally
    /// well empirically.
    ExecutionCerts {
        /// Wave whose execution certificate is missing.
        wave_id: WaveId,
        /// Always `None` for this variant; see variant-level doc.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
}
