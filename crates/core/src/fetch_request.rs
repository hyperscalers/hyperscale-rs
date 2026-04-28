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

/// Peer pool plus an optional canonical-source hint.
///
/// `preferred` is a hint to the network's selector — it tries this peer
/// first if it's in the pool, then falls back to health-weighted selection
/// over `peers`. Set `preferred` only when there's a structural reason
/// to expect one peer to have the data first (e.g. block proposer for
/// BFT-path fetches). Use `None` when any peer in the pool is equally
/// likely to serve.
#[derive(Debug, Clone)]
pub struct FetchPeers {
    /// Peer to try first each round, when one peer has a structural reason
    /// to be the canonical source. `None` for "no preferred — let the
    /// network pick by health/RTT."
    pub preferred: Option<ValidatorId>,
    /// Rotation pool walked after `preferred` (or as the full pool when
    /// `preferred` is `None`).
    pub peers: Vec<ValidatorId>,
}

impl FetchPeers {
    /// Build a peer set with a canonical-source hint.
    #[must_use]
    pub const fn with_preferred(preferred: ValidatorId, peers: Vec<ValidatorId>) -> Self {
        Self {
            preferred: Some(preferred),
            peers,
        }
    }

    /// Build a peer set with no canonical source — any peer in the pool is
    /// equally suitable; selection is left to the network layer.
    #[must_use]
    pub const fn rotation(peers: Vec<ValidatorId>) -> Self {
        Self {
            preferred: None,
            peers,
        }
    }
}

/// Fetch family — one variant per payload type.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Transaction fetch by id.
    Transactions {
        /// Transaction hashes to fetch.
        ids: Vec<TxHash>,
        /// Peer pool. BFT-path emitters set `preferred = Some(proposer)`;
        /// the mempool DA path uses `None`.
        peers: FetchPeers,
    },
    /// Local-provision fetch by id.
    LocalProvisions {
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
        /// Peer pool. BFT-path emitters set `preferred = Some(proposer)`.
        peers: FetchPeers,
    },
    /// Finalized-wave fetch by id.
    FinalizedWaves {
        /// Wave-id hashes to fetch.
        ids: Vec<WaveIdHash>,
        /// Peer pool. BFT-path emitters set `preferred = Some(proposer)`.
        peers: FetchPeers,
    },
    /// Cross-shard provisions fetch (`ScopeFetch` keyed by
    /// `(ShardGroupId, BlockHeight)`).
    RemoteProvisions {
        /// Source shard whose provisions are missing.
        source_shard: ShardGroupId,
        /// Source-shard block height for the missing provisions.
        block_height: BlockHeight,
        /// Source-shard peer pool. `preferred = Some(source-block proposer)`
        /// — they originated the provisions.
        peers: FetchPeers,
    },
    /// Cross-shard execution-cert fetch by `WaveId`.
    ExecutionCerts {
        /// Wave whose EC is missing.
        wave_id: WaveId,
        /// Source-shard peer pool. No canonical preferred — the wave's
        /// designated broadcaster role is computable but the network's
        /// health-weighted selection works equally well empirically.
        peers: FetchPeers,
    },
    /// Cross-shard committed-block-header fetch (`ScopeFetch` keyed by
    /// `(ShardGroupId, BlockHeight)`).
    RemoteHeader {
        /// Source shard whose headers are missing.
        source_shard: ShardGroupId,
        /// First missing height (fetch starts from here).
        from_height: BlockHeight,
        /// Source-shard peer pool. No canonical preferred — any peer can
        /// serve.
        peers: FetchPeers,
    },
}
