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
    BlockHeight, MessageClass, ProvisionHash, ShardGroupId, TxHash, ValidatorId, WaveId, WaveIdHash,
};

/// Why a fetch was issued.
///
/// Maps to a [`MessageClass`] override at the network layer so the same
/// wire type (e.g. `GetTransactionsRequest`) can be issued with different
/// urgency depending on the caller's context.
///
/// Most call sites match the wire type's static `NetworkMessage::class()`,
/// so the override is `None`. The override fires when the caller is *less
/// urgent* than the static default — e.g. the mempool DA-backfill path
/// issues `GetTransactionsRequest` (statically `BlockCompletion`) but
/// should be treated as `Recovery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FetchOrigin {
    /// Pending-block voting path (BFT pending state machine). Hot path —
    /// loss extends the current voting window.
    PendingBlock,
    /// Cross-shard execution dependency (provisions / EC fallback). Stalls
    /// cross-shard execution but local consensus continues.
    CrossShard,
    /// Mempool DA-backfill — best-effort propagation of txs the mempool
    /// missed via gossip. No live BFT round depends on this.
    Mempool,
    /// Sync / catch-up — node behind, recovering toward live state.
    Sync,
}

impl FetchOrigin {
    /// Class override for [`Network::request`](hyperscale_network::Network).
    ///
    /// `None` keeps the wire type's static `NetworkMessage::class()`; `Some`
    /// demotes to a less-urgent class for catch-up / best-effort traffic.
    #[must_use]
    pub const fn class_override(self) -> Option<MessageClass> {
        match self {
            Self::PendingBlock | Self::CrossShard => None,
            Self::Mempool | Self::Sync => Some(MessageClass::Recovery),
        }
    }
}

/// Peer pool plus an optional canonical-source hint.
///
/// `preferred` is a hint to the network's selector — it tries this peer
/// first if it's in the pool, then falls back to health-weighted selection
/// over `peers`. Set `preferred` only when there's a structural reason
/// to expect one peer to have the data first (e.g. block proposer for
/// BFT-path fetches). Use `None` when any peer in the pool is equally
/// likely to serve.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        /// Why this fetch was issued; drives the network class override.
        origin: FetchOrigin,
    },
    /// Local-provision fetch by id.
    LocalProvisions {
        /// Provision hashes to fetch.
        ids: Vec<ProvisionHash>,
        /// Peer pool. BFT-path emitters set `preferred = Some(proposer)`.
        peers: FetchPeers,
        /// Why this fetch was issued; drives the network class override.
        origin: FetchOrigin,
    },
    /// Finalized-wave fetch by id.
    FinalizedWaves {
        /// Wave-id hashes to fetch.
        ids: Vec<WaveIdHash>,
        /// Peer pool. BFT-path emitters set `preferred = Some(proposer)`.
        peers: FetchPeers,
        /// Why this fetch was issued; drives the network class override.
        origin: FetchOrigin,
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
        /// Why this fetch was issued; drives the network class override.
        origin: FetchOrigin,
    },
    /// Cross-shard execution-cert fetch by `WaveId`.
    ExecutionCerts {
        /// Wave whose EC is missing.
        wave_id: WaveId,
        /// Source-shard peer pool. No canonical preferred — the wave's
        /// designated broadcaster role is computable but the network's
        /// health-weighted selection works equally well empirically.
        peers: FetchPeers,
        /// Why this fetch was issued; drives the network class override.
        origin: FetchOrigin,
    },
}
