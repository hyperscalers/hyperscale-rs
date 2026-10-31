//! The ids of one fetch family, in one shape.
//!
//! Every payload the unified fetch protocols address has its own id type,
//! and three messages carry a batch of them: a coordinator cancelling ids
//! it no longer wants ([`crate::Action::AbandonFetch`],
//! [`crate::BeaconAction::AbandonFetch`]), and the node's own response
//! boundary releasing ids a peer failed to answer or answered in full.
//! All three name the same `(binding, Vec<Id>)` pair, so one enum per
//! loop spells it and that loop's one dispatcher routes it to the
//! binding's state machine.

use hyperscale_types::{
    Address, Anchor, BeaconBlockHash, BlockHash, BlockHeight, Epoch, FinalizationHash, Hash,
    LeafIndex, ProvisionHash, ShardId, SubstateKey, TerminalEvidence, TxHash, ValidatorId,
    VerdictCells,
};

/// A batch of ids under the shard-loop binding that fetches them, keyed
/// exactly as that binding's state machine is.
///
/// One variant per binding, which is not quite one per
/// [`crate::FetchRequest`]. The fetches the host's beacon loop drives
/// are [`BeaconFetchIds`]: no shard loop can be handed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchIds {
    /// Transactions by hash.
    Transactions(Vec<TxHash>),
    /// Intra-shard provision bundles by hash.
    LocalProvisions(Vec<ProvisionHash>),
    /// Finalizations by identity.
    Finalizations(Vec<FinalizationHash>),
    /// Cross-shard provision scopes as `(source_shard, target_shard,
    /// block_height)` — the requester's own shard is the target.
    RemoteProvisions(Vec<(ShardId, ShardId, BlockHeight)>),
    /// State-proof probes as `(anchor, key)`.
    StateProofs(Vec<(Anchor, SubstateKey)>),
    /// Verdict questions as `(anchor, cells)`: the three cells one
    /// question reads on a sibling, asked together so an answer holds
    /// each question whole. Fetched apart from [`Self::StateProofs`], so
    /// one that never returns holds no place a record, seat or sibling
    /// probe needs.
    VerdictProofs(Vec<(Anchor, VerdictCells)>),
    /// Departed shards' settled sets, by the terminal each is checked
    /// against.
    SettledTxs(Vec<TerminalEvidence>),
    /// Block proposals a committee member's vote named and this replica
    /// never received, by block hash.
    Proposals(Vec<BlockHash>),
}

/// The ids of the fetches the host's beacon loop drives: for its fold and
/// its participants, and the records and code every loop on the host
/// shares. The beacon loop's counterpart of [`FetchIds`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconFetchIds {
    /// Missing beacon proposals as `(epoch, validator)`.
    Proposals(Vec<(Epoch, ValidatorId)>),
    /// Ratify candidates a pool prevoted and the local member never
    /// received, as `(epoch, block_hash)`.
    Candidates(Vec<(Epoch, BeaconBlockHash)>),
    /// Beacon-witness leaf runs as `(source_shard, block_height,
    /// committed_block_hash, lo, hi)`.
    Witnesses(Vec<(ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex)>),
    /// Package artifacts by content address.
    PackageArtifacts(Vec<Hash>),
    /// Component instance records by address.
    InstanceRecords(Vec<Address>),
}
