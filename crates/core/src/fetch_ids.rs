//! The ids of one fetch family, in one shape.
//!
//! Every payload the unified fetch protocols address has its own id type,
//! and three messages carry a batch of them: a coordinator cancelling ids
//! it no longer wants ([`crate::Action::AbandonFetch`]), and the node's
//! own response boundary releasing ids a peer failed to answer or
//! answered in full. All three name the same `(binding, Vec<Id>)` pair,
//! so one enum spells it and one dispatcher routes it to the binding's
//! state machine.

use hyperscale_types::{
    Address, Anchor, BlockHash, BlockHeight, Epoch, FinalizationHash, Hash, LeafIndex,
    PredecessorTerminal, ProvisionHash, ShardId, SubstateKey, TerminalEvidence, TxHash,
    ValidatorId,
};

/// A batch of ids under the binding that fetches them, keyed exactly as
/// that binding's state machine is.
///
/// One variant per binding, which is not quite one per
/// [`crate::FetchRequest`]: a payload the node fetches without a request
/// variant of its own — a package artifact, an instance record — still
/// has ids to release, and so still has a variant here.
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
    /// Execution certificates as `(source_shard, tx_hash)`: the shard
    /// whose outcome is wanted and the transaction it is wanted for. A
    /// certificate answers for every transaction it covers, so a dropped
    /// one releases each of them.
    ExecutionCerts(Vec<(ShardId, TxHash)>),
    /// Committed-transaction membership queries as `(predecessor,
    /// tx_hash)`.
    CommittedTxs(Vec<(PredecessorTerminal, TxHash)>),
    /// State-proof probes as `(anchor, key)`.
    StateProofs(Vec<(Anchor, SubstateKey)>),
    /// Departed shards' settled sets, by the terminal each is checked
    /// against.
    SettledTxs(Vec<TerminalEvidence>),
    /// Missing beacon proposals as `(epoch, validator)`.
    BeaconProposals(Vec<(Epoch, ValidatorId)>),
    /// Beacon-witness leaf runs as `(source_shard, block_height,
    /// committed_block_hash, lo, hi)`.
    ShardWitnesses(Vec<(ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex)>),
    /// Package artifacts by content address.
    PackageArtifacts(Vec<Hash>),
    /// Component instance records by address.
    InstanceRecords(Vec<Address>),
}
