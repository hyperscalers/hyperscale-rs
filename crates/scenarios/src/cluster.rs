//! The [`Cluster`] trait: the harness-agnostic surface a scenario drives.

use std::sync::Arc;

use hyperscale_types::{
    BeaconState, BlockHeight, RoutableTransaction, ShardId, StateRoot, TransactionDecision,
    TransactionStatus, TxHash,
};

use crate::Budget;

/// A running cluster of assembled nodes, observed and driven by a scenario.
///
/// Implemented twice — `SimCluster` over the in-process `SimulationRunner`
/// (logical clock) and `ProdCluster` over the production QUIC + `RocksDB` cluster
/// (wall-clock). The trait is the *intersection* of what both can do: a submit
/// rail, a clock-advancing [`run_until`](Cluster::run_until), and a handful of
/// synchronous observations. Anything derivable from these — beacon epoch,
/// split admission, anchor roots — lives in [`crate::query`] / [`crate::wait`]
/// as free combinators rather than as trait methods, so the two adaptors share
/// one definition and cannot silently diverge.
///
/// `run_until` takes `impl Fn(&Self) -> bool`, so the trait is not object-safe;
/// scenarios are generic (`fn scenario(c: &mut impl Cluster)`). The borrow is
/// sequential — the immutable closure borrow never overlaps the `&mut self`
/// advance inside `run_until`.
pub trait Cluster {
    /// Submit a transaction, routed to whichever host serves its source shard.
    fn submit(&mut self, tx: Arc<RoutableTransaction>);

    /// Advance the cluster until `cond` holds or `budget` epochs elapse;
    /// return whether `cond` held.
    ///
    /// Sim drives its logical clock (and pumps reshape); production blocks on a
    /// poll loop while reshape advances organically via the supervisor.
    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool;

    /// The highest committed block height on `shard`, if any host serves it.
    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight>;

    /// The committed state root at `shard`'s tip, if any host serves it.
    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot>;

    /// Whether any host currently serves `shard`.
    fn serves_shard(&self, shard: ShardId) -> bool;

    /// The latest committed beacon state across the cluster (highest epoch).
    fn beacon_state(&self) -> Option<Arc<BeaconState>>;

    /// The status of `tx`, if any hosted mempool or execution still tracks it.
    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus>;

    /// Where `tx` landed on `shard`: the height it committed at (if any), and
    /// the height plus decision of its execution outcome (if any).
    fn chain_fate(
        &self,
        shard: ShardId,
        tx: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    );
}
