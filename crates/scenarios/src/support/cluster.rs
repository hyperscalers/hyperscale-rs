//! The [`Cluster`] trait: the harness-agnostic surface a scenario drives.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_crypto_bls::BlsSigner;
use hyperscale_engine::{PreviewGrants, PreviewReport};
use hyperscale_types::{
    Address, BeaconState, BlockHeight, Derivation, Event, ShardId, Signer, StateRoot, Transaction,
    TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp, WorkInFlight,
};

use super::Budget;
use super::query::RanAs;

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
    fn submit(&mut self, tx: Arc<Transaction>);

    /// A derivation the cluster answers alike to — what a scenario reads
    /// a routed fact off a transaction it built itself through.
    ///
    /// A transaction assembled in the scenario has been derived by
    /// nobody: routing, work and the rest are a node's answer, and the
    /// harness has to borrow one to ask.
    fn derivation(&self) -> Arc<dyn Derivation>;

    /// Advance the cluster until `cond` holds or `budget` epochs elapse;
    /// return whether `cond` held.
    ///
    /// Sim drives its logical clock (and pumps reshape); production blocks on a
    /// poll loop while reshape advances organically via the supervisor.
    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool;

    /// Elapsed time since genesis on the cluster's own clock — for building
    /// transaction validity windows. Sim returns its logical now; production
    /// returns wall-clock since start.
    fn now(&self) -> Duration;

    /// The highest committed block height on `shard`, if any host serves it.
    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight>;

    /// The committed state root at `shard`'s tip, if any host serves it.
    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot>;

    /// Whether any host currently serves `shard`.
    fn serves_shard(&self, shard: ShardId) -> bool;

    /// The latest committed beacon state across the cluster (highest epoch).
    fn beacon_state(&self) -> Option<Arc<BeaconState>>;

    /// Upper bound on the wall-clock cost for a submitted governance vote to
    /// fold into the beacon: transaction inclusion, an epoch-boundary crossing
    /// carrying the vote leaf, and a beacon quorum observing that crossing.
    /// The cascade is priced by the harness's clock, not by epoch count — the
    /// default covers a logical-clock harness that delivers every hop in
    /// simulated milliseconds; a real-network cluster overrides with the
    /// seconds-per-hop cost it actually pays. Scenarios divide this by the
    /// epoch length to size epoch-denominated vote leads.
    fn vote_fold_budget_ms(&self) -> u64 {
        5_000
    }

    /// Derive a deterministic signer under the cluster's own crypto
    /// scheme — for fixtures that mint keys outside the hosted set
    /// (e.g. validator-registration witnesses, whose possession proofs
    /// the beacon fold verifies with the cluster's verifier). Defaults
    /// to BLS, the production scheme; the sim harness overrides per its
    /// configured scheme.
    fn signer_from_seed(&self, seed: &[u8; 32]) -> Arc<dyn Signer> {
        Arc::new(BlsSigner::from_seed(seed))
    }

    /// The committed value of a cell on `shard`, read straight from a
    /// hosted store. `None` when no host serves `shard` or the cell is
    /// absent.
    ///
    /// An observation seam, not a protocol one: scenarios assert against
    /// committed state, and nothing a transaction carries comes from here.
    fn substate(&self, shard: ShardId, owner: Address, local: [u8; 16]) -> Option<Vec<u8>> {
        let _ = (shard, owner, local);
        None
    }

    /// What `tx` would move and cost, run against `shard`'s committed tip
    /// without committing anything.
    ///
    /// Engine-side and consensus-free: the transaction is never
    /// submitted, gossiped, or included, and nothing it computes is
    /// attested. `None` when no hosted store on `shard` can serve the
    /// snapshot and the tip whose clock the run reads.
    fn preview(
        &self,
        shard: ShardId,
        tx: &Transaction,
        grants: PreviewGrants,
    ) -> Option<PreviewReport> {
        let _ = (shard, tx, grants);
        None
    }

    /// The events `shard`'s own copy of `tx`'s receipt carries.
    ///
    /// An event is stored where its emitter lives, so this differs by
    /// shard for a multi-shard transaction by design. `None` when no
    /// hosted store on `shard` holds the receipt.
    fn events(&self, shard: ShardId, tx: TxHash) -> Option<Vec<Event>> {
        let _ = (shard, tx);
        None
    }

    /// The weighted-time anchor `shard`'s chain starts at — the cut a
    /// reshape successor judges pre-cut content against.
    ///
    /// `WeightedTimestamp::ZERO` for a chain born at network genesis, so a
    /// scenario reading it before a reshape sees "nothing predates this".
    /// `None` when no host serves `shard`.
    ///
    /// An observation seam: a scenario asserting on the pre-cut rule needs
    /// the rule's own input to know its candidate really is pre-cut, and
    /// nothing on the chain carries it.
    fn chain_origin_anchor(&self, shard: ShardId) -> Option<WeightedTimestamp>;

    /// The work `shard`'s committed tip leaves owing against the drain.
    ///
    /// `None` when no host serves `shard`, or when its tip carries no
    /// header a hosted store can answer for.
    ///
    /// An observation seam, like [`Self::chain_origin_anchor`]: a scenario
    /// asserting that stranded work returns to the drain has to read the
    /// level itself, and no transaction status reports it.
    fn committed_work_in_flight(&self, shard: ShardId) -> Option<WorkInFlight>;

    /// The status of `tx`, if any hosted mempool or execution still tracks it.
    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus>;

    /// What `shard`'s own certificates said it ran of `tx`, in commit
    /// order — the memberships it froze, not what the end state implies.
    ///
    /// An observation seam, like [`Self::chain_origin_anchor`]: a whole
    /// shape replicated on every participant and a shape divided into a
    /// core and its legs settle to the same balances, and a scenario
    /// asserting the divided path has to read which one ran. A shard
    /// that ran a member and later composed a reclaim for the same
    /// transaction reports both.
    fn ran(&self, shard: ShardId, tx: TxHash) -> Vec<RanAs>;

    /// Every abandonment record on `shard`'s chain naming `tx`: the
    /// height each committed at and the departed shard it speaks for.
    ///
    /// An observation seam like [`Self::ran`]: a record licenses a
    /// reclaim, and whether a chain wrote one for a transaction is a
    /// fact about its blocks that no balance reads back once the
    /// reclaim and the settlement it races have both landed.
    fn named_unsettled(&self, shard: ShardId, tx: TxHash) -> Vec<(BlockHeight, ShardId)>;

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
