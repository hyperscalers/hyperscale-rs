//! The [`Cluster`] trait: the harness-agnostic surface a scenario drives.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_crypto_bls::BlsSigner;
use hyperscale_engine::{PreviewGrants, PreviewReport};
use hyperscale_storage::RowState;
use hyperscale_types::{
    Address, BeaconState, BlockHeight, ChainOrigin, DeclaredRange, Derivation, Epoch, Event, Heard,
    PriceTable, ShardId, Signer, StandingAnswers, StandingToward, StateRoot, SubstateKey,
    TopologySnapshot, Transaction, TransactionDecision, TransactionStatus, TxHash, TxsInFlight,
    ValidatorId, WeightedTimestamp,
};

use super::Budget;
use super::query::{ChainMentions, ClaimsSection, RanAs, shard_decisions, status_rank};

/// The shards a submission of `tx` may enter at, the fee payer's first.
///
/// The payer's shard proposes the transaction, so a host serving it
/// carries a submission into a block on its own. A host serving only
/// another touched shard parks the submission until the payer's shard
/// engages it, and the only thing that prompts the payer's shard is the
/// gossip the submitting host sends — a fault that suppresses gossip
/// strands it there. Routing to the payer's shard is what a client does,
/// and it is what keeps a gossip fault a fault in delivery rather than in
/// submission.
///
/// # Panics
///
/// On a transaction whose root states no terms, which no scenario
/// builds.
#[must_use]
pub fn submission_shards(snapshot: &TopologySnapshot, tx: &Transaction) -> Vec<ShardId> {
    // Read off the envelope rather than the derivation: a submission
    // has not been verified yet, and routing it is what a client does.
    let payer = tx.body().terms.fee_payer;
    let payer = snapshot.shard_for_prefix(payer);
    let mut shards = vec![payer];
    shards.extend(
        snapshot
            .all_shards_for_transaction(tx)
            .into_iter()
            .filter(|&shard| shard != payer),
    );
    shards
}

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

    /// Submit a transaction to a host of `shard`, whatever its source
    /// shard would have been.
    ///
    /// What a client does when the shard that would run its transaction
    /// is not the one routing would pick. The case is a late delivery:
    /// the producing shard is long past the window it could include the
    /// transaction in and refuses it, where the delivering shard admits
    /// it on the record it consumes still standing.
    fn submit_to(&mut self, shard: ShardId, tx: Arc<Transaction>);

    /// A derivation the cluster answers alike to — what a scenario reads
    /// a routed fact off a transaction it built itself through.
    ///
    /// A transaction assembled in the scenario has been derived by
    /// nobody: routing, work and the rest are a node's answer, and the
    /// harness has to borrow one to ask.
    fn derivation(&self) -> Arc<dyn Derivation>;

    /// The price table the cluster's head window carries.
    ///
    /// A scenario quoting a fee asks the chain rather than a constant:
    /// the level moves with the fold, so a fixture pinned to the genesis
    /// table would start failing the first time a scenario ran long
    /// enough for the controller to move.
    fn prices(&self) -> PriceTable {
        self.beacon_state()
            .map_or(PriceTable::GENESIS, |state| state.prices)
    }

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

    /// The committed clock of `shard`'s block at `height`: its parent
    /// QC's weighted timestamp, where a host holds the block. A chain's
    /// own measure of time between two of its blocks, at the resolution
    /// of its quorum's votes rather than of a scenario's polls.
    fn committed_clock(&self, _shard: ShardId, _height: BlockHeight) -> Option<WeightedTimestamp> {
        None
    }

    /// Whether any host currently serves `shard`.
    fn serves_shard(&self, shard: ShardId) -> bool;

    /// The latest committed beacon state across the cluster (highest epoch).
    fn beacon_state(&self) -> Option<Arc<BeaconState>>;

    /// For each host still running `shard`'s loop: the oldest epoch whose
    /// window the host's beacon fold retains, and whether the loop's
    /// replica reads itself dissolved. Empty where the harness cannot
    /// look inside a host.
    fn running_loops(&self, _shard: ShardId) -> Vec<(Epoch, bool)> {
        Vec::new()
    }

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

    /// The validators this cluster runs that beacon genesis left out, with
    /// the keys they sign under, for [`grow_and_hold`](crate::grow_and_hold)
    /// to register once the grown topology holds.
    ///
    /// Each follows the beacon from boot like any pool extra, so it serves
    /// as soon as the fold admits it. Empty for a cluster that registered
    /// every validator at genesis; see
    /// [`ScenarioConfig::staged_pool_extras`](crate::ScenarioConfig::staged_pool_extras).
    fn staged_validators(&self) -> Vec<(ValidatorId, Arc<dyn Signer>)>;

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

    /// The committed entries of one collection interval on `shard`, read
    /// straight from a hosted store, ascending by order key. `None` when
    /// no host serves `shard`.
    ///
    /// The same observation seam as [`substate`](Self::substate), for
    /// what a collection holds rather than what a cell does.
    fn entries(&self, shard: ShardId, range: DeclaredRange) -> Option<Vec<(u128, Vec<u8>)>> {
        let _ = (shard, range);
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

    /// Where `shard`'s chain starts: its genesis height, and the weighted
    /// time anchor that is the cut a reshape successor judges pre-cut
    /// content against.
    ///
    /// [`ChainOrigin::ROOT`] for a chain born at network genesis, so a
    /// scenario reading it before a reshape sees "nothing predates this".
    /// `None` when no host serves `shard`.
    ///
    /// An observation seam: a scenario asserting on the pre-cut rule needs
    /// the rule's own input to know its candidate really is pre-cut, and
    /// nothing on the chain carries it.
    fn chain_origin(&self, shard: ShardId) -> Option<ChainOrigin>;

    /// The work `shard`'s committed tip leaves owing against the drain.
    ///
    /// `None` when no host serves `shard`, or when its tip carries no
    /// header a hosted store can answer for.
    ///
    /// An observation seam, like [`Self::chain_origin`]: a scenario
    /// asserting that stranded work returns to the drain has to read the
    /// level itself, and no transaction status reports it.
    fn committed_txs_in_flight(&self, shard: ShardId) -> Option<TxsInFlight>;

    /// Where each row `shard`'s own member collection holds at its tip
    /// stands, or `None` where this cluster cannot read state entries.
    ///
    /// An observation seam, like [`Self::committed_txs_in_flight`]: a
    /// terminal fates every row it holds, whether a successor reads one
    /// as its own is a fact about committed state no status reports, and
    /// so is which member a tick holds while another waits on it.
    fn member_rows(&self, _shard: ShardId) -> Option<BTreeMap<TxHash, RowState>> {
        None
    }

    /// What `shard`'s tip stands holding as its answer cap counts it:
    /// every answer its crossing rows hold, by producer route, and the
    /// crossings its member rows still owe, read whole off the store;
    /// `None` where this cluster cannot read state entries.
    ///
    /// An observation seam, like [`Self::member_rows`]: a recount
    /// independent of the count the coordinator keeps, so a scenario can
    /// hold the cap's bound against committed state.
    fn standing_answers(&self, _shard: ShardId) -> Option<StandingAnswers> {
        None
    }

    /// The rows `shard`'s tip holds toward each shard their settlement
    /// awaits, with the crossings they owe, or `None` where this cluster
    /// cannot read state entries.
    fn standing_toward(&self, _shard: ShardId) -> Option<StandingToward> {
        None
    }

    /// What the row `shard`'s tip holds for `tx` has heard of its
    /// siblings' verdicts: empty where no row stands, where it has heard
    /// nothing, or where this cluster cannot read state entries.
    ///
    /// An observation seam, like [`Self::member_rows`]: what a row has
    /// heard is committed state no status reports.
    fn heard(&self, _shard: ShardId, _tx: TxHash) -> Vec<Heard> {
        Vec::new()
    }

    /// Whether `shard`'s own member collection stood quiet at `height`:
    /// no row shared in flight, stated or accepted. `None` where this
    /// cluster cannot read state entries.
    ///
    /// # Panics
    ///
    /// Where this cluster reads state entries but holds no store of
    /// `shard` retaining `height`.
    ///
    /// An observation seam, like [`Self::member_rows`]: the rows a
    /// terminal fated are deleted by it, so only the state at its parent
    /// says whether the cut fell under a row that heard.
    fn quiet_at(&self, _shard: ShardId, _height: BlockHeight) -> Option<bool> {
        None
    }

    /// The furthest status any host reports for `tx`: what a scenario
    /// waiting on a transaction wants.
    ///
    /// # Panics
    ///
    /// As [`shard_decisions`] does, which every read of a status
    /// checks.
    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus> {
        let _ = shard_decisions(self, tx);
        self.tx_statuses(tx)
            .into_iter()
            .map(|(status, _)| status)
            .max_by_key(status_rank)
    }

    /// Every host's last reported status for `tx`, with the shard that
    /// reported it, where it reported one.
    fn tx_statuses(&self, tx: TxHash) -> Vec<(TransactionStatus, ShardId)>;

    /// What `shard`'s own certificates said it ran of `tx`, in commit
    /// order — the memberships it froze, not what the end state implies.
    ///
    /// An observation seam, like [`Self::chain_origin`]: a whole
    /// shape replicated on every participant and a shape divided into a
    /// core and its legs settle to the same balances, and a scenario
    /// asserting the divided path has to read which one ran. A shard
    /// that ran a member and later abandoned it reports both.
    fn ran(&self, shard: ShardId, tx: TxHash) -> Vec<RanAs>;

    /// Every abandonment record on `shard`'s chain naming `tx`: the
    /// height each committed at and the departed shard it speaks for.
    ///
    /// An observation seam like [`Self::ran`]: a record licenses an
    /// abandonment, and whether a chain wrote one for a transaction is
    /// a fact about its blocks that no balance reads back once the
    /// abandonment and the settlement it races have both landed.
    fn named_unsettled(&self, shard: ShardId, tx: TxHash) -> Vec<(BlockHeight, ShardId)>;

    /// Whether `shard`'s chain has carried a held reading of `key`, on
    /// any live store of the shard: how a crossing record reaches the
    /// shard that consumes it.
    fn reads_record(&self, shard: ShardId, key: SubstateKey) -> bool;

    /// How long `shard`'s chain waited for the record at `key` once it
    /// had committed `tx`, on its own committed clock, or `None` until
    /// it carries both, and where this cluster keeps no chain it walks
    /// that way.
    ///
    /// An observation seam beside [`Self::reads_record`]: that a record
    /// was read says nothing of what brought the reading, and a reading
    /// its consumer had to wait out a clock for rides a block at least
    /// that clock past the commit that filed the want.
    fn record_wait(&self, _shard: ShardId, _tx: TxHash, _key: SubstateKey) -> Option<Duration> {
        None
    }

    /// Every crossing decline on `shard`'s chain naming `tx`: the height
    /// each committed at and the record it refuses.
    ///
    /// An observation seam on [`Self::named_unsettled`]'s terms, and for
    /// the same reason: a decline licenses a producer to credit its
    /// value back, and whether a chain wrote one is a fact about its
    /// blocks rather than a balance — a crossing nobody ever answered
    /// and one refused in so many words leave the same value in the same
    /// cell until the producer acts on the difference.
    fn declined(&self, shard: ShardId, tx: TxHash) -> Vec<(BlockHeight, SubstateKey)>;

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

    /// The height at which `shard`'s chain burned `tx`'s price, if it
    /// has: the block carrying the finalization of the member that held
    /// its row, or its fate. Apart from [`chain_fate`](Self::chain_fate)'s
    /// decision, which says what the chain decided and not whether it
    /// burned anything.
    fn chain_burn(&self, shard: ShardId, tx: TxHash) -> Option<BlockHeight>;

    /// What credits committed on `shard`'s chain burned past
    /// `u128::MAX` on `key`: the most any host serving the chain counted
    /// over the blocks it committed itself. Zero where no host serves it.
    fn credit_burned(&self, shard: ShardId, key: SubstateKey) -> u128;

    /// Everything `shard`'s chain carries of `txs` from `from` up, read
    /// in one walk, or `None` where this cluster keeps no chain it walks
    /// that way.
    ///
    /// [`chain_fate`](Self::chain_fate), [`chain_burn`](Self::chain_burn)
    /// and [`named_unsettled`](Self::named_unsettled) for a whole set at
    /// once: each of those walks the chain for one transaction, which a
    /// scenario following thousands of them cannot repeat for each.
    fn chain_mentions(
        &self,
        _shard: ShardId,
        _from: BlockHeight,
        _txs: &BTreeSet<TxHash>,
    ) -> Option<ChainMentions> {
        None
    }

    /// Submit `tx` once `delay` of the cluster's clock has passed, and
    /// whether the delay was kept: a cluster that cannot schedule a
    /// submission makes it at once and says so, so a scenario spreading
    /// its offers can report the arrival it got.
    fn submit_after(&mut self, delay: Duration, tx: Arc<Transaction>) -> bool {
        let _ = delay;
        self.submit(tx);
        false
    }

    /// What each block of `shard`'s chain from `from` up carried in its
    /// claims section, in one walk, or `None` where this cluster keeps
    /// no chain it walks that way.
    ///
    /// An observation seam, like [`Self::chain_mentions`]: the section
    /// is one budget every reading of a block shares, and what each
    /// kind of reading took of it is a fact about the block that no
    /// counter summed over replicas and shards reads back.
    fn claims_sections(&self, _shard: ShardId, _from: BlockHeight) -> Option<Vec<ClaimsSection>> {
        None
    }

    /// The retirements each block of `shard`'s chain from `from` up read,
    /// by the shard each was read at, in one walk, or `None` where this
    /// cluster keeps no chain it walks that way.
    ///
    /// An observation seam, like [`Self::claims_sections`]: which
    /// consumer a producer retired toward is a fact about its blocks
    /// that no counter summed over replicas and shards reads back.
    fn retirements_by_holder(
        &self,
        _shard: ShardId,
        _from: BlockHeight,
    ) -> Option<BTreeMap<ShardId, u64>> {
        None
    }
}
