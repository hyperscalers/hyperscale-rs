//! Two-sided conservation: what a scenario's world held before, what it
//! holds after, and the prices that account for the difference.
//!
//! The characteristic failure of an escrow design is value stranded —
//! issued, never claimed, never reclaimed — which is a shrink, and a
//! one-sided "never grows" read passes it. So a [`World`] is opened over
//! everything a scenario's transactions can reach and asserted equal on
//! both sides, with the one legitimate sink accounted for explicitly: every
//! transaction a receipt committed for burned its declared price, once,
//! whatever the verdict was. [`Charges`] keeps that sum.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_effects_bridge::vm_statics::crossing_records;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    Address, ResourceAddr, ShardId, ShardTrie, SubstateKey, Transaction, TransactionDecision,
    TransactionStatus, TxHash,
};

use super::query::{
    Locked, MAX_SEARCHED_DEPTH, assert_a_full_block_fits, declared_price, held, held_at, locked_at,
    owed_at, unclaimable_at,
};
use super::tx::{recipient, sender};
use super::{Budget, Cluster};

/// How long a settled world is held settled before it is asserted.
///
/// The equality a scenario drives to is reached on the way past if value
/// comes back twice, so the sample that matters is the one taken after
/// the chain has had room to credit it again. A duplicate reclaim is
/// composed by a proposer a block or two behind the first, and the
/// harness advances its clock a second at a time on either harness, so
/// a handful of seconds covers several blocks without pricing a beacon
/// epoch into every conservation check.
const SETTLED_TAIL: Duration = Duration::from_secs(5);

/// The world a [`build_probe_transfer_tx`](super::tx::build_probe_transfer_tx)
/// train reaches: the first genesis-funded sender and recipient, in protocol resource.
pub fn probe_world<C: Cluster + ?Sized>(c: &C) -> World {
    World::open(
        c,
        *PROTOCOL_RESOURCE,
        [sender(0).1.address(), recipient(0).address()],
        [],
    )
}

/// Everything a scenario's transactions can reach that holds one
/// resource, and what it summed to when the scenario opened it.
pub struct World {
    resource: ResourceAddr,
    holders: Vec<Address>,
    cells: Vec<SubstateKey>,
    /// Record cells a scenario's crossings may leave standing. A
    /// crossing an outbound leg consumes is owed to that consumer until
    /// it claims, so its value sits in the record rather than in any
    /// account — held, not stranded, and counted here so the two sides
    /// still balance.
    owed: Vec<SubstateKey>,
    before: u128,
    /// Whether anything has read the world since it was opened. A world
    /// nobody read asserted nothing, so one that drops unread fails its
    /// scenario.
    read: Cell<bool>,
}

/// Refused here rather than by `#[must_use]`, which a binding satisfies
/// without a read. Silent while a panic is already unwinding, so the
/// scenario's own failure is the one reported.
impl Drop for World {
    fn drop(&mut self) {
        assert!(
            self.read.get() || std::thread::panicking(),
            "{:?}: a conservation world was opened and never read",
            self.resource,
        );
    }
}

impl World {
    /// Open the ledger over `holders`' vaults of `resource` and over
    /// `cells` — value a component keeps in its own state, which no
    /// address reaches.
    ///
    /// # Panics
    ///
    /// Panics if the world holds nothing, since a conservation check over
    /// a world that started empty passes for free.
    pub fn open<C: Cluster + ?Sized>(
        c: &C,
        resource: ResourceAddr,
        holders: impl IntoIterator<Item = Address>,
        cells: impl IntoIterator<Item = SubstateKey>,
    ) -> Self {
        let mut world = Self {
            resource,
            holders: holders.into_iter().collect(),
            cells: cells.into_iter().collect(),
            owed: Vec::new(),
            before: 0,
            read: Cell::new(false),
        };
        world.before = world.held(c);
        assert!(
            world.before > 0,
            "the conservation check has to be reading something, or it holds \
             trivially at zero",
        );
        world.read.set(false);
        world
    }

    /// What the world summed to when it was opened.
    #[must_use]
    pub fn before(&self) -> u128 {
        self.read.set(true);
        self.before
    }

    /// Count the crossings `records` may leave standing as value the
    /// world still holds.
    ///
    /// Registered after submission rather than at [`Self::open`],
    /// because a record cell's key is derived from the transaction and
    /// the value only reaches it once the producing leg runs. A key
    /// whose record never stands reads zero, so registering one costs
    /// nothing.
    pub fn owing(&mut self, records: impl IntoIterator<Item = SubstateKey>) {
        self.owed.extend(records);
    }

    /// What the world sums to now.
    #[must_use]
    pub fn held<C: Cluster + ?Sized>(&self, c: &C) -> u128 {
        self.read.set(true);
        let vaults = self
            .holders
            .iter()
            .fold(0u128, |sum, owner| sum + held(c, *owner, self.resource));
        let cells = self
            .cells
            .iter()
            .fold(vaults, |sum, cell| sum + held_at(c, *cell));
        self.owed.iter().fold(cells, |sum, record| {
            sum + owed_at(c, *record, self.resource)
        })
    }

    /// Every record this world registered that nothing can claim any
    /// more: standing, with no claim answering it, past the close of its
    /// own delivery window.
    #[must_use]
    pub fn stranded<C: Cluster + ?Sized>(&self, c: &C) -> Vec<(SubstateKey, u128)> {
        self.read.set(true);
        self.owed
            .iter()
            .filter_map(|cell| {
                let amount = unclaimable_at(c, *cell, self.resource);
                (amount > 0).then_some((*cell, amount))
            })
            .collect()
    }

    /// Every record this world registered that still holds value:
    /// standing, with no claim answering it, whatever its window says.
    ///
    /// [`stranded`](Self::stranded) without the window. A record inside
    /// its window is in flight and one past it is stranded; both stand
    /// here, which is what a scenario that expects a delivery to be
    /// owed reads.
    #[must_use]
    pub fn standing<C: Cluster + ?Sized>(&self, c: &C) -> Vec<(SubstateKey, u128)> {
        self.read.set(true);
        self.owed
            .iter()
            .filter_map(|cell| {
                let amount = owed_at(c, *cell, self.resource);
                (amount > 0).then_some((*cell, amount))
            })
            .collect()
    }

    /// Every crossing record the world can name that stands unanswered:
    /// the records of every transaction `charges` recorded, and the ones
    /// [`owing`](Self::owing) registered. Value locked rather than
    /// stranded — a record in flight reads the same way — so this
    /// reports and asserts nothing; a scenario that constructs a lock
    /// asserts on it.
    #[must_use]
    pub fn locked<C: Cluster + ?Sized>(&self, c: &C, charges: &Charges) -> Vec<Locked> {
        self.read.set(true);
        let records: BTreeSet<SubstateKey> = charges
            .records(c)
            .into_iter()
            .chain(self.owed.iter().copied())
            .collect();
        records
            .into_iter()
            .filter_map(|record| locked_at(c, record))
            .collect()
    }

    /// Whether what the world holds now, plus what `burned` accounts for,
    /// is exactly what it held when opened.
    ///
    /// A predicate rather than an assertion so a scenario can drive to it:
    /// a delivery lands a hop after its verdict, and the world balances
    /// only once it has.
    #[must_use]
    pub fn settles<C: Cluster + ?Sized>(&self, c: &C, burned: u128) -> bool {
        self.held(c) + burned == self.before
    }

    /// Drive until the world settles against what `charges` burned, then
    /// hold it there for [`SETTLED_TAIL`] and assert it: a delivery lands
    /// a hop after its verdict and a burn a block after its status, so
    /// the equality is reached rather than read at an instant — and a
    /// second credit of the same value reaches it on the way past, so
    /// reading it once says nothing about how many times value came
    /// back.
    ///
    /// Returns what [`locked`](Self::locked) reports at the settled
    /// instant.
    ///
    /// # Panics
    ///
    /// As [`assert_settled`](Self::assert_settled).
    pub fn assert_settles_within<C: Cluster>(
        &self,
        c: &mut C,
        charges: &Charges,
        budget: Budget,
        context: &str,
    ) -> Vec<Locked> {
        let _ = c.run_until(budget, |c| self.settles(c, charges.burned(c)));
        let tail = c.now() + SETTLED_TAIL;
        let _ = c.run_until(budget, |c| c.now() >= tail);
        let locked = self.assert_settled(c, charges, context);
        charges.assert_each_fits_a_full_block(c);
        locked
    }

    /// Assert [`settles`](Self::settles) against what `charges` burned,
    /// naming both sides, and report what stands locked.
    ///
    /// # Panics
    ///
    /// Panics if the world grew — value from nowhere — or shrank by more
    /// than the burn — value stranded.
    pub fn assert_settled<C: Cluster + ?Sized>(
        &self,
        c: &C,
        charges: &Charges,
        context: &str,
    ) -> Vec<Locked> {
        let burned = charges.burned(c);
        // Counting a standing record as value the world holds is what
        // keeps the sum honest while a crossing is in flight, and it is
        // also what a strand would hide: the value is there, so the two
        // sides balance whether or not anything can still reach it. A
        // record inside its delivery window is in flight and says
        // nothing; one past it can never be claimed, because the only
        // writer of the claim cell is a delivery member and admission
        // refuses one there.
        //
        // A tripwire rather than a demonstration: no scenario yet keeps a
        // shard from its delivery for the width of that window, so this
        // has never fired. It is what would catch the day one does.
        let stranded = self.stranded(c);
        assert!(
            stranded.is_empty(),
            "{context}: the world balances with {} crossing(s) past the close of their \
             delivery window that nothing can claim — {stranded:?}",
            stranded.len(),
        );
        let after = self.held(c);
        assert_eq!(
            after + burned,
            self.before,
            "{context}: the world held {} before and {after} after, with {burned} \
             burned — {}",
            self.before,
            if after + burned > self.before {
                "value came from nowhere"
            } else {
                "value was stranded"
            },
        );
        let locked = self.locked(c, charges);
        let holding: u128 = locked.iter().map(|lock| lock.amount).sum();
        println!(
            "{context}: {} locked record(s) holding {holding}",
            locked.len()
        );
        locked
    }
}

/// The prices a scenario's submissions owe.
///
/// One declared price per transaction, charged if and only if a receipt
/// for it committed: a success burns it inside its writes, a refusal or
/// an abandonment settles it apart on a committed finalization, and one
/// the network never resolved owes nothing. The last is not only the
/// transaction nobody included: a payer's deadline speaks an abort on
/// its own, and where no certificate ever follows — the payer's shard
/// terminating with the transaction in flight — the abort commits no
/// receipt and burns nothing, while a counterpart that abandons it on a
/// record of its own settles no fee either, since only the shard holding
/// the vault does. So an abort counts only once the chain owning the
/// payer's prefix carries its finalization.
///
/// The figure is the sender's declaration, derived from signed content,
/// and read once the verdict is in — a call into a package the chain has
/// yet to register prices only once it has. Keyed by hash, so a
/// transaction resubmitted — a replay probe — is owed once, as it is
/// charged once.
#[derive(Default)]
pub struct Charges {
    owed: BTreeMap<TxHash, Arc<Transaction>>,
    /// Aborts a chain has been seen to carry a finalization for. A
    /// committed finalization never uncommits, so the walk that found it
    /// is not repeated.
    finalized_aborts: RefCell<BTreeSet<TxHash>>,
}

impl Charges {
    /// Record `tx` without submitting it.
    pub fn record(&mut self, tx: &Arc<Transaction>) -> TxHash {
        let hash = tx.hash();
        self.owed.insert(hash, Arc::clone(tx));
        hash
    }

    /// Record `tx` and submit it.
    pub fn submit<C: Cluster + ?Sized>(&mut self, c: &mut C, tx: Transaction) -> TxHash {
        let tx = Arc::new(tx);
        let hash = self.record(&tx);
        c.submit(tx);
        hash
    }

    /// The record cell of every crossing the recorded transactions
    /// derive, skipping a transaction that does not derive here.
    #[must_use]
    pub fn records<C: Cluster + ?Sized>(&self, c: &C) -> Vec<SubstateKey> {
        let derivation = c.derivation();
        self.owed
            .values()
            .filter_map(|tx| tx.try_derived(derivation.as_ref()).ok())
            .flat_map(|derived| crossing_records(&derived.legs))
            .collect()
    }

    /// The envelope recorded under `hash`, for a scenario that has to
    /// offer the same signed transaction again.
    #[must_use]
    pub fn recorded(&self, hash: TxHash) -> Option<&Arc<Transaction>> {
        self.owed.get(&hash)
    }

    /// How many of the recorded transactions have been charged.
    #[must_use]
    pub fn charged<C: Cluster + ?Sized>(&self, c: &C) -> usize {
        self.owed
            .keys()
            .filter(|hash| self.is_charged(c, **hash))
            .count()
    }

    /// What the recorded transactions that were charged burned between
    /// them.
    ///
    /// # Panics
    ///
    /// On a cluster whose price band is open. The figure is read once
    /// the verdict is in, which is epochs after submission, and it
    /// prices against the head table — while the chain charged at the
    /// window its committing block anchored. Those are one table only
    /// while the level cannot move, so a conservation check spanning a
    /// fold would report its own arithmetic as stranded value.
    #[must_use]
    pub fn burned<C: Cluster + ?Sized>(&self, c: &C) -> u128 {
        let bounds = c.beacon_state().map(|state| state.params.price_bounds);
        assert!(
            bounds.is_none_or(|band| band.floor == band.ceiling),
            "conservation prices at the head table and cannot span a \
             price band: {bounds:?}"
        );
        self.owed
            .iter()
            .filter(|(hash, _)| self.is_charged(c, **hash))
            .map(|(_, tx)| declared_price(c, tx))
            .sum()
    }

    /// Assert that a full block of every charged transaction's shape fits
    /// the per-block cap on sweepable creation — the corpus pin the cap
    /// is sized against, read here because a charged transaction is one
    /// the price has already been derived for.
    ///
    /// # Panics
    ///
    /// As [`assert_a_full_block_fits`].
    pub fn assert_each_fits_a_full_block<C: Cluster + ?Sized>(&self, c: &C) {
        self.owed
            .iter()
            .filter(|(hash, _)| self.is_charged(c, **hash))
            .for_each(|(_, tx)| assert_a_full_block_fits(c, tx));
    }

    /// Whether a receipt for `hash` has committed: a decision either way,
    /// or an abort a chain that held the payer's prefix finalized.
    fn is_charged<C: Cluster + ?Sized>(&self, c: &C, hash: TxHash) -> bool {
        match c.tx_status(hash) {
            Some(TransactionStatus::Completed(TransactionDecision::Aborted)) => {
                if self.finalized_aborts.borrow().contains(&hash) {
                    return true;
                }
                let payer = self.owed[&hash].fee_payer();
                let finalized =
                    covering_chains(payer).any(|shard| c.chain_fate(shard, hash).1.is_some());
                if finalized {
                    self.finalized_aborts.borrow_mut().insert(hash);
                }
                finalized
            }
            Some(TransactionStatus::Completed(_)) => true,
            Some(
                TransactionStatus::Pending
                | TransactionStatus::Committed(_)
                | TransactionStatus::LegFinalized,
            )
            | None => false,
        }
    }
}

/// Every chain that could have held `payer`'s prefix — one per depth,
/// which is the line the prefix travels as the trie grows and shrinks.
///
/// The price of an abort is settled on the chain that held the payer
/// when the abort finalized, which after a reshape is not the chain that
/// holds it now: a split's parent and a merge's children keep serving
/// their frozen stores, so the finalization stays readable where it was
/// written while the beacon's live partition no longer names them. A
/// depth no chain ever existed at answers nothing, so asking is inert.
fn covering_chains(payer: Address) -> impl Iterator<Item = ShardId> {
    (0..=MAX_SEARCHED_DEPTH).map(move |depth| ShardTrie::uniform(depth).shard_for_prefix(payer))
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use hyperscale_types::{
        BeaconState, BlockHeight, Derivation, StateRoot, TxsInFlight, WeightedTimestamp,
    };

    use super::*;
    use crate::support::query::RanAs;

    /// A cluster serving nothing: every observation answers absent, and
    /// nothing a conservation read reaches drives it.
    struct Nowhere;

    impl Cluster for Nowhere {
        fn submit(&mut self, _: Arc<Transaction>) {
            unreachable!()
        }

        fn submit_to(&mut self, _: ShardId, _: Arc<Transaction>) {
            unreachable!()
        }

        fn derivation(&self) -> Arc<dyn Derivation> {
            unreachable!()
        }

        fn run_until(&mut self, _: Budget, _: impl Fn(&Self) -> bool) -> bool {
            unreachable!()
        }

        fn now(&self) -> Duration {
            unreachable!()
        }

        fn committed_height(&self, _: ShardId) -> Option<BlockHeight> {
            None
        }

        fn committed_state_root(&self, _: ShardId) -> Option<StateRoot> {
            None
        }

        fn serves_shard(&self, _: ShardId) -> bool {
            false
        }

        fn beacon_state(&self) -> Option<Arc<BeaconState>> {
            None
        }

        fn chain_origin_anchor(&self, _: ShardId) -> Option<WeightedTimestamp> {
            None
        }

        fn committed_txs_in_flight(&self, _: ShardId) -> Option<TxsInFlight> {
            None
        }

        fn tx_status(&self, _: TxHash) -> Option<TransactionStatus> {
            None
        }

        fn ran(&self, _: ShardId, _: TxHash) -> Vec<RanAs> {
            Vec::new()
        }

        fn named_unsettled(&self, _: ShardId, _: TxHash) -> Vec<(BlockHeight, ShardId)> {
            Vec::new()
        }

        fn declined(&self, _: ShardId, _: TxHash) -> Vec<(BlockHeight, SubstateKey)> {
            Vec::new()
        }

        fn chain_fate(
            &self,
            _: ShardId,
            _: TxHash,
        ) -> (
            Option<BlockHeight>,
            Option<(BlockHeight, TransactionDecision)>,
        ) {
            (None, None)
        }
    }

    /// A world as [`World::open`] leaves it: sampled, and not yet read.
    fn unread_world() -> World {
        World {
            resource: *PROTOCOL_RESOURCE,
            holders: Vec::new(),
            cells: Vec::new(),
            owed: Vec::new(),
            before: 1,
            read: Cell::new(false),
        }
    }

    #[test]
    fn a_world_opened_and_never_read_panics() {
        let dropped = catch_unwind(AssertUnwindSafe(|| drop(unread_world())));
        let message = dropped.expect_err("an unread world must refuse to drop");
        let message = message
            .downcast_ref::<String>()
            .expect("the refusal is a formatted message");
        assert!(
            message.contains("a conservation world was opened and never read"),
            "{message}",
        );

        let read = unread_world();
        assert_eq!(read.held(&Nowhere), 0);
        drop(read);
    }
}
