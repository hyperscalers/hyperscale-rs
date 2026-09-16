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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    Address, ResourceAddr, ShardId, ShardTrie, SubstateKey, Transaction, TransactionDecision,
    TransactionStatus, TxHash,
};

use super::query::{MAX_SEARCHED_DEPTH, assert_a_full_block_fits, declared_price, held, held_at};
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
    before: u128,
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
            before: 0,
        };
        world.before = world.held(c);
        assert!(
            world.before > 0,
            "the conservation check has to be reading something, or it holds \
             trivially at zero",
        );
        world
    }

    /// What the world summed to when it was opened.
    #[must_use]
    pub const fn before(&self) -> u128 {
        self.before
    }

    /// What the world sums to now.
    #[must_use]
    pub fn held<C: Cluster + ?Sized>(&self, c: &C) -> u128 {
        let vaults = self
            .holders
            .iter()
            .fold(0u128, |sum, owner| sum + held(c, *owner, self.resource));
        self.cells
            .iter()
            .fold(vaults, |sum, cell| sum + held_at(c, *cell))
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
    /// # Panics
    ///
    /// As [`assert_settled`](Self::assert_settled).
    pub fn assert_settles_within<C: Cluster>(
        &self,
        c: &mut C,
        charges: &Charges,
        budget: Budget,
        context: &str,
    ) {
        let _ = c.run_until(budget, |c| self.settles(c, charges.burned(c)));
        let tail = c.now() + SETTLED_TAIL;
        let _ = c.run_until(budget, |c| c.now() >= tail);
        self.assert_settled(c, charges.burned(c), context);
        charges.assert_each_fits_a_full_block(c);
    }

    /// Assert [`settles`](Self::settles), naming both sides.
    ///
    /// # Panics
    ///
    /// Panics if the world grew — value from nowhere — or shrank by more
    /// than the burn — value stranded.
    pub fn assert_settled<C: Cluster + ?Sized>(&self, c: &C, burned: u128, context: &str) {
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
