//! In-flight fee reservations at the payer shard.
//!
//! A committed transaction whose fee payer routes to this shard holds
//! `max_fee` against the payer's vault until its tick finalizes — the
//! window in which the reservation is engaged but not yet settled. The
//! ledger tracks exactly that window from chain content: entries insert
//! when a block commits the transaction and release when a committed
//! block carries the finalization resolving it, so every replica's
//! ledger is identical at equal committed frontiers.
//!
//! Entries are deadline-bounded like [`crate::commit_dedup`]'s tiers: a
//! transaction resolved outside the certificate path — a reshape
//! terminal's abort-by-omission, where no finalization ever commits —
//! prunes at its validity end plus the retention horizon rather than
//! encumbering the payer forever.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use hyperscale_storage::FeeHold;
use hyperscale_types::{
    Address, BlockHeight, Finalization, PrincipalAddr, RETENTION_HORIZON, Transaction, TxHash,
    Verifiable, WeightedTimestamp,
};

/// One engaged reservation: the payer's owner prefix, the held ceiling,
/// and the prune deadline.
struct Hold {
    payer: PrincipalAddr,
    max_fee: u128,
    deadline: WeightedTimestamp,
}

/// Every reservation the chain engaged and has not yet released, whoever
/// pays it: which payers this shard answers for is asked of the judged
/// block's committee where a demand is summed, never of the ledger, so a
/// reshape cannot drop a hold a block before the cut engaged.
///
/// Beside the holds, a ring of what each recent commit released or
/// pruned, so a demand is summed at the height a balance is read at
/// rather than at this node's tip: a hold released above that height is
/// still charged against a balance that has not yet paid the fee.
pub struct FeeReservationLedger {
    holds: HashMap<TxHash, Hold>,
    /// `(payer, amount)` each commit released or pruned, by its height.
    released: BTreeMap<BlockHeight, Vec<(Address, u128)>>,
    /// The ring answers for every height at or above this one: every
    /// release above it is recorded.
    floor: BlockHeight,
}

impl FeeReservationLedger {
    pub(crate) fn new() -> Self {
        Self {
            holds: HashMap::new(),
            released: BTreeMap::new(),
            floor: BlockHeight::GENESIS,
        }
    }

    /// Rebuild the ledger from the recovery walk's own reading of the
    /// committed chain.
    ///
    /// Constructed empty, a restarted coordinator under-counts held
    /// demand for every payer whose transactions committed before it —
    /// so it votes for blocks its peers refuse and, as proposer, offers
    /// transactions they refuse. That falsifies this module's own claim
    /// that every replica's ledger is identical at equal committed
    /// frontiers, and makes block validity depend on node-local memory.
    ///
    /// Every hold the walk read is taken, whoever pays it, as the live
    /// ledger takes them; [`held_for`](Self::held_for) sums by the payer
    /// asked about. The release ring starts at `tip`: nothing below it was
    /// recorded, so a read below it answers `None`.
    pub(crate) fn seeded(holds: &[FeeHold], tip: BlockHeight) -> Self {
        let mut ledger = Self::new();
        ledger.floor = tip;
        for hold in holds {
            ledger.holds.insert(
                hold.tx_hash,
                Hold {
                    payer: hold.payer,
                    max_fee: hold.max_fee,
                    deadline: hold.deadline,
                },
            );
        }
        ledger
    }

    /// Record the reservations a committed block engages: every
    /// transaction the block carries, whoever pays it.
    pub(crate) fn register_committed(&mut self, transactions: &[Arc<Verifiable<Transaction>>]) {
        for tx in transactions {
            let terms = tx.terms();
            let deadline = tx
                .validity_range()
                .end_timestamp_exclusive
                .plus(RETENTION_HORIZON);
            self.holds.entry(tx.hash()).or_insert(Hold {
                payer: terms.fee_payer,
                max_fee: terms.max_fee,
                deadline,
            });
        }
    }

    /// Release the reservations the finalizations of the block committed
    /// at `height` resolve — settlement and abort both arrive as
    /// finalizations — and record each in the ring at that height.
    pub(crate) fn release_finalized(
        &mut self,
        finalizations: &[Arc<Verifiable<Finalization>>],
        height: BlockHeight,
    ) {
        let mut released = Vec::new();
        for tick in finalizations {
            for tx_hash in tick.tx_hashes() {
                if let Some(hold) = self.holds.remove(&tx_hash) {
                    released.push((hold.payer.address(), hold.max_fee));
                }
            }
        }
        self.record(height, released);
    }

    /// Drop holds whose deadline is at or below `anchor`, the anchor of
    /// the block committed at `height`, and record each in the ring there.
    pub(crate) fn prune(&mut self, anchor: WeightedTimestamp, height: BlockHeight) {
        let mut pruned = Vec::new();
        self.holds.retain(|_, hold| {
            let keep = hold.deadline > anchor;
            if !keep {
                pruned.push((hold.payer.address(), hold.max_fee));
            }
            keep
        });
        self.record(height, pruned);
    }

    fn record(&mut self, height: BlockHeight, released: Vec<(Address, u128)>) {
        if !released.is_empty() {
            self.released.entry(height).or_default().extend(released);
        }
    }

    /// Forget the ring below `floor`, whose reads no pipelined vote can
    /// still make.
    pub(crate) fn retire_below(&mut self, floor: BlockHeight) {
        if floor > self.floor {
            self.released = self.released.split_off(&floor);
            self.floor = floor;
        }
    }

    /// The reservation engaged against `payer` as a balance read at
    /// `height` sees it: every hold still held, and every one released or
    /// pruned above `height`, whose fee that balance has not yet paid.
    /// `None` below the ring's floor, where the answer is not held.
    #[must_use]
    pub(crate) fn held_for_at(&self, payer: Address, height: BlockHeight) -> Option<u128> {
        if height < self.floor {
            return None;
        }
        let released = self
            .released
            .range(height.next()..)
            .flat_map(|(_, entries)| entries)
            .filter(|(released_for, _)| *released_for == payer)
            .fold(0u128, |sum, (_, amount)| sum.saturating_add(*amount));
        Some(self.held_for(payer).saturating_add(released))
    }

    /// The total engaged reservation against `payer`, saturating.
    #[must_use]
    pub(crate) fn held_for(&self, payer: Address) -> u128 {
        self.holds
            .values()
            .filter(|hold| hold.payer == payer)
            .fold(0u128, |sum, hold| sum.saturating_add(hold.max_fee))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{make_finalization, stub_transaction};
    use hyperscale_types::{
        AddressClass, BlockHeight, PrincipalAddr, TimestampRange, TransactionDecision, Verified,
    };

    use super::*;

    const PAYER: PrincipalAddr = PrincipalAddr::new([0xAA; 31]);
    const PAYER_ADDR: Address = PAYER.address();

    fn transaction(max_fee: u128, end_ms: u64) -> Arc<Verifiable<Transaction>> {
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(end_ms),
        );
        Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
            stub_transaction(PAYER, &[PAYER.address()], max_fee, validity),
        )))
    }

    #[test]
    fn holds_accumulate_and_release_on_finalizations() {
        let mut ledger = FeeReservationLedger::new();
        let tx = transaction(1_000, 60_000);
        ledger.register_committed(std::slice::from_ref(&tx));
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);
        assert_eq!(
            ledger.held_for(Address::new([0xBB; 31], AddressClass::Component)),
            0
        );

        let tick = Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(1),
            tx.hash(),
            TransactionDecision::Accept,
        )));
        ledger.release_finalized(std::slice::from_ref(&tick), BlockHeight::new(1));
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
    }

    fn finalizing(tx: &Arc<Verifiable<Transaction>>) -> Arc<Verifiable<Finalization>> {
        Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(1),
            tx.hash(),
            TransactionDecision::Accept,
        )))
    }

    /// A hold engaged at H and released at H+1 is still charged against a
    /// balance read at H, which has not paid the fee: a voter at tip H+1
    /// reading at H sums what a voter at tip H sums. A read below the
    /// ring's floor is not answered.
    #[test]
    fn holds_and_balance_are_read_at_one_height() {
        let tx = transaction(1_000, 60_000);
        let at_h = BlockHeight::new(5);

        let mut at_tip_h = FeeReservationLedger::new();
        at_tip_h.register_committed(std::slice::from_ref(&tx));

        let mut at_tip_next = FeeReservationLedger::new();
        at_tip_next.register_committed(std::slice::from_ref(&tx));
        at_tip_next.release_finalized(&[finalizing(&tx)], at_h.next());

        assert_eq!(at_tip_h.held_for_at(PAYER_ADDR, at_h), Some(1_000));
        assert_eq!(at_tip_next.held_for_at(PAYER_ADDR, at_h), Some(1_000));
        assert_eq!(at_tip_next.held_for_at(PAYER_ADDR, at_h.next()), Some(0));

        at_tip_next.retire_below(BlockHeight::new(6));
        assert_eq!(at_tip_next.held_for_at(PAYER_ADDR, at_h), None);
        assert_eq!(at_tip_next.held_for_at(PAYER_ADDR, at_h.next()), Some(0));
    }

    /// A hold engaged before a reshape moved its payer's prefix stays
    /// held until it is released or pruned: nothing narrows the ledger by
    /// a trie, so the committee a demand is summed under decides whether
    /// the payer is local, and a head a fold ahead drops nothing.
    #[test]
    fn a_hold_engaged_under_the_old_committee_counts_under_the_new() {
        let mut ledger = FeeReservationLedger::new();
        let tx = transaction(1_000, 60_000);
        ledger.register_committed(std::slice::from_ref(&tx));
        ledger.prune(WeightedTimestamp::from_millis(1_000), BlockHeight::new(2));
        assert_eq!(
            ledger.held_for_at(PAYER_ADDR, BlockHeight::new(2)),
            Some(1_000)
        );
    }

    /// A restart resumes the holds the chain already engaged. Constructed
    /// empty, this coordinator under-counts held demand for every payer
    /// whose transactions committed before the process did — so it votes
    /// for blocks its peers refuse.
    #[test]
    fn a_seeded_ledger_resumes_what_the_chain_engaged() {
        let tx = transaction(1_000, 60_000);
        let hold = FeeHold {
            tx_hash: tx.hash(),
            payer: PAYER,
            max_fee: 1_000,
            deadline: WeightedTimestamp::from_millis(60_000).plus(RETENTION_HORIZON),
        };
        let other = FeeHold {
            tx_hash: transaction(7, 60_000).hash(),
            payer: PrincipalAddr::new([0xBB; 31]),
            max_fee: 7,
            deadline: WeightedTimestamp::from_millis(60_000).plus(RETENTION_HORIZON),
        };

        let tip = BlockHeight::new(40);
        let mut ledger = FeeReservationLedger::seeded(&[hold, other], tip);
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);

        // A hold for another payer is never summed into this one's.
        assert_eq!(ledger.held_for(PrincipalAddr::new([0xBB; 31]).address()), 7);
        // Nothing below the tip it resumed at was recorded.
        assert_eq!(ledger.held_for_at(PAYER_ADDR, tip), Some(1_000));
        assert_eq!(ledger.held_for_at(PAYER_ADDR, BlockHeight::new(39)), None);

        // And the resumed hold releases on the finalization the chain
        // carries next, exactly as one this process registered would.
        let tick = Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(1),
            tx.hash(),
            TransactionDecision::Accept,
        )));
        ledger.release_finalized(std::slice::from_ref(&tick), tip.next());
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
    }

    #[test]
    fn prune_drops_holds_past_the_retention_deadline() {
        let mut ledger = FeeReservationLedger::new();
        let tx = transaction(1_000, 100);
        ledger.register_committed(std::slice::from_ref(&tx));

        ledger.prune(WeightedTimestamp::from_millis(100), BlockHeight::new(1));
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);

        let deadline = WeightedTimestamp::from_millis(100).plus(RETENTION_HORIZON);
        ledger.prune(deadline, BlockHeight::new(2));
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
        assert_eq!(
            ledger.held_for_at(PAYER_ADDR, BlockHeight::new(1)),
            Some(1_000),
            "a balance read below the prune still carries the hold",
        );
    }
}
