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

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_storage::FeeHold;
use hyperscale_types::{
    Address, Finalization, PrincipalAddr, RETENTION_HORIZON, Transaction, TxHash, Verifiable,
    WeightedTimestamp,
};

/// One engaged reservation: the payer's owner prefix, the held ceiling,
/// and the prune deadline.
struct Hold {
    payer: PrincipalAddr,
    max_fee: u128,
    deadline: WeightedTimestamp,
}

pub struct FeeReservationLedger {
    holds: HashMap<TxHash, Hold>,
}

impl FeeReservationLedger {
    pub fn new() -> Self {
        Self {
            holds: HashMap::new(),
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
    /// Every hold the walk read is taken, whoever pays it: the trie that
    /// decides which payers this shard answers for is not reachable at
    /// construction, and [`retain_payers`](Self::retain_payers) drops the
    /// rest at the first commit. A hold for a payer this shard does not
    /// hold is invisible to [`held_for`](Self::held_for) meanwhile, which
    /// sums by the payer asked about.
    pub fn seeded(holds: &[FeeHold]) -> Self {
        let mut ledger = Self::new();
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

    /// Record the reservations a committed block engages.
    ///
    /// Every transaction the block carries, whoever pays it — which
    /// payers this shard answers for is
    /// [`retain_payers`](Self::retain_payers)'s question, asked once
    /// against the trie rather than here and at the seed separately.
    pub fn register_committed(&mut self, transactions: &[Arc<Verifiable<Transaction>>]) {
        for tx in transactions {
            let vm = tx.body();
            let deadline = tx
                .validity_range()
                .end_timestamp_exclusive
                .plus(RETENTION_HORIZON);
            self.holds.entry(tx.hash()).or_insert(Hold {
                payer: vm.fee_payer,
                max_fee: vm.max_fee,
                deadline,
            });
        }
    }

    /// Release the reservations a committed block's finalizations
    /// resolve — settlement and abort both arrive as finalizations.
    pub fn release_finalized(&mut self, finalizations: &[Arc<Verifiable<Finalization>>]) {
        for tick in finalizations {
            for tx_hash in tick.tx_hashes() {
                self.holds.remove(&tx_hash);
            }
        }
    }

    /// Drop every hold whose payer this shard does not answer for.
    ///
    /// The one place locality is decided: the trie it reads moves at a
    /// reshape, so a payer whose prefix leaves takes its holds with it,
    /// and a seed taken before any trie was in scope is narrowed here on
    /// the first commit.
    pub fn retain_payers(&mut self, payer_local: impl Fn(Address) -> bool) {
        self.holds
            .retain(|_, hold| payer_local(hold.payer.address()));
    }

    /// Drop holds past their deadline. `now` is the latest committed
    /// block's weighted timestamp.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        self.holds.retain(|_, hold| hold.deadline > now);
    }

    /// The total engaged reservation against `payer`, saturating.
    #[must_use]
    pub fn held_for(&self, payer: Address) -> u128 {
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
        ledger.release_finalized(std::slice::from_ref(&tick));
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
    }

    #[test]
    fn a_transaction_this_shard_does_not_pay_for_holds_nothing() {
        let mut ledger = FeeReservationLedger::new();
        let tx = transaction(1_000, 60_000);
        ledger.register_committed(std::slice::from_ref(&tx));
        ledger.retain_payers(|_| false);
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
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

        let mut ledger = FeeReservationLedger::seeded(&[hold, other]);
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);

        // A hold for a payer this shard does not answer for was never
        // summed into one it does, and the first commit drops it.
        ledger.retain_payers(|address| address == PAYER_ADDR);
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);
        assert_eq!(ledger.held_for(PrincipalAddr::new([0xBB; 31]).address()), 0);

        // And the resumed hold releases on the finalization the chain
        // carries next, exactly as one this process registered would.
        let tick = Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(1),
            tx.hash(),
            TransactionDecision::Accept,
        )));
        ledger.release_finalized(std::slice::from_ref(&tick));
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
    }

    #[test]
    fn prune_drops_holds_past_the_retention_deadline() {
        let mut ledger = FeeReservationLedger::new();
        let tx = transaction(1_000, 100);
        ledger.register_committed(std::slice::from_ref(&tx));

        ledger.prune(WeightedTimestamp::from_millis(100));
        assert_eq!(ledger.held_for(PAYER_ADDR), 1_000);

        let past = WeightedTimestamp::from_millis(100)
            .plus(RETENTION_HORIZON)
            .plus(std::time::Duration::from_millis(1));
        ledger.prune(past);
        assert_eq!(ledger.held_for(PAYER_ADDR), 0);
    }
}
