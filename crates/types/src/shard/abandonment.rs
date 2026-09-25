//! What a departed counterpart left unsettled of the transactions this
//! shard still owes an outcome for.
//!
//! A cross-shard transaction needs every certificate its settlement
//! waits on, so one whose counterpart can never certify it can never
//! settle anywhere. That is the fact this shard needs in order to abandon
//! it. For a counterpart still running, the chain reads it off the
//! counterpart's own state: a claim carries what a commit-proven header
//! said of a cell, every replica folds the claim at the block that
//! carries it, and an absence inside its window licenses the reclaim
//! from the ledger alone. For a counterpart that left, there is no state
//! to read: its settled set is complete and beacon-attested, so absence
//! from it is proof, but the set can only be fetched while the terminal
//! it belongs to is still served.
//!
//! So the answer is written down while it can still be read. A record
//! names the transactions this chain still owes an outcome for that the
//! departed shard did not settle, and once committed it is ordinary
//! history: every replica reads the same verdicts off its own chain at
//! any distance, including one that was switched off when the
//! counterpart left, and one that never held the transaction rebuilds
//! its entry from the figures the record restates.
//!
//! What is never recorded is a settlement. That a counterpart *did*
//! settle a transaction changes nothing this shard can act on — the
//! transaction stays owed and unabandonable either way.
//!
//! Each name carries the figures composing the abort takes — the deadline
//! it opens at, the reservation it returns, and the charge it settles —
//! and the block of this chain that committed the transaction, which is
//! what dates the departure against it. The figures are functions of the
//! transaction body and the commit is a fact of the chain, so a proposer
//! restates them and a voter holding the transaction and the block
//! checks the restatement — and a replica whose rebuild never reached
//! the transaction's own block still holds enough to compose the same
//! verdict as its peers.

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_effects::{CrossingCell, Terms};
use hyperscale_vm_types::Quanta;

use crate::{
    ABANDONMENT_RECORD_BYTES, BlockHeight, Deadline, MAX_PREFIXES_PER_TX, MAX_UNSETTLED_PER_BLOCK,
    MAX_VALIDITY_RANGE, PriceTable, ROUTE_PREFIX_BYTES, RoutePrefix, ShardId, ShardTrie,
    SubstateKey, Transaction, TxHash, UNCLAIMED_CROSSING_BYTES, UNSETTLED_TX_BYTES,
    WeightedTimestamp,
};

/// Where a chain committed a transaction: the block, the anchor it was
/// admitted against, and the anchor it derived under.
///
/// A block carries two instants and they straddle an epoch cut once per
/// window, so a name that means to restate what its commit owed has to
/// say which it means. `anchor` is the block's own — its parent QC's
/// weighted timestamp — which dates the commit and orders it against a
/// departure's cut. `committee_anchor` is the anchor its *parent*
/// carried, since a block's committee keys on its parent: the trie that
/// classified the transaction and routed its crossings, and the table
/// that priced it. The height is where a replica reads both off its own
/// chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct CommittedAt {
    /// The block that carried the transaction.
    pub height: BlockHeight,
    /// The anchor that block was admitted against.
    pub anchor: WeightedTimestamp,
    /// The anchor its classification and its price were frozen at.
    pub committee_anchor: WeightedTimestamp,
}

/// What an abort of one transaction burns, and out of whose vault.
///
/// Both are functions of signed content — the vault the fee payer's
/// address derives, the amount its declaration prices to — so the
/// receipt settling an abort is the same receipt on every replica
/// whether or not the transaction ever reached an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct AbortCharge {
    /// The fee payer's vault, which the burn debits.
    pub vault: SubstateKey,
    /// The declared price: what every attempt owes, whatever refused it.
    pub amount: u128,
}

/// One transaction a counterpart can never settle, with what abandoning
/// it takes.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct UnsettledTx {
    /// The transaction.
    pub tx_hash: TxHash,
    /// The moment past which it can no longer finalize anywhere, and
    /// the anchor every absence window a record restates is read off,
    /// so a voter checks a proof's block against this figure rather
    /// than against a clock.
    pub deadline: Deadline,
    /// What the committing shard attests for the transaction — the
    /// price of its own share — which the abandonment carries as the
    /// outcome would have.
    pub charged: u128,
    /// What the abandonment burns, settled by the shard holding the
    /// vault and by no other.
    pub charge: AbortCharge,
    /// Where this chain committed the transaction.
    ///
    /// What dates a departure against the name: a shard that had left
    /// the trie by this anchor was issued nothing of the transaction,
    /// whatever its keyspace covered, while one still in it held the
    /// route the crossing went to. A transaction whose validity opened
    /// before a cut can commit here after it, so nothing read off the
    /// body says which side of the cut the commit fell on — only the
    /// chain does, and a name restates it so a replica holding no entry
    /// dates the departure as one that held the block would.
    pub committed: CommittedAt,
    /// The route every owner prefix the transaction touches takes,
    /// ascending — the whole reach, not one shard's share of it.
    ///
    /// Stated because a record is read by shards that never held the
    /// transaction. A validator rotated into a committee after the block
    /// that committed it meets the transaction here for the first time,
    /// and what it derives from the entry it builds — who was party to
    /// an abandonment — reaches a receipt root, so it has to reach the
    /// same set its peers do. The prefixes are the transaction's own, so
    /// stating them makes the derivation the same from the record as
    /// from the block.
    ///
    /// The whole reach rather than the composer's remote share: each
    /// reader owns a different part of it and filters its own.
    ///
    /// Routes rather than addresses, because placement is the only
    /// question asked of them and it reads no further than this.
    pub reach: Capped<Vec<RoutePrefix>, MAX_PREFIXES_PER_TX>,
}

/// The window a name says committed it: what its figures were frozen
/// against, and so what a restatement is checked against.
///
/// Both halves move, and neither moves backwards for a figure already
/// owed. A record is written when a deadline lapses, which is epochs
/// after the commit it names, so a checker reading its own window would
/// weigh the share at a placement the transaction never ran under and
/// the price at a table it was never charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitWindow {
    /// The placement the committing block froze the classification
    /// under, which is what prices a shard's own share.
    pub trie: ShardTrie,
    /// The table that block charged at.
    pub prices: PriceTable,
}

impl UnsettledTx {
    /// What abandoning `tx`, which this chain committed at `committed`,
    /// states.
    ///
    /// The one place every figure is derived, so a proposer restating
    /// them and a voter checking the restatement compute one value: the
    /// deadline is the transaction's own, the charge is the fee vault at
    /// the whole declared price under `table`, and the commit is the
    /// block's.
    ///
    /// `charged` is what the attesting shard's own share came to, which
    /// the caller reads off the classification its committing block
    /// froze — the whole price is placement-free and derives here, the
    /// share is not and cannot.
    ///
    /// # Panics
    ///
    /// As [`Transaction::work`], on a transaction that was never derived.
    #[must_use]
    pub fn for_transaction(
        tx: &Transaction,
        committed: CommittedAt,
        charged: Quanta,
        table: &PriceTable,
    ) -> Self {
        Self {
            tx_hash: tx.hash(),
            deadline: Deadline::of_transaction(tx),
            charged,
            charge: AbortCharge {
                vault: tx.fee_vault(),
                amount: tx.price(table),
            },
            committed,
            reach: tx.routing().all_routes(),
        }
    }

    /// An upper bound on what this name costs the block that carries it.
    ///
    /// A bound rather than the encoding, so a composer can spend the
    /// section's budget as it fills it and a voter can check the same
    /// figure without re-encoding what it just decoded. Everything but
    /// the reach is fixed width, and the reach is a route each.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        UNSETTLED_TX_BYTES + self.reach.len() * ROUTE_PREFIX_BYTES
    }

    /// Whether `shard`, leaving at `cut`, was party to this transaction
    /// as seen from `local`: it held one of the transaction's remote
    /// routes when this chain committed the transaction, and left
    /// afterwards.
    ///
    /// `departures` is every departure the reader can see, as the shard
    /// and the cut its chain ended at. Owning the route and leaving
    /// after the commit is not enough: a successor owns its
    /// predecessor's keyspace, so two cuts over one route inside one
    /// transaction's life would name it to both, and the second
    /// departure would abandon what the first already settled. The
    /// shard a record may name is the one that held the route then,
    /// which is the earliest departure over it after the commit.
    ///
    /// Dated by the block that committed the transaction here rather
    /// than by anything the body fixes: a cut is an instant on the
    /// chain's own clock, and the commit's anchor is the one reading
    /// of that clock at which the trie was consulted for the
    /// transaction. A window that opened before the cut says nothing —
    /// the commit may still have fallen after it, routed to the
    /// successor, which then holds a crossing the departed shard was
    /// never issued.
    ///
    /// Read off the figures a record restates and the departures alone,
    /// so the ledger composing a record and the admission judging it
    /// answer alike — and a replica holding no entry for the name
    /// answers as one that does, which is what lets it rebuild the entry
    /// from the record.
    #[must_use]
    pub fn party(
        &self,
        local: ShardId,
        shard: ShardId,
        cut: WeightedTimestamp,
        departures: &[(ShardId, WeightedTimestamp)],
    ) -> bool {
        let committed = self.committed.anchor;
        cut > committed
            && self.reach.iter().any(|&route| {
                !ShardTrie::shard_owns_route(local, route)
                    && ShardTrie::shard_owns_route(shard, route)
                    && first_to_leave(route, committed, departures).is_none_or(|first| first >= cut)
            })
    }
}

/// The earliest cut among `departures` over `route` after `after`: the
/// shard that held the route from `after` on, until it left.
fn first_to_leave(
    route: RoutePrefix,
    after: WeightedTimestamp,
    departures: &[(ShardId, WeightedTimestamp)],
) -> Option<WeightedTimestamp> {
    departures
        .iter()
        .filter(|(departed, departed_at)| {
            ShardTrie::shard_owns_route(*departed, route) && *departed_at > after
        })
        .map(|(_, departed_at)| *departed_at)
        .min()
}

/// A crossing this shard issued whose consumer's shard departed without
/// taking it, named off the record leaf rather than off a ledger entry.
///
/// A leg entry lives one [`CLAIM_WINDOW`](crate::CLAIM_WINDOW) past its
/// deadline, and a departure can be cut any number of epochs later, so a
/// name read off entries misses a crossing whose entry has aged out. The
/// leaf is still here and states what the rule needs: the consumer's
/// target and the issuing transaction's validity end, which the name
/// restates so admission judges the schedule side without the cell and
/// the voter's parent view checks the restatement.
///
/// It resolves nothing and reserves nothing: the leg finalized and
/// charged long ago. It licenses the record's reclaim alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct UnclaimedCrossing {
    /// The record, under this shard's prefix.
    pub record: SubstateKey,
    /// The transaction that issued it, which the departed shard's
    /// settled set must not name.
    pub tx: TxHash,
    /// The route of the consumer's target, which the departed shard held.
    pub consumer: RoutePrefix,
    /// The issuing transaction's validity end, as the record states it.
    pub validity_end: WeightedTimestamp,
}

impl UnclaimedCrossing {
    /// The name the record at `record` states.
    #[must_use]
    pub const fn of(record: SubstateKey, cell: &CrossingCell) -> Self {
        Self {
            record,
            tx: cell.tx,
            consumer: RoutePrefix::of(cell.consumer),
            validity_end: WeightedTimestamp::from_millis(cell.validity_end_ms),
        }
    }

    /// Whether `cell`, read at this name's record, is an escrowed record
    /// stating exactly what the name restates.
    #[must_use]
    pub fn restates(&self, cell: &CrossingCell) -> bool {
        matches!(cell.terms, Terms::Escrowed { .. }) && Self::of(self.record, cell) == *self
    }

    /// Whether `shard`, leaving at `cut`, was the only shard that could
    /// have taken this crossing, as seen from `local`.
    ///
    /// The consumer's route is remote and `shard` held it; the
    /// transaction's deadline had passed by the cut, so nothing could
    /// take the crossing after it; and `shard` is the first departure
    /// over the route after the transaction's validity could have
    /// opened. That instant bounds from below the producer's commit and
    /// so the record's write, the date [`UnsettledTx::party`] reads off
    /// the commit. A predecessor leaving inside the transaction's life
    /// could have taken the crossing and handed its answer on, and its
    /// settled set, not `shard`'s, would say so.
    #[must_use]
    pub fn party(
        &self,
        local: ShardId,
        shard: ShardId,
        cut: WeightedTimestamp,
        departures: &[(ShardId, WeightedTimestamp)],
    ) -> bool {
        let route = self.consumer;
        let opened = self.validity_end.minus(MAX_VALIDITY_RANGE);
        Deadline::of(self.validity_end).at() <= cut
            && !ShardTrie::shard_owns_route(local, route)
            && ShardTrie::shard_owns_route(shard, route)
            && first_to_leave(route, opened, departures) == Some(cut)
    }
}

/// How a block's resolutions stand against the transactions they name:
/// the figures its records restate, and the successes its finalizations
/// decide.
///
/// The voter's answer, read off committed bodies and blocks. A
/// validator whose store holds a transaction and the block a name says
/// committed it answers for it — a figure exactly or wrongly, a success
/// inside its deadline or past it — and one whose store never held them,
/// having synced past the block, cannot say, which is a third answer and
/// not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolutions {
    /// Every figure of every name is the one its transaction fixes and
    /// no success is overdue.
    Exact,
    /// A figure of this name differs from the one its transaction fixes:
    /// the block is refused.
    Wrong(TxHash),
    /// A finalization decides this transaction with success, by its own
    /// execution, at an anchor at or past its deadline, where a leg that
    /// issued for it may already have taken the crossing back against
    /// the consumer's decline.
    /// Only a member that awaits nobody is held to it: one with a sibling
    /// to stay atomic with settles on the sibling's clock. The block is
    /// refused.
    Overdue(TxHash),
    /// This validator does not hold this name's transaction, so it cannot
    /// say: the vote is deferred.
    Unknown(TxHash),
}

impl Resolutions {
    /// How `entries` stand against what this validator's store fixes
    /// for each, `restated` saying whether a name restates it exactly,
    /// `None` for one the store cannot answer for.
    ///
    /// A misstatement answers over an unknown name: a proposer who
    /// restates one figure wrongly is refused whatever else the record
    /// names, and only a record every name of which checks out is exact.
    pub fn of(
        entries: impl IntoIterator<Item = UnsettledTx>,
        restated: impl Fn(&UnsettledTx) -> Option<bool>,
    ) -> Self {
        let mut unknown = None;
        for entry in entries {
            match restated(&entry) {
                Some(true) => {}
                Some(false) => return Self::Wrong(entry.tx_hash),
                None => {
                    unknown.get_or_insert(entry.tx_hash);
                }
            }
        }
        unknown.map_or(Self::Exact, Self::Unknown)
    }

    /// This answer folded with the successes the block's finalizations
    /// decide for members that await nobody, `overdue` saying whether
    /// each sits at or past its deadline at the block's anchor, `None`
    /// for one this validator does not hold.
    ///
    /// A refusal answers over a deferral: a block carrying an overdue
    /// success is refused whatever else this validator cannot say.
    #[must_use]
    pub fn and_successes(
        self,
        successes: impl IntoIterator<Item = TxHash>,
        overdue: impl Fn(TxHash) -> Option<bool>,
    ) -> Self {
        self.and_each(successes, overdue, Self::Overdue)
    }

    /// One fold for every name a finalization is held to: a refusal
    /// already reached stands, the first name `judge` answers `true` for
    /// is refused as `refuse` names it, and a name it cannot answer for
    /// defers unless something refuses.
    fn and_each(
        self,
        names: impl IntoIterator<Item = TxHash>,
        judge: impl Fn(TxHash) -> Option<bool>,
        refuse: fn(TxHash) -> Self,
    ) -> Self {
        let mut unknown = match self {
            Self::Wrong(_) | Self::Overdue(_) => return self,
            Self::Unknown(tx_hash) => Some(tx_hash),
            Self::Exact => None,
        };
        for tx_hash in names {
            match judge(tx_hash) {
                Some(true) => return refuse(tx_hash),
                Some(false) => {}
                None => {
                    unknown.get_or_insert(tx_hash);
                }
            }
        }
        unknown.map_or(Self::Exact, Self::Unknown)
    }
}

/// One departed counterpart's remainder as this chain sees it: what it
/// left unsettled.
///
/// The record carries no proof. The proof is the departed shard's
/// settled set, which the voter fetches — it is complete and
/// beacon-attested, so absence from it is proof rather than ignorance —
/// and a voter that cannot read it defers.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct AbandonmentRecord {
    /// The counterpart shard that can never settle these.
    shard: ShardId,
    /// Its terminal block's weighted timestamp — what a validator
    /// resolves its settled set against, and what dates the record
    /// against the transactions it speaks for.
    terminal_wt: WeightedTimestamp,
    /// Transactions this chain still owes an outcome for that `shard`
    /// can never settle.
    ///
    /// Sorted by hash and duplicate-free on it, so the record has one form
    /// and a validator checking it walks the same order it would build.
    unsettled: Capped<Vec<UnsettledTx>, MAX_UNSETTLED_PER_BLOCK>,
    /// Crossings this shard issued that `shard` never took, named off
    /// their record leaves where no entry names their transaction.
    ///
    /// Sorted by record key and duplicate-free on it.
    unclaimed: Capped<Vec<UnclaimedCrossing>, MAX_UNSETTLED_PER_BLOCK>,
}

impl AbandonmentRecord {
    /// A record over what `shard`, which left at `terminal_wt`, did not
    /// settle of `unsettled`, in the canonical order.
    #[must_use]
    pub fn new(
        shard: ShardId,
        terminal_wt: WeightedTimestamp,
        unsettled: impl IntoIterator<Item = UnsettledTx>,
    ) -> Self {
        let mut unsettled: Vec<UnsettledTx> = unsettled.into_iter().collect();
        unsettled.sort_unstable_by_key(|entry| entry.tx_hash);
        unsettled.dedup_by_key(|entry| entry.tx_hash);
        // A list past the cap is one no record may carry, and an empty
        // record is one `is_well_formed` refuses — so an over-cap input
        // lands where it landed before, refused rather than trimmed into
        // a different record.
        Self {
            shard,
            terminal_wt,
            unsettled: Capped::new(unsettled).unwrap_or_default(),
            unclaimed: Capped::empty(),
        }
    }

    /// This record naming `unclaimed` as well, in the canonical order.
    #[must_use]
    pub fn with_unclaimed(self, unclaimed: impl IntoIterator<Item = UnclaimedCrossing>) -> Self {
        let mut unclaimed: Vec<UnclaimedCrossing> = unclaimed.into_iter().collect();
        unclaimed.sort_unstable_by_key(|crossing| crossing.record);
        unclaimed.dedup_by_key(|crossing| crossing.record);
        Self {
            unclaimed: Capped::new(unclaimed).unwrap_or_default(),
            ..self
        }
    }

    /// The counterpart shard.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.shard
    }

    /// Where the counterpart's chain ended.
    #[must_use]
    pub const fn terminal_wt(&self) -> WeightedTimestamp {
        self.terminal_wt
    }

    /// An upper bound on what this record costs the block that carries
    /// it: its own terms plus each name's.
    ///
    /// The figure the section's byte budget is spent in. It is what
    /// bounds the section rather than the name count, because a name's
    /// own cost varies with its reach — a transfer names two routes, a
    /// route dozens — so the same count of names spans a four-fold
    /// range of bytes.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        ABANDONMENT_RECORD_BYTES
            + self
                .unsettled
                .iter()
                .map(UnsettledTx::wire_weight)
                .sum::<usize>()
            + self.unclaimed.len() * UNCLAIMED_CROSSING_BYTES
    }

    /// The transactions it can never settle, each with what abandoning
    /// it takes.
    #[must_use]
    pub fn unsettled(&self) -> &[UnsettledTx] {
        &self.unsettled
    }

    /// Just the transactions named unsettled.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.unsettled.iter().map(|entry| entry.tx_hash)
    }

    /// The crossings named off their record leaves.
    #[must_use]
    pub fn unclaimed(&self) -> &[UnclaimedCrossing] {
        &self.unclaimed
    }

    /// How many names the record carries between its two lists.
    #[must_use]
    pub fn names(&self) -> usize {
        self.unsettled.len() + self.unclaimed.len()
    }

    /// Whether the record is in the one form it may take: each list
    /// sorted without repeats, no crossing issued by a transaction the
    /// record also names unsettled, and naming something.
    ///
    /// An empty record asserts nothing and would cost a block a leaf for
    /// it, so it is not well-formed rather than merely pointless. The
    /// upper bound is the block's, which a single record may spend the
    /// whole of; what stops several records spending it each is the sum
    /// the block's own check applies.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.names() > 0
            && self
                .unsettled
                .windows(2)
                .all(|pair| pair[0].tx_hash < pair[1].tx_hash)
            && self
                .unclaimed
                .windows(2)
                .all(|pair| pair[0].record < pair[1].record)
            && self.unclaimed.iter().all(|crossing| {
                self.unsettled
                    .binary_search_by_key(&crossing.tx, |entry| entry.tx_hash)
                    .is_err()
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_vm_effects::{Hash32, IntentHash};
    use hyperscale_vm_types::ResourceAddr;

    use super::*;
    use crate::{Address, AddressClass, Hash, LocalKey};

    fn tx(seed: u8) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
            deadline: Deadline::of(WeightedTimestamp::from_millis(u64::from(seed) * 100)),
            charged: u128::from(seed) * 7,
            charge: AbortCharge {
                vault: SubstateKey {
                    owner: Address::new([seed; 31], AddressClass::Component),
                    local: LocalKey([seed; 16]),
                },
                amount: u128::from(seed) * 3,
            },
            committed: CommittedAt {
                height: BlockHeight::new(u64::from(seed)),
                anchor: WeightedTimestamp::from_millis(u64::from(seed) * 10),
                committee_anchor: WeightedTimestamp::from_millis(u64::from(seed) * 10),
            },
            reach: Capped::from_array([RoutePrefix::of(Address::new(
                [seed; 31],
                AddressClass::Component,
            ))]),
        }
    }

    fn wt() -> WeightedTimestamp {
        WeightedTimestamp::from_millis(1_000)
    }

    /// One form: whatever order a caller offers, the record it builds is
    /// the record every other builder would have produced.
    /// A holder checks every figure: the same entry is exact, and one
    /// naming another vault, another amount, another reservation,
    /// another deadline or another commit is wrong.
    #[test]
    fn a_holder_checks_every_figure() {
        let held = |hash: TxHash| (hash == tx(1).tx_hash).then(|| tx(1));
        let restated = |entry: UnsettledTx| {
            Resolutions::of([entry], |entry| {
                held(entry.tx_hash).map(|held| held == *entry)
            })
        };

        assert_eq!(restated(tx(1)), Resolutions::Exact);
        let wrong = Resolutions::Wrong(tx(1).tx_hash);
        assert_eq!(
            restated(UnsettledTx {
                charge: AbortCharge {
                    vault: tx(2).charge.vault,
                    ..tx(1).charge
                },
                ..tx(1)
            }),
            wrong,
        );
        assert_eq!(
            restated(UnsettledTx {
                charge: AbortCharge {
                    amount: tx(1).charge.amount + 1,
                    ..tx(1).charge
                },
                ..tx(1)
            }),
            wrong,
        );
        assert_eq!(
            restated(UnsettledTx {
                charged: tx(1).charged + 1,
                ..tx(1)
            }),
            wrong,
        );
        assert_eq!(
            restated(UnsettledTx {
                deadline: Deadline::of(
                    tx(1).deadline.validity_end().plus(Duration::from_millis(1))
                ),
                ..tx(1)
            }),
            wrong,
        );
        assert_eq!(
            restated(UnsettledTx {
                committed: CommittedAt {
                    anchor: tx(1).committed.anchor.plus(Duration::from_millis(1)),
                    ..tx(1).committed
                },
                ..tx(1)
            }),
            wrong,
        );
        assert_eq!(
            restated(UnsettledTx {
                committed: CommittedAt {
                    height: tx(1).committed.height.next(),
                    ..tx(1).committed
                },
                ..tx(1)
            }),
            wrong,
        );
    }

    /// A departed shard is party to a name when it held one of the
    /// name's remote routes at the anchor this chain committed the
    /// transaction under, and left afterwards — however the body's
    /// window sits against the cut.
    #[test]
    fn a_party_is_dated_by_the_commit() {
        let local = ShardId::leaf(1, 1);
        let departed = ShardId::leaf(1, 0);
        let successor = ShardId::leaf(2, 0);
        let name = UnsettledTx {
            reach: Capped::from_array([RoutePrefix::of(Address::new(
                [0x00; 31],
                AddressClass::Component,
            ))]),
            committed: CommittedAt {
                height: BlockHeight::new(7),
                anchor: WeightedTimestamp::from_millis(1_000),
                committee_anchor: WeightedTimestamp::from_millis(1_000),
            },
            ..tx(1)
        };
        let after = WeightedTimestamp::from_millis(1_500);
        let before = WeightedTimestamp::from_millis(500);

        assert!(
            name.party(local, departed, after, &[(departed, after)]),
            "a shard that left after the commit held the route when the crossing went",
        );
        assert!(
            !name.party(local, departed, before, &[(departed, before)]),
            "a shard that had left by the commit was issued nothing, whatever its keyspace",
        );
        assert!(
            !name.party(local, local, after, &[(local, after)]),
            "the route has to be somebody else's",
        );
        let later = WeightedTimestamp::from_millis(2_000);
        assert!(
            !name.party(
                local,
                successor,
                later,
                &[(departed, after), (successor, later)]
            ),
            "a successor leaving later never held what its predecessor's departure covered",
        );
        assert!(
            name.party(
                local,
                departed,
                after,
                &[(departed, after), (successor, later)]
            ),
            "and the predecessor is still the one party",
        );
    }

    fn unclaimed(seed: u8, consumer: Address, validity_end: u64) -> UnclaimedCrossing {
        UnclaimedCrossing {
            record: SubstateKey {
                owner: Address::new([0x80 | seed; 31], AddressClass::Component),
                local: LocalKey([seed; 16]),
            },
            tx: TxHash::from(Hash::from_bytes(&[seed; 32])),
            consumer: RoutePrefix::of(consumer),
            validity_end: WeightedTimestamp::from_millis(validity_end),
        }
    }

    /// A departed shard is party to a crossing named off its leaf when it
    /// held the consumer's route from the transaction's validity opening
    /// to past its deadline, and was the first over that route to leave.
    #[test]
    fn an_unclaimed_crossing_is_dated_by_the_validity_end() {
        let local = ShardId::leaf(1, 1);
        let departed = ShardId::leaf(2, 0);
        let predecessor = ShardId::leaf(1, 0);
        let consumer = Address::new([0x00; 31], AddressClass::Component);
        let validity_end = 1_000_000;
        let crossing = unclaimed(1, consumer, validity_end);
        let deadline = Deadline::of(crossing.validity_end).at();
        let cut = deadline.plus(Duration::from_secs(600));

        assert!(
            crossing.party(local, departed, cut, &[(departed, cut)]),
            "the one holder of the consumer's route, leaving past the deadline",
        );
        assert!(
            crossing.party(local, departed, deadline, &[(departed, deadline)]),
            "a cut at the deadline itself leaves nothing to take",
        );
        let early = deadline.minus(Duration::from_millis(1));
        assert!(
            !crossing.party(local, departed, early, &[(departed, early)]),
            "a cut before the deadline leaves the crossing takeable by a successor",
        );
        assert!(
            !crossing.party(local, local, cut, &[(local, cut)]),
            "the consumer has to be somebody else's",
        );
        let stranger = ShardId::leaf(2, 1);
        assert!(
            !crossing.party(local, stranger, cut, &[(stranger, cut)]),
            "a shard not holding the consumer's route took nothing",
        );
        let inside = crossing
            .validity_end
            .minus(MAX_VALIDITY_RANGE)
            .plus(Duration::from_millis(1));
        assert!(
            !crossing.party(
                local,
                departed,
                cut,
                &[(predecessor, inside), (departed, cut)]
            ),
            "a predecessor leaving inside the transaction's life may have taken it",
        );
        let before = crossing.validity_end.minus(MAX_VALIDITY_RANGE);
        assert!(
            crossing.party(
                local,
                departed,
                cut,
                &[(predecessor, before), (departed, cut)]
            ),
            "one that left before the transaction could open took nothing",
        );
    }

    /// A name restates an escrowed record's transaction, consumer and
    /// validity end, and nothing else passes for it.
    #[test]
    fn an_unclaimed_crossing_restates_its_record() {
        let record = SubstateKey {
            owner: Address::new([0x81; 31], AddressClass::Component),
            local: LocalKey([1; 16]),
        };
        let cell = CrossingCell {
            resource: ResourceAddr::new([0xE1; 31]),
            amount: 5,
            intent: IntentHash(Hash32([3; 32])),
            local: 0,
            output: 0,
            validity_end_ms: 9_000,
            tx: TxHash::from(Hash::from_bytes(&[4; 32])),
            consumer: Address::new([0x10; 31], AddressClass::Component),
            terms: Terms::Escrowed { credit: record },
        };
        let name = UnclaimedCrossing::of(record, &cell);
        assert!(name.restates(&cell));
        for misstated in [
            UnclaimedCrossing {
                tx: TxHash::from(Hash::from_bytes(&[5; 32])),
                ..name
            },
            UnclaimedCrossing {
                validity_end: WeightedTimestamp::from_millis(9_001),
                ..name
            },
            UnclaimedCrossing {
                consumer: RoutePrefix::of(Address::new([0x90; 31], AddressClass::Component)),
                ..name
            },
        ] {
            assert!(!misstated.restates(&cell), "{misstated:?}");
        }
        let owed = CrossingCell {
            terms: Terms::Owed,
            ..cell
        };
        assert!(!name.restates(&owed), "nothing takes an owed crossing back");
    }

    /// A record may name crossings alone; its crossings are sorted by
    /// record, and none may be issued by a transaction it names
    /// unsettled.
    #[test]
    fn a_record_of_unclaimed_crossings_has_one_form() {
        let consumer = Address::new([0x00; 31], AddressClass::Component);
        let (one, two) = (unclaimed(1, consumer, 1), unclaimed(2, consumer, 1));
        let alone = AbandonmentRecord::new(ShardId::ROOT, wt(), []).with_unclaimed([two, one, two]);
        assert!(alone.is_well_formed());
        assert_eq!(alone.unclaimed(), &[one, two]);
        assert_eq!(alone.names(), 2);
        assert_eq!(
            alone.wire_weight(),
            ABANDONMENT_RECORD_BYTES + 2 * UNCLAIMED_CROSSING_BYTES
        );

        let reversed = AbandonmentRecord {
            unclaimed: Capped::from_array([two, one]),
            ..alone
        };
        assert!(!reversed.is_well_formed());

        let both = AbandonmentRecord::new(ShardId::ROOT, wt(), [tx(1)]).with_unclaimed([
            UnclaimedCrossing {
                tx: tx(1).tx_hash,
                ..one
            },
        ]);
        assert!(
            !both.is_well_formed(),
            "a transaction is named once, in one list",
        );
    }

    /// A validator that does not hold a transaction cannot say either
    /// way, which is a third answer and not a pass — and a misstatement
    /// elsewhere in the record answers over it.
    #[test]
    fn a_non_holder_cannot_say_unless_a_figure_is_wrong() {
        let held = |entry: &UnsettledTx| (entry.tx_hash == tx(1).tx_hash).then(|| tx(1) == *entry);
        assert_eq!(
            Resolutions::of([tx(2)], held),
            Resolutions::Unknown(tx(2).tx_hash)
        );
        assert_eq!(
            Resolutions::of([tx(2), tx(1)], held),
            Resolutions::Unknown(tx(2).tx_hash)
        );
        assert_eq!(
            Resolutions::of(
                [
                    tx(2),
                    UnsettledTx {
                        charged: tx(1).charged + 1,
                        ..tx(1)
                    }
                ],
                held
            ),
            Resolutions::Wrong(tx(1).tx_hash)
        );
        assert_eq!(Resolutions::of([], held), Resolutions::Exact);

        // Deliveries fold after the figures: a lapsed one refuses over an
        // unknown name, an unknown delivery defers, and a wrong figure
        // stands whatever the deliveries say.
        let lapsed = |tx_hash: TxHash| {
            if tx_hash == tx(3).tx_hash {
                Some(true)
            } else if tx_hash == tx(1).tx_hash {
                Some(false)
            } else {
                None
            }
        };
        assert_eq!(
            Resolutions::Exact.and_successes([tx(1).tx_hash], lapsed),
            Resolutions::Exact
        );
        assert_eq!(
            Resolutions::Exact.and_successes([tx(2).tx_hash], lapsed),
            Resolutions::Unknown(tx(2).tx_hash)
        );
        assert_eq!(
            Resolutions::Unknown(tx(2).tx_hash).and_successes([tx(3).tx_hash], lapsed),
            Resolutions::Overdue(tx(3).tx_hash)
        );
        assert_eq!(
            Resolutions::Wrong(tx(1).tx_hash).and_successes([tx(3).tx_hash], lapsed),
            Resolutions::Wrong(tx(1).tx_hash)
        );
    }

    #[test]
    fn a_record_is_built_in_its_canonical_order() {
        let jumbled = AbandonmentRecord::new(ShardId::ROOT, wt(), [tx(3), tx(1), tx(3), tx(2)]);
        let ordered = AbandonmentRecord::new(ShardId::ROOT, wt(), [tx(1), tx(2), tx(3)]);

        assert_eq!(jumbled, ordered, "sorted and deduplicated on the way in");
        assert!(jumbled.is_well_formed());
    }

    /// A record naming nothing is not a record. It would commit a block to
    /// a claim it does not make.
    #[test]
    fn an_empty_record_is_not_well_formed() {
        let empty = AbandonmentRecord::new(ShardId::ROOT, wt(), []);
        assert!(!empty.is_well_formed());
    }

    /// Out of order or repeating is a second form of the same claim, and
    /// the root would differ from the one the canonical form produces.
    #[test]
    fn a_record_out_of_its_canonical_order_is_refused() {
        let reversed = AbandonmentRecord {
            shard: ShardId::ROOT,
            terminal_wt: wt(),
            unsettled: Capped::from_array([tx(2), tx(1)]),
            unclaimed: Capped::empty(),
        };
        assert!(!reversed.is_well_formed());

        let repeating = AbandonmentRecord {
            shard: ShardId::ROOT,
            terminal_wt: wt(),
            unsettled: Capped::from_array([tx(1), tx(1)]),
            unclaimed: Capped::empty(),
        };
        assert!(!repeating.is_well_formed());
    }

    /// The figures ride each name, so a record that reaches a replica
    /// holding none of the transactions still says what abandoning them
    /// takes.
    #[test]
    fn a_name_carries_what_abandoning_it_takes() {
        let record = AbandonmentRecord::new(ShardId::ROOT, wt(), [tx(2), tx(1)]);
        assert_eq!(
            record.unsettled(),
            &[tx(1), tx(2)],
            "each name keeps its own deadline and reservation through the sort",
        );
    }
}
