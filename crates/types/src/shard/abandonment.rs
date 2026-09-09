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

use hyperscale_hbor::Hbor;

use crate::{
    ABANDONMENT_RECORD_BYTES, BlockHeight, Deadline, MAX_PREFIXES_PER_TX, MAX_UNSETTLED_PER_BLOCK,
    ROUTE_PREFIX_BYTES, RoutePrefix, ShardId, ShardTrie, SubstateKey, Transaction, TxHash,
    UNSETTLED_TX_BYTES, WeightedTimestamp,
};

/// Where a chain committed a transaction: the block, and the anchor it
/// carried.
///
/// The anchor is what the block was admitted against — its parent
/// QC's weighted timestamp — and so the instant its trie is read at:
/// the trie that classified the transaction, routed its crossings, and
/// named which shards were party to it. The height is where a replica
/// reads that anchor off its own chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct CommittedAt {
    /// The block that carried the transaction.
    pub height: BlockHeight,
    /// The anchor that block was admitted against.
    pub anchor: WeightedTimestamp,
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
    /// The reservation its committing block took against the drain, which
    /// the abandonment returns exactly.
    pub declared_work: u64,
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
    #[hbor(max = MAX_PREFIXES_PER_TX)]
    pub reach: Vec<RoutePrefix>,
}

impl UnsettledTx {
    /// What abandoning `tx`, which this chain committed at `committed`,
    /// states.
    ///
    /// The one place every figure is derived, so a proposer restating
    /// them and a voter checking the restatement compute one value: the
    /// deadline is the transaction's own, the reservation is the
    /// declared work, the charge is the fee vault at the declared price,
    /// and the commit is the block's.
    ///
    /// # Panics
    ///
    /// As [`Transaction::work`], on a transaction that was never derived.
    #[must_use]
    pub fn for_transaction(tx: &Transaction, committed: CommittedAt) -> Self {
        Self {
            tx_hash: tx.hash(),
            deadline: Deadline::of_transaction(tx),
            declared_work: tx.work(),
            charge: AbortCharge {
                vault: tx.fee_vault(),
                amount: tx.price(),
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
    pub const fn wire_weight(&self) -> usize {
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
                    && departures
                        .iter()
                        .filter(|(departed, departed_at)| {
                            ShardTrie::shard_owns_route(*departed, route)
                                && *departed_at > committed
                        })
                        .map(|(_, departed_at)| *departed_at)
                        .min()
                        .is_none_or(|first| first >= cut)
            })
    }
}

/// How a block's resolutions stand against the transactions they name:
/// the figures its records restate, and the deliveries its finalizations
/// carry.
///
/// The voter's answer, read off committed bodies and blocks. A
/// validator whose store holds a transaction and the block a name says
/// committed it answers for it — a figure exactly or wrongly, a
/// delivery inside its window or past the lapse, a success inside its
/// deadline or past it — and one whose store never held them, having
/// synced past the block, cannot say, which is a third answer and not a
/// pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolutions {
    /// Every figure of every name is the one its transaction fixes, no
    /// delivery has lapsed, and no success is overdue.
    Exact,
    /// A figure of this name differs from the one its transaction fixes:
    /// the block is refused.
    Wrong(TxHash),
    /// A finalization delivers a crossing of this transaction at an
    /// anchor at or past its lapse, where its issuer may already have
    /// proved the claim absent and taken the crossing back: the block is
    /// refused.
    Lapsed(TxHash),
    /// A finalization decides this transaction with success, by its own
    /// execution, at an anchor at or past its deadline, where a leg that
    /// issued for it may already have read the claim absent and taken
    /// the crossing back.
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

    /// This answer folded with the deliveries the block's finalizations
    /// carry, `lapsed` saying whether each has lapsed at the block's
    /// anchor, `None` for one this validator does not hold.
    ///
    /// A refusal answers over a deferral: a block carrying a lapsed
    /// delivery is refused whatever else this validator cannot say.
    #[must_use]
    pub fn and_deliveries(
        self,
        deliveries: impl IntoIterator<Item = TxHash>,
        lapsed: impl Fn(TxHash) -> Option<bool>,
    ) -> Self {
        self.and_each(deliveries, lapsed, Self::Lapsed)
    }

    /// This answer folded with the successes the block's finalizations
    /// decide for members that await nobody, `overdue` saying whether
    /// each sits at or past its deadline at the block's anchor, `None`
    /// for one this validator does not hold.
    ///
    /// A refusal answers over a deferral, as a lapsed delivery does.
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
            Self::Wrong(_) | Self::Lapsed(_) | Self::Overdue(_) => return self,
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
    #[hbor(max = MAX_UNSETTLED_PER_BLOCK)]
    unsettled: Vec<UnsettledTx>,
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
        Self {
            shard,
            terminal_wt,
            unsettled,
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
    }

    /// The transactions it can never settle, each with what abandoning
    /// it takes.
    #[must_use]
    pub fn unsettled(&self) -> &[UnsettledTx] {
        &self.unsettled
    }

    /// Just the transactions named.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.unsettled.iter().map(|entry| entry.tx_hash)
    }

    /// Whether the record is in the one form it may take: sorted names
    /// without repeats, and naming something.
    ///
    /// An empty record asserts nothing and would cost a block a leaf for
    /// it, so it is not well-formed rather than merely pointless. The
    /// upper bound is the block's, which a single record may spend the
    /// whole of; what stops several records spending it each is the sum
    /// the block's own check applies.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.unsettled.is_empty()
            && self.unsettled.len() <= MAX_UNSETTLED_PER_BLOCK
            && self
                .unsettled
                .windows(2)
                .all(|pair| pair[0].tx_hash < pair[1].tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{Address, AddressClass, Hash, LocalKey};

    fn tx(seed: u8) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
            deadline: Deadline::of(WeightedTimestamp::from_millis(u64::from(seed) * 100)),
            declared_work: u64::from(seed) * 7,
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
            },
            reach: vec![RoutePrefix::of(Address::new(
                [seed; 31],
                AddressClass::Component,
            ))],
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
                declared_work: tx(1).declared_work + 1,
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
            reach: vec![RoutePrefix::of(Address::new(
                [0x00; 31],
                AddressClass::Component,
            ))],
            committed: CommittedAt {
                height: BlockHeight::new(7),
                anchor: WeightedTimestamp::from_millis(1_000),
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
                        declared_work: tx(1).declared_work + 1,
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
            Resolutions::Exact.and_deliveries([tx(1).tx_hash], lapsed),
            Resolutions::Exact
        );
        assert_eq!(
            Resolutions::Exact.and_deliveries([tx(2).tx_hash], lapsed),
            Resolutions::Unknown(tx(2).tx_hash)
        );
        assert_eq!(
            Resolutions::Unknown(tx(2).tx_hash).and_deliveries([tx(3).tx_hash], lapsed),
            Resolutions::Lapsed(tx(3).tx_hash)
        );
        assert_eq!(
            Resolutions::Wrong(tx(1).tx_hash).and_deliveries([tx(3).tx_hash], lapsed),
            Resolutions::Wrong(tx(1).tx_hash)
        );

        // Successes fold the same way, and a refusal already reached
        // stands over one: the first refusal is the answer.
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
            Resolutions::Lapsed(tx(1).tx_hash).and_successes([tx(3).tx_hash], lapsed),
            Resolutions::Lapsed(tx(1).tx_hash)
        );
        assert_eq!(
            Resolutions::Overdue(tx(3).tx_hash).and_deliveries([tx(3).tx_hash], lapsed),
            Resolutions::Overdue(tx(3).tx_hash)
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
            unsettled: vec![tx(2), tx(1)],
        };
        assert!(!reversed.is_well_formed());

        let repeating = AbandonmentRecord {
            shard: ShardId::ROOT,
            terminal_wt: wt(),
            unsettled: vec![tx(1), tx(1)],
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
