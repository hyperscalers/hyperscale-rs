//! What a counterpart's chain established about the transactions this
//! shard still owes an outcome for, and the evidence that says so.
//!
//! A cross-shard transaction needs every certificate its settlement
//! waits on, so one whose counterpart can never certify it can never
//! settle anywhere. That is the fact this shard needs in order to abandon
//! it, and it is established one of two ways. The counterpart left
//! without settling: its settled set is complete and beacon-attested, so
//! absence from it is proof, but the set can only be fetched while the
//! terminal it belongs to is still served. Or the counterpart was heard
//! from — its certificate carried a verdict, or a proof against one of
//! its commit-proven headers answered for a cell — and what it said is
//! written down as one [`Heard`]: the [`Question`] asked, the [`Word`]
//! that answered it, and the moment it was taken at.
//!
//! Every word licenses an abort. A core's refusal ends the transaction
//! outright. A core's committed cell absent past the deadline says the
//! core never committed it, since before the deadline the core may still
//! legitimately commit and past the cell's own sweep the cell is gone
//! either way; a delivery's claim absent past the lapse says the same of
//! the delivery, on the same terms against its claim cell; and a
//! one-shard core's consumer claim absent past the deadline says the
//! core never took it, since a block carrying that core's success past
//! the deadline is refused.
//!
//! So the answer is written down while it can still be read. A record
//! names the transactions this chain still owes an outcome for, with the
//! evidence its counterpart's chain gave, and once committed it is
//! ordinary history: every replica reads the same verdicts off its own
//! chain at any distance, including one that was switched off when the
//! counterpart left.
//!
//! What is never recorded is a settlement. That a counterpart *did*
//! settle a transaction changes nothing this shard can act on — the
//! transaction stays owed and unabandonable either way. A consumer's
//! claim cell read present is the one settling answer, and it needs no
//! record: the reading is itself committed content, folded by every
//! replica at the block that carries it, and what it licenses — the
//! retirement of the record cell the issuer held for the claim — is
//! composed from the ledger that fold writes.
//!
//! Each name carries the figures composing the abort takes: the deadline
//! it opens at, the reservation it returns, and the charge it settles.
//! All are functions of the transaction body, so a proposer restates them
//! and a voter holding the transaction checks the restatement — and a
//! replica whose rebuild never reached the transaction's own block still
//! holds enough to compose the same verdict as its peers.

use hyperscale_hbor::Hbor;

use crate::{
    ABANDONMENT_RECORD_BYTES, Deadline, Hash, MAX_PREFIXES_PER_TX, MAX_UNSETTLED_PER_BLOCK,
    MAX_VALIDITY_RANGE, Probed, ROUTE_PREFIX_BYTES, RoutePrefix, ShardId, SubstateKey, Transaction,
    TransactionDecision, TxHash, UNSETTLED_TX_BYTES, WeightedTimestamp,
};

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
    /// What abandoning `tx` states, read off the transaction itself.
    ///
    /// The one place every figure is derived, so a proposer restating
    /// them and a voter checking the restatement compute one value: the
    /// deadline is the transaction's own, the reservation is the
    /// declared work, and the charge is the fee vault at the declared
    /// price.
    ///
    /// # Panics
    ///
    /// As [`Transaction::work`], on a transaction that was never derived.
    #[must_use]
    pub fn for_transaction(tx: &Transaction) -> Self {
        Self {
            tx_hash: tx.hash(),
            deadline: Deadline::of_transaction(tx),
            declared_work: tx.work(),
            charge: AbortCharge {
                vault: tx.fee_vault(),
                amount: tx.price(),
            },
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

    /// The earliest instant any shard could have committed the
    /// transaction: one validity range before its validity ends.
    ///
    /// What dates a departure against the entry — a shard that left
    /// before this never held the transaction, whatever its keyspace
    /// covers now. Read off the transaction rather than off the block
    /// that committed it, because the block differs per shard and the
    /// question does not: two shards commit one transaction at two
    /// frontiers, and a replica meeting it in a record has neither.
    /// Erring early is the safe direction — it can only widen who counts
    /// as party, never narrow it.
    #[must_use]
    pub fn first_commit(&self) -> WeightedTimestamp {
        self.deadline.validity_end().minus(MAX_VALIDITY_RANGE)
    }
}

/// How a block's resolutions stand against the transactions they name:
/// the figures its records restate, and the deliveries its finalizations
/// carry.
///
/// The voter's answer, read off committed bodies. A validator whose
/// store holds a transaction answers for it — a figure exactly or
/// wrongly, a delivery inside its window or past the lapse, a success
/// inside its deadline or past it — and one whose store never held it,
/// having synced past its block, cannot say,
/// which is a third answer and not a pass.
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
    /// How `entries` stand against the figures `held` reads off each
    /// named transaction, `None` for one it does not hold.
    ///
    /// A misstatement answers over an unknown name: a proposer who
    /// restates one figure wrongly is refused whatever else the record
    /// names, and only a record every name of which checks out is exact.
    pub fn of(
        entries: impl IntoIterator<Item = UnsettledTx>,
        held: impl Fn(TxHash) -> Option<UnsettledTx>,
    ) -> Self {
        let mut unknown = None;
        for entry in entries {
            match held(entry.tx_hash) {
                Some(figures) if figures == entry => {}
                Some(_) => return Self::Wrong(entry.tx_hash),
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

/// What a leg's ledger asks a counterpart about one transaction.
///
/// Its verdict, which its certificate answers; or one of its cells,
/// which a proof against one of its commit-proven headers answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Question {
    /// What the counterpart decided.
    Verdict,
    /// Whether the counterpart's state holds the probed cell.
    Cell(Probed),
}

impl Question {
    /// Every question, in the order a block carries their records.
    pub const ALL: [Self; 4] = [
        Self::Verdict,
        Self::Cell(Probed::Core),
        Self::Cell(Probed::Delivery),
        Self::Cell(Probed::Claim),
    ];
}

// A cell question per [`Probed`] and the verdict beside them. Held at
// compile time because the array is written out: a `Probed` variant
// added without a line here would leave the order a block carries its
// records silently short of one.
const _: () = assert!(Question::ALL.len() == Probed::ALL.len() + 1);

/// What a counterpart said in answer.
///
/// A certificate answers a [`Question::Verdict`] with a refusal, named
/// by its attested digest so a claim to it can be held to the copy a
/// voter holds. A proof answers a [`Question::Cell`] with an absence,
/// and the crossing is the issuer's to take back.
///
/// Neither a success nor a presence is among them. What a certificate
/// says of a success is that the counterpart's execution went through,
/// which is the cue to ask whether it wrote the claim that success
/// promises — see [`Spoken`](crate::Spoken). What a proof says of a
/// present cell is that the consumer holds the crossing, and that is
/// folded off the committed claim itself rather than restated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Word {
    /// The counterpart refused the transaction: a rejection or an abort.
    Refused {
        /// What the certificate decided — never an acceptance.
        decision: TransactionDecision,
        /// The certificate's attested digest: its signed identity, which
        /// is copy-invariant where its wire hash is not.
        digest: Hash,
    },
    /// The probed cell was absent.
    Absent,
}

/// One thing a counterpart's chain said about one transaction, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Heard {
    /// What was asked.
    pub question: Question,
    /// What answered it.
    pub word: Word,
    /// The moment the answer was taken at: the certificate's vote
    /// anchor, or the weighted timestamp of the block the absence was
    /// proved against — which has to sit inside the window the question
    /// is meaningful in, or the answer says nothing.
    pub at: WeightedTimestamp,
}

impl Heard {
    /// Whether the word answers the question: a certificate speaks to a
    /// verdict, a proof to a cell, and a verdict a record may carry is
    /// always a refusal.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        match (self.question, self.word) {
            (Question::Verdict, Word::Refused { decision, .. }) => {
                matches!(
                    decision,
                    TransactionDecision::Reject | TransactionDecision::Aborted
                )
            }
            (Question::Cell(_), Word::Absent) => true,
            (Question::Verdict, Word::Absent) | (Question::Cell(_), Word::Refused { .. }) => false,
        }
    }
}

/// What a counterpart's chain shows about the transactions a record
/// names, and when it was read there.
///
/// Every arm carries a moment and none carries its proof. The proof is
/// fetched by the voter — a settled set, a certificate, or a state proof
/// against a commit-proven header — and a voter that cannot verify
/// defers. An absence proof is a JMT non-inclusion path; carrying one
/// per entry would blow the record's size budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum CounterpartEvidence {
    /// The shard left without settling. Absence from its complete,
    /// beacon-attested settled set is the proof.
    Departed {
        /// Its terminal block's weighted timestamp — what a validator
        /// resolves its settled set against, and what dates the record
        /// against the transactions it speaks for.
        terminal_wt: WeightedTimestamp,
    },
    /// The shard was heard from: its certificate or its commit-proven
    /// state answered a question, and every name in the record got the
    /// same answer at the same moment.
    Heard(Heard),
}

impl CounterpartEvidence {
    /// The moment the evidence was taken at.
    #[must_use]
    pub const fn moment(&self) -> WeightedTimestamp {
        match self {
            Self::Departed { terminal_wt } => *terminal_wt,
            Self::Heard(heard) => heard.at,
        }
    }

    /// Whether the evidence is in a form a record may carry.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        match self {
            Self::Departed { .. } => true,
            Self::Heard(heard) => heard.is_well_formed(),
        }
    }
}

/// One counterpart's remainder as this chain sees it: what it can never
/// settle.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct AbandonmentRecord {
    /// The counterpart shard that can never settle these.
    shard: ShardId,
    /// Why not, and as of when.
    evidence: CounterpartEvidence,
    /// Transactions this chain still owes an outcome for that `shard`
    /// can never settle.
    ///
    /// Sorted by hash and duplicate-free on it, so the record has one form
    /// and a validator checking it walks the same order it would build.
    #[hbor(max = MAX_UNSETTLED_PER_BLOCK)]
    unsettled: Vec<UnsettledTx>,
}

impl AbandonmentRecord {
    /// Build a record over `unsettled`, in the canonical order.
    #[must_use]
    pub fn new(
        shard: ShardId,
        evidence: CounterpartEvidence,
        unsettled: impl IntoIterator<Item = UnsettledTx>,
    ) -> Self {
        let mut unsettled: Vec<UnsettledTx> = unsettled.into_iter().collect();
        unsettled.sort_unstable_by_key(|entry| entry.tx_hash);
        unsettled.dedup_by_key(|entry| entry.tx_hash);
        Self {
            shard,
            evidence,
            unsettled,
        }
    }

    /// A record over what a shard that left at `terminal_wt` did not
    /// settle.
    #[must_use]
    pub fn departed(
        shard: ShardId,
        terminal_wt: WeightedTimestamp,
        unsettled: impl IntoIterator<Item = UnsettledTx>,
    ) -> Self {
        Self::new(
            shard,
            CounterpartEvidence::Departed { terminal_wt },
            unsettled,
        )
    }

    /// A record over what `shard` was heard to say, of every name at
    /// once.
    #[must_use]
    pub fn heard(
        shard: ShardId,
        heard: Heard,
        unsettled: impl IntoIterator<Item = UnsettledTx>,
    ) -> Self {
        Self::new(shard, CounterpartEvidence::Heard(heard), unsettled)
    }

    /// The counterpart shard.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.shard
    }

    /// Why it can never settle these, and as of when.
    #[must_use]
    pub const fn evidence(&self) -> CounterpartEvidence {
        self.evidence
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

    /// Whether the record is in the one form it may take: evidence a
    /// word answers, sorted names without repeats, and naming something.
    ///
    /// An empty record asserts nothing and would cost a block a leaf for
    /// it, so it is not well-formed rather than merely pointless. The
    /// upper bound is the block's, which a single record may spend the
    /// whole of; what stops several records spending it each is the sum
    /// the block's own check applies.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.evidence.is_well_formed()
            && !self.unsettled.is_empty()
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
    /// naming another vault, another amount, another reservation or
    /// another deadline is wrong.
    #[test]
    fn a_holder_checks_every_figure() {
        let held = |hash: TxHash| (hash == tx(1).tx_hash).then(|| tx(1));
        let restated = |entry: UnsettledTx| Resolutions::of([entry], held);

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
    }

    /// A validator that does not hold a transaction cannot say either
    /// way, which is a third answer and not a pass — and a misstatement
    /// elsewhere in the record answers over it.
    #[test]
    fn a_non_holder_cannot_say_unless_a_figure_is_wrong() {
        let held = |hash: TxHash| (hash == tx(1).tx_hash).then(|| tx(1));
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
        let jumbled =
            AbandonmentRecord::departed(ShardId::ROOT, wt(), [tx(3), tx(1), tx(3), tx(2)]);
        let ordered = AbandonmentRecord::departed(ShardId::ROOT, wt(), [tx(1), tx(2), tx(3)]);

        assert_eq!(jumbled, ordered, "sorted and deduplicated on the way in");
        assert!(jumbled.is_well_formed());
    }

    /// A record naming nothing is not a record. It would commit a block to
    /// a claim it does not make.
    #[test]
    fn an_empty_record_is_not_well_formed() {
        let empty = AbandonmentRecord::departed(ShardId::ROOT, wt(), []);
        assert!(!empty.is_well_formed());
    }

    /// Out of order or repeating is a second form of the same claim, and
    /// the root would differ from the one the canonical form produces.
    #[test]
    fn a_record_out_of_its_canonical_order_is_refused() {
        let reversed = AbandonmentRecord {
            shard: ShardId::ROOT,
            evidence: CounterpartEvidence::Departed { terminal_wt: wt() },
            unsettled: vec![tx(2), tx(1)],
        };
        assert!(!reversed.is_well_formed());

        let repeating = AbandonmentRecord {
            shard: ShardId::ROOT,
            evidence: CounterpartEvidence::Departed { terminal_wt: wt() },
            unsettled: vec![tx(1), tx(1)],
        };
        assert!(!repeating.is_well_formed());
    }

    /// The figures ride each name, so a record that reaches a replica
    /// holding none of the transactions still says what abandoning them
    /// takes.
    #[test]
    fn a_name_carries_what_abandoning_it_takes() {
        let record = AbandonmentRecord::departed(ShardId::ROOT, wt(), [tx(2), tx(1)]);
        assert_eq!(
            record.unsettled(),
            &[tx(1), tx(2)],
            "each name keeps its own deadline and reservation through the sort",
        );
    }

    /// Every well-formed arm reads its moment back, and a word that does
    /// not answer its question is refused as a record.
    #[test]
    fn every_arm_reads_its_moment_and_only_an_answering_word_is_well_formed() {
        let digest = Hash::from_bytes(b"digest");
        let heard = |question, word| Heard {
            question,
            word,
            at: wt(),
        };
        let refused = Word::Refused {
            decision: TransactionDecision::Reject,
            digest,
        };
        let arms = [
            CounterpartEvidence::Departed { terminal_wt: wt() },
            CounterpartEvidence::Heard(heard(Question::Verdict, refused)),
            CounterpartEvidence::Heard(heard(Question::Cell(Probed::Core), Word::Absent)),
            CounterpartEvidence::Heard(heard(Question::Cell(Probed::Delivery), Word::Absent)),
            CounterpartEvidence::Heard(heard(Question::Cell(Probed::Claim), Word::Absent)),
        ];
        for arm in arms {
            assert_eq!(arm.moment(), wt());
            assert!(arm.is_well_formed());
            assert!(AbandonmentRecord::new(ShardId::ROOT, arm, [tx(1)]).is_well_formed());
        }
        let malformed = [
            heard(Question::Verdict, Word::Absent),
            heard(Question::Cell(Probed::Core), refused),
            heard(
                Question::Verdict,
                Word::Refused {
                    decision: TransactionDecision::Accept,
                    digest,
                },
            ),
        ];
        for heard in malformed {
            assert!(!heard.is_well_formed(), "{heard:?}");
            assert!(!AbandonmentRecord::heard(ShardId::ROOT, heard, [tx(1)]).is_well_formed());
        }
    }
}
