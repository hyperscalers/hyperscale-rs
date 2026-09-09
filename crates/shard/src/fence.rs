//! The vote fence: what this validator's own evidence says about the
//! claims a block makes on other chains.
//!
//! A block's content rules are deterministic over the block and the
//! committed chain, and every replica reaches the same verdict on them.
//! The fence is the other kind of check: a block claims that a departed
//! shard left a transaction unsettled, that a counterpart's cell read
//! one way, that a core's header carries a root, that a predecessor
//! never committed a transaction — and a validator can only hold those
//! claims to what it has itself mirrored. So the fence has three answers
//! rather than two. A claim the evidence contradicts refuses the vote for
//! good; a claim the evidence cannot yet answer withholds it, and names
//! what would let it answer; and a block making no claim this validator
//! cannot attest to passes.
//!
//! Everything the fence reads is a mirror shared with the execution
//! coordinator — the departed shards' settled sets, which anchors are
//! commit-proven, what cells this validator proved, what the predecessors
//! answered — so a block passes here exactly when
//! the composer that offered its content would have offered it against
//! the same mirror.

use hyperscale_core::{Action, FetchRequest, ProtocolEvent};
use hyperscale_types::{
    AbandonmentRecord, Block, CounterpartMirror, ProvenAnchors, ProvenCells, SettledSetVerdict,
    ShardId, StateClaim, TopologySchedule, WeightedTimestamp, settled_set_verdict,
};

use crate::precut::{Precut, PrecutStatus};

/// Why the fence withheld a vote.
#[derive(Debug)]
pub enum Withheld {
    /// This validator's evidence contradicts a claim the block makes;
    /// the block never gets this vote.
    Refused(String),
    /// This validator cannot yet check a claim the block makes; the
    /// block stays pending, and `wanted` asks for what would let it.
    Deferred {
        /// The claim, for the log.
        why: String,
        /// What to ask for, if anything, so the answer arrives.
        wanted: Vec<Action>,
    },
}

impl Withheld {
    const fn deferred(why: String) -> Self {
        Self::Deferred {
            why,
            wanted: Vec::new(),
        }
    }
}

/// The evidence a vote is fenced on, borrowed from the coordinator for
/// one judgment.
pub struct VoteFence<'a> {
    /// The departed shards' settled sets, and what committed records cover.
    pub mirror: &'a CounterpartMirror,
    /// The commit-proven remote headers.
    pub proven_anchors: &'a ProvenAnchors,
    /// The counterpart cells this validator has proven for itself.
    pub proven_cells: &'a ProvenCells,
    /// The predecessors' answers about transactions opening before the
    /// chain's origin.
    pub precut: &'a Precut,
    /// Where this chain began; content anchored before it belongs to a
    /// predecessor.
    pub cut: WeightedTimestamp,
    /// The shard this validator votes on.
    pub local_shard: ShardId,
}

impl VoteFence<'_> {
    /// Judge every claim `block` makes, in the order the cheapest
    /// evidence answers: its finalizations and its records against the
    /// settled sets, its state claims against the anchors and cells this
    /// validator has proven, and its pre-cut content against the
    /// predecessors' answers.
    ///
    /// # Errors
    ///
    /// The first claim this validator refuses or cannot yet check.
    pub fn judge(&self, schedule: &TopologySchedule, block: &Block) -> Result<(), Withheld> {
        let anchored_wt = block.header().parent_qc().weighted_timestamp();
        self.finalizations(schedule, block, anchored_wt)?;
        self.records(block)?;
        self.state_claims(block)?;
        self.precut(block)
    }

    /// The split-boundary fence over a block's finalizations.
    ///
    /// Each finalization's claims on its counterparts' settled sets —
    /// a settlement on every shard whose certificate it carries, an
    /// abandonment on every shard a local outcome awaited and never
    /// heard from — are the ones [`hyperscale_types::Finalization::claims`]
    /// derives, so a voter judges a tick by the rule its proposer's gate
    /// composed it under. Record coverage is read off the mirror the
    /// execution coordinator writes at the record's commit, so a replica
    /// that came up between the record and the abandonment holds the
    /// same answer its peers do.
    ///
    /// Past-terminal-ness is read off the **anchored** snapshot at
    /// `anchored_wt` (the block's `parent_qc` weighted timestamp), never
    /// the head, so every replica voting this block reaches the same
    /// verdict. A shard evicted from every retained window is so far past
    /// its terminal that any claim naming it is unreachable everywhere —
    /// refused. A past-terminal shard whose settled set isn't known yet
    /// defers the vote; past the set's evidence window the claim is
    /// categorically unprovable and refuses.
    ///
    /// # Errors
    ///
    /// A claim the sets contradict, or one no held set can answer.
    pub fn finalizations(
        &self,
        schedule: &TopologySchedule,
        block: &Block,
        anchored_wt: WeightedTimestamp,
    ) -> Result<(), Withheld> {
        let claims = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.claims(self.local_shard, |tx_hash| self.mirror.covers(tx_hash)));
        let verdict = self.mirror.with_settled(|settled| {
            settled_set_verdict(settled, schedule, self.local_shard, anchored_wt, claims)
        });
        match verdict {
            SettledSetVerdict::Pass => Ok(()),
            SettledSetVerdict::Reject => Err(Withheld::Refused(
                "finalization names a past-terminal shard that didn't settle it".into(),
            )),
            SettledSetVerdict::Defer => Err(Withheld::deferred(
                "settled set for a past-terminal shard unknown".into(),
            )),
        }
    }

    /// Whether the block's abandonment records are ones this voter can
    /// attest to.
    ///
    /// Each record is held to the departed shard's settled set. The
    /// figures each name restates are not this fence's to check: they
    /// are read off the committed body, which lives in the store, and so
    /// are checked by the delegated verification the vote also waits on.
    ///
    /// # Errors
    ///
    /// The first record whose evidence this validator contradicts or
    /// has not mirrored.
    pub fn records(&self, block: &Block) -> Result<(), Withheld> {
        block
            .abandonment_records()
            .iter()
            .try_for_each(|record| self.departure_stands(record))
    }

    /// Whether a departure record stands: this validator's own ledger
    /// says the departed shard was party to every name, and the shard's
    /// settled set names none of them. That the schedule attests the
    /// cut it names, inside the evidence window, is admission's rule.
    ///
    /// The set says what the departed shard settled; the ledger says
    /// what it was party to, and a record may name only that — a
    /// stranger to the departed shard is absent from its set trivially,
    /// and abandoning it would charge a payer for a transaction a live
    /// counterpart can still settle. The set is complete and
    /// beacon-attested, so absence from it is proof rather than
    /// ignorance; a voter that has not acquired it defers, since the
    /// record is only proposable inside the window the set can be read
    /// in, so a voter inside it either has the set or is about to.
    fn departure_stands(&self, record: &AbandonmentRecord) -> Result<(), Withheld> {
        let shard = record.shard();
        let stranger = self.mirror.with_parties(shard, |parties| {
            parties.map(|parties| {
                record
                    .tx_hashes()
                    .find(|tx_hash| !parties.contains(tx_hash))
            })
        });
        match stranger {
            None => {
                return Err(Withheld::deferred(format!(
                    "departure record's parties for {shard:?} not yet mirrored"
                )));
            }
            Some(Some(stranger)) => {
                return Err(Withheld::Refused(format!(
                    "abandonment record names {stranger}, which the departed shard {shard:?} \
                     was not party to"
                )));
            }
            Some(None) => {}
        }
        let settled = self.mirror.with_settled(|sets| {
            sets.get(&shard).map(|settled| {
                record
                    .tx_hashes()
                    .find(|tx_hash| settled.txs.contains(tx_hash))
            })
        });
        match settled {
            None => Err(Withheld::deferred(format!(
                "settled set of {shard:?} for an abandonment record unknown"
            ))),
            Some(Some(tx_hash)) => Err(Withheld::Refused(format!(
                "abandonment record names {tx_hash}, which its shard {shard:?} settled"
            ))),
            Some(None) => Ok(()),
        }
    }

    /// Whether the block's readings of counterparts' cells are ones this
    /// voter has taken for itself.
    ///
    /// A claim states what a counterpart's committed state said about a
    /// cell, and carries no proof of it. So it is held to this
    /// validator's own reading, twice over: the anchor against the
    /// commit-proven header held for that height, and each cell against
    /// what a multiproof this validator walked said of it. A reading
    /// that disagrees refuses the block for good — one of the two read a
    /// tree the other did not. A reading not taken defers, and asks for
    /// the proof that would take it.
    ///
    /// A reading not taken is the exception, since a probe anchors at
    /// the chain's committed clock: the members of a committee ask one
    /// counterpart the same question, at a header old enough that all
    /// of them hold it, so a voter has read the cell a block claims
    /// before the block arrives. What is left is the member whose own
    /// fetch has not landed. The recovery is a peer relaying the proof
    /// rather than the counterpart serving it again: the proposer holds
    /// those bytes by construction, and so does every member whose
    /// probe answered.
    ///
    /// Everything missing is asked for in one deferral — the commit
    /// proofs for anchors not held, and the relays for cells not read —
    /// so a block waits on one round trip rather than one per claim.
    ///
    /// # Errors
    ///
    /// A claim whose anchor or whose reading this validator contradicts,
    /// or everything it has yet to prove.
    pub fn state_claims(&self, block: &Block) -> Result<(), Withheld> {
        let mut wanted = Vec::new();
        let mut unread = 0usize;
        for claim in block.state_claims() {
            if self.anchor_stands(claim, &mut wanted)? {
                unread += self.cells_stand(claim, &mut wanted)?;
            }
        }
        if wanted.is_empty() {
            Ok(())
        } else {
            Err(Withheld::Deferred {
                why: format!(
                    "block claims {unread} cells this validator has not proven, at {} anchors it \
                     asks for",
                    wanted.len(),
                ),
                wanted,
            })
        }
    }

    /// Whether a claim's anchor is one this voter has commit-proven, and
    /// whether every term of it — the root and the clock — agrees with
    /// the header held for it. An anchor not held is asked for, and
    /// answers `false`: its cells are not readable until it is, since a
    /// reading is only ever taken against a root this validator proved.
    fn anchor_stands(
        &self,
        claim: &StateClaim,
        wanted: &mut Vec<Action>,
    ) -> Result<bool, Withheld> {
        let anchor = claim.anchor;
        match self.proven_anchors.at(anchor.shard, anchor.height) {
            Some(held) if held == anchor => Ok(true),
            Some(held) => Err(Withheld::Refused(format!(
                "state claim names an anchor of {:?} at height {} (root {:?}, clock {:?}) this \
                 validator's commit-proven header disagrees with (root {:?}, clock {:?})",
                anchor.shard,
                anchor.height.inner(),
                anchor.state_root,
                anchor.ts,
                held.state_root,
                held.ts,
            ))),
            None => {
                wanted.push(Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard: anchor.shard,
                    block_height: anchor.height,
                }));
                Ok(false)
            }
        }
    }

    /// Whether every cell a claim reads stands against this validator's
    /// own reading of it, returning how many it has not read.
    ///
    /// The unread ones are asked for together, as one relay of the whole
    /// claim: they were proven together on the proposer, so one proof
    /// answers all of them and asking cell by cell would fetch the same
    /// bytes repeatedly.
    fn cells_stand(&self, claim: &StateClaim, wanted: &mut Vec<Action>) -> Result<usize, Withheld> {
        let mut unread = Vec::new();
        for &(key, stated) in &claim.cells {
            match self.proven_cells.reading(claim.anchor, key) {
                Some(mine) if mine == stated => {}
                Some(mine) => {
                    return Err(Withheld::Refused(format!(
                        "state claim reads {key:?} of {:?} at height {} as {stated:?}, which this \
                         validator proved to be {mine:?}",
                        claim.anchor.shard,
                        claim.anchor.height.inner(),
                    )));
                }
                None => unread.push(key),
            }
        }
        let count = unread.len();
        if !unread.is_empty() {
            wanted.push(Action::Fetch(FetchRequest::RelayedStateProof {
                anchor: claim.anchor,
                keys: unread,
                shard: self.local_shard,
                preferred: None,
                class: None,
            }));
        }
        Ok(count)
    }

    /// Which of `block`'s transactions belong to the chain that ran
    /// before this one: those whose validity window opened before the
    /// cut. A certificate anchored before the cut is admission's to
    /// refuse; a transaction is different, since the hazard is only what
    /// the predecessor actually *committed*. One submitted before the
    /// cut and never committed is harmless, and landing it here is its
    /// first inclusion. Refusing the whole class is the safe default a
    /// successor runs under until it can ask the finer question, and the
    /// predecessors' answers are what narrow it: per predecessor, each
    /// absence proven against a `committed_txs_root` this chain
    /// commit-proved.
    ///
    /// Unresolved defers rather than refuses. Every honest validator
    /// reaches the same verdict once the answer lands, so a slow answer
    /// costs a wait; refusing would spend a round on it instead and make
    /// the block look bad rather than early. A proven replay refuses the
    /// block whatever else is outstanding, so the scan runs to the end
    /// rather than deferring on the first unresolved transaction it
    /// meets.
    ///
    /// Provisions are left out. A batch carries its *source* shard's
    /// weighted timestamp where the cut is in this chain's, so a rule
    /// written on that comparison would refuse honest batches near the
    /// boundary — and a pre-cut batch can only provision transactions the
    /// rule above already refuses, so it is inert here.
    ///
    /// # Errors
    ///
    /// A transaction a predecessor committed, or one no predecessor has
    /// answered for yet.
    pub fn precut(&self, block: &Block) -> Result<(), Withheld> {
        let mut deferred = None;
        for tx in block
            .transactions()
            .iter()
            .filter(|tx| tx.validity_range().start_timestamp_inclusive < self.cut)
        {
            match self.precut.status(&tx.hash()) {
                PrecutStatus::Absent => {}
                PrecutStatus::Committed => {
                    return Err(Withheld::Refused(format!(
                        "transaction {} predates this chain's origin and a predecessor \
                         committed it",
                        tx.hash()
                    )));
                }
                PrecutStatus::Unresolved => deferred = Some(tx.hash()),
            }
        }
        deferred.map_or(Ok(()), |tx_hash| {
            Err(Withheld::deferred(format!(
                "pre-cut transaction {tx_hash} unresolved against the predecessors"
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Anchor, BlockHeader, BlockHeaderParts, BlockHeight, Hash, Inclusion, LeafRoot, StateClaim,
        StateClaimsRoot, StateRoot, SubstateKey, WitnessSources,
    };

    use super::*;

    /// The counterpart every claim in these tests reads.
    const COUNTERPART: ShardId = ShardId::ROOT;
    /// The shard the fence votes on.
    const LOCAL: ShardId = ShardId::leaf(1, 1);
    /// A value hash, for the readings that are presences.
    const PRESENT: Inclusion = Inclusion::Present([7u8; 32]);

    fn anchor_at(seed: &[u8], height: u64) -> Anchor {
        Anchor {
            shard: COUNTERPART,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::from_bytes(seed)),
            ts: WeightedTimestamp::from_millis(height * 1_000),
        }
    }

    /// A block whose only content is `claims`.
    fn block_claiming(claims: Vec<StateClaim>) -> Block {
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: LOCAL,
                height: BlockHeight::new(6),
                state_claims_root: StateClaimsRoot::over(&claims),
                provision_tx_roots: BTreeMap::new(),
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(claims),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// The evidence one validator holds, and the fence over it.
    struct Held {
        mirror: CounterpartMirror,
        proven_anchors: ProvenAnchors,
        proven_cells: ProvenCells,
        precut: Precut,
    }

    impl Held {
        fn nothing() -> Self {
            Self {
                mirror: CounterpartMirror::new(),
                proven_anchors: ProvenAnchors::new(),
                proven_cells: ProvenCells::new(),
                precut: Precut::default(),
            }
        }

        /// This validator has commit-proven `anchor` and read `cells`
        /// against it.
        fn proved(
            self,
            anchor: Anchor,
            cells: impl IntoIterator<Item = (SubstateKey, Inclusion)>,
        ) -> Self {
            self.proven_anchors.record(anchor);
            self.proven_cells.proven(anchor, cells);
            self
        }

        fn judge(&self, block: &Block) -> Result<(), Withheld> {
            VoteFence {
                mirror: &self.mirror,
                proven_anchors: &self.proven_anchors,
                proven_cells: &self.proven_cells,
                precut: &self.precut,
                cut: WeightedTimestamp::ZERO,
                local_shard: LOCAL,
            }
            .state_claims(block)
        }
    }

    /// A claim reading exactly what this validator proved passes, and
    /// asks for nothing.
    #[test]
    fn a_claim_this_validator_proved_for_itself_stands() {
        let (present, absent) = (test_key(1), test_key(2));
        let anchor = anchor_at(b"root", 4);
        let readings = [(present, PRESENT), (absent, Inclusion::Absent)];
        let held = Held::nothing().proved(anchor, readings);

        let block = block_claiming(vec![StateClaim::new(anchor, readings)]);
        assert!(held.judge(&block).is_ok());
    }

    /// A claim that reads a cell the other way is refused for good: one
    /// of the two walked a tree the other did not, and no evidence
    /// arriving later reconciles that.
    #[test]
    fn a_claim_this_validator_reads_the_other_way_is_refused() {
        let key = test_key(1);
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing().proved(anchor, [(key, PRESENT)]);

        let block = block_claiming(vec![StateClaim::new(anchor, [(key, Inclusion::Absent)])]);
        let Withheld::Refused(why) = held.judge(&block).expect_err("the reading contradicts")
        else {
            panic!("a contradicted reading refuses rather than defers");
        };
        assert!(why.contains("this validator proved"), "{why}");
    }

    /// A cell this validator has not proven defers, and the deferral
    /// asks a committee peer to relay the proof — every unread cell of
    /// one claim in a single ask, since one proof answers them all.
    #[test]
    fn a_cell_this_validator_has_not_proven_defers_and_asks_a_peer() {
        let (first, second) = (test_key(1), test_key(2));
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing().proved(anchor, []);

        let block = block_claiming(vec![StateClaim::new(
            anchor,
            [(first, Inclusion::Absent), (second, Inclusion::Absent)],
        )]);
        let Withheld::Deferred { wanted, .. } = held.judge(&block).expect_err("nothing is proven")
        else {
            panic!("an unproven reading defers rather than refusing");
        };
        match wanted.as_slice() {
            [
                Action::Fetch(FetchRequest::RelayedStateProof {
                    anchor: at,
                    keys,
                    shard,
                    ..
                }),
            ] => {
                assert_eq!(*at, anchor);
                assert_eq!(keys, &[first, second]);
                assert_eq!(*shard, LOCAL, "asked of this shard's own committee");
            }
            other => panic!("expected one relay for the claim, got {other:?}"),
        }
    }

    /// An anchor this validator has not commit-proven asks for the
    /// commit proof and nothing else: a reading is only ever taken
    /// against a root this validator proved, so there is no cell to
    /// relay until the anchor stands.
    #[test]
    fn an_unproven_anchor_asks_for_its_commit_proof_alone() {
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing();

        let block = block_claiming(vec![StateClaim::new(
            anchor,
            [(test_key(1), Inclusion::Absent)],
        )]);
        let Withheld::Deferred { wanted, .. } =
            held.judge(&block).expect_err("the anchor is not proven")
        else {
            panic!("an unproven anchor defers");
        };
        assert!(matches!(
            wanted.as_slice(),
            [Action::Continuation(
                ProtocolEvent::CommitProofNeeded { .. }
            )]
        ));
    }

    /// An anchor whose root this validator's own proven header
    /// disagrees with is refused before any cell is read.
    #[test]
    fn an_anchor_naming_another_root_is_refused() {
        let key = test_key(1);
        let held = Held::nothing().proved(anchor_at(b"fork", 4), [(key, PRESENT)]);

        let block = block_claiming(vec![StateClaim::new(
            anchor_at(b"root", 4),
            [(key, PRESENT)],
        )]);
        assert!(matches!(
            held.judge(&block)
                .expect_err("the anchor is another chain's"),
            Withheld::Refused(_)
        ));
    }

    /// Everything outstanding is asked for at once, so a block waits on
    /// one round trip rather than one per claim.
    #[test]
    fn one_deferral_asks_for_everything_outstanding() {
        let (first, second) = (test_key(1), test_key(2));
        let (proven, unproven) = (anchor_at(b"root", 4), anchor_at(b"root", 9));
        let held = Held::nothing().proved(proven, []);

        let block = block_claiming(vec![
            StateClaim::new(proven, [(first, Inclusion::Absent)]),
            StateClaim::new(unproven, [(second, Inclusion::Absent)]),
        ]);
        let Withheld::Deferred { wanted, .. } =
            held.judge(&block).expect_err("neither is checkable")
        else {
            panic!("both are questions of absent evidence");
        };
        assert_eq!(
            wanted.len(),
            2,
            "one relay and one commit proof: {wanted:?}"
        );
    }

    /// A refusal wins over a deferral: a block carrying one claim this
    /// validator contradicts never gets the vote, whatever else it also
    /// leaves unanswered.
    #[test]
    fn a_contradicted_claim_refuses_a_block_that_also_defers() {
        let (contradicted, unread) = (test_key(1), test_key(2));
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing().proved(anchor, [(contradicted, PRESENT)]);

        let block = block_claiming(vec![StateClaim::new(
            anchor,
            [
                (contradicted, Inclusion::Absent),
                (unread, Inclusion::Absent),
            ],
        )]);
        assert!(matches!(
            held.judge(&block).expect_err("the contradiction decides"),
            Withheld::Refused(_)
        ));
    }
}
