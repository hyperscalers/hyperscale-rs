//! The vote fence: what this validator's own evidence says about the
//! claims a block makes on other chains.
//!
//! A block's content rules are deterministic over the block and the
//! committed chain, and every replica reaches the same verdict on them.
//! The fence is the other kind of check: a block claims that a departed
//! shard left a transaction unsettled, that a counterpart's header at a
//! height carries a root, that a predecessor never committed a
//! transaction — and a validator can only hold those claims to what it
//! has itself mirrored. So the fence has three answers rather than two.
//! A claim the evidence contradicts refuses the vote for good; a claim
//! the evidence cannot yet answer withholds it, and names what would
//! let it answer; and a block making no claim this validator cannot
//! attest to passes.
//!
//! Everything the fence reads is a mirror shared with the execution
//! coordinator — the departed shards' settled sets, which anchors are
//! commit-proven, what the predecessors answered — so a block passes
//! here exactly when the composer that offered its content would have
//! offered it against the same mirror. What a state claim reads of a
//! cell is not the fence's question: the claim carries its proof, and
//! admission walks it from the block alone.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    AbandonmentRecord, Block, CounterpartMirror, ProvenAnchors, SettledSetVerdict, ShardId,
    StateClaim, TopologySchedule, WeightedTimestamp, settled_set_verdict,
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
    /// The departed shards' settled sets, and what committed records
    /// cover.
    pub(crate) mirror: &'a CounterpartMirror,
    /// The commit-proven remote headers.
    pub(crate) proven_anchors: &'a ProvenAnchors,
    /// The predecessors' answers about transactions opening before the
    /// chain's origin.
    pub(crate) precut: &'a Precut,
    /// Where this chain began; content anchored before it belongs to a
    /// predecessor.
    pub(crate) cut: WeightedTimestamp,
    /// The shard this validator votes on.
    pub(crate) local_shard: ShardId,
}

impl VoteFence<'_> {
    /// Judge every claim `block` makes, in the order the cheapest
    /// evidence answers: its finalizations and its records against the
    /// settled sets, its state claims' anchors against the headers this
    /// validator has commit-proven, and its pre-cut content against the
    /// predecessors' answers.
    ///
    /// # Errors
    ///
    /// The first claim this validator refuses or cannot yet check.
    pub(crate) fn judge(&self, schedule: &TopologySchedule, block: &Block) -> Result<(), Withheld> {
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
    pub(crate) fn finalizations(
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
            .try_for_each(|record| self.record_stands(record))
    }

    /// Whether an abandonment record stands: the departed shard's
    /// settled set names none of the record's names. That the schedule
    /// attests the cut it names, inside the evidence window, and that
    /// the departed shard was party to every name, are admission's
    /// rules.
    ///
    /// The set is complete and beacon-attested, so absence from it is
    /// proof rather than ignorance; a voter that has not acquired it
    /// defers, since the record is only proposable inside the window the
    /// set can be read in, so a voter inside it either has the set or is
    /// about to.
    fn record_stands(&self, record: &AbandonmentRecord) -> Result<(), Withheld> {
        let shard = record.shard();
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

    /// Whether every anchor the block's state claims read against is a
    /// header this voter has commit-proven.
    ///
    /// A claim carries its proof, and admission has already walked it
    /// under the anchor's root, so what is left to this voter is the
    /// anchor itself: the root and the clock the claim names must be
    /// the ones of the header held for that height. A disagreeing
    /// anchor refuses the block for good — the reading was taken
    /// against a root this chain never committed, or dated to a clock
    /// it never carried. An anchor not held defers, and asks for the
    /// commit proof that would let it answer.
    ///
    /// A missing anchor is the exception, since a probe anchors at the
    /// chain's committed clock: the members of a committee ask one
    /// counterpart the same question, at a header old enough that all
    /// of them hold it. Every missing anchor is asked for in one
    /// deferral, so a block waits on one round trip rather than one per
    /// claim.
    ///
    /// # Errors
    ///
    /// A claim whose anchor this validator contradicts, or every anchor
    /// it has yet to prove.
    pub(crate) fn state_claims(&self, block: &Block) -> Result<(), Withheld> {
        let mut wanted = Vec::new();
        for claim in block.state_claims() {
            // A claim anchored at the block's own parent is this
            // chain's, which no commit-proven header of a counterpart
            // holds: the state-root verification re-reads it.
            if claim.anchor.shard == self.local_shard {
                continue;
            }
            self.anchor_stands(claim, &mut wanted)?;
        }
        if wanted.is_empty() {
            Ok(())
        } else {
            Err(Withheld::Deferred {
                why: format!(
                    "block claims against {} anchors this validator has not commit-proven",
                    wanted.len(),
                ),
                wanted,
            })
        }
    }

    /// Whether a claim's anchor is one this voter has commit-proven, and
    /// whether every term of it — the root and the clock — agrees with
    /// the header held for it. An anchor not held is asked for.
    fn anchor_stands(&self, claim: &StateClaim, wanted: &mut Vec<Action>) -> Result<(), Withheld> {
        let anchor = claim.anchor;
        match self.proven_anchors.at(anchor.shard, anchor.height) {
            Some(held) if held == anchor => Ok(()),
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
                Ok(())
            }
        }
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
    pub(crate) fn precut(&self, block: &Block) -> Result<(), Withheld> {
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

    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Anchor, BlockHeader, BlockHeaderParts, BlockHeight, Hash, Inclusion, LeafRoot,
        MerkleInclusionProof, StateClaim, StateClaimsRoot, StateRoot, SubstateKey, WitnessSources,
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

    /// A claim at `anchor` over `cells`. The fence reads no proof, so
    /// the claim carries none worth walking.
    fn claim(
        anchor: Anchor,
        cells: impl IntoIterator<Item = (SubstateKey, Inclusion)>,
    ) -> StateClaim {
        StateClaim::new(anchor, cells, MerkleInclusionProof::dummy())
    }

    /// A block whose only content is `claims`.
    fn block_claiming(claims: Vec<StateClaim>) -> Block {
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: LOCAL,
                height: BlockHeight::new(6),
                state_claims_root: StateClaimsRoot::over(&claims),
                provision_tx_roots: Capped::default(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::new(claims).expect("a list written out in a test")),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// The evidence one validator holds, and the fence over it.
    struct Held {
        mirror: CounterpartMirror,
        proven_anchors: ProvenAnchors,
        precut: Precut,
    }

    impl Held {
        fn nothing() -> Self {
            Self {
                mirror: CounterpartMirror::new(),
                proven_anchors: ProvenAnchors::new(),
                precut: Precut::default(),
            }
        }

        /// This validator has commit-proven `anchor`.
        fn proved(self, anchor: Anchor) -> Self {
            self.proven_anchors.record(anchor);
            self
        }

        fn judge(&self, block: &Block) -> Result<(), Withheld> {
            VoteFence {
                mirror: &self.mirror,
                proven_anchors: &self.proven_anchors,
                precut: &self.precut,
                cut: WeightedTimestamp::ZERO,
                local_shard: LOCAL,
            }
            .state_claims(block)
        }
    }

    /// A claim at an anchor this validator commit-proved passes with no
    /// fetch of any cell: nothing here reads what the claim says of a
    /// cell, since the claim proves that itself.
    #[test]
    fn a_claim_at_a_held_anchor_stands_with_no_cell_fetched() {
        let (present, absent) = (test_key(1), test_key(2));
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing().proved(anchor);

        let block = block_claiming(vec![claim(
            anchor,
            [(present, PRESENT), (absent, Inclusion::Absent)],
        )]);
        assert!(held.judge(&block).is_ok());
    }

    /// A voter that has fetched nothing of its own votes on a block of
    /// claims at anchors it holds, with no deferral: what it came up
    /// holding after a restart is the headers, and that is all the
    /// fence asks of it.
    #[test]
    fn a_voter_with_no_fetches_of_its_own_votes_on_held_anchors() {
        let (first, second, third) = (test_key(1), test_key(2), test_key(3));
        let (older, newer) = (anchor_at(b"root", 4), anchor_at(b"root", 9));
        let held = Held::nothing().proved(older).proved(newer);

        let block = block_claiming(vec![
            claim(older, [(first, Inclusion::Absent)]),
            claim(older, [(second, PRESENT)]),
            claim(newer, [(third, Inclusion::Absent)]),
        ]);
        assert!(held.judge(&block).is_ok());
    }

    /// An anchor this validator has not commit-proven asks for the
    /// commit proof and nothing else: there is no cell to fetch, since
    /// the claim carries the proof of its readings.
    #[test]
    fn an_unproven_anchor_asks_for_its_commit_proof_alone() {
        let anchor = anchor_at(b"root", 4);
        let held = Held::nothing();

        let block = block_claiming(vec![claim(anchor, [(test_key(1), Inclusion::Absent)])]);
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
    /// disagrees with is refused.
    #[test]
    fn an_anchor_naming_another_root_is_refused() {
        let key = test_key(1);
        let held = Held::nothing().proved(anchor_at(b"fork", 4));

        let block = block_claiming(vec![claim(anchor_at(b"root", 4), [(key, PRESENT)])]);
        assert!(matches!(
            held.judge(&block)
                .expect_err("the anchor is another chain's"),
            Withheld::Refused(_)
        ));
    }

    /// Every missing anchor is asked for at once, so a block waits on
    /// one round trip rather than one per claim.
    #[test]
    fn one_deferral_asks_for_every_unproven_anchor() {
        let (first, second, third) = (test_key(1), test_key(2), test_key(3));
        let (proven, unproven, other) = (
            anchor_at(b"root", 4),
            anchor_at(b"root", 9),
            anchor_at(b"root", 12),
        );
        let held = Held::nothing().proved(proven);

        let block = block_claiming(vec![
            claim(proven, [(first, Inclusion::Absent)]),
            claim(unproven, [(second, Inclusion::Absent)]),
            claim(other, [(third, Inclusion::Absent)]),
        ]);
        let Withheld::Deferred { wanted, .. } =
            held.judge(&block).expect_err("two anchors are not held")
        else {
            panic!("both are questions of absent evidence");
        };
        assert_eq!(
            wanted.len(),
            2,
            "one commit proof per missing anchor: {wanted:?}"
        );
    }

    /// A refusal wins over a deferral: a block carrying one claim this
    /// validator contradicts never gets the vote, whatever else it also
    /// leaves unanswered.
    #[test]
    fn a_contradicted_anchor_refuses_a_block_that_also_defers() {
        let (first, second) = (test_key(1), test_key(2));
        let held = Held::nothing().proved(anchor_at(b"fork", 4));

        let block = block_claiming(vec![
            claim(anchor_at(b"root", 4), [(first, Inclusion::Absent)]),
            claim(anchor_at(b"root", 9), [(second, Inclusion::Absent)]),
        ]);
        assert!(matches!(
            held.judge(&block).expect_err("the contradiction decides"),
            Withheld::Refused(_)
        ));
    }
}
