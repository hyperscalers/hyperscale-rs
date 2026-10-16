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
//! commit-proven, what the predecessors answered — or the schedule the
//! beacon publishes, which says which anchors are boundaries it
//! recorded. So a block passes here exactly when the composer that
//! offered its content would have offered it against the same evidence.
//! What a state claim reads of a cell is not the fence's question: the
//! claim carries its proof, and admission walks it from the block alone.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    AbandonmentRecord, Anchor, Block, BoundaryAttestation, CounterpartMirror, ProvenAnchors,
    ShardId, StateClaim, TopologySchedule, WeightedTimestamp,
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
    pub(crate) const fn deferred(why: String) -> Self {
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
    /// evidence answers: its records against the settled sets, its state
    /// claims' anchors against the headers this validator has
    /// commit-proven, and its pre-cut content against the predecessors'
    /// answers. What its finalizations settle is held to the member rows
    /// they name, which the block's own claims are folded into, alongside
    /// its tick lines.
    ///
    /// # Errors
    ///
    /// The first claim this validator refuses or cannot yet check.
    pub(crate) fn judge(&self, schedule: &TopologySchedule, block: &Block) -> Result<(), Withheld> {
        self.records(block)?;
        self.state_claims(schedule, block)?;
        self.precut(block)
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
    /// settled set names none of the record's names, nor the transaction
    /// behind any crossing it names. That the schedule
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

    /// Whether every anchor the block's state claims read against is
    /// one this voter can attest to: a header it has commit-proven, or,
    /// for a boundary claim, a boundary its schedule records.
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
    /// A boundary claim, which the block's own anchor tells from a
    /// fresh one ([`StateClaim::at_boundary`]), is held to the schedule
    /// in place of the headers: its anchor is too old for any header
    /// this voter still holds, and what makes its reading final is that
    /// the beacon recorded the anchor as its shard's boundary.
    ///
    /// # Errors
    ///
    /// A claim whose anchor this validator contradicts, or every anchor
    /// it has yet to prove or to fold.
    pub(crate) fn state_claims(
        &self,
        schedule: &TopologySchedule,
        block: &Block,
    ) -> Result<(), Withheld> {
        let block_anchor = block.header().parent_qc().weighted_timestamp();
        let mut wanted = Vec::new();
        let mut unfolded = 0usize;
        for claim in block.state_claims() {
            // A claim anchored at the block's own parent is this
            // chain's, which no commit-proven header of a counterpart
            // holds: the state-root verification re-reads it.
            if claim.anchor.shard == self.local_shard {
                continue;
            }
            if claim.at_boundary(block_anchor) {
                unfolded += usize::from(!Self::boundary_stands(schedule, &claim.anchor)?);
            } else {
                self.anchor_stands(claim, &mut wanted)?;
            }
        }
        if wanted.is_empty() && unfolded == 0 {
            Ok(())
        } else {
            Err(Withheld::Deferred {
                why: format!(
                    "block claims against {} anchors this validator has not commit-proven and \
                     {unfolded} boundaries its beacon has not folded",
                    wanted.len(),
                ),
                wanted,
            })
        }
    }

    /// Whether a boundary claim's anchor is a boundary this voter's
    /// schedule records for its shard: `true` where it stands, and
    /// `false` where the anchor sits above every boundary held for the
    /// shard's lineage, which is a boundary this voter's beacon may be
    /// one fold short of. The vote then waits for that fold, which
    /// re-drives it, and asks for nothing: no fetch brings a beacon
    /// block sooner.
    ///
    /// # Errors
    ///
    /// An anchor a held record contradicts, at its height with another
    /// root or clock, and one at or below a held boundary that no held
    /// record names: no fold to come records a boundary beneath one
    /// already recorded.
    fn boundary_stands(schedule: &TopologySchedule, anchor: &Anchor) -> Result<bool, Withheld> {
        match schedule.attests_boundary(anchor) {
            BoundaryAttestation::Stands => Ok(true),
            BoundaryAttestation::Unknown if schedule.above_held_boundaries(anchor) => Ok(false),
            BoundaryAttestation::Unknown => Err(Withheld::Refused(format!(
                "state claim names a boundary of {:?} at height {} that no schedule window \
                 this validator holds records as a boundary a claim may stand at",
                anchor.shard,
                anchor.height.inner(),
            ))),
            BoundaryAttestation::Contradicted => Err(Withheld::Refused(format!(
                "state claim names a boundary of {:?} at height {} (root {:?}, clock {:?}) \
                 the beacon recorded otherwise",
                anchor.shard,
                anchor.height.inner(),
                anchor.state_root,
                anchor.ts,
            ))),
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
    /// successor runs under until it knows which chains it succeeds. A
    /// left child and a merged parent then read every predecessor's
    /// markers in their own state, which the marker rule does at the
    /// parent view; a right child asks its parent's terminal state for
    /// each marker, by a proof against the root this chain commit-proved.
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
    /// A transaction the parent's terminal state marks committed, or one
    /// not yet answered for.
    pub(crate) fn precut(&self, block: &Block) -> Result<(), Withheld> {
        let mut deferred = None;
        for tx in block
            .transactions()
            .iter()
            .filter(|tx| tx.validity_range().start_timestamp_inclusive < self.cut)
        {
            match self
                .precut
                .status(tx.hash(), tx.validity_range().end_timestamp_exclusive)
            {
                PrecutStatus::Absent => {}
                PrecutStatus::Committed => {
                    return Err(Withheld::Refused(format!(
                        "transaction {} predates this chain's origin and its parent's \
                         terminal state holds its marker",
                        tx.hash()
                    )));
                }
                PrecutStatus::Unresolved => deferred = Some(tx.hash()),
            }
        }
        deferred.map_or(Ok(()), |tx_hash| {
            Err(Withheld::deferred(format!(
                "pre-cut transaction {tx_hash} unresolved against the parent's terminal"
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
        AggregateSignature, Anchor, BeaconWitnessLeafCount, BlockHash, BlockHeader,
        BlockHeaderParts, BlockHeight, Epoch, Hash, Inclusion, LeafRoot, MerkleInclusionProof,
        NetworkDefinition, QuorumCertificate, RETENTION_HORIZON, Round, SectionRoots, ShardAnchor,
        SignerBitfield, StateClaim, StateClaimsRoot, StateRoot, SubstateKey, TopologySnapshot,
        ValidatorSet, WitnessSources,
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
                body_root: SectionRoots {
                    state_claims: StateClaimsRoot::over(&claims),
                    ..SectionRoots::EMPTY
                }
                .root(),
                provision_tx_roots: Capped::default(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::new(claims).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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
            self.judge_under(&no_boundaries(), block)
        }

        fn judge_under(&self, schedule: &TopologySchedule, block: &Block) -> Result<(), Withheld> {
            VoteFence {
                mirror: &self.mirror,
                proven_anchors: &self.proven_anchors,
                precut: &self.precut,
                cut: WeightedTimestamp::ZERO,
                local_shard: LOCAL,
            }
            .state_claims(schedule, block)
        }
    }

    /// A schedule recording no boundary for any shard.
    fn no_boundaries() -> TopologySchedule {
        recording(&[])
    }

    /// A schedule of one window whose head records each of `boundaries`
    /// for the counterpart, the newest last.
    fn recording(boundaries: &[Anchor]) -> TopologySchedule {
        let snapshot = |boundary: Option<&Anchor>| {
            let snapshot = TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(Vec::new()),
            );
            Arc::new(
                snapshot.with_boundaries(
                    boundary
                        .map(|anchor| {
                            (
                                anchor.shard,
                                ShardAnchor {
                                    state_root: anchor.state_root,
                                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
                                    height: anchor.height,
                                    weighted_timestamp: anchor.ts,
                                    witness_base: BeaconWitnessLeafCount::ZERO,
                                    terminal_settled_txs: None,
                                    handoff_complete: None,
                                    terminal_epoch: None,
                                },
                            )
                        })
                        .into_iter()
                        .collect(),
                ),
            )
        };
        let mut schedule = TopologySchedule::new(1_000_000, Epoch::GENESIS, snapshot(None));
        for (at, boundary) in boundaries.iter().enumerate() {
            schedule.insert(Epoch::new(at as u64 + 1), snapshot(Some(boundary)));
        }
        schedule.set_head(snapshot(boundaries.last()));
        schedule
    }

    /// A block anchored at `anchor_ms` whose only content is `claims`.
    fn block_claiming_at(anchor_ms: u64, claims: Vec<StateClaim>) -> Block {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            LOCAL,
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::new(5),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(anchor_ms),
        );
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: LOCAL,
                height: BlockHeight::new(6),
                parent_qc: parent_qc.into(),
                body_root: SectionRoots {
                    state_claims: StateClaimsRoot::over(&claims),
                    ..SectionRoots::EMPTY
                }
                .root(),
                provision_tx_roots: Capped::default(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::new(claims).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A boundary claim is held to the boundaries the voter's schedule
    /// records, and to no header. Where the schedule records its anchor
    /// the vote proceeds with no commit proof held. A voter behind the
    /// beacon, whose newest record for the shard sits below the anchor,
    /// defers and asks for nothing, and votes once it folds the record.
    /// An anchor at a recorded height with another root, or at a height
    /// no record names beneath one already recorded, is refused. The
    /// same anchor read fresh is the headers' to answer.
    #[test]
    fn a_voter_behind_the_beacon_defers_a_boundary_claim() {
        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        let older = anchor_at(b"older boundary", 40);
        let newer = anchor_at(b"newer boundary", 80);
        let block_ms = newer.ts.as_millis() + horizon_ms + 1;
        let reading = |anchor: Anchor| {
            block_claiming_at(
                block_ms,
                vec![claim(anchor, [(test_key(1), Inclusion::Absent)])],
            )
        };
        let held = Held::nothing();

        let behind = recording(&[older]);
        let Withheld::Deferred { wanted, .. } = held
            .judge_under(&behind, &reading(newer))
            .expect_err("the newer boundary is one this voter has yet to fold")
        else {
            panic!("a boundary above every record held defers");
        };
        assert!(wanted.is_empty(), "no fetch brings a beacon fold sooner");
        assert!(held.judge_under(&behind, &reading(older)).is_ok());

        let folded = recording(&[older, newer]);
        assert!(
            held.judge_under(&folded, &reading(newer)).is_ok(),
            "the fold that records the boundary lets the vote proceed",
        );
        assert!(
            held.judge_under(&folded, &reading(older)).is_ok(),
            "and an older boundary a held window still records stands",
        );

        let other_branch = Anchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"another branch")),
            ..newer
        };
        assert!(matches!(
            held.judge_under(&folded, &reading(other_branch)),
            Err(Withheld::Refused(_))
        ));
        let between = anchor_at(b"no boundary", 60);
        assert!(
            matches!(
                held.judge_under(&folded, &reading(between)),
                Err(Withheld::Refused(_))
            ),
            "an anchor beneath a recorded boundary is one no fold will record",
        );
        let ahead = anchor_at(b"not yet", 90);
        let block_ahead = block_claiming_at(
            ahead.ts.as_millis() + horizon_ms + 1,
            vec![claim(ahead, [(test_key(1), Inclusion::Absent)])],
        );
        assert!(matches!(
            held.judge_under(&folded, &block_ahead),
            Err(Withheld::Deferred { .. })
        ));

        // A millisecond younger, the claim is fresh, and the headers
        // answer for its anchor: held, it stands whatever the schedule
        // records.
        let fresh = block_claiming_at(
            newer.ts.as_millis() + horizon_ms,
            vec![claim(newer, [(test_key(1), Inclusion::Absent)])],
        );
        let Withheld::Deferred { wanted, .. } = held
            .judge_under(&behind, &fresh)
            .expect_err("the header is not held")
        else {
            panic!("an unproven anchor defers");
        };
        assert_eq!(wanted.len(), 1, "and asks for its commit proof");
        assert!(
            Held::nothing()
                .proved(newer)
                .judge_under(&behind, &fresh)
                .is_ok()
        );
    }

    /// A claim is held to the headers up to the horizon and to the
    /// schedule a millisecond past it, whatever header this voter holds
    /// for its anchor. Commit-proven and fresh, it passes. Aged past the
    /// horizon at an anchor no schedule records, it is deferred with no
    /// header asked for, or refused once a newer boundary of its shard
    /// is held; at an anchor the schedule records, it passes. So a
    /// proposer carries past the horizon only what its schedule records.
    #[test]
    fn a_claim_aged_past_the_horizon_is_held_to_the_schedule_whatever_header_is_held() {
        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        let read = anchor_at(b"a header this voter holds", 80);
        let held = Held::nothing().proved(read);
        let reading = || vec![claim(read, [(test_key(1), Inclusion::Absent)])];
        let fresh = block_claiming_at(read.ts.as_millis() + horizon_ms, reading());
        assert!(held.judge(&fresh).is_ok());
        let aged = block_claiming_at(read.ts.as_millis() + horizon_ms + 1, reading());
        let Err(Withheld::Deferred { wanted, .. }) = held.judge(&aged) else {
            panic!("an anchor above every boundary held defers");
        };
        assert!(wanted.is_empty(), "and no header is asked for");
        let newer = anchor_at(b"a boundary recorded since", 90);
        assert!(matches!(
            held.judge_under(&recording(&[newer]), &aged),
            Err(Withheld::Refused(_))
        ));
        assert!(held.judge_under(&recording(&[read]), &aged).is_ok());
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

    /// A right child's vote on a pre-cut transaction reads its parent's
    /// terminal state: an unanswered marker defers, a present one
    /// refuses, an absent one passes. A left child's vote passes it on
    /// to the marker rule, which reads the parent's markers in its own
    /// state.
    #[test]
    fn a_right_childs_vote_reads_its_parents_terminal() {
        use hyperscale_storage::committed_tx_cell_key;
        use hyperscale_types::test_utils::{
            install_stub_protocol_statics, make_live_block, stub_transaction, test_prefix,
            test_principal,
        };
        use hyperscale_types::{TimestampRange, ValidatorId};

        install_stub_protocol_statics();
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let terminal = Anchor {
            shard: parent,
            height: BlockHeight::new(9),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(1_000),
        };
        let validity = TimestampRange::new(
            WeightedTimestamp::from_millis(500),
            WeightedTimestamp::from_millis(60_000),
        );
        let tx = Arc::new(stub_transaction(
            test_principal(1),
            &[test_prefix(1)],
            1_000,
            validity,
        ));
        let marker = committed_tx_cell_key(parent, tx.hash(), validity.end_timestamp_exclusive);
        let block = make_live_block(
            right,
            BlockHeight::new(11),
            2_000,
            ValidatorId::new(1),
            vec![tx],
            vec![],
        );
        let (mirror, proven_anchors) = (CounterpartMirror::new(), ProvenAnchors::new());
        let judge = |precut: &Precut, local_shard: ShardId| {
            VoteFence {
                mirror: &mirror,
                proven_anchors: &proven_anchors,
                precut,
                cut: terminal.ts,
                local_shard,
            }
            .precut(&block)
        };

        let mut asking = Precut::adopted(right, &[terminal]);
        assert!(matches!(
            judge(&asking, right),
            Err(Withheld::Deferred { .. })
        ));
        asking.record(terminal, marker, true);
        assert!(matches!(judge(&asking, right), Err(Withheld::Refused(_))));
        let mut absent = Precut::adopted(right, &[terminal]);
        absent.record(terminal, marker, false);
        assert!(judge(&absent, right).is_ok());

        assert!(judge(&Precut::adopted(left, &[terminal]), left).is_ok());
    }

    /// An abandonment record stands only on the departed shard's settled
    /// set: a voter without the set defers, one whose set names a
    /// transaction the record names refuses, and one whose set names none
    /// of them votes. No certificate of the departed shard enters.
    #[test]
    fn an_abandonment_record_is_held_to_the_settled_set() {
        use std::collections::BTreeSet;

        use hyperscale_types::{
            AbortCharge, Address, AddressClass, CommittedAt, Deadline, LocalKey, RoutePrefix,
            SettledTxSet, TxHash, UnsettledTx,
        };

        let departed = ShardId::leaf(1, 0);
        let terminal_wt = WeightedTimestamp::from_millis(9_000);
        let named = TxHash::from(Hash::from_bytes(b"named"));
        let other = TxHash::from(Hash::from_bytes(b"other"));
        let record = AbandonmentRecord::new(
            departed,
            terminal_wt,
            [UnsettledTx {
                tx_hash: named,
                deadline: Deadline::of(WeightedTimestamp::from_millis(8_000)),
                charged: 1,
                charge: AbortCharge {
                    vault: SubstateKey {
                        owner: Address::new([0x11; 31], AddressClass::Component),
                        local: LocalKey([0x22; 16]),
                    },
                    amount: 1,
                },
                committed: CommittedAt {
                    height: BlockHeight::new(3),
                    anchor: WeightedTimestamp::from_millis(3_000),
                    committee_anchor: WeightedTimestamp::from_millis(2_000),
                },
                reach: Capped::from_array([RoutePrefix::of(Address::new(
                    [0x33; 31],
                    AddressClass::Principal,
                ))]),
            }],
        );
        let stands = |settled: Option<BTreeSet<TxHash>>| {
            let held = Held::nothing();
            if let Some(txs) = settled {
                held.mirror
                    .record_settled(departed, SettledTxSet { txs, terminal_wt });
            }
            VoteFence {
                mirror: &held.mirror,
                proven_anchors: &held.proven_anchors,
                precut: &held.precut,
                cut: WeightedTimestamp::ZERO,
                local_shard: LOCAL,
            }
            .record_stands(&record)
        };

        assert!(
            matches!(stands(None), Err(Withheld::Deferred { .. })),
            "a voter without the departed shard's set defers",
        );
        assert!(
            matches!(
                stands(Some(BTreeSet::from([named]))),
                Err(Withheld::Refused(_))
            ),
            "a record naming a transaction its shard settled is refused",
        );
        assert!(
            stands(Some(BTreeSet::from([other]))).is_ok(),
            "a record naming nothing its shard settled stands",
        );
    }
}
