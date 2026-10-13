//! The split-boundary settled-set predicate.
//!
//! When a shard `P` splits, its chain terminates at a terminal block `B`.
//! A cross-shard transaction's `P`-half settles only if `P` committed the
//! certificate covering it by `B` — otherwise one side of the transaction
//! would apply without the other. `S_P` is the set of transactions `P`
//! settled by `B`; a surviving counterpart reconstructs it from `P`'s tail
//! chain.
//!
//! This module holds the shared predicate both sides apply: the shard
//! coordinator's pre-vote fence (a block carrying such a transaction votes
//! only if every past-terminal outcome is settled) and the execution
//! coordinator's finalize-hygiene gate (don't even produce a finalization
//! the fence would reject). Keeping one predicate keeps the two verdicts
//! from drifting — a disagreement would let a gate produce what the fence
//! rejects.

use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;

use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    Block, BlockHash, BlockHeader, BlockHeight, LeafRoot, SectionRoots, SettledTxsRoot, ShardId,
    TickLine, TickManifest, TickManifestRoot, TopologySchedule, TxHash, WeightedTimestamp,
    WindowLookup,
};

/// What a survivor needs to acquire a departed shard's settled set: the
/// terminal to ask for and the root the answer must recompute to.
///
/// Every field is read off the node's own beacon fold — the terminal
/// anchor's height, hash and attested root from the boundary record, the
/// cut from the schedule's window grid — so nothing here is fetched and
/// nothing here is trusted. It is the key the acquisition is tracked
/// under: a revised terminal is a different key, and how long the answer
/// stays wanted is decided by whoever derives the wanted set, not
/// stamped here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalEvidence {
    /// The departed shard.
    pub shard: ShardId,
    /// Height of the departed shard's terminal block, naming the window
    /// end the serve reconstructs from.
    pub height: BlockHeight,
    /// Hash of the terminal block — which terminal this targets, so a
    /// revised one replaces rather than duplicates.
    pub block_hash: BlockHash,
    /// The terminal cut's weighted timestamp.
    pub terminal_wt: WeightedTimestamp,
    /// The beacon-attested `settled_txs_root` a fetched list must
    /// recompute to.
    pub attested_root: SettledTxsRoot,
}

/// A departed shard's terminal block as far as its tick manifest: the
/// header, the root of each body section, and the manifest's lines.
///
/// The header binds the lines through its body root, so a holder of the
/// terminal's block hash checks the three against each other and needs
/// no other section of the block. A terminal ends every accepted row it
/// still holds by a [`TickLine::End`] line, so the lines name every
/// transaction the departed shard had accepted and a sibling can still
/// ask about, and a transaction they do not name is one it left.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct TerminalLines {
    /// Carried whole because the boundary record names the terminal by
    /// its block hash alone, and the body root is read out of the header
    /// that hashes to it.
    pub header: BlockHeader,
    /// All nine, though only the manifest's is recomputed: the body root
    /// is one hash over them together, so none can be left out.
    pub roots: SectionRoots,
    /// Every line and in block order, since the root is over the lines
    /// as the block lists them; the end lines alone would not recompute
    /// it.
    pub manifest: TickManifest,
}

/// Why a served [`TerminalLines`] is not the terminal its evidence
/// names.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum UnboundLines {
    /// The header is not the terminal block's.
    #[error("the header does not hash to the terminal block")]
    Header,
    /// The section roots are not the ones the header commits.
    #[error("the section roots do not combine to the header's body root")]
    Roots,
    /// The lines are not the manifest the section roots commit.
    #[error("the lines do not recompute the manifest root")]
    Manifest,
}

impl UnboundLines {
    /// Metrics label for the failure.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Header => "terminal_header_mismatch",
            Self::Roots => "terminal_body_root_mismatch",
            Self::Manifest => "terminal_manifest_root_mismatch",
        }
    }
}

impl TerminalLines {
    /// The lines of `block` with what binds them to its header.
    #[must_use]
    pub fn of(block: &Block) -> Self {
        Self {
            header: block.header().clone(),
            roots: SectionRoots::of(block),
            manifest: block.tick_manifest().clone(),
        }
    }

    /// The transactions the terminal `evidence` names ended, taken only
    /// where the lines are that terminal's own: the header hashes to the
    /// evidence's block, the section roots combine to the header's body
    /// root, and the lines recompute the manifest root among them.
    ///
    /// The manifest root commits every line in order, so a server can
    /// neither drop an end line nor add one.
    ///
    /// # Errors
    ///
    /// The first [`UnboundLines`] link that does not hold.
    pub fn ended_under(
        &self,
        evidence: &TerminalEvidence,
    ) -> Result<BTreeSet<TxHash>, UnboundLines> {
        if self.header.hash() != evidence.block_hash {
            return Err(UnboundLines::Header);
        }
        if self.roots.root() != self.header.body_root() {
            return Err(UnboundLines::Roots);
        }
        if TickManifestRoot::over(&self.manifest) != self.roots.tick_manifest {
            return Err(UnboundLines::Manifest);
        }
        Ok(self
            .manifest
            .iter()
            .filter_map(|line| match line {
                TickLine::End { tx } => Some(*tx),
                _ => None,
            })
            .collect())
    }
}

/// A terminated shard's settled-transaction set.
///
/// `txs` are the **cross-shard** transactions whose certificate committed
/// in its chain at or before its terminal block — the only ones a
/// counterpart fence ever queries. `terminal_wt` is the weighted timestamp
/// at which the shard terminated. How long the set stays readable is not
/// carried here: the evidence window is derived from the schedule at each
/// judgment ([`TopologySchedule::terminal_evidence_readable`]), because a
/// value stamped at acquisition can differ between replicas that acquired
/// at different moments relative to the beacon's handoff-complete stamp.
#[derive(Clone, Debug)]
pub struct SettledTxSet {
    /// Cross-shard transactions the terminated shard settled by its
    /// terminal block.
    pub txs: BTreeSet<TxHash>,
    /// The terminal block's weighted timestamp.
    pub terminal_wt: WeightedTimestamp,
}

/// The verdict on a set of cross-shard execution certificates against the
/// known settled sets, at an anchored weighted timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettledSetVerdict {
    /// No outcome names a past-terminal shard, or every such outcome's
    /// transaction is in that shard's settled set.
    Pass,
    /// An outcome names a transaction a past-terminal shard did not
    /// settle, or names a shard whose evidence the anchor's window cannot
    /// read: the window is evicted, carries no record of the shard, or
    /// sits past its evidence window — categorically unreachable.
    Reject,
    /// An outcome names a past-terminal shard whose settled set isn't
    /// known yet, a shard scheduled to terminate whose settled set can
    /// only exist once it does, or an anchor in a window not yet
    /// committed — hold until the set or the window is in hand.
    Defer,
}

/// What a finalization claims about one transaction, which decides which
/// way the terminated partner's settled set has to read.
///
/// The two are opposite questions about the same evidence. A settlement
/// applies this shard's half, so it needs the partner to have settled its
/// own half too. An abort of a member whose certificate is out states
/// the transaction reaches no outcome anywhere, so it needs the partner
/// *not* to have settled — a partner that did settle is the one case
/// where aborting would tear a cross-shard transaction in half.
///
/// Both read the same set and both need it readable. Opposite questions
/// about the partner's set are still questions about the partner's set,
/// so a set nobody can read leaves either claim unproven and rejects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxClaim {
    /// This shard settles the transaction, on coverage the finalization
    /// carries.
    Settled,
    /// This shard aborts a transaction its own tick ran: a member
    /// that executed there and is attested aborted, whose certificate a
    /// counterpart could have settled against. An abandonment, which
    /// its tick seats from a line and does not run, puts no claim at
    /// all.
    Abandoned,
}

/// What a partner shard's evidence says at a judging anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The shard is live, and `terminating` where it is scheduled to
    /// leave.
    Live {
        /// Whether an admitted reshape or a coast takes it out.
        terminating: bool,
    },
    /// It has departed and its settled set can still be read.
    Readable,
    /// Its settled set can never be read at this anchor: the anchor's
    /// window is evicted or carries no boundary record for it, or its
    /// handoff is stamped and aged past the evidence window.
    Unreadable,
    /// The judging anchor's window is not yet committed.
    Unknown,
}

/// What `shard`'s evidence says at `anchored_wt`.
///
/// Read off the anchor's own window and nothing older, so two replicas
/// answer alike however many windows each retains: the window's trie says
/// whether the shard is live, and its boundary record, where the beacon's
/// handoff-complete stamp lands, whether a departed one can still be
/// read. An anchor exactly on the shard's cut falls in the window the cut
/// opens and reads the shard as departed. The one reading behind the
/// settled-set fence and every licence that turns on a partner no longer
/// being able to answer.
#[must_use]
pub fn partner_evidence(
    topology_schedule: &TopologySchedule,
    shard: ShardId,
    anchored_wt: WeightedTimestamp,
) -> Evidence {
    let window = match topology_schedule.lookup(anchored_wt) {
        WindowLookup::Window(window) => window,
        WindowLookup::NotYetCommitted => return Evidence::Unknown,
        // Below the schedule floor nothing about the window is readable.
        WindowLookup::Evicted => return Evidence::Unreadable,
    };
    if window.shard_trie().contains(shard) {
        return Evidence::Live {
            terminating: topology_schedule.termination_scheduled(shard, anchored_wt),
        };
    }
    if window.evidence_readable(shard, anchored_wt, topology_schedule.windows()) {
        Evidence::Readable
    } else {
        Evidence::Unreadable
    }
}

/// Resolve a finalization's per-transaction claims against the known
/// settled sets at `anchored_wt`.
///
/// `claims` yields `(shard, tx_hash, claim)` for each participating shard
/// of each transaction the finalization puts a question about. A
/// [`Settled`](TxClaim::Settled) claim's shards are the ones whose
/// certificates the finalization carries; an
/// [`Abandoned`](TxClaim::Abandoned) claim has no counterpart certificate
/// to read them off, so its caller supplies the participants the
/// committing block assigned. An abandonment is among no claims: its
/// line is its licence, named for a member no tick ran, one a record
/// covers, one reaching no other shard or one a recovery released, so
/// no set is asked about it and it is admitted whatever its
/// counterparts' evidence reads.
///
/// Past-terminal-ness is read off the **anchored** snapshot at
/// `anchored_wt`, so callers that must agree across replicas (the vote
/// fence) pass the voted block's `parent_qc` weighted timestamp;
/// node-local callers (the finalize gate) pass their committed timestamp.
///
/// A shard that is not yet past-terminal but is scheduled to terminate (an
/// admitted split/merge or a coast toward its terminal block) is fenced the
/// same way whichever claim names it: `Defer` until it terminates and its
/// settled set answers. This closes the pre-boundary window in which a
/// survivor could finalize a straddler the terminating side never settled,
/// and the matching one in which it could abandon one the terminating side
/// did settle.
pub fn settled_set_verdict<S, I>(
    settled_sets: &HashMap<ShardId, SettledTxSet, S>,
    topology_schedule: &TopologySchedule,
    local_shard: ShardId,
    anchored_wt: WeightedTimestamp,
    claims: I,
) -> SettledSetVerdict
where
    S: BuildHasher,
    I: IntoIterator<Item = (ShardId, TxHash, TxClaim)>,
{
    let mut defer = false;
    for (shard, tx_hash, claim) in claims {
        if shard == local_shard {
            continue;
        }
        let settlement = matches!(claim, TxClaim::Settled);

        match partner_evidence(topology_schedule, shard, anchored_wt) {
            // Gone for good. Both claims need the set: a settlement is
            // unreachable without the partner's coverage, and an abort
            // claim turns on the partner *not* having settled against
            // the certificate the member's run put out, which a set
            // nobody can read cannot establish.
            Evidence::Unreadable => return SettledSetVerdict::Reject,
            // `shard` is live now, but if it is scheduled to terminate it
            // may leave the trie before it resolves this transaction — and
            // once it does, only its settled set is authoritative. Deciding
            // on coverage alone would then risk applying a transaction the
            // terminating side never settled, or abandoning one it did.
            // Defer to its settled set, exactly as for an already
            // terminated shard.
            Evidence::Live { terminating } => {
                defer |= terminating;
                continue;
            }
            // The judging anchor's window hasn't folded yet — transient
            // lag, the same hold the missing set takes below.
            Evidence::Unknown => {
                defer = true;
                continue;
            }
            Evidence::Readable => {}
        }
        match settled_sets.get(&shard) {
            // The partner's verdict, read the way the claim needs it: a
            // settlement needs the partner to have settled, an
            // abandonment needs it not to have.
            Some(settled) => {
                if settled.txs.contains(&tx_hash) != settlement {
                    return SettledSetVerdict::Reject;
                }
            }
            None => defer = true,
        }
    }
    if defer {
        SettledSetVerdict::Defer
    } else {
        SettledSetVerdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, Epoch, EpochWindows, Hash, NetworkDefinition, ShardAnchor,
        StateRoot, TERMINAL_EVIDENCE_EPOCHS, TopologySnapshot, ValidatorSet,
    };

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const PEER: ShardId = ShardId::leaf(1, 1);

    const EPOCH_MS: u64 = 300_000;
    /// The cut PEER terminates at: the close of the window it last lives in.
    const CUT_MS: u64 = EPOCH_MS;

    fn wt(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    fn snap(leaves: &[ShardId], cut: &[(ShardId, u64)]) -> Arc<TopologySnapshot> {
        snap_departed(leaves, cut, &[])
    }

    /// [`snap`] carrying a terminal boundary record per departed shard, as
    /// every projected snapshot does while the beacon retains the record.
    /// `handoff_complete: None` is an open evidence window.
    fn snap_departed(
        leaves: &[ShardId],
        cut: &[(ShardId, u64)],
        departed: &[(ShardId, Option<Epoch>)],
    ) -> Arc<TopologySnapshot> {
        let boundaries: BTreeMap<ShardId, ShardAnchor> = departed
            .iter()
            .map(|(shard, handoff_complete)| {
                (
                    *shard,
                    ShardAnchor {
                        state_root: StateRoot::ZERO,
                        block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                        height: BlockHeight::new(9),
                        weighted_timestamp: wt(CUT_MS),
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_settled_txs: None,
                        handoff_complete: *handoff_complete,
                        terminal_epoch: None,
                    },
                )
            })
            .collect();
        Arc::new(
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                boundaries,
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            )
            .with_scheduled_terminals(cut.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
    }

    /// PEER lives in window 0 and terminates at its close; its children hold
    /// the keyspace from window 1 on. The handoff stamp is the caller's:
    /// `None` holds the evidence window open.
    fn peer_terminated_stamped(handoff_complete: Option<Epoch>) -> TopologySchedule {
        let (left, right) = PEER.children();
        let mut sched =
            TopologySchedule::new(EPOCH_MS, Epoch::new(0), snap(&[LOCAL, PEER], &[(PEER, 0)]));
        // Retained well past the whole evidence window, so an anchor inside
        // it resolves a window rather than falling off the head.
        let post = snap_departed(&[LOCAL, left, right], &[], &[(PEER, handoff_complete)]);
        for epoch in 1..=TERMINAL_EVIDENCE_EPOCHS * 3 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched
    }

    fn peer_terminated() -> TopologySchedule {
        peer_terminated_stamped(None)
    }

    /// A set for PEER carrying `txs`, readable for the terminal-evidence
    /// window past the cut — what the acquisition stamps on it.
    fn set_of(txs: &[TxHash]) -> HashMap<ShardId, SettledTxSet> {
        let mut sets = HashMap::new();
        sets.insert(
            PEER,
            SettledTxSet {
                txs: txs.iter().copied().collect(),
                terminal_wt: wt(CUT_MS),
            },
        );
        sets
    }

    fn verdict(
        sets: &HashMap<ShardId, SettledTxSet>,
        anchored_ms: u64,
        claims: &[(ShardId, TxHash, TxClaim)],
    ) -> SettledSetVerdict {
        settled_set_verdict(
            sets,
            &peer_terminated(),
            LOCAL,
            wt(anchored_ms),
            claims.iter().copied(),
        )
    }

    /// The set is the authority, and the two claims read it opposite ways: a
    /// settlement needs the departed shard to have settled, an abandonment
    /// needs it not to have.
    #[test]
    fn the_two_claims_read_the_same_set_in_opposite_directions() {
        let inside = CUT_MS + EPOCH_MS;
        let settled = set_of(&[tx(1)]);

        assert_eq!(
            verdict(&settled, inside, &[(PEER, tx(1), TxClaim::Settled)]),
            SettledSetVerdict::Pass,
        );
        assert_eq!(
            verdict(&settled, inside, &[(PEER, tx(1), TxClaim::Abandoned)]),
            SettledSetVerdict::Reject,
            "the partner settled it, so abandoning would tear it in half",
        );
        assert_eq!(
            verdict(&settled, inside, &[(PEER, tx(2), TxClaim::Abandoned)]),
            SettledSetVerdict::Pass,
            "one the set does not name is one the partner never settled",
        );
        assert_eq!(
            verdict(&settled, inside, &[(PEER, tx(2), TxClaim::Settled)]),
            SettledSetVerdict::Reject,
            "and settling it would need coverage that never existed",
        );
    }

    /// A past-terminal shard whose set is not held yet defers rather than
    /// deciding — the evidence exists, this replica has not read it.
    #[test]
    fn an_unheld_set_defers_both_claims() {
        let none = HashMap::new();
        let inside = CUT_MS + EPOCH_MS;
        for claim in [TxClaim::Settled, TxClaim::Abandoned] {
            assert_eq!(
                verdict(&none, inside, &[(PEER, tx(1), claim)]),
                SettledSetVerdict::Defer,
            );
        }
    }

    /// The window that decides counts from the beacon's handoff-complete
    /// stamp on the judging anchor's snapshot, not from the cut. Before the
    /// stamp the window is open — a slow seeding or a partition cannot age
    /// the evidence out from under the survivor still trying to read it —
    /// and once stamped it closes the evidence window later, refusing both
    /// claims alike.
    #[test]
    fn the_evidence_window_counts_from_the_handoff_stamp() {
        let settled = set_of(&[tx(1)]);

        // Unstamped: readable at any distance past the cut.
        assert_eq!(
            verdict(
                &settled,
                CUT_MS + EPOCH_MS * (TERMINAL_EVIDENCE_EPOCHS + 2),
                &[(PEER, tx(1), TxClaim::Settled)],
            ),
            SettledSetVerdict::Pass,
            "an open window reads however late the anchor",
        );

        // Stamped at epoch 2: expiry is the evidence window past that.
        let handoff = Epoch::new(2);
        let stamped = peer_terminated_stamped(Some(handoff));
        let expiry = EpochWindows::new(EPOCH_MS).handoff_evidence_expiry(handoff);
        let stamped_verdict = |anchored_ms: u64| {
            settled_set_verdict(
                &settled,
                &stamped,
                LOCAL,
                wt(anchored_ms),
                [(PEER, tx(1), TxClaim::Settled)],
            )
        };
        assert_eq!(
            stamped_verdict(expiry.as_millis()),
            SettledSetVerdict::Pass,
            "readable to the last instant of the window",
        );
        assert_eq!(
            stamped_verdict(expiry.as_millis() + 1),
            SettledSetVerdict::Reject,
            "and unreadable past it, which refuses both claims alike",
        );
    }

    /// Claims about this shard are not the fence's business — it asks only
    /// what a *counterpart* did.
    #[test]
    fn a_claim_about_the_local_shard_is_not_asked() {
        let none = HashMap::new();
        assert_eq!(
            verdict(
                &none,
                CUT_MS + EPOCH_MS,
                &[(LOCAL, tx(1), TxClaim::Abandoned)],
            ),
            SettledSetVerdict::Pass,
        );
    }

    /// A shard still live in the anchored window is decided by its own
    /// certificates, not by a set that cannot exist yet — unless it is
    /// scheduled to terminate, which defers instead. The pre-boundary hold
    /// is what keeps a survivor from applying a straddler the terminating
    /// side never settles.
    #[test]
    fn a_shard_scheduled_to_terminate_defers_before_its_cut() {
        let none = HashMap::new();
        assert_eq!(
            verdict(&none, 0, &[(PEER, tx(1), TxClaim::Settled)]),
            SettledSetVerdict::Defer,
            "PEER is live in window 0 and carries an admitted terminal",
        );
    }

    /// A departed shard is read off the judging anchor's own window, so a
    /// replica that still retains the window the shard last lived in and
    /// one that has evicted it read the same evidence and reach the same
    /// verdict.
    #[test]
    fn a_departed_shard_reads_alike_whatever_older_windows_are_retained() {
        let mut deep = peer_terminated();
        let mut shallow = peer_terminated();
        shallow.evict_below(Epoch::new(1));

        let inside = wt(CUT_MS + EPOCH_MS);
        let settled = set_of(&[tx(1)]);
        for schedule in [&deep, &shallow] {
            assert_eq!(partner_evidence(schedule, PEER, inside), Evidence::Readable,);
            assert_eq!(
                settled_set_verdict(
                    &settled,
                    schedule,
                    LOCAL,
                    inside,
                    [(PEER, tx(1), TxClaim::Settled)],
                ),
                SettledSetVerdict::Pass,
            );
        }

        // A window carrying neither the shard nor its record says the
        // same on both: nothing can be read.
        let swept = snap(&[LOCAL], &[]);
        let later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS * 3 + 1);
        deep.insert(later, Arc::clone(&swept));
        shallow.insert(later, swept);
        let past = wt(EPOCH_MS * later.inner());
        for schedule in [&deep, &shallow] {
            assert_eq!(partner_evidence(schedule, PEER, past), Evidence::Unreadable,);
        }
    }

    /// An anchor ahead of every window this schedule holds is a lagging
    /// beacon, not a departed counterpart: the reading is unknown and
    /// both claims hold until the window is committed.
    #[test]
    fn an_anchor_in_a_window_not_yet_committed_reads_unknown() {
        let schedule = peer_terminated();
        let ahead = wt(EPOCH_MS * (TERMINAL_EVIDENCE_EPOCHS * 3 + 1));
        let (left, _) = PEER.children();

        for shard in [PEER, left] {
            assert_eq!(
                partner_evidence(&schedule, shard, ahead),
                Evidence::Unknown,
                "{shard:?}",
            );
        }
        for claim in [TxClaim::Settled, TxClaim::Abandoned] {
            assert_eq!(
                settled_set_verdict(
                    &set_of(&[tx(1)]),
                    &schedule,
                    LOCAL,
                    ahead,
                    [(PEER, tx(1), claim)],
                ),
                SettledSetVerdict::Defer,
                "{claim:?}",
            );
        }
    }

    /// An anchor exactly on the cut falls in the window the cut opens,
    /// which no longer carries the shard: it reads that window's boundary
    /// record, and the claim is judged by the settled set. A schedule
    /// holding only the closing window cannot say yet.
    #[test]
    fn an_anchor_on_the_cut_reads_the_boundary_record() {
        let schedule = peer_terminated();
        assert_eq!(
            partner_evidence(&schedule, PEER, wt(CUT_MS)),
            Evidence::Readable,
        );
        let settled = set_of(&[tx(1)]);
        assert_eq!(
            verdict(&settled, CUT_MS, &[(PEER, tx(1), TxClaim::Settled)]),
            SettledSetVerdict::Pass,
        );
        assert_eq!(
            verdict(&settled, CUT_MS, &[(PEER, tx(1), TxClaim::Abandoned)]),
            SettledSetVerdict::Reject,
        );
        assert_eq!(
            verdict(&HashMap::new(), CUT_MS, &[(PEER, tx(1), TxClaim::Settled)]),
            SettledSetVerdict::Defer,
            "the record is readable and the set is not held yet",
        );

        let closing_only =
            TopologySchedule::new(EPOCH_MS, Epoch::new(0), snap(&[LOCAL, PEER], &[(PEER, 0)]));
        assert_eq!(
            partner_evidence(&closing_only, PEER, wt(CUT_MS)),
            Evidence::Unknown,
        );
        assert_eq!(
            settled_set_verdict(
                &settled,
                &closing_only,
                LOCAL,
                wt(CUT_MS),
                [(PEER, tx(1), TxClaim::Settled)],
            ),
            SettledSetVerdict::Defer,
        );
    }

    /// One deferral does not soften a rejection elsewhere: a torn claim is
    /// refused whatever else the same finalization asks about.
    #[test]
    fn a_rejection_dominates_a_deferral() {
        let settled = set_of(&[tx(1)]);
        assert_eq!(
            verdict(
                &settled,
                CUT_MS + EPOCH_MS,
                &[
                    (PEER, tx(1), TxClaim::Abandoned),
                    (ShardId::leaf(2, 2), tx(3), TxClaim::Settled),
                ],
            ),
            SettledSetVerdict::Reject,
        );
    }
}
