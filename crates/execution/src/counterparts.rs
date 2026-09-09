//! What counterparts have said about the transactions in flight here,
//! and what this shard still asks them.
//!
//! One account of the exchange: the ledger of what this shard owes an
//! outcome for, the mirror of what counterparts were heard to say —
//! shared with the vote fence, which checks a record against exactly
//! what was offered from — the questions put to silent counterparts,
//! and the proofs fetched back to offer in a block. Everything here is
//! folded from committed content or from a certificate every replica
//! hears the same way, so replicas at one frontier hold one account.
//! The tick machine reads the ledger through it and decides what to do
//! with a strand nobody can answer for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::{Action, FetchIds, FetchRequest, ProtocolEvent};
use hyperscale_metrics::{record_rebuilt_verdict_entry, record_reclaim_probe_answered};
use hyperscale_storage::committed_tx_cell_key;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Anchor, Block, BlockHeight, CLAIM_VISIBILITY_LAG,
    CounterpartEvidence, CounterpartMirror, Deadline, ExecutionCertificate, Heard, Inclusion,
    MAX_ABANDONMENT_RECORDS_PER_BLOCK, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STATE_CLAIMS_PER_BLOCK,
    MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof, Probed, ProvenAnchors, ProvenCells, Question,
    SettledTxSet, ShardId, ShardTrie, Spoken, StateClaim, SubstateKey, TerminalEvidence,
    TopologySchedule, TransactionDecision, TxHash, TxResolution, UnsettledTx, Verifiable, Verified,
    WeightedTimestamp, Word,
};
use hyperscale_vm_effects::CrossingCell;

use crate::unresolved::{Probeable, Released, Unanswerable, UnresolvedTxs};

/// One counterpart cell a leg entry asks about: the shard holding it,
/// the cell, the anchor an answer is held to, and which question it is.
type CounterpartCell = (ShardId, SubstateKey, Probed);

/// What counterparts were heard to say, by shard and question, then by
/// the moment and word of each answer: the grouping a block's records
/// are composed from.
type HeardByQuestion =
    BTreeMap<(ShardId, Question), BTreeMap<(WeightedTimestamp, Word), Vec<UnsettledTx>>>;

/// Every cell `entry` asks a counterpart about, under `trie`: each other
/// core shard's committed cell, each delivery's claim on the shard that
/// was to deliver it and on whatever shard holds the cell's prefix now,
/// and each core consumer's claim. The one enumeration the prober and
/// the commit-time fold both read, so what is asked and what is answered
/// are the same cells.
///
/// `local` is never asked about: a core member holds the core it is part
/// of, itself included, because the arity an absent committed cell is
/// read against is the core's own — but what it has committed is not
/// something it fetches a proof of.
fn counterpart_cells(entry: &Probeable, local: ShardId, trie: &ShardTrie) -> Vec<CounterpartCell> {
    // The committed cell is asked about only where its absence would
    // answer: a core of more than one shard, whose shards settle on each
    // other's certificates with no clock. A core of one shard answers
    // through its claim, which the deadline fences.
    //
    // Every core shard is asked, because any one of them absent is the
    // whole answer — a core that one of its shards never included can
    // never settle — while the shards that did include say only that a
    // sibling is still pending. Asking the lowest alone leaves the
    // crossing stranded whenever that shard is the one that included.
    // Nothing is asked before the deadline, so a core that settles pays
    // for none of this.
    let core_answers = Probed::Core
        .read(Inclusion::Absent, entry.core.len())
        .is_some();
    let core = entry
        .core
        .iter()
        .filter(move |&&shard| core_answers && shard != local)
        .map(|&shard| {
            (
                shard,
                committed_tx_cell_key(shard, entry.tx_hash, entry.deadline.validity_end()),
                Probed::Core,
            )
        });
    let deliveries = entry.deliveries.iter().flat_map(|&(delivered_by, claim)| {
        BTreeSet::from([delivered_by, trie.shard_for_prefix(claim.owner)])
            .into_iter()
            .map(move |shard| (shard, claim, Probed::Delivery))
    });
    let claims = entry.claims.iter().flat_map(|&(shard, claim)| {
        BTreeSet::from([shard, trie.shard_for_prefix(claim.owner)])
            .into_iter()
            .map(move |shard| (shard, claim, Probed::Claim))
    });
    core.chain(deliveries).chain(claims).collect()
}

/// What one block's abandonment records may still spend.
///
/// Two figures, because the section answers to two questions. The names
/// are the drain's: how many transactions can be owed an outcome at once
/// is what [`MAX_UNSETTLED_PER_BLOCK`] bounds. The bytes are the wire's:
/// a name costs its reach as well as itself, so the same count of names
/// spans a four-fold range and only
/// [`MAX_PROPOSAL_EVIDENCE_BYTES`] keeps the section inside the frame
/// that carries it.
struct Budget {
    names: usize,
    bytes: usize,
}

impl Budget {
    /// A block's whole allowance, before any record is composed. The
    /// record's own terms are charged with the first name it takes,
    /// which is what leaves room for them.
    const fn empty() -> Self {
        Self {
            names: MAX_UNSETTLED_PER_BLOCK,
            bytes: MAX_PROPOSAL_EVIDENCE_BYTES,
        }
    }

    /// Whether either figure is exhausted.
    const fn spent(&self) -> bool {
        self.names == 0 || self.bytes == 0
    }

    /// Take as many of `unsettled` as the budget still affords, in the
    /// order offered, and charge for them. What is left is dropped: a
    /// name a record does not carry stays uncovered and is offered
    /// again next block.
    fn take(&mut self, unsettled: &mut Vec<UnsettledTx>) {
        let mut taken = 0;
        let mut spend = ABANDONMENT_RECORD_BYTES;
        for entry in unsettled.iter().take(self.names) {
            let next = spend + entry.wire_weight();
            if next > self.bytes {
                break;
            }
            spend = next;
            taken += 1;
        }
        unsettled.truncate(taken);
        if taken == 0 {
            return;
        }
        self.names -= taken;
        self.bytes -= spend;
    }
}

/// An inherited escrow record, and where its one question stands.
///
/// One question, to one shard: is the claim cell this record names
/// present? So the bookkeeping is one height rather than the ledger's
/// `Asked` — there is no set of counterparts to track, no fetch release
/// to sequence, and no record to compose, because the answer is a
/// reading and a reading is block content already.
#[derive(Debug, Clone)]
pub struct Inherited {
    /// The record leaf, which carries the claim key, the issuing
    /// transaction and the expiry every window is read off.
    pub cell: CrossingCell,
    /// The newest counterpart header the claim has been asked at, so
    /// the question is not re-sent at the same one every block.
    asked_at: Option<BlockHeight>,
    /// What a committed claim read of the cell, once one has read it:
    /// present at any anchor, absent only past the lapse.
    pub answer: Option<Inclusion>,
}

impl Inherited {
    /// The record as it arrives at a seat: undisposed, unasked.
    #[must_use]
    pub const fn seated(cell: CrossingCell) -> Self {
        Self {
            cell,
            asked_at: None,
            answer: None,
        }
    }

    /// The deadline every window this record is read against derives
    /// from — the producing intent's, recovered from the expiry the leaf
    /// states.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        Deadline::from_expiry(self.cell.expiry_ms)
    }
}

/// Whether any undisposed inherited record is still waiting on `key`.
///
/// Read off the keys rather than off a name, because an inherited
/// record names no transaction this chain committed.
fn awaited_by(inherited: &BTreeMap<SubstateKey, Inherited>, key: SubstateKey) -> bool {
    inherited
        .values()
        .any(|record| record.answer.is_none() && record.cell.consumer_claim == key)
}

/// What a commit folded, and what it could not answer for.
pub struct Committed {
    /// The fetches it releases and the probes it opens.
    pub actions: Vec<Action>,
    /// The transactions let go of because every counterpart has fallen
    /// silent — the tick machine's to discard.
    pub unanswerable: Vec<Unanswerable>,
}

/// What this validator holds to offer in a block it proposes.
pub struct Offers {
    /// Readings its own fetches took that no block has carried yet, in
    /// the one order a block carries them.
    pub state_claims: Vec<StateClaim>,
    /// The records it has evidence for and has not yet written down.
    pub abandonment_records: Vec<AbandonmentRecord>,
}

pub struct Counterparts {
    local_shard: ShardId,

    /// Committed transactions still owed an outcome, folded from the
    /// chain rather than read off live tick state — the only account of
    /// what this shard has in flight that can be rebuilt after losing
    /// that state.
    pub(crate) ledger: UnresolvedTxs,

    /// What counterparts have said about the transactions legs here
    /// issued for, shared with the shard coordinator's vote fence: a
    /// core's refusal, a proved absence. This account is the only
    /// writer, and the only one that says what to drop — the ledger
    /// above is what an entry there speaks for.
    ///
    /// One mirror, because the fence checks a record against exactly
    /// what was offered from, and two copies could answer differently.
    pub(crate) mirror: Arc<CounterpartMirror>,

    /// Commit-proven remote source blocks, shared with the shard
    /// coordinator, which owns the mirror and feeds it off
    /// `RemoteHeaderCommitted`.
    ///
    /// A cross-shard EC is consumable only against a proven source block
    /// — a bare QC certifies availability, and an f+1..2f corrupt
    /// committee can certify a sibling that never commits and export ECs
    /// computed from it. The same anchors are what a probe of a
    /// counterpart's committed set is taken against, and what this
    /// validator's vote fence holds a block's state claims to: one
    /// mirror, so a claim cannot pass the fence at an anchor no prober
    /// here would have chosen.
    pub(crate) proven_anchors: Arc<ProvenAnchors>,

    /// What this validator's own fetches have proven of counterparts'
    /// cells, shared with the shard coordinator's vote fence and with
    /// the state-proof server that relays a peer the bytes.
    ///
    /// Written here because a fetch lands here, and read there because
    /// a block states a reading rather than proving it. Kept apart from
    /// the mirror above for the reason stated on
    /// [`ProvenCells`]: a reading licenses this validator's vote and
    /// composes nothing.
    pub(crate) proven_cells: Arc<ProvenCells>,

    /// The readings this validator's own fetches took, each with the
    /// transactions whose probes it spoke to, held to offer in a block
    /// this validator proposes: a claim is committed content, folded by
    /// every replica at the same height, and the fetch is only how the
    /// proposer came by the answer. A claim leaves when a block carries
    /// it, or when every transaction it answered for is gone.
    fetched: BTreeMap<StateClaim, BTreeSet<TxHash>>,

    /// The escrow records this shard inherited with a prefix, each still
    /// undisposed, by cell key.
    ///
    /// A seat's store arrives holding value its predecessors escrowed
    /// and nothing else names it: its ledger begins empty, no body
    /// arrives with the leaves, and the chains that issued the crossings
    /// have ended, so no counterpart record will ever be composed about
    /// them. What is left is the claim cell each record names, and the
    /// leaf carries every term needed to ask about it. Held here rather
    /// than beside the tick machine because the question is a
    /// counterpart's to answer, like every other question in this file.
    pub(crate) inherited: BTreeMap<SubstateKey, Inherited>,
    /// Fetches the ledger let go of since the last commit — a question
    /// the chain answered first, or one whose entry is gone — released
    /// as one abandon at the commit, so a counterpart that never serves
    /// the height does not pin the slot.
    released_fetches: Vec<(Anchor, SubstateKey)>,
}

impl Counterparts {
    #[must_use]
    pub const fn new(
        local_shard: ShardId,
        proven_anchors: Arc<ProvenAnchors>,
        proven_cells: Arc<ProvenCells>,
        mirror: Arc<CounterpartMirror>,
    ) -> Self {
        Self {
            local_shard,
            ledger: UnresolvedTxs::new(local_shard),
            mirror,
            proven_anchors,
            proven_cells,
            fetched: BTreeMap::new(),
            inherited: BTreeMap::new(),
            released_fetches: Vec::new(),
        }
    }

    /// As [`Self::new`], holding the escrow records a reshape seat
    /// imported with its prefix. A leaf that does not decode is one no
    /// disposal could be composed from, so it is dropped rather than
    /// held.
    pub fn seated(
        local_shard: ShardId,
        proven_anchors: Arc<ProvenAnchors>,
        proven_cells: Arc<ProvenCells>,
        evidence: Arc<CounterpartMirror>,
        records: &[(SubstateKey, Vec<u8>)],
    ) -> Self {
        let mut counterparts = Self::new(local_shard, proven_anchors, proven_cells, evidence);
        counterparts.inherited = records
            .iter()
            .filter_map(|(key, value)| {
                Some((*key, Inherited::seated(CrossingCell::from_bytes(value)?)))
            })
            .collect();
        counterparts
    }

    /// Fold what a committed block says about counterparts — the proofs
    /// and verdict records it carries, the entries its certificates
    /// resolve, the departures the schedule now proves — let go of what
    /// no window can still answer, and ask what the block's clock opens.
    ///
    /// `trie` is the block's committee's, which says who was party to
    /// each transaction, and `now` the committed clock every deadline is
    /// read against.
    pub fn on_commit(
        &mut self,
        trie: &ShardTrie,
        topology_schedule: &TopologySchedule,
        block: &Block,
        now: WeightedTimestamp,
    ) -> Committed {
        self.gc_settled_sets(topology_schedule, now);
        // A reading the chain now carries is everybody's: its answers
        // are folded here, and nothing offers it again.
        for claim in block.state_claims() {
            self.fetched.remove(claim);
        }
        let mut actions = self.fold_state_claims(trie, block);
        actions.extend(self.fold_verdict_records(block));
        // Every verdict this block carries resolves its transactions,
        // whichever way it went; what is left past every window that
        // could still carry one is nobody's to resolve.
        let released = self.ledger.release_resolved(block.certificates());
        self.released_fetches.extend(released);
        // What the block writes down about departed shards, before the
        // prune below reads what is still answerable.
        let rebuilt = self
            .ledger
            .record_abandonment_records(block.abandonment_records());
        for _ in 0..rebuilt {
            record_rebuilt_verdict_entry();
        }
        self.cover_recorded(block);
        self.stamp_departures(topology_schedule, now);
        let pruned = self.ledger.prune(now);
        self.released_fetches.extend(pruned.released);
        actions.extend(self.release_answered_fetches());
        // The committed clock is what opens a leg's deadline, so the
        // cores gone silent past it are asked here.
        actions.extend(self.probe(trie, now));
        Committed {
            actions,
            unanswerable: pruned.unanswerable,
        }
    }

    /// Record a departed shard's settled set beside what this ledger
    /// says the shard was party to: a departure record may name only
    /// these, and the fence reads it from the same mirror.
    pub fn on_settled(&self, shard: ShardId, settled: SettledTxSet) {
        let parties = self.ledger.party_to(shard, settled.terminal_wt);
        self.mirror.record_settled(shard, settled, parties);
    }

    /// The departed shards whose settled sets the fence will need and
    /// this validator does not hold: every shard the schedule still
    /// routes to whose boundary record attests a settled root, until the
    /// handoff-anchored evidence window has closed at `now` (an
    /// unstamped window is open). Re-derived whole on every beacon fold,
    /// so a set acquired, a window closed or a shard evicted simply
    /// drops out.
    #[must_use]
    pub fn wanted_settled_sets(
        &self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) -> Vec<TerminalEvidence> {
        let head = topology_schedule.head();
        topology_schedule
            .routable_shards()
            .into_iter()
            .filter(|&shard| shard != self.local_shard)
            .filter(|&shard| !self.mirror.with_settled(|sets| sets.contains_key(&shard)))
            .filter(|&shard| {
                topology_schedule
                    .handoff_evidence_expiry(shard)
                    .is_none_or(|expiry| now <= expiry)
            })
            .filter_map(|shard| {
                let anchor = head.boundary(shard)?;
                let attested_root = anchor.terminal_roots?.settled_txs;
                let terminal_wt = topology_schedule.terminal_cut_wt(shard)?;
                Some(TerminalEvidence {
                    shard,
                    height: anchor.height,
                    block_hash: anchor.block_hash,
                    terminal_wt,
                    attested_root,
                })
            })
            .collect()
    }

    /// What this validator holds to offer in a block it proposes.
    #[must_use]
    pub fn offers(&self) -> Offers {
        Offers {
            state_claims: self.state_claims(),
            abandonment_records: self.abandonment_records(),
        }
    }

    /// Ask each silent counterpart whether it took the transaction a
    /// leg here issued for, once the transaction's deadline has passed.
    ///
    /// The deadline gates the probe and never the reclaim: absence at a
    /// block past the floor is the evidence, and before it the
    /// counterpart may still legitimately act. A core of more than one
    /// shard is asked about the transaction's committed cell past the
    /// deadline, and every core shard is asked: any one of them absent
    /// is the whole answer, while the shards that did include say only
    /// that a sibling is pending, so asking one alone strands the
    /// crossing whenever that shard is the one that included. A core of
    /// one shard writes no cell and is asked about its consumer's claim
    /// instead. A delivering shard is asked about the crossing's claim
    /// cell past the lapse, the delivery window's close plus the
    /// finalization delay, since a delivery admitted under the close has
    /// claimed by then or never will. Each is asked against that shard's
    /// newest commit-proven header inside its window — at or past its
    /// floor and short of the probed cell's own sweep, since a proof
    /// against a swept cell is a true proof of nothing — of those
    /// standing at `now`, the chain's committed clock.
    ///
    /// That ceiling is what makes a committee ask one question rather
    /// than four. The answer is held to each voter's own reading, so a
    /// proposer anchoring where its peers did not sends every one of
    /// them to fetch bytes before it can vote; anchoring at a clock they
    /// share, on a header old enough that all of them hold it, they have
    /// already read the cell the block claims. A shard whose header has
    /// not reached here yet is asked when it does, and one whose every
    /// standing header is past the window is not asked at all: the entry
    /// then waits out its horizon.
    ///
    /// A delivering shard that departs at a reshape may leave no header
    /// past the lapse at all, so the claim cell is asked about wherever
    /// its prefix sits: on the shard that was to deliver it and on the
    /// shard the trie names for its owner now, which is the successor
    /// holding the departed chain's cells. Both are asked rather than
    /// the trie's answer alone, because the vote fence checks a record
    /// against the voter's own proof of the shard it names, and two
    /// validators straddling the cut would otherwise prove different
    /// shards and never both vote one record.
    ///
    /// The cell is named from signed content and the counterpart shard
    /// alone, so nothing but the header and the proof is fetched.
    pub fn probe(&mut self, trie: &ShardTrie, now: WeightedTimestamp) -> Vec<Action> {
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        for entry in self.ledger.probeable(now) {
            for (shard, key, probed) in counterpart_cells(&entry, self.local_shard, trie) {
                // The newest header an absence would answer at, of those
                // standing at the chain's clock: the one the shard is
                // likeliest to still serve, and the one every member of
                // this committee is asking of. Where no header answers
                // one — the cue fired before the window opened — the
                // newest standing past the cue's own visibility will do,
                // because the reading the cue is after is a presence,
                // and a presence answers wherever it was taken.
                let readable = entry.cued_at.map(|at| at.plus(CLAIM_VISIBILITY_LAG));
                let Some(anchor) = self
                    .proven_anchors
                    .newest_licensed(shard, now, |ts| {
                        probed.absence_answers_at(ts, entry.deadline)
                    })
                    .or_else(|| {
                        self.proven_anchors.newest_licensed(shard, now, |ts| {
                            readable.is_none_or(|readable| ts >= readable)
                        })
                    })
                else {
                    continue;
                };
                // A question in flight, one this validator's own fetch
                // answered and one the chain answered are left alone: a
                // core's header lands every block, and moving a probe
                // to each new one abandons the fetch before its answer
                // returns. A probe whose fetch returned a reading that
                // answered nothing is moved on, which is how a cell
                // read outside its window is asked again — at a newer
                // header, not of the same one every block.
                if self
                    .ledger
                    .probe_stands(entry.tx_hash, shard, key, anchor.height)
                {
                    continue;
                }
                self.ledger
                    .record_probe(entry.tx_hash, shard, key, probed, anchor);
                wanted.entry(anchor).or_default().push(key);
            }
        }
        // The records this shard inherited ask one question each, of
        // whoever holds the claim's prefix now. Nothing is asked of a
        // claim this shard holds itself — the tick reads that cell
        // directly — and nothing is asked twice at one header.
        for record in self.inherited.values_mut() {
            if record.answer.is_some() {
                continue;
            }
            let claim = record.cell.consumer_claim;
            let shard = trie.shard_for_prefix(claim.owner);
            if shard == self.local_shard {
                continue;
            }
            let Some(anchor) = self.proven_anchors.newest_licensed(shard, now, |_| true) else {
                continue;
            };
            if record.asked_at.is_some_and(|asked| asked >= anchor.height) {
                continue;
            }
            record.asked_at = Some(anchor.height);
            wanted.entry(anchor).or_default().push(claim);
        }
        wanted
            .into_iter()
            .map(|(anchor, keys)| {
                Action::Fetch(FetchRequest::StateProof {
                    anchor,
                    keys,
                    preferred: None,
                    class: None,
                })
            })
            .collect()
    }

    /// Take what a fetched proof attests: hold it as proven, close the
    /// questions it answers, and keep the reading to offer in a block
    /// this validator proposes.
    ///
    /// The proof is walked once, on the way into [`ProvenCells`], and
    /// what comes back is the reading. That is what a block carries and
    /// what this validator's vote fence holds another proposer's block
    /// to, so it is recorded whatever the ledger wanted — a proof a peer
    /// relayed answers for a claim rather than for a probe, and the
    /// ledger has no entry waiting on it.
    ///
    /// What the ledger did ask about is what is offered. The probes the
    /// proof spoke to are marked answered, so the question is not put to
    /// the same header again, and the claim is kept beside the
    /// transactions it answered for, dated to the clock the probe read
    /// off the header.
    pub fn on_proof_fetched(
        &mut self,
        anchor: Anchor,
        keys: Vec<SubstateKey>,
        proof: MerkleInclusionProof,
    ) {
        let answered = self.ledger.mark_probes_answered(anchor, &keys);
        let Some(inclusions) = self.proven_cells.record(anchor, keys, proof) else {
            tracing::warn!(
                shard = ?anchor.shard,
                height = anchor.height.inner(),
                "A fetched state proof does not answer for its keys"
            );
            return;
        };
        // A question the proof answered is not put again, and the
        // reading that answered it is the one held to offer: what the
        // answer means is still the chain's to say, and until a block
        // carries the claim nothing here has composed anything from it.
        //
        // One rule for both, because a reading that answers nothing is
        // worth neither. A probe fires from the deadline, and a lapse
        // opens a validity range past it, so the readings taken in
        // between are absences outside their window — true of the tree
        // and mute about the question. Offering one spends a block's
        // cap on a cell no record can be composed from, and holds every
        // voter to a non-answer taken at one height.
        let mut answering: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut speaks_for: BTreeSet<TxHash> = BTreeSet::new();
        for entry in &answered {
            let Some(&(_, inclusion)) = inclusions.iter().find(|(key, _)| *key == entry.key) else {
                continue;
            };
            if entry
                .probed
                .answer(anchor.ts, entry.deadline, inclusion, entry.core)
                .is_some()
            {
                self.ledger
                    .verify_probe(entry.tx_hash, entry.shard, entry.key);
                answering.insert(entry.key);
                speaks_for.insert(entry.tx_hash);
            }
        }
        // An inherited record names no transaction, so what it wants is
        // read off the keys.
        answering.extend(
            inclusions
                .iter()
                .map(|(key, _)| *key)
                .filter(|key| awaited_by(&self.inherited, *key)),
        );
        if answering.is_empty() {
            return;
        }
        let cells = inclusions
            .iter()
            .copied()
            .filter(|(key, _)| answering.contains(key));
        self.fetched
            .entry(StateClaim::new(anchor, cells))
            .or_default()
            .extend(speaks_for);
    }

    /// Fold the claims a committed block carries into the answers every
    /// replica holds, and hand each to the vote fence.
    ///
    /// A claim answers every cell of the ledger's on the anchor's shard
    /// whose window the anchor's clock sits inside — whether or not this
    /// replica had a probe out, and wherever its own probe sat — so a
    /// replica that never fetched reads the same answer as the one that
    /// did. A key found present means the counterpart took the
    /// transaction: a claim cell present is the consumer holding the
    /// crossing, which is written straight to the ledger and licenses
    /// the retirement, and the counterpart's own certificate speaks for
    /// the verdict next. A core consumer's claim absent on a core of
    /// more than one shard says only that a sibling is pending, and is
    /// asked again at the next header.
    /// The first proof to answer a cell is the answer; a later one adds
    /// nothing. The hand-off is a continuation emitted here rather than
    /// a map the fence reads later, so an answer is never collected
    /// before it is drained.
    fn fold_state_claims(&mut self, trie: &ShardTrie, block: &Block) -> Vec<Action> {
        if block.state_claims().is_empty() {
            return Vec::new();
        }
        let cells: Vec<(Probeable, Vec<CounterpartCell>)> = self
            .ledger
            .cells()
            .into_iter()
            .map(|entry| {
                let cells = counterpart_cells(&entry, self.local_shard, trie);
                (entry, cells)
            })
            .collect();
        let mut actions = Vec::new();
        for claim in block.state_claims() {
            actions.extend(self.fold_cells(claim, &cells));
            self.fold_inherited(claim, trie);
        }
        actions
    }

    /// Read a committed proof against the claims the inherited records
    /// are waiting on.
    ///
    /// Judged by the same per-word rule the ledger's cells are: a
    /// presence answers wherever it was taken, since the claim cell is
    /// written by the consuming execution and by nothing else; an
    /// absence answers only inside the window it means something in,
    /// which for a record whose consumer's role the leaf does not name
    /// is the lapse — past it no core of any arity can still commit, so
    /// the silence is final.
    fn fold_inherited(&mut self, stated: &StateClaim, trie: &ShardTrie) {
        for record in self.inherited.values_mut() {
            if record.answer.is_some() {
                continue;
            }
            let claim = record.cell.consumer_claim;
            if trie.shard_for_prefix(claim.owner) != stated.anchor.shard {
                continue;
            }
            let Some(inclusion) = stated.reading(claim) else {
                continue;
            };
            let Some(inclusion) =
                Probed::Delivery.answer(stated.anchor.ts, record.deadline(), inclusion, 0)
            else {
                continue;
            };
            record.answer = Some(inclusion);
        }
    }

    /// Fold the verdicts a committed block's records restate: each is
    /// the counterpart's own word, folded from the chain, so a replica
    /// that never heard the certificate broadcast holds it from the
    /// block alone.
    fn fold_verdict_records(&self, block: &Block) -> Vec<Action> {
        let mut actions = Vec::new();
        for record in block.abandonment_records() {
            if let CounterpartEvidence::Heard(heard) = record.evidence()
                && heard.question == Question::Verdict
            {
                for entry in record.unsettled() {
                    actions.extend(self.fold_verdict(record.shard(), entry.tx_hash, heard));
                }
            }
        }
        actions
    }

    /// Fold one claim's answers into the questions the ledger is
    /// waiting on.
    fn fold_cells(
        &mut self,
        claim: &StateClaim,
        cells: &[(Probeable, Vec<CounterpartCell>)],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for (entry, cells) in cells {
            for &(shard, key, probed) in cells {
                if shard != claim.anchor.shard {
                    continue;
                }
                let Some(inclusion) = claim.reading(key) else {
                    continue;
                };
                // Judged per word and by the one arity rule, whoever
                // fetched the proof: an absence is read only inside
                // its window and only for the arity that writes the
                // cell, a presence wherever it was taken — and a probe
                // never sent may still be answered by a claim a block
                // carries.
                let Some(inclusion) =
                    probed.answer(claim.anchor.ts, entry.deadline, inclusion, entry.core.len())
                else {
                    continue;
                };
                // The question is answered with what the chain read,
                // and a fetch still out for it is released with it. A
                // claim cell present is the consumer holding the
                // crossing, which is what licenses the retirement; a
                // committed cell present says only that the core
                // committed the transaction, and settles nothing.
                let Some(Released(released)) =
                    self.ledger
                        .close_question(entry.tx_hash, shard, key, probed, inclusion)
                else {
                    continue;
                };
                self.released_fetches.extend(released);
                record_reclaim_probe_answered(inclusion.is_present());
                let tx_hash = entry.tx_hash;
                match inclusion {
                    // The counterpart took it, and its certificate
                    // says how. Its broadcast may have missed this
                    // shard, so it is fetched rather than waited for.
                    Inclusion::Present(_) => {
                        actions.push(Action::Fetch(FetchRequest::ExecutionCerts {
                            source_shard: shard,
                            tx_hash,
                            preferred: None,
                            class: None,
                        }));
                    }
                    Inclusion::Absent => {
                        self.mirror.record(
                            tx_hash,
                            shard,
                            Heard {
                                question: Question::Cell(probed),
                                word: Word::Absent,
                                at: claim.anchor.ts,
                            },
                        );
                    }
                }
            }
        }
        actions
    }

    /// Write what the block's records cover into the mirror the gate and
    /// the fence read: neither asks a settled set about a transaction
    /// the chain has established no counterpart can settle.
    fn cover_recorded(&self, block: &Block) {
        for record in block.abandonment_records() {
            for tx_hash in record.tx_hashes() {
                self.mirror.cover(tx_hash);
            }
        }
    }

    /// Fold what `shard` said of `tx_hash` into the mirror the vote
    /// fence reads, and tell the mempool.
    ///
    /// Fed from two directions and read the same way from both: a
    /// certificate arriving by broadcast, and a record the chain
    /// committed, which is the counterpart's own word folded from the
    /// chain rather than from whatever this replica happened to hear —
    /// so a replica that came up between a core's verdict and the
    /// record's proposal holds the same answer its peers do. First
    /// write wins, as the chain's answer is: a second certificate or
    /// record restates a decision already held.
    ///
    /// Only a word this shard has a use for is kept. A core's refusal
    /// is the transaction's verdict, where a leg here issued for it, and
    /// a core shard's acceptance counts toward the transaction being
    /// accepted, which is every core shard saying so. A consumer's
    /// acceptance keeps nothing: it opens the probe whose answer settles
    /// the record held for its claim.
    pub fn fold_verdict(&self, shard: ShardId, tx_hash: TxHash, heard: Heard) -> Vec<Action> {
        if shard == self.local_shard || heard.question != Question::Verdict {
            return Vec::new();
        }
        let Word::Refused { decision, .. } = heard.word else {
            return Vec::new();
        };
        if self.ledger.core_holds(tx_hash, shard)
            && self.ledger.unsettled_figures(tx_hash).is_some()
            && self.mirror.record(tx_hash, shard, heard)
        {
            return vec![Action::Continuation(ProtocolEvent::TransactionsResolved {
                resolutions: vec![(tx_hash, TxResolution::CoreDecided(decision))],
            })];
        }
        Vec::new()
    }

    /// Fold a counterpart's claiming success: the cue to ask whether it
    /// wrote the claim, and — where the shard is in the core — one more
    /// core shard saying the transaction went through.
    ///
    /// Nothing is written down. A success is not evidence: its own
    /// finalization can still be refused afterwards, so what a record
    /// stands on is the claim cell proved present, and this only opens
    /// the question.
    pub fn fold_claimed(
        &mut self,
        shard: ShardId,
        tx_hash: TxHash,
        at: WeightedTimestamp,
    ) -> Vec<Action> {
        if shard == self.local_shard {
            return Vec::new();
        }
        if self.ledger.consumer_holds(tx_hash, shard) {
            self.ledger.cue_probe(tx_hash, at);
        }
        if self.ledger.core_holds(tx_hash, shard) && self.ledger.record_acceptance(tx_hash, shard) {
            return vec![Action::Continuation(ProtocolEvent::TransactionsResolved {
                resolutions: vec![(
                    tx_hash,
                    TxResolution::CoreDecided(TransactionDecision::Accept),
                )],
            })];
        }
        Vec::new()
    }

    /// The readings this validator's own fetches took that no block has
    /// carried yet, in the one order a block carries them, under the
    /// block's cap.
    fn state_claims(&self) -> Vec<StateClaim> {
        self.fetched
            .keys()
            .take(MAX_STATE_CLAIMS_PER_BLOCK)
            .cloned()
            .collect()
    }

    /// Drop the claims no transaction they answered for still needs,
    /// and release every fetch the ledger let go — a question the chain
    /// answered first, or one whose entry is gone — so a counterpart
    /// that never serves the height does not pin the slot.
    fn release_answered_fetches(&mut self) -> Vec<Action> {
        let unresolved = &self.ledger;
        // A claim is worth carrying while something still wants what it
        // answers: a transaction the ledger owes an outcome for, or an
        // inherited record whose claim it speaks to. The second has no
        // transaction here at all, which is why the keys are read rather
        // than the names.
        let inherited = &self.inherited;
        self.fetched.retain(|claim, answered| {
            answered.iter().any(|tx_hash| unresolved.contains(*tx_hash))
                || claim
                    .cells
                    .iter()
                    .any(|(key, _)| awaited_by(inherited, *key))
        });
        // The one retention rule for what counterparts said: an entry
        // there speaks for a transaction this ledger still owes an
        // outcome for, and the ledger is here.
        self.mirror.retain(&|tx_hash| unresolved.contains(tx_hash));
        let ids = std::mem::take(&mut self.released_fetches);
        if ids.is_empty() {
            Vec::new()
        } else {
            vec![Action::AbandonFetch(FetchIds::StateProofs(ids))]
        }
    }

    /// The records this shard has evidence for and has not yet written
    /// down — what each departed counterpart left of its business here.
    ///
    /// Composed from the settled sets, which is what bounds when this can
    /// speak at all: a set is acquired once the departed shard's terminal
    /// roots are attested and dropped at its evidence expiry, so a record
    /// is only ever offered while the evidence for it is readable, which
    /// is the same window every voter can check it in. Absence from a set
    /// is proof rather than ignorance — the set is complete and
    /// beacon-attested — so a transaction of ours it does not name is one
    /// that shard never settled and now never will.
    ///
    /// Bounded by [`MAX_PROPOSAL_EVIDENCE_BYTES`] and by
    /// [`MAX_UNSETTLED_PER_BLOCK`], one of each across every record,
    /// with the remainder left for the next block. The bytes are what
    /// stops first: a name's cost varies with its reach, so the count
    /// alone would admit a section several frames wide.
    ///
    /// The departures are filled before what was heard, so which of them
    /// the budgets reach is the same on every proposer: a departure is
    /// composed from the settled sets, which every replica at a
    /// committed height holds alike, while what a validator has heard is
    /// its own. Truncating loses nothing — a name no record carries
    /// stays uncovered and is offered again next block.
    ///
    /// Ascending by shard, which is the one order a block may carry them
    /// in.
    fn abandonment_records(&self) -> Vec<AbandonmentRecord> {
        let mut budget = Budget::empty();
        // One record per shard and arm, ascending: a departure first,
        // since it covers everything the shard was party to, then one
        // per question for the shards still running, in the order the
        // block carries them.
        let mut records: BTreeMap<(ShardId, Option<Question>), AbandonmentRecord> = BTreeMap::new();
        // The sets are a hash map, so the shards are walked in sorted
        // order rather than its own: which departures the budget reaches
        // must not turn on a per-process iteration order.
        self.mirror.with_settled(|sets| {
            let mut shards: Vec<ShardId> = sets.keys().copied().collect();
            shards.sort_unstable();
            for shard in shards {
                if budget.spent() || records.len() == MAX_ABANDONMENT_RECORDS_PER_BLOCK {
                    break;
                }
                let settled = &sets[&shard];
                let mut unsettled = self.ledger.outstanding_with(shard, settled.terminal_wt);
                unsettled.retain(|entry| !settled.txs.contains(&entry.tx_hash));
                budget.take(&mut unsettled);
                if unsettled.is_empty() {
                    continue;
                }
                let record = AbandonmentRecord::departed(shard, settled.terminal_wt, unsettled);
                records.insert((shard, None), record);
            }
        });
        // What counterparts were heard to say, one record per shard and
        // question, at the shard's earliest anchor: a record states the
        // one moment every name in it was answered at, since one
        // spanning two satisfies the fence's equality check for neither,
        // and the rest waits a block. Nothing is offered beside a
        // departure, which answers for everything the shard was party
        // to.
        let mut heard: HeardByQuestion = BTreeMap::new();
        for (tx_hash, shard, word) in self.mirror.all() {
            let Some(figures) = self.ledger.unsettled_figures(tx_hash) else {
                continue;
            };
            heard
                .entry((shard, word.question))
                .or_default()
                .entry((word.at, word.word))
                .or_default()
                .push(figures);
        }
        for ((shard, question), anchors) in heard {
            if budget.spent() || records.len() == MAX_ABANDONMENT_RECORDS_PER_BLOCK {
                break;
            }
            if records.contains_key(&(shard, None)) {
                continue;
            }
            let Some(((at, word), mut unsettled)) = anchors.into_iter().next() else {
                continue;
            };
            budget.take(&mut unsettled);
            if unsettled.is_empty() {
                continue;
            }
            let evidence = Heard { question, word, at };
            records.insert(
                (shard, Some(question)),
                AbandonmentRecord::heard(shard, evidence, unsettled),
            );
        }
        records.into_values().collect()
    }

    /// Record where each departed shard's chain ended, for the entries
    /// whose fate only that shard's settled set can decide.
    ///
    /// Read on every commit, while the schedule still carries the window
    /// that proves the terminal — the account outlives that window, and a
    /// departure it never recorded reads afterwards as a counterpart that
    /// never left. Re-run rather than gated on first sight, because the
    /// expiry is not knowable at the cut: the beacon stamps the handoff
    /// complete some epochs later, and the ledger's entry fills in on the
    /// first commit after the stamp lands.
    pub fn stamp_departures(
        &mut self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) {
        for (shard, cut) in topology_schedule.departures_at(now) {
            if shard != self.local_shard {
                self.ledger.record_terminal(
                    shard,
                    cut,
                    topology_schedule.handoff_evidence_expiry(shard),
                );
            }
        }
        // A departure held open is asked about by name on every commit,
        // since the schedule lists it only while a retained window
        // carries the shard and the stamp lands on the head's boundary
        // record, which outlives that window. One whose evidence the
        // schedule no longer reads at all closes now — the same reading
        // the settled sets are dropped on — so an entry a record covers
        // against it retires with the set that could have answered.
        for shard in self.ledger.unstamped_departures() {
            if let Some(expiry) = topology_schedule.handoff_evidence_expiry(shard) {
                self.ledger.stamp_terminal(shard, expiry);
            } else if !topology_schedule.terminal_evidence_readable(shard, now) {
                self.ledger.stamp_terminal(shard, now);
            }
        }
    }

    /// Fold every verdict a certificate carries, before it is routed:
    /// the leg's tick settled long ago, so the certificate routes
    /// nowhere, and what it says is the one thing in it this shard still
    /// has a use for.
    pub fn on_certificate(&mut self, ec: &Arc<Verified<ExecutionCertificate>>) -> Vec<Action> {
        let shard = ec.shard_id();
        let mut actions = Vec::new();
        for (tx_hash, spoken) in ec.verdicts() {
            actions.extend(match spoken {
                Spoken::Refused(heard) => self.fold_verdict(shard, tx_hash, heard),
                Spoken::Claimed { at } => self.fold_claimed(shard, tx_hash, at),
            });
        }
        actions
    }

    /// Whether `shard`'s settled set stands in for a commit proof of this
    /// certificate's source block.
    ///
    /// Membership means the transaction's certificate committed in the
    /// departed chain at or before its terminal, and the set itself was
    /// verified against the beacon-attested terminal root — a stronger
    /// statement than a commit proof of one source block, which is
    /// exactly what a departed chain can no longer supply. Every outcome
    /// must be named: one outside the set is a verdict the departed
    /// shard never settled, and a certificate naming nothing gives the
    /// set nothing to vouch for.
    pub fn settled_set_admits(
        &self,
        shard: ShardId,
        cert: &Verifiable<ExecutionCertificate>,
    ) -> bool {
        self.mirror.with_settled(|sets| {
            sets.get(&shard).is_some_and(|settled| {
                let outcomes = cert.tx_outcomes();
                !outcomes.is_empty()
                    && outcomes
                        .iter()
                        .all(|outcome| settled.txs.contains(&outcome.tx_hash()))
            })
        })
    }

    /// Drop settled sets past their evidence window. Past it the gate
    /// rejects any outcome naming the shard regardless of the set, so
    /// retaining it only leaks memory.
    fn gc_settled_sets(&self, topology_schedule: &TopologySchedule, now: WeightedTimestamp) {
        self.mirror
            .retain_departures(&|shard| topology_schedule.terminal_evidence_readable(shard, now));
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, Hash, LocalKey, RoutePrefix, evidence_admits_block,
    };

    use super::*;

    /// One name reaching `routes` prefixes, seeded by `seed`.
    fn name(seed: usize, routes: usize) -> UnsettledTx {
        let byte = u8::try_from(seed % 256).expect("masked");
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(&seed.to_le_bytes())),
            deadline: Deadline::of(WeightedTimestamp::from_millis(60_000)),
            declared_work: 5,
            charge: AbortCharge {
                vault: SubstateKey {
                    owner: Address::new([byte; 31], AddressClass::Component),
                    local: LocalKey([byte; 16]),
                },
                amount: 1,
            },
            reach: (0..routes)
                .map(|at| {
                    RoutePrefix::from(Address::new(
                        [u8::try_from(at % 256).expect("masked"); 31],
                        AddressClass::Component,
                    ))
                })
                .collect(),
        }
    }

    /// A backlog wider than one block's bytes is carried across blocks
    /// with nothing lost: each block takes a prefix of what is offered,
    /// the next takes up where it stopped, and every name is carried by
    /// exactly one.
    #[test]
    fn a_backlog_over_the_byte_budget_drains_across_blocks() {
        let wide = name(0, 6).wire_weight();
        let backlog: Vec<UnsettledTx> = (0..3 * MAX_PROPOSAL_EVIDENCE_BYTES / wide)
            .map(|seed| name(seed, 6))
            .collect();

        let mut left = backlog.clone();
        let mut carried: Vec<UnsettledTx> = Vec::new();
        for _ in 0..8 {
            if left.is_empty() {
                break;
            }
            let mut offered = left.clone();
            Budget::empty().take(&mut offered);
            assert!(!offered.is_empty(), "each block carries something");
            let record = AbandonmentRecord::departed(
                ShardId::ROOT,
                WeightedTimestamp::ZERO,
                offered.clone(),
            );
            assert!(
                evidence_admits_block(record.wire_weight()),
                "and what it carries is a section a voter admits",
            );
            left.drain(..offered.len());
            carried.extend(offered);
        }
        assert!(left.is_empty(), "the backlog drains");
        assert_eq!(
            carried, backlog,
            "each name carried once, in the order offered"
        );
    }

    /// The bytes stop the composer before the names do, which is the
    /// whole point of the second figure: a name's reach is not something
    /// a count can see.
    #[test]
    fn the_bytes_are_what_stops_a_wide_backlog() {
        let mut wide: Vec<UnsettledTx> = (0..MAX_UNSETTLED_PER_BLOCK)
            .map(|seed| name(seed, 6))
            .collect();
        Budget::empty().take(&mut wide);
        assert!(
            wide.len() < MAX_UNSETTLED_PER_BLOCK,
            "the byte budget bites first",
        );
        assert!(evidence_admits_block(
            ABANDONMENT_RECORD_BYTES + wide.iter().map(UnsettledTx::wire_weight).sum::<usize>()
        ));
    }

    /// A budget with bytes to spare still stops at the drain's count:
    /// the two figures answer different questions and neither subsumes
    /// the other.
    #[test]
    fn the_names_are_what_stops_a_narrow_backlog() {
        let narrow = name(0, 0).wire_weight();
        assert!(
            MAX_UNSETTLED_PER_BLOCK * narrow > MAX_PROPOSAL_EVIDENCE_BYTES,
            "a reachless name is still wide enough that the bytes bind at the drain's count",
        );
        let mut budget = Budget::empty();
        budget.bytes = usize::MAX;
        let mut offered: Vec<UnsettledTx> = (0..MAX_UNSETTLED_PER_BLOCK + 10)
            .map(|seed| name(seed, 0))
            .collect();
        budget.take(&mut offered);
        assert_eq!(offered.len(), MAX_UNSETTLED_PER_BLOCK);
    }

    /// A record's own terms are charged once, with the first name it
    /// takes, so a budget spent across several records still leaves room
    /// for each one's header.
    #[test]
    fn a_records_own_terms_are_charged_with_its_first_name() {
        let mut budget = Budget::empty();
        let mut one = vec![name(0, 2)];
        budget.take(&mut one);
        assert_eq!(
            MAX_PROPOSAL_EVIDENCE_BYTES - budget.bytes,
            ABANDONMENT_RECORD_BYTES + name(0, 2).wire_weight(),
        );
        let mut none: Vec<UnsettledTx> = Vec::new();
        let before = budget.bytes;
        budget.take(&mut none);
        assert_eq!(budget.bytes, before, "an empty take charges nothing");
    }
}
