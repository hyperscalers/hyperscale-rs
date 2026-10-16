//! What a block says about a counterpart's cells, and the proof of it.
//!
//! A shard asks a counterpart about the cells a crossing or a member
//! leaves there: a core member asks its siblings' committed cells, a
//! producer asks its consumer's answer to a record it issued, and a
//! consumer reads the record it takes. What is done with the answer, an
//! abandonment licensed or a record retired, returned or taken, is
//! decided by every replica alike, so the answer has to be the chain's
//! rather than a replica's, or the decision splits. That is what a block
//! carries: the claim, one reading per cell against a commit-proven
//! header, and the multiproof the readings were taken from.
//!
//! The proof travels with the claim so that the claim is checkable from
//! the block alone. Every replica walks it at admission under the
//! anchor's root, so a bad proof refuses the block on every replica
//! alike, and a voter never holds a reading to a fetch of its own. What
//! a voter still holds for itself is the anchor: whether the header the
//! claim names is one it commit-proved is the vote fence's question.
//! The proof is over exactly the keys the claim reads, and the section
//! that carries claims is spent by the byte, proof and values included.
//!
//! A reading may carry the cell's value. A crossing record reaches its
//! consumer this way: the bytes ride beside the key, and `verify` holds
//! them to the presence the proof reconstructs, so no hash travels with
//! them and none is trusted.
//!
//! A reading may name the crossing it speaks for. A crossing key is a
//! hash only the crossing's identity derives, so a claim carries the
//! identity beside such a key, and what the reading licenses the commit
//! fold to remove is read off the identity: a consumer's `Taken` read
//! present licenses removing the producer's record, and a record read
//! absent licenses removing its answers where the commit fold judges
//! the absence final: read at a boundary the beacon recorded for the
//! record's shard, with the producing member's exit proven there. The
//! identity is bound to its key by derivation, checked where the
//! claim's form is.
//!
//! A crossing's keys name its edge and no transaction, and an edge is
//! issued again by any later transaction carrying its intent. So an
//! answer read present speaks for one record only: the one whose
//! transaction and validity end the answer's bytes derive from. A
//! presence states the hash of the bytes it proves, and a reader
//! holding the record derives the answers its transaction would hold
//! and compares ([`StateClaim::answers`]). An answer of any other
//! transaction answers nothing for the record.
//!
//! A claim may name the members whose verdict cells it holds. A verdict
//! cell is keyed by a transaction and the anchor's shard, so a name is
//! bound to its cell by derivation as a crossing is, and a consumer's
//! fold takes the row under each name and reads that member's cells at
//! the claim's anchor: its work is bounded by what the block carries and
//! pays for, never by the rows that stand.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Bytes, Capped, Hbor};
use hyperscale_vm_effects::{Answered, CrossingCell, CrossingId, CrossingLeaf, ProtocolHasher};

use crate::state_key::jmt_value_hash;
use crate::{
    Anchor, Inclusion, MAX_HELD_VALUE_BYTES, MAX_PROOFS_PER_QUERY, MerkleInclusionProof,
    RETENTION_HORIZON, STATE_CLAIM_BYTES, STATE_CLAIM_CELL_BYTES, STATE_CLAIM_CROSSING_BYTES,
    STATE_CLAIM_VERDICT_BYTES, ShardId, StateProofError, SubstateKey, TxHash, WeightedTimestamp,
    member_order, verdict_leaf,
};

/// What a claim states of one cell: whether the anchor's root holds it,
/// or the value it holds there.
///
/// [`Inclusion`] stays the proof's vocabulary: no proof yields a held
/// value, so the arm belongs to the claim. A held value is what a
/// consumer reads a crossing record's terms off; every other reader
/// sees it through [`StateClaim::reading`] as the presence it proves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Stated {
    /// Whether the key has a leaf, and its value hash if so.
    Inclusion(Inclusion),
    /// The bytes the key holds under the anchor's root.
    Held(Bytes<MAX_HELD_VALUE_BYTES>),
}

impl From<Inclusion> for Stated {
    fn from(inclusion: Inclusion) -> Self {
        Self::Inclusion(inclusion)
    }
}

impl Stated {
    /// What the proof would say of the cell: a held value is a presence
    /// hashing to it.
    #[must_use]
    pub fn inclusion(&self) -> Inclusion {
        match self {
            Self::Inclusion(inclusion) => *inclusion,
            Self::Held(bytes) => Inclusion::Present(jmt_value_hash(bytes)),
        }
    }

    /// The bytes it holds, if it carries them.
    #[must_use]
    pub fn held(&self) -> Option<&[u8]> {
        match self {
            Self::Inclusion(_) => None,
            Self::Held(bytes) => Some(bytes),
        }
    }

    /// The bytes this reading costs a block beyond the key and the
    /// reading itself: a held value and its length prefix.
    fn value_weight(&self) -> usize {
        self.held().map_or(0, |bytes| bytes.len() + 4)
    }
}

/// One anchor's answers: what a commit-proven header says about each
/// cell asked of it, and the proof that it does.
///
/// The anchor names the shard, the height, the root the reading was
/// taken against and the block's clock, every term of which a voter
/// holds to the commit-proven header it has for the height. The cells
/// are sorted and without repeats, so the claim has one form and a
/// validator checking it walks the order it would build. The proof
/// claims exactly the cells' keys under the anchor's root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct StateClaim {
    /// The commit-proven state the readings were taken against.
    pub anchor: Anchor,
    /// Each cell asked about, with what the anchor's root says of it.
    pub cells: Capped<Vec<(SubstateKey, Stated)>, MAX_PROOFS_PER_QUERY>,
    /// The crossings the readings speak for: for each cell key that is
    /// one of a crossing's three, the identity that derives it, sorted
    /// by key and without repeats. What such a reading licenses the
    /// commit fold to remove is read off the identity, never named by
    /// the proposer. Outside the proof, which proves keys and values;
    /// the derivation is what binds it.
    pub crossings: Capped<Vec<(SubstateKey, CrossingId)>, MAX_PROOFS_PER_QUERY>,
    /// The members whose verdict cells of the anchor's shard the claim
    /// holds, ascending by their order keys and without repeats: the
    /// rows a consumer's fold reads this anchor for. Outside the proof,
    /// as the crossings are; each is bound by deriving a cell of the
    /// claim.
    pub verdicts: Capped<Vec<TxHash>, MAX_PROOFS_PER_QUERY>,
    /// The multiproof the readings were taken from, over exactly the
    /// cells' keys.
    pub proof: MerkleInclusionProof,
}

/// What a proposer holds to offer at one boundary anchor: the claims
/// read there, and which of their cells each answer's deletion, or each
/// record's return, reads.
///
/// A return reads its consumer's `Never` alone. A deletion reads its
/// record's key and its producing member's row leaf, and the member's
/// committed marker where the boundary's clock is short of the
/// transaction's validity end, and they sort apart: one anchor's
/// readings are one key-ordered list cut into claims, so a deletion's
/// cells can sit in different claims. A block that carried a record's
/// absence without the row leaf beside it would delete nothing for the
/// bytes, so what is carried is cut by the deletion and never by the
/// cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryOffer {
    /// The claims held at the anchor, ascending, the spans of their keys
    /// disjoint: the form a block carries one anchor's claims in.
    pub claims: Vec<StateClaim>,
    /// The cells each deletion reads, the deletions in the order a block
    /// short of room for them all carries them.
    pub deletions: Vec<Vec<SubstateKey>>,
}

impl BoundaryOffer {
    /// What the first `deletions` deletions read, every one of them
    /// whole and no cell of any other, as one key-ordered list cut into
    /// claims of [`MAX_PROOFS_PER_QUERY`] cells: each run's cells cut
    /// from the held claims that read them and merged into one claim
    /// (`StateClaim::merge`), so a run takes one place and the nodes
    /// its pieces' proofs share ride once.
    ///
    /// A run whose pieces do not merge rides as the pieces.
    #[must_use]
    pub fn carrying(&self, deletions: usize) -> Vec<StateClaim> {
        let keys: Vec<SubstateKey> = self
            .deletions
            .iter()
            .take(deletions)
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut carried = Vec::new();
        for run in keys.chunks(MAX_PROOFS_PER_QUERY) {
            let (first, last) = (run[0], run[run.len() - 1]);
            let pieces: Vec<StateClaim> = self
                .claims
                .iter()
                .filter(|claim| {
                    claim
                        .cells
                        .first()
                        .zip(claim.cells.last())
                        .is_some_and(|((lo, _), (hi, _))| *lo <= last && first <= *hi)
                })
                .filter_map(|claim| claim.restrict(|key| run.binary_search(&key).is_ok()))
                .collect();
            match StateClaim::merge(&pieces) {
                Some(merged) => carried.push(merged),
                None => carried.extend(pieces),
            }
        }
        carried
    }
}

/// What a block's claims carry, read the one way the commit fold
/// retires it and a proposer passes it over.
///
/// A deletion is one answer's and a return one record's, whatever
/// anchor reads it, so [`Self::deletes`] and [`Self::returns`] ask by
/// key across anchors. `deleted` stays keyed by anchor, as the commit
/// cut is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarriedClaims {
    /// The keys of every claim that names no member, by anchor.
    cells: BTreeMap<Anchor, BTreeSet<SubstateKey>>,
    /// The part of `cells` read by claims that delete and return
    /// nothing. A deletion's row and marker are read again by the next
    /// answer of the same transaction, and a `Never` is a return, so
    /// neither is a cell carried twice.
    read: BTreeMap<Anchor, BTreeSet<SubstateKey>>,
    /// The record keys read absent under their crossing's name
    /// ([`StateClaim::deleting`]), by anchor.
    deleted: BTreeMap<Anchor, BTreeSet<SubstateKey>>,
    /// The `Never` keys read present under their crossing's name
    /// ([`StateClaim::returning`]).
    returned: BTreeSet<SubstateKey>,
    /// The crossings named by claims anchored on the carrying block's
    /// own shard: the ones it reads at its parent.
    local: BTreeSet<CrossingId>,
}

/// How many of what a block carries an earlier block carried too, by
/// kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Recarried {
    /// Cells of claims that delete and return nothing, at one anchor.
    pub cells: usize,
    /// Record keys read absent, at any anchor.
    pub deletions: usize,
    /// `Never` keys read present.
    pub returns: usize,
    /// Crossings read at the parent.
    pub local: usize,
}

impl CarriedClaims {
    /// What `claims`, the claims of one block of `shard`'s, carry.
    #[must_use]
    pub fn of(shard: ShardId, claims: &[StateClaim]) -> Self {
        let mut carried = Self::default();
        for claim in claims {
            if claim.verdicts.is_empty() {
                let keys = claim.keys();
                if claim.deleting().next().is_none() && claim.returning().next().is_none() {
                    carried
                        .read
                        .entry(claim.anchor)
                        .or_default()
                        .extend(keys.iter().copied());
                }
                carried.cells.entry(claim.anchor).or_default().extend(keys);
            }
            let deleting: Vec<SubstateKey> = claim.deleting().collect();
            if !deleting.is_empty() {
                carried
                    .deleted
                    .entry(claim.anchor)
                    .or_default()
                    .extend(deleting);
            }
            carried
                .returned
                .extend(claim.returning().map(|(never, _)| never));
            if claim.anchor.shard == shard {
                carried
                    .local
                    .extend(claim.crossings.iter().map(|(_, id)| *id));
            }
        }
        carried
    }

    /// Add what `other` carries.
    pub fn extend(&mut self, other: &Self) {
        let union = |into: &mut BTreeMap<Anchor, BTreeSet<SubstateKey>>,
                     from: &BTreeMap<Anchor, BTreeSet<SubstateKey>>| {
            for (anchor, keys) in from {
                into.entry(*anchor)
                    .or_default()
                    .extend(keys.iter().copied());
            }
        };
        union(&mut self.cells, &other.cells);
        union(&mut self.read, &other.read);
        union(&mut self.deleted, &other.deleted);
        self.returned.extend(other.returned.iter().copied());
        self.local.extend(other.local.iter().copied());
    }

    /// The keys of claims naming no member, by anchor: what the commit
    /// fold cuts from the claims held to offer.
    #[must_use]
    pub const fn cells(&self) -> &BTreeMap<Anchor, BTreeSet<SubstateKey>> {
        &self.cells
    }

    /// The keys carried at `anchor` by claims naming no member.
    #[must_use]
    pub fn cells_at(&self, anchor: &Anchor) -> Option<&BTreeSet<SubstateKey>> {
        self.cells.get(anchor)
    }

    /// The record keys read absent, by anchor: what the commit fold
    /// cuts from the boundary readings held.
    #[must_use]
    pub const fn deleted(&self) -> &BTreeMap<Anchor, BTreeSet<SubstateKey>> {
        &self.deleted
    }

    /// Whether `record` is read absent at any anchor.
    #[must_use]
    pub fn deletes(&self, record: SubstateKey) -> bool {
        self.deleted.values().any(|keys| keys.contains(&record))
    }

    /// Whether `never` is read present.
    #[must_use]
    pub fn returns(&self, never: SubstateKey) -> bool {
        self.returned.contains(&never)
    }

    /// Whether `id` is read at the carrying block's parent.
    #[must_use]
    pub fn reads_locally(&self, id: &CrossingId) -> bool {
        self.local.contains(id)
    }

    /// How much of what this carries `earlier` carried too: cells this
    /// reads that `earlier` carried at the same anchor, record keys and
    /// `Never` keys by key, and crossings read at the parent.
    #[must_use]
    pub fn recarried(&self, earlier: &Self) -> Recarried {
        let cells = self
            .read
            .iter()
            .filter_map(|(anchor, keys)| {
                let before = earlier.cells.get(anchor)?;
                Some(keys.intersection(before).count())
            })
            .sum();
        let deleted: BTreeSet<SubstateKey> = self.deleted.values().flatten().copied().collect();
        Recarried {
            cells,
            deletions: deleted
                .into_iter()
                .filter(|record| earlier.deletes(*record))
                .count(),
            returns: self.returned.intersection(&earlier.returned).count(),
            local: self.local.intersection(&earlier.local).count(),
        }
    }
}

/// The transaction a crossing record is of and the validity end the
/// record states: with the crossing, everything an answer to that
/// record is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Issuer {
    /// The transaction whose leg wrote the record.
    pub tx: TxHash,
    /// That transaction's validity end, as the record states it.
    pub validity_end_ms: u64,
}

impl From<&CrossingCell> for Issuer {
    fn from(cell: &CrossingCell) -> Self {
        Self {
            tx: cell.tx,
            validity_end_ms: cell.validity_end_ms,
        }
    }
}

impl Issuer {
    /// The issuer of the record `value` is, where `value` is a record of
    /// exactly `id`: read at `id`'s record key, and naming `id`'s
    /// consumer. `None` for any other bytes.
    #[must_use]
    pub fn of_record(id: &CrossingId, value: &[u8]) -> Option<Self> {
        match CrossingLeaf::read(&ProtocolHasher, id.record_key(&ProtocolHasher), value)? {
            CrossingLeaf::Record { crossing, cell } if crossing.id == *id => Some((&cell).into()),
            CrossingLeaf::Record { .. } | CrossingLeaf::Answer { .. } => None,
        }
    }

    /// Whether `value`, read at `id`'s `answered` key, is this issuer's
    /// answer: the test a reader holding the cell itself makes, on the
    /// bytes [`answer_hashes`] hashes.
    #[must_use]
    pub fn answered_by(self, id: &CrossingId, answered: Answered, value: &[u8]) -> bool {
        id.answered_by(self.tx, self.validity_end_ms, answered, value)
    }
}

/// The value hashes a presence of `id`'s `answered` key states where
/// the cell is `issuer`'s answer: one for a `Taken`, two for a `Never`,
/// seen and unseen.
///
/// The hash of each of [`CrossingId::answer_values`], the bytes every
/// writer of an answer writes, so a proven presence binds to the record
/// of one transaction without carrying the answer's value.
#[must_use]
pub fn answer_hashes(id: &CrossingId, issuer: Issuer, answered: Answered) -> Vec<[u8; 32]> {
    id.answer_values(issuer.tx, issuer.validity_end_ms, answered)
        .iter()
        .map(|value| jmt_value_hash(value))
        .collect()
}

/// The three keys `id` derives: its record, its `Taken` and its `Never`.
fn crossing_keys(id: &CrossingId) -> [SubstateKey; 3] {
    [
        id.record_key(&ProtocolHasher),
        id.answer_key(&ProtocolHasher, Answered::Taken),
        id.answer_key(&ProtocolHasher, Answered::Never),
    ]
}

impl StateClaim {
    /// A claim over `cells`, in the one order it may carry them, proven
    /// by `proof`.
    #[must_use]
    pub fn new<S: Into<Stated>>(
        anchor: Anchor,
        cells: impl IntoIterator<Item = (SubstateKey, S)>,
        proof: MerkleInclusionProof,
    ) -> Self {
        let mut cells: Vec<(SubstateKey, Stated)> = cells
            .into_iter()
            .map(|(key, stated)| (key, stated.into()))
            .collect();
        cells.sort_unstable();
        cells.dedup_by_key(|(key, _)| *key);
        // A reading list past the cap is one no claim may carry, and an
        // empty claim is one `is_well_formed` refuses — so an over-cap
        // input lands where it landed before, refused rather than
        // trimmed into a different claim.
        let cells = Capped::new(cells).unwrap_or_default();
        Self {
            anchor,
            cells,
            crossings: Capped::empty(),
            verdicts: Capped::empty(),
            proof,
        }
    }

    /// This claim naming the crossings its readings speak for, in the
    /// one order it may carry them.
    ///
    /// More crossings than the cap is a list no claim may carry. The
    /// claim is then left reading no cell, which `is_well_formed`
    /// refuses, and never well formed with its crossings gone.
    #[must_use]
    pub fn naming(
        mut self,
        crossings: impl IntoIterator<Item = (SubstateKey, CrossingId)>,
    ) -> Self {
        let mut crossings: Vec<(SubstateKey, CrossingId)> = crossings.into_iter().collect();
        crossings.sort_unstable();
        crossings.dedup_by_key(|(key, _)| *key);
        match Capped::new(crossings) {
            Ok(crossings) => self.crossings = crossings,
            Err(_) => self.cells = Capped::empty(),
        }
        self
    }

    /// This claim naming the members whose verdict cells it holds, in
    /// the one order it may carry them.
    ///
    /// More members than the cap is a list no claim may carry. The
    /// claim is then left reading no cell, which `is_well_formed`
    /// refuses, and never well formed with its members gone.
    #[must_use]
    pub fn hearing(mut self, verdicts: impl IntoIterator<Item = TxHash>) -> Self {
        let mut verdicts: Vec<TxHash> = verdicts.into_iter().collect();
        verdicts.sort_unstable();
        verdicts.dedup();
        match Capped::new(verdicts) {
            Ok(verdicts) => self.verdicts = verdicts,
            Err(_) => self.cells = Capped::empty(),
        }
        self
    }

    /// Whether the claim is in the one form it may take: sorted cells,
    /// one reading per key, naming something, no more than the cap,
    /// every crossing named beside a cell of the claim whose key that
    /// crossing derives, every member named whose verdict cell on the
    /// anchor's shard is a cell of the claim, and no member named
    /// beside a crossing or a held value.
    ///
    /// A claim naming no cell answers nothing and would cost a block a
    /// leaf for it, so it is not well-formed rather than merely
    /// pointless. A crossing named against a key it does not derive
    /// would license removing another crossing's cells, so the
    /// derivation is checked here, once, with no state read.
    ///
    /// Members ascend strictly by order key, the first 128 bits of the
    /// hash, which is what keys a verdict cell: two transactions sharing
    /// one share a cell, a shard holds a row for at most one of them,
    /// and a claim naming both is refused, so each cell is named once.
    ///
    /// A claim that names a member is a verdict claim and nothing else.
    /// One that also named a crossing or held a value would raise its
    /// producer's read frontier from among the readings that ride last,
    /// and would be two kinds of claim at once to the budgets a block
    /// weighs its claims against.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.cells.is_empty()
            && (self.verdicts.is_empty() || (self.crossings.is_empty() && !self.holds_a_value()))
            && self.cells.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && self.crossings.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && self
                .crossings
                .iter()
                .all(|(key, id)| self.holds(*key) && crossing_keys(id).contains(key))
            && self
                .verdicts
                .windows(2)
                .all(|pair| member_order(pair[0]) < member_order(pair[1]))
            && self
                .verdicts
                .iter()
                .all(|tx| self.holds(verdict_leaf(self.anchor.shard, *tx)))
    }

    /// Whether this is a verdict claim: one that names a member.
    ///
    /// Read off the claim alone, so the proposer that spends a block's
    /// claims section and every voter that holds the block to it sort
    /// one claim the same way. A well-formed claim that names a member
    /// names no crossing and holds no value, so every well-formed claim
    /// is of exactly one kind.
    #[must_use]
    pub fn is_verdict_claim(&self) -> bool {
        !self.verdicts.is_empty()
    }

    /// Whether the claim is anchored more than [`RETENTION_HORIZON`]
    /// before `block_anchor`, the clock of the block carrying it.
    ///
    /// A fresh reading is at most a horizon old, and a boundary the
    /// beacon recorded is older than that by the time any schedule holds
    /// it, so the age alone tells the two apart, as a function of the
    /// claim and its block that every replica computes alike. That the
    /// anchor is a boundary the beacon recorded is the vote fence's to
    /// hold.
    #[must_use]
    pub fn at_boundary(&self, block_anchor: WeightedTimestamp) -> bool {
        block_anchor.elapsed_since(self.anchor.ts) > RETENTION_HORIZON
    }

    /// Whether the claim reads only what a boundary reading may: it
    /// names no member, holds no value, and reads nothing present under
    /// a crossing it names but that crossing's `Never`.
    ///
    /// What is left is a record read absent under its crossing's name,
    /// which an answer is deleted on; a consumer's `Never` read present
    /// under its crossing's name, which its record is taken back on;
    /// and cells that name nothing: the member row and the committed
    /// marker an exit is proven by. An unnamed cell licenses nothing on
    /// its own at any age.
    #[must_use]
    pub fn reads_as_a_boundary(&self) -> bool {
        self.verdicts.is_empty()
            && !self.holds_a_value()
            && self
                .crossings
                .iter()
                .all(|(key, id)| match self.reading(*key) {
                    Some(Inclusion::Absent) => true,
                    Some(Inclusion::Present(_)) => {
                        *key == id.answer_key(&ProtocolHasher, Answered::Never)
                    }
                    None => false,
                })
    }

    /// Whether the claim reads a crossing's `Never` present under that
    /// crossing's name: the one presence a record is taken back on,
    /// which is read only at a boundary of the shard that wrote it or at
    /// the parent of a chain holding both ends.
    #[must_use]
    pub fn reads_a_never(&self) -> bool {
        self.crossings.iter().any(|(key, id)| {
            *key == id.answer_key(&ProtocolHasher, Answered::Never)
                && matches!(self.reading(*key), Some(Inclusion::Present(_)))
        })
    }

    /// Whether `key` is a cell of the claim.
    fn holds(&self, key: SubstateKey) -> bool {
        self.cells
            .binary_search_by_key(&key, |(cell, _)| *cell)
            .is_ok()
    }

    /// The crossing the reading of `key` speaks for, if it names one.
    #[must_use]
    pub fn crossing_of(&self, key: SubstateKey) -> Option<CrossingId> {
        self.crossings
            .iter()
            .find(|(named, _)| *named == key)
            .map(|(_, id)| *id)
    }

    /// Whether the claim reads `id` answered in `answered`'s role for
    /// the record `issuer` issued: the answer key present, stating the
    /// hash of one of the answers that issuer's transaction would hold.
    ///
    /// A held value is the same test, on the presence it hashes to. The
    /// one test of whose answer a reading is: a presence of any other
    /// bytes is an answer to another transaction's record at the same
    /// key, and licenses nothing against this one.
    #[must_use]
    pub fn answers(&self, id: &CrossingId, issuer: impl Into<Issuer>, answered: Answered) -> bool {
        match self.reading(id.answer_key(&ProtocolHasher, answered)) {
            Some(Inclusion::Present(stated)) => {
                answer_hashes(id, issuer.into(), answered).contains(&stated)
            }
            Some(Inclusion::Absent) | None => false,
        }
    }

    /// The records the readings retire, each with the transaction whose
    /// record it is, ascending and each once: the record of a crossing
    /// whose `Taken` is read present as the answer to that record
    /// ([`Self::answers`]). Every other reading retires nothing.
    ///
    /// `issued` says whose record of a crossing the reader holds: the
    /// record in the state a fold lands on, or the entries a ledger
    /// holds for it. A `Taken` that is no answer to a record `issued`
    /// names retires nothing, so a take of one transaction's record
    /// never removes a later transaction's at the same key.
    ///
    /// The one statement of the rule, read by the root's fold and by
    /// every mirror of it. Each arm reads one reading, so a claim cut
    /// into pieces retires what the whole did. What a record read
    /// absent does to its answers depends on the answers themselves, so
    /// the fold, which reads them, decides it.
    #[must_use]
    pub fn retires<I>(&self, issued: impl Fn(&CrossingId) -> I) -> Vec<(SubstateKey, TxHash)>
    where
        I: IntoIterator<Item = Issuer>,
    {
        let mut retired: Vec<(SubstateKey, TxHash)> = self
            .crossings
            .iter()
            .filter(|(key, id)| *key == id.answer_key(&ProtocolHasher, Answered::Taken))
            .flat_map(|(_, id)| {
                issued(id)
                    .into_iter()
                    .filter(|issuer| self.answers(id, *issuer, Answered::Taken))
                    .map(|issuer| (id.record_key(&ProtocolHasher), issuer.tx))
            })
            .collect();
        retired.sort_unstable();
        retired.dedup();
        retired
    }

    /// The record keys read absent that name their crossing: the
    /// readings that would delete an answer, which the read frontier
    /// licenses from the record's owner alone.
    pub fn deleting(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        self.crossings.iter().filter_map(|(key, id)| {
            (*key == id.record_key(&ProtocolHasher)
                && self.reading(*key) == Some(Inclusion::Absent))
            .then_some(*key)
        })
    }

    /// The `Never` keys read present under their crossing's name, each
    /// with that crossing: the records a block carrying the claim takes
    /// back.
    pub fn returning(&self) -> impl Iterator<Item = (SubstateKey, CrossingId)> + '_ {
        self.crossings.iter().filter_map(|(key, id)| {
            (*key == id.answer_key(&ProtocolHasher, Answered::Never)
                && matches!(self.reading(*key), Some(Inclusion::Present(_))))
            .then_some((*key, *id))
        })
    }

    /// Whether the proof says of every cell what the claim says, under
    /// the anchor's root, and of nothing else.
    ///
    /// The one check a block's claim gets, run by every replica at
    /// admission: the proof is walked over exactly the claim's keys,
    /// and each reading is held to what the walk reconstructed. A
    /// presence must match the proof's presence, hash and all, an
    /// absence its absence, and a held value must hash to the presence
    /// the proof reconstructs for its key.
    ///
    /// # Errors
    ///
    /// As [`StateProofError`] lists them: a proof that does not decode,
    /// misses or exceeds the claim's keys, or reconstructs another root,
    /// and [`StateProofError::ReadingMismatch`] for a reading the proof
    /// does not bear out.
    pub fn verify(&self) -> Result<(), StateProofError> {
        let proven =
            self.proof
                .exact_inclusions(self.anchor.state_root, self.anchor.shard, &self.keys())?;
        if proven
            .iter()
            .zip(self.cells.iter())
            .all(|((_, proved), (_, stated))| *proved == stated.inclusion())
        {
            Ok(())
        } else {
            Err(StateProofError::ReadingMismatch)
        }
    }

    /// The cells this claim answers for.
    #[must_use]
    pub fn keys(&self) -> Vec<SubstateKey> {
        self.cells.iter().map(|(key, _)| *key).collect()
    }

    /// What the claim says of `key`, if it says anything, as the
    /// presence or absence the proof reconstructs: a held value reads
    /// as the presence it hashes to.
    #[must_use]
    pub fn reading(&self, key: SubstateKey) -> Option<Inclusion> {
        self.stated(key).map(Stated::inclusion)
    }

    /// The value the claim carries for `key`, if it carries one.
    #[must_use]
    pub fn held(&self, key: SubstateKey) -> Option<&[u8]> {
        self.stated(key).and_then(Stated::held)
    }

    /// Whether any cell of the claim carries its value.
    #[must_use]
    pub fn holds_a_value(&self) -> bool {
        self.cells.iter().any(|(_, stated)| stated.held().is_some())
    }

    fn stated(&self, key: SubstateKey) -> Option<&Stated> {
        self.cells
            .iter()
            .find(|(asked, _)| *asked == key)
            .map(|(_, stated)| stated)
    }

    /// This claim cut down to the cells `keep` admits, its proof cut
    /// with them, or `None` when nothing is left or the proof cannot be
    /// cut. A crossing or a member named goes exactly where its cell
    /// goes.
    ///
    /// The cut proof is the one a fresh fetch over the kept keys would
    /// bring, so the piece is a claim in its own right: what a proposer
    /// carries when the whole does not fit, and what a composer holds
    /// once a block has carried the rest.
    #[must_use]
    pub fn restrict(&self, keep: impl Fn(SubstateKey) -> bool) -> Option<Self> {
        let cells: Vec<(SubstateKey, Stated)> = self
            .cells
            .iter()
            .filter(|(key, _)| keep(*key))
            .cloned()
            .collect();
        if cells.is_empty() {
            return None;
        }
        if cells.len() == self.cells.len() {
            return Some(self.clone());
        }
        let keys: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
        let proof = self.proof.restrict(&keys).ok()?;
        let crossings: Vec<(SubstateKey, CrossingId)> = self
            .crossings
            .iter()
            .filter(|(key, _)| keys.contains(key))
            .copied()
            .collect();
        let verdicts: Vec<TxHash> = self
            .verdicts
            .iter()
            .filter(|tx| keys.contains(&verdict_leaf(self.anchor.shard, **tx)))
            .copied()
            .collect();
        Some(
            Self::new(self.anchor, cells, proof)
                .naming(crossings)
                .hearing(verdicts),
        )
    }

    /// One claim over every cell `pieces` read, all at one anchor: their
    /// readings, the crossings and members they name, and the union of
    /// their proofs, which carries each node the pieces share once. A
    /// piece is a claim in its own right, so what the merged claim reads
    /// and licenses is what the pieces did together.
    ///
    /// `None` where there is no piece, the pieces stand at different
    /// anchors, read one cell two ways, read more cells than a claim may,
    /// or their proofs are not over one root.
    #[must_use]
    pub(crate) fn merge(pieces: &[Self]) -> Option<Self> {
        let anchor = pieces.first()?.anchor;
        if pieces.iter().any(|piece| piece.anchor != anchor) {
            return None;
        }
        let mut cells: Vec<(SubstateKey, Stated)> = pieces
            .iter()
            .flat_map(|piece| piece.cells.iter().cloned())
            .collect();
        cells.sort_unstable();
        cells.dedup();
        if cells.len() > MAX_PROOFS_PER_QUERY || cells.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return None;
        }
        let proof = MerkleInclusionProof::union(pieces.iter().map(|piece| &piece.proof)).ok()?;
        Some(
            Self::new(anchor, cells, proof)
                .naming(
                    pieces
                        .iter()
                        .flat_map(|piece| piece.crossings.iter().copied()),
                )
                .hearing(
                    pieces
                        .iter()
                        .flat_map(|piece| piece.verdicts.iter().copied()),
                ),
        )
    }

    /// The bytes this claim costs a block: the figures the wire budget
    /// prices its terms, each cell, each crossing named and each member
    /// named at, every value a cell holds, and the proof as it encodes.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        let values: usize = self
            .cells
            .iter()
            .map(|(_, stated)| stated.value_weight())
            .sum();
        STATE_CLAIM_BYTES
            + self.cells.len() * STATE_CLAIM_CELL_BYTES
            + self.crossings.len() * STATE_CLAIM_CROSSING_BYTES
            + self.verdicts.len() * STATE_CLAIM_VERDICT_BYTES
            + values
            + self.proof.as_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::to_vec;
    use hyperscale_vm_effects::{Hash32, IntentHash, Terms};

    use super::*;
    use crate::test_utils::{proven_claim, test_key};
    use crate::{
        Address, AddressClass, BlockHeight, Hash, LocalKey, ResourceAddr, ShardId, StateRoot,
        WeightedTimestamp,
    };

    fn key(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    fn anchor() -> Anchor {
        Anchor {
            shard: ShardId::ROOT,
            height: BlockHeight::new(3),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
            ts: WeightedTimestamp::ZERO,
        }
    }

    /// A verdict claim names a member and nothing else: a claim naming
    /// nobody is not one, and a claim naming a member beside a crossing
    /// or beside a held value is no claim at all. A piece cut from a
    /// verdict claim is one wherever it keeps a verdict cell.
    #[test]
    fn a_verdict_claim_names_a_member_and_nothing_else() {
        let shard = ShardId::leaf(1, 0);
        let tx = TxHash::from(Hash::from_bytes(b"member"));
        let leaf = verdict_leaf(shard, tx);
        let id = CrossingId {
            producer: key(0x21).owner,
            consumer: key(0x22).owner,
            intent: IntentHash(Hash32([0x21; 32])),
            local: 0,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let bare = proven_claim(shard, 3, &[leaf], &[leaf]);
        assert!(bare.is_well_formed() && !bare.is_verdict_claim());
        let verdict = bare.hearing([tx]);
        assert!(verdict.is_well_formed() && verdict.is_verdict_claim());

        let named = proven_claim(shard, 3, &[leaf], &[leaf, record]).naming([(record, id)]);
        assert!(named.is_well_formed() && !named.is_verdict_claim());
        let crossing = named.hearing([tx]);
        assert_eq!(crossing.verify(), Ok(()));
        assert!(
            !crossing.is_well_formed(),
            "a member named beside a crossing",
        );

        let mut valued = verdict;
        valued.cells = Capped::from_array([(leaf, Stated::Held(Bytes::new(vec![7]).unwrap()))]);
        assert!(!valued.is_well_formed(), "a member named beside a value");
        valued.verdicts = Capped::empty();
        assert!(valued.is_well_formed() && !valued.is_verdict_claim());

        let beside = test_key(3);
        let wide = proven_claim(shard, 3, &[leaf], &[leaf, beside]).hearing([tx]);
        assert!(wide.is_well_formed() && wide.is_verdict_claim());
        let cut = wide
            .restrict(|kept| kept == leaf)
            .expect("the verdict cell");
        assert!(cut.is_well_formed() && cut.is_verdict_claim());
    }

    /// One form: whatever order a caller offers, the claim it builds is
    /// the claim every other builder would have produced.
    #[test]
    fn a_claim_is_built_in_its_canonical_order() {
        let present = Inclusion::Present([7u8; 32]);
        let jumbled = StateClaim::new(
            anchor(),
            [
                (key(3), Inclusion::Absent),
                (key(1), present),
                (key(3), Inclusion::Absent),
                (key(2), present),
            ],
            MerkleInclusionProof::dummy(),
        );
        let ordered = StateClaim::new(
            anchor(),
            [
                (key(1), present),
                (key(2), present),
                (key(3), Inclusion::Absent),
            ],
            MerkleInclusionProof::dummy(),
        );
        assert_eq!(jumbled, ordered);
        assert!(jumbled.is_well_formed());
        assert_eq!(jumbled.reading(key(1)), Some(present));
        assert_eq!(jumbled.reading(key(3)), Some(Inclusion::Absent));
        assert_eq!(jumbled.reading(key(4)), None);
    }

    /// Empty, repeating, or out of order is a second form of the same
    /// claim, or no claim at all.
    #[test]
    fn a_claim_out_of_its_form_is_refused() {
        let over = |cells: Vec<(SubstateKey, Inclusion)>| StateClaim {
            anchor: anchor(),
            cells: Capped::new(cells.into_iter().map(|(key, i)| (key, i.into())).collect())
                .expect("a list written out in a test"),
            crossings: Capped::empty(),
            verdicts: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        };
        assert!(!over(Vec::new()).is_well_formed());
        assert!(
            !over(vec![
                (key(2), Inclusion::Absent),
                (key(1), Inclusion::Absent)
            ])
            .is_well_formed()
        );
        assert!(
            !over(vec![
                (key(1), Inclusion::Absent),
                (key(1), Inclusion::Absent)
            ])
            .is_well_formed()
        );
    }

    /// A claim whose proof bears out every reading verifies; one whose
    /// reading disagrees with its proof, whose proof answers for a key
    /// the claim does not read, or whose anchor names another root does
    /// not.
    #[test]
    fn a_claim_is_held_to_its_proof() {
        let (held, missing) = (test_key(1), test_key(2));
        let claim = proven_claim(ShardId::ROOT, 3, &[held], &[held, missing]);
        assert_eq!(claim.verify(), Ok(()));
        assert!(claim.reading(held).is_some_and(Inclusion::is_present));
        assert_eq!(claim.reading(missing), Some(Inclusion::Absent));

        let mut flipped = claim.clone();
        flipped.cells = Capped::new(vec![
            (held, Inclusion::Absent.into()),
            (missing, Inclusion::Absent.into()),
        ])
        .expect("two cells");
        assert_eq!(flipped.verify(), Err(StateProofError::ReadingMismatch));

        let narrower = StateClaim::new(
            claim.anchor,
            [(held, claim.reading(held).unwrap())],
            claim.proof.clone(),
        );
        assert_eq!(narrower.verify(), Err(StateProofError::ExtraClaim));

        let mut other_root = claim.clone();
        other_root.anchor.state_root = StateRoot::from_raw(Hash::from_bytes(b"another"));
        assert_eq!(other_root.verify(), Err(StateProofError::RootMismatch));

        let mut bit_flipped = claim;
        let mut bytes = bit_flipped.proof.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        bit_flipped.proof = MerkleInclusionProof::new(bytes);
        assert!(bit_flipped.verify().is_err());
    }

    /// A claim may carry a cell's value. It keeps one canonical form,
    /// round-trips, reads as the presence it hashes to, weighs its
    /// bytes, and verifies only where the proof's presence is that hash:
    /// one byte changed refuses, and so does a value where the proof
    /// says absent.
    #[test]
    fn a_held_value_is_held_to_the_proof() {
        use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

        let (held, missing) = (test_key(1), test_key(2));
        let bare = proven_claim(ShardId::ROOT, 3, &[held], &[held, missing]);
        // The fixture tree's leaf value is the key's own bytes.
        let value = held.to_bytes().to_vec();
        let carrying = StateClaim::new(
            bare.anchor,
            [
                (held, Stated::Held(Bytes::new(value.clone()).unwrap())),
                (missing, Inclusion::Absent.into()),
            ],
            bare.proof.clone(),
        );
        assert_eq!(carrying.verify(), Ok(()));
        assert_eq!(carrying.held(held), Some(value.as_slice()));
        assert_eq!(carrying.held(missing), None);
        assert_eq!(carrying.reading(held), bare.reading(held));
        assert!(carrying.holds_a_value() && !bare.holds_a_value());
        assert_eq!(
            carrying.wire_weight(),
            bare.wire_weight() + value.len() + 4,
            "a held value costs its bytes and a length prefix",
        );
        let encoded = hbor_to_vec(&carrying).unwrap();
        assert!(encoded.len() <= carrying.wire_weight());
        assert_eq!(hbor_from_slice::<StateClaim>(&encoded).unwrap(), carrying);

        let mut altered = value.clone();
        altered[0] ^= 0x01;
        let forged = StateClaim::new(
            bare.anchor,
            [
                (held, Stated::Held(Bytes::new(altered).unwrap())),
                (missing, Inclusion::Absent.into()),
            ],
            bare.proof.clone(),
        );
        assert_eq!(forged.verify(), Err(StateProofError::ReadingMismatch));

        let absent_held = StateClaim::new(
            bare.anchor,
            [
                (held, bare.reading(held).unwrap().into()),
                (missing, Stated::Held(Bytes::new(value).unwrap())),
            ],
            bare.proof,
        );
        assert_eq!(absent_held.verify(), Err(StateProofError::ReadingMismatch));
    }

    /// A claim cut by key is a claim in its own right: the piece
    /// verifies on its own, and the cut proof is what a fetch over the
    /// kept keys alone would bring.
    #[test]
    fn a_claim_cut_by_key_still_proves_its_piece() {
        let (a, b, c) = (test_key(1), test_key(2), test_key(3));
        let whole = proven_claim(ShardId::ROOT, 3, &[a, c], &[a, b, c]);
        let piece = whole.restrict(|key| key != b).expect("two cells kept");
        assert_eq!(piece.keys(), vec![a, c]);
        assert_eq!(piece.verify(), Ok(()));
        assert_eq!(
            piece,
            proven_claim(ShardId::ROOT, 3, &[a, c], &[a, c]),
            "the piece is the claim a narrower fetch would have built",
        );
        assert!(whole.restrict(|_| false).is_none());
        assert_eq!(whole.restrict(|_| true), Some(whole.clone()));
        assert!(piece.wire_weight() < whole.wire_weight());
    }

    fn crossing(seed: u8) -> CrossingId {
        CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed.wrapping_add(1); 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    /// A claim over `readings`, each named for `id` where the reading
    /// speaks for it.
    fn speaking(readings: Vec<(SubstateKey, Inclusion, Option<CrossingId>)>) -> StateClaim {
        StateClaim::new(
            anchor(),
            readings
                .iter()
                .map(|(key, inclusion, _)| (*key, *inclusion)),
            MerkleInclusionProof::dummy(),
        )
        .naming(
            readings
                .into_iter()
                .filter_map(|(key, _, id)| id.map(|id| (key, id))),
        )
    }

    /// A reading names only a crossing that derives its key, and what
    /// it licenses is read off the identity: a `Taken` present removes
    /// the record, a record absent removes both answers, and a record
    /// present, an answer absent, a `Never` present or a bare reading
    /// remove nothing.
    #[test]
    fn a_reading_speaks_for_the_crossing_that_derives_its_key() {
        let id = crossing(0x31);
        let other = crossing(0x32);
        let [record, taken, never] = crossing_keys(&id);
        let present = Inclusion::Present([7; 32]);

        assert!(speaking(vec![(taken, present, Some(id))]).is_well_formed());
        assert!(
            !speaking(vec![(taken, present, Some(other))]).is_well_formed(),
            "a crossing is named only beside a key it derives",
        );
        assert!(
            !StateClaim::new(anchor(), [(record, present)], MerkleInclusionProof::dummy())
                .naming([(taken, id)])
                .is_well_formed(),
            "and only beside a cell the claim reads",
        );

        let issuer = Issuer {
            tx: member(1),
            validity_end_ms: 60_000,
        };
        let held = |named: &CrossingId| (*named == id).then_some(issuer);
        let stating = |answered| Inclusion::Present(answer_hashes(&id, issuer, answered)[0]);
        let (took, declined) = (stating(Answered::Taken), stating(Answered::Never));
        assert_eq!(
            speaking(vec![(taken, took, Some(id))]).retires(held),
            vec![(record, issuer.tx)],
            "the consumer's Taken of the record's transaction retires the record",
        );
        assert!(
            speaking(vec![(taken, present, Some(id))])
                .retires(held)
                .is_empty(),
            "a Taken stating any other bytes is no answer to this record",
        );
        assert!(
            speaking(vec![(taken, took, Some(id))])
                .retires(|_| None)
                .is_empty(),
            "and a Taken retires nothing where no record of its crossing is held",
        );
        assert!(
            speaking(vec![(record, Inclusion::Absent, Some(id))])
                .retires(held)
                .is_empty(),
            "a record read absent retires nothing; its answers are the fold's",
        );
        assert!(
            speaking(vec![(record, took, Some(id))])
                .retires(held)
                .is_empty()
        );
        assert!(
            speaking(vec![(taken, Inclusion::Absent, Some(id))])
                .retires(held)
                .is_empty()
        );
        assert!(
            speaking(vec![(never, declined, Some(id))])
                .retires(held)
                .is_empty()
        );
        assert!(speaking(vec![(taken, took, None)]).retires(held).is_empty());

        let deleting: Vec<SubstateKey> = speaking(vec![
            (record, Inclusion::Absent, Some(id)),
            (taken, Inclusion::Absent, Some(id)),
        ])
        .deleting()
        .collect();
        assert_eq!(deleting, vec![record], "only the record's absence deletes");

        let named = speaking(vec![(taken, present, Some(id))]);
        let bare = speaking(vec![(taken, present, None)]);
        assert_eq!(
            named.wire_weight(),
            bare.wire_weight() + STATE_CLAIM_CROSSING_BYTES,
            "the crossing named is paid for",
        );
        assert_eq!(named.crossing_of(taken), Some(id));
        assert_eq!(bare.crossing_of(taken), None);
    }

    /// A reading answers for a record only where it states the bytes
    /// that record's transaction would hold: its `Taken`, or its `Never`
    /// seen or unseen, bare or as a held value. The same key stating
    /// another transaction's answer, the same transaction's under
    /// another validity end, or the other role's bytes answers nothing.
    #[test]
    fn an_answer_binds_to_the_record_of_its_own_transaction() {
        let id = crossing(0x34);
        let [_, taken, never] = crossing_keys(&id);
        let issuer = Issuer {
            tx: member(1),
            validity_end_ms: 60_000,
        };
        let later = Issuer {
            tx: member(2),
            ..issuer
        };
        let extended = Issuer {
            validity_end_ms: 60_001,
            ..issuer
        };
        let reads = |key: SubstateKey, value: Vec<u8>, held: bool| {
            let stated = if held {
                Stated::Held(Bytes::new(value).expect("an answer fits"))
            } else {
                Stated::Inclusion(Inclusion::Present(jmt_value_hash(&value)))
            };
            StateClaim::new(anchor(), [(key, stated)], MerkleInclusionProof::dummy())
                .naming([(key, id)])
        };
        let took = id
            .answer(issuer.tx, Answered::Taken, issuer.validity_end_ms)
            .to_bytes();
        let declined = id
            .answer(issuer.tx, Answered::Never, issuer.validity_end_ms)
            .to_bytes();
        let unseen = id
            .unseen_never(issuer.tx, issuer.validity_end_ms)
            .to_bytes();
        assert_eq!(answer_hashes(&id, issuer, Answered::Taken).len(), 1);
        assert_eq!(
            answer_hashes(&id, issuer, Answered::Never),
            vec![jmt_value_hash(&declined), jmt_value_hash(&unseen)],
        );

        for held in [false, true] {
            let claim = reads(taken, took.clone(), held);
            assert!(claim.answers(&id, issuer, Answered::Taken));
            assert!(!claim.answers(&id, issuer, Answered::Never));
            assert!(!claim.answers(&id, later, Answered::Taken));
            assert!(!claim.answers(&id, extended, Answered::Taken));

            for value in [&declined, &unseen] {
                let claim = reads(never, value.clone(), held);
                assert!(claim.answers(&id, issuer, Answered::Never));
                assert!(!claim.answers(&id, issuer, Answered::Taken));
                assert!(!claim.answers(&id, later, Answered::Never));
                assert!(!claim.answers(&id, extended, Answered::Never));
            }
            assert!(
                !reads(never, took.clone(), held).answers(&id, issuer, Answered::Never),
                "a Taken's bytes at the decline key are no decline",
            );
        }
        let absent = StateClaim::new(
            anchor(),
            [(taken, Inclusion::Absent)],
            MerkleInclusionProof::dummy(),
        )
        .naming([(taken, id)]);
        assert!(!absent.answers(&id, issuer, Answered::Taken));

        for (answered, value) in [
            (Answered::Taken, &took),
            (Answered::Never, &declined),
            (Answered::Never, &unseen),
        ] {
            assert!(issuer.answered_by(&id, answered, value));
            assert!(!later.answered_by(&id, answered, value));
            assert!(!extended.answered_by(&id, answered, value));
        }
        let record = id.cell(
            issuer.tx,
            ResourceAddr::new([0xE1; 31]),
            5,
            issuer.validity_end_ms,
            Terms::Owed,
        );
        assert_eq!(Issuer::of_record(&id, &record.to_bytes()), Some(issuer));
        let stranger = CrossingId {
            consumer: Address::new([0x7F; 31], AddressClass::Component),
            ..id
        };
        assert_eq!(Issuer::of_record(&stranger, &record.to_bytes()), None);
        assert_eq!(Issuer::of_record(&id, &took), None);
    }

    /// A crossing named beside its key encodes inside the bytes the
    /// budget prices it at.
    #[test]
    fn a_named_crossing_fits_its_priced_bytes() {
        let id = crossing(0xFF);
        let encoded = to_vec(&(crossing_keys(&id)[0], id)).expect("a key and an identity encode");
        assert!(
            encoded.len() <= STATE_CLAIM_CROSSING_BYTES,
            "{} bytes over {STATE_CLAIM_CROSSING_BYTES}",
            encoded.len(),
        );
    }

    /// A claim cut by key keeps the crossings named beside the keys it
    /// keeps and no other.
    #[test]
    fn a_cut_claim_keeps_the_crossings_of_the_keys_it_keeps() {
        let id = crossing(0x33);
        let [record, taken, _] = crossing_keys(&id);
        let (a, b) = if record < taken {
            (record, taken)
        } else {
            (taken, record)
        };
        let whole = proven_claim(ShardId::ROOT, 3, &[a], &[a, b]).naming([(a, id), (b, id)]);
        assert!(whole.is_well_formed());
        let piece = whole.restrict(|key| key == a).expect("one cell kept");
        assert_eq!(
            piece.crossings.iter().copied().collect::<Vec<_>>(),
            vec![(a, id)]
        );
        assert!(piece.is_well_formed());
    }

    fn member(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    /// A second transaction keyed where `tx` is: the same first 128 bits
    /// of the hash, which is all a verdict cell's key reads of it.
    fn sharing_the_key_of(tx: TxHash) -> TxHash {
        let mut bytes = *tx.as_bytes();
        bytes[31] ^= 0x01;
        TxHash::from(Hash::from_hash_bytes(&bytes))
    }

    /// A claim at the root shard reading `leaves` present.
    fn holding(leaves: &[SubstateKey]) -> StateClaim {
        StateClaim::new(
            anchor(),
            leaves
                .iter()
                .map(|leaf| (*leaf, Inclusion::Present([7; 32]))),
            MerkleInclusionProof::dummy(),
        )
    }

    /// A member is named only where its verdict cell on the anchor's
    /// shard is a cell of the claim: not beside another member's cell,
    /// not beside its own cell on another shard, not out of order and
    /// not twice. A name is paid for.
    #[test]
    fn a_verdict_name_binds_only_its_leaf_cell() {
        let (first, second) = (member(1), member(2));
        let leaf = |tx: TxHash| verdict_leaf(ShardId::ROOT, tx);
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };

        let bare = holding(&[leaf(first)]);
        let named = bare.clone().hearing([first]);
        assert!(bare.is_well_formed() && named.is_well_formed());
        assert_eq!(
            named.wire_weight(),
            bare.wire_weight() + STATE_CLAIM_VERDICT_BYTES,
            "the member named is paid for",
        );
        assert!(
            !holding(&[leaf(first)]).hearing([second]).is_well_formed(),
            "a member is named only beside its own verdict cell",
        );
        assert!(
            !holding(&[key(3)]).hearing([first]).is_well_formed(),
            "and beside no other cell",
        );
        assert!(
            !holding(&[verdict_leaf(ShardId::leaf(1, 1), first)])
                .hearing([first])
                .is_well_formed(),
            "the cell is the one the anchor's own shard keys",
        );

        let both = holding(&[leaf(first), leaf(second)]);
        assert!(both.clone().hearing([second, first]).is_well_formed());
        let written = |names: Vec<TxHash>| StateClaim {
            verdicts: Capped::new(names).expect("a list written out in a test"),
            ..both.clone()
        };
        assert!(written(vec![low, high]).is_well_formed());
        assert!(!written(vec![high, low]).is_well_formed(), "names ascend");
        assert!(
            !written(vec![low, low]).is_well_formed(),
            "and none repeats"
        );
    }

    /// Two transactions sharing the first 128 bits of their hashes share
    /// one verdict cell. A claim names either of them beside it, and
    /// never both: the cell is one shard's word on one member.
    #[test]
    fn two_names_under_one_leaf_key_are_refused() {
        let tx = member(4);
        let twin = sharing_the_key_of(tx);
        let leaf = verdict_leaf(ShardId::ROOT, tx);
        assert_ne!(tx, twin);
        assert_eq!(leaf, verdict_leaf(ShardId::ROOT, twin));

        assert!(holding(&[leaf]).hearing([tx]).is_well_formed());
        assert!(holding(&[leaf]).hearing([twin]).is_well_formed());
        assert!(!holding(&[leaf]).hearing([tx, twin]).is_well_formed());
    }

    /// A claim cut by key keeps a member named exactly where it keeps
    /// that member's verdict cell, so no cut strands a name or drops
    /// one whose cell rides on.
    #[test]
    fn a_cut_claim_keeps_the_names_of_the_leaves_it_keeps() {
        let (first, second) = (member(1), member(2));
        let (a, b, other) = (
            verdict_leaf(ShardId::ROOT, first),
            verdict_leaf(ShardId::ROOT, second),
            test_key(3),
        );
        let whole =
            proven_claim(ShardId::ROOT, 3, &[a, other], &[a, b, other]).hearing([first, second]);
        assert!(whole.is_well_formed());
        assert_eq!(whole.verify(), Ok(()));

        let piece = whole.restrict(|key| key != b).expect("two cells kept");
        assert_eq!(piece.verdicts.iter().copied().collect::<Vec<_>>(), [first]);
        assert!(piece.is_well_formed());
        assert_eq!(piece.verify(), Ok(()));

        let rest = whole.restrict(|key| key == other).expect("one cell kept");
        assert!(rest.verdicts.is_empty() && rest.is_well_formed());
        assert_eq!(whole.restrict(|_| true), Some(whole));
    }

    /// A builder handed more names than a claim may carry does not lose
    /// them quietly: the claim it returns is one no block may carry, for
    /// members and for crossings alike, and a list at the cap is kept
    /// whole.
    #[test]
    fn names_past_the_cap_leave_no_well_formed_claim() {
        let count = u16::try_from(MAX_PROOFS_PER_QUERY + 1).expect("a small cap");
        let numbered = |at: u16| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&at.to_be_bytes());
            TxHash::from(Hash::from_hash_bytes(&bytes))
        };
        let leaf = verdict_leaf(ShardId::ROOT, numbered(0));

        let at_the_cap = holding(&[leaf]).hearing((0..count - 1).map(numbered));
        assert_eq!(at_the_cap.verdicts.len(), MAX_PROOFS_PER_QUERY);
        assert_eq!(at_the_cap.cells.len(), 1);

        let over = holding(&[leaf]).hearing((0..count).map(numbered));
        assert!(over.verdicts.is_empty() && over.cells.is_empty());
        assert!(!over.is_well_formed());

        let id = crossing(0x35);
        let keyed = |at: u16| {
            let mut local = [0u8; 16];
            local[..2].copy_from_slice(&at.to_be_bytes());
            SubstateKey {
                owner: Address::new([0x35; 31], AddressClass::Component),
                local: LocalKey(local),
            }
        };
        let over = holding(&[leaf]).naming((0..count).map(|at| (keyed(at), id)));
        assert!(over.crossings.is_empty() && over.cells.is_empty());
        assert!(!over.is_well_formed());
    }

    /// A member named encodes inside the bytes the budget prices it at.
    #[test]
    fn a_named_verdict_fits_its_priced_bytes() {
        let encoded = to_vec(&member(0xFF)).expect("a hash encodes");
        assert!(
            encoded.len() <= STATE_CLAIM_VERDICT_BYTES,
            "{} bytes over {STATE_CLAIM_VERDICT_BYTES}",
            encoded.len(),
        );
        let leaves: Vec<SubstateKey> = (1..=40)
            .map(|seed| verdict_leaf(ShardId::ROOT, member(seed)))
            .collect();
        let named = holding(&leaves).hearing((1..=40).map(member));
        assert!(named.is_well_formed());
        let encoded = to_vec(&named).expect("a claim encodes").len();
        assert!(
            encoded <= named.wire_weight(),
            "{encoded} bytes over the {} its weight claims",
            named.wire_weight(),
        );
    }

    /// Pieces merge only into a claim each of them could have been cut
    /// from: none at two anchors, none reading one cell two ways, none
    /// past the cells a claim may read, and none whose proofs stand
    /// over different roots.
    #[test]
    fn pieces_that_no_one_claim_could_read_do_not_merge() {
        let (a, b) = (test_key(1), test_key(2));
        let whole = proven_claim(ShardId::ROOT, 3, &[a], &[a, b]);
        let piece_a = whole.restrict(|key| key == a).expect("a kept");
        let piece_b = whole.restrict(|key| key == b).expect("b kept");
        assert_eq!(
            StateClaim::merge(&[piece_a.clone(), piece_b.clone()]),
            Some(whole),
            "honest pieces merge back to the whole",
        );

        let mut later = piece_b;
        later.anchor.height = BlockHeight::new(4);
        assert_eq!(
            StateClaim::merge(&[piece_a.clone(), later]),
            None,
            "two anchors",
        );

        let absent_a = StateClaim::new(
            piece_a.anchor,
            [(a, Inclusion::Absent)],
            piece_a.proof.clone(),
        );
        assert_eq!(
            StateClaim::merge(&[piece_a.clone(), absent_a]),
            None,
            "one cell read present in one piece and absent in another",
        );

        let numbered = |at: u16| {
            let mut local = [0u8; 16];
            local[..2].copy_from_slice(&at.to_be_bytes());
            SubstateKey {
                owner: Address::new([0x41; 31], AddressClass::Component),
                local: LocalKey(local),
            }
        };
        let count = u16::try_from(MAX_PROOFS_PER_QUERY + 1).expect("a small cap");
        let keys: Vec<SubstateKey> = (0..count).map(numbered).collect();
        let (low, high) = keys.split_at(MAX_PROOFS_PER_QUERY / 2);
        let low = proven_claim(ShardId::ROOT, 3, &keys[..1], low);
        let high = proven_claim(ShardId::ROOT, 3, &keys[..1], high);
        assert_eq!(low.anchor, high.anchor);
        assert_eq!(
            StateClaim::merge(&[low, high]),
            None,
            "more cells than a claim may read",
        );

        let other = proven_claim(ShardId::ROOT, 3, &[a, b], &[b]);
        assert_ne!(other.anchor.state_root, piece_a.anchor.state_root);
        let mut over_another_root = other;
        over_another_root.anchor = piece_a.anchor;
        assert_eq!(
            StateClaim::merge(&[piece_a, over_another_root]),
            None,
            "proofs over different roots",
        );
    }

    /// The claims of one block in [`CarriedClaims`]'s terms: a fresh
    /// fetch's cells at its anchor, a deletion's record and row, a
    /// return's `Never`, and the crossings read at the block's parent.
    /// A verdict claim's cells are none of them.
    struct Carriers {
        own: ShardId,
        older: Anchor,
        newer: Anchor,
        parent: Anchor,
    }

    impl Carriers {
        fn new() -> Self {
            let own = ShardId::leaf(1, 0);
            let at = |shard, height: u64| Anchor {
                shard,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::from_bytes(&height.to_le_bytes())),
                ts: WeightedTimestamp::from_millis(height * 1_000),
            };
            Self {
                own,
                older: at(ShardId::leaf(1, 1), 3),
                newer: at(ShardId::leaf(1, 1), 7),
                parent: at(own, 9),
            }
        }

        fn crossing(seed: u8) -> CrossingId {
            CrossingId {
                producer: key(0x21).owner,
                consumer: key(0x22).owner,
                intent: IntentHash(Hash32([seed; 32])),
                local: 0,
                output: 0,
            }
        }

        fn fetched(at: Anchor, keys: &[SubstateKey]) -> StateClaim {
            StateClaim::new(
                at,
                keys.iter().map(|key| (*key, Inclusion::Present([1; 32]))),
                MerkleInclusionProof::dummy(),
            )
        }

        fn deleting(at: Anchor, id: CrossingId, row: SubstateKey) -> StateClaim {
            let record = id.record_key(&ProtocolHasher);
            StateClaim::new(
                at,
                [
                    (record, Inclusion::Absent),
                    (row, Inclusion::Present([2; 32])),
                ],
                MerkleInclusionProof::dummy(),
            )
            .naming([(record, id)])
        }

        fn returning(at: Anchor, id: CrossingId) -> StateClaim {
            let never = id.answer_key(&ProtocolHasher, Answered::Never);
            StateClaim::new(
                at,
                [(never, Inclusion::Present([3; 32]))],
                MerkleInclusionProof::dummy(),
            )
            .naming([(never, id)])
        }

        fn local(at: Anchor, id: CrossingId) -> StateClaim {
            let record = id.record_key(&ProtocolHasher);
            StateClaim::new(
                at,
                [(record, Inclusion::Present([4; 32]))],
                MerkleInclusionProof::dummy(),
            )
            .naming([(record, id)])
        }
    }

    /// A block's claims are read into what each retires: every cell of a
    /// claim naming no member at its anchor, a record read absent at any
    /// anchor, a `Never` read present, and the crossings a claim at the
    /// block's own shard names. A verdict claim's cells are not carried.
    #[test]
    fn what_a_block_carries_is_read_off_its_claims() {
        let Carriers {
            own,
            older,
            newer,
            parent,
        } = Carriers::new();
        let (deleted, returned, local) = (
            Carriers::crossing(1),
            Carriers::crossing(2),
            Carriers::crossing(3),
        );
        let row = key(0x31);
        let member = TxHash::from(Hash::from_bytes(b"member"));
        let claims = [
            Carriers::fetched(older, &[key(1), key(2)]),
            Carriers::deleting(older, deleted, row),
            Carriers::returning(newer, returned),
            Carriers::local(parent, local),
            Carriers::fetched(newer, &[verdict_leaf(newer.shard, member)]).hearing([member]),
        ];
        let carried = CarriedClaims::of(own, &claims);
        let record = deleted.record_key(&ProtocolHasher);
        assert_eq!(
            carried.cells_at(&older),
            Some(&BTreeSet::from([key(1), key(2), record, row])),
        );
        assert_eq!(
            carried.cells_at(&newer),
            Some(&BTreeSet::from([
                returned.answer_key(&ProtocolHasher, Answered::Never)
            ])),
            "the verdict claim's leaf is not carried",
        );
        assert_eq!(
            carried.deleted(),
            &BTreeMap::from([(older, BTreeSet::from([record]))]),
        );
        assert!(carried.deletes(record) && !carried.deletes(row));
        assert!(carried.returns(returned.answer_key(&ProtocolHasher, Answered::Never)));
        assert!(!carried.returns(deleted.answer_key(&ProtocolHasher, Answered::Never)));
        assert!(carried.reads_locally(&local));
        assert!(
            !carried.reads_locally(&deleted) && !carried.reads_locally(&returned),
            "only the crossings named at the block's own shard are read at its parent",
        );
        assert_eq!(
            claims
                .iter()
                .flat_map(|claim| claim.returning().map(|(_, id)| id))
                .collect::<Vec<_>>(),
            vec![returned],
        );
    }

    /// A repeat is counted once by kind: a cell a fresh claim reads at
    /// the anchor an earlier block carried it at, a record read absent
    /// again at any anchor, a `Never` read again, and a crossing read
    /// again at the parent. A deletion's row read again beside another
    /// record is no repeat: the next answer of the same transaction
    /// reads it.
    #[test]
    fn a_repeat_is_counted_once_by_kind() {
        let Carriers {
            own,
            older,
            newer,
            parent,
        } = Carriers::new();
        let (deleted, other, returned, local) = (
            Carriers::crossing(1),
            Carriers::crossing(4),
            Carriers::crossing(2),
            Carriers::crossing(3),
        );
        let row = key(0x31);
        let earlier = CarriedClaims::of(
            own,
            &[
                Carriers::fetched(older, &[key(1), key(2)]),
                Carriers::deleting(older, deleted, row),
                Carriers::returning(newer, returned),
                Carriers::local(parent, local),
            ],
        );
        let later = CarriedClaims::of(
            own,
            &[
                Carriers::fetched(older, &[key(2), key(3)]),
                Carriers::fetched(newer, &[key(1)]),
                Carriers::deleting(newer, deleted, row),
                Carriers::deleting(older, other, row),
                Carriers::returning(older, returned),
                Carriers::local(
                    Anchor {
                        height: BlockHeight::new(10),
                        ..parent
                    },
                    local,
                ),
            ],
        );
        assert_eq!(
            later.recarried(&earlier),
            Recarried {
                cells: 1,
                deletions: 1,
                returns: 1,
                local: 1,
            },
        );
        assert_eq!(
            later.recarried(&CarriedClaims::default()),
            Recarried::default()
        );
        let mut both = earlier;
        both.extend(&later);
        assert_eq!(both.recarried(&both).deletions, 2);
        assert!(both.deletes(other.record_key(&ProtocolHasher)));
    }
}
