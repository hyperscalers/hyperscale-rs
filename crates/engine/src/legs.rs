//! Which legs of a transaction this shard runs.
//!
//! Turns a transaction's frozen star plus a placement into the
//! [`LegPlan`] the kernel executes. Pure and node-independent: nothing
//! here consults the executing node, because two shards divide one
//! manifest separately and their answers have to agree, or a crossing is
//! issued that nobody claims. Every placement fact a plan reads is
//! frozen in the [`Classified`] the committing block took, so two
//! replicas planning one tick under different topology heads still plan
//! it the same.
//!
//! The star is sources → middle → sinks and the middle is one unit, so a
//! shard's work for one transaction is its inbound legs, its share of the
//! core if it is in the core set, and its outbound legs — and the only
//! thing any of it waits for is the arrivals its own legs consume. There
//! is no visit index and no re-entry.
//!
//! A leg whose home is in the core set is not a leg. It runs in the core
//! member on its shard, passes its value directly, and is replicated
//! where the core is: a shard's sides and an edge's claimants are both
//! read off which shards run a node, and a leg beside the core on its
//! own shard would otherwise be departed into a record its consumer, on
//! the same shard, could never be handed.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_types::{
    Address, EscrowedValue, Role, ShardId, ShardTrie, SubstateKey, Transaction, TxHash,
    WeightedTimestamp,
};
use hyperscale_vm_effects::{
    Answered, CrossingCell, CrossingEdge as StarEdge, CrossingId, Kind, Star, star_at,
};
use hyperscale_vm_kernel::{Arrival, Crossed, Departure, LegPlan, OwnerSet, PlanFault};
use hyperscale_vm_types::{
    DeclaredWork, LegShape, MAX_CROSSINGS_PER_TX, PriceTable, ProtocolHasher, Quanta,
};

use crate::sharding::TrieShardResolver;

/// One value edge whose producer and consumer do not run together, under
/// the protocol's shard identifiers.
pub(crate) type CrossingEdge = StarEdge<ShardId>;

/// Where a classification resolves an owner.
///
/// Two states rather than a trie that stands in for both, because the
/// question `local_work` and `judges_for` ask is "is this owner mine",
/// and a classification with no placement behind it answers yes to all
/// of them. A single-leaf trie answers that only for
/// [`ShardId::ROOT`](hyperscale_types::ShardId::ROOT) and answers `no`
/// everywhere else, which is the whole share silently dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Placement {
    /// Read against a trie: an owner is `shard`'s when the trie routes
    /// its prefix there.
    Read(Arc<ShardTrie>),
    /// No placement read, so every owner is the asker's: the shape runs
    /// whole wherever it runs.
    Whole,
}

impl Placement {
    /// Whether `shard` holds `owner` under this placement.
    fn holds(&self, owner: Address, shard: ShardId) -> bool {
        match self {
            Self::Read(trie) => trie.shard_for_prefix(owner) == shard,
            Self::Whole => true,
        }
    }
}

/// What a shard runs of a transaction, frozen at the placement its block
/// committed: the star its shape implies under the trie the block
/// committed under, and which of its shards commit it.
///
/// Taken once, at one placement, and carried from there — every consumer
/// reads this and none re-derives it, so a reshape landing between
/// composition and execution cannot leave one shard running a whole
/// manifest while its counterpart waits to be sent half of it, and two
/// replicas whose topology heads flipped at different moments plan one
/// tick alike. Only [`Self::freeze`] can answer that a transaction
/// divides; [`Self::whole`] is the always-correct answer for a caller
/// with no placement to freeze against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    /// Where the classification resolves an owner, and whether it read a
    /// placement at all.
    placement: Placement,
    /// The star: whether the shape divides, each node's settled role and
    /// home, the core set, and every edge that crosses.
    star: Star<ShardId>,
    /// The shards that commit the transaction when it divides: every
    /// shard running a node it does not only take delivery of.
    committing: BTreeSet<ShardId>,
}

impl Classified {
    /// Freeze `legs` against `trie`: the classifier's star, and off it
    /// which shards commit. Nothing else enters — the trie is the one
    /// placement fact, and it changes only at a cut, where the shard
    /// leaving it commits nothing more — so every shard and every replica
    /// committing the transaction under one trie freezes one shape.
    ///
    /// The classifier reads no window. A shard scheduled to leave the
    /// trie divides like any other, in its final window too: a record
    /// cell follows its prefix to the successor, and a record's reading
    /// reaches whoever holds its consumer's prefix when it is pushed or
    /// read. A rule that read the
    /// block's window here would flip at the boundary into that window
    /// while the trie did not, and two shards committing one transaction
    /// on either side of it would freeze different shapes.
    ///
    /// `payer` and `accounts` are the routing the envelope declares
    /// beyond any node's frame: the fee payer, whose home bears the core
    /// where no node can, and the accounts its intents act as. The two
    /// are held to different rules — a payer needs a shard that commits,
    /// an account a shard the core waits on — which is why they arrive
    /// apart rather than folded into one list.
    #[must_use]
    pub fn freeze(
        legs: &[LegShape],
        payer: Address,
        accounts: &[Address],
        trie: &ShardTrie,
    ) -> Self {
        let trie = Arc::new(trie.clone());
        let placement = Placement::Read(Arc::clone(&trie));
        let star = star_at(legs, payer, accounts, &TrieShardResolver { trie: &trie })
            .map_shards(|shard| ShardId::from_heap_index(shard.0));
        let committing = if star.decomposes {
            star.committing()
        } else {
            BTreeSet::new()
        };
        Self {
            placement,
            star,
            committing,
        }
    }

    /// The whole shape on every participant, with no placement read.
    #[must_use]
    pub const fn whole() -> Self {
        Self {
            placement: Placement::Whole,
            star: Star::whole(),
            committing: BTreeSet::new(),
        }
    }

    /// The trie this classification was read against, where it read one.
    ///
    /// `None` from [`Self::whole`], which answers for a participant that
    /// runs everything — so a caller asking which owners are elsewhere
    /// has its answer without a trie: none of them are.
    #[must_use]
    pub fn placement(&self) -> Option<&ShardTrie> {
        match &self.placement {
            Placement::Read(trie) => Some(trie),
            Placement::Whole => None,
        }
    }

    /// Whether `shard` commits this transaction: every participant of a
    /// shape that runs whole, and for one that divides, every shard
    /// running a node it does not only take delivery of.
    ///
    /// A shard running nothing but deliveries never includes the
    /// transaction. Its owed crossings are credited by its commit fold
    /// off the records' readings, and nothing it does bears a verdict or
    /// issues a crossing.
    #[must_use]
    pub fn commits_at(&self, shard: ShardId) -> bool {
        !self.decomposed() || self.committing.contains(&shard)
    }

    /// The shards among `participants` that commit this transaction.
    #[must_use]
    pub fn committing(&self, participants: impl IntoIterator<Item = ShardId>) -> BTreeSet<ShardId> {
        participants
            .into_iter()
            .filter(|shard| self.commits_at(*shard))
            .collect()
    }

    /// Whether the legs run where their state lives. Only
    /// [`Self::freeze`] can say yes; [`Self::whole`] never does.
    #[must_use]
    pub const fn decomposed(&self) -> bool {
        self.star.decomposes
    }

    /// The shards the core's nodes sit on.
    #[must_use]
    pub const fn core(&self) -> &BTreeSet<ShardId> {
        &self.star.core
    }

    /// Whether `shard` runs each of the manifest's `nodes` nodes, in
    /// node order.
    ///
    /// What a member bears, which is more than what its shard holds. A
    /// shape that runs whole runs every node on every participant. One
    /// that divides runs the nodes homed here that are not delivered
    /// here, and every core node once the core reaches here — so a
    /// multi-shard core replicates its nodes onto each of its shards and
    /// each of them burns their ceilings.
    ///
    /// The count is the caller's because [`Self::whole`] reads no
    /// placement and so holds no node list; a frozen classification's
    /// own is the same figure.
    ///
    /// Read for what a block reserves against its caps. Answered for a
    /// shard the transaction's routing reaches; a shard it does not
    /// reach runs nothing and is never asked.
    #[must_use]
    pub(crate) fn runs_at(&self, shard: ShardId, nodes: usize) -> Vec<bool> {
        if !self.decomposed() {
            return vec![true; nodes];
        }
        (0..u32::try_from(nodes).unwrap_or(u32::MAX))
            .map(|node| runs(&self.star, node, shard))
            .collect()
    }

    /// What `tx` declares against `shard` under the placement this
    /// classification froze: the shares of the owners the shard holds,
    /// the terms of the nodes its members run, and what every
    /// committing shard bears. What a block on that shard reserves
    /// against its caps, and what its outcome attests.
    ///
    /// Off the classification rather than off placement alone, because a
    /// shard runs more nodes than it holds: a shape that runs whole runs
    /// all of them, and one that divides replicates its core onto every
    /// core shard. Effects and footprint still follow placement — a cell
    /// is excluded and written where it lives — so those shares sum to
    /// the whole across a trie, while compute and the artifacts
    /// instantiation reads sum past it by the replication, and by one
    /// verification of the signatures per shard beyond the first.
    ///
    /// # Panics
    ///
    /// On a transaction that was never derived, as `Transaction::work`.
    #[must_use]
    pub fn local_work(&self, tx: &Transaction, shard: ShardId) -> DeclaredWork {
        let here = self.runs_at(shard, tx.node_terms().len());
        let with_nodes = here
            .iter()
            .zip(tx.node_terms())
            .filter(|(runs, _)| **runs)
            .fold(tx.everywhere(), |total, (_, term)| {
                total.saturating_add(*term)
            });
        // One artifact read per package this shard instantiates, however
        // many of that package's nodes it runs — and none for a package
        // it runs no node of.
        let with_artifacts = tx.artifacts().iter().fold(with_nodes, |total, artifact| {
            if artifact
                .nodes
                .iter()
                .any(|node| here.get(*node as usize).copied().unwrap_or(false))
            {
                total.saturating_add(DeclaredWork {
                    read_bytes: artifact.read_bytes,
                    ..DeclaredWork::ZERO
                })
            } else {
                total
            }
        });
        tx.shares()
            .iter()
            .filter(|share| self.placement.holds(share.owner, shard))
            .fold(with_artifacts, |total, share| {
                total.saturating_add(share.work)
            })
    }

    /// What `shard` attests for `tx` under `table`: the price of
    /// [`Self::local_work`], raised by the signed priority. What its
    /// outcome carries and the beacon weighs its emission by; the payer
    /// burns `Transaction::price`, the whole.
    ///
    /// # Panics
    ///
    /// As [`Self::local_work`].
    #[must_use]
    pub fn local_price(&self, tx: &Transaction, shard: ShardId, table: &PriceTable) -> Quanta {
        table.price(&self.local_work(tx, shard), tx.terms().priority_bp)
    }

    /// The value edges that cross, in `(producer, output)` order.
    ///
    /// None when the shape runs whole: every participant runs every
    /// node, so nothing is handed between them.
    #[must_use]
    pub fn edges(&self) -> &[CrossingEdge] {
        if self.decomposed() {
            &self.star.edges
        } else {
            &[]
        }
    }

    /// Every crossing of the shape with its consumer's frozen home: the
    /// shard the consuming node was homed on when the transaction
    /// committed. A cut moves the consumer's cells to whoever holds its
    /// prefix now, which a caller resolves off the trie it is given; the
    /// frozen home is what a probe asks first.
    ///
    /// The one fold every reader of the edges filters: on `from` for
    /// what a shard issued, on `to` for what it consumes, on the kind
    /// for which family the crossing is, and the keys come off the
    /// crossing's own identity. Empty for a whole shape, which hands
    /// nothing between shards.
    pub fn crossings(&self) -> impl Iterator<Item = (&CrossingEdge, ShardId)> {
        self.edges()
            .iter()
            .map(|edge| (edge, self.home(edge.consumer)))
    }

    /// The escrowed records `local` issues, ascending: what a departure
    /// of the transaction's consumers takes back there.
    ///
    /// # Panics
    ///
    /// Never: a star carries at most [`MAX_CROSSINGS_PER_TX`] edges.
    #[must_use]
    pub fn escrowed_records(
        &self,
        local: ShardId,
    ) -> Capped<Vec<SubstateKey>, MAX_CROSSINGS_PER_TX> {
        let records: BTreeSet<SubstateKey> = self
            .edges()
            .iter()
            .filter(|edge| edge.from == local && edge.crossing.kind == Kind::Escrowed)
            .map(|edge| edge.crossing.id.record_key(&ProtocolHasher))
            .collect();
        Capped::new(records.into_iter().collect()).expect("a star's edges are capped")
    }

    /// The edges `local` consumes and may refuse: the escrowed ones,
    /// which a core member consumes.
    ///
    /// Whether a consumer may refuse is decided here, off the frozen
    /// classification. An escrowed edge's consumer is a core node, so
    /// only a core member consumes one; an owed edge's consumer runs in
    /// no member, and its fold's credit is never refused. The producer
    /// writes `Terms::Owed` exactly for an owed edge, off the same flag.
    pub fn refusable_consumed(&self, local: ShardId) -> impl Iterator<Item = &CrossingEdge> {
        self.edges()
            .iter()
            .filter(move |edge| edge.crossing.kind == Kind::Escrowed && edge.to.contains(&local))
    }

    /// What `local` runs of the transaction, what arrives for it, and
    /// what departs from it.
    ///
    /// Every node that runs here and is not delivered here: an owed
    /// crossing's consumer runs in no member, since the consumer's
    /// commit fold credits it.
    ///
    /// `arrivals` is what committed bundles attested for the edges this
    /// member consumes — read, never derived. `validity_end` is the
    /// transaction's own, which every record it departs states.
    ///
    /// # Errors
    ///
    /// [`PlanDefect`], on its own terms — never a smaller plan.
    pub fn plan(
        &self,
        arrivals: &[EscrowedValue],
        local: ShardId,
        validity_end: WeightedTimestamp,
    ) -> Result<ShardPlan, PlanDefect> {
        if !self.decomposed() {
            return Ok(ShardPlan::whole());
        }
        let runs_here = |node: u32| runs(&self.star, node, local);
        let mut plan = LegPlan::whole(self.star.homes.len());
        let mut participant = false;
        for node in 0..self.star.nodes() {
            if runs_here(node) {
                participant = true;
            } else {
                plan.skip(node)?;
            }
        }
        if !participant {
            return Err(PlanDefect::NotAParticipant);
        }
        for edge in &self.star.edges {
            if runs_here(edge.consumer) && !runs_here(edge.producer) {
                let arrived = arrivals
                    .iter()
                    .find(|value| (value.node, value.output) == (edge.producer, edge.output))
                    .ok_or(PlanDefect::MissingArrival {
                        node: edge.producer,
                        output: edge.output,
                    })?;
                // A refusable arrival files the decline cell its
                // refusal would write, so the take screen covers it.
                let id = edge.crossing.id;
                plan.arrives(
                    edge.producer,
                    edge.output,
                    &Arrival {
                        crossed: Crossed {
                            resource: arrived.resource,
                            amount: arrived.amount,
                        },
                        claim: id.answer_key(&ProtocolHasher, Answered::Taken),
                        crossing: edge.crossing,
                        never: (edge.crossing.kind == Kind::Escrowed)
                            .then(|| id.answer_key(&ProtocolHasher, Answered::Never)),
                        validity_end_ms: validity_end.as_millis(),
                    },
                )?;
            } else if runs_here(edge.producer) && !runs_here(edge.consumer) {
                plan.departs(
                    edge.producer,
                    edge.output,
                    Departure {
                        record: edge.crossing.id.record_key(&ProtocolHasher),
                        crossing: edge.crossing,
                        validity_end_ms: validity_end.as_millis(),
                    },
                )?;
            }
        }
        Ok(ShardPlan {
            legs: plan,
            judges: self.judges_for(local),
        })
    }

    /// The node's home. A node past the manifest has none, and answers
    /// the root — a shard no leaf is, so nothing matches it.
    fn home(&self, node: u32) -> ShardId {
        self.star
            .homes
            .get(node as usize)
            .copied()
            .unwrap_or(ShardId::ROOT)
    }

    /// What `local` judges: the core set if it is in it, itself
    /// otherwise.
    fn judges_for(&self, local: ShardId) -> OwnerSet {
        let Placement::Read(trie) = &self.placement else {
            // Nothing was placed, so nothing is elsewhere: a participant
            // running the whole shape judges every owner in it.
            return OwnerSet::whole();
        };
        let trie = Arc::clone(trie);
        if self.star.core.contains(&local) {
            let core = self.star.core.clone();
            OwnerSet::of(move |owner| core.contains(&trie.shard_for_prefix(owner)))
        } else {
            OwnerSet::of(move |owner| trie.shard_for_prefix(owner) == local)
        }
    }
}

/// What `transactions` reserve on `shard` under `trie` between them:
/// each one's local share, folded.
///
/// The one fold, so the proposer stamping a header, the voter checking
/// it, and the admission that judges the block against its caps all
/// reach the same figure — a second spelling of the sum would be a
/// header whose claim nothing else agrees with.
#[must_use]
pub fn local_work_over<'a>(
    transactions: impl IntoIterator<Item = &'a Transaction>,
    trie: &ShardTrie,
    shard: ShardId,
) -> DeclaredWork {
    transactions
        .into_iter()
        .fold(DeclaredWork::ZERO, |total, tx| {
            total.saturating_add(
                Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie)
                    .local_work(tx, shard),
            )
        })
}

/// Whether `node` runs in `local`'s member: it runs on `local`, and is
/// not an owed crossing's consumer there, which the consumer's commit
/// fold credits and no member runs.
fn runs(star: &Star<ShardId>, node: u32, local: ShardId) -> bool {
    star.running(node).contains(&local) && !star.delivers_at(node, local)
}

/// One shard's member of a frozen transaction.
///
/// Every per-member quantity is a function of the frozen classification,
/// where the member runs and what the transaction reaches. Derived once here and asked by name, so a
/// consumer reads the question it means and cannot reach another's answer
/// except through its own name.
///
/// The two that look alike stay apart, and the sets they read are why.
/// [`reaches_beyond`](Self::reaches_beyond) asks whether the transaction
/// touches another shard at all, off the participants;
/// [`abortable`](Self::abortable) asks whether *this member's*
/// settlement waits on another shard, off what it awaits. A leg of a
/// divided transaction reaches beyond and is not abortable — it awaits
/// only itself — and reading either for the other is how a member's
/// writes get held provisional that nothing can retract, or released
/// that something can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    classified: Classified,
    local: ShardId,
    /// Every shard the transaction touches. Beside the classification
    /// because a whole shape's member awaits all of them, and no frozen
    /// answer names them.
    participating: BTreeSet<ShardId>,
}

impl Member {
    /// The member `local` runs of a transaction frozen as `classified`
    /// and reaching `participating`.
    #[must_use]
    pub const fn of(
        classified: Classified,
        local: ShardId,
        participating: BTreeSet<ShardId>,
    ) -> Self {
        Self {
            classified,
            local,
            participating,
        }
    }

    /// The member a caller with no placement to freeze against runs:
    /// the whole transaction, on its own shard, reaching nobody else.
    #[must_use]
    pub fn whole(local: ShardId) -> Self {
        Self::of(Classified::whole(), local, BTreeSet::from([local]))
    }

    /// The classification this member was frozen against.
    #[must_use]
    pub const fn classified(&self) -> &Classified {
        &self.classified
    }

    /// The shard running it.
    #[must_use]
    pub const fn local(&self) -> ShardId {
        self.local
    }

    /// Every shard the transaction touches. Who of them is owed this
    /// member's certificate is the tick's membership's question.
    #[must_use]
    pub const fn reach(&self) -> &BTreeSet<ShardId> {
        &self.participating
    }

    /// Whether the transaction reaches beyond this shard — the fact that
    /// makes its writes provisional and its verdict a counterpart's to
    /// share. Off the participants, never off what this member awaits.
    #[must_use]
    pub fn reaches_beyond(&self) -> bool {
        self.participating.iter().any(|&shard| shard != self.local)
    }

    /// Whether a counterpart's verdict can still discard this member's
    /// effects after it executes. Off what this member awaits, never off
    /// what the transaction reaches.
    #[must_use]
    pub fn abortable(&self) -> bool {
        self.awaited().iter().any(|&shard| shard != self.local)
    }

    /// Whose certificate this member's settlement waits on: the whole
    /// core set for a member of it, every participant for a whole shape,
    /// and itself otherwise.
    #[must_use]
    pub fn awaited(&self) -> BTreeSet<ShardId> {
        if !self.classified.decomposed() {
            self.participating.clone()
        } else if self.in_core() {
            self.classified.core().clone()
        } else {
            BTreeSet::from([self.local])
        }
    }

    /// What this shard is to the transaction, in the word its
    /// certificate will carry.
    ///
    /// The one classification of a member, so whether its certificate
    /// decides, whether it executes and whether a counterpart may ask
    /// about it are all read off [`Role`] rather than off predicates
    /// restating it here.
    #[must_use]
    pub fn role(&self) -> Role {
        if !self.classified.decomposed() {
            Role::Whole
        } else if self.in_core() {
            Role::Core
        } else {
            Role::Leg
        }
    }

    /// Whether this shard's nodes sit in the core set.
    #[must_use]
    pub fn in_core(&self) -> bool {
        self.classified.core().contains(&self.local)
    }
}

/// What a member runs of its transaction: the shape its committing
/// block froze, or the reclaim of the records a producer here left.
///
/// A reclaim names cells and not a manifest. That is what lets a
/// shard holding the record and no body compose one — a reshape
/// successor, whose store arrives as a prefix of leaves and whose ledger
/// begins empty: the record leaf says which cells the member touches,
/// and the transaction is a name on the receipt rather than an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Runs {
    /// The transaction as classified at commit — whole, or the legs
    /// this shard's placement gives it.
    Shape(Member),
    /// No node at all: the records of crossings a producer here issued
    /// that no consumer will take, credited back and removed.
    Reclaim {
        /// The member the reclaim runs as: whole, on its own shard,
        /// reaching nobody else.
        member: Member,
        /// The record cells to take back, each with the evidence that
        /// licenses it. One the commit fold has already removed, or one
        /// its evidence does not bind, is skipped, not refused: the rest
        /// are still this member's.
        records: Vec<(SubstateKey, Unclaimable)>,
        /// Whether this shard settled the transaction's price already.
        /// A leg that ran burned it inside its writes at its own
        /// finalization; one that never ran — held for a bundle that
        /// never came — owes it still, and the reclaim's receipt is the
        /// one of this shard's left to carry it. An inherited record's
        /// price was settled by the chain that dissolved.
        charged: bool,
    },
}

/// What licenses taking one record back: the evidence the engine binds
/// to the record it reads before it credits anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unclaimable {
    /// The consumer's `Never`, read present at `read`.
    Never {
        /// The decline cell the reading was of.
        read: SubstateKey,
    },
    /// A verdict that `tx` was never settled by the consumer: a departure
    /// naming it, or its own entry's.
    IssuedBy {
        /// The transaction the verdict names.
        tx: TxHash,
    },
}

impl Unclaimable {
    /// Whether this evidence speaks for the record at `key`: a `Never`
    /// read at the decline cell its own crossing derives, or a verdict
    /// naming the transaction that issued it.
    #[must_use]
    pub fn binds(self, key: SubstateKey, cell: &CrossingCell) -> bool {
        match self {
            Self::Never { read } => {
                CrossingId::of_record(key.owner, cell).answer_key(&ProtocolHasher, Answered::Never)
                    == read
            }
            Self::IssuedBy { tx } => cell.tx == tx,
        }
    }
}

impl Runs {
    /// The member this runs as.
    #[must_use]
    pub const fn member(&self) -> &Member {
        match self {
            Self::Shape(member) | Self::Reclaim { member, .. } => member,
        }
    }

    /// Whether the transaction reaches beyond the running shard. A
    /// reclaim reaches nobody: every cell it touches is a record this
    /// shard holds.
    #[must_use]
    pub fn reaches_beyond(&self) -> bool {
        match self {
            Self::Shape(member) => member.reaches_beyond(),
            Self::Reclaim { .. } => false,
        }
    }

    /// Whether a counterpart's verdict can still discard this member's
    /// effects after it executes. Nothing retracts a reclaim.
    #[must_use]
    pub fn abortable(&self) -> bool {
        match self {
            Self::Shape(member) => member.abortable(),
            Self::Reclaim { .. } => false,
        }
    }

    /// Whether the transaction's price was levied on this shard already,
    /// so this member charges nothing: a reclaim on a leg that ran, or on
    /// a record whose transaction was priced elsewhere.
    #[must_use]
    pub(crate) const fn charged_already(&self) -> bool {
        match self {
            Self::Shape(_) => false,
            Self::Reclaim { charged, .. } => *charged,
        }
    }
}

/// The `Never` answer `tx` writes for `edge`: the decline cell under the
/// consuming node's target, and its bytes naming the producer whose
/// record it answers for.
///
/// Derived through the crossing's one identity, so the member's refusal
/// receipt and the abandonment cannot derive two different cells.
#[must_use]
pub fn never_answer(
    tx: TxHash,
    validity_end_ms: u64,
    edge: &CrossingEdge,
) -> (SubstateKey, Vec<u8>) {
    let id = edge.crossing.id;
    (
        id.answer_key(&ProtocolHasher, Answered::Never),
        id.answer(tx, Answered::Never, validity_end_ms).to_bytes(),
    )
}

/// What one shard runs of a transaction, and the scope it judges under.
#[derive(Clone, Debug)]
pub struct ShardPlan {
    /// Which nodes this shard runs, what arrives for them, and what
    /// departs from them.
    pub legs: LegPlan,
    /// What this shard judges before any body runs: its own shard for a
    /// leg member, the whole core set for a core member.
    pub judges: OwnerSet,
}

impl ShardPlan {
    /// The plan every execution ran before there was anything else to
    /// run: nothing skipped, nothing crossing, every owner in scope.
    #[must_use]
    pub(crate) fn whole() -> Self {
        Self {
            legs: LegPlan::whole(0),
            judges: OwnerSet::whole(),
        }
    }
}

/// What a plan cannot be built from.
///
/// Every arm here is reachable only from a malformed input, and each is
/// stated rather than smoothed over: a plan that invented value would
/// credit an execution with something nobody certified, and a plan that
/// dropped one reaches its consumer as a missing producer edge — an
/// outcome priced to nobody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanDefect {
    /// A consumer this shard runs takes an edge from a producer it does
    /// not run, and nothing attested arrived for it.
    #[error("nothing arrived for edge ({node}, {output})")]
    MissingArrival {
        /// The producing node.
        node: u32,
        /// Which of its outputs.
        output: u32,
    },
    /// This shard runs nothing of the transaction.
    #[error("this shard runs no leg of the transaction")]
    NotAParticipant,
    /// What the plan itself refuses: an edge acted on twice, an action
    /// disagreeing with who runs the node, or more crossings than one
    /// outcome can state a verdict for.
    #[error(transparent)]
    Fault(#[from] PlanFault),
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Address, AddressClass, LocalKey, MAX_INTENT_VALIDITY_RANGE, SubstateKey,
    };
    use hyperscale_vm_effects::{CrossingAnswer, CrossingId, Hash32, IntentHash};
    use hyperscale_vm_types::{LegRole, ResourceAddr, ValueEdge};

    use super::*;

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

    /// The fixtures' one validity end; nothing here reads a clock.
    const VALIDITY_END: WeightedTimestamp = WeightedTimestamp::from_millis(1_000);

    /// An owner whose top bit is `high`, which is what a depth-one trie
    /// splits on.
    fn owner(seed: u8, high: bool) -> Address {
        let mut body = [seed; 31];
        body[0] = if high { 0x80 | seed } else { seed & 0x7F };
        Address::new(body, AddressClass::Component)
    }

    /// An owner on the `path`th leaf of a uniform depth-2 trie.
    fn owner_at(seed: u8, path: u8) -> Address {
        let mut body = [seed; 31];
        body[0] = (path << 6) | (seed & 0x3F);
        Address::new(body, AddressClass::Component)
    }

    fn cell(owner: Address, slot: u8) -> SubstateKey {
        SubstateKey {
            owner,
            local: LocalKey([slot; 16]),
        }
    }

    fn leg(target: Address, role: LegRole, edges: &[(u32, u32)], local: u32) -> LegShape {
        LegShape {
            target,
            role,
            edges: edges
                .iter()
                .map(|(source, output)| ValueEdge {
                    source: *source,
                    output: *output,
                    non_fungible: false,
                })
                .collect(),
            presents: Vec::new(),
            declares: vec![target],
            intent: IntentHash(Hash32([7; 32])),
            local,
        }
    }

    /// The record cell the edge `node` leaves on `output`. The consumer
    /// is not in a record's key.
    fn record(legs: &[LegShape], node: u32, output: u32) -> SubstateKey {
        let producer = &legs[node as usize];
        CrossingId::of_edge(producer, producer.target, output).record_key(&ProtocolHasher)
    }

    /// The record keys of the crossings `local` issues, in edge order:
    /// every one, or those of one `kind`.
    fn issued(classified: &Classified, local: ShardId, kind: Option<Kind>) -> Vec<SubstateKey> {
        classified
            .crossings()
            .filter(|(edge, _)| {
                edge.from == local && kind.is_none_or(|kind| edge.crossing.kind == kind)
            })
            .map(|(edge, _)| edge.crossing.id.record_key(&ProtocolHasher))
            .collect()
    }

    /// The claim cells consumers of the `kind` crossings `local` issues
    /// write, each with the consumer's frozen home.
    fn claims(classified: &Classified, local: ShardId, kind: Kind) -> Vec<(ShardId, SubstateKey)> {
        classified
            .crossings()
            .filter(|(edge, _)| edge.from == local && edge.crossing.kind == kind)
            .map(|(edge, home)| {
                (
                    home,
                    edge.crossing
                        .id
                        .answer_key(&ProtocolHasher, Answered::Taken),
                )
            })
            .collect()
    }

    fn arrival(node: u32, output: u32, amount: u128) -> EscrowedValue {
        EscrowedValue {
            node,
            output,
            resource: RESOURCE,
            amount,
            // The planner reads the edge, never the record: which cell a
            // bundle proved is the requirement's business.
            record: cell(owner(0xFF, true), 9),
        }
    }

    fn trie() -> ShardTrie {
        ShardTrie::uniform(1)
    }

    fn low() -> ShardId {
        ShardId::leaf(1, 0)
    }

    fn high() -> ShardId {
        ShardId::leaf(1, 1)
    }

    /// A transfer: sign-in and withdraw on the low shard, deposit on the
    /// high one. The sign-in is the only core, by demotion.
    fn transfer() -> Vec<LegShape> {
        let alice = owner(0x11, false);
        let bob = owner(0x22, true);
        vec![
            leg(alice, LegRole::Attesting, &[], 0),
            leg(alice, LegRole::Inbound, &[], 1),
            leg(bob, LegRole::Outbound, &[(1, 0)], 2),
        ]
    }

    /// A swap: sign-in, withdraw and deposit on the caller's low shard,
    /// the venue on the high one.
    fn swap() -> Vec<LegShape> {
        let alice = owner(0x11, false);
        let venue = owner(0x33, true);
        vec![
            leg(alice, LegRole::Attesting, &[], 0),
            leg(alice, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(alice, LegRole::Outbound, &[(2, 0)], 3),
        ]
    }

    fn frozen(legs: &[LegShape]) -> Classified {
        let classified = Classified::freeze(legs, legs[0].target, &[], &trie());
        assert!(classified.decomposed(), "the fixture has to decompose");
        classified
    }

    /// The claim cells a shard's owed crossings are answered by: a
    /// transfer's withdraw is owed the deposit's claim on the
    /// recipient's shard, the recipient's shard issues nothing, and a
    /// swap's withdraw is consumed by the core, which owes nothing.
    #[test]
    fn owed_claims_name_the_consumers_of_what_a_shard_issued() {
        let legs = transfer();
        let bob = owner(0x22, true);
        let expected =
            CrossingId::of_edge(&legs[1], bob, 0).answer_key(&ProtocolHasher, Answered::Taken);
        assert_eq!(
            claims(&frozen(&legs), low(), Kind::Owed),
            vec![(high(), expected)]
        );
        assert!(
            claims(&frozen(&legs), high(), Kind::Owed).is_empty(),
            "the delivering shard issued nothing",
        );
        assert!(
            claims(&Classified::whole(), low(), Kind::Owed).is_empty(),
            "a whole shape hands nothing between shards",
        );

        assert!(
            claims(&frozen(&swap()), low(), Kind::Owed).is_empty(),
            "a crossing the core consumes is answered by the core, not a delivery",
        );
    }

    /// The two kinds partition what a shard issues, exactly.
    ///
    /// Every record a producer here writes is one or the other, and the
    /// plan the same classification builds stamps each departure with
    /// the kind whose terms the kernel then writes onto the leaf. The
    /// entry path settles the escrowed ones under the transaction's own
    /// name and the leaf path disposes the owed ones; if the two sets
    /// overlapped, a second member would read a cell the first deleted,
    /// and if they left a gap its value would stand with nothing naming
    /// it.
    #[test]
    fn every_record_a_shard_issues_is_of_exactly_one_kind() {
        let mut saw_escrowed = false;
        let mut saw_owed = false;
        for legs in [transfer(), swap()] {
            let classified = frozen(&legs);
            for local in [low(), high()] {
                let all: BTreeSet<SubstateKey> =
                    issued(&classified, local, None).into_iter().collect();
                let escrowed: BTreeSet<SubstateKey> =
                    issued(&classified, local, Some(Kind::Escrowed))
                        .into_iter()
                        .collect();
                let owed: BTreeSet<SubstateKey> = issued(&classified, local, Some(Kind::Owed))
                    .into_iter()
                    .collect();

                saw_escrowed |= !escrowed.is_empty();
                saw_owed |= !owed.is_empty();
                assert!(
                    escrowed.is_disjoint(&owed),
                    "no record is both kinds at {local:?}",
                );
                assert_eq!(
                    &escrowed | &owed,
                    all,
                    "and between them they are everything issued at {local:?}",
                );

                // The kind each departure carries is the kind the leaf
                // will state, so the partition above is the one the
                // kernel writes down.
                let plan = classified.plan(&[], local, VALIDITY_END);
                if let Ok(plan) = plan {
                    for record in plan.legs.records() {
                        let departing = classified
                            .edges()
                            .iter()
                            .find(|edge| edge.crossing.id.record_key(&ProtocolHasher) == record)
                            .expect("a planned record is an edge of the shape");
                        assert_eq!(
                            departing.crossing.kind == Kind::Owed,
                            owed.contains(&record),
                            "the departure's kind and the accessor agree on {record:?}",
                        );
                    }
                }
            }
        }
        assert!(
            saw_escrowed && saw_owed,
            "the fixtures have to issue both kinds, or the partition holds for free",
        );
    }

    /// The whole shape on every participant, whatever the trie.
    #[test]
    fn a_whole_transaction_plans_the_whole_shape() {
        let plan = Classified::whole()
            .plan(&[], low(), VALIDITY_END)
            .expect("a whole plan needs nothing");
        assert!(plan.legs.is_whole());
        assert!(plan.judges.covers(owner(0x22, true)));
        assert!(Classified::whole().edges().is_empty());
    }

    /// A transfer plans one inbound leg on the sender's shard and one
    /// outbound on the recipient's, with one crossing between them.
    #[test]
    fn a_transfer_divides_into_an_inbound_and_an_outbound_leg() {
        let legs = transfer();
        let divided = frozen(&legs);

        let edges = divided.edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from, low());
        assert_eq!(edges[0].to, BTreeSet::from([high()]));
        assert_eq!(
            edges[0].crossing.id.record_key(&ProtocolHasher),
            record(&legs, 1, 0)
        );
        assert_eq!(divided.core(), &BTreeSet::from([low()]));

        let sender = divided
            .plan(&[], low(), VALIDITY_END)
            .expect("the sender's legs need no arrival");
        assert!(sender.legs.runs(0) && sender.legs.runs(1) && !sender.legs.runs(2));
        assert!(sender.legs.departure(1, 0).is_some());
        assert!(sender.judges.covers(owner(0x11, false)));
        assert!(!sender.judges.covers(owner(0x22, true)));

        // The deposit is the recipient's shard's commit fold, off the
        // record's reading: that shard commits nothing and plans no
        // member.
        assert!(divided.commits_at(low()) && !divided.commits_at(high()));
        assert_eq!(
            divided
                .plan(&[arrival(1, 0, 100)], high(), VALIDITY_END)
                .err(),
            Some(PlanDefect::NotAParticipant),
        );
        assert_eq!(
            divided.runs_at(high(), legs.len()),
            vec![false; legs.len()],
            "and reserves nothing",
        );
    }

    /// A shard's escrowed records are the escrowed edges it issues, and
    /// never an owed one: a transfer's crossing is owed and names none,
    /// a swap's withdraw into the venue is escrowed and names its record.
    #[test]
    fn escrowed_records_are_the_escrowed_edges_a_shard_issues() {
        assert!(frozen(&transfer()).escrowed_records(low()).is_empty());
        let swap = frozen(&swap());
        let escrowed: Vec<SubstateKey> = swap
            .edges()
            .iter()
            .filter(|edge| edge.from == low() && edge.crossing.kind == Kind::Escrowed)
            .map(|edge| edge.crossing.id.record_key(&ProtocolHasher))
            .collect();
        assert!(!escrowed.is_empty(), "the swap escrows into its venue");
        assert_eq!(swap.escrowed_records(low()).to_vec(), escrowed);
        assert!(
            swap.escrowed_records(high()).is_empty(),
            "the venue issues nothing escrowed"
        );
    }

    /// Every departure and arrival a plan files, and every `Never` the
    /// member writes, states the validity end the plan was handed, which
    /// is the transaction's: the answer's figure is the record's.
    #[test]
    fn a_departure_carries_the_transactions_validity_end() {
        let legs = swap();
        let divided = frozen(&legs);
        let edge = divided
            .edges()
            .iter()
            .find(|edge| edge.producer == 1)
            .expect("the withdraw crosses to the venue");
        let later = VALIDITY_END.plus(MAX_INTENT_VALIDITY_RANGE);
        for validity_end in [VALIDITY_END, later] {
            let departure = divided
                .plan(&[], low(), validity_end)
                .expect("the caller's legs need no arrival")
                .legs
                .departure(edge.producer, edge.output)
                .expect("the withdraw departs");
            assert_eq!(departure.validity_end_ms, validity_end.as_millis());
            let arrival = divided
                .plan(&[arrival(1, 0, 100)], high(), validity_end)
                .expect("the venue has its arrival")
                .legs
                .arrival(edge.producer, edge.output)
                .expect("the venue takes the crossing");
            assert_eq!(
                arrival.validity_end_ms,
                validity_end.as_millis(),
                "the answer a take writes states the record's figure",
            );
            let (_, never) = never_answer(TxHash(Hash32([1; 32])), validity_end.as_millis(), edge);
            assert_eq!(
                CrossingAnswer::from_bytes(&never)
                    .expect("a decline decodes")
                    .validity_end_ms,
                validity_end.as_millis(),
            );
        }
    }

    /// A swap plans the sign-in, the withdraw and the deposit on the
    /// caller's shard, the venue on its own, and the core is one shard.
    #[test]
    fn a_swap_keeps_the_core_on_the_venue_alone() {
        let legs = swap();
        let divided = frozen(&legs);
        assert_eq!(divided.core(), &BTreeSet::from([high()]));

        // The caller runs one member: it signs in and withdraws, waiting
        // on nothing, and the venue's output is banked by its commit fold
        // once the record's reading lands.
        let caller = divided
            .plan(&[], low(), VALIDITY_END)
            .expect("the caller's legs take no arrival");
        assert!(caller.legs.runs(0) && caller.legs.runs(1));
        assert!(!caller.legs.runs(2) && !caller.legs.runs(3));
        assert!(caller.legs.departure(1, 0).is_some());
        assert!(caller.legs.arrival(2, 0).is_none());
        assert!(divided.commits_at(low()));

        let venue = divided
            .plan(&[arrival(1, 0, 100)], high(), VALIDITY_END)
            .expect("the venue has its arrival");
        assert!(venue.legs.runs(2));
        assert!(!venue.legs.runs(0) && !venue.legs.runs(1) && !venue.legs.runs(3));
        assert!(venue.legs.arrival(1, 0).is_some());
        assert!(venue.legs.departure(2, 0).is_some());
        assert!(venue.judges.covers(owner(0x33, true)));
        assert!(!venue.judges.covers(owner(0x11, false)));
    }

    /// A consumer whose producer runs elsewhere needs its arrival, and a
    /// plan with none is a defect rather than a smaller plan.
    #[test]
    fn a_missing_arrival_is_a_defect() {
        let legs = swap();
        assert_eq!(
            frozen(&legs).plan(&[], high(), VALIDITY_END).err(),
            Some(PlanDefect::MissingArrival { node: 1, output: 0 }),
        );
    }

    /// A core's crossing to a delivery elsewhere is the core shard's to
    /// take back when the delivery lapses, claimed under the core node's
    /// own target; the caller's shard, which issued the withdraw, takes
    /// back that one and never the venue's.
    #[test]
    fn a_core_shard_reclaims_what_it_issued_to_a_delivery() {
        let legs = swap();
        let divided = frozen(&legs);
        let venue = divided
            .plan(&[arrival(1, 0, 100)], high(), VALIDITY_END)
            .expect("a core issues what it minted");
        assert!(venue.legs.departure(2, 0).is_some());

        let reclaimed = issued(&divided, high(), None);
        assert_eq!(reclaimed, vec![record(&legs, 2, 0)]);
        assert_eq!(reclaimed[0].owner, owner(0x33, true));
        assert_eq!(
            claims(&divided, high(), Kind::Owed)
                .into_iter()
                .map(|(shard, _)| shard)
                .collect::<Vec<_>>(),
            vec![low()],
            "and its deliveries are the caller's shard's to make"
        );
    }

    /// A shard that runs nothing of the transaction is not a participant.
    #[test]
    fn a_non_participant_is_a_defect() {
        let legs = swap();
        let elsewhere = ShardTrie::uniform(2);
        let divided_deeper = Classified::freeze(&legs, legs[0].target, &[], &elsewhere);
        assert!(divided_deeper.decomposed());
        // Under a four-leaf trie the low owners sit at path 0 and the
        // venue at path 2, so leaf 1 runs nothing.
        assert_eq!(
            divided_deeper
                .plan(&[], ShardId::leaf(2, 1), VALIDITY_END)
                .err(),
            Some(PlanDefect::NotAParticipant),
        );
    }

    /// The sender takes back exactly what its inbound leg issued, under
    /// its own target, and never the venue's crossing; a shard that
    /// issued nothing has nothing to reclaim.
    #[test]
    fn a_reclaim_takes_back_the_inbound_crossing_alone() {
        let legs = swap();
        let reclaimed = issued(&frozen(&legs), low(), None);
        assert_eq!(
            reclaimed,
            vec![record(&legs, 1, 0)],
            "the venue's crossing is not the caller's"
        );
        assert_eq!(reclaimed[0].owner, owner(0x11, false));

        let legs = transfer();
        assert!(
            issued(&frozen(&legs), high(), None).is_empty(),
            "the recipient's shard issued nothing"
        );
    }

    /// A leg whose home is a core shard is the core member's: the venue's
    /// output to a recipient on the venue's own shard is passed directly
    /// rather than departed into a record the shard could never be
    /// handed.
    #[test]
    fn an_outbound_leg_on_a_core_shard_runs_in_the_core_member() {
        let bob = owner(0x22, false);
        let venue = owner(0x33, true);
        let recipient = owner(0x44, true);
        let legs = vec![
            leg(bob, LegRole::Attesting, &[], 0),
            leg(bob, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(recipient, LegRole::Outbound, &[(2, 0)], 3),
        ];
        let classified = frozen(&legs);
        assert!(classified.commits_at(high()));
        let edges = classified.edges();
        assert_eq!(edges.len(), 1, "only the withdraw crosses");
        assert_eq!((edges[0].producer, edges[0].output), (1, 0));

        let core = classified
            .plan(&[arrival(1, 0, 5)], high(), VALIDITY_END)
            .expect("the core member runs the venue and the deposit");
        assert!(core.legs.runs(2) && core.legs.runs(3));
        assert!(
            core.legs.departure(2, 0).is_none(),
            "the venue's output stays in the execution"
        );
        assert!(issued(&classified, high(), None).is_empty());
    }

    /// An inbound leg on one shard of a multi-shard core is replicated
    /// with the core: nothing is promised to the other core shard, and
    /// each plans the withdraw beside the venues.
    #[test]
    fn an_inbound_leg_on_a_core_shard_is_replicated_with_the_core() {
        let trie = ShardTrie::uniform(2);
        let (leaf0, leaf1, leaf2) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        let legs = vec![
            leg(owner_at(0x11, 0), LegRole::Attesting, &[], 0),
            leg(owner_at(0x11, 0), LegRole::Inbound, &[], 1),
            leg(owner_at(0x12, 0), LegRole::Core, &[(1, 0)], 2),
            leg(owner_at(0x13, 2), LegRole::Core, &[(2, 0)], 3),
            leg(owner_at(0x14, 1), LegRole::Outbound, &[(3, 0)], 4),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert!(classified.decomposed());
        assert_eq!(classified.core(), &BTreeSet::from([leaf0, leaf2]));
        let edges = classified.edges();
        assert_eq!(
            edges.iter().map(|edge| edge.producer).collect::<Vec<_>>(),
            vec![3],
            "only the second venue's output to the deposit crosses"
        );
        assert_eq!(edges[0].to, BTreeSet::from([leaf1]));
        for shard in [leaf0, leaf2] {
            let plan = classified
                .plan(&[], shard, VALIDITY_END)
                .expect("a core shard plans the withdraw beside the venues");
            assert!(
                plan.legs.runs(0) && plan.legs.runs(1) && plan.legs.runs(2) && plan.legs.runs(3)
            );
            assert!(plan.legs.departure(1, 0).is_none());
            assert!(plan.legs.departure(3, 0).is_some());
        }
    }

    /// An inbound leg off the core feeds core nodes on two shards: the
    /// edge crosses to every core shard, and the record's consumer
    /// routes to one of them, so a push reaches one core shard and the
    /// other reads the record through its own ask.
    #[test]
    fn an_inbound_leg_off_the_core_crosses_to_every_core_shard() {
        let trie = ShardTrie::uniform(2);
        let (leaf0, leaf1, leaf2) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        let legs = vec![
            leg(owner_at(0x11, 1), LegRole::Inbound, &[], 0),
            leg(owner_at(0x12, 0), LegRole::Core, &[(0, 0)], 1),
            leg(owner_at(0x13, 2), LegRole::Core, &[(1, 0)], 2),
            leg(owner_at(0x14, 1), LegRole::Outbound, &[(2, 0)], 3),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert!(classified.decomposed());
        assert_eq!(classified.core(), &BTreeSet::from([leaf0, leaf2]));
        let edges = classified.edges();
        let inbound = edges
            .iter()
            .find(|edge| edge.producer == 0)
            .expect("the inbound leg's output crosses");
        assert_eq!(inbound.from, leaf1);
        assert_eq!(inbound.to, BTreeSet::from([leaf0, leaf2]));
        let owner = trie.shard_for_prefix(inbound.crossing.id.consumer);
        assert!(
            inbound.to.contains(&owner),
            "the record's consumer routes to one of the core shards it crosses to"
        );
    }

    /// What a shard runs is what its block reserves, and a multi-shard
    /// core runs more than it holds: each of its shards runs every core
    /// node, so each of them owes those nodes' ceilings.
    ///
    /// The same question the plan answers, asked without arrivals,
    /// because a budget is read before a member is composed. The
    /// falsifier is the node homed on the other core shard: a reading
    /// off placement alone would leave it out of both budgets but in
    /// both executions.
    #[test]
    fn a_core_shard_runs_every_core_node_and_reserves_each_of_them() {
        let trie = ShardTrie::uniform(2);
        let (leaf0, leaf1, leaf2) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        let legs = vec![
            leg(owner_at(0x11, 0), LegRole::Attesting, &[], 0),
            leg(owner_at(0x11, 0), LegRole::Inbound, &[], 1),
            leg(owner_at(0x12, 0), LegRole::Core, &[(1, 0)], 2),
            leg(owner_at(0x13, 2), LegRole::Core, &[(2, 0)], 3),
            leg(owner_at(0x14, 1), LegRole::Outbound, &[(3, 0)], 4),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([leaf0, leaf2]));
        for shard in [leaf0, leaf2] {
            assert_eq!(
                classified.runs_at(shard, legs.len()),
                vec![true, true, true, true, false],
                "a core shard runs the core whole and never the delivery"
            );
        }
        assert_eq!(
            classified.runs_at(leaf1, legs.len()),
            vec![false; legs.len()],
            "and the shard taking delivery runs nothing: its fold credits the deposit"
        );
    }

    /// A shape that runs whole runs every node on every participant, so
    /// every participant reserves the whole of it. Nothing is divided,
    /// so nothing about the core narrows what a member bears.
    #[test]
    fn a_shape_that_runs_whole_is_reserved_whole_everywhere() {
        let legs = transfer();
        let whole = Classified::whole();
        assert!(!whole.decomposed());
        for shard in [low(), high()] {
            assert_eq!(whole.runs_at(shard, legs.len()), vec![true; legs.len()]);
        }
    }

    /// A leg beside the core folds even where what makes it beside the
    /// core folds in the same pass, so no edge is left crossing between
    /// two nodes one member runs.
    ///
    /// Left unfolded, the shard running both ends files neither a
    /// departure nor an arrival for that edge while the core's other
    /// shards demand one, and a multi-shard core has no clock to give up
    /// on it — so the shape holds its cells until a reshape.
    #[test]
    fn a_leg_whose_consumer_folds_beside_the_core_leaves_no_crossing() {
        let trie = ShardTrie::uniform(2);
        let (leaf0, leaf1, leaf2) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        // A route across two venues, with a top-up beside the first one
        // feeding the same sink the route ends in.
        let legs = vec![
            leg(owner_at(0x11, 1), LegRole::Inbound, &[], 0),
            leg(owner_at(0x12, 0), LegRole::Core, &[(0, 0)], 1),
            leg(owner_at(0x13, 2), LegRole::Core, &[(1, 0)], 2),
            leg(owner_at(0x14, 0), LegRole::Inbound, &[], 3),
            leg(owner_at(0x15, 0), LegRole::Outbound, &[(2, 0), (3, 0)], 4),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert!(classified.decomposed());
        assert_eq!(classified.core(), &BTreeSet::from([leaf0, leaf2]));
        assert_eq!(
            classified
                .edges()
                .iter()
                .map(|edge| edge.producer)
                .collect::<Vec<_>>(),
            vec![0],
            "only the caller's leg crosses",
        );

        for shard in [leaf0, leaf2] {
            let plan = classified
                .plan(&[arrival(0, 0, 5)], shard, VALIDITY_END)
                .expect("every core shard plans the whole core");
            assert!(
                (1..5).all(|node| plan.legs.runs(node)) && !plan.legs.runs(0),
                "the core and everything folded beside it, and not the caller's leg",
            );
            assert!(
                plan.legs.departure(3, 0).is_none(),
                "the top-up's value stays inside the execution",
            );
        }
        assert!(
            issued(&classified, leaf0, None).is_empty(),
            "a core shard issues no record for an edge it runs both ends of",
        );
        assert_eq!(classified.plan(&[], leaf1, VALIDITY_END).err(), None);
    }

    /// A core member judges its whole core; a leg judges its own shard.
    ///
    /// A core node's conditions are settled once for the core and on
    /// every shard that runs it, so each has to judge what the others
    /// hold. This is the one place the two owner sets differ, and it is
    /// why a core node can hold a cell it does not apply — which is why
    /// an origin has to be filtered down to what it does.
    #[test]
    fn a_core_member_judges_its_whole_core() {
        let trie = ShardTrie::uniform(2);
        let (leaf0, leaf1, leaf2) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        let (caller, here, sibling) = (owner_at(0x11, 1), owner_at(0x12, 0), owner_at(0x13, 2));
        let legs = vec![
            leg(caller, LegRole::Inbound, &[], 0),
            leg(here, LegRole::Core, &[(0, 0)], 1),
            leg(sibling, LegRole::Core, &[(1, 0)], 2),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([leaf0, leaf2]));

        let core = classified.judges_for(leaf0);
        assert!(core.covers(here), "a core member judges its own node");
        assert!(core.covers(sibling), "and the node its sibling runs");
        assert!(
            !core.covers(caller),
            "and nothing outside the core, whose members judge for themselves",
        );

        let off_the_core = classified.judges_for(leaf1);
        assert!(off_the_core.covers(caller));
        assert!(
            !off_the_core.covers(here) && !off_the_core.covers(sibling),
            "a leg judges its own shard alone",
        );
    }

    /// A sink fed beside itself runs in the shard's member: an outbound
    /// leg whose producer runs on its own shard takes the value directly,
    /// while one fed by the core elsewhere is credited by that shard's
    /// commit fold.
    #[test]
    fn a_sink_fed_beside_itself_runs_in_the_issuing_member() {
        let alice = owner(0x11, false);
        let carol = owner(0x55, false);
        let venue = owner(0x33, true);
        let legs = vec![
            leg(alice, LegRole::Attesting, &[], 0),
            leg(alice, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(alice, LegRole::Outbound, &[(2, 0)], 3),
            leg(alice, LegRole::Inbound, &[], 4),
            leg(carol, LegRole::Outbound, &[(4, 0)], 5),
        ];
        let classified = frozen(&legs);
        assert!(classified.commits_at(low()));
        assert_eq!(
            classified
                .edges()
                .iter()
                .map(|edge| edge.producer)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "the local transfer's edge never crosses"
        );
        let member = classified
            .plan(&[], low(), VALIDITY_END)
            .expect("the member runs both withdraws and the local deposit");
        assert!(member.legs.runs(1) && member.legs.runs(4) && member.legs.runs(5));
        assert!(
            !member.legs.runs(3),
            "and not the venue's return, which the fold credits"
        );
        assert!(member.legs.departure(1, 0).is_some());
        assert!(member.legs.departure(4, 0).is_none());
    }

    /// A sink fed from both sides of its own shard runs whole: its
    /// issuing member could only hand it the local edge through a bundle
    /// to itself.
    #[test]
    fn a_sink_fed_from_both_sides_runs_whole() {
        let alice = owner(0x11, false);
        let venue = owner(0x33, true);
        let legs = vec![
            leg(alice, LegRole::Attesting, &[], 0),
            leg(alice, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(alice, LegRole::Inbound, &[], 3),
            leg(alice, LegRole::Outbound, &[(2, 0), (3, 0)], 4),
        ];
        let whole = Classified::freeze(&legs, legs[0].target, &[], &trie());
        assert!(!whole.decomposed());
        assert!(
            whole.commits_at(low()),
            "a whole shape commits on every participant"
        );
        let mut one_sided = legs;
        one_sided[4] = leg(alice, LegRole::Outbound, &[(2, 0)], 4);
        one_sided[3] = leg(alice, LegRole::Outbound, &[], 3);
        assert!(Classified::freeze(&one_sided, one_sided[0].target, &[], &trie()).decomposed());
    }
}
