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

use hyperscale_types::{Address, EscrowedValue, Role, ShardId, ShardTrie, SubstateKey};
use hyperscale_vm_effects::{CrossingEdge as StarEdge, Star, star_at};
use hyperscale_vm_kernel::{Crossed, Departure, LegPlan, OwnerSet, PlanFault};
use hyperscale_vm_types::{LegRole, LegShape, ProtocolHasher};

use crate::sharding::TrieShardResolver;

/// One value edge whose producer and consumer do not run together, under
/// the protocol's shard identifiers.
pub type CrossingEdge = StarEdge<ShardId>;

/// The classification frozen onto a transaction when its block
/// committed: the star its shape implies under the trie the block
/// committed under, and which of its shards deliver.
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
    /// The trie the classification was read against, and the one every
    /// plan built from it resolves an owner through.
    trie: Arc<ShardTrie>,
    /// The star: whether the shape divides, each node's settled role and
    /// home, the core set, and every edge that crosses.
    star: Star<ShardId>,
    delivering: BTreeSet<ShardId>,
    /// The shards that run an outbound leg beside an inbound one: a
    /// swap's caller, which withdraws before the venue and banks after
    /// it. Never a core shard, whose legs are its core member's.
    mixed: BTreeSet<ShardId>,
}

/// Which of a shard's legs a member runs.
///
/// A shard outside the core may hold legs on both sides of it: inbound
/// ones that feed it and outbound ones that consume what it returns. The
/// two cannot be one admission, since the outbound legs wait on a
/// crossing the core issues only after the inbound ones have crossed to
/// it. So a shard's work divides into at most two members — an issuing
/// one that runs its inbound legs, its share of the core, and any
/// outbound leg whose producer runs beside it, and a delivering one that
/// runs the outbound legs whose producers run elsewhere, once their
/// arrivals land — and a shard with legs on one side only has the one.
/// A node's side is decided by where its edges come from, never by its
/// role alone, so a member's arrivals are exactly the edges that cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    /// The inbound legs and the core share: what settles, what issues,
    /// what a verdict is drawn from.
    Issuing,
    /// The outbound legs: a delivery, admitted when what it consumes has
    /// crossed, deciding nothing and reserving nothing.
    Delivering,
}

impl Classified {
    /// Freeze `legs` against `trie`: the classifier's star, and off it
    /// which shards deliver. Nothing else enters — the trie is the one
    /// placement fact, and it changes only at a cut, where the shard
    /// leaving it commits nothing more — so every shard and every replica
    /// committing the transaction under one trie freezes one shape.
    ///
    /// The classifier reads no window. A shard scheduled to leave the
    /// trie divides like any other, in its final window too: a record
    /// cell follows its prefix to the successor, a claim or a delivery
    /// is a pull on whoever holds the prefix when it is made, and a
    /// crossing the delivery window closes on unclaimed is reclaimed on
    /// the successor's own proof of its absence. A rule that read the
    /// block's window here would flip at the boundary into that window
    /// while the trie did not, and two shards committing one transaction
    /// on either side of it would freeze different shapes.
    #[must_use]
    pub fn freeze(legs: &[LegShape], owners: &[Address], trie: &ShardTrie) -> Self {
        let trie = Arc::new(trie.clone());
        let star = star_at(
            legs,
            owners,
            &TrieShardResolver { trie: &trie },
            &ProtocolHasher,
        )
        .map_shards(|shard| ShardId::from_heap_index(shard.0));
        let (delivering, mixed) = if star.decomposes {
            let (delivers, settles) = delivery_sides(&star);
            (
                delivers.difference(&settles).copied().collect(),
                delivers.intersection(&settles).copied().collect(),
            )
        } else {
            (BTreeSet::new(), BTreeSet::new())
        };
        Self {
            trie,
            star,
            delivering,
            mixed,
        }
    }

    /// The whole shape on every participant, with no placement read.
    #[must_use]
    pub fn whole() -> Self {
        Self {
            trie: Arc::new(ShardTrie::single()),
            star: Star::whole(),
            delivering: BTreeSet::new(),
            mixed: BTreeSet::new(),
        }
    }

    /// The trie this classification was read against.
    #[must_use]
    pub fn trie(&self) -> &ShardTrie {
        &self.trie
    }

    /// Whether `shard` only delivers for this transaction: it sits
    /// outside the core and every leg it runs is a delivery, so nothing
    /// it does bears a verdict or issues a crossing. Such a member is
    /// admissible past the transaction's validity end, since the record
    /// cell it claims is bounded by its own sweep and not by the window.
    #[must_use]
    pub fn only_delivers_at(&self, shard: ShardId) -> bool {
        self.delivering.contains(&shard)
    }

    /// Whether `shard` runs an outbound leg beside an inbound one, and
    /// so runs this transaction as two members: an issuing one at its
    /// commit, and a delivering one once the core's output has crossed
    /// back to it.
    #[must_use]
    pub fn mixed_at(&self, shard: ShardId) -> bool {
        self.mixed.contains(&shard)
    }

    /// The side `shard`'s first member runs: its delivery where it only
    /// delivers, and everything that issues otherwise. A mixed shard's
    /// delivering member is registered by the issuing one's admission.
    #[must_use]
    pub fn first_side_at(&self, shard: ShardId) -> Side {
        if self.only_delivers_at(shard) {
            Side::Delivering
        } else {
            Side::Issuing
        }
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

    /// The claim cells consumers of what `local` issued write, each
    /// under the shard holding the consumer's target — the consumer's
    /// own home, since a claim sits under its target wherever else the
    /// core runs it.
    ///
    /// One fold, asked for by name in two halves rather than returned as
    /// one list: a delivery's claim is probed at the lapse and a core
    /// consumer's at the deadline, so a caller that took them together
    /// would have to split them again before asking.
    fn claims_issued(&self, local: ShardId, delivered: bool) -> Vec<(ShardId, SubstateKey)> {
        self.edges()
            .iter()
            .filter(|edge| edge.from == local && edge.delivers == delivered)
            .map(|edge| (self.home(edge.consumer), edge.claim.key()))
            .collect()
    }

    /// The claim cells core consumers write for the crossings a leg on
    /// `local` issued. What a probe asks the core about once the
    /// transaction's deadline has passed: a claim present there says
    /// the core took the crossing.
    #[must_use]
    pub fn core_claims(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.claims_issued(local, false)
    }

    /// The claim cells deliveries elsewhere write for the crossings a
    /// node on `local` issued — an inbound leg's, or the core's on a
    /// core shard.
    ///
    /// A delivery that never claimed leaves exactly this cell absent,
    /// which is what a lapse probe asks the delivering shard about, and
    /// the crossing is then the producer's to take back.
    #[must_use]
    pub fn delivered_claims(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.claims_issued(local, true)
    }

    /// Every record cell a producer on `local` writes for a consumer
    /// elsewhere, in edge order.
    ///
    /// What a retirement of this transaction deletes and what a reclaim
    /// of it credits back are the same cells; the two differ in what a
    /// committed record licensed doing with them, which is the ledger's
    /// question rather than this one's. So there is one fold, and the
    /// caller names the disposition.
    #[must_use]
    pub fn records_issued(&self, local: ShardId) -> Vec<SubstateKey> {
        self.edges()
            .iter()
            .filter(|edge| edge.from == local)
            .map(|edge| edge.record.key())
            .collect()
    }

    /// What `local` runs of the transaction on `side`, what arrives for
    /// it, and what departs from it.
    ///
    /// `arrivals` is what committed bundles attested for the edges this
    /// member consumes — read, never derived.
    ///
    /// # Errors
    ///
    /// [`PlanDefect`], on its own terms — never a smaller plan.
    pub fn plan(
        &self,
        arrivals: &[EscrowedValue],
        local: ShardId,
        side: Side,
    ) -> Result<ShardPlan, PlanDefect> {
        if !self.decomposed() {
            return Ok(ShardPlan::whole());
        }
        let runs_here = |node: u32| runs(&self.star, node, local, side);
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
                plan.arrives(
                    edge.producer,
                    edge.output,
                    Crossed {
                        resource: arrived.resource,
                        amount: arrived.amount,
                    },
                    edge.claim,
                )?;
            } else if runs_here(edge.producer) && !runs_here(edge.consumer) {
                plan.departs(
                    edge.producer,
                    edge.output,
                    Departure {
                        site: edge.record,
                        consumer_claim: edge.claim.key(),
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
        let trie = Arc::clone(&self.trie);
        if self.star.core.contains(&local) {
            let core = self.star.core.clone();
            OwnerSet::of(move |owner| core.contains(&trie.shard_for_prefix(owner)))
        } else {
            OwnerSet::of(move |owner| trie.shard_for_prefix(owner) == local)
        }
    }
}

/// The side `node` runs on at `local`: a sink whose producers run
/// elsewhere is a delivery, waiting on their arrival; everything else —
/// a source, the core, a sink fed beside itself — issues.
///
/// `Side` is this crate's naming for the answer [`Star::delivers_at`]
/// gives: which of a shard's at most two members runs the node.
fn side_of(star: &Star<ShardId>, node: u32, local: ShardId) -> Side {
    if star.delivers_at(node, local) {
        Side::Delivering
    } else {
        Side::Issuing
    }
}

/// Whether `node` runs in `local`'s member on `side`.
fn runs(star: &Star<ShardId>, node: u32, local: ShardId, side: Side) -> bool {
    star.running(node).contains(&local) && side_of(star, node, local) == side
}

/// The shards running a delivery, and the shards running anything that
/// issues. A shard in both runs the transaction as two members.
fn delivery_sides(star: &Star<ShardId>) -> (BTreeSet<ShardId>, BTreeSet<ShardId>) {
    let mut delivers = BTreeSet::new();
    let mut settles = BTreeSet::new();
    for node in 0..star.nodes() {
        for shard in star.running(node) {
            match (star.role(node), side_of(star, node, shard)) {
                (LegRole::Attesting, _) => {}
                (_, Side::Delivering) => {
                    delivers.insert(shard);
                }
                (_, Side::Issuing) => {
                    settles.insert(shard);
                }
            }
        }
    }
    (delivers, settles)
}

/// One shard's member of a frozen transaction.
///
/// Every per-member quantity is a function of the frozen classification,
/// where the member runs, which of its shard's legs it takes and what the
/// transaction reaches. Derived once here and asked by name, so a
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
    side: Side,
    /// Every shard the transaction touches. Beside the classification
    /// because a whole shape's member awaits all of them, and no frozen
    /// answer names them.
    participating: BTreeSet<ShardId>,
}

impl Member {
    /// The member `local` runs on `side` of a transaction frozen as
    /// `classified` and reaching `participating`.
    #[must_use]
    pub const fn of(
        classified: Classified,
        local: ShardId,
        side: Side,
        participating: BTreeSet<ShardId>,
    ) -> Self {
        Self {
            classified,
            local,
            side,
            participating,
        }
    }

    /// The member a caller with no placement to freeze against runs:
    /// the whole transaction, on its own shard, reaching nobody else.
    #[must_use]
    pub fn whole(local: ShardId) -> Self {
        Self::of(
            Classified::whole(),
            local,
            Side::Issuing,
            BTreeSet::from([local]),
        )
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

    /// Which of its shard's legs it runs.
    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }

    /// Every shard the transaction touches — who this tick's certificate
    /// is owed to, since any of them may need what a member escrowed.
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
    ///
    /// Reads the side, so a shard with legs on both sides of the core is
    /// a `Delivery` in its delivering member and a `Leg` in its issuing
    /// one. That is a different question from what such a shard's single
    /// ledger entry is, which is the leg's — see `Part::of`.
    #[must_use]
    pub fn role(&self) -> Role {
        if !self.classified.decomposed() {
            Role::Whole
        } else if self.in_core() {
            Role::Core
        } else if self.delivers() {
            Role::Delivery
        } else {
            Role::Leg
        }
    }

    /// Whether the member only delivers: a leg that failed is the
    /// transaction's end on its shard, but a delivery that failed decides
    /// nothing — the value it claims stays in its cell for a later claim.
    #[must_use]
    pub fn delivers(&self) -> bool {
        self.classified.decomposed() && self.side == Side::Delivering
    }

    /// Whether this shard's nodes sit in the core set.
    #[must_use]
    pub fn in_core(&self) -> bool {
        self.classified.core().contains(&self.local)
    }

    /// Whether this shard runs an outbound leg beside an inbound one, and
    /// so runs the transaction as two members.
    #[must_use]
    pub fn runs_both_sides(&self) -> bool {
        self.classified.mixed_at(self.local)
    }

    /// Whether this is the second member its shard runs of the
    /// transaction: a mixed shard's delivering one, whose issuing member
    /// took the block's reservation, settled the price and committed the
    /// signers' nullifiers, so this one does none of those.
    #[must_use]
    pub fn is_second(&self) -> bool {
        self.side == Side::Delivering && self.runs_both_sides()
    }
}

/// What licenses a member to settle the records a producer here left.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Licence {
    /// Every consumer claimed, on the evidence of its claim cell proved
    /// present: the records are deleted.
    Claimed,
    /// No consumer ever claimed, on the evidence of a committed record:
    /// the crossings are credited back and the records deleted.
    Unclaimed,
    /// This shard's own state: records it inherited with a prefix, each
    /// decided against the claim cell it names — credited back where
    /// that cell is absent inside the window an absence means something
    /// in, deleted where it is there. The one licence that is this
    /// shard's own evidence: a record arriving with a prefix has no
    /// counterpart left to ask, and the shard that inherited it holds
    /// both halves of the crossing or cannot decide it at all.
    OwnLeaf,
}

/// What a member runs of its transaction: the shape its committing
/// block froze, or a settlement of the records a producer here left.
///
/// A settlement names cells and not a manifest. That is what lets a
/// shard holding the record and no body compose one — a reshape
/// successor, whose store arrives as a prefix of leaves and whose ledger
/// begins empty: the record leaf says which cells the member touches,
/// and the transaction is a name on the receipt rather than an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Runs {
    /// The transaction as classified at commit — whole, or the legs
    /// this shard's placement gives it on its side.
    Shape(Member),
    /// No node at all: the records of crossings a producer here issued,
    /// settled on `on`.
    Settle {
        /// The member the settlement runs as: whole, on its own shard,
        /// reaching nobody else.
        member: Member,
        /// The record cells to settle.
        records: Vec<SubstateKey>,
        /// What licenses the settlement, and so what it does to each
        /// record.
        on: Licence,
        /// Whether this shard settled the transaction's price already.
        /// A leg that ran burned it inside its writes at its own
        /// finalization; one that never ran — held for a bundle that
        /// never came — owes it still, and the reclaim's receipt is the
        /// one of this shard's left to carry it. A retirement is
        /// housekeeping on a transaction whose price its leg settled,
        /// and an inherited record's price was settled by the chain
        /// that dissolved.
        charged: bool,
    },
}

impl Runs {
    /// The member this runs as.
    #[must_use]
    pub const fn member(&self) -> &Member {
        match self {
            Self::Shape(member) | Self::Settle { member, .. } => member,
        }
    }

    /// Whether the transaction reaches beyond the running shard. A
    /// settlement reaches nobody: every cell it touches is a record this
    /// shard holds.
    #[must_use]
    pub fn reaches_beyond(&self) -> bool {
        match self {
            Self::Shape(member) => member.reaches_beyond(),
            Self::Settle { .. } => false,
        }
    }

    /// Whether a counterpart's verdict can still discard this member's
    /// effects after it executes. Nothing retracts a settlement.
    #[must_use]
    pub fn abortable(&self) -> bool {
        match self {
            Self::Shape(member) => member.abortable(),
            Self::Settle { .. } => false,
        }
    }

    /// Whether the transaction's price was levied on this shard already,
    /// so this member charges nothing: the delivering member of a mixed
    /// shard, whose issuing member charged; a settlement on a leg that
    /// ran, or on a record whose transaction was priced elsewhere.
    #[must_use]
    pub fn charged_already(&self) -> bool {
        match self {
            Self::Shape(member) => member.is_second(),
            Self::Settle {
                on: Licence::Unclaimed,
                charged,
                ..
            } => *charged,
            Self::Settle {
                on: Licence::Claimed | Licence::OwnLeaf,
                ..
            } => true,
        }
    }
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
    pub fn whole() -> Self {
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
    use hyperscale_types::{Address, AddressClass, LocalKey, SubstateKey};
    use hyperscale_vm_effects::{CrossingSite, Hash32, SubintentHash};
    use hyperscale_vm_types::{ResourceAddr, ValueEdge};

    use super::*;

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

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
            intent: SubintentHash(Hash32([7; 32])),
            local,
            expiry_ms: 1_000,
        }
    }

    /// The record cell the edge `node` leaves on `output`.
    fn record(legs: &[LegShape], node: u32, output: u32) -> SubstateKey {
        CrossingSite::record_of(&ProtocolHasher, &legs[node as usize], output).key()
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
        let classified = Classified::freeze(legs, &[], &trie());
        assert!(classified.decomposed(), "the fixture has to decompose");
        classified
    }

    /// The claim cells a shard's issued crossings are owed by deliveries
    /// elsewhere: a transfer's withdraw is owed the deposit's claim on
    /// the recipient's shard, the recipient's shard issues nothing, and a
    /// swap's withdraw is consumed by the core, which is no delivery.
    #[test]
    fn delivered_claims_name_the_deliveries_of_what_a_shard_issued() {
        let legs = transfer();
        let bob = owner(0x22, true);
        let expected = CrossingSite::claim_of(&ProtocolHasher, bob, &legs[1], 0).key();
        assert_eq!(
            frozen(&legs).delivered_claims(low()),
            vec![(high(), expected)]
        );
        assert!(
            frozen(&legs).delivered_claims(high()).is_empty(),
            "the delivering shard issued nothing",
        );
        assert!(
            Classified::whole().delivered_claims(low()).is_empty(),
            "a whole shape hands nothing between shards",
        );

        assert!(
            frozen(&swap()).delivered_claims(low()).is_empty(),
            "a crossing the core consumes is answered by the core, not a delivery",
        );
    }

    /// The whole shape on every participant, whatever the trie.
    #[test]
    fn a_whole_transaction_plans_the_whole_shape() {
        let plan = Classified::whole()
            .plan(&[], low(), Side::Issuing)
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
        assert_eq!(edges[0].record.key(), record(&legs, 1, 0));
        assert_eq!(divided.core(), &BTreeSet::from([low()]));

        let sender = divided
            .plan(&[], low(), Side::Issuing)
            .expect("the sender's legs need no arrival");
        assert!(sender.legs.runs(0) && sender.legs.runs(1) && !sender.legs.runs(2));
        assert!(sender.legs.departure(1, 0).is_some());
        assert!(sender.judges.covers(owner(0x11, false)));
        assert!(!sender.judges.covers(owner(0x22, true)));

        let recipient = divided
            .plan(&[arrival(1, 0, 100)], high(), Side::Delivering)
            .expect("the recipient's leg has its arrival");
        assert!(!recipient.legs.runs(0) && !recipient.legs.runs(1) && recipient.legs.runs(2));
        assert_eq!(
            recipient.legs.arrival(1, 0).map(|arrival| arrival.crossed),
            Some(Crossed {
                resource: RESOURCE,
                amount: 100
            })
        );
        assert!(recipient.judges.covers(owner(0x22, true)));
        assert!(!recipient.judges.covers(owner(0x11, false)));
    }

    /// A swap plans the sign-in, the withdraw and the deposit on the
    /// caller's shard, the venue on its own, and the core is one shard.
    #[test]
    fn a_swap_keeps_the_core_on_the_venue_alone() {
        let legs = swap();
        let divided = frozen(&legs);
        assert_eq!(divided.core(), &BTreeSet::from([high()]));

        // The caller runs the transaction as two members: its issuing one
        // signs in and withdraws, waiting on nothing, and its delivering
        // one banks the venue's output once that has crossed back.
        let issuing = divided
            .plan(&[], low(), Side::Issuing)
            .expect("the caller's issuing legs take no arrival");
        assert!(issuing.legs.runs(0) && issuing.legs.runs(1));
        assert!(!issuing.legs.runs(2) && !issuing.legs.runs(3));
        assert!(issuing.legs.departure(1, 0).is_some());
        assert!(issuing.legs.arrival(2, 0).is_none());
        let delivering = divided
            .plan(&[arrival(2, 0, 90)], low(), Side::Delivering)
            .expect("the caller's delivering leg has its arrival");
        assert!(delivering.legs.runs(3));
        assert!(!delivering.legs.runs(0) && !delivering.legs.runs(1) && !delivering.legs.runs(2));
        assert!(delivering.legs.arrival(2, 0).is_some());
        assert!(delivering.legs.departure(1, 0).is_none());

        let venue = divided
            .plan(&[arrival(1, 0, 100)], high(), Side::Issuing)
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
        let legs = transfer();
        assert_eq!(
            frozen(&legs).plan(&[], high(), Side::Delivering).err(),
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
            .plan(&[arrival(1, 0, 100)], high(), Side::Issuing)
            .expect("a core issues what it minted");
        assert!(venue.legs.departure(2, 0).is_some());

        let reclaimed = divided.records_issued(high());
        assert_eq!(reclaimed, vec![record(&legs, 2, 0)]);
        assert_eq!(reclaimed[0].owner, owner(0x33, true));
        assert_eq!(
            divided
                .delivered_claims(high())
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
        let divided_deeper = Classified::freeze(&legs, &[], &elsewhere);
        assert!(divided_deeper.decomposed());
        // Under a four-leaf trie the low owners sit at path 0 and the
        // venue at path 2, so leaf 1 runs nothing.
        assert_eq!(
            divided_deeper
                .plan(&[], ShardId::leaf(2, 1), Side::Issuing)
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
        let reclaimed = frozen(&legs).records_issued(low());
        assert_eq!(
            reclaimed,
            vec![record(&legs, 1, 0)],
            "the venue's crossing is not the caller's"
        );
        assert_eq!(reclaimed[0].owner, owner(0x11, false));

        let legs = transfer();
        assert!(
            frozen(&legs).records_issued(high()).is_empty(),
            "the recipient's shard issued nothing"
        );
    }

    /// A leg whose home is a core shard is the core member's: the venue's
    /// output to a recipient on the venue's own shard is passed directly
    /// rather than departed into a record the shard could never be
    /// handed, and the shard has no delivering member at all.
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
        assert!(
            !classified.mixed_at(high()),
            "the core shard runs one member"
        );
        assert!(!classified.only_delivers_at(high()));
        let edges = classified.edges();
        assert_eq!(edges.len(), 1, "only the withdraw crosses");
        assert_eq!((edges[0].producer, edges[0].output), (1, 0));

        let core = classified
            .plan(&[arrival(1, 0, 5)], high(), Side::Issuing)
            .expect("the core member runs the venue and the deposit");
        assert!(core.legs.runs(2) && core.legs.runs(3));
        assert!(
            core.legs.departure(2, 0).is_none(),
            "the venue's output stays in the execution"
        );
        assert_eq!(
            classified.plan(&[], high(), Side::Delivering).err(),
            Some(PlanDefect::NotAParticipant),
        );
        assert!(classified.records_issued(high()).is_empty());
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
        let classified = Classified::freeze(&legs, &[], &trie);
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
                .plan(&[], shard, Side::Issuing)
                .expect("a core shard plans the withdraw beside the venues");
            assert!(
                plan.legs.runs(0) && plan.legs.runs(1) && plan.legs.runs(2) && plan.legs.runs(3)
            );
            assert!(plan.legs.departure(1, 0).is_none());
            assert!(plan.legs.departure(3, 0).is_some());
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
        let classified = Classified::freeze(&legs, &[], &trie);
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
                .plan(&[arrival(0, 0, 5)], shard, Side::Issuing)
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
            classified.records_issued(leaf0).is_empty(),
            "a core shard issues no record for an edge it runs both ends of",
        );
        assert_eq!(classified.plan(&[], leaf1, Side::Issuing).err(), None);
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
        let classified = Classified::freeze(&legs, &[], &trie);
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

    /// A sink fed beside itself issues: an outbound leg whose producer
    /// runs on its own shard's issuing member takes the value directly,
    /// while one fed by the core elsewhere is that shard's delivery.
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
        assert!(
            classified.mixed_at(low()),
            "the venue's return is a delivery"
        );
        assert_eq!(
            classified
                .edges()
                .iter()
                .map(|edge| edge.producer)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "the local transfer's edge never crosses"
        );
        let issuing = classified
            .plan(&[], low(), Side::Issuing)
            .expect("the issuing member runs both withdraws and the local deposit");
        assert!(issuing.legs.runs(1) && issuing.legs.runs(4) && issuing.legs.runs(5));
        assert!(!issuing.legs.runs(3));
        assert!(issuing.legs.departure(1, 0).is_some());
        assert!(issuing.legs.departure(4, 0).is_none());
        let delivering = classified
            .plan(&[arrival(2, 0, 7)], low(), Side::Delivering)
            .expect("the delivering member runs the venue's return alone");
        assert!(delivering.legs.runs(3) && !delivering.legs.runs(5));
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
        let whole = Classified::freeze(&legs, &[], &trie());
        assert!(!whole.decomposed());
        assert!(
            !whole.only_delivers_at(low()) && !whole.mixed_at(low()),
            "a whole shape gives the sink's shard no second member to wait on it"
        );
        let mut one_sided = legs;
        one_sided[4] = leg(alice, LegRole::Outbound, &[(2, 0)], 4);
        one_sided[3] = leg(alice, LegRole::Outbound, &[], 3);
        assert!(Classified::freeze(&one_sided, &[], &trie()).decomposed());
    }
}
