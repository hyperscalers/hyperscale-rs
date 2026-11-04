//! Preview: what a candidate envelope would do, without doing it.
//!
//! A wallet's question before it signs is what a transaction moves and
//! what it costs. [`Executor::preview`] answers it by running the
//! envelope through the same derivation, the same kernel, and the same
//! fee arithmetic a tick would, against a snapshot the caller supplies —
//! and then reporting the receipt's movements and settles rather than
//! folding them into anything.
//!
//! The entry is engine-side and consensus-free by construction. There is
//! no `Action`, no `ProtocolEvent`, no network handler and no mempool
//! path: reaching it means already holding the executor and a snapshot,
//! which nothing a peer submits ever does. Nothing it computes is
//! attested, ordered, or written.
//!
//! A preview is complete exactly where its snapshot is. Cells the
//! snapshot cannot serve read absent, so an envelope spanning shards
//! previews truthfully only at a node holding every cell it touches —
//! which is a question about the snapshot, not about the preview.
//!
//! What another node answered is proven present but, for a collection
//! interval, not proven whole; the report names every such interval in
//! [`PreviewReport::unproven_intervals`] rather than presenting a gap a
//! server left as the collection's own.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use hyperscale_effects_bridge::admit_package;
use hyperscale_hbor::Capped;
use hyperscale_storage::{AnchorUnheld, SubstateStore, SubstateView, Substates, VersionedStore};
use hyperscale_types::network::request::{CellRange, MAX_RANGES_PER_QUERY};
use hyperscale_types::{
    Address, BlockHeight, CollectionId, Event, MAX_PROOFS_PER_QUERY, ShardId, ShardTrie,
    Transaction, WeightedTimestamp,
};
use hyperscale_vm_kernel::{EnvInputs, OwnerSet, Substates as KernelReads, decode_amount};
use hyperscale_vm_preview::{Report as PreviewRun, Slack, preview as preview_run};
use hyperscale_vm_types::{EffectSet, EffectTarget, Outcome, PriceTable, SeedWindow, SubstateKey};

use crate::batch::TickEnvironment;
use crate::executor::{
    PayerFee, PointReads, TickBaseline, abort_reason, batch_entry, materialize_declared,
    protocol_hash, routed_to,
};
use crate::genesis::vault_key;
use crate::{Executor, PROTOCOL_RESOURCE};

/// What a preview run is permitted that a committed execution is not.
///
/// Grants are opt-in: the empty set is the default, and a preview under
/// it answers exactly what the chain would answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreviewGrants {
    /// Run on credit: the fee is still reported, but never reaches the
    /// payer's vault. This is what lets a wallet price an envelope whose
    /// payer could not cover the ceiling it names.
    pub free_credit: bool,
}

/// A preview's point reads of the shard it reads itself, over the hosted
/// chain's view: what answers a take's or a filing's probe at an order
/// no declared interval reached.
///
/// A preview runs beside the commit pipeline, so retention can pass the
/// view's anchor mid-run. A probe the view can then no longer answer
/// reads absent and is kept as an interval nobody proved, for the report
/// to name: the run completes and says which points it could not read.
pub struct PreviewPoints {
    /// The shard the view is of: only its owners' points are read here.
    shard: ShardId,
    view: Arc<dyn HeldEntries>,
    unread: Mutex<BTreeSet<UnprovenInterval>>,
}

/// A view that says whether it still holds the entry it is asked for.
trait HeldEntries: Send + Sync {
    fn entry_held(
        &self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, AnchorUnheld>;
}

impl<S: SubstateStore + VersionedStore> HeldEntries for SubstateView<S> {
    fn entry_held(
        &self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, AnchorUnheld> {
        Self::entry_held(self, owner, collection, order)
    }
}

impl PreviewPoints {
    /// Point reads over `view`, `shard`'s chain, which the preview's
    /// snapshot is of.
    #[must_use]
    pub fn new<S: SubstateStore + VersionedStore>(
        shard: ShardId,
        view: Arc<SubstateView<S>>,
    ) -> Self {
        Self {
            shard,
            view: view as Arc<dyn HeldEntries>,
            unread: Mutex::new(BTreeSet::new()),
        }
    }

    /// The points a probe asked for and the view could not answer.
    fn unread(&self) -> BTreeSet<UnprovenInterval> {
        self.unread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// These reads as a baseline's: the owners `trie` routes to its own
    /// shard alone.
    fn reader(self: &Arc<Self>, trie: &ShardTrie) -> (OwnerSet, Arc<dyn PointReads>) {
        (
            routed_to(trie, self.shard),
            Arc::clone(self) as Arc<dyn PointReads>,
        )
    }
}

impl std::fmt::Debug for PreviewPoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreviewPoints").finish_non_exhaustive()
    }
}

impl PointReads for PreviewPoints {
    fn entry(&self, owner: Address, collection: CollectionId, order: u128) -> Option<Vec<u8>> {
        self.view
            .entry_held(owner, collection, order)
            .unwrap_or_else(|_| {
                self.unread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(UnprovenInterval {
                        owner,
                        collection,
                        lo: order,
                        hi: order,
                    });
                None
            })
    }
}

/// The transaction environment a preview reads, supplied by the caller
/// because a candidate has no committing block to take it from.
#[derive(Clone, Debug)]
pub struct PreviewInputs {
    /// The transaction clock. A committed execution reads the payer
    /// block's parent-QC weighted timestamp; while the transaction is a
    /// candidate, the caller's own tip is the nearest thing that exists.
    pub clock: WeightedTimestamp,
    /// The seeds a matured seal resolves against, and the grid that
    /// says which epoch a seal written by this run would record.
    ///
    /// A preview of a settlement is a preview of a *committed* seal: the
    /// word is already fixed by the epoch that seal named, so what runs
    /// here is what would run on chain. A preview of a *closing* is not
    /// — which epoch the seal ends up recording is decided by the block
    /// that commits it.
    pub env: TickEnvironment,
    /// What this run is granted.
    pub grants: PreviewGrants,
    /// The shards this node can answer about, and the trie that routes
    /// a declared cell to one.
    ///
    /// A preview reads committed state, and a node holds only its own
    /// shards' — so a transaction declaring a cell elsewhere is one it
    /// cannot answer about at all. Naming what it holds is what lets the
    /// report say that, rather than run against absences a kernel reads
    /// as empty cells and hand back a verdict the chain would not reach.
    pub holds: Holds,
    /// The table the quote is weighed at.
    ///
    /// A preview answers about a transaction nothing has committed yet,
    /// so there is no anchor to resolve: the caller passes the head's
    /// table, and a fold moving it between the quote and the commit is
    /// what the signed ceiling absorbs.
    pub prices: PriceTable,
    /// The point reads of the shard the snapshot is of, or `None` to
    /// answer every probe from the declared pre-read alone.
    pub points: Option<Arc<PreviewPoints>>,
}

/// What one shard is to be asked for on a preview's behalf.
///
/// The declaration's own vocabulary, split by who holds it: point cells
/// by key, collection intervals by owner, collection and order window.
///
/// One ask per declared target, however many modes reach it. A cell read
/// and written is one leaf to fetch, and asking twice for it spends the
/// server's query budget twice over to answer the same question.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredReads {
    /// Point cells to answer, present or absent.
    ///
    /// Under the same cap the request that carries them is held to, so
    /// a set this holds is one a fan-out can ask for.
    pub keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
    /// Collection intervals to answer, each at the cap the declaration
    /// signed for.
    pub ranges: Capped<Vec<CellRange>, MAX_RANGES_PER_QUERY>,
}

impl Executor {
    /// What a preview of `tx` would have to fetch, per shard that holds
    /// it, skipping the shards in `held` because the caller reads those
    /// itself.
    ///
    /// What a fan-out needs before it can ask anyone anything. The
    /// declaration is a pure function of signed content and published
    /// metadata, so it is known before a single cell is fetched, and
    /// what it names is the whole of what the run may touch.
    ///
    /// The same derivation [`Self::preview`] runs, so a fan-out gathers
    /// exactly the set the run then reads: never a cell it does not
    /// need, and never one short of what it does. An entry becomes its
    /// width-one interval here, the same normalization the materializer
    /// applies, so the two vocabulary walks stay parallel.
    ///
    /// # Errors
    ///
    /// The reason the preview would have refused with, for an envelope
    /// that does not derive at all.
    pub fn preview_reads(
        &self,
        tx: &Transaction,
        trie: &ShardTrie,
        held: &BTreeSet<ShardId>,
    ) -> Result<BTreeMap<ShardId, DeclaredReads>, String> {
        let mut by_shard: BTreeMap<ShardId, DeclaredReads> = BTreeMap::new();
        // A publish writes its own two cells and reads nobody else's, so
        // its fee vault below is the whole of what it fans out for.
        if tx.body().artifact.is_none() {
            self.declared_reads(tx, trie, held, &mut by_shard)?;
        }
        // The fee payer's vault, which the charge reads and no
        // declaration names. Added once: a payer spending its own vault
        // already named it, and asking twice buys two leaves of one
        // shard's proof and two spends of its query budget.
        let vault = vault_key(tx.body().terms.fee_payer, *PROTOCOL_RESOURCE);
        let shard = trie.shard_for_prefix(vault.owner);
        if !held.contains(&shard) {
            let asks = by_shard.entry(shard).or_default();
            if !asks.keys.contains(&vault) {
                asks.keys
                    .push(vault)
                    .map_err(|_| "declared reads name more cells than one request carries")?;
            }
        }
        Ok(by_shard)
    }

    /// What the declaration alone reaches, bucketed by the shard that
    /// holds it.
    fn declared_reads(
        &self,
        tx: &Transaction,
        trie: &ShardTrie,
        held: &BTreeSet<ShardId>,
        by_shard: &mut BTreeMap<ShardId, DeclaredReads>,
    ) -> Result<(), String> {
        let (prepared, _) = Self::prepare_admitting(tx, &self.records(), &self.world.cache)?;
        for target in prepared.declaration.set.targets() {
            let owner = match target {
                EffectTarget::Point(key) => key.owner,
                EffectTarget::Entry { owner, .. } | EffectTarget::Range { owner, .. } => owner,
            };
            let shard = trie.shard_for_prefix(owner);
            if held.contains(&shard) {
                continue;
            }
            let asks = by_shard.entry(shard).or_default();
            match target {
                EffectTarget::Point(key) => asks
                    .keys
                    .push(key)
                    .map_err(|_| "declared reads name more cells than one request carries")?,
                EffectTarget::Entry {
                    owner,
                    collection,
                    order,
                } => asks
                    .ranges
                    .push(CellRange {
                        owner,
                        collection,
                        lo: order,
                        hi: order,
                        cap: 1,
                    })
                    .map_err(|_| "declared reads name more intervals than one request carries")?,
                EffectTarget::Range {
                    owner,
                    collection,
                    lo,
                    hi,
                    cap,
                } => asks
                    .ranges
                    .push(CellRange {
                        owner,
                        collection,
                        lo,
                        hi,
                        cap,
                    })
                    .map_err(|_| "declared reads name more intervals than one request carries")?,
            }
        }
        Ok(())
    }
}

/// What a node can answer a preview about: the shards whose committed
/// state it holds, the answers a fan-out gathered for the rest, and the
/// trie that says which shard a cell is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holds {
    /// The routing in force, for resolving a declared cell's owner.
    pub trie: ShardTrie,
    /// The shards `local` answers for — which is however many shards
    /// the caller's snapshot spans, and a snapshot spans one.
    ///
    /// Not the shards the node hosts: a node hosting several holds a
    /// store apiece, and a cell on one of the others is as absent from
    /// this snapshot as a cell on a stranger's. Those are gathered
    /// like any other, from their own stores rather than over the wire.
    pub shards: BTreeSet<ShardId>,
    /// What was gathered for the shards it does not.
    ///
    /// Empty is the local-only preview: a declaration reaching past
    /// `shards` is then refused by name, which is what a node with no
    /// fan-out behind it can honestly say.
    pub fetched: FetchedCells,
}

impl Holds {
    /// Whether a cell owned by `owner` is one this node reads itself.
    fn serves(&self, owner: Address) -> bool {
        self.shards.contains(&self.trie.shard_for_prefix(owner))
    }

    /// The shard `owner`'s cells live on, if neither this node nor a
    /// fan-out can answer for it.
    fn unanswered(&self, owner: Address) -> Option<ShardId> {
        let shard = self.trie.shard_for_prefix(owner);
        (!self.shards.contains(&shard) && !self.fetched.anchors.contains_key(&shard))
            .then_some(shard)
    }

    /// The shards `declared` and the fee payer's vault reach that
    /// neither this node holds nor a fan-out answered for.
    ///
    /// The vault beside the declaration because the charge reads it and
    /// no declaration names it: a composer paying out of an account on
    /// another shard is the ordinary cross-shard case, and a cell nobody
    /// was asked for is not an empty cell.
    fn missing(&self, declared: &EffectSet, payer: Address) -> BTreeSet<ShardId> {
        declared
            .iter()
            .map(|effect| match effect.target {
                EffectTarget::Point(key) => key.owner,
                EffectTarget::Entry { owner, .. } | EffectTarget::Range { owner, .. } => owner,
            })
            .chain(std::iter::once(payer))
            .filter_map(|owner| self.unanswered(owner))
            .collect()
    }
}

/// One collection's answered entries, ascending by order.
pub type FetchedEntries = Vec<(u128, Vec<u8>)>;

/// The committed state a fan-out gathered from shards this node does not
/// serve, in the shape a run reads it.
///
/// A [`Substates`] rather than a bag the executor unpacks, so a remote
/// cell and a local one materialize through the one call: what differs
/// between them is which store answered, and nothing downstream of that
/// needs to know.
///
/// Only shards named in `anchors` were answered. A shard absent from it
/// was never asked or never replied, and [`Holds::missing`] refuses the
/// preview by name rather than letting a kernel read the silence as an
/// empty cell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchedCells {
    /// Point cells that were present under their shard's proof.
    pub cells: BTreeMap<SubstateKey, Vec<u8>>,
    /// Entries per collection, ascending by order and one to an order,
    /// as the serving shard answered the declared intervals.
    pub entries: BTreeMap<(Address, CollectionId), FetchedEntries>,
    /// The committed height each answering shard spoke at.
    ///
    /// One per shard and chosen by the server, so a preview over several
    /// is a run over snapshots that were never simultaneous — which is
    /// the optimism the report already declares, stated in heights.
    pub anchors: BTreeMap<ShardId, BlockHeight>,
    /// The declared intervals another node answered, each of which is
    /// that node's word on what the interval leaves out.
    ///
    /// Every entry an interval returns is proven under its shard's root,
    /// but nothing proves the interval holds no entry the server
    /// omitted, so an answer narrower than the collection reads as a
    /// collection holding less. Two kinds of interval are not here: one
    /// this node answered out of a store of its own, for the same reason
    /// the snapshot's own reads are not, since the report is already
    /// this node's word; and one of a single order whose leaf the proof
    /// attests — present with the entry that came back, or absent when
    /// none did — which leaves nothing to omit.
    pub unproven: BTreeSet<UnprovenInterval>,
}

/// A declared collection interval whose answer is proven present entry
/// by entry and not proven whole.
///
/// Keyed the way the declaration names it, so a caller can tell which of
/// its reads rests on a server's completeness and ask another for that
/// interval. The cap is not part of it: an omission is a property of the
/// interval, and two caps over one interval rest on the same answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnprovenInterval {
    /// The collection's owner, which fixes the shard that answered.
    pub owner: Address,
    /// The collection under that owner.
    pub collection: CollectionId,
    /// The first order in the interval, inclusive.
    pub lo: u128,
    /// The last order in the interval, inclusive.
    pub hi: u128,
}

impl From<&CellRange> for UnprovenInterval {
    fn from(range: &CellRange) -> Self {
        Self {
            owner: range.owner,
            collection: range.collection,
            lo: range.lo,
            hi: range.hi,
        }
    }
}

impl FetchedCells {
    /// Fold another gathering's answers into this one.
    ///
    /// One shard's worth at a time, because verification decides a
    /// peer's verdict and so has to finish before the answer is handed
    /// back — what arrives here has already been checked against the
    /// root its shard attested.
    pub fn absorb_from(&mut self, other: Self) {
        self.cells.extend(other.cells);
        for ((owner, collection), entries) in other.entries {
            self.merge_entries(owner, collection, entries);
        }
        self.anchors.extend(other.anchors);
        self.unproven.extend(other.unproven);
    }

    /// Fold one interval's answer into its collection, keeping the
    /// entries ascending and one to an order.
    ///
    /// A collection is reached by as many declared targets as the
    /// manifest names it in, and they all share this one bucket: an
    /// entry and a range over the same collection are distinct targets,
    /// and two ranges may overlap. Appending would leave the bucket
    /// unsorted and doubled, which is the one property
    /// [`entries_in_range`](Substates::entries_in_range) reads it for —
    /// it filters and takes, and never sorts.
    ///
    /// Two answers to one order are two readings of one leaf under one
    /// root, so keeping either is keeping what that root attested.
    pub fn merge_entries(
        &mut self,
        owner: Address,
        collection: CollectionId,
        answered: impl IntoIterator<Item = (u128, Vec<u8>)>,
    ) {
        let entries = self.entries.entry((owner, collection)).or_default();
        entries.extend(answered);
        entries.sort_by_key(|(order, _)| *order);
        entries.dedup_by_key(|(order, _)| *order);
    }
}

impl Substates for FetchedCells {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> FetchedEntries {
        self.entries
            .get(&(owner, collection))
            .into_iter()
            .flatten()
            .filter(|(order, _)| (lo..=hi).contains(order))
            .take(limit)
            .cloned()
            .collect()
    }
}

/// The committed state a preview reads: this node's own where it serves
/// the shard, and what a fan-out fetched where it does not.
///
/// The routing is by owner, which is what fixes a cell's shard, so the
/// two halves can never both answer for one cell and a cell neither
/// answers for was refused before the run.
struct PreviewCells<'a> {
    local: &'a (dyn Substates + Sync),
    holds: &'a Holds,
}

impl Substates for PreviewCells<'_> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        if self.holds.serves(key.owner) {
            self.local.cell(key)
        } else {
            self.holds.fetched.cell(key)
        }
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if self.holds.serves(owner) {
            self.local
                .entries_in_range(owner, collection, lo, hi, limit)
        } else {
            self.holds
                .fetched
                .entries_in_range(owner, collection, lo, hi, limit)
        }
    }
}

/// How a previewed envelope ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// It completed: the reported changes are what would apply.
    Completed,
    /// It aborted, so nothing but the fee would apply.
    Aborted {
        /// The deterministic reason, as the receipt would carry it.
        reason: String,
    },
    /// It could not be admitted, so it would never enter a block and
    /// nobody would pay for it.
    Refused {
        /// Why admission would refuse it.
        reason: String,
    },
}

/// One amount cell's change under a previewed envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceChange {
    /// The cell.
    pub key: SubstateKey,
    /// What the snapshot held.
    pub before: u128,
    /// What the envelope would leave — the fee included, unless the run
    /// was free-credited.
    pub after: u128,
    /// Credited to the cell by commutative movement.
    pub credit: u128,
    /// Debited from it by commutative movement.
    pub debit: u128,
    /// Settled out of a reservation the transaction held on it.
    pub settled: u128,
}

impl ResourceChange {
    /// An untouched cell at its committed amount.
    const fn at(key: SubstateKey, before: u128) -> Self {
        Self {
            key,
            before,
            after: before,
            credit: 0,
            debit: 0,
            settled: 0,
        }
    }
}

/// What a candidate envelope would move and what it would cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewReport {
    /// How the run ended.
    pub outcome: PreviewOutcome,
    /// Every amount cell the run moved, in canonical key order, plus the
    /// payer's vault whenever the fee reaches it.
    pub changes: Vec<ResourceChange>,
    /// What the payer would burn. Zero for a refusal, which costs
    /// nothing because it never reaches a block.
    pub fee: u128,
    /// Fuel the run consumed — what the fee is the capped form of, so a
    /// wallet can see whether its ceiling bound the charge.
    pub fuel: u64,
    /// The ceiling each node's run asks for, in node order: what it
    /// spent with a margin over it. What a composer signs into
    /// `gas_limits`, which is the reason a preview exists before the
    /// envelope does.
    pub ceilings: Vec<u64>,
    /// What the run emitted.
    pub(crate) events: Vec<Event>,
    /// The committed height each answering shard read at, by shard.
    ///
    /// A preview is a statement about state at a moment, and the moment
    /// is the server's: each height is chosen by whoever answered, so a
    /// run over several shards is a run over snapshots that were never
    /// simultaneous. Carried out rather than discarded because the
    /// ceilings beside it are what a composer signs — a report taken over
    /// state far behind the tip yields ceilings a real run can trip, and
    /// the fee burns on the trap. A caller that cannot judge the age
    /// cannot see that coming.
    ///
    /// Empty for a verdict that read no shard: a refusal before the run,
    /// or a publish, whose answer is a pure function of its bytes.
    pub anchors: BTreeMap<ShardId, BlockHeight>,
    /// The declared intervals the run read on another node's word that
    /// they leave nothing out.
    ///
    /// Each entry such an interval returned is proven, but the interval
    /// is not proven whole: a server can answer with fewer entries than
    /// it holds, and the run reads the gap as empty. A verdict, a fee or
    /// a ceiling here may rest on that gap, so a caller that cannot
    /// accept a server's completeness asks another node for these
    /// intervals or does not sign. Point cells are never here: each is
    /// proven present or proven absent. See [`FetchedCells::unproven`]
    /// for the intervals that are whole without a completeness proof.
    ///
    /// Empty for a verdict that read no shard, and for a run whose every
    /// interval this node answered from its own stores.
    pub unproven_intervals: BTreeSet<UnprovenInterval>,
}

impl PreviewReport {
    /// The report for an envelope that never reached execution.
    fn refused(reason: impl Into<String>) -> Self {
        Self {
            outcome: PreviewOutcome::Refused {
                reason: reason.into(),
            },
            changes: Vec::new(),
            fee: 0,
            fuel: 0,
            ceilings: Vec::new(),
            events: Vec::new(),
            anchors: BTreeMap::new(),
            unproven_intervals: BTreeSet::new(),
        }
    }
}

/// The committed amount a cell holds in `base`, absent reading as zero —
/// the same reading the fold gives an absent cell.
fn amount_at(base: &TickBaseline, key: SubstateKey) -> u128 {
    base.cells
        .get(&key)
        .map_or(0, |bytes| decode_amount(bytes).unwrap_or(0))
}

/// Fold a run's movements and settles into the wallet's report, landing
/// the fee on the payer's vault unless the run was credited.
///
/// The walk is `OwnerSet::whole()` deliberately: the report answers what the
/// transaction does, and which shard applies which part of it is a
/// question about commitment, not about resources.
fn resource_changes(
    base: &TickBaseline,
    moved: Option<&PreviewRun>,
    fee: u128,
    payer: SubstateKey,
    grants: PreviewGrants,
) -> Vec<ResourceChange> {
    let mut changes: BTreeMap<SubstateKey, ResourceChange> = BTreeMap::new();
    if let Some(moved) = moved {
        for (key, movement) in &moved.movements {
            let change = changes
                .entry(*key)
                .or_insert_with(|| ResourceChange::at(*key, amount_at(base, *key)));
            change.credit = change.credit.saturating_add(movement.credit);
            change.debit = change.debit.saturating_add(movement.debit);
        }
        for (key, settled) in &moved.settles {
            let change = changes
                .entry(*key)
                .or_insert_with(|| ResourceChange::at(*key, amount_at(base, *key)));
            change.settled = change.settled.saturating_add(settled.debit);
        }
    }
    let charged_to = (fee > 0 && !grants.free_credit).then_some(payer);
    if let Some(vault) = charged_to {
        changes
            .entry(vault)
            .or_insert_with(|| ResourceChange::at(vault, amount_at(base, vault)));
    }
    changes
        .into_values()
        .map(|mut change| {
            let charged = if charged_to == Some(change.key) {
                fee
            } else {
                0
            };
            change.after = change
                .before
                .saturating_add(change.credit)
                .saturating_sub(change.debit)
                .saturating_sub(change.settled)
                .saturating_sub(charged);
            change
        })
        .collect()
}

impl Executor {
    /// Run `tx` against `snapshot` and report what it would move and what
    /// it would cost, committing nothing.
    ///
    /// `tx` is the envelope in the wire form a wallet would submit, so
    /// the preview's identity — which fresh-key derivation roots at — is
    /// the one the chain would use.
    #[must_use]
    pub fn preview(
        &self,
        snapshot: &(dyn Substates + Sync),
        tx: &Transaction,
        inputs: &PreviewInputs,
    ) -> PreviewReport {
        let vm = tx.body();
        // Read off the envelope rather than off `fee_vault`, which
        // panics on an envelope derivation refuses — the exact envelope
        // a preview exists to give an answer about.
        let terms = &vm.terms;
        let vault = vault_key(terms.fee_payer, *PROTOCOL_RESOURCE);
        // Local cells and fetched ones through the one call: which store
        // answered is the routing's business and nothing below it.
        let cells = PreviewCells {
            local: snapshot,
            holds: &inputs.holds,
        };
        if let Some(artifact) = &vm.artifact {
            // The report says what the charge would leave, which is a
            // reading of the payer's vault. A node that cannot answer
            // for it names the shard rather than reporting a cell it
            // asked nobody about.
            if let Some(shard) = inputs.holds.unanswered(vault.owner) {
                return PreviewReport::refused(format!(
                    "this node holds {:?} and the fee payer's vault is on {shard:?}",
                    inputs.holds.shards
                ));
            }
            let payer = PayerFee {
                vault,
                max_fee: terms.max_fee,
                // A publish is priced through the table like anything
                // else: its artifact is retention and its two point
                // writes are writes, all of it in the declared vector.
                price: match tx.price_under(self.derivation().as_ref(), &inputs.prices) {
                    Ok(price) => price,
                    Err(error) => return PreviewReport::refused(error.to_string()),
                },
                abortable: false,
            };
            return preview_publish(&cells, artifact, payer, inputs.grants);
        }

        // A preview is advisory, so it answers from what this node
        // holds rather than from what a block carries: it is not
        // producing a receipt root, and a client asking what an envelope
        // would do wants the answer for a component whose seal landed on
        // some other shard.
        let (prepared, admitted) =
            match Self::prepare_admitting(tx, &self.records(), &self.world.cache) {
                Ok(derived) => derived,
                Err(reason) => return PreviewReport::refused(reason),
            };
        let payer = PayerFee {
            vault,
            max_fee: terms.max_fee,
            // The declaration's price, read off what prepared rather
            // than derived again: the preparation above already lowered
            // the envelope, and deriving a second time would price the
            // same fold twice.
            price: inputs.prices.price(&prepared.work, terms.priority_bp),
            // A preview is one envelope against one snapshot: no tick can
            // discard effects it completed, so the reserve-receipt shape
            // does not arise.
            abortable: false,
        };
        // A cell this node does not hold is not an empty cell, and a
        // kernel cannot tell the two apart: it would read the absence,
        // refuse the withdrawal over it, and the report would name a
        // verdict the chain never reaches. So the shards are checked
        // before the run rather than the run explaining itself after.
        let missing = inputs.holds.missing(&prepared.declaration.set, vault.owner);
        if !missing.is_empty() {
            return PreviewReport::refused(format!(
                "this node holds {:?} and the transaction reads cells on {missing:?}",
                inputs.holds.shards
            ));
        }
        // A preview judges against committed state alone: it is not in
        // a tick, so no tick's reservation is in flight over the
        // baseline it reads, and total locality covers every cell the
        // envelope touches.
        // A probe past the pre-read reads this node's own shard through
        // the hosted chain; an owner the preview fetched reads what was
        // fetched alone, so a probe past it is advisory.
        let mut base = TickBaseline {
            points: inputs
                .points
                .as_ref()
                .map(|points| points.reader(&inputs.holds.trie)),
            ..TickBaseline::default()
        };
        materialize_declared(
            &cells,
            &prepared.declaration.set,
            &OwnerSet::whole(),
            &mut base,
        );
        // The fee vault is not a declared effect, and the report needs
        // its committed amount to say what the charge would leave. Read
        // through the same routing: a composer paying out of an account
        // on another shard is the ordinary cross-shard case.
        if let Some(value) = cells.cell(payer.vault) {
            base.cells.insert(payer.vault, value);
        }
        let base = Arc::new(base);

        let vm_tx = tx.hash();
        // The same entry a tick would run, so the report meters against
        // the bounds the chain would: total locality is the one thing a
        // preview differs in, and it differs deliberately.
        let batch = [batch_entry(
            vm_tx,
            &prepared,
            EnvInputs {
                clock_ms: inputs.clock.as_millis(),
                epoch: inputs.env.windows.epoch_for(inputs.clock).inner(),
                // A node short of the frontier previews every draw as
                // not yet rolled: a preview waits on nothing, and the
                // chain would wait for the seed rather than guess it.
                seeds: inputs
                    .env
                    .seed_window_for(inputs.clock)
                    .unwrap_or_else(SeedWindow::unfolded),
            },
            OwnerSet::whole(),
            None,
            false,
        )];
        // The run itself is the preview library's: it holds the source
        // seam, the optimism a report rests on, and the ceiling policy,
        // so a wallet asking a node and a wallet asking a fixture get
        // the same answer in the same shape. What stays here is what
        // needs the chain: the price, the payer's vault and the amounts
        // behind the cells the run moved.
        let report = preview_run(
            &batch[0],
            Some(&admitted),
            Arc::clone(&base) as Arc<dyn KernelReads>,
            &self.backend,
            protocol_hash,
            Slack::GENEROUS,
        );
        // One price whatever the outcome, held to the ceiling like the burn.
        let fee = payer.price.min(payer.max_fee);
        PreviewReport {
            outcome: preview_outcome(&report.outcome),
            changes: resource_changes(&base, Some(&report), fee, payer.vault, inputs.grants),
            fee,
            fuel: report.spent.iter().fold(0u64, |t, n| t.saturating_add(*n)),
            ceilings: report.ceilings,
            events: report.events,
            anchors: inputs.holds.fetched.anchors.clone(),
            unproven_intervals: inputs.unproven(),
        }
    }
}

impl PreviewInputs {
    /// Every read the run rests on that nobody proved: the intervals a
    /// server answered, and the points this node's own view could no
    /// longer read.
    fn unproven(&self) -> BTreeSet<UnprovenInterval> {
        let mut unproven = self.holds.fetched.unproven.clone();
        unproven.extend(self.points.iter().flat_map(|points| points.unread()));
        unproven
    }
}

/// A publish's answer, which needs no state: the whole verdict is a pure
/// function of the artifact's bytes, and its price is one derivation over
/// their length.
///
/// An artifact admission refuses costs nothing, because a publish that
/// cannot be admitted never enters a block.
fn preview_publish(
    snapshot: &(dyn Substates + Sync),
    artifact: &[u8],
    payer: PayerFee,
    grants: PreviewGrants,
) -> PreviewReport {
    if let Err(error) = admit_package(artifact) {
        return PreviewReport::refused(error.to_string());
    }
    let mut base = TickBaseline::default();
    if let Some(value) = snapshot.cell(payer.vault) {
        base.cells.insert(payer.vault, value);
    }
    let fee = payer.price.min(payer.max_fee);
    PreviewReport {
        outcome: PreviewOutcome::Completed,
        changes: resource_changes(&base, None, fee, payer.vault, grants),
        fee,
        // A publish invokes nothing, so nothing burns fuel and there is
        // no node to bound; what it costs is the fee above, which
        // prices its artifact as bytes retained and written rather than
        // as anything executed.
        fuel: 0,
        ceilings: Vec::new(),
        events: Vec::new(),
        // A publish reads no shard's state: its verdict is a pure
        // function of the artifact's bytes.
        anchors: BTreeMap::new(),
        unproven_intervals: BTreeSet::new(),
    }
}

/// The kernel's verdict as a preview reports it.
///
/// The reason is the one a tick would record, so a wallet reads the same
/// text the chain would.
fn preview_outcome(outcome: &Outcome) -> PreviewOutcome {
    match outcome {
        Outcome::Completed { .. } => PreviewOutcome::Completed,
        aborted => PreviewOutcome::Aborted {
            reason: abort_reason(aborted),
        },
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{AddressClass, LocalKey};
    use hyperscale_vm_types::{Effect, Mode};

    use super::*;

    const COLLECTION: CollectionId = CollectionId([0xEE; 16]);

    fn owner(seed: u8) -> Address {
        Address::new([seed; 31], AddressClass::Component)
    }

    fn point(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: owner(seed),
            local: LocalKey([seed; 16]),
        }
    }

    /// A fan-out's answers read back as the store they stand in for:
    /// a cell it carries, nothing for one it does not, and an interval
    /// narrowed to what the caller asks of it.
    #[test]
    fn fetched_cells_answer_as_a_store() {
        let mut fetched = FetchedCells::default();
        fetched.cells.insert(point(1), vec![7]);
        fetched.entries.insert(
            (owner(2), COLLECTION),
            (0u128..8)
                .map(|order| (order, vec![u8::try_from(order).expect("eight entries")]))
                .collect(),
        );

        assert_eq!(fetched.cell(point(1)), Some(vec![7]));
        assert_eq!(
            fetched.cell(point(9)),
            None,
            "a cell nobody fetched is not a cell the store holds"
        );
        assert_eq!(
            fetched
                .entries_in_range(owner(2), COLLECTION, 2, 5, 2)
                .iter()
                .map(|(order, _)| *order)
                .collect::<Vec<_>>(),
            vec![2, 3],
            "the interval is bounded by both the caller's window and its limit"
        );
        assert!(
            fetched
                .entries_in_range(owner(9), COLLECTION, 0, u128::MAX, 8)
                .is_empty(),
            "a collection nobody fetched is empty, and the shard's absence from \
             `anchors` is what keeps that from being read as a verdict"
        );
    }

    /// Several answers about one collection are one collection.
    ///
    /// An entry and a range over it are distinct declared targets that
    /// share a bucket, and two ranges may overlap — so the fold merges.
    /// Appending would leave the bucket out of order and doubled, and
    /// `entries_in_range` filters and takes without ever sorting, so the
    /// doubling reaches the run as entries the collection does not hold.
    #[test]
    fn answers_about_one_collection_merge_rather_than_stack() {
        let mut fetched = FetchedCells::default();
        // A range over [4, 6], then the entry at 1, then a second range
        // overlapping the first: the order answers arrive in is the
        // order the declaration named its targets, which is nobody's
        // idea of ascending.
        fetched.merge_entries(owner(2), COLLECTION, [(4u128, vec![4]), (6, vec![6])]);
        fetched.merge_entries(owner(2), COLLECTION, [(1u128, vec![1])]);
        fetched.merge_entries(owner(2), COLLECTION, [(4u128, vec![4]), (5, vec![5])]);

        assert_eq!(
            fetched.entries[&(owner(2), COLLECTION)]
                .iter()
                .map(|(order, _)| *order)
                .collect::<Vec<_>>(),
            vec![1, 4, 5, 6],
            "ascending, and one to an order"
        );
        assert_eq!(
            fetched
                .entries_in_range(owner(2), COLLECTION, 0, u128::MAX, 3)
                .iter()
                .map(|(order, _)| *order)
                .collect::<Vec<_>>(),
            vec![1, 4, 5],
            "so a limit takes the lowest three and not whichever three \
             happened to be answered first"
        );
    }

    /// A shard a fan-out answered for is no longer missing; one it was
    /// silent about still is, however many cells happen to be in hand.
    #[test]
    fn an_answered_shard_is_not_missing() {
        let trie = ShardTrie::uniform_from_count(2);
        let mut declared = EffectSet::new();
        for seed in [0x00u8, 0xFF] {
            declared
                .insert_at_cap(Effect {
                    target: EffectTarget::Point(point(seed)),
                    mode: Mode::Read,
                })
                .unwrap();
        }
        let reached: BTreeSet<ShardId> = [owner(0x00), owner(0xFF)]
            .iter()
            .map(|o| trie.shard_for_prefix(*o))
            .collect();
        assert_eq!(
            reached.len(),
            2,
            "the fixture has to straddle to have teeth"
        );
        let (held, remote) = {
            let mut it = reached.iter();
            (*it.next().unwrap(), *it.next().unwrap())
        };

        let local_only = Holds {
            trie: trie.clone(),
            shards: BTreeSet::from([held]),
            fetched: FetchedCells::default(),
        };
        let on = |shard| {
            [owner(0x00), owner(0xFF)]
                .into_iter()
                .find(|o| trie.shard_for_prefix(*o) == shard)
                .expect("one of the fixture's two owners is on each shard")
        };
        assert_eq!(
            local_only.missing(&declared, on(held)),
            BTreeSet::from([remote]),
            "with no fan-out behind it, the far shard is one this node cannot answer about"
        );

        // And the fee payer's vault answers to the same rule though no
        // declaration names it: a sponsored transfer whose manifest is
        // entirely local still reads a cell on the payer's own shard,
        // and a cell nobody was asked for is not an empty cell.
        assert_eq!(
            local_only.missing(&EffectSet::new(), on(remote)),
            BTreeSet::from([remote]),
            "a payer this node cannot answer for refuses the preview \
             rather than reading its vault as zero"
        );

        let mut fetched = FetchedCells::default();
        fetched.anchors.insert(remote, BlockHeight::new(9));
        let fanned_out = Holds {
            trie: trie.clone(),
            shards: BTreeSet::from([held]),
            fetched,
        };
        assert!(
            fanned_out.missing(&declared, on(held)).is_empty(),
            "a shard that answered is one the preview can speak for"
        );
    }
}

/// A preview's probes past its pre-read, read through the hosted chain.
#[cfg(test)]
mod point_tests {
    use std::sync::LazyLock;

    use hyperscale_effects_bridge::account_address;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified, placeholder_local_ec,
        push_certificate,
    };
    use hyperscale_storage::{
        ChainEntry, ChainWrites, GenesisCommit, MemberInputs, ParentAnchor, PendingChain,
        ShardChainWriter,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_transactions::{Ceilings, Client, Terms};
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, ConsensusReceipt, Ed25519PrivateKey, EntryKey, Epoch,
        Finalization, FrontierInputs, GlobalReceiptHash, MAX_INTENT_VALIDITY_RANGE, NetworkId,
        PrincipalAddr, ProposerTimestamp, ProtocolHasher, QuorumCertificate, RETENTION_HORIZON,
        ResourceAddr, Round, SettledWrites, SignerBitfield, StoredReceipt, TickHalf, TickId,
        TimestampRange, TxHash, WitnessSources,
    };
    use hyperscale_vm_effects::holdings_collection;
    use hyperscale_vm_kernel::ExecutionMode;
    use hyperscale_vm_stdlib::account;

    use super::*;
    use crate::genesis::{GenesisPackages, genesis_writes};

    const ALICE: u8 = 1;
    const BOB: u8 = 2;
    /// The non-fungible resource Alice holds.
    const NF: ResourceAddr = ResourceAddr::new([0xE7; 31]);

    fn key_of(seed: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
    }

    fn principal(seed: u8) -> PrincipalAddr {
        account_address(&key_of(seed).public_key().0)
    }

    fn client() -> &'static Client {
        static CLIENT: LazyLock<Client> = LazyLock::new(|| Client::genesis(NetworkId(244)));
        &CLIENT
    }

    /// Alice's holdings entry at `id`.
    fn held(id: u128) -> EntryKey {
        let alice = principal(ALICE);
        EntryKey {
            owner: alice.address(),
            collection: holdings_collection(&ProtocolHasher, alice, NF),
            order: id,
        }
    }

    /// Genesis funding Alice and Bob, Alice holding the [`NF`] ids named.
    fn holding(ids: &[u128]) -> Arc<SimShardStorage> {
        let genesis = genesis_writes(
            &[(principal(ALICE), 10_000), (principal(BOB), 10_000)],
            &[],
            &GenesisPackages::protocol(),
        );
        let (cells, _) = genesis.into_parts();
        let entries = ids.iter().map(|id| (held(*id), Some(vec![1]))).collect();
        let seeded = SettledWrites::from_parts(cells, entries);
        let storage = SimShardStorage::default();
        storage.install_genesis(&seeded, &seeded);
        Arc::new(storage)
    }

    /// Alice withdraws `id` and deposits it with Bob. `withdraw-nf`
    /// declares her holdings at a cap of one, so the pre-read lifts her
    /// two lowest ids and a later one is the take's own probe.
    fn withdrawal_of(id: u64) -> Transaction {
        let chain = client().records();
        let mut b = client().builder(&chain, principal(ALICE));
        let funds =
            account::withdraw_nf(&mut b, principal(ALICE), NF, &[id]).expect("withdraw-nf types");
        account::deposit_nf(&mut b, principal(BOB), funds).expect("deposit-nf types");
        let graph = b.build().expect("every output is consumed");
        let validity = TimestampRange::new(
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(MAX_INTENT_VALIDITY_RANGE.as_secs() * 1_000),
        );
        Transaction::new(client().sign(
            graph,
            &key_of(ALICE),
            validity,
            Terms {
                max_fee: 1_000,
                ceilings: Ceilings::Guessed,
                priority_bp: 0,
                message: Vec::new(),
            },
        ))
    }

    /// Preview `tx` over `snapshot`, its probes read through `points`.
    fn preview_over(
        snapshot: &(dyn Substates + Sync),
        tx: &Transaction,
        points: Arc<PreviewPoints>,
    ) -> PreviewReport {
        Executor::new(ExecutionMode::Serial).preview(
            snapshot,
            tx,
            &PreviewInputs {
                clock: WeightedTimestamp::from_millis(1_000),
                env: TickEnvironment::unfolded(),
                grants: PreviewGrants::default(),
                holds: Holds {
                    trie: ShardTrie::single(),
                    shards: BTreeSet::from([ShardId::ROOT]),
                    fetched: FetchedCells::default(),
                },
                prices: PriceTable::GENESIS,
                points: Some(points),
            },
        )
    }

    /// A probe at a point the view no longer holds, because retention
    /// passed its anchor while the preview ran, reads absent and is named
    /// as a point nobody proved: the report completes and says so.
    #[test]
    fn a_preview_probe_past_retention_reports_it_unproven() {
        let horizon = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        let storage = holding(&[1, 2, 3]);
        let chain = Arc::new(PendingChain::new(
            Arc::clone(&storage),
            BlockHeight::GENESIS,
        ));
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        // A block whose parent QC stamps `ms`, the clock retention is
        // measured against.
        let block = |height: u64, ms: u64| {
            let parent_qc = QuorumCertificate::new(
                BlockHash::ZERO,
                ShardId::ROOT,
                BlockHeight::new(height - 1),
                BlockHash::ZERO,
                Round::INITIAL,
                Epoch::GENESIS,
                SignerBitfield::new(4),
                AggregateSignature::new([0u8; 96]),
                WeightedTimestamp::from_millis(ms),
            );
            make_test_certified(Block::Live {
                header: BlockHeader::new(BlockHeaderParts {
                    shard_id: ShardId::ROOT,
                    height: BlockHeight::new(height),
                    parent_block_hash: BlockHash::ZERO,
                    parent_qc: parent_qc.into(),
                    timestamp: ProposerTimestamp::from_millis(ms),
                    ..Default::default()
                }),
                transactions: Arc::new(Capped::empty()),
                certificates: Arc::new(Capped::empty()),
                provisions: Arc::new(Capped::empty()),
                abandonment_records: Arc::new(Capped::empty()),
                state_claims: Arc::new(Capped::empty()),
                tick_manifest: Arc::new(Capped::empty()),
                terms: Arc::new(Capped::empty()),
                witness_sources: Arc::new(WitnessSources::empty()),
            })
        };
        commit_settled_at(&*storage, &block(1, 1_000), &[], &[], &witness);
        let started = chain.view_at_persisted_tip();
        commit_settled_at(&*storage, &block(2, 1_001 + horizon), &[], &[], &witness);
        assert!(
            started
                .entry_held(held(3).owner, held(3).collection, 3)
                .is_err(),
            "the started view's anchor has aged out"
        );

        let now = chain.view_at_persisted_tip();
        let report = preview_over(
            &now.snapshot(),
            &withdrawal_of(3),
            Arc::new(PreviewPoints::new(ShardId::ROOT, started)),
        );
        assert!(
            matches!(report.outcome, PreviewOutcome::Aborted { .. }),
            "the probe read the id as absent: {:?}",
            report.outcome
        );
        assert_eq!(
            report.unproven_intervals,
            BTreeSet::from([UnprovenInterval {
                owner: held(3).owner,
                collection: held(3).collection,
                lo: 3,
                hi: 3,
            }]),
            "and the report names the point it could not read"
        );
    }

    /// A view anchored at a block still pending answers a probe out of
    /// that block's own writes.
    #[test]
    fn a_preview_on_a_pending_tip_reads_its_points() {
        let storage = holding(&[1, 2]);
        let chain = Arc::new(PendingChain::new(
            Arc::clone(&storage),
            BlockHeight::GENESIS,
        ));
        let parent_height = storage.jmt_height();
        let height = parent_height.next();

        // The pending block files id 3 with Alice.
        let writes =
            SettledWrites::from_parts(BTreeMap::new(), BTreeMap::from([(held(3), Some(vec![1]))]));
        let receipt = StoredReceipt {
            tx_hash: TxHash::ZERO,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes: writes.into(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        };
        let finalization = Finalization::new(
            TickId::new(ShardId::ROOT, height),
            TickHalf::Determined,
            Some(placeholder_local_ec(ShardId::ROOT, height)),
            Capped::from_array([receipt]),
        );
        let certified = make_test_certified(push_certificate(
            make_test_block(height),
            finalization.into(),
        ));
        let block = certified.block();
        let parent_view = chain.view_at(block.header().parent_block_hash(), parent_height);
        let anchored = parent_view.snapshot();
        let (_, jmt_snapshot, _) = storage.prepare_block_commit(
            ParentAnchor {
                state_root: storage.state_root(),
                height: parent_height,
                state: &anchored,
                pending: parent_view.pending_snapshots(),
                base_reads: None,
            },
            &block.certificates()[..],
            ChainWrites {
                creations: &[],
                removals: &[],
                sweep_frontier: block.header().sweep_frontier(),
                frontier: &FrontierInputs::still(ShardId::ROOT),
                state_claims: block.state_claims(),
                members: &MemberInputs::still(ShardId::ROOT),
            },
            height,
        );
        chain.insert(
            block.hash(),
            ChainEntry {
                parent_block_hash: block.header().parent_block_hash(),
                height,
                settled_txs: Vec::new(),
                jmt_snapshot,
                certified_block: Some(Arc::clone(&certified)),
            },
        );

        let tip = chain.view_at(block.hash(), height);
        assert_eq!(
            tip.entry_held(held(3).owner, held(3).collection, 3),
            Ok(Some(vec![1])),
            "the pending block's own write answers"
        );
        let report = preview_over(
            &tip.snapshot(),
            &withdrawal_of(3),
            Arc::new(PreviewPoints::new(ShardId::ROOT, Arc::clone(&tip))),
        );
        assert_eq!(
            report.outcome,
            PreviewOutcome::Completed,
            "the take found the id the pending tip filed"
        );
        assert!(report.unproven_intervals.is_empty());
    }
}
