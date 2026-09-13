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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_effects_bridge::admit_package;
use hyperscale_storage::Substates;
use hyperscale_types::{
    Address, BlockHeight, CollectionId, Event, ShardId, ShardTrie, Transaction, WeightedTimestamp,
};
// The vm's own shard vocabulary, which a source's anchor is stated in;
// the consensus `ShardId` above is what a trie routes to.
use hyperscale_vm_effects::ShardId as SourceShard;
use hyperscale_vm_kernel::{EnvInputs, OwnerSet, decode_amount};
use hyperscale_vm_preview::{
    CellSource, Local, Report as PreviewRun, Slack, preview as preview_run,
};
use hyperscale_vm_types::{EffectSet, EffectTarget, Outcome, PriceTable, SubstateKey};

use crate::batch::TickEnvironment;
use crate::executor::{
    PayerFee, TargetAuthority, TickBaseline, abort_reason, batch_entry, materialize_declared,
    protocol_hash,
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
    /// Treat every gated node as carrying its target's authority.
    ///
    /// A composition is priced and displayed before its counterparties
    /// sign, so a wallet needs an answer about an envelope that is not
    /// yet admissible — and refusing it would leave the wallet unable to
    /// show the user what they are being asked to sign. Granting this is
    /// the caller saying they know the difference.
    pub assume_target_auth: bool,
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
}

/// What a node can answer a preview about: the shards whose committed
/// state it holds, the answers a fan-out gathered for the rest, and the
/// trie that says which shard a cell is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holds {
    /// The routing in force, for resolving a declared cell's owner.
    pub trie: ShardTrie,
    /// The shards this node serves state for.
    pub shards: BTreeSet<ShardId>,
    /// What was fetched from the shards it does not.
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

    /// The shards `declared` reaches that neither this node holds nor a
    /// fan-out answered for.
    fn missing(&self, declared: &EffectSet) -> BTreeSet<ShardId> {
        declared
            .iter()
            .map(|effect| match effect.target {
                EffectTarget::Point(key) => key.owner,
                EffectTarget::Entry { owner, .. } | EffectTarget::Range { owner, .. } => owner,
            })
            .map(|owner| self.trie.shard_for_prefix(owner))
            .filter(|shard| {
                !self.shards.contains(shard) && !self.fetched.anchors.contains_key(shard)
            })
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
    /// Entries per collection, ascending by order, as the serving shard
    /// answered the declared interval.
    pub entries: BTreeMap<(Address, CollectionId), FetchedEntries>,
    /// The committed height each answering shard spoke at.
    ///
    /// One per shard and chosen by the server, so a preview over several
    /// is a run over snapshots that were never simultaneous — which is
    /// the optimism the report already declares, stated in heights.
    pub anchors: BTreeMap<ShardId, BlockHeight>,
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
    pub events: Vec<Event>,
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
        // Derived rather than read off `fee_vault`, which panics on an
        // envelope derivation refuses — the exact envelope a preview
        // exists to give an answer about.
        let vault = vault_key(vm.fee_payer, *PROTOCOL_RESOURCE);
        if let Some(artifact) = vm.artifact() {
            let payer = PayerFee {
                vault,
                max_fee: vm.max_fee,
                // A publish is priced through the table like anything
                // else: its artifact is retention and its two point
                // writes are writes, all of it in the declared vector.
                price: match tx.price_under(self.derivation().as_ref(), &inputs.prices) {
                    Ok(price) => price,
                    Err(error) => return PreviewReport::refused(error.to_string()),
                },
                abortable: false,
            };
            return preview_publish(snapshot, artifact, payer, inputs.grants);
        }

        let authority = if inputs.grants.assume_target_auth {
            TargetAuthority::Assumed
        } else {
            TargetAuthority::Required
        };
        // A preview is advisory, so it answers from what this node
        // holds rather than from what a block carries: it is not
        // producing a receipt root, and a client asking what an envelope
        // would do wants the answer for a component whose seal landed on
        // some other shard.
        let (prepared, admitted) =
            match Self::prepare_admitting(tx, &self.records(), &self.world.cache, authority) {
                Ok(derived) => derived,
                Err(reason) => return PreviewReport::refused(reason),
            };
        let payer = PayerFee {
            vault,
            max_fee: vm.max_fee,
            // The declaration's price, read off what prepared rather
            // than derived again: a preview under an assumed authority
            // admits what derivation would refuse.
            price: inputs.prices.price(&prepared.work, vm.priority_bp),
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
        let missing = inputs.holds.missing(&prepared.declaration.set);
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
        let mut base = TickBaseline::default();
        // Local cells and fetched ones through the one call: which store
        // answered is the routing's business and nothing below it.
        let cells = PreviewCells {
            local: snapshot,
            holds: &inputs.holds,
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
                seeds: inputs.env.seeds.clone(),
            },
            OwnerSet::whole(),
            None,
        )];
        // The run itself is the preview library's: it holds the source
        // seam, the optimism a report rests on, and the ceiling policy,
        // so a wallet asking a node and a wallet asking a fixture get
        // the same answer in the same shape. What stays here is what
        // needs the chain: the price, the payer's vault and the amounts
        // behind the cells the run moved.
        // One shard nominally: a preview reads a whole snapshot, so what
        // the anchor says is when it was read rather than who held it.
        let source: Arc<dyn CellSource> = Arc::new(Local::at(
            Arc::clone(&base),
            SourceShard(0),
            inputs.clock.as_millis(),
        ));
        let report = preview_run(
            &batch[0],
            Some(&admitted),
            source,
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
        }
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
        assert_eq!(
            local_only.missing(&declared),
            BTreeSet::from([remote]),
            "with no fan-out behind it, the far shard is one this node cannot answer about"
        );

        let mut fetched = FetchedCells::default();
        fetched.anchors.insert(remote, BlockHeight::new(9));
        let fanned_out = Holds {
            trie,
            shards: BTreeSet::from([held]),
            fetched,
        };
        assert!(
            fanned_out.missing(&declared).is_empty(),
            "a shard that answered is one the preview can speak for"
        );
    }
}
