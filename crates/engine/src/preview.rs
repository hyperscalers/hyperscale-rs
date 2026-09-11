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

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_effects_bridge::admit_package;
use hyperscale_storage::Substates;
use hyperscale_types::{Event, Transaction, WeightedTimestamp};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ManifestWalk, OwnerSet, Receipt, decode_amount, execute_batch,
};
use hyperscale_vm_types::{Outcome, SubstateKey, price_attos};

use crate::batch::TickEnvironment;
use crate::executor::{
    PayerFee, TargetAuthority, TickBaseline, abort_reason, materialize_declared, protocol_hash,
    publish_work,
};
use crate::genesis::vault_key;
use crate::{Executor, XRD};

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
    receipt: Option<&Receipt>,
    fee: u128,
    payer: SubstateKey,
    grants: PreviewGrants,
) -> Vec<ResourceChange> {
    let mut changes: BTreeMap<SubstateKey, ResourceChange> = BTreeMap::new();
    if let Some(receipt) = receipt {
        let whole = OwnerSet::whole();
        let moved = receipt.delta.owned(&whole);
        for (key, movement) in moved.movements() {
            let change = changes
                .entry(key)
                .or_insert_with(|| ResourceChange::at(key, amount_at(base, key)));
            change.credit = change.credit.saturating_add(movement.credit);
            change.debit = change.debit.saturating_add(movement.debit);
        }
        for (key, settled) in moved.settles() {
            let change = changes
                .entry(key)
                .or_insert_with(|| ResourceChange::at(key, amount_at(base, key)));
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
        let vault = vault_key(vm.fee_payer, *XRD);
        if let Some(artifact) = vm.artifact() {
            let payer = PayerFee {
                vault,
                max_fee: vm.max_fee,
                price: u128::from(publish_work(artifact)),
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
        let prepared = match Self::prepare_with_authority(tx, &self.records(), authority) {
            Ok(derived) => derived,
            Err(reason) => return PreviewReport::refused(reason),
        };
        let payer = PayerFee {
            vault,
            max_fee: vm.max_fee,
            // The declaration's price, read off what prepared rather
            // than derived again: a preview under an assumed authority
            // admits what derivation would refuse.
            price: price_attos(prepared.work),
            // A preview is one envelope against one snapshot: no tick can
            // discard effects it completed, so the reserve-receipt shape
            // does not arise.
            abortable: false,
        };
        // A preview judges against committed state alone: it is not in
        // a tick, so no tick's reservation is in flight over the
        // baseline it reads, and total locality covers every cell the
        // envelope touches.
        let mut base = TickBaseline::default();
        materialize_declared(
            snapshot,
            &prepared.declaration.set,
            &OwnerSet::whole(),
            &mut base,
        );
        // The fee vault is not a declared effect, and the report needs
        // its committed amount to say what the charge would leave.
        if let Some(value) = snapshot.cell(payer.vault) {
            base.cells.insert(payer.vault, value);
        }
        let base = Arc::new(base);

        let vm_tx = tx.hash();
        let batch = [BatchTx::new(
            vm_tx,
            prepared.declaration,
            EnvInputs {
                clock_ms: inputs.clock.as_millis(),
                epoch: inputs.env.windows.epoch_for(inputs.clock).inner(),
                seeds: inputs.env.seeds.clone(),
            },
        )
        .with_job(prepared.job)
        .with_nullifiers(prepared.nullifiers)];
        let walk = ManifestWalk {
            backend: &self.backend,
        };
        // Total locality: the report covers every cell the envelope
        // touches, and the kernel judges each against whatever the
        // snapshot served for it.
        let outcome = match execute_batch(
            Arc::clone(&base) as Arc<dyn Baseline>,
            &batch,
            &walk,
            protocol_hash,
            self.mode,
        ) {
            Ok(outcome) => outcome,
            // The screen is a property of one derivation's own output, so
            // this is unreachable for anything `prepare` accepted — and a
            // preview answers rather than panics either way.
            Err(error) => return PreviewReport::refused(error.to_string()),
        };
        let Some(receipt) = outcome.receipts.get(&vm_tx) else {
            return PreviewReport::refused("the batch produced no receipt");
        };
        // One price whatever the outcome, held to the ceiling like the burn.
        let fee = payer.price.min(payer.max_fee);
        PreviewReport {
            outcome: preview_outcome(&receipt.outcome),
            changes: resource_changes(&base, Some(receipt), fee, payer.vault, inputs.grants),
            fee,
            fuel: receipt.fuel,
            events: receipt.events.clone(),
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
    let work = publish_work(artifact);
    let mut base = TickBaseline::default();
    if let Some(value) = snapshot.cell(payer.vault) {
        base.cells.insert(payer.vault, value);
    }
    let fee = u128::from(work).min(payer.max_fee);
    PreviewReport {
        outcome: PreviewOutcome::Completed,
        changes: resource_changes(&base, None, fee, payer.vault, grants),
        fee,
        fuel: work,
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
