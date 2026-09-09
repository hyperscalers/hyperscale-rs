//! [`Finalization`] — every participating shard's certificate for one
//! tick, plus the receipts that tick's own execution produced.
//!
//! [`Finalization`] is the raw wire form. Its verified form is
//! `Verified<Finalization>`; predicate at
//! [`impl Verify<&FinalizationContext<'_>>`](Verify::verify) below.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use blake3::Hasher;
use hyperscale_crypto::Verifier;
use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::{
    ConsensusPublicKey, ConsensusReceipt, ExecutionCertificate, ExecutionCertificateContext,
    ExecutionCertificateVerifyError, ExecutionOutcome, FinalizationHash, GlobalReceiptHash, Hash,
    MAX_TXS_PER_BLOCK, NetworkDefinition, ShardId, StoredReceipt, SubstateKey, TickId,
    TransactionDecision, TxClaim, TxHash, TxOutcome, Verifiable, Verified, Verify,
};

/// Cap on execution certificates accepted in a single [`Finalization`] at
/// decode time.
///
/// A tick's EC set is one local EC plus at most one EC per participating
/// remote shard (and may include a few extras if a remote shard committed
/// the tick's transactions across multiple blocks). 1024 is well above any
/// realistic shard count and bounds the per-element pre-allocation that
/// would otherwise let a peer claim billions of inner ECs and OOM the
/// validator at decode time.
pub const MAX_EXECUTION_CERTIFICATES_PER_TICK: usize = 1024;

/// Which half of its tick a finalization settles.
///
/// A tick settles in two halves and they are not interchangeable: the
/// determined half carries writes every later tick can already read, so
/// it is what settlement order is measured over, while the legs half
/// waits on counterparts and may land arbitrarily late. Nothing else on
/// a finalization tells them apart — the certificates are the same shape
/// either way, and which members reach beyond the shard is a fact about
/// transactions committed in earlier blocks. So the half travels with
/// the finalization, and is covered by its hash: a flipped marker would
/// otherwise advance the settlement frontier past a half that never
/// settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum TickHalf {
    /// The members whose settlement needs no shard but this one, settling
    /// on the tick's own certificate.
    Determined,
    /// The members whose settlement waits on a counterpart's verdict.
    Legs,
}

/// A finalization — every participating shard has attested the tick's
/// transactions, and the local receipts stand beside the proof.
///
/// Receipts are written atomically with the block at commit time (not
/// fire-and-forget).
///
/// # Derived views
///
/// The tick's canonical tx list, ordering, and per-tx decisions are all
/// **derived** from the execution certificates, not stored alongside them.
/// See:
/// - [`Finalization::local_ec`] — the authoritative EC (where `ec.tick_id() == tick_id`)
/// - [`Finalization::tx_hashes`] — iterator over the tick's tx hashes in block order
/// - [`Finalization::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// `receipts` contains only txs that actually executed (sparse subset of
/// `tx_hashes()`, same block order). Aborted txs produce no receipt.
///
/// # Invariant (well-formed)
///
/// A well-formed `Finalization` contains **exactly one local EC** — the
/// EC where `ec.tick_id() == fw.tick_id`. The local EC is the authoritative
/// source for the tick's tx set and canonical (block) ordering. Remote ECs
/// attest against their own ticks and may cover only subsets; the local
/// shard, by construction, produces a single EC per tick.
///
/// Enforced at construction by `TickState::attestation` and at
/// the wire boundary by the decode impl. [`Finalization::local_ec`]
/// `expect`s it.
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(validate = check_finalization)]
pub struct Finalization {
    tick_id: TickId,
    /// Which half of `tick_id` this settles. Ordering is per half, so
    /// the identity that orders is too.
    half: TickHalf,
    #[hbor(max = MAX_EXECUTION_CERTIFICATES_PER_TICK)]
    execution_certificates: Vec<Arc<Verifiable<ExecutionCertificate>>>,
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    receipts: Vec<StoredReceipt>,
}

/// The exactly-one-local-EC invariant, enforced at the wire boundary. Zero
/// local ECs would crash [`Finalization::local_ec`]; multiple would let
/// downstream code silently disagree on which EC is authoritative for tx
/// ordering.
fn check_finalization(tick: &Finalization) -> Result<(), &'static str> {
    let local = tick
        .execution_certificates
        .iter()
        .filter(|ec| ec.tick_id() == &tick.tick_id)
        .count();
    if local == 1 {
        Ok(())
    } else {
        Err("a finalization carries exactly one local execution certificate")
    }
}

/// What one outcome settles, given the verdict the whole tick reached.
///
/// A transaction settles its own effects only if every participant
/// accepted it. Otherwise the effects are discarded — that is what makes
/// a cross-shard abort atomic — and what is left is the charge the
/// outcome named beside them, which is how an attempt nobody applied
/// still costs its payer.
///
/// Every participant *accepted* it, not every participant present: a set
/// of certificates missing one is a transaction with no verdict yet, and
/// that is [`Finalization::uncovered_transactions`]'s question, asked
/// before this one.
///
/// One rule with two readers: the tick's own shard builds its receipt
/// list from it, and every peer re-derives it to check that list. They
/// have to be the same rule, because a tick that stored the other side
/// of a transaction would either move value one-sidedly or waive a
/// charge, depending on which way it got it wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settles {
    /// The transaction's own effects, under this receipt hash.
    Effects(GlobalReceiptHash),
    /// The charge named beside the outcome, under this receipt hash.
    Charge(GlobalReceiptHash),
    /// The canonical failure record — a failure owing no charge.
    Failure,
    /// Nothing at all.
    Nothing,
}

/// Every transaction some participant refused: aborted, or executed to a
/// failure. Abort is dominant and success unanimous, so one refusal
/// anywhere discards the transaction's effects everywhere.
#[must_use]
pub fn refused_transactions(
    execution_certificates: &[Arc<Verifiable<ExecutionCertificate>>],
) -> BTreeSet<TxHash> {
    execution_certificates
        .iter()
        .flat_map(|ec| ec.tx_outcomes())
        .filter(|outcome| !matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. }))
        .map(TxOutcome::tx_hash)
        .collect()
}

/// What `outcome` settles, given the transactions `refused` names.
#[must_use]
pub fn settles(outcome: &TxOutcome, refused: &BTreeSet<TxHash>) -> Settles {
    match outcome.outcome() {
        ExecutionOutcome::Succeeded { receipt_hash } if !refused.contains(&outcome.tx_hash()) => {
            Settles::Effects(*receipt_hash)
        }
        // Refused here, or completed here and refused by a counterpart.
        // Either way the effects are gone and the charge is what is left.
        _ => match (outcome.fee_receipt(), outcome.outcome()) {
            (Some(charge), _) => Settles::Charge(charge),
            (None, ExecutionOutcome::Failed) => Settles::Failure,
            (None, _) => Settles::Nothing,
        },
    }
}

/// Reason a `Finalization` doesn't agree with the certificates it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptValidationError {
    /// The tick has no EC whose `tick_id` is the tick's own. Every
    /// committed tick carries exactly one such "local" EC per the
    /// `TickState::attestation` invariant; this indicates a malformed
    /// or tampered certificate.
    MissingLocalEc,
    /// A transaction the tick settles names a participant no carried
    /// certificate speaks for, so the set decides nothing about it.
    IncompleteCoverage {
        /// Hash of the tx left without a verdict.
        tx_hash: TxHash,
        /// A participant it names that has not reported.
        missing: ShardId,
    },
    /// A non-aborted `tx_outcome` has no corresponding receipt.
    MissingReceipt {
        /// Hash of the tx whose receipt is missing.
        tx_hash: TxHash,
    },
    /// A receipt's `tx_hash` doesn't match the expected position in
    /// canonical order.
    TxHashMismatch {
        /// `tx_hash` the canonical order required at this position.
        expected: TxHash,
        /// `tx_hash` the receipt actually carried.
        actual: TxHash,
    },
    /// EC attested the tx as `Succeeded` but the stored receipt is `Failed`.
    UnexpectedFailure {
        /// Hash of the tx.
        tx_hash: TxHash,
    },
    /// EC attested the tx as `Failed` but the stored receipt is `Succeeded`.
    UnexpectedSuccess {
        /// Hash of the tx.
        tx_hash: TxHash,
    },
    /// EC's `receipt_hash` for a `Succeeded` tx disagrees with the stored
    /// receipt's `receipt_hash`. Catches divergent state for the same tx
    /// across validators that both succeeded but produced different writes.
    ReceiptHashMismatch {
        /// Hash of the tx.
        tx_hash: TxHash,
        /// `receipt_hash` attested by the EC.
        expected: GlobalReceiptHash,
        /// `receipt_hash` carried by the stored receipt.
        actual: GlobalReceiptHash,
    },
    /// More receipts than non-aborted outcomes.
    ExtraReceipt {
        /// Hash of the surplus receipt's tx.
        tx_hash: TxHash,
    },
}

impl Finalization {
    /// Stored receipts for txs that executed. Aborted txs are absent —
    /// `receipts.len() <= tx_count()`. Preserves canonical block order.
    /// Held in-memory until block commit, then written atomically with block metadata.
    #[must_use]
    pub const fn receipts(&self) -> &Vec<StoredReceipt> {
        &self.receipts
    }

    /// The tick this tick finalizes. Globally unique; `hash(tick_id)` is
    /// the identity key for manifest/storage.
    #[must_use]
    pub const fn tick_id(&self) -> &TickId {
        &self.tick_id
    }

    /// Which half of its tick this settles — what settlement order is
    /// measured over.
    #[must_use]
    pub const fn half(&self) -> TickHalf {
        self.half
    }

    /// Whether this settles the half that carries writes later ticks can
    /// already read, and so the half the settlement frontier tracks.
    #[must_use]
    pub const fn is_determined(&self) -> bool {
        matches!(self.half, TickHalf::Determined)
    }

    /// Execution certificates from all participating shards.
    /// Always includes the local EC (see invariant above).
    /// May contain multiple ECs from the same remote shard — this happens when
    /// a remote shard committed this tick's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (`shard_id`, `tick_id`) for deterministic `receipt_hash`.
    ///
    /// Each EC rides as `Verifiable<ExecutionCertificate>`: wire-decoded
    /// certificates land [`Verifiable::Unverified`]; locally assembled
    /// ones carry the [`Verifiable::Verified`] marker from
    /// [`Self::from_verified_ecs`].
    #[must_use]
    pub fn execution_certificates(&self) -> &[Arc<Verifiable<ExecutionCertificate>>] {
        &self.execution_certificates
    }

    /// The local shard's EC — authoritative for tick membership and ordering.
    ///
    /// A well-formed tick has exactly one EC with `ec.tick_id() == fw.tick_id`
    /// (invariant established by `TickState::attestation` and the
    /// endorsement + convergence gate).
    ///
    /// # Panics
    ///
    /// Panics if the local EC is missing — that indicates a malformed
    /// or tampered tick.
    #[must_use]
    pub fn local_ec(&self) -> &ExecutionCertificate {
        self.execution_certificates
            .iter()
            .find(|ec| ec.tick_id() == &self.tick_id)
            .expect("finalization invariant: local EC must be present")
    }

    /// The leaf a block's `certificate_root` commits for this
    /// finalization: its tick, then each constituent certificate's
    /// content, in the order the vec was sorted into at construction.
    ///
    /// **The certificates are committed by content, not by identity.** A
    /// certificate carries the outcomes naming its holder, so many valid
    /// copies of one exist and they differ in what they cover — and
    /// anyone holding a copy can build a narrower one, since dropping a
    /// leaf from a set you hold means supplying that leaf's hash as a
    /// proof node. Naming the tick alone would leave every one of those
    /// copies hashing alike, and the difference between them is what
    /// decides a verdict: [`refused_transactions`] reads the carried
    /// outcomes, so a copy with a counterpart's abort dropped turns
    /// [`settles`] from the charge to the effects. A finalization built
    /// consistently around the narrower copy passes its own receipt check
    /// — the same certificate set feeds both sides of it — so this leaf
    /// is what has to tell the two apart.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding of a `TickId` fails — a closed wire type,
    /// infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> FinalizationHash {
        let mut hasher = Hasher::new();
        hasher.update(&hbor_to_vec(&self.tick_id).unwrap());
        hasher.update(&hbor_to_vec(&self.half).unwrap());
        for ec in &self.execution_certificates {
            hasher.update(ec.wire_hash().as_bytes());
        }
        FinalizationHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }

    /// Number of transactions in this tick.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.local_ec().tx_outcomes().len()
    }

    /// Iterator over each receipt's consensus payload, in canonical
    /// block order. Used by pending-chain insertion and local-receipt
    /// root verification.
    pub fn consensus_receipts(&self) -> impl Iterator<Item = Arc<ConsensusReceipt>> + '_ {
        self.receipts.iter().map(|r| Arc::clone(&r.consensus))
    }

    /// Work this shard attests across the tick's transactions.
    ///
    /// Read off the local EC's outcomes rather than the receipts, so it
    /// covers the verdicts that produced no receipt — a failure or an
    /// abort still declared, routed, and locked.
    ///
    /// Saturating, so a forged tick cannot wrap a block's running total
    /// into a smaller number than its parent's.
    #[must_use]
    pub fn attested_work(&self) -> u64 {
        self.local_ec()
            .tx_outcomes()
            .iter()
            .fold(0u64, |sum, outcome| {
                sum.saturating_add(outcome.attested_work())
            })
    }

    /// Work this tick releases back to the drain budget.
    ///
    /// The reservations its transactions took when their block committed
    /// them, returned now that they are settled. Read off the same
    /// outcomes as [`Self::attested_work`] and for the same reason: it
    /// has to cover every verdict, because an aborted transaction leaves
    /// the drain exactly as a completed one does.
    ///
    /// Saturating, so a forged tick cannot wrap a block's running total.
    #[must_use]
    pub fn declared_work(&self) -> u64 {
        self.local_ec()
            .tx_outcomes()
            .iter()
            .fold(0u64, |sum, outcome| {
                sum.saturating_add(outcome.declared_work())
            })
    }

    /// Iterator over the tick's tx hashes in canonical block order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.local_ec().tx_outcomes().iter().map(TxOutcome::tx_hash)
    }

    /// The transactions this finalization resolves: those whose local
    /// outcome bears the verdict. A leg that succeeded is named here and
    /// resolved elsewhere, so it is among [`Self::tx_hashes`] and not
    /// among these.
    pub fn deciding_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.local_ec()
            .tx_outcomes()
            .iter()
            .filter(|outcome| outcome.decides())
            .map(TxOutcome::tx_hash)
    }

    /// What this finalization claims of each counterpart's settled set,
    /// per transaction — the question the split-boundary fence puts to
    /// the sets, derived once for the proposer's gate and the voter's
    /// fence so the two cannot judge one tick differently.
    ///
    /// A certificate a counterpart signed is a settlement claim on it:
    /// `local` applies its half on coverage the counterpart attested, so
    /// the counterpart must have settled its own. A local outcome no
    /// counterpart attested, for a member that awaited some, is an
    /// abandonment claim on each one it awaited: the abort is dominant
    /// and needs no verdict of theirs, but it needs them not to have
    /// settled. A member that awaited nobody — a leg, a core answering
    /// alone, a reclaim — claims nothing: its verdict is its own, and no
    /// counterpart's set can contradict it.
    ///
    /// Nor does a name `covered` claims anything: a committed record has
    /// already established that no counterpart can settle it, in a form
    /// that does not expire with the set it was read from, and putting
    /// the question again would let the set's own horizon refuse a
    /// verdict the chain already licensed.
    pub fn claims(
        &self,
        local: ShardId,
        covered: impl Fn(TxHash) -> bool,
    ) -> Vec<(ShardId, TxHash, TxClaim)> {
        let mut claims: Vec<(ShardId, TxHash, TxClaim)> = Vec::new();
        let mut attested_remotely: HashSet<TxHash> = HashSet::new();
        for ec in &self.execution_certificates {
            let shard = ec.shard_id();
            if shard == local {
                continue;
            }
            for outcome in ec.tx_outcomes() {
                attested_remotely.insert(outcome.tx_hash());
                claims.push((shard, outcome.tx_hash(), TxClaim::Settled));
            }
        }
        for outcome in self.local_ec().tx_outcomes() {
            let tx_hash = outcome.tx_hash();
            if attested_remotely.contains(&tx_hash) || covered(tx_hash) {
                continue;
            }
            claims.extend(
                outcome
                    .counterparts()
                    .iter()
                    .map(|&shard| (shard, tx_hash, TxClaim::Abandoned)),
            );
        }
        claims
    }

    /// Whether the tick contains a given tx.
    #[must_use]
    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.local_ec()
            .tx_outcomes()
            .iter()
            .any(|o| &o.tx_hash() == tx_hash)
    }

    /// This tick's attestation half — the tick and its certificates,
    /// without the receipts.
    ///
    /// What the certificates column family stores: receipts live in the
    /// receipts column family and rejoin through [`Self::reconstruct`],
    /// so holding both copies would duplicate every receipt and outlive
    /// the retention the receipt store applies to them.
    #[must_use]
    pub fn attestation(&self) -> Self {
        Self {
            tick_id: self.tick_id,
            half: self.half,
            execution_certificates: self.execution_certificates.clone(),
            receipts: Vec::new(),
        }
    }

    /// Restore the receipts of an [`attestation`](Self::attestation) read
    /// back out of storage.
    ///
    /// Used on the storage/sync serving side to rebuild the in-memory shape
    /// from committed state. Walks the local EC's `tx_outcomes` in canonical
    /// block order and fetches a receipt for each outcome that settles one.
    ///
    /// Returns `None` if:
    /// - The tick lacks a local EC (malformed — should not happen for a
    ///   committed tick per the `TickState::attestation` invariant).
    /// - A receipt the tick settled is missing from the lookup
    ///   (peer/storage has incomplete state — a syncing peer should try a
    ///   different source).
    pub fn reconstruct<F>(attestation: Self, mut lookup: F) -> Option<Self>
    where
        F: FnMut(&TxHash) -> Option<Arc<ConsensusReceipt>>,
    {
        let local_ec = attestation
            .execution_certificates
            .iter()
            .find(|ec| ec.tick_id() == &attestation.tick_id)?;

        // Which outcomes owe a receipt is [`settles`]'s question, asked
        // against the whole certificate — the same reading that built the
        // list. An outcome that settles nothing was never stored, and an
        // outcome that settles something was: anything else here would
        // either demand a receipt that does not exist or admit one the
        // tick never carried.
        let refused = refused_transactions(&attestation.execution_certificates);
        let mut receipts: Vec<StoredReceipt> = Vec::with_capacity(local_ec.tx_outcomes().len());
        for outcome in local_ec.tx_outcomes() {
            if matches!(settles(outcome, &refused), Settles::Nothing) {
                continue;
            }
            let receipt = lookup(&outcome.tx_hash())?;
            receipts.push(StoredReceipt::synced(outcome.tx_hash(), receipt));
        }

        Some(attestation.with_receipts(receipts))
    }

    /// Build a `Finalization` from raw inputs. Each EC lands
    /// [`Verifiable::Unverified`] — this is the constructor for wire
    /// reconstruction and tests, where the ECs carry no verification
    /// marker. Locally aggregated ticks that already hold
    /// [`Verified<ExecutionCertificate>`]s use [`Self::from_verified_ecs`]
    /// to carry their markers through.
    ///
    /// Validates neither the exactly-one-local-EC invariant nor the
    /// receipt-count cap; both are enforced at the wire boundary by the
    /// `Decode` impl, and the first also at the build boundary by
    /// `TickState::attestation`.
    #[must_use]
    pub fn new(
        tick_id: TickId,
        half: TickHalf,
        execution_certificates: Vec<Arc<ExecutionCertificate>>,
        receipts: Vec<StoredReceipt>,
    ) -> Self {
        Self {
            tick_id,
            half,
            execution_certificates: execution_certificates
                .into_iter()
                .map(|ec| Arc::new(Verifiable::from(Arc::unwrap_or_clone(ec))))
                .collect(),
            receipts,
        }
    }

    /// Build a receiptless `Finalization` from execution certificates
    /// that have already cleared their per-EC signature predicate,
    /// carrying the [`Verifiable::Verified`] marker on each. Receipts
    /// arrive through [`Self::with_receipts`], which is what the caller
    /// needs the certificates to decide.
    ///
    /// Used by `TickState::into_finalization`, whose ECs were produced
    /// through the [`Verified::<ExecutionCertificate>::aggregate`] gate.
    /// Keeping the marker leaves the ECs internally consistent with the
    /// [`Verified<Finalization>`](Verified) they're sealed into, so a
    /// later [`Finalization::verify`](Verify::verify) short-circuits
    /// them instead of re-checking.
    #[must_use]
    pub fn from_verified_ecs(
        tick_id: TickId,
        half: TickHalf,
        execution_certificates: Vec<Verified<ExecutionCertificate>>,
    ) -> Self {
        Self {
            tick_id,
            half,
            execution_certificates: execution_certificates
                .into_iter()
                .map(|ec| Arc::new(Verifiable::from(ec)))
                .collect(),
            receipts: Vec::new(),
        }
    }

    /// The same tick carrying `receipts`. The receipt-count cap is
    /// enforced at encode and decode, not here.
    #[must_use]
    pub fn with_receipts(mut self, receipts: Vec<StoredReceipt>) -> Self {
        self.receipts = receipts;
        self
    }

    /// Transactions this tick's own certificate names a participant for
    /// that no carried certificate speaks for, each with one such shard.
    ///
    /// The completeness half of the settlement rule, and the half a set
    /// of certificates cannot supply on its own: [`settles`] reads the
    /// outcomes in front of it, so a set with a counterpart's refusal
    /// removed reads as unanimous and is internally consistent while it
    /// does. What that set cannot do is deny the participant, because
    /// the tick's own certificate names it under the signed receipt root
    /// ([`TxOutcome::counterparts`]) — so the question of who is missing
    /// is answerable from the set alone, which is what makes this
    /// checkable by every validator and not just the node that built it.
    ///
    /// Refusal needs no completeness. One refusal anywhere discards the
    /// transaction's effects everywhere, so a set carrying any is already
    /// decided and the shards yet to report can only agree.
    ///
    /// Read off the tick's own certificate rather than the union of all
    /// of them: participants are resolved against the topology that
    /// committed the transaction, and two shards that committed it across
    /// a reshape cut can name different sets. This shard settles on the
    /// set it committed under, which is the one its own committee signed.
    #[must_use]
    pub fn uncovered_transactions(&self) -> BTreeMap<TxHash, ShardId> {
        let Some(local_ec) = self
            .execution_certificates
            .iter()
            .find(|ec| ec.tick_id() == &self.tick_id)
        else {
            return BTreeMap::new();
        };
        let refused = refused_transactions(&self.execution_certificates);
        let mut certifying: HashMap<TxHash, HashSet<ShardId>> = HashMap::new();
        for ec in &self.execution_certificates {
            let shard = ec.shard_id();
            for outcome in ec.tx_outcomes() {
                certifying
                    .entry(outcome.tx_hash())
                    .or_default()
                    .insert(shard);
            }
        }
        local_ec
            .tx_outcomes()
            .iter()
            .filter(|outcome| !refused.contains(&outcome.tx_hash()))
            .filter_map(|outcome| {
                let reported = certifying.get(&outcome.tx_hash());
                let missing = outcome
                    .counterparts()
                    .iter()
                    .find(|shard| !reported.is_some_and(|reported| reported.contains(shard)))?;
                Some((outcome.tx_hash(), *missing))
            })
            .collect()
    }

    /// Validate the tick against the certificates it carries: that they
    /// decide every transaction it settles, and that `receipts` follow
    /// from what they decided.
    ///
    /// Completeness first — a transaction whose participants have not all
    /// reported has no verdict to check receipts against, and
    /// [`Self::uncovered_transactions`] is where the reason lives.
    ///
    /// Then exactly one receipt per outcome that carries one — every
    /// non-aborted outcome, plus every abort settling a fee — in
    /// `tx_outcomes` canonical order, with matching `tx_hash` and
    /// matching receipt hash.
    ///
    /// This does **not** verify `database_updates` or `writes_root` —
    /// `ConsensusReceipt::Succeeded` carries only shard-filtered writes, so the global
    /// `writes_root` the EC commits to can't be reconstructed from a
    /// stored receipt alone. Use to catch gross drift (wrong tx, wrong
    /// success/fail, missing or surplus receipts) at peer-tick ingress.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`ReceiptValidationError`] variant on
    /// the first inconsistency found.
    pub fn validate_against_certificates(&self) -> Result<(), ReceiptValidationError> {
        let local_ec = self
            .execution_certificates
            .iter()
            .find(|ec| ec.tick_id() == &self.tick_id)
            .ok_or(ReceiptValidationError::MissingLocalEc)?;

        if let Some((&tx_hash, &missing)) = self.uncovered_transactions().iter().next() {
            return Err(ReceiptValidationError::IncompleteCoverage { tx_hash, missing });
        }

        let refused = refused_transactions(&self.execution_certificates);
        let mut receipt_iter = self.receipts.iter();
        for outcome in local_ec.tx_outcomes() {
            let ec_kind = match settles(outcome, &refused) {
                Settles::Effects(hash) | Settles::Charge(hash) => Some(hash),
                Settles::Failure => None,
                Settles::Nothing => continue,
            };

            let receipt =
                receipt_iter
                    .next()
                    .ok_or_else(|| ReceiptValidationError::MissingReceipt {
                        tx_hash: outcome.tx_hash(),
                    })?;
            if receipt.tx_hash != outcome.tx_hash() {
                return Err(ReceiptValidationError::TxHashMismatch {
                    expected: outcome.tx_hash(),
                    actual: receipt.tx_hash,
                });
            }

            match (ec_kind, receipt.consensus.as_ref()) {
                (
                    Some(expected_hash),
                    ConsensusReceipt::Succeeded {
                        receipt_hash: actual_hash,
                        ..
                    },
                ) => {
                    if *actual_hash != expected_hash {
                        return Err(ReceiptValidationError::ReceiptHashMismatch {
                            tx_hash: outcome.tx_hash(),
                            expected: expected_hash,
                            actual: *actual_hash,
                        });
                    }
                }
                (Some(_), ConsensusReceipt::Failed) => {
                    return Err(ReceiptValidationError::UnexpectedFailure {
                        tx_hash: outcome.tx_hash(),
                    });
                }
                (None, ConsensusReceipt::Succeeded { .. }) => {
                    return Err(ReceiptValidationError::UnexpectedSuccess {
                        tx_hash: outcome.tx_hash(),
                    });
                }
                (None, ConsensusReceipt::Failed) => { /* match — both Failed */ }
            }
        }
        if let Some(extra) = receipt_iter.next() {
            return Err(ReceiptValidationError::ExtraReceipt {
                tx_hash: extra.tx_hash,
            });
        }
        Ok(())
    }

    /// The receipts that reach state.
    ///
    /// A transaction settles its effects only if the tick decided to
    /// accept it — every participant together, not the shard whose EC
    /// carried the receipt. A leg that completed here while its
    /// counterpart refused it moved nothing, and a shard applying its own
    /// half regardless would move value one-sidedly.
    ///
    /// A charge is not an effect. The fee receipt an outcome names
    /// settles whatever the verdict, which is what makes a refused
    /// attempt cost its payer something.
    ///
    /// The [`settles`] rule the receipts were built under, re-read
    /// against the certificate rather than trusted: a tick arriving from
    /// a peer is validated at ingress, and this is the backstop for
    /// anything that reaches state by another road.
    ///
    /// It bites in one direction only. A refused transaction settles the
    /// charge its outcome named and nothing else, and one no set of
    /// certificates decides — a participant it names has not reported —
    /// settles nothing at all, because the failure to stop there moves
    /// value one-sidedly. Anything the certificates refuse nothing of and
    /// decide between them passes as it stands — a receipt whose hash
    /// disagreed with its outcome is caught at ingress, and dropping it
    /// here instead would lose committed state with no diagnostic.
    ///
    /// The attested roots are deliberately not filtered this way:
    /// `local_receipt_root` covers everything the tick carried, because
    /// it attests what execution produced. This attests what the tick
    /// decided, which is a different question.
    #[must_use]
    pub fn settling_receipts(&self) -> Vec<StoredReceipt> {
        // Read off the certificates rather than through `tx_decisions`,
        // whose canonical order needs the local EC: a receipt names its
        // own transaction, so nothing here has to enumerate the tick, and
        // a malformed certificate needs no special case on the commit
        // path.
        let refused = refused_transactions(&self.execution_certificates);
        let uncovered = self.uncovered_transactions();
        // Per transaction, not a bare set of hashes: two legs of one payer
        // owing the same floor produce byte-identical charges, and a set
        // would let either stand in for the other.
        let mut charges: HashMap<TxHash, GlobalReceiptHash> = HashMap::new();
        for ec in &self.execution_certificates {
            for outcome in ec.tx_outcomes() {
                if let Settles::Charge(hash) = settles(outcome, &refused) {
                    charges.insert(outcome.tx_hash(), hash);
                }
            }
        }
        self.receipts
            .iter()
            .filter(|receipt| {
                !uncovered.contains_key(&receipt.tx_hash)
                    && (!refused.contains(&receipt.tx_hash)
                        || charges.get(&receipt.tx_hash) == Some(&receipt.consensus.receipt_hash()))
            })
            .cloned()
            .collect()
    }

    /// The committed cells this shard's own outcomes retract: what the
    /// block settling this finalization deletes beside the sweep's
    /// removals. Only the local certificate's, since a committed cell is
    /// written under the shard that included the transaction and a
    /// counterpart's retractions are that counterpart's to apply.
    pub fn retractions(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        // Read off the certificates by tick rather than through the
        // local-certificate accessor, which is a lookup that must
        // succeed: a malformed finalization needs no special case on the
        // commit path.
        self.execution_certificates
            .iter()
            .filter(|ec| ec.tick_id() == &self.tick_id)
            .flat_map(|ec| ec.tx_outcomes())
            .filter_map(TxOutcome::retracts)
    }

    /// Aggregate per-tx decisions across all ECs (Aborted > Reject > Accept).
    ///
    /// Iteration order follows the local EC's canonical (block) order.
    #[must_use]
    pub fn tx_decisions(&self) -> Vec<(TxHash, TransactionDecision)> {
        let mut aborted: HashSet<TxHash> = HashSet::new();
        let mut failure: HashSet<TxHash> = HashSet::new();
        for ec in &self.execution_certificates {
            for outcome in ec.tx_outcomes() {
                if outcome.is_aborted() {
                    aborted.insert(outcome.tx_hash());
                }
                if !matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. }) {
                    failure.insert(outcome.tx_hash());
                }
            }
        }
        self.tx_hashes()
            .map(|h| {
                let d = if aborted.contains(&h) {
                    TransactionDecision::Aborted
                } else if failure.contains(&h) {
                    TransactionDecision::Reject
                } else {
                    TransactionDecision::Accept
                };
                (h, d)
            })
            .collect()
    }
}

/// Inputs the [`Finalization`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct FinalizationContext<'a> {
    /// Network identifier — feeds the domain-separated signing message
    /// for each constituent EC.
    pub network: &'a NetworkDefinition,
    /// Committee public keys for each EC, parallel to
    /// `tick.execution_certificates()`. Each inner slice is the
    /// committee for that EC's shard, in committee order.
    pub ec_public_keys: &'a [Vec<ConsensusPublicKey>],
    /// Scheme verifier the EC checks run through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`Finalization`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FinalizationVerifyError {
    /// `ec_public_keys.len() != tick.execution_certificates().len()`.
    /// Caller-side packaging error.
    #[error(
        "ec_public_keys length {actual} doesn't match execution_certificates length {expected}"
    )]
    PublicKeyVectorLengthMismatch {
        /// Number of ECs in the tick.
        expected: usize,
        /// Number of public-key vectors supplied.
        actual: usize,
    },
    /// One of the embedded ECs failed its own predicate.
    #[error("execution certificate at index {index}: {source}")]
    ExecutionCertificate {
        /// Position in `tick.execution_certificates()` whose verify failed.
        index: usize,
        /// The underlying EC verifier error.
        source: ExecutionCertificateVerifyError,
    },
}

/// Construction asserts: every [`ExecutionCertificate`] in
/// `tick.execution_certificates()` verifies under its corresponding
/// `ec_public_keys[i]` committee.
///
/// Construction goes through one of four gates:
///
/// - [`<Finalization as Verify>::verify`](Verify::verify) — runs the
///   embedded-EC predicate over every constituent EC that doesn't
///   already carry a live verification marker.
/// - [`Verified::<Finalization>::seal`] — wraps a locally-finalized
///   tick whose ECs were produced through the
///   [`Verified::<ExecutionCertificate>::aggregate`] gate.
/// - [`Verified::<Finalization>::from_committed_block`] — wraps a
///   tick reaching downstream consumers via a
///   [`Verified<CertifiedBlock>`], where the source committee's QC
///   BFT-transitively attests the per-EC signature claim.
///
/// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
impl Verify<&FinalizationContext<'_>> for Finalization {
    type Error = FinalizationVerifyError;

    fn verify(&self, ctx: &FinalizationContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let ecs = self.execution_certificates();
        if ctx.ec_public_keys.len() != ecs.len() {
            return Err(FinalizationVerifyError::PublicKeyVectorLengthMismatch {
                expected: ecs.len(),
                actual: ctx.ec_public_keys.len(),
            });
        }
        for (index, (ec, pks)) in ecs.iter().zip(ctx.ec_public_keys.iter()).enumerate() {
            // A tick assembled in-memory from aggregated ECs carries each
            // one already Verified; wire-decoded ticks arrive Unverified
            // and run the per-EC predicate here.
            if ec.is_verified() {
                continue;
            }
            let ec_ctx = ExecutionCertificateContext {
                network: ctx.network,
                public_keys: pks,
                verifier: ctx.verifier,
            };
            ec.as_unverified().verify(&ec_ctx).map_err(|source| {
                FinalizationVerifyError::ExecutionCertificate { index, source }
            })?;
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Finalization> {
    /// Wrap a locally-finalization whose ECs were built through the
    /// [`Verified::<ExecutionCertificate>::aggregate`] gate.
    ///
    /// Trust source: every EC the tick carries was produced from a
    /// quorum of verified votes on this validator, so
    /// the predicate (per-EC signature verify against the matching committee)
    /// holds by construction. Used at the [`TickState::into_finalization`]
    /// boundary.
    ///
    /// [`TickState::into_finalization`]: crate::TickState::into_finalization
    #[must_use]
    pub const fn seal(tick: Finalization) -> Self {
        // SAFETY: every EC in `tick.execution_certificates()` was
        // built by the local aggregator from verified votes (see
        // `Verified::<ExecutionCertificate>::aggregate`); the per-EC
        // signature verify against the matching committee pubkey vector
        // holds by construction.
        Self::new_unchecked(tick)
    }

    /// Wrap a finalization reaching the system via a committed block.
    ///
    /// Trust source: the tick was carried inside a
    /// [`Verified<CertifiedBlock>`]; 2f+1 of the block's committee
    /// signed over `block.hash()`, which commits to every contained
    /// tick via the header's `certificate_root` and to each tick's
    /// receipt set via `local_receipt_root`. Honest signers ran the
    /// per-EC signature predicate before voting, so the predicate
    /// [`<Finalization as Verify>::verify`] would run is
    /// BFT-transitively attested by that committee.
    ///
    /// Used at sync admission, where the QC chain replaces local
    /// per-EC signature checks on each contained tick.
    ///
    /// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
    #[must_use]
    pub const fn from_committed_block(tick: Finalization) -> Self {
        // SAFETY: the tick was carried in a `Verified<CertifiedBlock>`;
        // the source committee's QC attests its inclusion and per-EC
        // signature checks via the block's `certificate_root` and
        // `local_receipt_root`. Mirrors `Verified::<Provisions>::from_committed_block`
        // and the QC-transitive trust shape on
        // `Verified::<CertifiedBlock>::from_qc_attestation`.
        Self::new_unchecked(tick)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::{
        AggregateSignature, BlockHash, BlockHeight, ExecutionVote, Hash, ShardId, SignerBitfield,
        ValidatorId, WeightedTimestamp, compute_global_receipt_root,
    };

    /// The half is part of what a finalization is, so it is part of its
    /// identity.
    ///
    /// The settlement frontier reads the half off the block and advances
    /// on it. If two finalizations differing only in their half shared a
    /// hash, a proposer could present the legs half as the determined one
    /// under a hash the certificate root already commits to — advancing
    /// the frontier past a determined half that never settled, and
    /// barring it forever.
    #[test]
    fn the_half_a_finalization_settles_is_part_of_its_identity() {
        let local_wid = tick_id(0, 7, &[]);
        let ec = Arc::new(ExecutionCertificate::new(
            local_wid,
            WeightedTimestamp::from_millis(1),
            compute_global_receipt_root(&[make_outcome(1)]),
            vec![make_outcome(1)],
            AggregateSignature::ZERO,
            SignerBitfield::new(2),
        ));
        let determined = Finalization::new(
            local_wid,
            TickHalf::Determined,
            vec![Arc::clone(&ec)],
            vec![],
        );
        let legs = Finalization::new(local_wid, TickHalf::Legs, vec![ec], vec![]);

        assert_ne!(
            determined.receipt_hash(),
            legs.receipt_hash(),
            "a flipped half must not pass under the hash the block commits to",
        );
    }

    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            },
        )
    }

    fn tick_id(shard: u64, height: u64, _remote: &[u64]) -> TickId {
        TickId::new(ShardId::leaf(3, shard), BlockHeight::new(height))
    }

    /// Build a verified EC for `tick_id` by aggregating real signed votes
    /// from `signers`. Output verifies against `signers.public_key()`s.
    fn make_verified_ec(
        net: &NetworkDefinition,
        tick_id: &TickId,
        outcomes: &[TxOutcome],
        signers: &[BlsSigner],
    ) -> Verified<ExecutionCertificate> {
        let root = compute_global_receipt_root(outcomes);
        let committee: Vec<ValidatorId> = (0..signers.len())
            .map(|i| ValidatorId::new(u64::try_from(i).unwrap()))
            .collect();
        let votes: Vec<Verified<ExecutionVote>> = signers
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                Verified::<ExecutionVote>::sign_local(
                    net,
                    BlockHash::from_raw(Hash::from_bytes(b"block")),
                    tick_id.block_height(),
                    WeightedTimestamp::from_millis(tick_id.block_height().inner() + 1),
                    *tick_id,
                    tick_id.shard_id(),
                    outcomes.to_vec(),
                    ValidatorId::new(u64::try_from(i).unwrap()),
                    sk,
                )
                .expect("sign")
            })
            .collect();
        Verified::<ExecutionCertificate>::aggregate(&BlsVerifier, tick_id, root, &votes, &committee)
    }

    /// Honest path: every EC verifies under its committee PKs.
    #[test]
    fn verify_accepts_finalization_with_valid_ecs() {
        let net = NetworkDefinition::simulator();

        let local_wid = tick_id(0, 7, &[1]);
        let remote_wid = tick_id(1, 7, &[0]);

        let shard0_signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let shard1_signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let shard0_pks: Vec<ConsensusPublicKey> =
            shard0_signers.iter().map(BlsSigner::public_key).collect();
        let shard1_pks: Vec<ConsensusPublicKey> =
            shard1_signers.iter().map(BlsSigner::public_key).collect();

        let local_outcomes = vec![make_outcome(1), make_outcome(2)];
        let remote_outcomes = vec![make_outcome(1), make_outcome(2)];
        let local_ec =
            make_verified_ec(&net, &local_wid, &local_outcomes, &shard0_signers).into_inner();
        let remote_ec =
            make_verified_ec(&net, &remote_wid, &remote_outcomes, &shard1_signers).into_inner();

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            vec![Arc::new(local_ec), Arc::new(remote_ec)],
            vec![],
        );

        let ec_pks = vec![shard0_pks, shard1_pks];
        let ctx = FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            ec_public_keys: &ec_pks,
        };
        tick.verify(&ctx).expect("honest finalization must verify");
    }

    /// One tampered EC fails its own predicate; the error names the
    /// failing index.
    #[test]
    fn verify_rejects_finalization_with_one_bad_ec() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[1]);
        let remote_wid = tick_id(1, 7, &[0]);

        let shard0_signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let shard1_signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let shard0_pks: Vec<ConsensusPublicKey> =
            shard0_signers.iter().map(BlsSigner::public_key).collect();
        let shard1_pks: Vec<ConsensusPublicKey> =
            shard1_signers.iter().map(BlsSigner::public_key).collect();

        let local_outcomes = vec![make_outcome(1)];
        let remote_outcomes = vec![make_outcome(1)];
        let local_ec =
            make_verified_ec(&net, &local_wid, &local_outcomes, &shard0_signers).into_inner();
        let remote_ec =
            make_verified_ec(&net, &remote_wid, &remote_outcomes, &shard1_signers).into_inner();

        // Tamper the second EC's aggregated signature.
        let tampered_remote = ExecutionCertificate::new(
            *remote_ec.tick_id(),
            remote_ec.vote_anchor_ts(),
            remote_ec.global_receipt_root(),
            remote_ec.tx_outcomes().clone(),
            AggregateSignature::new([0xFF; 96]),
            remote_ec.signers().clone(),
        );

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            vec![Arc::new(local_ec), Arc::new(tampered_remote)],
            vec![],
        );

        let ec_pks = vec![shard0_pks, shard1_pks];
        let ctx = FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            ec_public_keys: &ec_pks,
        };
        let err = tick.verify(&ctx).expect_err("tampered EC must fail verify");
        assert!(matches!(
            err,
            FinalizationVerifyError::ExecutionCertificate { index: 1, .. }
        ));
    }

    /// `from_committed_block` produces a verified tick whose inner is
    /// byte-equal to the input — the gate names the trust source, it
    /// does not modify the tick. Honest signers behind a real
    /// `Verified<CertifiedBlock>` would have already cleared every
    /// contained EC's signature predicate; this test pins the gate's
    /// no-op-on-content shape.
    #[test]
    fn from_committed_block_wraps_input_without_modification() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[]);
        let sks: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let outcomes = vec![make_outcome(1)];
        let ec = make_verified_ec(&net, &local_wid, &outcomes, &sks).into_inner();

        let tick = Finalization::new(local_wid, TickHalf::Determined, vec![Arc::new(ec)], vec![]);

        let verified = Verified::<Finalization>::from_committed_block(tick.clone());
        assert_eq!(verified.into_inner(), tick);
    }

    /// `ec_public_keys` length must match the number of ECs.
    #[test]
    fn verify_rejects_mismatched_public_key_vector_length() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[]);
        let sks: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();

        let outcomes = vec![make_outcome(1)];
        let ec = make_verified_ec(&net, &local_wid, &outcomes, &sks).into_inner();

        let tick = Finalization::new(local_wid, TickHalf::Determined, vec![Arc::new(ec)], vec![]);

        // Supply two public-key vectors for a single-EC tick.
        let ec_pks: Vec<Vec<ConsensusPublicKey>> = vec![vec![], vec![]];
        let ctx = FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            ec_public_keys: &ec_pks,
        };
        assert_eq!(
            tick.verify(&ctx),
            Err(FinalizationVerifyError::PublicKeyVectorLengthMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }
}
