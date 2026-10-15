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
use hyperscale_hbor::{Capped, Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::{
    ConsensusPublicKey, ConsensusReceipt, ExecutionCertificate, ExecutionCertificateContext,
    ExecutionCertificateVerifyError, ExecutionOutcome, FAILED_RECEIPT_HASH, FinalizationHash,
    GlobalReceiptHash, Hash, MAX_TXS_PER_BLOCK, NetworkDefinition, Role, ShardId, StoredReceipt,
    TickId, TransactionDecision, TxClaim, TxHash, TxOutcome, TxResolution, Verifiable, Verified,
    Verify,
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
/// A tick settles in halves and they are not interchangeable: the
/// determined half carries writes every later tick can already read, so
/// it is what settlement order is measured over; the stating half says
/// what this shard's own certificate reached for every member a
/// counterpart's verdict can still discard; and a legs half waits on
/// those counterparts and may land arbitrarily late. Nothing else on a
/// finalization tells them apart — the certificates are the same shape
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
    /// What the tick's own certificate reached for every member whose
    /// settlement waits on a counterpart, once and whole. A member it
    /// refused settles here, on its refusal receipt; one that succeeded
    /// is stated, settles nothing, and waits for a legs half.
    Stated,
    /// The stated members whose counterparts have given their verdict.
    /// It settles by member: a finalization of this half names the ones
    /// it settles, and a tick may take several.
    Legs,
}

/// The members a legs half settles, each beside the receipt hash its own
/// outcome states, in the order the tick's own certificate attests them.
type Named = Capped<Vec<(TxHash, GlobalReceiptHash)>, MAX_TXS_PER_BLOCK>;

/// A finalization — every participating shard has attested the
/// transactions it settles, and the local receipts stand beside the
/// proof.
///
/// Receipts are written atomically with the block at commit time (not
/// fire-and-forget).
///
/// # Derived views
///
/// The transactions a finalization settles, their order, and per-tx
/// decisions are all **derived** from the execution certificates and the
/// names, not stored alongside them. See:
/// - [`Finalization::local_ec`] — the authoritative EC (where `ec.tick_id() == tick_id`)
/// - [`Finalization::settled_outcomes`] — the outcomes of that EC this finalization settles
/// - [`Finalization::tx_hashes`] — iterator over their tx hashes in block order
/// - [`Finalization::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// A determined half settles every outcome of its own certificate. A
/// stating half settles the outcomes its certificate refused, and states
/// the ones that succeeded without settling them
/// ([`Finalization::stated_outcomes`]). A legs half settles the ones it
/// names, since a member whose counterparts have all certified does not
/// wait for a tick-mate whose counterpart has not: every view reads the
/// names, and an outcome the half does not name is one it says nothing
/// about.
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
    execution_certificates:
        Capped<Vec<Arc<Verifiable<ExecutionCertificate>>>, MAX_EXECUTION_CERTIFICATES_PER_TICK>,
    receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    /// The members a legs half settles; empty in a determined half,
    /// which settles every member its certificate attests, and in a
    /// stating half, whose certificate says which it settles. Part of
    /// the identity, so two legs halves of one tick are two
    /// finalizations.
    named: Named,
}

/// The exactly-one-local-EC invariant and the form of the names, enforced
/// at the wire boundary. Zero local ECs would crash
/// [`Finalization::local_ec`]; multiple would let downstream code
/// silently disagree on which EC is authoritative for tx ordering; and
/// every view reads the names against that certificate's outcomes. A
/// stating half carries that certificate and no other: it says what this
/// shard reached, and a counterpart's certificate beside it would let a
/// view read a verdict the half does not carry.
fn check_finalization(tick: &Finalization) -> Result<(), &'static str> {
    let local = tick
        .execution_certificates
        .iter()
        .filter(|ec| ec.tick_id() == &tick.tick_id)
        .count();
    if local != 1 {
        return Err("a finalization carries exactly one local execution certificate");
    }
    if tick.half == TickHalf::Stated && tick.execution_certificates.len() != 1 {
        return Err("a stating half carries its own tick's certificate and no other");
    }
    tick.names_stand()
        .map_err(|_| "a finalization names only what its own certificate bears out")
}

/// The hash a legs half names beside `outcome`'s transaction: the
/// receipt of a success, else the refusal receipt the outcome names,
/// else nothing.
fn named_hash(outcome: &TxOutcome) -> GlobalReceiptHash {
    match outcome.outcome() {
        ExecutionOutcome::Succeeded { receipt_hash } => *receipt_hash,
        ExecutionOutcome::Failed | ExecutionOutcome::Aborted => {
            outcome.refusal_receipt().unwrap_or(GlobalReceiptHash::ZERO)
        }
    }
}

/// The names a half of `half` takes over `outcomes`: every one for a
/// legs half, none for a determined or a stating one.
fn names_of(half: TickHalf, outcomes: &[TxOutcome]) -> Named {
    match half {
        TickHalf::Determined | TickHalf::Stated => Capped::empty(),
        TickHalf::Legs => Capped::new(
            outcomes
                .iter()
                .map(|outcome| (outcome.tx_hash(), named_hash(outcome)))
                .collect(),
        )
        .expect("a certificate's outcomes are within the cap its names share"),
    }
}

/// What one outcome settles, given the verdict the whole tick reached.
///
/// A transaction settles its own effects only if every participant
/// accepted it. Otherwise the effects are discarded — that is what makes
/// a cross-shard abort atomic — and what is left is the refusal receipt
/// the outcome named beside them: the payer's charge, which is how an
/// attempt nobody applied still costs its payer, and the consumer's
/// `Never` for every refusable crossing it consumed, which is how its
/// producers learn the value is theirs to credit back. Per shard,
/// exactly one of a take inside the effects and a `Never` inside the
/// refusal receipt can settle.
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
    /// The refusal receipt named beside the outcome, under this receipt
    /// hash: the charge and the `Never` answers.
    Refusal(GlobalReceiptHash),
    /// The canonical failure record — a failure owing nothing apart.
    Failure,
    /// Nothing at all.
    Nothing,
}

impl Settles {
    /// The hash of the receipt this settles — the identity a stored
    /// receipt is kept under beside its transaction — or `None` when it
    /// settles nothing.
    #[must_use]
    pub fn receipt_hash(self) -> Option<GlobalReceiptHash> {
        match self {
            Self::Effects(hash) | Self::Refusal(hash) => Some(hash),
            Self::Failure => Some(*FAILED_RECEIPT_HASH),
            Self::Nothing => None,
        }
    }
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

/// Whether `outcome` is this shard's success: the yes a stating half
/// states and does not settle.
const fn succeeded(outcome: &TxOutcome) -> bool {
    matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. })
}

/// What `outcome` settles, given the transactions `refused` names.
#[must_use]
pub fn settles(outcome: &TxOutcome, refused: &BTreeSet<TxHash>) -> Settles {
    match outcome.outcome() {
        ExecutionOutcome::Succeeded { receipt_hash } if !refused.contains(&outcome.tx_hash()) => {
            Settles::Effects(*receipt_hash)
        }
        // Refused here, or completed here and refused by a counterpart.
        // Either way the effects are gone and the refusal receipt is
        // what is left.
        _ => match (outcome.refusal_receipt(), outcome.outcome()) {
            (Some(refusal), _) => Settles::Refusal(refusal),
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
    /// A name the half's own certificate does not bear out: a member it
    /// does not attest, one out of its order, one under another hash, a
    /// legs half naming nobody, or a determined or stating half naming
    /// anybody.
    Misnamed {
        /// The first name that fails, where one does.
        tx_hash: Option<TxHash>,
    },
}

impl Finalization {
    /// Stored receipts for txs that executed. Aborted txs are absent —
    /// `receipts.len() <= tx_count()`. Preserves canonical block order.
    /// Held in-memory until block commit, then written atomically with block metadata.
    #[must_use]
    pub fn receipts(&self) -> &Vec<StoredReceipt> {
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

    /// The same legs half settling only those of its names in `members`,
    /// and carrying only their receipts: how a half is narrowed to the
    /// members that have their verdict. A determined half and a stating
    /// half name nobody and are returned as they are.
    #[must_use]
    pub fn naming(mut self, members: &HashSet<TxHash>) -> Self {
        if matches!(self.half, TickHalf::Legs) {
            self.named.retain(|(tx_hash, _)| members.contains(tx_hash));
            self.receipts
                .retain(|receipt| members.contains(&receipt.tx_hash));
        }
        self
    }

    /// The tick's own certificate, where the finalization carries one.
    fn local_certificate(&self) -> Option<&ExecutionCertificate> {
        self.execution_certificates
            .iter()
            .find(|ec| ec.tick_id() == &self.tick_id)
            .map(|ec| ec.as_unverified())
    }

    /// The outcomes of the tick's own certificate this finalization
    /// settles, in the certificate's order: every one for a determined
    /// half, the ones other than a success for a stating half, the named
    /// ones for a legs half. Nothing where the certificate is missing.
    ///
    /// The one reading of what a finalization settles. A success a
    /// stating half carries is a yes that settles nothing, read through
    /// [`Self::stated_outcomes`]; an outcome a legs half carries and does
    /// not name is a tick-mate still waiting on its counterparts, which
    /// a later half of the same tick settles.
    pub fn settled_outcomes(&self) -> impl Iterator<Item = &TxOutcome> + '_ {
        let half = self.half;
        let mut names = self.named.iter().map(|(tx_hash, _)| *tx_hash).peekable();
        self.local_certificate()
            .into_iter()
            .flat_map(|ec| ec.tx_outcomes().iter())
            .filter(move |outcome| match half {
                TickHalf::Determined => true,
                TickHalf::Stated => !succeeded(outcome),
                TickHalf::Legs => names.next_if_eq(&outcome.tx_hash()).is_some(),
            })
    }

    /// The outcomes a stating half states and does not settle, in the
    /// certificate's order: its successes, each a yes its counterparts
    /// have yet to answer. Nothing of any other half.
    pub fn stated_outcomes(&self) -> impl Iterator<Item = &TxOutcome> + '_ {
        let stating = self.half == TickHalf::Stated;
        self.local_certificate()
            .into_iter()
            .flat_map(|ec| ec.tx_outcomes().iter())
            .filter(move |outcome| stating && succeeded(outcome))
    }

    /// The members a legs half settles by their effects: each name whose
    /// own outcome succeeded, that no certificate the half carries
    /// refuses, and whose every counterpart has reported. Nothing of any
    /// other half.
    ///
    /// The one reading of which names accept. A name outside it settles
    /// a refusal receipt or nothing at all, so the receipts that settle
    /// and the rows that go on standing as accepted are picked by it
    /// alike.
    #[must_use]
    pub fn accepted_names(&self) -> BTreeSet<TxHash> {
        if self.half != TickHalf::Legs {
            return BTreeSet::new();
        }
        let refused = refused_transactions(&self.execution_certificates);
        let uncovered = self.uncovered_transactions();
        self.settled_outcomes()
            .filter(|outcome| {
                matches!(settles(outcome, &refused), Settles::Effects(_))
                    && !uncovered.contains_key(&outcome.tx_hash())
            })
            .map(TxOutcome::tx_hash)
            .collect()
    }

    /// Whether the half's own certificate bears its names out: a
    /// determined half and a stating half name nobody, and a legs half
    /// names at least one
    /// member, each one the certificate attests, in its order and under
    /// the hash its outcome states. The error is the first name that
    /// fails, where the fault is one name's.
    fn names_stand(&self) -> Result<(), Option<TxHash>> {
        let stands = match self.half {
            TickHalf::Determined | TickHalf::Stated => self.named.is_empty(),
            TickHalf::Legs => !self.named.is_empty(),
        };
        if !stands {
            return Err(None);
        }
        let mut outcomes = self
            .local_certificate()
            .into_iter()
            .flat_map(|ec| ec.tx_outcomes().iter());
        let unborne = self.named.iter().find(|(tx_hash, hash)| {
            !outcomes.any(|outcome| outcome.tx_hash() == *tx_hash && named_hash(outcome) == *hash)
        });
        unborne.map_or(Ok(()), |(tx_hash, _)| Err(Some(*tx_hash)))
    }

    /// Execution certificates from all participating shards.
    /// Always includes the local EC (see invariant above).
    /// May contain multiple ECs from the same remote shard — this happens when
    /// a remote shard committed this tick's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (`shard_id`, `tick_id`) for deterministic `receipt_hash`.
    ///
    /// Each EC rides as `Verifiable<ExecutionCertificate>`: wire-decoded
    /// certificates land `Verifiable::Unverified`; locally assembled
    /// ones carry the `Verifiable::Verified` marker from
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

    /// The same finalization attested by `local`, the tick's own complete
    /// certificate signed at a later anchor, projected to the members
    /// this one settles. Receipts and every counterpart certificate stay.
    ///
    /// A tick's own certificate stops verifying anywhere once its anchor's
    /// window is evicted, and a tick whose half is still owed then is
    /// re-attested by a later committee over the same outcomes, so the
    /// copy carrying the later certificate is the one a block can still
    /// carry. `None` unless `local` is that: the same tick and root, the
    /// same outcomes here, at a later anchor.
    #[must_use]
    pub fn reanchored(&self, local: &Verified<ExecutionCertificate>) -> Option<Self> {
        let held = self.local_ec();
        if local.tick_id() != &self.tick_id
            || !local.is_complete()
            || local.global_receipt_root() != held.global_receipt_root()
            || local.vote_anchor_ts() <= held.vote_anchor_ts()
        {
            return None;
        }
        let members: HashSet<TxHash> = held.tx_outcomes().iter().map(TxOutcome::tx_hash).collect();
        let projected = local.project_to(&members)?;
        if projected.tx_outcomes() != held.tx_outcomes() {
            return None;
        }
        let projected = Arc::new(Verifiable::from(projected));
        Some(Self {
            tick_id: self.tick_id,
            half: self.half,
            execution_certificates: self.execution_certificates.map(|ec| {
                if ec.tick_id() == &self.tick_id {
                    Arc::clone(&projected)
                } else {
                    Arc::clone(ec)
                }
            }),
            receipts: self.receipts.clone(),
            named: self.named.clone(),
        })
    }

    /// The leaf a block's certificates section commits for this
    /// finalization: its tick and half, each constituent certificate's
    /// content, in the order the vec was sorted into at construction,
    /// and then its names.
    ///
    /// **The names are part of the identity.** Two legs halves of one
    /// tick carry the same certificates wherever one counterpart's copy
    /// covers both their members, and differ only in which members they
    /// settle; under one hash the second would be refused as a repeat of
    /// the first, and a proposer could present one set of names under a
    /// leaf committing to another.
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
    /// Panics if HBOR encoding of a `TickId` or of the names fails —
    /// closed wire types, infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> FinalizationHash {
        let mut hasher = Hasher::new();
        hasher.update(&hbor_to_vec(&self.tick_id).unwrap());
        hasher.update(&hbor_to_vec(&self.half).unwrap());
        for ec in &self.execution_certificates {
            hasher.update(ec.wire_hash().as_bytes());
        }
        hasher.update(&hbor_to_vec(&self.named).unwrap());
        FinalizationHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }

    /// Number of transactions this finalization settles.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.settled_outcomes().count()
    }

    /// Iterator over each receipt's consensus payload, in canonical
    /// block order. Used by pending-chain insertion and local-receipt
    /// root verification.
    pub fn consensus_receipts(&self) -> impl Iterator<Item = Arc<ConsensusReceipt>> + '_ {
        self.receipts.iter().map(|r| Arc::clone(&r.consensus))
    }

    /// What this finalization adds to its block's fee total, in quanta:
    /// what the transactions a determined half settles were charged
    /// between them; every outcome of a stating half's certificate, a
    /// yes included, since a member is counted where its shard states
    /// its outcome; and nothing for a legs half, whose members their
    /// stating half counted. Saturating, so a forged tick cannot wrap a
    /// block's running total.
    #[must_use]
    pub fn charged(&self) -> u128 {
        match self.half {
            TickHalf::Determined | TickHalf::Stated => self
                .settled_outcomes()
                .chain(self.stated_outcomes())
                .fold(0u128, |sum, outcome| sum.saturating_add(outcome.charged())),
            TickHalf::Legs => 0,
        }
    }

    /// Iterator over the hashes of the transactions this finalization
    /// settles, in canonical block order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.settled_outcomes().map(TxOutcome::tx_hash)
    }

    /// The transactions this finalization resolves: those whose local
    /// outcome bears the verdict. A leg that succeeded is named here and
    /// resolved elsewhere, so it is among [`Self::tx_hashes`] and not
    /// among these.
    pub fn deciding_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.settled_outcomes()
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
    /// counterpart attested, for a member that ran in this tick awaiting
    /// some, is an abandonment claim on each one it awaited: the abort is
    /// dominant and needs no verdict of theirs, but a certificate of this
    /// shard's for the member is out, so it needs them not to have
    /// settled against it. A member that awaited nobody — a leg or a core
    /// answering alone — claims nothing: its verdict is its own, and no
    /// counterpart's set can contradict it.
    ///
    /// Nor does a member its tick settles and never ran, a
    /// [`Role::Settling`] outcome. The one such member that names
    /// counterparts is an abandonment, seated from an `Aborted` line. A
    /// line aborts a member that ever ran only where a committed record
    /// covers it, where it reaches no other shard, or once a recovery
    /// has released it; every other abort is of a member no tick ran,
    /// for which no certificate of this shard's exists for a counterpart
    /// to have settled against. No half settles a member a recovery
    /// released, whatever a counterpart did against the certificate the
    /// replaced committee left, so its abort is put to no set either:
    /// it ends the row on this shard. Its certificate is the fresh
    /// committee's, anchored past the recovery's bridge, so a counterpart
    /// that has not settled verifies it and ends its own row by it, and
    /// one that settled keeps what it settled. Its licence is the
    /// line, which every voter held to the member's row, and a settled
    /// set has nothing to add to it.
    ///
    /// Nor does a name `covered` claims anything: a committed record has
    /// already established that no counterpart can settle it, in a form
    /// that does not expire with the set it was read from, and putting
    /// the question again would let the set's own horizon refuse a
    /// verdict the chain already licensed.
    ///
    /// Nor does an outcome a legs half does not name, a counterpart's
    /// or this shard's: the half settles nothing of that transaction, so
    /// it asks nothing about it, and the half that names it does.
    ///
    /// Nor does a stating half, of anything. A refusal it settles stands
    /// in the certificate every counterpart must carry to settle the
    /// member, a member runs once, and a yes settles nothing.
    pub fn claims(
        &self,
        local: ShardId,
        covered: impl Fn(TxHash) -> bool,
    ) -> Vec<(ShardId, TxHash, TxClaim)> {
        if self.half == TickHalf::Stated {
            return Vec::new();
        }
        let mut claims: Vec<(ShardId, TxHash, TxClaim)> = Vec::new();
        let mut attested_remotely: HashSet<TxHash> = HashSet::new();
        let names = self.names();
        for ec in &self.execution_certificates {
            let shard = ec.shard_id();
            if shard == local {
                continue;
            }
            for outcome in ec.tx_outcomes() {
                if names
                    .as_ref()
                    .is_some_and(|names| !names.contains(&outcome.tx_hash()))
                {
                    continue;
                }
                attested_remotely.insert(outcome.tx_hash());
                claims.push((shard, outcome.tx_hash(), TxClaim::Settled));
            }
        }
        for outcome in self.settled_outcomes() {
            let tx_hash = outcome.tx_hash();
            if attested_remotely.contains(&tx_hash)
                || outcome.role() == Role::Settling
                || covered(tx_hash)
            {
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

    /// The transactions a legs half names or a stating half settles,
    /// which are all either settles anything of; `None` for a determined
    /// half, which is held to no names.
    fn names(&self) -> Option<HashSet<TxHash>> {
        match self.half {
            TickHalf::Determined => None,
            TickHalf::Stated | TickHalf::Legs => Some(self.tx_hashes().collect()),
        }
    }

    /// Whether this finalization settles a given tx.
    #[must_use]
    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.settled_outcomes().any(|o| &o.tx_hash() == tx_hash)
    }

    /// This finalization's attestation half — the tick, its certificates
    /// and its names, without the receipts.
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
            receipts: Capped::empty(),
            named: self.named.clone(),
        }
    }

    /// The key of every receipt this finalization settles, in its local
    /// certificate's outcome order: each settling outcome's transaction
    /// and receipt hash. `None` when the tick lacks a local certificate.
    ///
    /// Which outcomes owe a receipt is [`settles`]'s question, asked
    /// against the whole certificate — the same reading that built the
    /// list. An outcome that settles nothing was never stored, and an
    /// outcome that settles something was: anything else would either
    /// demand a receipt that does not exist or admit one the tick never
    /// carried.
    #[must_use]
    pub fn settled_receipts(&self) -> Option<Vec<(TxHash, GlobalReceiptHash)>> {
        self.local_certificate()?;
        let refused = refused_transactions(&self.execution_certificates);
        Some(
            self.settled_outcomes()
                .filter_map(|outcome| {
                    settles(outcome, &refused)
                        .receipt_hash()
                        .map(|receipt_hash| (outcome.tx_hash(), receipt_hash))
                })
                .collect(),
        )
    }

    /// Restore the receipts of an [`attestation`](Self::attestation) read
    /// back out of storage.
    ///
    /// Used on the storage/sync serving side to rebuild the in-memory shape
    /// from committed state. Walks the local EC's `tx_outcomes` in canonical
    /// block order and fetches a receipt for each outcome that settles one,
    /// by its transaction and the hash of the receipt the outcome names, so
    /// each block rebuilds with the receipt it settled.
    ///
    /// Returns `None` if:
    /// - The tick lacks a local EC (malformed — should not happen for a
    ///   committed tick per the `TickState::attestation` invariant).
    /// - A receipt the tick settled is missing from the lookup
    ///   (peer/storage has incomplete state — a syncing peer should try a
    ///   different source).
    ///
    /// # Panics
    ///
    /// If a list runs past the cap its type states, which a committee's own vote cannot.
    pub fn reconstruct<F>(attestation: Self, mut lookup: F) -> Option<Self>
    where
        F: FnMut(&TxHash, &GlobalReceiptHash) -> Option<Arc<ConsensusReceipt>>,
    {
        let receipts: Vec<StoredReceipt> = attestation
            .settled_receipts()?
            .into_iter()
            .map(|(tx_hash, receipt_hash)| {
                lookup(&tx_hash, &receipt_hash).map(|receipt| StoredReceipt::new(tx_hash, receipt))
            })
            .collect::<Option<_>>()?;

        Some(attestation.with_receipts(
            Capped::new(receipts).expect("a list under the cap its source already met"),
        ))
    }

    /// Build a `Finalization` from raw inputs. Each EC lands
    /// `Verifiable::Unverified` — this is the constructor for wire
    /// reconstruction and tests, where the ECs carry no verification
    /// marker. Locally aggregated ticks that already hold
    /// [`Verified<ExecutionCertificate>`]s use [`Self::from_verified_ecs`]
    /// to carry their markers through.
    ///
    /// A legs half built here names every member its own certificate
    /// attests; [`Self::naming`] narrows it.
    ///
    /// Validates neither the exactly-one-local-EC invariant nor the
    /// receipt-count cap; both are enforced at the wire boundary by the
    /// `Decode` impl, and the first also at the build boundary by
    /// `TickState::attestation`.
    #[must_use]
    pub fn new(
        tick_id: TickId,
        half: TickHalf,
        execution_certificates: &Capped<
            Vec<Arc<ExecutionCertificate>>,
            MAX_EXECUTION_CERTIFICATES_PER_TICK,
        >,
        receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    ) -> Self {
        Self {
            tick_id,
            half,
            execution_certificates: execution_certificates
                .map(|ec| Arc::new(Verifiable::from((**ec).clone()))),
            receipts,
            named: Capped::empty(),
        }
        .naming_every_member()
    }

    /// Build a receiptless `Finalization` from execution certificates
    /// that have already cleared their per-EC signature predicate,
    /// carrying the `Verifiable::Verified` marker on each. Receipts
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
        execution_certificates: &Capped<
            Vec<Verified<ExecutionCertificate>>,
            MAX_EXECUTION_CERTIFICATES_PER_TICK,
        >,
    ) -> Self {
        Self {
            tick_id,
            half,
            execution_certificates: execution_certificates
                .map(|ec| Arc::new(Verifiable::from(ec.clone()))),
            receipts: Capped::empty(),
            named: Capped::empty(),
        }
        .naming_every_member()
    }

    /// A legs half naming every member its own certificate attests, as
    /// each constructor builds one; [`Self::naming`] narrows it.
    fn naming_every_member(mut self) -> Self {
        self.named = self
            .local_certificate()
            .map_or_else(Capped::empty, |ec| names_of(self.half, ec.tx_outcomes()));
        self
    }

    /// The same tick carrying `receipts`. The receipt-count cap is
    /// enforced at encode and decode, not here.
    #[must_use]
    pub fn with_receipts(
        mut self,
        receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    ) -> Self {
        self.receipts = receipts;
        self
    }

    /// Transactions this finalization settles that the tick's own
    /// certificate names a participant for and no carried certificate
    /// speaks for, each with one such shard.
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
    pub(crate) fn uncovered_transactions(&self) -> BTreeMap<TxHash, ShardId> {
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
        self.settled_outcomes()
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
    /// The names first, since every later step reads the outcomes they
    /// pick out. Then completeness — a transaction whose participants
    /// have not all reported has no verdict to check receipts against,
    /// and [`Self::uncovered_transactions`] is where the reason lives.
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
        if self.local_certificate().is_none() {
            return Err(ReceiptValidationError::MissingLocalEc);
        }
        self.names_stand()
            .map_err(|tx_hash| ReceiptValidationError::Misnamed { tx_hash })?;

        if let Some((&tx_hash, &missing)) = self.uncovered_transactions().iter().next() {
            return Err(ReceiptValidationError::IncompleteCoverage { tx_hash, missing });
        }

        let refused = refused_transactions(&self.execution_certificates);
        let mut receipt_iter = self.receipts.iter();
        for outcome in self.settled_outcomes() {
            let ec_kind = match settles(outcome, &refused) {
                Settles::Effects(hash) | Settles::Refusal(hash) => Some(hash),
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
    /// A refusal receipt is not an effect. The one an outcome names
    /// settles whatever the verdict, which is what makes a refused
    /// attempt cost its payer something and answer its producers.
    ///
    /// The [`settles`] rule the receipts were built under, re-read
    /// against the certificate rather than trusted: a tick arriving from
    /// a peer is validated at ingress, and this is the backstop for
    /// anything that reaches state by another road.
    ///
    /// It bites in one direction only. A refused transaction settles the
    /// refusal receipt its outcome named and nothing else, and one no set of
    /// certificates decides — a participant it names has not reported —
    /// settles nothing at all, because the failure to stop there moves
    /// value one-sidedly. Anything the certificates refuse nothing of and
    /// decide between them passes as it stands — a receipt whose hash
    /// disagreed with its outcome is caught at ingress, and dropping it
    /// here instead would lose committed state with no diagnostic.
    ///
    /// The attested roots are deliberately not filtered this way:
    /// the local receipts section covers everything the tick carried, because
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
        // would let either stand in for the other. Off the local
        // certificate only: two core shards name different refusal
        // receipts for one transaction, each carrying its own answers,
        // and a map filled across every certificate would keep whichever
        // came last.
        let mut refusals: HashMap<TxHash, GlobalReceiptHash> = HashMap::new();
        for outcome in self.settled_outcomes() {
            if let Settles::Refusal(hash) = settles(outcome, &refused) {
                refusals.insert(outcome.tx_hash(), hash);
            }
        }
        // A receipt of a transaction a legs half does not name, or of
        // one a stating half states a yes for, settles nothing: the half
        // reaches no verdict on it. A legs half settles the effects of
        // the names it accepts and the refusal receipt of any other.
        let names = self.names();
        let accepted = self.accepted_names();
        self.receipts
            .iter()
            .filter(|receipt| {
                let refusal =
                    refusals.get(&receipt.tx_hash) == Some(&receipt.consensus.receipt_hash());
                match self.half {
                    TickHalf::Legs => accepted.contains(&receipt.tx_hash) || refusal,
                    TickHalf::Determined | TickHalf::Stated => {
                        names
                            .as_ref()
                            .is_none_or(|names| names.contains(&receipt.tx_hash))
                            && !uncovered.contains_key(&receipt.tx_hash)
                            && (!refused.contains(&receipt.tx_hash) || refusal)
                    }
                }
            })
            .cloned()
            .collect()
    }

    /// Aggregate per-tx decisions across all ECs (Aborted > Reject > Accept),
    /// for the transactions this finalization settles.
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

    /// What this finalization settles about each transaction it names,
    /// in block order.
    ///
    /// A leg's success decides nothing: the leg finalized. A member
    /// settling what an execution left is the transaction aborted,
    /// whatever its outcome reads: an abandonment is the abort. Any other
    /// name decides as [`Self::tx_decisions`] aggregates it.
    ///
    /// Read off the outcomes alone, so a replica holding no account of
    /// the transaction reads a name exactly as one that holds it.
    #[must_use]
    pub fn resolutions(&self) -> Vec<(TxHash, TxResolution)> {
        self.settled_outcomes()
            .zip(self.tx_decisions())
            .map(|(outcome, (tx_hash, decision))| {
                let resolution = if !outcome.decides() {
                    TxResolution::LegFinalized
                } else if outcome.executes() {
                    TxResolution::Decided(decision)
                } else {
                    TxResolution::Decided(TransactionDecision::Aborted)
                };
                (tx_hash, resolution)
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
    /// holds by construction. Used at the `TickState::into_finalization`
    /// boundary.
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
    /// tick and to each tick's receipt set via the header's body root. Honest signers ran the
    /// per-EC signature predicate before voting, so the predicate
    /// [`<Finalization as Verify>::verify`](Verify::verify) would run is
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
        // signature checks via the block's body root. Mirrors
        // `Verified::<Provisions>::from_committed_block` and the
        // QC-transitive trust shape on
        // `Verified::<CertifiedBlock>::from_qc_attestation`.
        Self::new_unchecked(tick)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::from_slice;

    use super::*;
    use crate::{
        AggregateSignature, BlockHeight, ExecutionVote, GlobalReceiptRoot, Hash, ShardId,
        SignerBitfield, StateWrites, ValidatorId, WeightedTimestamp, compute_global_receipt_root,
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
            Capped::from_array([make_outcome(1)]),
            AggregateSignature::ZERO,
            SignerBitfield::new(2),
        ));
        let determined = Finalization::new(
            local_wid,
            TickHalf::Determined,
            &Capped::from_array([Arc::clone(&ec)]),
            Capped::from_array([]),
        );
        let legs = Finalization::new(
            local_wid,
            TickHalf::Legs,
            &Capped::from_array([ec]),
            Capped::from_array([]),
        );

        assert_ne!(
            determined.receipt_hash(),
            legs.receipt_hash(),
            "a flipped half must not pass under the hash the block commits to",
        );
    }

    /// For one outcome, `settles` returns the transaction's effects or
    /// its refusal receipt and never both; and a tick whose sibling
    /// certificate names a different refusal receipt for the same
    /// transaction settles the local one. Two core shards each carry
    /// their own `Never` answers, so the receipts differ, and a map
    /// filled across every certificate would keep whichever came last.
    #[test]
    fn a_refusal_receipt_is_the_local_certificates() {
        let tx = TxHash::from(Hash::from_bytes(&[1; 4]));
        let effects = GlobalReceiptHash::from_raw(Hash::from_bytes(b"effects"));
        let ours = GlobalReceiptHash::from_raw(Hash::from_bytes(b"ours"));
        let theirs = GlobalReceiptHash::from_raw(Hash::from_bytes(b"theirs"));
        let accepted = TxOutcome::with_refusal(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: effects,
            },
            ours,
        );
        assert_eq!(
            settles(&accepted, &BTreeSet::new()),
            Settles::Effects(effects),
            "accepted everywhere, the effects settle and the refusal receipt does not",
        );
        assert_eq!(
            settles(&accepted, &BTreeSet::from([tx])),
            Settles::Refusal(ours),
            "refused elsewhere, the effects go and the refusal receipt is what is left",
        );
        let refused = TxOutcome::with_refusal(tx, ExecutionOutcome::Failed, ours);
        assert_eq!(settles(&refused, &BTreeSet::new()), Settles::Refusal(ours));

        let local_wid = tick_id(0, 7, &[]);
        let remote_wid = tick_id(1, 3, &[]);
        let receipt = |hash: GlobalReceiptHash| StoredReceipt {
            tx_hash: tx,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: hash,
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        };
        let certificate = |wid: TickId, refusal: GlobalReceiptHash| {
            Arc::new(ExecutionCertificate::new(
                wid,
                WeightedTimestamp::from_millis(1),
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::with_refusal(
                    tx,
                    ExecutionOutcome::Failed,
                    refusal,
                )]),
                AggregateSignature::ZERO,
                SignerBitfield::new(2),
            ))
        };
        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            &Capped::from_array([
                certificate(remote_wid, theirs),
                certificate(local_wid, ours),
            ]),
            Capped::from_array([]),
        )
        .with_receipts(Capped::from_array([receipt(ours), receipt(theirs)]));
        assert_eq!(
            tick.settling_receipts()
                .iter()
                .map(|receipt| receipt.consensus.receipt_hash())
                .collect::<Vec<_>>(),
            vec![ours],
            "the local certificate's refusal receipt settles, and the sibling's does not",
        );
    }

    /// A name resolves off its own outcome and nothing else: a leg's
    /// success is the leg finalizing, a leg's failure and a whole
    /// member's verdict decide as they read, and a member settling what
    /// an execution left aborts the transaction whatever its outcome
    /// reads: a settling success is no accept.
    #[test]
    fn a_name_resolves_off_its_own_outcome() {
        use crate::Role;
        use crate::test_utils::finalization_of;

        let succeeded = ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        };
        let tx = TxHash::from(Hash::from_bytes(b"named"));
        let resolved =
            |outcome: TxOutcome| finalization_of(BlockHeight::new(1), vec![outcome]).resolutions();
        let decided = |decision| vec![(tx, TxResolution::Decided(decision))];

        assert_eq!(
            resolved(TxOutcome::new(tx, succeeded.clone()).as_role(Role::Leg)),
            vec![(tx, TxResolution::LegFinalized)],
            "a leg's success is its own state",
        );
        assert_eq!(
            resolved(TxOutcome::new(tx, ExecutionOutcome::Failed).as_role(Role::Leg)),
            decided(TransactionDecision::Reject),
            "a leg's failure is the verdict",
        );
        assert_eq!(
            resolved(TxOutcome::new(tx, succeeded.clone()).as_role(Role::Core)),
            decided(TransactionDecision::Accept),
            "a combined core's success is the verdict",
        );
        assert_eq!(
            resolved(TxOutcome::new(tx, ExecutionOutcome::Failed)),
            decided(TransactionDecision::Reject),
            "and so is a whole member's",
        );
        for (outcome, settling) in [
            (succeeded, "a settling success"),
            (ExecutionOutcome::Failed, "a settling failure"),
            (ExecutionOutcome::Aborted, "an abandonment"),
        ] {
            assert_eq!(
                resolved(TxOutcome::new(tx, outcome).as_role(Role::Settling)),
                decided(TransactionDecision::Aborted),
                "{settling} aborts the transaction",
            );
        }
    }

    /// An abandonment, attested `Aborted` by a member its tick settles
    /// and never ran, puts no claim to any counterpart's settled set,
    /// covered or not. A member that ran in the tick and is attested
    /// aborted there claims of every counterpart it awaited, unless a
    /// record covers it.
    #[test]
    fn an_abandonment_claims_nothing_of_its_counterparts() {
        use crate::test_utils::finalization_of;

        let local = ShardId::ROOT;
        let (near, far) = (ShardId::leaf(2, 1), ShardId::leaf(2, 2));
        let tx = TxHash::from(Hash::from_bytes(b"abandoned"));
        let aborted = |role| {
            finalization_of(
                BlockHeight::new(1),
                vec![
                    TxOutcome::new(tx, ExecutionOutcome::Aborted)
                        .charging(7)
                        .awaiting([near, far])
                        .as_role(role),
                ],
            )
        };

        let abandonment = aborted(Role::Settling);
        assert!(abandonment.local_ec().tx_outcomes()[0].reaches_beyond());
        for covered in [false, true] {
            assert_eq!(abandonment.claims(local, |_| covered), vec![]);
        }

        for ran in [Role::Whole, Role::Core] {
            assert_eq!(
                aborted(ran).claims(local, |_| false),
                vec![
                    (near, tx, TxClaim::Abandoned),
                    (far, tx, TxClaim::Abandoned),
                ],
                "{ran:?}: its certificate is out for a counterpart to settle against",
            );
            assert_eq!(aborted(ran).claims(local, |_| true), vec![], "{ran:?}");
        }
    }

    const SIBLING: u64 = 1;

    /// A core member's success here under `receipt`, awaiting the
    /// sibling shard, charged `charged`.
    fn core(seed: u8, receipt: &[u8], charged: u128) -> TxOutcome {
        TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(receipt)),
            },
        )
        .charging(charged)
        .awaiting([ShardId::leaf(3, SIBLING)])
        .as_role(Role::Core)
    }

    /// The sibling's outcome for `local`'s transaction, awaiting this
    /// shard for it.
    fn sibling(local: &TxOutcome, outcome: ExecutionOutcome) -> TxOutcome {
        TxOutcome::new(local.tx_hash(), outcome)
            .awaiting([ShardId::leaf(3, 0)])
            .as_role(Role::Core)
    }

    /// The legs half of tick 7 here, its own certificate attesting
    /// `local` and the sibling's attesting `remote`, naming every member
    /// its own certificate carries.
    fn legs_half(local: Vec<TxOutcome>, remote: Vec<TxOutcome>) -> Finalization {
        let certificate = |tick: TickId, outcomes: Vec<TxOutcome>| {
            Arc::new(ExecutionCertificate::new(
                tick,
                WeightedTimestamp::from_millis(1),
                compute_global_receipt_root(&outcomes),
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(2),
            ))
        };
        let local_wid = tick_id(0, 7, &[]);
        Finalization::new(
            local_wid,
            TickHalf::Legs,
            &Capped::from_array([
                certificate(local_wid, local),
                certificate(tick_id(SIBLING, 3, &[]), remote),
            ]),
            Capped::empty(),
        )
    }

    /// A receipt of `outcome`'s transaction under `hash`.
    fn receipt_under(outcome: &TxOutcome, hash: &[u8]) -> StoredReceipt {
        StoredReceipt {
            tx_hash: outcome.tx_hash(),
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(hash)),
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        }
    }

    fn only(outcome: &TxOutcome) -> HashSet<TxHash> {
        HashSet::from([outcome.tx_hash()])
    }

    /// A legs half naming one member settles it on the certificates that
    /// cover it, whatever its tick-mates still wait for: every view reads
    /// the name, and coverage is asked of it alone.
    #[test]
    fn a_covered_leg_settles_beside_an_uncovered_tick_mate() {
        let (covered, waiting) = (core(1, b"covered", 10), core(2, b"waiting", 20));
        let whole = legs_half(
            vec![covered.clone(), waiting.clone()],
            vec![sibling(&covered, covered.outcome().clone())],
        );
        assert_eq!(
            whole
                .clone()
                .with_receipts(Capped::from_array([receipt_under(&covered, b"covered")]))
                .validate_against_certificates(),
            Err(ReceiptValidationError::IncompleteCoverage {
                tx_hash: waiting.tx_hash(),
                missing: ShardId::leaf(3, SIBLING),
            }),
            "a half naming the waiting member too has no verdict on it",
        );

        let receipt = receipt_under(&covered, b"covered");
        let half = whole
            .naming(&only(&covered))
            .with_receipts(Capped::from_array([receipt.clone()]));
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.settling_receipts(), vec![receipt]);
        assert_eq!(
            half.settled_receipts(),
            Some(vec![(
                covered.tx_hash(),
                GlobalReceiptHash::from_raw(Hash::from_bytes(b"covered")),
            )]),
        );
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), [covered.tx_hash()]);
        assert_eq!(
            half.deciding_tx_hashes().collect::<Vec<_>>(),
            [covered.tx_hash()],
        );
        assert_eq!(
            (half.tx_count(), half.charged()),
            (1, 0),
            "a legs half charges nothing: its tick's stating half counted the member",
        );
        assert!(half.contains_tx(&covered.tx_hash()) && !half.contains_tx(&waiting.tx_hash()));
        assert_eq!(
            half.tx_decisions(),
            vec![(covered.tx_hash(), TransactionDecision::Accept)],
        );
        assert_eq!(
            half.resolutions(),
            vec![(
                covered.tx_hash(),
                TxResolution::Decided(TransactionDecision::Accept),
            )],
        );
        assert_eq!(
            Finalization::reconstruct(half.attestation(), |tx_hash, receipt_hash| {
                (*tx_hash == covered.tx_hash()
                    && *receipt_hash == GlobalReceiptHash::from_raw(Hash::from_bytes(b"covered")))
                .then(|| Arc::clone(&half.receipts()[0].consensus))
            }),
            Some(half),
            "a stored half rebuilds from the receipts of its names alone",
        );
    }

    /// A named member a counterpart refused settles its refusal receipt
    /// and not its effects, beside a tick-mate still waiting. The hash
    /// named for a member is its own outcome's: the receipt of a
    /// success, else the refusal receipt, else nothing.
    #[test]
    fn a_named_refused_leg_settles_its_refusal() {
        let refusal = GlobalReceiptHash::from_raw(Hash::from_bytes(b"refusal"));
        let ran = TxOutcome::with_refusal(
            TxHash::from(Hash::from_bytes(&[1; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"effects")),
            },
            refusal,
        )
        .charging(10)
        .awaiting([ShardId::leaf(3, SIBLING)])
        .as_role(Role::Core);
        let waiting = core(2, b"waiting", 20);
        let charge = receipt_under(&ran, b"refusal");
        let half = legs_half(
            vec![ran.clone(), waiting],
            vec![sibling(&ran, ExecutionOutcome::Failed)],
        )
        .naming(&only(&ran))
        .with_receipts(Capped::from_array([charge.clone()]));

        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.settling_receipts(), vec![charge]);
        assert_eq!(
            half.tx_decisions(),
            vec![(ran.tx_hash(), TransactionDecision::Reject)],
        );
        assert_eq!(
            half.named.as_slice(),
            [(
                ran.tx_hash(),
                GlobalReceiptHash::from_raw(Hash::from_bytes(b"effects")),
            )],
            "a success is named by its own receipt, whatever a counterpart said",
        );

        let failed = TxOutcome::with_refusal(
            TxHash::from(Hash::from_bytes(&[3; 4])),
            ExecutionOutcome::Failed,
            refusal,
        )
        .as_role(Role::Core);
        let aborted = TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[4; 4])),
            ExecutionOutcome::Aborted,
        )
        .as_role(Role::Core);
        assert_eq!(
            legs_half(vec![failed.clone(), aborted.clone()], vec![])
                .named
                .as_slice(),
            [
                (failed.tx_hash(), refusal),
                (aborted.tx_hash(), GlobalReceiptHash::ZERO),
            ],
        );
    }

    /// The names are part of what a legs half is: two halves of one tick
    /// over the same certificates, naming different members, are two
    /// finalizations a block and the dedup window tell apart.
    #[test]
    fn two_legs_halves_of_one_tick_hash_apart() {
        let (first, second) = (core(1, b"first", 10), core(2, b"second", 20));
        let whole = legs_half(
            vec![first.clone(), second.clone()],
            vec![
                sibling(&first, first.outcome().clone()),
                sibling(&second, second.outcome().clone()),
            ],
        );
        let hashes = [
            whole.clone().naming(&only(&first)).receipt_hash(),
            whole.clone().naming(&only(&second)).receipt_hash(),
            whole.receipt_hash(),
        ];
        assert_eq!(
            hashes.iter().collect::<HashSet<_>>().len(),
            3,
            "each set of names is its own identity: {hashes:?}",
        );
    }

    /// A half is held to names its own certificate bears out, where it
    /// is decoded and where it is validated: a legs half names members
    /// the certificate attests, in its order, each under the hash its
    /// outcome states, and at least one; a determined half names none.
    #[test]
    fn a_half_misnaming_its_certificate_is_refused() {
        let (first, second) = (core(1, b"first", 10), core(2, b"second", 20));
        let whole = legs_half(
            vec![first.clone(), second.clone()],
            vec![
                sibling(&first, first.outcome().clone()),
                sibling(&second, second.outcome().clone()),
            ],
        );
        let decoded = |fw: &Finalization| {
            hbor_to_vec(fw)
                .ok()
                .and_then(|bytes| from_slice::<Finalization>(&bytes).ok())
        };
        assert_eq!(decoded(&whole), Some(whole.clone()));
        let narrowed = whole.clone().naming(&only(&second));
        assert_eq!(decoded(&narrowed), Some(narrowed));

        let stranger = TxHash::from(Hash::from_bytes(b"stranger"));
        let names = whole.named.to_vec();
        for (half, named, failing) in [
            (TickHalf::Legs, vec![], None),
            (
                TickHalf::Legs,
                vec![names[1], names[0]],
                Some(first.tx_hash()),
            ),
            (
                TickHalf::Legs,
                vec![(first.tx_hash(), GlobalReceiptHash::ZERO)],
                Some(first.tx_hash()),
            ),
            (
                TickHalf::Legs,
                vec![names[0], (stranger, GlobalReceiptHash::ZERO)],
                Some(stranger),
            ),
            (TickHalf::Determined, names.clone(), None),
        ] {
            let mut misnamed = whole.clone();
            misnamed.half = half;
            misnamed.named = Capped::new(named).expect("a list written out in a test");
            assert_eq!(
                misnamed.validate_against_certificates(),
                Err(ReceiptValidationError::Misnamed { tx_hash: failing }),
                "{half:?} naming {:?}",
                misnamed.named,
            );
            assert_eq!(
                decoded(&misnamed),
                None,
                "{half:?} naming {:?}",
                misnamed.named
            );
        }
    }

    /// An outcome a legs half does not name puts no claim to a
    /// counterpart's settled set: not a settlement where a certificate
    /// covers it, and not an abandonment where none does.
    #[test]
    fn an_unnamed_outcome_claims_nothing() {
        let local = ShardId::leaf(3, 0);
        let (named, unnamed) = (core(1, b"named", 10), core(2, b"unnamed", 20));
        let settled = vec![(ShardId::leaf(3, SIBLING), named.tx_hash(), TxClaim::Settled)];

        let elsewhere = core(3, b"of another tick", 30);
        let covered = legs_half(
            vec![named.clone(), unnamed.clone()],
            vec![
                sibling(&named, named.outcome().clone()),
                sibling(&unnamed, unnamed.outcome().clone()),
                sibling(&elsewhere, elsewhere.outcome().clone()),
            ],
        )
        .naming(&only(&named));
        assert_eq!(covered.claims(local, |_| false), settled);

        let uncovered = legs_half(
            vec![named.clone(), unnamed],
            vec![sibling(&named, named.outcome().clone())],
        )
        .naming(&only(&named));
        assert_eq!(uncovered.claims(local, |_| false), settled);
    }

    /// The stating half of tick 7 here over `outcomes`, on its own
    /// certificate alone.
    fn stating_half(outcomes: Vec<TxOutcome>) -> Finalization {
        let local_wid = tick_id(0, 7, &[]);
        Finalization::new(
            local_wid,
            TickHalf::Stated,
            &Capped::from_array([Arc::new(ExecutionCertificate::new(
                local_wid,
                WeightedTimestamp::from_millis(1),
                compute_global_receipt_root(&outcomes),
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(2),
            ))]),
            Capped::empty(),
        )
    }

    /// A core member this shard refused under `refusal`, charged
    /// `charged`.
    fn refused_core(seed: u8, refusal: &[u8], charged: u128) -> TxOutcome {
        TxOutcome::with_refusal(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Failed,
            GlobalReceiptHash::from_raw(Hash::from_bytes(refusal)),
        )
        .charging(charged)
        .awaiting([ShardId::leaf(3, SIBLING)])
        .as_role(Role::Core)
    }

    /// A success a stating half carries is a yes and nothing more: no
    /// view that says what the half settles, resolves, claims or stores
    /// names it. It is read through `stated_outcomes` alone, and counted
    /// only in what the half charges.
    #[test]
    fn a_stated_yes_decides_nothing() {
        let local = ShardId::leaf(3, 0);
        let yes = core(1, b"effects", 10);
        let half = stating_half(vec![yes.clone()]);

        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.settled_outcomes().count(), 0);
        assert_eq!(half.stated_outcomes().collect::<Vec<_>>(), [&yes]);
        assert_eq!(half.tx_count(), 0);
        assert_eq!(half.tx_hashes().count(), 0);
        assert_eq!(half.deciding_tx_hashes().count(), 0);
        assert!(!half.contains_tx(&yes.tx_hash()));
        assert_eq!(half.claims(local, |_| false), vec![]);
        assert_eq!(half.settled_receipts(), Some(vec![]));
        assert_eq!(half.settling_receipts(), vec![]);
        assert_eq!(half.tx_decisions(), vec![]);
        assert_eq!(half.resolutions(), vec![]);
        assert_eq!(half.uncovered_transactions(), BTreeMap::new());
        assert!(half.named.is_empty());
        assert_eq!(
            Finalization::reconstruct(half.attestation(), |_, _| None),
            Some(half.clone()),
            "a stored stating half of yeses rebuilds from no receipt",
        );
        assert_eq!(
            half.charged(),
            10,
            "the stating half is where a member is counted"
        );

        for other in [TickHalf::Determined, TickHalf::Legs] {
            let mut read_as = half.clone();
            read_as.half = other;
            assert_eq!(
                read_as.stated_outcomes().count(),
                0,
                "{other:?} states nothing"
            );
        }
    }

    /// A stating half settles the refusal receipts of the members its
    /// certificate refused and nothing of a member it states a yes for:
    /// a receipt riding beside a yes fails validation, and the commit
    /// path's own reading drops it whatever let it through.
    #[test]
    fn a_stating_half_carrying_a_yes_receipt_settles_only_its_refusals() {
        let local = ShardId::leaf(3, 0);
        let (yes, no) = (core(1, b"effects", 10), refused_core(2, b"refusal", 20));
        let aborted = TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[3; 4])),
            ExecutionOutcome::Aborted,
        )
        .charging(5)
        .awaiting([ShardId::leaf(3, SIBLING)])
        .as_role(Role::Settling);
        let charge = receipt_under(&no, b"refusal");
        let half = stating_half(vec![yes.clone(), no.clone(), aborted.clone()])
            .with_receipts(Capped::from_array([charge.clone()]));

        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.settling_receipts(), vec![charge.clone()]);
        assert_eq!(
            half.tx_hashes().collect::<Vec<_>>(),
            [no.tx_hash(), aborted.tx_hash()],
        );
        assert_eq!(half.stated_outcomes().collect::<Vec<_>>(), [&yes]);
        assert_eq!(
            half.tx_decisions(),
            vec![
                (no.tx_hash(), TransactionDecision::Reject),
                (aborted.tx_hash(), TransactionDecision::Aborted),
            ],
        );
        assert_eq!(
            half.claims(local, |_| false),
            vec![],
            "a refusal stands in the certificate a counterpart must carry",
        );
        assert_eq!(
            (half.tx_count(), half.charged()),
            (2, 35),
            "every outcome of the certificate is charged, the yes included",
        );

        let smuggled = half.with_receipts(Capped::from_array([
            receipt_under(&yes, b"effects"),
            charge.clone(),
        ]));
        assert!(
            smuggled.validate_against_certificates().is_err(),
            "a yes carries no receipt",
        );
        assert_eq!(
            smuggled.settling_receipts(),
            vec![charge],
            "and one carried beside it reaches no state",
        );
    }

    /// A stating half says what this shard's own certificate reached and
    /// carries no other: one with a counterpart's certificate beside it
    /// does not decode, and neither does one naming a member.
    #[test]
    fn a_stating_half_carrying_a_second_certificate_does_not_decode() {
        let yes = core(1, b"effects", 10);
        let decoded = |fw: &Finalization| {
            hbor_to_vec(fw)
                .ok()
                .and_then(|bytes| from_slice::<Finalization>(&bytes).ok())
        };
        let alone = stating_half(vec![yes.clone()]);
        assert_eq!(decoded(&alone), Some(alone.clone()));

        let mut beside = legs_half(
            vec![yes.clone()],
            vec![sibling(&yes, yes.outcome().clone())],
        );
        assert_eq!(
            decoded(&beside),
            Some(beside.clone()),
            "a legs half carries both"
        );
        beside.half = TickHalf::Stated;
        beside.named = Capped::empty();
        assert_eq!(beside.execution_certificates().len(), 2);
        assert_eq!(decoded(&beside), None);

        let mut naming = alone;
        naming.named = Capped::from_array([(yes.tx_hash(), named_hash(&yes))]);
        assert_eq!(
            naming.validate_against_certificates(),
            Err(ReceiptValidationError::Misnamed { tx_hash: None }),
        );
        assert_eq!(decoded(&naming), None);
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
                    WeightedTimestamp::from_millis(tick_id.block_height().inner() + 1),
                    *tick_id,
                    Capped::new(outcomes.to_vec()).expect("a list written out in a test"),
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
            &Capped::from_array([Arc::new(local_ec), Arc::new(remote_ec)]),
            Capped::from_array([]),
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
            Capped::new(remote_ec.tx_outcomes().clone()).expect("a list written out in a test"),
            AggregateSignature::new([0xFF; 96]),
            remote_ec.signers().clone(),
        );

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            &Capped::from_array([Arc::new(local_ec), Arc::new(tampered_remote)]),
            Capped::from_array([]),
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

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            &Capped::from_array([Arc::new(ec)]),
            Capped::from_array([]),
        );

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

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            &Capped::from_array([Arc::new(ec)]),
            Capped::from_array([]),
        );

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
