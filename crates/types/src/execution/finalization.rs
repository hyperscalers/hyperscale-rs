//! [`Finalization`] — every participating shard's certificate for one
//! tick, plus the receipts that tick's own execution produced.
//!
//! [`Finalization`] is the raw wire form. Its verified form is
//! `Verified<Finalization>`; predicate at
//! [`impl Verify<&FinalizationContext<'_>>`](Verify::verify) below.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use blake3::Hasher;
use hyperscale_crypto::Verifier;
use hyperscale_hbor::{Capped, Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::{
    ConsensusPublicKey, ConsensusReceipt, ExecutionCertificate, ExecutionCertificateContext,
    ExecutionCertificateVerifyError, ExecutionOutcome, FAILED_RECEIPT_HASH, FinalizationHash,
    GlobalReceiptHash, Hash, MAX_TXS_PER_BLOCK, NetworkDefinition, RETENTION_HORIZON,
    StoredReceipt, TickId, TransactionDecision, TxHash, TxOutcome, TxResolution, Verifiable,
    Verified, Verify, WeightedTimestamp, receipt_hash_of,
};

/// Which half of its tick a finalization settles.
///
/// A tick settles in halves and they are not interchangeable: the
/// determined half carries writes every later tick can already read, so
/// it is what settlement order is measured over; the stating half says
/// what this shard's own certificate reached for every member a
/// sibling's verdict can still discard; and a legs half applies the
/// effects of stated members whose siblings' state accepts them, and may
/// land arbitrarily late. The half travels with the finalization and is
/// covered by its hash: a flipped marker would otherwise advance the
/// settlement frontier past a half that never settled.
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
    /// Stated members whose siblings' state accepts them, each named
    /// beside the receipt its row states. It carries no certificate, and
    /// settles by member: a finalization of this half names the ones it
    /// settles, and a tick may take several.
    Legs,
}

/// The members a legs half settles, each beside the hash of the receipt
/// it carries for the member, which is the one the member's row states.
type Named = Capped<Vec<(TxHash, GlobalReceiptHash)>, MAX_TXS_PER_BLOCK>;

/// A finalization — what one half of a tick settles, and the local
/// receipts it settles.
///
/// Receipts are written atomically with the block at commit time (not
/// fire-and-forget).
///
/// # Derived views
///
/// The transactions a finalization settles, their order, and per-tx
/// decisions are all **derived** from its certificate or its names, not
/// stored alongside them. See:
/// - [`Finalization::local_ec`] — the authoritative EC (where `ec.tick_id() == tick_id`)
/// - [`Finalization::settled_outcomes`] — the outcomes of that EC this finalization settles
/// - [`Finalization::tx_hashes`] — iterator over their tx hashes in block order
/// - [`Finalization::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// A determined half settles every outcome of its own certificate. A
/// stating half settles the outcomes its certificate refused, and states
/// the ones that succeeded without settling them
/// ([`Finalization::stated_outcomes`]). A legs half carries no
/// certificate and settles the effects of the members it names, each
/// beside the receipt it carries: the members a block may name in one
/// are the stated rows whose siblings' state accepts them, and a member
/// does not wait for a tick-mate still waiting on its own siblings.
///
/// `receipts` contains only txs that actually executed (sparse subset of
/// `tx_hashes()`, same block order). Aborted txs produce no receipt.
///
/// # Invariant (well-formed)
///
/// A well-formed determined or stating half contains **exactly one EC**,
/// its own tick's — the EC where `ec.tick_id() == fw.tick_id` — and names
/// nobody.
/// The local EC is the authoritative source for the half's tx set and
/// canonical (block) ordering. A well-formed legs half contains no
/// certificate, names at least one member, and carries one receipt per
/// name, in the names' order, each recomputing to the hash named for it.
///
/// Enforced at construction by `TickState` and at the wire boundary by
/// the decode impl.
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
    /// The tick's own certificate: present in a determined or stating
    /// half, absent from a legs half. A sibling's verdict is read from
    /// its committed state, so no finalization carries another tick's.
    certificate: Option<Arc<Verifiable<ExecutionCertificate>>>,
    receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    /// The members a legs half settles; empty in a determined half,
    /// which settles every member its certificate attests, and in a
    /// stating half, whose certificate says which it settles. Part of
    /// the identity, so two legs halves of one tick are two
    /// finalizations.
    named: Named,
}

/// The form of each half, enforced at the wire boundary.
///
/// A determined or stating half carries its own tick's certificate, the
/// authoritative source of what it settles, and names nobody. A legs
/// half carries no certificate at all, and is held to the receipts it
/// names, each recomputed from what it carries; or, stored as an
/// [attestation](Finalization::attestation), to no receipt, which
/// [`Finalization::reconstruct`] restores and every block that carries
/// the half is held to by its validation.
fn check_finalization(tick: &Finalization) -> Result<(), &'static str> {
    if tick.half == TickHalf::Legs {
        if tick.certificate.is_some() {
            return Err("a legs half carries no certificate");
        }
        if tick.receipts.is_empty() && !tick.named.is_empty() {
            return Ok(());
        }
        return tick
            .names_stand()
            .map_err(|_| "a legs half names the receipts it carries, each under its own hash");
    }
    if tick
        .certificate
        .as_ref()
        .is_none_or(|ec| ec.tick_id() != &tick.tick_id)
    {
        return Err("a determined or stating half carries its own tick's certificate");
    }
    tick.names_stand()
        .map_err(|_| "a determined or stating half names nobody")
}

/// What one outcome of a determined or stating half settles.
///
/// A success settles its own effects. Anything else discards them, and
/// what is left is the refusal receipt the outcome named beside them:
/// the payer's charge, which is how an attempt nobody applied still
/// costs its payer, and the consumer's `Never` for every refusable
/// crossing it consumed, which is how its producers learn the value is
/// theirs to credit back. Per shard, exactly one of a take inside the
/// effects and a `Never` inside the refusal receipt can settle.
///
/// A success a stating half carries states a yes and settles nothing:
/// the half settles only the outcomes [`Finalization::settled_outcomes`]
/// reads.
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

/// Whether `outcome` is this shard's success: the yes a stating half
/// states and does not settle.
const fn succeeded(outcome: &TxOutcome) -> bool {
    matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. })
}

/// What `outcome` settles.
#[must_use]
pub const fn settles(outcome: &TxOutcome) -> Settles {
    match outcome.outcome() {
        ExecutionOutcome::Succeeded { receipt_hash } => Settles::Effects(*receipt_hash),
        // Refused here: the effects are gone and the refusal receipt is
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
    /// A determined or stating half has no EC whose `tick_id` is the
    /// tick's own, which every one carries; this indicates a malformed or
    /// tampered half.
    MissingLocalEc,
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
    /// A name the half does not bear out: a legs half naming nobody, a
    /// name with no receipt beside it in its order or with one under
    /// another hash, or a determined or stating half naming anybody.
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
    /// members a block may accept. A determined half and a stating half
    /// name nobody and are returned as they are.
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
        self.certificate
            .as_deref()
            .map(Verifiable::as_unverified)
            .filter(|ec| ec.tick_id() == &self.tick_id)
    }

    /// The outcomes of the tick's own certificate this finalization
    /// settles, in the certificate's order: every one for a determined
    /// half, the ones other than a success for a stating half, and none
    /// for a legs half, which carries no certificate and settles its
    /// names ([`Self::tx_hashes`]).
    ///
    /// A success a stating half carries is a yes that settles nothing,
    /// read through [`Self::stated_outcomes`].
    pub fn settled_outcomes(&self) -> impl Iterator<Item = &TxOutcome> + '_ {
        let half = self.half;
        self.local_certificate()
            .into_iter()
            .flat_map(|ec| ec.tx_outcomes().iter())
            .filter(move |outcome| match half {
                TickHalf::Determined => true,
                TickHalf::Stated => !succeeded(outcome),
                TickHalf::Legs => false,
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

    /// The members a legs half settles by their effects: every name.
    /// Nothing of any other half.
    #[must_use]
    pub fn accepted_names(&self) -> BTreeSet<TxHash> {
        self.named.iter().map(|(tx_hash, _)| *tx_hash).collect()
    }

    /// Whether the half's names stand: a determined half and a stating
    /// half name nobody, and a legs half names at least one member, each
    /// beside the receipt it carries for it, in its order, a success
    /// whose hash is the one named and whose content recomputes to it
    /// under the shard's own locality, which a member a sibling shares
    /// the verdict on always runs under. The error is the first name
    /// that fails, where the fault is one name's.
    fn names_stand(&self) -> Result<(), Option<TxHash>> {
        match self.half {
            TickHalf::Determined | TickHalf::Stated => {
                return if self.named.is_empty() {
                    Ok(())
                } else {
                    Err(None)
                };
            }
            TickHalf::Legs if self.named.is_empty() => return Err(None),
            TickHalf::Legs => {}
        }
        let mut receipts = self.receipts.iter();
        for &(tx_hash, hash) in self.named.iter() {
            let held = receipts.next().is_some_and(|receipt| {
                receipt.tx_hash == tx_hash
                    && matches!(*receipt.consensus, ConsensusReceipt::Succeeded { .. })
                    && receipt.consensus.receipt_hash() == hash
                    && receipt_hash_of(&receipt.consensus, true) == Some(hash)
            });
            if !held {
                return Err(Some(tx_hash));
            }
        }
        receipts
            .next()
            .map_or(Ok(()), |extra| Err(Some(extra.tx_hash)))
    }

    /// The tick's own certificate as it rides: `Verifiable::Unverified`
    /// off the wire, `Verifiable::Verified` where it was assembled here
    /// ([`Self::from_verified_ec`]). `None` for a legs half.
    #[must_use]
    pub const fn certificate(&self) -> Option<&Arc<Verifiable<ExecutionCertificate>>> {
        self.certificate.as_ref()
    }

    /// The tick's own certificate, authoritative for what a determined or
    /// stating half settles and in what order. `None` for a legs half,
    /// which carries none.
    #[must_use]
    pub fn local_ec(&self) -> Option<&ExecutionCertificate> {
        self.local_certificate()
    }

    /// How long the chain carrying this finalization in a block anchored
    /// at `carried_at` remembers it and the members it resolves: its own
    /// certificate's deadline, past which no shard can still reference
    /// the tick, and for a legs half, which carries none, the retention
    /// horizon past the block that carries it.
    #[must_use]
    pub fn retained_until(&self, carried_at: WeightedTimestamp) -> WeightedTimestamp {
        self.local_ec().map_or_else(
            || carried_at.plus(RETENTION_HORIZON),
            ExecutionCertificate::deadline,
        )
    }

    /// The same finalization attested by `local`, the tick's own complete
    /// certificate signed at a later anchor, projected to the members
    /// this one settles, with the same receipts. A legs half carries no
    /// certificate to re-attest.
    ///
    /// A tick's own certificate stops verifying anywhere once its anchor's
    /// window is evicted, and a tick whose half is still owed then is
    /// re-attested by a later committee over the same outcomes, so the
    /// copy carrying the later certificate is the one a block can still
    /// carry. `None` unless `local` is that: the same tick and root, the
    /// same outcomes here, at a later anchor.
    #[must_use]
    pub fn reanchored(&self, local: &Verified<ExecutionCertificate>) -> Option<Self> {
        let held = self.local_ec()?;
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
        Some(Self {
            tick_id: self.tick_id,
            half: self.half,
            certificate: Some(Arc::new(Verifiable::from(projected))),
            receipts: self.receipts.clone(),
            named: self.named.clone(),
        })
    }

    /// The leaf a block's certificates section commits for this
    /// finalization: its tick and half, its certificate's content where
    /// it carries one, and then its names.
    ///
    /// **The names are part of the identity.** Two legs halves of one
    /// tick carry no certificate and differ only in which members they
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
    /// copies hashing alike, and the difference between them is what the
    /// half settles.
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
        if let Some(ec) = &self.certificate {
            hasher.update(ec.wire_hash().as_bytes());
        }
        hasher.update(&hbor_to_vec(&self.named).unwrap());
        FinalizationHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }

    /// Number of transactions this finalization settles.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.tx_hashes().count()
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
    /// settles, in canonical block order: its settled outcomes', or a
    /// legs half's names.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.settled_outcomes()
            .map(TxOutcome::tx_hash)
            .chain(self.named.iter().map(|(tx_hash, _)| *tx_hash))
    }

    /// The transactions this finalization resolves: those whose local
    /// outcome bears the verdict, and every name of a legs half, each an
    /// accept of a member a sibling shares the verdict on. A leg that
    /// succeeded is named here and resolved elsewhere, so it is among
    /// [`Self::tx_hashes`] and not among these.
    pub fn deciding_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.settled_outcomes()
            .filter(|outcome| outcome.decides())
            .map(TxOutcome::tx_hash)
            .chain(self.named.iter().map(|(tx_hash, _)| *tx_hash))
    }

    /// The transactions a stating half settles, which are all it settles
    /// anything of; `None` for any other half.
    fn stated_names(&self) -> Option<HashSet<TxHash>> {
        (self.half == TickHalf::Stated).then(|| self.tx_hashes().collect())
    }

    /// Whether this finalization settles a given tx.
    #[must_use]
    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.tx_hashes().any(|settled| settled == *tx_hash)
    }

    /// This finalization's attestation half — the tick, its certificate
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
            certificate: self.certificate.clone(),
            receipts: Capped::empty(),
            named: self.named.clone(),
        }
    }

    /// The key of every receipt this finalization settles, in its order:
    /// each settling outcome's transaction and receipt hash, or a legs
    /// half's names. `None` when a determined or stating half lacks its
    /// local certificate.
    ///
    /// Which outcomes owe a receipt is [`settles`]'s question — the same
    /// reading that built the list. An outcome that settles nothing was
    /// never stored, and an outcome that settles something was: anything
    /// else would either demand a receipt that does not exist or admit
    /// one the tick never carried.
    #[must_use]
    pub fn settled_receipts(&self) -> Option<Vec<(TxHash, GlobalReceiptHash)>> {
        if self.half == TickHalf::Legs {
            return Some(self.named.to_vec());
        }
        self.local_certificate()?;
        Some(
            self.settled_outcomes()
                .filter_map(|outcome| {
                    settles(outcome)
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
    /// from committed state. Walks [`Self::settled_receipts`] in order and
    /// fetches each receipt by its transaction and hash, so each block
    /// rebuilds with the receipts it settled.
    ///
    /// Returns `None` if:
    /// - A determined or stating half lacks its local EC (malformed —
    ///   should not happen for a committed tick).
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

    /// Build a determined or stating `Finalization` from raw inputs. The
    /// certificate lands `Verifiable::Unverified`: this is the
    /// constructor for wire reconstruction and tests, where it carries no
    /// verification marker. A locally aggregated tick that already holds
    /// a [`Verified<ExecutionCertificate>`] uses [`Self::from_verified_ec`]
    /// to carry its marker through; a legs half is built by
    /// [`Self::accepting`].
    ///
    /// Validates neither that the certificate is the tick's own nor the
    /// receipt-count cap; both are enforced at the wire boundary by the
    /// `Decode` impl, and the first also at the build boundary by
    /// `TickState::attestation`.
    #[must_use]
    pub fn new(
        tick_id: TickId,
        half: TickHalf,
        certificate: Option<Arc<ExecutionCertificate>>,
        receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    ) -> Self {
        Self {
            tick_id,
            half,
            certificate: certificate.map(|ec| Arc::new(Verifiable::from(Arc::unwrap_or_clone(ec)))),
            receipts,
            named: Capped::empty(),
        }
    }

    /// The legs half of `tick_id` accepting the member of each of
    /// `receipts`, its effects receipt, named beside its hash. It carries
    /// no certificate: the names are held to the receipts they name here,
    /// and to the rows that state them where a block admits the half.
    ///
    /// # Panics
    ///
    /// Never: the names are as many as the receipts, under one cap.
    #[must_use]
    pub fn accepting(
        tick_id: TickId,
        receipts: Capped<Vec<StoredReceipt>, MAX_TXS_PER_BLOCK>,
    ) -> Self {
        let named = Capped::new(
            receipts
                .iter()
                .map(|receipt| (receipt.tx_hash, receipt.consensus.receipt_hash()))
                .collect(),
        )
        .expect("one name per receipt, under the receipts' cap");
        Self {
            tick_id,
            half: TickHalf::Legs,
            certificate: None,
            receipts,
            named,
        }
    }

    /// Build a receiptless determined or stating `Finalization` from the
    /// tick's own certificate, which has already cleared its signature
    /// predicate, carrying its `Verifiable::Verified` marker. Receipts
    /// arrive through [`Self::with_receipts`], which is what the caller
    /// needs the certificate to decide.
    ///
    /// Used by `TickState`, whose certificate was produced through the
    /// [`Verified::<ExecutionCertificate>::aggregate`] gate. Keeping the
    /// marker leaves it consistent with the
    /// [`Verified<Finalization>`](Verified) it is sealed into, so a later
    /// [`Finalization::verify`](Verify::verify) short-circuits it instead
    /// of re-checking.
    #[must_use]
    pub fn from_verified_ec(half: TickHalf, certificate: Verified<ExecutionCertificate>) -> Self {
        Self {
            tick_id: *certificate.tick_id(),
            half,
            certificate: Some(Arc::new(Verifiable::from(certificate))),
            receipts: Capped::empty(),
            named: Capped::empty(),
        }
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

    /// Validate the half against what it carries: that its names stand,
    /// and that `receipts` follow from what its certificate decided.
    ///
    /// The names first, since a legs half is its names: each beside the
    /// receipt it carries, which recomputes to the named hash. A
    /// determined or stating half then carries exactly one receipt per
    /// outcome that settles one — every non-aborted outcome, plus every
    /// abort settling a fee — in `tx_outcomes` canonical order, with
    /// matching `tx_hash` and matching receipt hash.
    ///
    /// This does **not** verify a determined or stating half's
    /// `database_updates` or `writes_root` — its receipts carry only
    /// shard-filtered writes, so the global `writes_root` the EC commits
    /// to can't be reconstructed from a stored receipt alone. Use to catch
    /// gross drift (wrong tx, wrong success/fail, missing or surplus
    /// receipts) at peer-tick ingress.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`ReceiptValidationError`] variant on
    /// the first inconsistency found.
    pub fn validate_against_certificates(&self) -> Result<(), ReceiptValidationError> {
        self.names_stand()
            .map_err(|tx_hash| ReceiptValidationError::Misnamed { tx_hash })?;
        if self.half == TickHalf::Legs {
            return Ok(());
        }
        if self.local_certificate().is_none() {
            return Err(ReceiptValidationError::MissingLocalEc);
        }

        let mut receipt_iter = self.receipts.iter();
        for outcome in self.settled_outcomes() {
            let ec_kind = match settles(outcome) {
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
    /// A legs half settles the effects receipt of every member it names,
    /// under the hash it names. A determined or stating half settles each
    /// outcome's receipt as [`settles`] reads it: a success its effects,
    /// and any other outcome the refusal receipt it named and nothing
    /// else. A refusal receipt is not an effect: it settles whatever the
    /// verdict, which is what makes a refused attempt cost its payer
    /// something and answer its producers.
    ///
    /// The rule the receipts were built under, re-read rather than
    /// trusted: a tick arriving from a peer is validated at ingress, and
    /// this is the backstop for anything that reaches state by another
    /// road. A receipt of a transaction the half settles nothing of — a
    /// yes a stating half states — settles nothing.
    ///
    /// The attested roots are deliberately not filtered this way:
    /// the local receipts section covers everything the tick carried, because
    /// it attests what execution produced. This attests what the tick
    /// decided, which is a different question.
    #[must_use]
    pub fn settling_receipts(&self) -> Vec<StoredReceipt> {
        if self.half == TickHalf::Legs {
            return self
                .receipts
                .iter()
                .filter(|receipt| {
                    self.named
                        .contains(&(receipt.tx_hash, receipt.consensus.receipt_hash()))
                })
                .cloned()
                .collect();
        }
        // Per transaction, not a bare set of hashes: two legs of one payer
        // owing the same floor produce byte-identical charges, and a set
        // would let either stand in for the other.
        let mut refusals: HashMap<TxHash, GlobalReceiptHash> = HashMap::new();
        let mut refused: HashSet<TxHash> = HashSet::new();
        for outcome in self.settled_outcomes() {
            if !succeeded(outcome) {
                refused.insert(outcome.tx_hash());
            }
            if let Settles::Refusal(hash) = settles(outcome) {
                refusals.insert(outcome.tx_hash(), hash);
            }
        }
        let stated = self.stated_names();
        self.receipts
            .iter()
            .filter(|receipt| {
                let refusal =
                    refusals.get(&receipt.tx_hash) == Some(&receipt.consensus.receipt_hash());
                stated
                    .as_ref()
                    .is_none_or(|names| names.contains(&receipt.tx_hash))
                    && (!refused.contains(&receipt.tx_hash) || refusal)
            })
            .cloned()
            .collect()
    }

    /// Per-tx decisions (Aborted > Reject > Accept) for the transactions
    /// this finalization settles, off its own certificate's outcomes; every
    /// name of a legs half is an accept.
    ///
    /// Iteration order follows [`Self::tx_hashes`].
    #[must_use]
    pub fn tx_decisions(&self) -> Vec<(TxHash, TransactionDecision)> {
        let mut aborted: HashSet<TxHash> = HashSet::new();
        let mut failure: HashSet<TxHash> = HashSet::new();
        for outcome in self.settled_outcomes() {
            if outcome.is_aborted() {
                aborted.insert(outcome.tx_hash());
            }
            if !succeeded(outcome) {
                failure.insert(outcome.tx_hash());
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
    /// whatever its outcome reads: an abandonment is the abort. A legs
    /// half's name is the transaction accepted. Any other name decides as
    /// [`Self::tx_decisions`] aggregates it.
    ///
    /// Read off the half alone, so a replica holding no account of the
    /// transaction reads a name exactly as one that holds it.
    #[must_use]
    pub fn resolutions(&self) -> Vec<(TxHash, TxResolution)> {
        let accepted = self
            .named
            .iter()
            .map(|(tx_hash, _)| (*tx_hash, TxResolution::Decided(TransactionDecision::Accept)));
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
            .chain(accepted)
            .collect()
    }
}

/// Inputs the [`Finalization`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct FinalizationContext<'a> {
    /// Network identifier — feeds the domain-separated signing message
    /// for the certificate.
    pub network: &'a NetworkDefinition,
    /// The committee of the finalization's certificate, in committee
    /// order: present exactly when the finalization carries one.
    pub public_keys: Option<&'a [ConsensusPublicKey]>,
    /// Scheme verifier the certificate check runs through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`Finalization`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FinalizationVerifyError {
    /// Keys supplied for a finalization carrying no certificate, or none
    /// for one carrying it. Caller-side packaging error.
    #[error("public keys supplied do not match the certificate carried")]
    PublicKeysMismatch,
    /// The certificate failed its own predicate.
    #[error("execution certificate: {source}")]
    ExecutionCertificate {
        /// The underlying certificate verifier error.
        source: ExecutionCertificateVerifyError,
    },
}

/// Construction asserts: the [`ExecutionCertificate`] the finalization
/// carries, if any, verifies under the committee its anchor resolves.
///
/// Construction goes through one of three gates:
///
/// - [`<Finalization as Verify>::verify`](Verify::verify) — runs the
///   certificate's predicate unless it already carries a live
///   verification marker.
/// - [`Verified::<Finalization>::seal`] — wraps a locally built half
///   whose certificate was produced through the
///   [`Verified::<ExecutionCertificate>::aggregate`] gate.
/// - [`Verified::<Finalization>::from_committed_block`] — wraps a
///   tick reaching downstream consumers via a
///   [`Verified<CertifiedBlock>`], where the source committee's QC
///   BFT-transitively attests the certificate's signature claim.
///
/// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
impl Verify<&FinalizationContext<'_>> for Finalization {
    type Error = FinalizationVerifyError;

    fn verify(&self, ctx: &FinalizationContext<'_>) -> Result<Verified<Self>, Self::Error> {
        match (self.certificate(), ctx.public_keys) {
            (None, None) => {}
            // A half assembled in-memory carries its certificate already
            // Verified; a wire-decoded one arrives Unverified and runs the
            // predicate here.
            (Some(ec), Some(public_keys)) => {
                if !ec.is_verified() {
                    let ec_ctx = ExecutionCertificateContext {
                        network: ctx.network,
                        public_keys,
                        verifier: ctx.verifier,
                    };
                    ec.as_unverified().verify(&ec_ctx).map_err(|source| {
                        FinalizationVerifyError::ExecutionCertificate { source }
                    })?;
                }
            }
            _ => return Err(FinalizationVerifyError::PublicKeysMismatch),
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Finalization> {
    /// Wrap a locally built half whose certificate came through the
    /// [`Verified::<ExecutionCertificate>::aggregate`] gate.
    ///
    /// Trust source: the certificate was produced from a quorum of
    /// verified votes on this validator, so the predicate (its signature
    /// verifies under its committee) holds by construction.
    #[must_use]
    pub const fn seal(tick: Finalization) -> Self {
        // SAFETY: the certificate, where the half carries one, was built
        // by the local aggregator from verified votes (see
        // `Verified::<ExecutionCertificate>::aggregate`); its signature
        // verifies under its committee by construction.
        Self::new_unchecked(tick)
    }

    /// Wrap a finalization reaching the system via a committed block.
    ///
    /// Trust source: the tick was carried inside a
    /// [`Verified<CertifiedBlock>`]; 2f+1 of the block's committee
    /// signed over `block.hash()`, which commits to every contained
    /// tick and to each tick's receipt set via the header's body root. Honest signers ran the
    /// certificate signature predicate before voting, so the predicate
    /// [`<Finalization as Verify>::verify`](Verify::verify) would run is
    /// BFT-transitively attested by that committee.
    ///
    /// Used at sync admission, where the QC chain replaces local
    /// certificate signature checks on each contained tick.
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
        Address, AddressClass, AggregateSignature, BlockHeight, ExecutionVote, Hash, LocalKey,
        Role, ShardId, SignerBitfield, StateWrites, SubstateKey, ValidatorId, WeightedTimestamp,
        compute_global_receipt_root,
    };

    /// The half is part of what a finalization is, so it is part of its
    /// identity.
    ///
    /// The settlement frontier reads the half off the block and advances
    /// on it. If two finalizations differing only in their half shared a
    /// hash, a proposer could present one half as another under a hash
    /// the certificate root already commits to — advancing the frontier
    /// past a determined half that never settled, and barring it forever.
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
            Some(Arc::clone(&ec)),
            Capped::from_array([]),
        );
        let stating = Finalization::new(
            local_wid,
            TickHalf::Stated,
            Some(ec),
            Capped::from_array([]),
        );

        assert_ne!(
            determined.receipt_hash(),
            stating.receipt_hash(),
            "a flipped half must not pass under the hash the block commits to",
        );
    }

    /// For one outcome, `settles` returns the transaction's effects or
    /// its refusal receipt and never both.
    #[test]
    fn a_success_settles_its_effects_and_a_refusal_its_receipt() {
        let tx = TxHash::from(Hash::from_bytes(&[1; 4]));
        let effects = GlobalReceiptHash::from_raw(Hash::from_bytes(b"effects"));
        let ours = GlobalReceiptHash::from_raw(Hash::from_bytes(b"ours"));
        let accepted = TxOutcome::with_refusal(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: effects,
            },
            ours,
        );
        assert_eq!(
            settles(&accepted),
            Settles::Effects(effects),
            "a success settles its effects and not its refusal receipt",
        );
        let refused = TxOutcome::with_refusal(tx, ExecutionOutcome::Failed, ours);
        assert_eq!(settles(&refused), Settles::Refusal(ours));
    }

    /// A name resolves off its own outcome and nothing else: a leg's
    /// success is the leg finalizing, a leg's failure and a whole
    /// member's verdict decide as they read, and a member settling what
    /// an execution left aborts the transaction whatever its outcome
    /// reads: a settling success is no accept. A legs half's name is an
    /// accept.
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
        let accepting = legs_half(&[effects_of(tx, 1)]);
        assert_eq!(
            accepting.resolutions(),
            decided(TransactionDecision::Accept),
            "a legs half's name is an accept",
        );
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

    /// `tx`'s effects receipt, writing one cell under `seed` and stating
    /// the hash its content recomputes to.
    fn effects_of(tx: TxHash, seed: u8) -> StoredReceipt {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address::new([seed; 31], AddressClass::Component),
                local: LocalKey([seed; 16]),
            },
            Some(vec![seed]),
        );
        let unhashed = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        };
        let receipt_hash = receipt_hash_of(&unhashed, true).expect("a projected success");
        let ConsensusReceipt::Succeeded { writes, .. } = unhashed else {
            unreachable!("built a success")
        };
        StoredReceipt {
            tx_hash: tx,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash,
                writes,
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        }
    }

    fn member(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 4]))
    }

    /// The legs half of tick 7 here accepting the member of each of
    /// `receipts`.
    fn legs_half(receipts: &[StoredReceipt]) -> Finalization {
        Finalization::accepting(
            tick_id(0, 7, &[]),
            Capped::new(receipts.to_vec()).expect("a list written out in a test"),
        )
    }

    fn only(tx: TxHash) -> HashSet<TxHash> {
        HashSet::from([tx])
    }

    fn decoded(fw: &Finalization) -> Option<Finalization> {
        hbor_to_vec(fw)
            .ok()
            .and_then(|bytes| from_slice::<Finalization>(&bytes).ok())
    }

    /// A legs half settles the effects of the members it names, each
    /// beside the receipt it carries: every view reads the names, it
    /// charges nothing, and a stored copy rebuilds from the receipts of
    /// its names alone. Narrowed to one name, it settles that member and
    /// says nothing of its tick-mate.
    #[test]
    fn a_legs_half_settles_the_effects_it_names() {
        let (first, waiting) = (member(1), member(2));
        let (receipt, other) = (effects_of(first, 1), effects_of(waiting, 2));
        let whole = legs_half(&[receipt.clone(), other]);
        assert_eq!(whole.validate_against_certificates(), Ok(()));
        assert_eq!(decoded(&whole), Some(whole.clone()));

        let half = whole.naming(&only(first));
        let hash = receipt.consensus.receipt_hash();
        assert_eq!(decoded(&half), Some(half.clone()));
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert!(half.certificate().is_none());
        assert!(half.local_ec().is_none());
        assert_eq!(half.settling_receipts(), vec![receipt.clone()]);
        assert_eq!(half.settled_receipts(), Some(vec![(first, hash)]));
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), [first]);
        assert_eq!(half.deciding_tx_hashes().collect::<Vec<_>>(), [first]);
        assert_eq!(half.accepted_names(), BTreeSet::from([first]));
        assert_eq!(
            (half.tx_count(), half.charged()),
            (1, 0),
            "a legs half charges nothing: its tick's stating half counted the member",
        );
        assert!(half.contains_tx(&first) && !half.contains_tx(&waiting));
        assert_eq!(
            half.tx_decisions(),
            vec![(first, TransactionDecision::Accept)]
        );
        let stored = half.attestation();
        assert_eq!(
            decoded(&stored),
            Some(stored.clone()),
            "stored without its receipts, it decodes",
        );
        assert_eq!(
            stored.validate_against_certificates(),
            Err(ReceiptValidationError::Misnamed {
                tx_hash: Some(first)
            }),
            "and no block may carry it so",
        );
        assert_eq!(
            Finalization::reconstruct(half.attestation(), |tx_hash, receipt_hash| {
                (*tx_hash == first && *receipt_hash == hash).then(|| Arc::clone(&receipt.consensus))
            }),
            Some(half),
            "a stored half rebuilds from the receipts of its names alone",
        );
    }

    /// The names are part of what a legs half is: two halves of one tick
    /// naming different members are two finalizations a block and the
    /// dedup window tell apart.
    #[test]
    fn two_legs_halves_of_one_tick_hash_apart() {
        let (first, second) = (member(1), member(2));
        let whole = legs_half(&[effects_of(first, 1), effects_of(second, 2)]);
        let hashes = [
            whole.clone().naming(&only(first)).receipt_hash(),
            whole.clone().naming(&only(second)).receipt_hash(),
            whole.receipt_hash(),
        ];
        assert_eq!(
            hashes.iter().collect::<HashSet<_>>().len(),
            3,
            "each set of names is its own identity: {hashes:?}",
        );
    }

    /// A legs half is held to the receipts it names, where it is decoded
    /// and where it is validated: at least one name, each beside its
    /// receipt in its order under the hash the receipt states, which its
    /// content recomputes to; and a determined half names none.
    #[test]
    fn a_legs_half_is_held_to_the_receipts_it_names() {
        let (first, second) = (member(1), member(2));
        let (one, two) = (effects_of(first, 1), effects_of(second, 2));
        let whole = legs_half(&[one.clone(), two.clone()]);
        let names = whole.named.to_vec();

        let stripped = StoredReceipt {
            tx_hash: first,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: one.consensus.receipt_hash(),
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        };
        let failed = StoredReceipt {
            tx_hash: first,
            consensus: Arc::new(ConsensusReceipt::Failed),
        };
        for (named, receipts, failing) in [
            (vec![], vec![], None),
            (
                vec![names[1], names[0]],
                vec![one.clone(), two.clone()],
                Some(second),
            ),
            (vec![names[0]], vec![two.clone()], Some(first)),
            (
                vec![(first, GlobalReceiptHash::ZERO)],
                vec![one.clone()],
                Some(first),
            ),
            (vec![names[0]], vec![stripped], Some(first)),
            (
                vec![(first, FAILED_RECEIPT_HASH.to_owned())],
                vec![failed],
                Some(first),
            ),
            (vec![names[0]], vec![one.clone(), two], Some(second)),
            (vec![names[0], names[1]], vec![one], Some(second)),
        ] {
            let mut misnamed = whole.clone();
            misnamed.named = Capped::new(named).expect("a list written out in a test");
            misnamed.receipts = Capped::new(receipts).expect("a list written out in a test");
            assert_eq!(
                misnamed.validate_against_certificates(),
                Err(ReceiptValidationError::Misnamed { tx_hash: failing }),
                "naming {:?}",
                misnamed.named,
            );
            assert_eq!(decoded(&misnamed), None, "naming {:?}", misnamed.named);
        }

        let mut determined = stating_half(vec![core(1, b"effects", 10)]);
        determined.half = TickHalf::Determined;
        determined.named = Capped::new(names).expect("a list written out in a test");
        assert_eq!(
            determined.validate_against_certificates(),
            Err(ReceiptValidationError::Misnamed { tx_hash: None }),
        );
        assert_eq!(decoded(&determined), None);
    }

    /// A legs half carries no certificate: one carrying any does not
    /// decode, its own tick's or a counterpart's, whatever it names.
    #[test]
    fn a_legs_half_carrying_a_certificate_is_refused() {
        let yes = core(1, b"effects", 10);
        let local_wid = tick_id(0, 7, &[]);
        let certificate = |wid: TickId, outcome: TxOutcome| {
            Arc::new(ExecutionCertificate::new(
                wid,
                WeightedTimestamp::from_millis(1),
                compute_global_receipt_root(std::slice::from_ref(&outcome)),
                Capped::from_array([outcome]),
                AggregateSignature::ZERO,
                SignerBitfield::new(2),
            ))
        };
        for certificate in [
            certificate(local_wid, yes.clone()),
            certificate(tick_id(SIBLING, 3, &[]), yes.clone()),
        ] {
            let carrying = Finalization::new(
                local_wid,
                TickHalf::Legs,
                Some(certificate),
                Capped::from_array([receipt_under(&yes, b"effects")]),
            );
            assert_eq!(decoded(&carrying), None);
            assert!(carrying.validate_against_certificates().is_err());
        }
    }

    /// The stating half of tick 7 here over `outcomes`, on its own
    /// certificate alone.
    fn stating_half(outcomes: Vec<TxOutcome>) -> Finalization {
        let local_wid = tick_id(0, 7, &[]);
        Finalization::new(
            local_wid,
            TickHalf::Stated,
            Some(Arc::new(ExecutionCertificate::new(
                local_wid,
                WeightedTimestamp::from_millis(1),
                compute_global_receipt_root(&outcomes),
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(2),
            ))),
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
        let yes = core(1, b"effects", 10);
        let half = stating_half(vec![yes.clone()]);

        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.settled_outcomes().count(), 0);
        assert_eq!(half.stated_outcomes().collect::<Vec<_>>(), [&yes]);
        assert_eq!(half.tx_count(), 0);
        assert_eq!(half.tx_hashes().count(), 0);
        assert_eq!(half.deciding_tx_hashes().count(), 0);
        assert!(!half.contains_tx(&yes.tx_hash()));
        assert_eq!(half.settled_receipts(), Some(vec![]));
        assert_eq!(half.settling_receipts(), vec![]);
        assert_eq!(half.tx_decisions(), vec![]);
        assert_eq!(half.resolutions(), vec![]);
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
    /// names nobody: one naming a member is misnamed.
    #[test]
    fn a_stating_half_names_nobody() {
        let yes = core(1, b"effects", 10);
        let alone = stating_half(vec![yes.clone()]);
        assert_eq!(decoded(&alone), Some(alone.clone()));

        let mut naming = alone;
        naming.named = Capped::from_array([(yes.tx_hash(), GlobalReceiptHash::ZERO)]);
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

    /// Honest path: the certificate verifies under its committee's keys.
    #[test]
    fn verify_accepts_finalization_with_valid_ecs() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[1]);
        let signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let pks: Vec<ConsensusPublicKey> = signers.iter().map(BlsSigner::public_key).collect();
        let outcomes = vec![make_outcome(1), make_outcome(2)];
        let local_ec = make_verified_ec(&net, &local_wid, &outcomes, &signers).into_inner();

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            Some(Arc::new(local_ec)),
            Capped::from_array([]),
        );

        let ctx = FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: Some(&pks),
        };
        tick.verify(&ctx).expect("honest finalization must verify");
    }

    /// A tampered certificate fails its own predicate.
    #[test]
    fn verify_rejects_finalization_with_one_bad_ec() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[1]);
        let signers: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let pks: Vec<ConsensusPublicKey> = signers.iter().map(BlsSigner::public_key).collect();
        let outcomes = vec![make_outcome(1)];
        let local_ec = make_verified_ec(&net, &local_wid, &outcomes, &signers).into_inner();

        let tampered = ExecutionCertificate::new(
            *local_ec.tick_id(),
            local_ec.vote_anchor_ts(),
            local_ec.global_receipt_root(),
            Capped::new(local_ec.tx_outcomes().clone()).expect("a list written out in a test"),
            AggregateSignature::new([0xFF; 96]),
            local_ec.signers().clone(),
        );

        let tick = Finalization::new(
            local_wid,
            TickHalf::Determined,
            Some(Arc::new(tampered)),
            Capped::from_array([]),
        );

        let ctx = FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: Some(&pks),
        };
        let err = tick.verify(&ctx).expect_err("tampered EC must fail verify");
        assert!(matches!(
            err,
            FinalizationVerifyError::ExecutionCertificate { .. }
        ));
    }

    /// `from_committed_block` produces a verified tick whose inner is
    /// byte-equal to the input — the gate names the trust source, it
    /// does not modify the tick. Honest signers behind a real
    /// `Verified<CertifiedBlock>` would have already cleared every
    /// contained certificate's signature predicate; this test pins the gate's
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
            Some(Arc::new(ec)),
            Capped::from_array([]),
        );

        let verified = Verified::<Finalization>::from_committed_block(tick.clone());
        assert_eq!(verified.into_inner(), tick);
    }

    /// Keys are supplied exactly when the finalization carries a
    /// certificate.
    #[test]
    fn verify_rejects_keys_that_do_not_match_the_certificate_carried() {
        let net = NetworkDefinition::simulator();
        let local_wid = tick_id(0, 7, &[]);
        let sks: Vec<BlsSigner> = (0..2).map(|_| BlsSigner::generate()).collect();
        let ec = make_verified_ec(&net, &local_wid, &[make_outcome(1)], &sks).into_inner();
        let determined = Finalization::new(
            local_wid,
            TickHalf::Determined,
            Some(Arc::new(ec)),
            Capped::from_array([]),
        );
        let legs = Finalization::accepting(local_wid, Capped::from_array([]));
        let keys: Vec<ConsensusPublicKey> = Vec::new();
        let context = |public_keys| FinalizationContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys,
        };
        assert_eq!(
            determined.verify(&context(None)),
            Err(FinalizationVerifyError::PublicKeysMismatch)
        );
        assert_eq!(
            legs.verify(&context(Some(&keys))),
            Err(FinalizationVerifyError::PublicKeysMismatch)
        );
    }
}
