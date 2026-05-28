//! Merkle root computation and verification for the per-block fields in
//! [`BlockHeader`].
//!
//! Each per-root type's verified form is `Verified<XRoot>`; predicate at
//! the `impl Verify<&XRootContext<'_>>` below. Construction goes through
//! one of three gates per type:
//!
//! - `Verified::<XRoot>::compute(data) -> Self` — produce the canonical
//!   root from leaf data. Infallible; verified-by-construction.
//! - `<XRoot as Verify>::verify(&self, ctx)` — recompute from data
//!   carried in `ctx` and compare against `self`. On success the
//!   returned wrapper carries `self`, which (by the predicate) equals
//!   `compute(data)`. The error reports the computed/claimed pair on
//!   mismatch.
//! - `Verified::<XRoot>::from_pipeline_attestation(root)` — re-wrap a
//!   root the verification pipeline's per-root tracking has already
//!   confirmed (skip case or previously-verified entry).

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeight, BoundedBTreeMap, CertificateRoot,
    ConsensusReceipt, FinalizedWave, Hash, LocalReceiptRoot, MAX_REMOTE_SHARDS_PER_WAVE,
    ProvisionTxRoot, ProvisionsRoot, ReadySignal, Round, RoutableTransaction, ShardGroupId,
    ShardWitnessPayload, StoredReceipt, TopologySnapshot, TransactionRoot, TxHash, Verified,
    Verify, WeightedTimestamp, compute_merkle_root,
};

// ─── VerifiedCertificateRoot ────────────────────────────────────────────────

/// Inputs the [`CertificateRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct CertificateRootContext<'a> {
    /// The block's finalized wave certificates — each contributes one
    /// leaf (its `receipt_hash`) to the recomputed root.
    pub certificates: &'a [Arc<FinalizedWave>],
}

/// Failure modes of [`CertificateRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CertRootVerifyError {
    /// The root computed from the supplied certificates does not match
    /// the claimed root.
    #[error("computed certificate root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: CertificateRoot,
        /// Root computed from the supplied certificates.
        computed: CertificateRoot,
    },
}

impl Verified<CertificateRoot> {
    /// Compute the certificate root from `certificates`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(certificates: &[Arc<FinalizedWave>]) -> Self {
        if certificates.is_empty() {
            return Self::new_unchecked(CertificateRoot::ZERO);
        }
        let leaves: Vec<Hash> = certificates
            .iter()
            .map(|fw| fw.certificate().receipt_hash().into_raw())
            .collect();
        Self::new_unchecked(CertificateRoot::from_raw(compute_merkle_root(&leaves)))
    }

    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no certificates (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: CertificateRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: the wrapped [`CertificateRoot`] equals
/// `compute_merkle_root` of each underlying wave certificate's
/// `receipt_hash`, in block order.
impl Verify<&CertificateRootContext<'_>> for CertificateRoot {
    type Augment = ();
    type Error = CertRootVerifyError;

    fn verify(&self, ctx: &CertificateRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.certificates).as_ref();
        if computed != *self {
            return Err(CertRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}

// ─── VerifiedLocalReceiptRoot ───────────────────────────────────────────────

/// Inputs the [`LocalReceiptRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct LocalReceiptRootContext<'a> {
    /// The block's stored receipts — each contributes one leaf
    /// (`local_receipt_hash`) to the recomputed root.
    pub receipts: &'a [StoredReceipt],
}

/// Failure modes of [`LocalReceiptRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LocalReceiptRootVerifyError {
    /// The root computed from the supplied receipts does not match the
    /// claimed root.
    #[error("computed local receipt root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: LocalReceiptRoot,
        /// Root computed from the supplied receipts.
        computed: LocalReceiptRoot,
    },
}

impl Verified<LocalReceiptRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no certificates (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: LocalReceiptRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the local-receipt root from `receipts`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(receipts: &[StoredReceipt]) -> Self {
        if receipts.is_empty() {
            return Self::new_unchecked(LocalReceiptRoot::ZERO);
        }
        let leaves: Vec<Hash> = receipts
            .iter()
            .map(|r| r.consensus.local_receipt_hash())
            .collect();
        Self::new_unchecked(LocalReceiptRoot::from_raw(compute_merkle_root(&leaves)))
    }
}

/// Construction asserts: the wrapped [`LocalReceiptRoot`] equals
/// `compute_merkle_root` of each receipt's `local_receipt_hash`, in
/// block order.
impl Verify<&LocalReceiptRootContext<'_>> for LocalReceiptRoot {
    type Augment = ();
    type Error = LocalReceiptRootVerifyError;

    fn verify(&self, ctx: &LocalReceiptRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.receipts).as_ref();
        if computed != *self {
            return Err(LocalReceiptRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}

// ─── VerifiedProvisionsRoot ─────────────────────────────────────────────────

/// Inputs the [`ProvisionsRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionsRootContext<'a> {
    /// Provision-batch hashes in block order — each contributes one
    /// leaf to the recomputed root.
    pub batch_hashes: &'a [Hash],
}

/// Failure modes of [`ProvisionsRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ProvisionRootVerifyError {
    /// The root computed from the supplied provision-batch hashes does
    /// not match the claimed root.
    #[error("computed provision root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: ProvisionsRoot,
        /// Root computed from the supplied batch hashes.
        computed: ProvisionsRoot,
    },
}

impl Verified<ProvisionsRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no provisions (header claims `ProvisionsRoot::ZERO`) or
    /// an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: ProvisionsRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the provisions root from `batch_hashes`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(batch_hashes: &[Hash]) -> Self {
        if batch_hashes.is_empty() {
            return Self::new_unchecked(ProvisionsRoot::ZERO);
        }
        Self::new_unchecked(ProvisionsRoot::from_raw(compute_merkle_root(batch_hashes)))
    }
}

/// Construction asserts: the wrapped [`ProvisionsRoot`] equals
/// `compute_merkle_root` of the batch hashes in block order.
impl Verify<&ProvisionsRootContext<'_>> for ProvisionsRoot {
    type Augment = ();
    type Error = ProvisionRootVerifyError;

    fn verify(&self, ctx: &ProvisionsRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.batch_hashes).as_ref();
        if computed != *self {
            return Err(ProvisionRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}

// ─── VerifiedTransactionRoot ────────────────────────────────────────────────

/// Inputs the [`TransactionRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct TransactionRootContext<'a> {
    /// The block's transactions — each contributes one leaf (its
    /// content hash) to the recomputed root.
    pub transactions: &'a [Arc<RoutableTransaction>],
    /// Parent QC's `weighted_timestamp` — the shard-consensus-authenticated
    /// clock for this block, used as the anchor every tx's `validity_range`
    /// must enclose. An honest cluster never sees a window mismatch here
    /// because the proposer applied the same check during transaction
    /// selection.
    pub validity_anchor: WeightedTimestamp,
}

/// Failure modes of [`TransactionRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum TxRootVerifyError {
    /// The root computed from the supplied transactions does not match
    /// the claimed root.
    #[error("computed transaction root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: TransactionRoot,
        /// Root computed from the supplied transactions.
        computed: TransactionRoot,
    },
    /// A transaction's `validity_range` either was malformed or did not
    /// contain the parent QC's weighted timestamp.
    #[error(
        "tx {tx_hash:?} validity window {start_ms}..{end_ms} \
         does not contain anchor {anchor_ms}"
    )]
    ValidityWindowExpired {
        /// Hash of the offending transaction.
        tx_hash: TxHash,
        /// Anchor (parent QC's weighted timestamp) in millis.
        anchor_ms: u64,
        /// Start of the tx's validity window in millis (inclusive).
        start_ms: u64,
        /// End of the tx's validity window in millis (exclusive).
        end_ms: u64,
    },
}

impl Verified<TransactionRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no transactions (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: TransactionRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the transaction root from `transactions`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(transactions: &[Arc<RoutableTransaction>]) -> Self {
        if transactions.is_empty() {
            return Self::new_unchecked(TransactionRoot::ZERO);
        }
        let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.hash().into_raw()).collect();
        // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
        // merkle inclusion proofs can be generated and verified for any leaf.
        Self::new_unchecked(TransactionRoot::from_raw(compute_merkle_root(&leaves)))
    }
}

/// Construction asserts both:
///
/// 1. The wrapped [`TransactionRoot`] equals `compute_merkle_root` of
///    each transaction's hash, in block order (already hash-ascending).
/// 2. Every transaction's `validity_range` is well-formed against and
///    contains the block's `validity_anchor` (the parent QC's
///    weighted timestamp).
impl Verify<&TransactionRootContext<'_>> for TransactionRoot {
    type Augment = ();
    type Error = TxRootVerifyError;

    fn verify(&self, ctx: &TransactionRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.transactions).as_ref();
        if computed != *self {
            return Err(TxRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        for tx in ctx.transactions {
            let range = tx.validity_range();
            if !range.is_well_formed(ctx.validity_anchor) || !range.contains(ctx.validity_anchor) {
                return Err(TxRootVerifyError::ValidityWindowExpired {
                    tx_hash: tx.hash(),
                    anchor_ms: ctx.validity_anchor.as_millis(),
                    start_ms: range.start_timestamp_inclusive.as_millis(),
                    end_ms: range.end_timestamp_exclusive.as_millis(),
                });
            }
        }
        Ok(Verified::new_unchecked(*self))
    }
}

// ─── VerifiedProvisionTxRoots ───────────────────────────────────────────────

/// Inputs the provision-tx-roots verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionTxRootsContext<'a> {
    /// Topology snapshot anchoring shard routing — drives which target
    /// shards each cross-shard tx contributes to.
    pub topology: &'a TopologySnapshot,
    /// The block's transactions in block order.
    pub transactions: &'a [Arc<RoutableTransaction>],
}

/// Provision-tx roots map type as carried by [`BlockHeader`](crate::BlockHeader).
///
/// Type alias rather than a separate newtype because the bound `MAX_REMOTE_SHARDS_PER_WAVE`
/// is invariant across every site that touches this map.
pub type ProvisionTxRootsMap =
    BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>;

/// Failure modes of provision-tx-roots verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionTxRootsVerifyError {
    /// The per-target-shard map computed from the supplied transactions
    /// does not match the claimed map.
    #[error("computed provision_tx_roots {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed per-target-shard provision-tx roots.
        expected: BTreeMap<ShardGroupId, ProvisionTxRoot>,
        /// Map computed from the supplied transactions.
        computed: BTreeMap<ShardGroupId, ProvisionTxRoot>,
    },
}

impl Verified<ProvisionTxRootsMap> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the
    /// header's claimed map is empty (no cross-shard targets) or an
    /// earlier verifier run already accepted `map`.
    #[must_use]
    pub const fn from_pipeline_attestation(map: ProvisionTxRootsMap) -> Self {
        Self::new_unchecked(map)
    }

    /// Compute the per-target-shard provision-tx roots from
    /// `transactions` under `topology`. Verified by construction.
    ///
    /// For each cross-shard tx, the tx hash lands in the bucket of every
    /// remote shard it touches. Each bucket is merkle-committed in
    /// already-hash-ascending block order so the target shard can verify
    /// a received `Provisions` carries the full set it was meant to
    /// receive. Only emits an entry for targets with ≥1 tx — empty for
    /// blocks with no cross-shard txs.
    ///
    /// # Panics
    ///
    /// Panics if the computed map exceeds [`MAX_REMOTE_SHARDS_PER_WAVE`]
    /// entries — that would require a single block to fan out across
    /// more shards than the consensus configuration allows.
    #[must_use]
    pub fn compute(topology: &TopologySnapshot, transactions: &[Arc<RoutableTransaction>]) -> Self {
        let local_shard = topology.local_shard();
        let mut per_target: BTreeMap<ShardGroupId, Vec<Hash>> = BTreeMap::new();

        for tx in transactions {
            if topology.is_single_shard_transaction(tx) {
                continue;
            }
            for shard in topology.all_shards_for_transaction(tx) {
                if shard == local_shard {
                    continue;
                }
                per_target
                    .entry(shard)
                    .or_default()
                    .push(tx.hash().into_raw());
            }
        }

        let map: BTreeMap<ShardGroupId, ProvisionTxRoot> = per_target
            .into_iter()
            .map(|(shard, hashes)| {
                (
                    shard,
                    ProvisionTxRoot::from_raw(compute_merkle_root(&hashes)),
                )
            })
            .collect();
        Self::new_unchecked(map.into())
    }
}

/// Construction asserts: the wrapped map equals
/// [`Verified::<ProvisionTxRootsMap>::compute`] of the block's
/// transactions under the supplied topology.
impl Verify<&ProvisionTxRootsContext<'_>> for ProvisionTxRootsMap {
    type Augment = ();
    type Error = ProvisionTxRootsVerifyError;

    fn verify(&self, ctx: &ProvisionTxRootsContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = Verified::<ProvisionTxRootsMap>::compute(ctx.topology, ctx.transactions);
        if computed.as_ref() != self {
            let expected: BTreeMap<_, _> = self.iter().map(|(k, v)| (*k, *v)).collect();
            let computed: BTreeMap<_, _> =
                computed.as_ref().iter().map(|(k, v)| (*k, *v)).collect();
            return Err(ProvisionTxRootsVerifyError::Mismatch { expected, computed });
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── VerifiedBeaconWitnessRoot ──────────────────────────────────────────────

/// Inputs the [`BeaconWitnessRoot`] verifier reads against.
///
/// Re-derives the block's new witness payloads from the three canonical
/// sources (`receipts`, the missed-round walk over
/// `(parent_round, round)`, and `ready_signals`), appends them to
/// `parent_witness_leaves`, and checks the resulting `(root, count)`
/// matches the header's claim.
#[derive(Debug)]
pub struct BeaconWitnessRootContext<'a> {
    /// Header's claimed leaf count after appending this block's new
    /// witness payloads. Verification checks the computed count matches.
    pub expected_leaf_count: BeaconWitnessLeafCount,
    /// Accumulator leaves at the parent block's tip — the prefix the
    /// new payloads append onto.
    pub parent_witness_leaves: Vec<Hash>,
    /// Round of the parent block — anchors the missed-proposal walk.
    pub parent_round: Round,
    /// Height of the block being verified.
    pub height: BlockHeight,
    /// Round at which the block was proposed.
    pub round: Round,
    /// Receipts that contribute leaves via `beacon_witness_events`.
    pub receipts: &'a [StoredReceipt],
    /// Ready signals carried on the block's manifest.
    pub ready_signals: &'a [ReadySignal],
    /// Topology snapshot anchoring the proposer-rotation rule the
    /// missed-round walk reads.
    pub topology: &'a TopologySnapshot,
}

/// Failure modes of [`BeaconWitnessRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum BeaconWitnessRootVerifyError {
    /// Either the recomputed merkle root or the leaf count diverges
    /// from the header's claim — either one fails the block.
    #[error(
        "computed beacon-witness root {computed_root:?}/count {computed_count} ≠ \
         claimed {expected_root:?}/count {expected_count}"
    )]
    Mismatch {
        /// Header's claimed beacon-witness root.
        expected_root: BeaconWitnessRoot,
        /// Root computed by re-deriving leaves and merkle-ing.
        computed_root: BeaconWitnessRoot,
        /// Header's claimed leaf count.
        expected_count: u64,
        /// Count computed from the recomputed leaves.
        computed_count: u64,
    },
}

/// Walk the rounds `(parent_round, committed_round)` and emit one
/// `MissedProposal` witness per skipped round, identifying the expected
/// proposer via [`TopologySnapshot::proposer_for`].
///
/// Returns `Vec::new()` when `committed_round <= parent_round + 1` (the
/// successful proposer took the first attempt at this height — nothing
/// to report). Used by both the proposer-side derivation and the
/// post-execution verifier so a future change to leader rotation moves
/// both sides simultaneously.
#[must_use]
pub fn missed_proposals_since_prev_commit(
    height: BlockHeight,
    parent_round: Round,
    committed_round: Round,
    topology: &TopologySnapshot,
) -> Vec<ShardWitnessPayload> {
    let mut missed = Vec::new();
    let mut round = parent_round.next();
    while round < committed_round {
        let proposer_id = topology.proposer_for(height, round);
        missed.push(ShardWitnessPayload::MissedProposal {
            proposer_id,
            height,
            round,
        });
        round = round.next();
    }
    missed
}

/// Canonical leaf-derivation rule used by both proposer and verifier.
///
/// Ordering (locked — every honest validator must produce the same
/// `Vec<ShardWitnessPayload>` given the same inputs):
///
/// 1. Receipt-emitted witnesses in receipt-iteration order; within a
///    receipt, in the order the engine recorded them.
/// 2. `MissedProposal` witnesses in ascending round order (the helper
///    already sorts; pass its output verbatim).
/// 3. `Ready` witnesses in ascending `validator_id` order.
#[must_use]
pub fn derive_leaves(
    receipts: &[StoredReceipt],
    missed: &[ShardWitnessPayload],
    ready_signals: &[ReadySignal],
) -> Vec<ShardWitnessPayload> {
    let mut out = Vec::new();
    for receipt in receipts {
        if let ConsensusReceipt::Succeeded {
            beacon_witness_events,
            ..
        } = receipt.consensus.as_ref()
        {
            for event in beacon_witness_events {
                out.push(ShardWitnessPayload::from(event.clone()));
            }
        }
    }
    out.extend_from_slice(missed);
    let mut sorted: Vec<&ReadySignal> = ready_signals.iter().collect();
    sorted.sort_by_key(|s| s.validator_id());
    for signal in sorted {
        out.push(ShardWitnessPayload::Ready {
            id: signal.validator_id(),
        });
    }
    out
}

impl Verified<BeaconWitnessRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: an earlier
    /// verifier run already accepted `root` for this block.
    #[must_use]
    pub const fn from_pipeline_attestation(root: BeaconWitnessRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: re-deriving the block's new witness payloads
/// from the receipts + missed-round walk + `ready_signals`, appending to
/// `parent_witness_leaves`, and merkle-ing the result produces a root
/// that equals the header's claimed [`BeaconWitnessRoot`] **and** a
/// leaf count that equals the header's claimed count.
impl Verify<&BeaconWitnessRootContext<'_>> for BeaconWitnessRoot {
    type Augment = ();
    type Error = BeaconWitnessRootVerifyError;

    fn verify(&self, ctx: &BeaconWitnessRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let expected_root = *self;
        let missed = missed_proposals_since_prev_commit(
            ctx.height,
            ctx.parent_round,
            ctx.round,
            ctx.topology,
        );
        let new_leaves = derive_leaves(ctx.receipts, &missed, ctx.ready_signals);

        let mut leaves = ctx.parent_witness_leaves.clone();
        leaves.reserve(new_leaves.len());
        for payload in &new_leaves {
            leaves.push(payload.leaf_hash());
        }
        let computed_root = Self::from_raw(compute_merkle_root(&leaves));
        let computed_count = BeaconWitnessLeafCount::new(leaves.len() as u64);
        if computed_root != expected_root || computed_count != ctx.expected_leaf_count {
            tracing::warn!(
                ?expected_root,
                ?computed_root,
                expected_count = ctx.expected_leaf_count.inner(),
                computed_count = computed_count.inner(),
                height = ctx.height.inner(),
                round = ctx.round.inner(),
                "Beacon-witness root verification FAILED"
            );
            return Err(BeaconWitnessRootVerifyError::Mismatch {
                expected_root,
                computed_root,
                expected_count: ctx.expected_leaf_count.inner(),
                computed_count: computed_count.inner(),
            });
        }
        Ok(Verified::new_unchecked(expected_root))
    }
}
