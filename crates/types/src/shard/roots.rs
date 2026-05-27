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
//! - `Verified::<XRoot>::new_unchecked(root)` — audit point. Reserved
//!   for storage-recovery and other call sites where the predicate was
//!   established by other means.

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use crate::{
    BeaconWitnessRoot, BoundedBTreeMap, CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot,
    MAX_REMOTE_SHARDS_PER_WAVE, ProvisionTxRoot, ProvisionsRoot, RoutableTransaction, ShardGroupId,
    StoredReceipt, TopologySnapshot, TransactionRoot, TxHash, Verified, Verify, WeightedTimestamp,
    compute_merkle_root,
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
//
// The `Verify` impl and `BeaconWitnessRootContext` live in the
// `hyperscale-shard` crate alongside the leaf-derivation helpers; only
// the verified type and error live here so they can ride in
// protocol-event payloads from `hyperscale-core`.

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
