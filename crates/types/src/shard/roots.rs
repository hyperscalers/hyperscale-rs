//! Merkle root computation and verification for the per-block fields in
//! [`BlockHeader`].
//!
//! Each per-root verified typestate carries the claim that the root was
//! computed from the canonical leaf data. Construction goes through one
//! of three gates per type:
//!
//! - `VerifiedXRoot::compute(data) -> Self` — produce the canonical
//!   root from leaf data. Infallible; verified-by-construction.
//! - `VerifiedXRoot::verify(claimed, data) -> Result<Self, XRootVerifyError>`
//!   — recompute from data and compare against `claimed`. On success
//!   the returned wrapper carries `claimed`, which (by the predicate)
//!   equals `compute(data)`. The error reports the computed/claimed
//!   pair on mismatch.
//! - `VerifiedXRoot::new_unchecked(root) -> Self` — audit point.
//!   Reserved for storage-recovery and other call sites where the
//!   predicate was established by other means.
//!
//! The free `compute_x_root` functions remain as thin wrappers around
//! `VerifiedXRoot::compute(...).into_inner()` for proposer / builder
//! sites that only need the raw root value (e.g. populating a
//! [`BlockHeader`](crate::BlockHeader) field for the wire).

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

use thiserror::Error;

use crate::{
    BeaconWitnessRoot, BoundedBTreeMap, CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot,
    MAX_REMOTE_SHARDS_PER_WAVE, ProvisionTxRoot, ProvisionsRoot, RoutableTransaction, ShardGroupId,
    StoredReceipt, TopologySnapshot, TransactionRoot, TxHash, Verify, WeightedTimestamp,
    compute_merkle_root, compute_provision_tx_roots,
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

/// Certificate merkle root whose authenticity against a set of
/// finalized waves is type-level.
///
/// Construction asserts: the wrapped [`CertificateRoot`] equals
/// `compute_merkle_root` of each underlying wave certificate's
/// `receipt_hash`, in block order.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCertificateRoot(CertificateRoot);

impl VerifiedCertificateRoot {
    /// Compute the certificate root from `certificates`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(certificates: &[Arc<FinalizedWave>]) -> Self {
        if certificates.is_empty() {
            return Self(CertificateRoot::ZERO);
        }
        let leaves: Vec<Hash> = certificates
            .iter()
            .map(|fw| fw.certificate().receipt_hash().into_raw())
            .collect();
        Self(CertificateRoot::from_raw(compute_merkle_root(&leaves)))
    }

    /// Audit-point constructor. Skips the predicate.
    ///
    /// Reserved for storage-recovery (root was verified before
    /// persistence). Every call site carries a `// SAFETY:` comment
    /// naming the trust source.
    #[must_use]
    pub const fn new_unchecked(root: CertificateRoot) -> Self {
        Self(root)
    }

    /// Consume and return the raw root, dropping the verified claim.
    #[must_use]
    pub const fn into_inner(self) -> CertificateRoot {
        self.0
    }
}

impl AsRef<CertificateRoot> for VerifiedCertificateRoot {
    fn as_ref(&self) -> &CertificateRoot {
        &self.0
    }
}

impl Deref for VerifiedCertificateRoot {
    type Target = CertificateRoot;
    fn deref(&self) -> &CertificateRoot {
        &self.0
    }
}

impl Verify<&CertificateRootContext<'_>> for CertificateRoot {
    type Verified = VerifiedCertificateRoot;
    type Error = CertRootVerifyError;

    fn verify(&self, ctx: &CertificateRootContext<'_>) -> Result<Self::Verified, Self::Error> {
        let computed = VerifiedCertificateRoot::compute(ctx.certificates).0;
        if computed != *self {
            return Err(CertRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(VerifiedCertificateRoot(*self))
    }
}

/// Compute the certificate merkle root for a block's finalized waves.
///
/// Each underlying wave certificate's `receipt_hash` becomes a leaf.
/// Returns `Hash::ZERO` if there are no certificates. Thin wrapper around
/// [`VerifiedCertificateRoot::compute`] for sites that only need the raw
/// root value.
#[must_use]
pub fn compute_certificate_root(certificates: &[Arc<FinalizedWave>]) -> CertificateRoot {
    VerifiedCertificateRoot::compute(certificates).into_inner()
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

/// Local-receipt merkle root whose authenticity against a receipt list
/// is type-level.
///
/// Construction asserts: the wrapped [`LocalReceiptRoot`] equals
/// `compute_merkle_root` of each receipt's `local_receipt_hash`, in
/// block order.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedLocalReceiptRoot(LocalReceiptRoot);

impl VerifiedLocalReceiptRoot {
    /// Compute the local-receipt root from `receipts`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(receipts: &[StoredReceipt]) -> Self {
        if receipts.is_empty() {
            return Self(LocalReceiptRoot::ZERO);
        }
        let leaves: Vec<Hash> = receipts
            .iter()
            .map(|r| r.consensus.local_receipt_hash())
            .collect();
        Self(LocalReceiptRoot::from_raw(compute_merkle_root(&leaves)))
    }

    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(root: LocalReceiptRoot) -> Self {
        Self(root)
    }

    /// Consume and return the raw root, dropping the verified claim.
    #[must_use]
    pub const fn into_inner(self) -> LocalReceiptRoot {
        self.0
    }
}

impl AsRef<LocalReceiptRoot> for VerifiedLocalReceiptRoot {
    fn as_ref(&self) -> &LocalReceiptRoot {
        &self.0
    }
}

impl Deref for VerifiedLocalReceiptRoot {
    type Target = LocalReceiptRoot;
    fn deref(&self) -> &LocalReceiptRoot {
        &self.0
    }
}

impl Verify<&LocalReceiptRootContext<'_>> for LocalReceiptRoot {
    type Verified = VerifiedLocalReceiptRoot;
    type Error = LocalReceiptRootVerifyError;

    fn verify(&self, ctx: &LocalReceiptRootContext<'_>) -> Result<Self::Verified, Self::Error> {
        let computed = VerifiedLocalReceiptRoot::compute(ctx.receipts).0;
        if computed != *self {
            return Err(LocalReceiptRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(VerifiedLocalReceiptRoot(*self))
    }
}

/// Compute the local-receipt merkle root for a block's receipts.
///
/// Each receipt's [`ConsensusReceipt::local_receipt_hash`](crate::ConsensusReceipt::local_receipt_hash)
/// (outcome tag + `event_root` + `database_updates_hash`) becomes a leaf,
/// in canonical block order — the same order
/// [`FinalizedWave::validate_receipts_against_ec`](crate::FinalizedWave::validate_receipts_against_ec)
/// walks them, and the order every construction site (`finalize_wave`,
/// `FinalizedWave::reconstruct`) builds them.
///
/// Returns `Hash::ZERO` if there are no receipts. Thin wrapper around
/// [`VerifiedLocalReceiptRoot::compute`].
#[must_use]
pub fn compute_local_receipt_root(receipts: &[StoredReceipt]) -> LocalReceiptRoot {
    VerifiedLocalReceiptRoot::compute(receipts).into_inner()
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

/// Provisions merkle root whose authenticity against a list of batch
/// hashes is type-level.
///
/// Construction asserts: the wrapped [`ProvisionsRoot`] equals
/// `compute_merkle_root` of the batch hashes in block order.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedProvisionsRoot(ProvisionsRoot);

impl VerifiedProvisionsRoot {
    /// Compute the provisions root from `batch_hashes`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(batch_hashes: &[Hash]) -> Self {
        if batch_hashes.is_empty() {
            return Self(ProvisionsRoot::ZERO);
        }
        Self(ProvisionsRoot::from_raw(compute_merkle_root(batch_hashes)))
    }

    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(root: ProvisionsRoot) -> Self {
        Self(root)
    }

    /// Consume and return the raw root, dropping the verified claim.
    #[must_use]
    pub const fn into_inner(self) -> ProvisionsRoot {
        self.0
    }
}

impl AsRef<ProvisionsRoot> for VerifiedProvisionsRoot {
    fn as_ref(&self) -> &ProvisionsRoot {
        &self.0
    }
}

impl Deref for VerifiedProvisionsRoot {
    type Target = ProvisionsRoot;
    fn deref(&self) -> &ProvisionsRoot {
        &self.0
    }
}

impl Verify<&ProvisionsRootContext<'_>> for ProvisionsRoot {
    type Verified = VerifiedProvisionsRoot;
    type Error = ProvisionRootVerifyError;

    fn verify(&self, ctx: &ProvisionsRootContext<'_>) -> Result<Self::Verified, Self::Error> {
        let computed = VerifiedProvisionsRoot::compute(ctx.batch_hashes).0;
        if computed != *self {
            return Err(ProvisionRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(VerifiedProvisionsRoot(*self))
    }
}

/// Compute the provisions merkle root for a block.
///
/// Each provisions' hash becomes a leaf. Returns `Hash::ZERO` if empty.
/// Thin wrapper around [`VerifiedProvisionsRoot::compute`].
#[must_use]
pub fn compute_provision_root(batch_hashes: &[Hash]) -> ProvisionsRoot {
    VerifiedProvisionsRoot::compute(batch_hashes).into_inner()
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

/// Transaction merkle root paired with type-level proof that every
/// included transaction is in-window for this block.
///
/// Construction asserts both:
///
/// 1. The wrapped [`TransactionRoot`] equals `compute_merkle_root` of
///    each transaction's hash, in block order (already hash-ascending).
/// 2. Every transaction's `validity_range` is well-formed against and
///    contains the block's `validity_anchor` (the parent QC's
///    weighted timestamp).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTransactionRoot(TransactionRoot);

impl VerifiedTransactionRoot {
    /// Compute the transaction root from `transactions`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(transactions: &[Arc<RoutableTransaction>]) -> Self {
        if transactions.is_empty() {
            return Self(TransactionRoot::ZERO);
        }
        let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.hash().into_raw()).collect();
        // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
        // merkle inclusion proofs can be generated and verified for any leaf.
        Self(TransactionRoot::from_raw(compute_merkle_root(&leaves)))
    }

    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(root: TransactionRoot) -> Self {
        Self(root)
    }

    /// Consume and return the raw root, dropping the verified claim.
    #[must_use]
    pub const fn into_inner(self) -> TransactionRoot {
        self.0
    }
}

impl AsRef<TransactionRoot> for VerifiedTransactionRoot {
    fn as_ref(&self) -> &TransactionRoot {
        &self.0
    }
}

impl Deref for VerifiedTransactionRoot {
    type Target = TransactionRoot;
    fn deref(&self) -> &TransactionRoot {
        &self.0
    }
}

impl Verify<&TransactionRootContext<'_>> for TransactionRoot {
    type Verified = VerifiedTransactionRoot;
    type Error = TxRootVerifyError;

    fn verify(&self, ctx: &TransactionRootContext<'_>) -> Result<Self::Verified, Self::Error> {
        let computed = VerifiedTransactionRoot::compute(ctx.transactions).0;
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
        Ok(VerifiedTransactionRoot(*self))
    }
}

/// Compute the transaction merkle root for a block.
///
/// Each transaction's hash becomes a leaf directly. Returns `Hash::ZERO`
/// if empty. Thin wrapper around [`VerifiedTransactionRoot::compute`].
#[must_use]
pub fn compute_transaction_root(transactions: &[Arc<RoutableTransaction>]) -> TransactionRoot {
    VerifiedTransactionRoot::compute(transactions).into_inner()
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

/// Per-target-shard provision-tx merkle root map whose authenticity
/// against a block's transactions is type-level.
///
/// Construction asserts: the wrapped map equals
/// [`compute_provision_tx_roots`](crate::compute_provision_tx_roots) of
/// the block's transactions under the supplied topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvisionTxRoots(ProvisionTxRootsMap);

impl VerifiedProvisionTxRoots {
    /// Compute the per-target-shard provision-tx roots from
    /// `transactions` under `topology`. Verified by construction.
    ///
    /// # Panics
    ///
    /// Panics if the computed map exceeds [`MAX_REMOTE_SHARDS_PER_WAVE`]
    /// entries — that would require a single block to fan out across
    /// more shards than the consensus configuration allows.
    #[must_use]
    pub fn compute(topology: &TopologySnapshot, transactions: &[Arc<RoutableTransaction>]) -> Self {
        Self(compute_provision_tx_roots(topology, transactions).into())
    }

    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(roots: ProvisionTxRootsMap) -> Self {
        Self(roots)
    }

    /// Consume and return the raw bounded map, dropping the verified claim.
    #[must_use]
    pub fn into_inner(self) -> ProvisionTxRootsMap {
        self.0
    }
}

impl AsRef<ProvisionTxRootsMap> for VerifiedProvisionTxRoots {
    fn as_ref(&self) -> &ProvisionTxRootsMap {
        &self.0
    }
}

impl Deref for VerifiedProvisionTxRoots {
    type Target = ProvisionTxRootsMap;
    fn deref(&self) -> &ProvisionTxRootsMap {
        &self.0
    }
}

impl Verify<&ProvisionTxRootsContext<'_>> for ProvisionTxRootsMap {
    type Verified = VerifiedProvisionTxRoots;
    type Error = ProvisionTxRootsVerifyError;

    fn verify(&self, ctx: &ProvisionTxRootsContext<'_>) -> Result<Self::Verified, Self::Error> {
        let computed = compute_provision_tx_roots(ctx.topology, ctx.transactions);
        if computed != self.0 {
            let expected: BTreeMap<_, _> = self.iter().map(|(k, v)| (*k, *v)).collect();
            return Err(ProvisionTxRootsVerifyError::Mismatch { expected, computed });
        }
        Ok(VerifiedProvisionTxRoots(self.clone()))
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

/// Verified beacon-witness root whose authenticity against the block's
/// witness inputs is type-level.
///
/// Construction asserts: re-deriving the block's new witness payloads
/// from `receipts`, the missed-round walk, and `ready_signals` (in the
/// canonical leaf-derivation order), appending their leaf hashes to
/// `parent_witness_leaves`, and merkle-ing the result produces a root
/// and leaf count equal to the wrapped values.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedBeaconWitnessRoot(BeaconWitnessRoot);

impl VerifiedBeaconWitnessRoot {
    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(root: BeaconWitnessRoot) -> Self {
        Self(root)
    }

    /// Consume and return the raw root, dropping the verified claim.
    #[must_use]
    pub const fn into_inner(self) -> BeaconWitnessRoot {
        self.0
    }
}

impl AsRef<BeaconWitnessRoot> for VerifiedBeaconWitnessRoot {
    fn as_ref(&self) -> &BeaconWitnessRoot {
        &self.0
    }
}

impl Deref for VerifiedBeaconWitnessRoot {
    type Target = BeaconWitnessRoot;
    fn deref(&self) -> &BeaconWitnessRoot {
        &self.0
    }
}
