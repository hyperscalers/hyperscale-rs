//! [`BodyRoot`]: the header's one commitment to a block's body sections.
//!
//! Every section keeps its own root, computed the way that root always
//! is; the header carries only their combination. No reader proves
//! anything against one section's root alone — each recomputes the
//! sections from a block it holds — so a single hash over all of them
//! binds the body to the header as tightly as a field per section would.

use std::sync::Arc;

use thiserror::Error;

use crate::{
    AbandonmentRoot, Block, BodyRoot, CertificateRoot, EngagementRoot, Hash, LeafRoot,
    LocalReceiptRoot, ProvisionsRoot, SetRoot, StateClaimsRoot, StoredReceipt, TickManifestRoot,
    Transaction, TransactionRoot, TxHash, Verifiable, Verified, Verify, WeightedTimestamp,
};

/// Domain tag separating the body root's preimage from every other
/// preimage the codebase hashes.
const BODY_ROOT_TAG: &[u8] = b"hyperscale.body_root.v1";

/// The root of each body section, in the order the body root hashes
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionRoots {
    /// Padded merkle root over the transactions' hashes.
    pub transactions: TransactionRoot,
    /// Root over the finalizations' receipt hashes.
    pub certificates: CertificateRoot,
    /// Root over the finalizations' local receipts.
    pub local_receipts: LocalReceiptRoot,
    /// Root over the provision batches' hashes.
    pub provisions: ProvisionsRoot,
    /// Root over the abandonment records.
    pub abandonment: AbandonmentRoot,
    /// Root over the state claims.
    pub state_claims: StateClaimsRoot,
    /// Set root over what the provisions name.
    pub engagements: EngagementRoot,
    /// Root over the tick manifest's lines.
    pub tick_manifest: TickManifestRoot,
}

impl SectionRoots {
    /// Every section empty.
    pub const EMPTY: Self = Self {
        transactions: TransactionRoot::ZERO,
        certificates: CertificateRoot::ZERO,
        local_receipts: LocalReceiptRoot::ZERO,
        provisions: ProvisionsRoot::ZERO,
        abandonment: AbandonmentRoot::ZERO,
        state_claims: StateClaimsRoot::ZERO,
        engagements: EngagementRoot::ZERO,
        tick_manifest: TickManifestRoot::ZERO,
    };

    /// The sections of `block`, in either form: a sealed block keeps the
    /// provision hashes and the engagements its dropped bodies named.
    #[must_use]
    pub fn of(block: &Block) -> Self {
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        let provision_hashes: Vec<Hash> = block
            .provision_hashes()
            .iter()
            .map(|hash| hash.into_raw())
            .collect();
        Self {
            transactions: Verified::<TransactionRoot>::compute(block.transactions()).into_inner(),
            certificates: CertificateRoot::over(block.certificates()),
            local_receipts: LocalReceiptRoot::over(&receipts),
            provisions: ProvisionsRoot::over(&provision_hashes),
            abandonment: AbandonmentRoot::over(block.abandonment_records()),
            state_claims: StateClaimsRoot::over(block.state_claims()),
            engagements: EngagementRoot::over(block.engagements().iter()),
            tick_manifest: TickManifestRoot::over(block.tick_manifest()),
        }
    }

    /// The body root: zero for an empty body, as every section's own
    /// root is for an empty section, and otherwise the tagged hash of the
    /// eight roots in field order.
    #[must_use]
    pub fn root(&self) -> BodyRoot {
        if *self == Self::EMPTY {
            return BodyRoot::ZERO;
        }
        BodyRoot::from_raw(Hash::from_parts(&[
            BODY_ROOT_TAG,
            self.transactions.as_bytes(),
            self.certificates.as_bytes(),
            self.local_receipts.as_bytes(),
            self.provisions.as_bytes(),
            self.abandonment.as_bytes(),
            self.state_claims.as_bytes(),
            self.engagements.as_bytes(),
            self.tick_manifest.as_bytes(),
        ]))
    }
}

/// Inputs the [`BodyRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct BodyRootContext<'a> {
    /// The block whose sections the root must commit.
    pub block: &'a Block,
    /// The parent QC's weighted timestamp, which every transaction's
    /// validity range must enclose. An honest cluster never sees a
    /// window mismatch here, because the proposer applied the same check
    /// when it selected the transactions.
    pub validity_anchor: WeightedTimestamp,
}

/// Failure modes of [`BodyRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum BodyRootVerifyError {
    /// The block's sections combine to a root other than the claimed one.
    #[error("computed body root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: BodyRoot,
        /// Root the block's sections combine to.
        computed: BodyRoot,
    },
    /// A transaction's validity range was malformed or did not contain
    /// the parent QC's weighted timestamp.
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

/// Construction asserts both:
///
/// 1. The wrapped [`BodyRoot`] is [`SectionRoots::root`] of the block's
///    sections.
/// 2. Every transaction's validity range is well-formed against and
///    contains the block's validity anchor.
impl Verify<&BodyRootContext<'_>> for BodyRoot {
    type Error = BodyRootVerifyError;

    fn verify(&self, ctx: &BodyRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = SectionRoots::of(ctx.block).root();
        if computed != *self {
            return Err(BodyRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        check_validity_windows(ctx.block.transactions(), ctx.validity_anchor)?;
        Ok(Verified::new_unchecked(*self))
    }
}

fn check_validity_windows(
    transactions: &[Arc<Verifiable<Transaction>>],
    anchor: WeightedTimestamp,
) -> Result<(), BodyRootVerifyError> {
    for tx in transactions {
        let range = tx.validity_range();
        if !range.is_well_formed(anchor) || !range.contains(anchor) {
            return Err(BodyRootVerifyError::ValidityWindowExpired {
                tx_hash: tx.hash(),
                anchor_ms: anchor.as_millis(),
                start_ms: range.start_timestamp_inclusive.as_millis(),
                end_ms: range.end_timestamp_exclusive.as_millis(),
            });
        }
    }
    Ok(())
}
