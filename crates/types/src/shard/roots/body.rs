//! [`BodyRoot`]: the header's one commitment to a block's body sections.
//!
//! Every section keeps its own root over its own content; the header
//! carries only their combination. No reader proves anything against one
//! section's root alone — each recomputes the sections from a block it
//! holds — so a single hash over all of them binds the body to the header
//! as tightly as a field per section would.

use std::sync::Arc;

use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    AbandonmentRoot, Block, BodyRoot, CertificateRoot, EngagementRoot, Hash, LeafRoot,
    LocalReceiptRoot, ProvisionsRoot, SetRoot, StateClaimsRoot, StoredReceipt, TermsRoot,
    TickManifestRoot, Transaction, TransactionRoot, TxHash, Verifiable, Verified, Verify,
    WeightedTimestamp,
};

/// Domain tag separating the body root's preimage from every other
/// preimage the codebase hashes.
const BODY_ROOT_TAG: &[u8] = b"hyperscale.body_root.v1";

/// The root of each body section, in the order the body root hashes
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
    /// Root over the terms section's entries.
    pub terms: TermsRoot,
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
        terms: TermsRoot::ZERO,
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
            terms: TermsRoot::over(block.terms()),
        }
    }

    /// The body root: zero for an empty body, as every section's own
    /// root is for an empty section, and otherwise the tagged hash of the
    /// nine roots in field order.
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
            self.terms.as_bytes(),
        ]))
    }
}

/// Why a block's body is not the body its header commits.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum UnboundBody {
    /// A finalization's receipts do not follow from the certificates it
    /// carries. The body root alone cannot catch this: it commits the
    /// receipts the body holds, not their grouping per tick.
    #[error("a finalization's receipts do not follow from its certificates")]
    ReceiptsVsCertificates,
    /// The body's sections combine to a root other than the header's.
    #[error("the body's sections combine to a root other than the header's")]
    BodyRoot,
}

impl UnboundBody {
    /// Metrics label for the failure.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReceiptsVsCertificates => "receipts_vs_ec_mismatch",
            Self::BodyRoot => "body_root_mismatch",
        }
    }
}

impl Block {
    /// Hold the body this block carries to the one its header commits.
    ///
    /// A QC signs the header alone, so a certified header says nothing
    /// about a body that arrived beside it until this check binds the two.
    ///
    /// # Errors
    ///
    /// The first [`UnboundBody`] reason the body fails on.
    pub fn check_body_bound(&self) -> Result<(), UnboundBody> {
        if self
            .certificates()
            .iter()
            .any(|fw| fw.validate_against_certificates().is_err())
        {
            return Err(UnboundBody::ReceiptsVsCertificates);
        }
        if SectionRoots::of(self).root() != self.header().body_root() {
            return Err(UnboundBody::BodyRoot);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;

    use super::*;
    use crate::test_utils::{make_live_block, rebound, stating_half_on};
    use crate::{
        BlockHeight, ConsensusReceipt, ExecutionOutcome, Finalization, GlobalReceiptHash, Role,
        ShardId, StateWrites, TxOutcome, ValidatorId, receipt_hash_of,
    };

    /// A body carrying a stating half is bound to its header with the
    /// effects receipt of each yes it states, and the local receipts
    /// root commits to it: a half missing the receipt is unbound. Sealed
    /// into storage, where the attestation keeps the yes receipt inline
    /// and the store keeps the refusal receipt beside it, the block
    /// rebuilds to the same body root.
    #[test]
    fn a_sealed_stating_block_keeps_its_body_root() {
        let unhashed = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: StateWrites::default(),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        };
        let effects = receipt_hash_of(&unhashed, true).expect("a projected success");
        let yes = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"yes")),
            ExecutionOutcome::Succeeded {
                receipt_hash: effects,
            },
        )
        .charging(3)
        .awaiting([ShardId::leaf(1, 1)])
        .as_role(Role::Core);
        let refusal = GlobalReceiptHash::from_raw(Hash::from_bytes(b"refusal"));
        let no = TxOutcome::with_refusal(
            TxHash::from(Hash::from_bytes(b"no")),
            ExecutionOutcome::Failed,
            refusal,
        )
        .charging(4)
        .awaiting([ShardId::leaf(1, 1)])
        .as_role(Role::Core);
        let yes_receipt = StoredReceipt::new(
            yes.tx_hash(),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: effects,
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        );
        let refusal_receipt = StoredReceipt::new(
            no.tx_hash(),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: refusal,
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        );
        let carrying = |receipts: Vec<StoredReceipt>| {
            let half = stating_half_on(
                ShardId::ROOT,
                BlockHeight::new(1),
                vec![yes.clone(), no.clone()],
                receipts,
            );
            rebound(make_live_block(
                ShardId::ROOT,
                BlockHeight::new(2),
                0,
                ValidatorId::new(0),
                Vec::new(),
                vec![Verifiable::from(half)],
            ))
        };
        let block = carrying(vec![yes_receipt, refusal_receipt.clone()]);
        assert_eq!(block.check_body_bound(), Ok(()));
        assert_eq!(
            carrying(vec![refusal_receipt.clone()]).check_body_bound(),
            Err(UnboundBody::ReceiptsVsCertificates),
            "a yes without its receipt",
        );

        let half = block.certificates()[0].as_unverified();
        let stored = half.stored_receipts();
        assert_eq!(stored, vec![refusal_receipt]);
        let rebuilt = Finalization::reconstruct(half.attestation(), |tx_hash, hash| {
            stored
                .iter()
                .find(|receipt| {
                    receipt.tx_hash == *tx_hash && receipt.consensus.receipt_hash() == *hash
                })
                .map(|receipt| Arc::clone(&receipt.consensus))
        })
        .expect("the store holds what the half settles");
        assert_eq!(&rebuilt, half);
        let resealed = rebound(make_live_block(
            ShardId::ROOT,
            BlockHeight::new(2),
            0,
            ValidatorId::new(0),
            Vec::new(),
            vec![Verifiable::from(rebuilt)],
        ));
        assert_eq!(
            SectionRoots::of(&resealed).root(),
            block.header().body_root(),
        );
    }
}
