//! [`Block`] enum (Live/Sealed).
//!
//! [`Block`] is the raw wire form. [`VerifiedBlock`] is the verified
//! typestate produced by composite assembly — it carries the claim that
//! the block's header is verified (and thus its parent QC is verified)
//! and every internal commitment root the block declares has been
//! checked against the inline data.

use std::ops::Deref;
use std::sync::Arc;

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, BoundedVec, FinalizedWave, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISIONS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProvisionHash, Provisions, RoutableTransaction,
    ShardGroupId, StateRoot, TxHash, ValidatorId, VerifiedBeaconWitnessRoot, VerifiedBlockHeader,
    VerifiedCertificateRoot, VerifiedLocalReceiptRoot, VerifiedProvisionTxRoots,
    VerifiedProvisionsRoot, VerifiedTransactionRoot,
};

/// Shared transaction list — wrapped in `Arc` so root-verification actions
/// can hold their own owner without deep-cloning the per-tx `Arc` array.
pub type SharedTransactions = Arc<BoundedVec<Arc<RoutableTransaction>, MAX_TXS_PER_BLOCK>>;

/// Shared certificate list — same rationale as [`SharedTransactions`].
pub type SharedCertificates = Arc<BoundedVec<Arc<FinalizedWave>, MAX_FINALIZED_TX_PER_BLOCK>>;

/// Shared provision list — same rationale as [`SharedTransactions`].
pub type SharedProvisions = Arc<BoundedVec<Arc<Provisions>, MAX_PROVISIONS_PER_BLOCK>>;

/// Shared provision-hash list — carried on `Block::Sealed` so that
/// sync-serving glue can re-attach provision bodies even after the
/// payload has been dropped. Same `Arc` rationale as [`SharedTransactions`].
pub type SharedProvisionHashes = Arc<BoundedVec<ProvisionHash, MAX_PROVISIONS_PER_BLOCK>>;

/// Complete block with header and transaction data.
///
/// Transactions are stored in a single flat list, sorted by hash for deterministic ordering.
///
/// Blocks have two variants reflecting their temporal lifecycle:
/// - **`Live`**: within the cross-shard execution window. Carries the
///   provisions needed to execute cross-shard waves locally.
/// - **`Sealed`**: past the execution window (at least `WAVE_TIMEOUT` of
///   wall-clock behind the local committed tip). Waves are finalized from
///   certs + receipts alone, so provisions are no longer needed and are
///   dropped from memory. The on-disk / storage shape is always `Sealed`.
///
/// The header's `provision_root` commits to the original provision set, so
/// `Sealed` is self-consistent — a `Live` block matches its `Sealed` form
/// modulo the provision payload.
#[derive(Debug, Clone, BasicSbor)]
pub enum Block {
    /// Block within its cross-shard execution window — carries provisions.
    #[sbor(discriminator(BLOCK_VARIANT_LIVE))]
    Live {
        /// Block header (contains all merkle roots).
        header: BlockHeader,
        /// Transactions in this block, sorted by hash.
        transactions: SharedTransactions,
        /// Wave certificates finalized in this block.
        certificates: SharedCertificates,
        /// Provisions needed to execute cross-shard waves locally.
        provisions: SharedProvisions,
    },
    /// Block past its execution window — provision bodies dropped, but
    /// the original `ProvisionHash` list is retained so sync-serving glue
    /// can still identify which bodies the block consumed and re-attach
    /// them from the in-memory cache when promoting back to `Live`.
    #[sbor(discriminator(BLOCK_VARIANT_SEALED))]
    Sealed {
        /// Block header (contains all merkle roots).
        header: BlockHeader,
        /// Transactions in this block, sorted by hash.
        transactions: SharedTransactions,
        /// Wave certificates finalized in this block.
        certificates: SharedCertificates,
        /// Content hashes of the provisions the block consumed while
        /// `Live`. Empty iff the block consumed no provisions.
        provision_hashes: SharedProvisionHashes,
    },
}

// Variant discriminator constants — referenced by the `#[sbor(discriminator)]`
// attributes above. Naming them explicitly means future variants can't
// silently renumber existing ones.
const BLOCK_VARIANT_LIVE: u8 = 0;
const BLOCK_VARIANT_SEALED: u8 = 1;

// Manual PartialEq - compare transaction/certificate content, not Arc pointers.
// Provisions are excluded from equality: the header's `provision_root` already
// commits to them, and a Live and Sealed form of the same block should compare
// equal for content purposes.
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        fn tx_lists_equal(a: &[Arc<RoutableTransaction>], b: &[Arc<RoutableTransaction>]) -> bool {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.hash() == y.hash())
        }
        fn cert_lists_equal(a: &[Arc<FinalizedWave>], b: &[Arc<FinalizedWave>]) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| x.as_ref() == y.as_ref())
        }

        self.header() == other.header()
            && tx_lists_equal(self.transactions(), other.transactions())
            && cert_lists_equal(self.certificates(), other.certificates())
    }
}

impl Eq for Block {}

impl Block {
    /// Create an empty genesis block with the given proposer and JMT state.
    ///
    /// Genesis is born `Live` with no provisions — the temporality machinery
    /// activates only once there are cross-shard waves in flight.
    #[must_use]
    pub fn genesis(
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        state_root: StateRoot,
    ) -> Self {
        Self::Live {
            header: BlockHeader::genesis(shard_group_id, proposer, state_root),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    /// Block header — present in both variants.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        match self {
            Self::Live { header, .. } | Self::Sealed { header, .. } => header,
        }
    }

    /// Transactions in the block — present in both variants. Returns a borrow
    /// of the shared handle; callers that need to hand the list to an action
    /// crossing thread boundaries `.clone()` the `Arc` (refcount bump only,
    /// no Vec or per-tx clone).
    #[must_use]
    pub const fn transactions(&self) -> &SharedTransactions {
        match self {
            Self::Live { transactions, .. } | Self::Sealed { transactions, .. } => transactions,
        }
    }

    /// Finalized waves (certificates) in the block — present in both variants.
    /// See [`Self::transactions`] for the sharing rationale.
    #[must_use]
    pub const fn certificates(&self) -> &SharedCertificates {
        match self {
            Self::Live { certificates, .. } | Self::Sealed { certificates, .. } => certificates,
        }
    }

    /// Provisions. Non-empty only for `Live`; `Sealed` blocks have
    /// dropped their provisions because the cross-shard execution window
    /// they served has passed. Use `is_live()` when the variant itself
    /// matters — this accessor flattens both cases to a slice.
    #[must_use]
    pub fn provisions(&self) -> &[Arc<Provisions>] {
        match self {
            Self::Live { provisions, .. } => provisions,
            Self::Sealed { .. } => &[],
        }
    }

    /// Content hashes of the block's provisions, regardless of variant.
    /// Computed inline from `provisions` on `Live`; read from the carried
    /// list on `Sealed`. The two paths agree on the same block by
    /// construction: `into_sealed` derives the `Sealed` list by hashing
    /// the `Live` provisions before dropping the bodies.
    #[must_use]
    pub fn provision_hashes(&self) -> Vec<ProvisionHash> {
        match self {
            Self::Live { provisions, .. } => provisions.iter().map(|p| p.hash()).collect(),
            Self::Sealed {
                provision_hashes, ..
            } => provision_hashes.iter().copied().collect(),
        }
    }

    /// True if this block is still in its `Live` variant.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }

    /// Convert to `Sealed` by dropping provision bodies and retaining only
    /// their hashes. Identity on an already-sealed block. This is the
    /// canonical persisted shape; sync-serving glue re-attaches provision
    /// bodies (via `into_live`) when the requester needs them.
    #[must_use]
    pub fn into_sealed(self) -> Self {
        match self {
            Self::Live {
                header,
                transactions,
                certificates,
                provisions,
            } => {
                let hashes: Vec<ProvisionHash> = provisions.iter().map(|p| p.hash()).collect();
                Self::Sealed {
                    header,
                    transactions,
                    certificates,
                    provision_hashes: Arc::new(hashes.into()),
                }
            }
            sealed @ Self::Sealed { .. } => sealed,
        }
    }

    /// Attach provisions, promoting `Sealed` → `Live`. Used by sync-serving
    /// to upgrade a persisted block when the requester is still inside the
    /// cross-shard execution window.
    ///
    /// # Panics
    ///
    /// Panics if invoked on a `Live` block — that would silently discard
    /// the existing provision set.
    #[must_use]
    pub fn into_live(self, provisions: SharedProvisions) -> Self {
        match self {
            Self::Sealed {
                header,
                transactions,
                certificates,
                ..
            } => Self::Live {
                header,
                transactions,
                certificates,
                provisions,
            },
            Self::Live { .. } => {
                panic!("into_live called on an already-Live block")
            }
        }
    }

    /// Compute hash of this block (hashes the header).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.header().hash()
    }

    /// Get block height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.header().height()
    }

    /// Get total number of transactions.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.transactions().len()
    }

    /// Check if this block contains a specific transaction by hash.
    #[must_use]
    pub fn contains_transaction(&self, tx_hash: &TxHash) -> bool {
        self.transactions().iter().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get all transaction hashes.
    #[must_use]
    pub fn transaction_hashes(&self) -> Vec<TxHash> {
        self.transactions().iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.header().is_genesis()
    }

    /// Get number of wave certificates in this block.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certificates().len()
    }
}

/// Failure modes of [`VerifiedBlock`] composite assembly.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum VerifiedBlockAssembleError {
    /// The supplied [`VerifiedBlockHeader`] does not belong to `block`
    /// (the header's hash differs from `block.hash()`).
    #[error(
        "verified header does not match block: header.hash={header_hash:?} block.hash={block_hash:?}"
    )]
    HeaderMismatch {
        /// Hash carried by the supplied verified header.
        header_hash: BlockHash,
        /// Hash computed from the supplied block.
        block_hash: BlockHash,
    },
}

/// Verified block — header verified plus every internal commitment root
/// checked against the inline data.
///
/// Construction asserts:
/// 1. The header passes [`<BlockHeader as crate::Verify>`](crate::Verify)
///    (which transitively asserts `parent_qc` is verified).
/// 2. The block's contents match its declared commitment roots
///    (`transaction_root`, `certificate_root`, `local_receipt_root`,
///    `provision_root`, `provision_tx_roots`, `beacon_witness_root`).
///    Each per-root check is witnessed by a typed `VerifiedXRoot`
///    value the constructor consumes.
///
/// Construction goes through one of two gates:
///
/// - [`Self::assemble`] — composite path. Takes a [`VerifiedBlockHeader`]
///   for the block plus the typed per-root witnesses, and checks that
///   the header refers to this block.
/// - [`Self::new_unchecked`] — audit point. Used at storage-recovery
///   boundaries and at sites that established the predicate by other
///   means (e.g. the block was produced and verified in-process). Every
///   call site documents the trust source with a `// SAFETY:` comment.
///
/// State-root verification is intentionally not a witness here. Its
/// verified value (`VerifiedStateRoot<P>`) carries a `PreparedCommit`
/// byproduct that the action handler side-channels via
/// `ActionContext::commit_prepared`, so the verified value can't ride
/// in cleanly; the JMT-replay check still gates voting and commit via
/// the parallel pipeline path.
///
/// `#[repr(transparent)]` over [`Block`]; [`Deref<Target = Block>`](Deref)
/// exposes the raw accessors. No mutable access, no `Encode`/`Decode` —
/// the wire decode path always produces an unverified [`Block`].
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBlock(Block);

impl VerifiedBlock {
    /// Composite assembly. Pairs `block` with a [`VerifiedBlockHeader`]
    /// after confirming the header's content matches the block, and
    /// consumes a typed witness for each per-root verification.
    ///
    /// The witnesses are taken by value: each `VerifiedXRoot` can only
    /// have been produced by its `Verify` impl (the only constructor
    /// outside `new_unchecked`), so consuming them at assemble time
    /// makes the predicate structurally unforgeable — no caller can
    /// fabricate a "verified" marker without having run the check.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedBlockAssembleError::HeaderMismatch`] when the
    /// verified header does not match the supplied block.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_arguments,
        clippy::missing_const_for_fn
    )] // typed witnesses are consumed; the moves make the assembly contract explicit
    pub fn assemble(
        block: Block,
        header: VerifiedBlockHeader,
        _tx_root: VerifiedTransactionRoot,
        _certificate_root: VerifiedCertificateRoot,
        _local_receipt_root: VerifiedLocalReceiptRoot,
        _provision_root: VerifiedProvisionsRoot,
        _provision_tx_roots: VerifiedProvisionTxRoots,
        _beacon_witness_root: VerifiedBeaconWitnessRoot,
    ) -> Result<Self, VerifiedBlockAssembleError> {
        let header_hash = header.as_ref().hash();
        let block_hash = block.hash();
        if header_hash != block_hash {
            return Err(VerifiedBlockAssembleError::HeaderMismatch {
                header_hash,
                block_hash,
            });
        }
        Ok(Self(block))
    }

    /// Audit-point constructor. Skips the predicate.
    ///
    /// Permitted use sites: storage-recovery (block was verified before
    /// persistence), genesis, and own-block paths where the local
    /// proposer just built and roots-checked the block in-process. Every
    /// call site carries a `// SAFETY:` comment naming the trust source.
    #[must_use]
    pub const fn new_unchecked(block: Block) -> Self {
        Self(block)
    }

    /// Consume the verified block and return the raw form. Drops the
    /// verified claim.
    #[must_use]
    pub fn into_inner(self) -> Block {
        self.0
    }
}

impl AsRef<Block> for VerifiedBlock {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl Deref for VerifiedBlock {
    type Target = Block;
    fn deref(&self) -> &Block {
        &self.0
    }
}

impl From<VerifiedBlock> for Block {
    fn from(verified: VerifiedBlock) -> Self {
        verified.0
    }
}
