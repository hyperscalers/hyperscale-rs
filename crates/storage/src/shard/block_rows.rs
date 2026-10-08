//! A committed block as rows, and the one reconstruction both backends
//! read it back through.
//!
//! A committed block is never stored whole. Its height keys a
//! [`BlockMetadata`] row — header, manifest, engagements and QC — and
//! the manifest names the rest by hash: each transaction, each
//! finalization's attestation, and through the attestation's local
//! certificate each receipt it settled. Provision bodies are not part of
//! the block's rows at all; the stored shape is [`Block::Sealed`], which
//! keeps only their hashes.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_types::{
    Block, BlockHeight, BlockMetadata, CertifiedBlock, ConsensusReceipt, Finalization,
    FinalizationHash, GlobalReceiptHash, QuorumCertificate, Transaction, TxHash, Verifiable,
    Verified,
};

use crate::BlockForSync;

/// The rows a backend keeps a committed block as, each looked up the way
/// the backend keys it.
pub trait BlockRows {
    /// The metadata row at `height`.
    fn block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata>;

    /// The transactions `hashes` name, in their order, skipping any the
    /// backend does not hold.
    fn transactions(&self, hashes: &[TxHash]) -> Vec<Transaction>;

    /// The finalization attestations `ids` name, in their order, skipping
    /// any the backend does not hold.
    fn attestations(&self, ids: &[FinalizationHash]) -> Vec<Finalization>;

    /// The consensus receipt `tx_hash` settled under `receipt_hash`.
    fn consensus_receipt(
        &self,
        tx_hash: &TxHash,
        receipt_hash: &GlobalReceiptHash,
    ) -> Option<Arc<ConsensusReceipt>>;
}

/// Why a height did not rebuild into a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unbuilt {
    /// No metadata row at the height: no block is stored there.
    Absent,
    /// The manifest names transactions the backend does not hold.
    MissingTransactions {
        /// Transactions the manifest names.
        expected: usize,
        /// Transactions found.
        found: usize,
    },
    /// The manifest names attestations the backend does not hold.
    MissingAttestations {
        /// Attestations the manifest names.
        expected: usize,
        /// Attestations found.
        found: usize,
    },
    /// An attestation settles a receipt the backend does not hold.
    MissingReceipt,
}

/// A block rebuilt from its rows, in the [`Block::Sealed`] shape, with
/// the QC its metadata row stored beside it.
#[derive(Debug, Clone)]
pub struct RebuiltBlock {
    /// The block, carrying its provision hashes and not their bodies.
    pub block: Block,
    /// The QC that committed it, as stored.
    pub qc: Verifiable<QuorumCertificate>,
}

impl RebuiltBlock {
    /// The block paired with its QC, or `None` when the two name
    /// different blocks — rows that no longer agree with each other.
    #[must_use]
    pub fn certified(self) -> Option<Verified<CertifiedBlock>> {
        let height = self.block.height();
        match CertifiedBlock::new_checked(self.block, self.qc) {
            Ok(certified) => Some(Verified::<CertifiedBlock>::from_persisted(certified)),
            Err(err) => {
                tracing::error!(
                    height = height.inner(),
                    block_hash = ?err.block_hash,
                    qc_block_hash = ?err.qc_block_hash,
                    "Stored block and QC have mismatched hashes — possible corruption"
                );
                None
            }
        }
    }

    /// The block as a sync response serves it: the provision hashes ride
    /// beside it so the serving side can re-attach bodies from its cache.
    #[must_use]
    pub fn for_sync(self) -> BlockForSync {
        let provision_hashes = self.block.provision_hashes().into_inner();
        BlockForSync {
            block: self.block,
            qc: self.qc.into_unverified(),
            provision_hashes,
        }
    }
}

/// Rebuild the block committed at `height` from `rows`.
///
/// All or nothing: a manifest naming a transaction or an attestation the
/// rows lack, or an attestation settling a receipt they lack, answers
/// [`Unbuilt`] rather than a shorter block. Each finalization rejoins
/// its receipts through [`Finalization::reconstruct`], and its
/// certificates arrive `Unverified`: the stored rows carry no
/// verification marker, so a reader that needs one runs the predicate.
///
/// # Errors
///
/// [`Unbuilt`] naming what is missing.
///
/// # Panics
///
/// If the rows rebuild a list past the cap the committed block met,
/// which rows written from that block cannot.
pub fn reconstruct_block(
    rows: &impl BlockRows,
    height: BlockHeight,
) -> Result<RebuiltBlock, Unbuilt> {
    let metadata = rows.block_metadata(height).ok_or(Unbuilt::Absent)?;
    let (header, manifest, engagements, qc, _) = metadata.into_parts();

    let transactions = rows.transactions(manifest.tx_hashes());
    if transactions.len() != manifest.transaction_count() {
        return Err(Unbuilt::MissingTransactions {
            expected: manifest.transaction_count(),
            found: transactions.len(),
        });
    }

    let attestations = rows.attestations(manifest.cert_ids());
    if attestations.len() != manifest.cert_ids().len() {
        return Err(Unbuilt::MissingAttestations {
            expected: manifest.cert_ids().len(),
            found: attestations.len(),
        });
    }

    let certificates: Vec<Arc<Verifiable<Finalization>>> = attestations
        .into_iter()
        .map(|attestation| {
            Finalization::reconstruct(attestation, |tx_hash, receipt_hash| {
                rows.consensus_receipt(tx_hash, receipt_hash)
            })
            .map(|finalization| Arc::new(finalization.into()))
        })
        .collect::<Option<_>>()
        .ok_or(Unbuilt::MissingReceipt)?;

    let transactions: Vec<Arc<Verifiable<Transaction>>> = transactions
        .into_iter()
        .map(|tx| {
            Arc::new(Verifiable::from(Verified::<Transaction>::from_persisted(
                tx,
            )))
        })
        .collect();

    let block = Block::Sealed {
        header,
        transactions: Arc::new(
            Capped::new(transactions).expect("a rebuilt block keeps the caps its source met"),
        ),
        certificates: Arc::new(
            Capped::new(certificates).expect("a rebuilt block keeps the caps its source met"),
        ),
        provision_hashes: Arc::new(manifest.provision_hashes().clone()),
        engagements: Arc::new(engagements),
        abandonment_records: Arc::new(manifest.abandonment_records().clone()),
        state_claims: Arc::new(manifest.state_claims().clone()),
        tick_manifest: Arc::new(manifest.tick_manifest().clone()),
        witness_sources: Arc::new(manifest.witness_sources().clone()),
    };
    Ok(RebuiltBlock { block, qc })
}
