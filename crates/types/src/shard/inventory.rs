//! Inventory-driven block elision.
//!
//! The inventory/elision protocol lets a block-fetch responder drop bodies
//! the requester already holds locally:
//!
//! - The requester ships an [`Inventory`] (per-category bloom filters of
//!   hashes it already has) inside its block-fetch request.
//! - The responder builds an [`ElidedCertifiedBlock`] from the full block
//!   plus the inventory: hashes are always inline; bodies that match a
//!   filter are replaced with `None`.
//! - The requester rehydrates via [`ElidedCertifiedBlock::try_rehydrate`]
//!   using closures that resolve elided hashes against its mempool /
//!   cert cache / provision store; missing bodies surface as a
//!   [`RehydrationMiss`] for top-up.
//!
//! All types live in this single module so the protocol surface is in one
//! place — the request- and response-side wrappers (`GetBlockRequest`,
//! `GetBlockResponse`) live under [`crate::network`] and re-export the
//! types defined here.

use std::fmt;
use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{
    Block, BlockHash, BlockHeader, BloomFilter, BloomKey, BoundedVec, CertifiedBlock,
    FinalizedWave, LinkageError, MAX_FINALIZED_TX_PER_BLOCK, MAX_PROVISIONS_PER_BLOCK,
    MAX_TXS_PER_BLOCK, ProvisionHash, Provisions, QuorumCertificate, RoutableTransaction, TxHash,
    Verifiable, Verified, WaveId,
};

/// Inventory of locally-known item hashes, grouped by category.
///
/// All fields are optional so callers can skip categories that don't fit
/// within the filter size cap — the responder treats absence as "send
/// everything for this category."
///
/// Phantom typing on [`BloomFilter`] keeps tx/cert/provision filters from
/// being swapped by accident; wire bytes are identical regardless of `T`.
#[derive(Debug, Clone, Default, PartialEq, Eq, BasicSbor)]
pub struct Inventory {
    /// Transactions the requester can resolve from mempool or
    /// recently-evicted cache. Responder may omit the corresponding
    /// transaction body.
    pub tx_have: Option<BloomFilter<TxHash>>,
    /// Finalized wave certificates the requester already has cached.
    /// Responder may omit matching `FinalizedWave` bodies.
    pub cert_have: Option<BloomFilter<WaveId>>,
    /// Provisions the requester already has in its provision store.
    /// Independent of the responder's own `Live → Sealed` downgrade.
    pub provision_have: Option<BloomFilter<ProvisionHash>>,
}

impl Inventory {
    /// Inventory that advertises nothing — equivalent to "send everything."
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether every category is absent. Responders can short-circuit the
    /// elision path entirely when this is true.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tx_have.is_none() && self.cert_have.is_none() && self.provision_have.is_none()
    }
}

/// A block in elided wire form.
///
/// Every item (tx / cert / provision) has its hash listed, but bodies may
/// be omitted for items the requester declared in its [`Inventory`]. The
/// requester rehydrates by looking up omitted bodies in its own mempool /
/// cert cache / provision store.
///
/// `provisions: None` preserves the `Block::Sealed` shape; `Some(_)`
/// preserves `Block::Live` (possibly with some bodies elided).
///
/// Hash lists are always complete — they commit to the block's content
/// and let the requester reconstruct a `Block` even when bodies are
/// missing.
///
/// Per-collection caps mirror [`Block`]'s caps one-to-one — the elided
/// form is a structural transformation of `Block` and inherits its
/// natural ceilings.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ElidedCertifiedBlock {
    header: BlockHeader,
    qc: Verifiable<QuorumCertificate>,
    transactions: BoundedVec<(TxHash, Option<Arc<RoutableTransaction>>), MAX_TXS_PER_BLOCK>,
    certificates: BoundedVec<(WaveId, Option<Arc<FinalizedWave>>), MAX_FINALIZED_TX_PER_BLOCK>,
    provisions: ElidedProvisions,
}

/// Variant-discriminated provisions payload for [`ElidedCertifiedBlock`].
///
/// `Live` mirrors a [`Block::Live`] with per-provision bodies optionally
/// elided per the requester's inventory. `Sealed` mirrors a
/// [`Block::Sealed`] and carries only the content hashes — the requester
/// re-attaches bodies from its own provision cache if it needs to upgrade
/// the block back to `Live`. Carrying hashes (rather than `None`) lets the
/// receiver in turn serve the same block as `Live` to downstream peers
/// without losing the hash list across each sync hop.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ElidedProvisions {
    /// Block was `Live` at serve time.
    Live(BoundedVec<(ProvisionHash, Option<Arc<Provisions>>), MAX_PROVISIONS_PER_BLOCK>),
    /// Block was `Sealed` at serve time; hashes only.
    Sealed(BoundedVec<ProvisionHash, MAX_PROVISIONS_PER_BLOCK>),
}

impl ElidedCertifiedBlock {
    /// Block header (always inline).
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Certifying quorum certificate (always inline).
    #[must_use]
    pub fn qc(&self) -> &QuorumCertificate {
        self.qc.as_unverified()
    }

    /// Per-transaction `(hash, optional body)` pairs; body is `None` when elided.
    ///
    /// Bodies are `Arc`-wrapped so server-side elision and receiver-side
    /// rehydration share the same allocations as the local mempool /
    /// pending-block stores rather than deep-cloning every body.
    #[must_use]
    pub const fn transactions(
        &self,
    ) -> &BoundedVec<(TxHash, Option<Arc<RoutableTransaction>>), MAX_TXS_PER_BLOCK> {
        &self.transactions
    }

    /// Per-certificate `(wave id, optional body)` pairs; body is `None` when elided.
    #[must_use]
    pub const fn certificates(
        &self,
    ) -> &BoundedVec<(WaveId, Option<Arc<FinalizedWave>>), MAX_FINALIZED_TX_PER_BLOCK> {
        &self.certificates
    }

    /// Provisions payload. The variant tells the receiver whether the
    /// block was `Live` (per-provision bodies, optionally elided) or
    /// `Sealed` (hash-only).
    #[must_use]
    pub const fn provisions(&self) -> &ElidedProvisions {
        &self.provisions
    }
    /// Build an elided response from a full block + QC + the requester's
    /// inventory. Bodies whose hashes appear in the inventory filters are
    /// replaced with `None`; hashes are always included so the requester
    /// can reconstruct the block.
    #[must_use]
    pub fn elide(
        block: &Block,
        qc: impl Into<Verifiable<QuorumCertificate>>,
        inventory: &Inventory,
    ) -> Self {
        let qc = qc.into();
        let header = block.header().clone();
        let is_live = block.is_live();

        // The `block.transactions()/certificates()/provisions()` source
        // collections are themselves `BoundedVec`s capped at the same
        // limits as the elided fields, so each `.into()` below cannot
        // panic — the iterator can't outproduce its source.
        let transactions: Vec<_> = block
            .transactions()
            .iter()
            .map(|tx| {
                let hash = tx.hash();
                let body = if matches_filter(inventory.tx_have.as_ref(), &hash) {
                    None
                } else {
                    Some(Arc::clone(tx))
                };
                (hash, body)
            })
            .collect();

        let certificates: Vec<_> = block
            .certificates()
            .iter()
            .map(|fw| {
                let id = fw.wave_id().clone();
                let body = if matches_filter(inventory.cert_have.as_ref(), &id) {
                    None
                } else {
                    Some(Arc::clone(fw))
                };
                (id, body)
            })
            .collect();

        let provisions = if is_live {
            let entries: Vec<_> = block
                .provisions()
                .iter()
                .map(|p| {
                    let hash = p.hash();
                    let body = if matches_filter(inventory.provision_have.as_ref(), &hash) {
                        None
                    } else {
                        Some(Arc::clone(p))
                    };
                    (hash, body)
                })
                .collect();
            ElidedProvisions::Live(entries.into())
        } else {
            ElidedProvisions::Sealed(block.provision_hashes().into())
        };

        Self {
            header,
            qc,
            transactions: transactions.into(),
            certificates: certificates.into(),
            provisions,
        }
    }

    /// Rehydrate to a full [`CertifiedBlock`] by resolving any elided
    /// body via the provided lookup closures.
    ///
    /// Walks every entry exactly once. Returns `Ok(cert)` when every body
    /// is either inline or successfully resolved. Returns
    /// `Err(RehydrationMiss)` listing every hash the lookups couldn't
    /// resolve — the caller uses that list to issue a top-up request and
    /// then retry rehydration with lookups augmented by the top-up
    /// bodies.
    ///
    /// # Errors
    ///
    /// Returns [`RehydrateError::Missing`] when one or more elided bodies
    /// could not be resolved by the supplied lookup closures, or
    /// [`RehydrateError::QcMismatch`] when the inline QC's `block_hash`
    /// does not match the inline header's hash.
    pub fn try_rehydrate<FTx, FCert, FProv>(
        &self,
        mut tx_lookup: FTx,
        mut cert_lookup: FCert,
        mut provision_lookup: FProv,
    ) -> Result<CertifiedBlock, RehydrateError>
    where
        FTx: FnMut(&TxHash) -> Option<Arc<RoutableTransaction>>,
        FCert: FnMut(&WaveId) -> Option<Arc<FinalizedWave>>,
        FProv: FnMut(&ProvisionHash) -> Option<Arc<Provisions>>,
    {
        // Header + QC are always inline, so the pairing can be checked
        // before resolving any bodies. A peer that sends a mismatched
        // (header, qc) pair fails fast without us doing lookup work.
        let header_hash = self.header.hash();
        if self.qc.as_unverified().block_hash() != header_hash {
            return Err(RehydrateError::QcMismatch {
                header_hash,
                qc_block_hash: self.qc.as_unverified().block_hash(),
            });
        }
        let mut miss = RehydrationMiss::default();
        let mut txs = Vec::with_capacity(self.transactions.len());
        for (hash, body) in self.transactions.iter() {
            if let Some(tx) = body {
                txs.push(Some(Arc::clone(tx)));
            } else if let Some(resolved) = tx_lookup(hash) {
                txs.push(Some(resolved));
            } else {
                txs.push(None);
                miss.missing_tx.push(*hash);
            }
        }

        let mut certs = Vec::with_capacity(self.certificates.len());
        for (id, body) in self.certificates.iter() {
            if let Some(fw) = body {
                certs.push(Some(Arc::clone(fw)));
            } else if let Some(resolved) = cert_lookup(id) {
                certs.push(Some(resolved));
            } else {
                certs.push(None);
                miss.missing_cert.push(id.clone());
            }
        }

        let live_provs = match &self.provisions {
            ElidedProvisions::Live(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (hash, body) in entries.iter() {
                    if let Some(p) = body {
                        out.push(Some(Arc::clone(p)));
                    } else if let Some(resolved) = provision_lookup(hash) {
                        out.push(Some(resolved));
                    } else {
                        out.push(None);
                        miss.missing_provision.push(*hash);
                    }
                }
                Some(out)
            }
            ElidedProvisions::Sealed(_) => None,
        };

        if !miss.is_empty() {
            return Err(RehydrateError::Missing(miss));
        }

        let txs: Vec<Arc<RoutableTransaction>> = txs.into_iter().map(Option::unwrap).collect();
        let certs: Vec<Arc<FinalizedWave>> = certs.into_iter().map(Option::unwrap).collect();
        let txs = Arc::new(txs.into());
        let certs = Arc::new(certs.into());
        let block = match (live_provs, &self.provisions) {
            (Some(entries), _) => {
                let provisions: Vec<Arc<Provisions>> =
                    entries.into_iter().map(Option::unwrap).collect();
                Block::Live {
                    header: self.header.clone(),
                    transactions: txs,
                    certificates: certs,
                    provisions: Arc::new(provisions.into()),
                }
            }
            (None, ElidedProvisions::Sealed(hashes)) => Block::Sealed {
                header: self.header.clone(),
                transactions: txs,
                certificates: certs,
                provision_hashes: Arc::new(hashes.clone()),
            },
            (None, ElidedProvisions::Live(_)) => {
                unreachable!("live_provs is Some when provisions is Live")
            }
        };
        Ok(CertifiedBlock::new_unchecked(block, self.qc.clone()))
    }
}

impl Verified<ElidedCertifiedBlock> {
    /// Pair an [`ElidedCertifiedBlock`] with a verified QC after
    /// confirming the linkage invariant.
    ///
    /// Construction asserts: the inline QC was verified, and
    /// `qc.block_hash == header.hash()`. Per-element verification of
    /// the inline transaction / certificate bodies is *not* part of
    /// this predicate — callers that need verified bodies run those
    /// checks separately at admission, the same way they would on a
    /// rehydrated [`CertifiedBlock`].
    ///
    /// # Errors
    ///
    /// Returns [`LinkageError::BlockHashMismatch`] when
    /// `qc.block_hash != elided.header().hash()`.
    pub fn assemble_from_qc(
        elided: ElidedCertifiedBlock,
        qc: Verified<QuorumCertificate>,
    ) -> Result<Self, LinkageError> {
        let header_hash = elided.header.hash();
        let qc_block_hash = qc.block_hash();
        if qc_block_hash != header_hash {
            return Err(LinkageError::BlockHashMismatch {
                block_hash: header_hash,
                qc_block_hash,
            });
        }
        Ok(Self::new_unchecked(ElidedCertifiedBlock {
            header: elided.header,
            qc: Verifiable::Verified(qc),
            transactions: elided.transactions,
            certificates: elided.certificates,
            provisions: elided.provisions,
        }))
    }
}

/// Hashes whose bodies [`ElidedCertifiedBlock::try_rehydrate`] couldn't
/// resolve from the provided lookups.
///
/// Drives follow-up fetches for the missing transactions, wave certificates,
/// and provisions via the per-payload fetch protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RehydrationMiss {
    /// Transaction hashes whose bodies could not be resolved.
    pub missing_tx: Vec<TxHash>,
    /// Wave ids whose finalized-wave bodies could not be resolved.
    pub missing_cert: Vec<WaveId>,
    /// Provision hashes whose bodies could not be resolved.
    pub missing_provision: Vec<ProvisionHash>,
}

impl RehydrationMiss {
    /// Whether every category is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.missing_tx.is_empty()
            && self.missing_cert.is_empty()
            && self.missing_provision.is_empty()
    }

    /// Total number of missing hashes across categories.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.missing_tx.len() + self.missing_cert.len() + self.missing_provision.len()
    }
}

/// Why [`ElidedCertifiedBlock::try_rehydrate`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehydrateError {
    /// One or more elided body hashes could not be resolved by the
    /// supplied lookup closures. The caller should issue a top-up.
    Missing(RehydrationMiss),
    /// The inline QC's `block_hash` does not match the inline header's
    /// hash. A peer sent an invalid pairing; the response is unusable
    /// regardless of body availability.
    QcMismatch {
        /// Hash of the inline header.
        header_hash: BlockHash,
        /// `block_hash` field from the inline QC.
        qc_block_hash: BlockHash,
    },
}

impl fmt::Display for RehydrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(miss) => write!(f, "{} missing bodies", miss.total()),
            Self::QcMismatch {
                header_hash,
                qc_block_hash,
            } => write!(
                f,
                "qc.block_hash {qc_block_hash:?} does not match header hash {header_hash:?}"
            ),
        }
    }
}

impl std::error::Error for RehydrateError {}

fn matches_filter<T>(filter: Option<&BloomFilter<T>>, item: &T) -> bool
where
    T: BloomKey,
{
    filter.is_some_and(|bf| bf.contains(item))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::test_utils::test_transaction;
    use crate::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, BloomFilter, BoundedVec,
        CertificateRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot, ValidatorId,
        WeightedTimestamp, zero_bls_signature,
    };

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block::Live {
            header: BlockHeader::new(
                ShardGroupId::new(0),
                BlockHeight::new(1),
                BlockHash::from_raw(Hash::from_bytes(b"parent")),
                QuorumCertificate::genesis(ShardGroupId::new(0)),
                ValidatorId::new(0),
                ProposerTimestamp::from_millis(1_234_567_890),
                Round::INITIAL,
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
            ),
            transactions: Arc::new(vec![Arc::new(tx)].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            block.height(),
            block.header().parent_block_hash(),
            block.header().round(),
            SignerBitfield::new(0),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    #[test]
    fn empty_inventory_keeps_all_bodies() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let expected_tx_hash = block.transactions()[0].hash();
        let elided = ElidedCertifiedBlock::elide(&block, qc, &Inventory::empty());
        assert_eq!(elided.transactions.len(), 1);
        let (hash, body) = &elided.transactions[0];
        assert_eq!(*hash, expected_tx_hash);
        assert!(body.is_some(), "empty inventory should not elide bodies");
    }

    #[test]
    fn matching_inventory_elides_body_but_keeps_hash() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let tx_hash = block.transactions()[0].hash();
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);
        let (hash, body) = &elided.transactions[0];
        assert_eq!(*hash, tx_hash);
        assert!(body.is_none(), "requester already has this tx, elide body");
    }

    #[test]
    fn rehydrate_from_lookup_restores_full_block() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let tx_arc = Arc::clone(&block.transactions()[0]);
        let tx_hash = tx_arc.hash();
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);
        let rehydrated = elided
            .try_rehydrate(
                |h| {
                    if *h == tx_hash {
                        Some(Arc::clone(&tx_arc))
                    } else {
                        None
                    }
                },
                |_| None,
                |_| None,
            )
            .expect("rehydration should succeed when lookup has body");
        assert_eq!(rehydrated.height(), block.height());
        assert_eq!(rehydrated.block(), &block);
    }

    #[test]
    fn rehydrate_reports_missing_hashes() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let tx_hash = block.transactions()[0].hash();
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);
        let err = elided
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect_err("rehydration should fail when elided body has no local source");
        let RehydrateError::Missing(miss) = err else {
            panic!("expected Missing, got {err:?}");
        };
        assert_eq!(miss.total(), 1);
        assert_eq!(miss.missing_tx, vec![tx_hash]);
    }

    #[test]
    fn rehydrate_can_retry_after_topup_augments_lookups() {
        // Simulates the topup flow: first attempt reports miss; the
        // caller fetches the body and retries with an augmented lookup.
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let tx_arc = Arc::clone(&block.transactions()[0]);
        let tx_hash = tx_arc.hash();
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);

        let err = elided
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect_err("first pass should miss");
        let RehydrateError::Missing(miss) = err else {
            panic!("expected Missing, got {err:?}");
        };
        assert_eq!(miss.missing_tx, vec![tx_hash]);

        let topup_tx = Arc::clone(&tx_arc);
        let recovered = elided
            .try_rehydrate(
                |h| {
                    if *h == tx_hash {
                        Some(Arc::clone(&topup_tx))
                    } else {
                        None
                    }
                },
                |_| None,
                |_| None,
            )
            .expect("second pass with topup body should succeed");
        assert_eq!(recovered.block(), &block);
    }

    /// Hand-roll an `ElidedCertifiedBlock` whose `transactions` length
    /// prefix exceeds the cap. The `BoundedVec` decoder fires before any
    /// per-element work happens.
    #[test]
    fn decode_rejects_oversized_transactions_count() {
        use sbor::{
            BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
            NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
        };

        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = Vec::with_capacity(512);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            enc.encode(&header).unwrap();
            enc.encode(&qc).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_certificates_count() {
        use sbor::{
            BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
            NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
        };

        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = Vec::with_capacity(512);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            enc.encode(&header).unwrap();
            enc.encode(&qc).unwrap();
            // Empty transactions.
            enc.encode(&Vec::<(TxHash, Option<Arc<RoutableTransaction>>)>::new())
                .unwrap();
            // Oversized certificates.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_FINALIZED_TX_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_FINALIZED_TX_PER_BLOCK
                    && actual == MAX_FINALIZED_TX_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_provisions_count() {
        use sbor::{
            BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
            NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
        };

        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = Vec::with_capacity(512);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            enc.encode(&header).unwrap();
            enc.encode(&qc).unwrap();
            enc.encode(&Vec::<(TxHash, Option<Arc<RoutableTransaction>>)>::new())
                .unwrap();
            enc.encode(&Vec::<(WaveId, Option<Arc<FinalizedWave>>)>::new())
                .unwrap();
            // ElidedProvisions::Live(oversized) — discriminator 0, one field.
            enc.write_value_kind(ValueKind::Enum).unwrap();
            enc.write_discriminator(0).unwrap();
            enc.write_size(1).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
