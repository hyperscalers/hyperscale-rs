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

use hyperscale_hbor::Hbor;

use crate::{
    AbandonmentRecord, Block, BlockHash, BlockHeader, BloomFilter, BloomKey, CertifiedBlock,
    Finalization, FinalizationHash, MAX_FINALIZED_TX_PER_BLOCK, MAX_PROVISION_TARGET_SHARDS,
    MAX_PROVISIONS_PER_BLOCK, MAX_STATE_CLAIMS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProvisionHash,
    Provisions, QuorumCertificate, StateClaim, Transaction, TxHash, Verifiable, WitnessSources,
};

/// Inventory of locally-known item hashes, grouped by category.
///
/// All fields are optional so callers can skip categories that don't fit
/// within the filter size cap — the responder treats absence as "send
/// everything for this category."
///
/// Phantom typing on [`BloomFilter`] keeps tx/cert/provision filters from
/// being swapped by accident; wire bytes are identical regardless of `T`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hbor)]
pub struct Inventory {
    /// Transactions the requester can resolve from mempool or
    /// recently-evicted cache. Responder may omit the corresponding
    /// transaction body.
    pub tx_have: Option<BloomFilter<TxHash>>,
    /// Transactions the requester already holds a finalization for.
    /// Responder may omit a `Finalization` body once every one of its
    /// transactions matches.
    pub cert_have: Option<BloomFilter<TxHash>>,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ElidedCertifiedBlock {
    header: Verifiable<BlockHeader>,
    qc: Verifiable<QuorumCertificate>,
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    transactions: Vec<(TxHash, Option<Arc<Verifiable<Transaction>>>)>,
    #[hbor(max = MAX_FINALIZED_TX_PER_BLOCK)]
    certificates: Vec<(FinalizationHash, Option<Arc<Verifiable<Finalization>>>)>,
    provisions: ElidedProvisions,
    /// What departed shards left unresolved of the serving chain's
    /// business, always inline: the records are small, rare, and are what
    /// a verdict is composed on, so a hop that dropped them would hand
    /// back a block that cannot answer for itself.
    #[hbor(max = MAX_PROVISION_TARGET_SHARDS)]
    abandonment_records: Vec<AbandonmentRecord>,
    /// The block's state claims, always inline: they are small, and the
    /// receiver folds them at commit.
    #[hbor(max = MAX_STATE_CLAIMS_PER_BLOCK)]
    state_claims: Vec<StateClaim>,
    /// The block's beacon-witness inputs, always inline (never elided):
    /// they are small and the receiver needs them to reproduce the
    /// block's beacon-witness leaves at commit.
    witness_sources: WitnessSources,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum ElidedProvisions {
    /// Block was `Live` at serve time.
    Live(
        #[hbor(max = MAX_PROVISIONS_PER_BLOCK)]
        Vec<(ProvisionHash, Option<Arc<Verifiable<Provisions>>>)>,
    ),
    /// Block was `Sealed` at serve time; hashes only.
    Sealed(#[hbor(max = MAX_PROVISIONS_PER_BLOCK)] Vec<ProvisionHash>),
}

impl ElidedCertifiedBlock {
    /// Block header (always inline).
    #[must_use]
    pub fn header(&self) -> &BlockHeader {
        self.header.as_unverified()
    }

    /// Borrow the header's [`Verifiable`] wrapper, exposing the verification
    /// marker. Used by typestate consumers that branch on whether the
    /// inline header has already been verified.
    #[must_use]
    pub const fn header_verifiable(&self) -> &Verifiable<BlockHeader> {
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
    pub const fn transactions(&self) -> &Vec<(TxHash, Option<Arc<Verifiable<Transaction>>>)> {
        &self.transactions
    }

    /// Per-certificate `(tick id, optional body)` pairs; body is `None` when elided.
    #[must_use]
    pub const fn certificates(
        &self,
    ) -> &Vec<(FinalizationHash, Option<Arc<Verifiable<Finalization>>>)> {
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
        // collections are capped at the same limits as the elided fields
        // by `Block`'s own decode validator, so the elided form cannot
        // outgrow the caps its fields declare.
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
                let id = fw.receipt_hash();
                let body = if finalization_is_held(inventory.cert_have.as_ref(), fw) {
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
            ElidedProvisions::Live(entries)
        } else {
            ElidedProvisions::Sealed(block.provision_hashes())
        };

        Self {
            header: header.into(),
            qc,
            transactions,
            certificates,
            provisions,
            abandonment_records: block.abandonment_records().to_vec(),
            state_claims: block.state_claims().to_vec(),
            witness_sources: block.witness_sources().as_ref().clone(),
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
        FTx: FnMut(&TxHash) -> Option<Arc<Verifiable<Transaction>>>,
        FCert: FnMut(&FinalizationHash) -> Option<Arc<Verifiable<Finalization>>>,
        FProv: FnMut(&ProvisionHash) -> Option<Arc<Verifiable<Provisions>>>,
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
        for (hash, body) in &self.transactions {
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
        for (id, body) in &self.certificates {
            if let Some(fw) = body {
                certs.push(Some(Arc::clone(fw)));
            } else if let Some(resolved) = cert_lookup(id) {
                certs.push(Some(resolved));
            } else {
                certs.push(None);
                miss.missing_cert.push(*id);
            }
        }

        let live_provs = match &self.provisions {
            ElidedProvisions::Live(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (hash, body) in entries {
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

        let txs: Vec<Arc<Verifiable<Transaction>>> = txs.into_iter().map(Option::unwrap).collect();
        let certs: Vec<Arc<Verifiable<Finalization>>> =
            certs.into_iter().map(Option::unwrap).collect();
        let txs = Arc::new(txs);
        let certs = Arc::new(certs);
        let block = match (live_provs, &self.provisions) {
            (Some(entries), _) => {
                let provisions: Vec<Arc<Verifiable<Provisions>>> =
                    entries.into_iter().map(Option::unwrap).collect();
                Block::Live {
                    header: self.header.as_unverified().clone(),
                    transactions: txs,
                    certificates: certs,
                    provisions: Arc::new(provisions),
                    abandonment_records: Arc::new(self.abandonment_records.clone()),
                    state_claims: Arc::new(self.state_claims.clone()),
                    witness_sources: Arc::new(self.witness_sources.clone()),
                }
            }
            (None, ElidedProvisions::Sealed(hashes)) => Block::Sealed {
                header: self.header.as_unverified().clone(),
                transactions: txs,
                certificates: certs,
                provision_hashes: Arc::new(hashes.clone()),
                abandonment_records: Arc::new(self.abandonment_records.clone()),
                state_claims: Arc::new(self.state_claims.clone()),
                witness_sources: Arc::new(self.witness_sources.clone()),
            },
            (None, ElidedProvisions::Live(_)) => {
                unreachable!("live_provs is Some when provisions is Live")
            }
        };
        Ok(CertifiedBlock::new_unchecked(block, self.qc.clone()))
    }
}

/// Hashes whose bodies [`ElidedCertifiedBlock::try_rehydrate`] couldn't
/// resolve from the provided lookups.
///
/// Drives follow-up fetches for the missing transactions, finalizations,
/// and provisions via the per-payload fetch protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RehydrationMiss {
    /// Transaction hashes whose bodies could not be resolved.
    pub missing_tx: Vec<TxHash>,
    /// Tick ids whose finalization bodies could not be resolved.
    pub missing_cert: Vec<FinalizationHash>,
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

/// Whether the requester's transaction filter covers every transaction of
/// `fw`, which is what it takes to hold the tick itself. A tick with no
/// transactions is never held — a vacuous match would elide a body the
/// requester has no way to resolve.
fn finalization_is_held(filter: Option<&BloomFilter<TxHash>>, fw: &Finalization) -> bool {
    let Some(bf) = filter else {
        return false;
    };
    let mut txs = fw.tx_hashes().peekable();
    txs.peek().is_some() && txs.all(|tx| bf.contains(&tx))
}

#[cfg(test)]
mod tests {

    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::test_utils::test_transaction;
    use crate::{
        AggregateSignature, BlockHash, BlockHeaderParts, BlockHeight, BloomFilter, ChainOrigin,
        ExecutionCertificate, ExecutionOutcome, GlobalReceiptHash, GlobalReceiptRoot, Hash,
        ProposerTimestamp, ShardId, SignerBitfield, TickHalf, TickId, TxOutcome, WeightedTimestamp,
    };

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(1),
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                timestamp: ProposerTimestamp::from_millis(1_234_567_890),
                ..Default::default()
            }),
            transactions: Arc::new(vec![Arc::new(Verifiable::from(tx))]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// Block carrying one two-transaction finalization and no
    /// transactions of its own.
    fn create_test_block_with_finalization(tx_hashes: &[TxHash]) -> Block {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| {
                TxOutcome::new(
                    *h,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        let ec = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let fw = Verifiable::from(Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![Arc::new(ec)],
            Vec::new(),
        ));

        let Block::Live {
            header,
            transactions,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } = create_test_block()
        else {
            unreachable!("create_test_block builds a Live block")
        };
        Block::Live {
            header,
            transactions,
            certificates: Arc::new(vec![Arc::new(fw)]),
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
        }
    }

    fn cert_filter(tx_hashes: &[TxHash]) -> Inventory {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(16, 0.01).unwrap();
        for h in tx_hashes {
            bf.insert(h);
        }
        Inventory {
            tx_have: None,
            cert_have: Some(bf),
            provision_have: None,
        }
    }

    /// A tick is held only when the requester has every one of its
    /// transactions — a partial match leaves the body inline, because a
    /// requester holding half a tick holds no tick at all.
    #[test]
    fn cert_elision_requires_every_transaction_of_the_tick() {
        let a = TxHash::from(Hash::from_bytes(b"tick tx a"));
        let b = TxHash::from(Hash::from_bytes(b"tick tx b"));
        let block = create_test_block_with_finalization(&[a, b]);
        let qc = create_test_qc(&block);

        let partial = ElidedCertifiedBlock::elide(&block, qc.clone(), &cert_filter(&[a]));
        assert!(
            partial.certificates[0].1.is_some(),
            "one of two transactions is not the tick"
        );

        let full = ElidedCertifiedBlock::elide(&block, qc, &cert_filter(&[a, b]));
        assert!(full.certificates[0].1.is_none(), "requester has the tick");
    }

    /// An empty tick would match a filter vacuously; eliding it would
    /// leave the requester unable to resolve a body it never had.
    #[test]
    fn cert_elision_never_elides_a_transactionless_tick() {
        let block = create_test_block_with_finalization(&[]);
        let qc = create_test_qc(&block);
        let elided = ElidedCertifiedBlock::elide(&block, qc, &cert_filter(&[]));
        assert!(elided.certificates[0].1.is_some());
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            block.height(),
            block.header().parent_block_hash(),
            block.header().round(),
            SignerBitfield::new(0),
            AggregateSignature::ZERO,
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

    /// Forge an `ElidedCertifiedBlock` whose `transactions` length claims
    /// one past the cap, padded to input-satisfiability — the protocol cap
    /// fires before any per-element work happens.
    #[test]
    fn decode_rejects_oversized_transactions_count() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = hbor_to_vec(&header).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&qc).unwrap());
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 64));
        let err = hbor_from_slice::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_certificates_count() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = hbor_to_vec(&header).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&qc).unwrap());
        // Empty transactions.
        buf.extend_from_slice(
            &hbor_to_vec(&Vec::<(TxHash, Option<Arc<Transaction>>)>::new()).unwrap(),
        );
        // Oversized certificates claim.
        varint::write(&mut buf, MAX_FINALIZED_TX_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_FINALIZED_TX_PER_BLOCK + 1) * 64,
        ));
        let err = hbor_from_slice::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_FINALIZED_TX_PER_BLOCK
                    && actual == MAX_FINALIZED_TX_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_provisions_count() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let header = block.header().clone();

        let mut buf = hbor_to_vec(&header).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&qc).unwrap());
        buf.extend_from_slice(
            &hbor_to_vec(&Vec::<(TxHash, Option<Arc<Transaction>>)>::new()).unwrap(),
        );
        buf.extend_from_slice(
            &hbor_to_vec(&Vec::<(FinalizationHash, Option<Arc<Finalization>>)>::new()).unwrap(),
        );
        // ElidedProvisions::Live(oversized) — discriminant 0, then the claim.
        buf.push(0);
        varint::write(&mut buf, MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_PROVISIONS_PER_BLOCK + 1) * 64,
        ));
        let err = hbor_from_slice::<ElidedCertifiedBlock>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
