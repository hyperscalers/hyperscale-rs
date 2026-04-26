//! Block fetch response.

use crate::request::Inventory;
use hyperscale_types::{
    Block, BlockHeader, CertifiedBlock, FinalizedWave, MessagePriority, NetworkMessage,
    ProvisionHash, Provisions, QuorumCertificate, RoutableTransaction, TxHash, WaveIdHash,
};
use sbor::prelude::BasicSbor;
use std::sync::Arc;

/// A block in elided wire form: every item (tx / cert / provision) has its
/// hash listed, but bodies may be omitted for items the requester declared
/// in its [`Inventory`]. The requester rehydrates by looking up omitted
/// bodies in its own mempool / cert cache / provision store.
///
/// `provisions: None` preserves the `Block::Sealed` shape; `Some(_)`
/// preserves `Block::Live` (possibly with some bodies elided).
///
/// Hash lists are always complete — they commit to the block's content
/// and let the requester reconstruct a `Block` even when bodies are
/// missing.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ElidedCertifiedBlock {
    /// Block header (always inline).
    pub header: BlockHeader,
    /// Certifying quorum certificate (always inline).
    pub qc: QuorumCertificate,
    /// Per-transaction `(hash, optional body)` pairs; body is `None` when elided.
    pub transactions: Vec<(TxHash, Option<RoutableTransaction>)>,
    /// Per-certificate `(wave-id hash, optional body)` pairs; body is `None` when elided.
    pub certificates: Vec<(WaveIdHash, Option<FinalizedWave>)>,
    /// Per-provision `(hash, optional body)` pairs. `None` overall preserves the
    /// `Block::Sealed` shape; `Some(_)` preserves `Block::Live`.
    pub provisions: Option<Vec<(ProvisionHash, Option<Provisions>)>>,
}

impl ElidedCertifiedBlock {
    /// Build an elided response from a full block + QC + the requester's
    /// inventory. Bodies whose hashes appear in the inventory filters are
    /// replaced with `None`; hashes are always included so the requester
    /// can reconstruct the block.
    #[must_use]
    pub fn elide(block: &Block, qc: QuorumCertificate, inventory: &Inventory) -> Self {
        let header = block.header().clone();
        let is_live = block.is_live();

        let transactions = block
            .transactions()
            .iter()
            .map(|tx| {
                let hash = tx.hash();
                let body = if matches_filter(inventory.tx_have.as_ref(), &hash) {
                    None
                } else {
                    Some((**tx).clone())
                };
                (hash, body)
            })
            .collect();

        let certificates = block
            .certificates()
            .iter()
            .map(|fw| {
                let hash = fw.wave_id_hash();
                let body = if matches_filter(inventory.cert_have.as_ref(), &hash) {
                    None
                } else {
                    Some((**fw).clone())
                };
                (hash, body)
            })
            .collect();

        let provisions = if is_live {
            Some(
                block
                    .provisions()
                    .iter()
                    .map(|p| {
                        let hash = p.hash();
                        let body = if matches_filter(inventory.provision_have.as_ref(), &hash) {
                            None
                        } else {
                            Some((**p).clone())
                        };
                        (hash, body)
                    })
                    .collect(),
            )
        } else {
            None
        };

        Self {
            header,
            qc,
            transactions,
            certificates,
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
    /// Returns [`RehydrationMiss`] when one or more elided bodies could
    /// not be resolved by the supplied lookup closures.
    pub fn try_rehydrate<FTx, FCert, FProv>(
        &self,
        mut tx_lookup: FTx,
        mut cert_lookup: FCert,
        mut provision_lookup: FProv,
    ) -> Result<CertifiedBlock, RehydrationMiss>
    where
        FTx: FnMut(&TxHash) -> Option<Arc<RoutableTransaction>>,
        FCert: FnMut(&WaveIdHash) -> Option<Arc<FinalizedWave>>,
        FProv: FnMut(&ProvisionHash) -> Option<Arc<Provisions>>,
    {
        let mut miss = RehydrationMiss::default();
        let mut txs = Vec::with_capacity(self.transactions.len());
        for (hash, body) in &self.transactions {
            if let Some(tx) = body {
                txs.push(Some(Arc::new(tx.clone())));
            } else if let Some(resolved) = tx_lookup(hash) {
                txs.push(Some(resolved));
            } else {
                txs.push(None);
                miss.missing_tx.push(*hash);
            }
        }

        let mut certs = Vec::with_capacity(self.certificates.len());
        for (hash, body) in &self.certificates {
            if let Some(fw) = body {
                certs.push(Some(Arc::new(fw.clone())));
            } else if let Some(resolved) = cert_lookup(hash) {
                certs.push(Some(resolved));
            } else {
                certs.push(None);
                miss.missing_cert.push(*hash);
            }
        }

        let provs = self.provisions.as_ref().map(|entries| {
            let mut out = Vec::with_capacity(entries.len());
            for (hash, body) in entries {
                if let Some(p) = body {
                    out.push(Some(Arc::new(p.clone())));
                } else if let Some(resolved) = provision_lookup(hash) {
                    out.push(Some(resolved));
                } else {
                    out.push(None);
                    miss.missing_provision.push(*hash);
                }
            }
            out
        });

        if !miss.is_empty() {
            return Err(miss);
        }

        let txs: Vec<Arc<RoutableTransaction>> = txs.into_iter().map(Option::unwrap).collect();
        let certs: Vec<Arc<FinalizedWave>> = certs.into_iter().map(Option::unwrap).collect();
        let block = match provs {
            Some(entries) => {
                let provisions: Vec<Arc<Provisions>> =
                    entries.into_iter().map(Option::unwrap).collect();
                Block::Live {
                    header: self.header.clone(),
                    transactions: txs,
                    certificates: certs,
                    provisions,
                }
            }
            None => Block::Sealed {
                header: self.header.clone(),
                transactions: txs,
                certificates: certs,
            },
        };
        Ok(CertifiedBlock::new_unchecked(block, self.qc.clone()))
    }
}

/// Hashes whose bodies [`ElidedCertifiedBlock::try_rehydrate`] couldn't
/// resolve from the provided lookups. Used as the payload of a follow-up
/// [`GetBlockTopUpRequest`](crate::request::GetBlockTopUpRequest).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RehydrationMiss {
    /// Transaction hashes whose bodies could not be resolved.
    pub missing_tx: Vec<TxHash>,
    /// Wave-id hashes whose finalized-wave bodies could not be resolved.
    pub missing_cert: Vec<WaveIdHash>,
    /// Provision hashes whose bodies could not be resolved.
    pub missing_provision: Vec<ProvisionHash>,
}

impl RehydrationMiss {
    /// Whether every category is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing_tx.is_empty()
            && self.missing_cert.is_empty()
            && self.missing_provision.is_empty()
    }

    /// Total number of missing hashes across categories.
    #[must_use]
    pub fn total(&self) -> usize {
        self.missing_tx.len() + self.missing_cert.len() + self.missing_provision.len()
    }
}

fn matches_filter<T>(filter: Option<&hyperscale_types::BloomFilter<T>>, hash: &T) -> bool
where
    T: hyperscale_types::TypedHash,
{
    filter.is_some_and(|bf| bf.contains(hash))
}

/// Response to a block fetch request.
///
/// Carries a block in elided form together with its certifying QC.
/// Inline bodies may be omitted for items the requester already holds
/// (see [`ElidedCertifiedBlock`]); hash lists are always complete.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockResponse {
    /// The requested block (elided) + certifying QC. `None` when the
    /// serving peer doesn't have the block.
    pub certified: Option<ElidedCertifiedBlock>,
}

impl GetBlockResponse {
    /// Create a response with a found block.
    #[must_use]
    pub fn found(certified: ElidedCertifiedBlock) -> Self {
        Self {
            certified: Some(certified),
        }
    }

    /// Create a response for a block not found.
    #[must_use]
    pub fn not_found() -> Self {
        Self { certified: None }
    }

    /// Check if the block was found.
    #[must_use]
    pub fn has_block(&self) -> bool {
        self.certified.is_some()
    }

    /// Consume and return the elided block.
    #[must_use]
    pub fn into_elided(self) -> Option<ElidedCertifiedBlock> {
        self.certified
    }
}

// Network message implementation
impl NetworkMessage for GetBlockResponse {
    fn message_type_id() -> &'static str {
        "block.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHash, BlockHeight, CertificateRoot, Hash, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot,
        ValidatorId, WeightedTimestamp, test_utils::test_transaction, zero_bls_signature,
    };
    use std::collections::BTreeMap;

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block::Live {
            header: BlockHeader {
                shard_group_id: ShardGroupId(0),
                height: BlockHeight(1),
                parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: ProposerTimestamp(1_234_567_890),
                round: Round::INITIAL,
                is_fallback: false,
                state_root: StateRoot::ZERO,
                transaction_root: TransactionRoot::ZERO,
                certificate_root: CertificateRoot::ZERO,
                local_receipt_root: LocalReceiptRoot::ZERO,
                provision_root: ProvisionsRoot::ZERO,
                waves: vec![],
                provision_tx_roots: BTreeMap::new(),
                in_flight: 0,
            },
            transactions: vec![Arc::new(tx)],
            certificates: vec![],
            provisions: vec![],
        }
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            shard_group_id: ShardGroupId(0),
            height: block.height(),
            parent_block_hash: block.header().parent_hash,
            round: block.header().round,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(0),
            weighted_timestamp: WeightedTimestamp::ZERO,
        }
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
        let mut bf: hyperscale_types::BloomFilter<TxHash> =
            hyperscale_types::BloomFilter::with_capacity(16, 0.01).unwrap();
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
        let mut bf: hyperscale_types::BloomFilter<TxHash> =
            hyperscale_types::BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc.clone(), &inv);
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
        assert_eq!(&rehydrated.block, &block);
    }

    #[test]
    fn rehydrate_reports_missing_hashes() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let tx_hash = block.transactions()[0].hash();
        let mut bf: hyperscale_types::BloomFilter<TxHash> =
            hyperscale_types::BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);
        let miss = elided
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect_err("rehydration should fail when elided body has no local source");
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
        let mut bf: hyperscale_types::BloomFilter<TxHash> =
            hyperscale_types::BloomFilter::with_capacity(16, 0.01).unwrap();
        bf.insert(&tx_hash);
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let elided = ElidedCertifiedBlock::elide(&block, qc, &inv);

        let miss = elided
            .try_rehydrate(|_| None, |_| None, |_| None)
            .expect_err("first pass should miss");
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
        assert_eq!(&recovered.block, &block);
    }

    #[test]
    fn response_found_and_not_found_helpers() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let elided = ElidedCertifiedBlock::elide(&block, qc, &Inventory::empty());
        let response = GetBlockResponse::found(elided.clone());
        assert!(response.has_block());
        assert_eq!(response.into_elided(), Some(elided));

        let nf = GetBlockResponse::not_found();
        assert!(!nf.has_block());
        assert_eq!(nf.into_elided(), None);
    }
}
