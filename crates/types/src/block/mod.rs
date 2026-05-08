//! Block types for consensus.
//!
//! - [`header`]: [`BlockHeader`] (BFT-voted metadata).
//! - [`block`]: [`Block`] (the Live/Sealed enum + manual SBOR encoding).
//! - [`manifest`]: hash-level [`BlockManifest`] and denormalized [`BlockMetadata`].
//! - [`committed_header`]: [`CommittedBlockHeader`] cross-shard trust attestation.
//! - [`certified`]: [`CertifiedBlock`] pairing of a block with its certifying QC.
//! - [`vote`]: [`BlockVote`] BFT vote.
//! - [`roots`]: per-block merkle root helpers used by [`BlockHeader`] consumers.
//! - [`limits`]: protocol-level caps on per-block payload sizes.

#[allow(clippy::module_inception)]
mod block;
pub mod certified;
pub mod committed_header;
pub mod header;
pub mod inventory;
pub mod limits;
pub mod manifest;
pub mod roots;
pub mod vote;

pub use block::{Block, SharedCertificates, SharedProvisions, SharedTransactions};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::test_validity_range;
    use crate::{
        BlockHash, BlockHeader, BlockHeight, Bls12381G2Signature, BoundedBTreeMap, BoundedVec,
        CertificateRoot, ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot,
        TransactionRoot, TxHash, TxOutcome, ValidatorId, WaveCertificate, WaveId,
        WeightedTimestamp, compute_certificate_root, compute_transaction_root,
        generate_ed25519_keypair, routable_from_notarized_v1, sign_and_notarize,
    };

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            shard_group_id: ShardGroupId::new(0),
            height: BlockHeight::new(1),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardGroupId::new(0)),
            proposer: ValidatorId::new(0),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: BoundedVec::new(),
            provision_tx_roots: BoundedBTreeMap::new(),
            in_flight: InFlightCount::ZERO,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight::new(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header().transaction_root, TransactionRoot::ZERO);
        assert_eq!(
            genesis.header().parent_qc,
            QuorumCertificate::genesis(ShardGroupId::new(0))
        );
    }

    #[test]
    fn test_compute_transaction_root_empty() {
        let root = compute_transaction_root(&[]);
        assert_eq!(root, TransactionRoot::ZERO);
    }

    #[test]
    fn test_compute_transaction_root_deterministic() {
        use radix_common::network::NetworkDefinition;
        use radix_transactions::builder::ManifestBuilder;

        // Create a simple transaction for testing
        let manifest = ManifestBuilder::new().drop_all_proofs().build();
        let network = NetworkDefinition::simulator();
        let key = generate_ed25519_keypair();
        let notarized = sign_and_notarize(manifest, &network, 1, &key).unwrap();
        let tx = Arc::new(routable_from_notarized_v1(notarized, test_validity_range()).unwrap());

        let root1 = compute_transaction_root(std::slice::from_ref(&tx));
        let root2 = compute_transaction_root(std::slice::from_ref(&tx));
        assert_eq!(root1, root2);
        assert_ne!(root1, TransactionRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_empty() {
        let root = compute_certificate_root(&[]);
        assert_eq!(root, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_deterministic() {
        let make_fw = |seed: u8| -> Arc<FinalizedWave> {
            let ec = Arc::new(ExecutionCertificate::new(
                WaveId::new(
                    ShardGroupId::new(0),
                    BlockHeight::new(10),
                    BTreeSet::from([ShardGroupId::new(1)]),
                ),
                WeightedTimestamp::from_millis(11),
                GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 100; 4])),
                vec![TxOutcome {
                    tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
                    outcome: ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(
                            &[seed + 50; 4],
                        )),
                    },
                }],
                Bls12381G2Signature([0u8; 96]),
                SignerBitfield::new(4),
            ));
            Arc::new(FinalizedWave {
                certificate: Arc::new(WaveCertificate {
                    wave_id: WaveId::new(
                        ShardGroupId::new(0),
                        BlockHeight::new(10),
                        BTreeSet::from([ShardGroupId::new(1)]),
                    ),
                    execution_certificates: vec![ec],
                }),
                receipts: BoundedVec::new(),
            })
        };

        let certs = vec![make_fw(1), make_fw(2)];
        let root1 = compute_certificate_root(&certs);
        let root2 = compute_certificate_root(&certs);
        assert_eq!(root1, root2);
        assert_ne!(root1, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_single_cert() {
        let ec = Arc::new(ExecutionCertificate::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(10), BTreeSet::new()),
            WeightedTimestamp::from_millis(11),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt")),
            vec![TxOutcome {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                outcome: ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"rh")),
                },
            }],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ));
        let cert = Arc::new(WaveCertificate {
            wave_id: WaveId::new(ShardGroupId::new(0), BlockHeight::new(10), BTreeSet::new()),
            execution_certificates: vec![ec],
        });
        let expected_receipt_hash = cert.receipt_hash();
        let fw = Arc::new(FinalizedWave {
            certificate: cert,
            receipts: BoundedVec::new(),
        });

        let root = compute_certificate_root(std::slice::from_ref(&fw));
        // Single cert: certificate_root should equal the cert's receipt_hash
        assert_eq!(root.into_raw(), expected_receipt_hash.into_raw());
    }

    #[test]
    fn test_genesis_certificate_root_is_zero() {
        let genesis = Block::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO);
        assert_eq!(genesis.header().certificate_root, CertificateRoot::ZERO);
    }

    #[test]
    fn certified_block_decode_rejects_qc_block_hash_mismatch() {
        use sbor::{DecodeError, basic_decode, basic_encode};

        use crate::CertifiedBlock;

        // Forge a non-genesis block paired with a genesis QC. Without the
        // pairing check at decode this slips past the synced-block apply
        // path's `qc.is_genesis()` quorum-power bypass.
        let mut bad_block =
            Block::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO)
                .into_sealed()
                .into_live(Arc::new(BoundedVec::new()));
        if let Block::Live { ref mut header, .. } = bad_block {
            header.height = BlockHeight::new(7);
        }
        let genesis_qc = QuorumCertificate::genesis(ShardGroupId::new(0));
        let bytes = basic_encode(&CertifiedBlockWire {
            block: bad_block,
            qc: genesis_qc,
        })
        .unwrap();
        let err = basic_decode::<CertifiedBlock>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    /// Wire-shape twin of `CertifiedBlock` that skips the pairing invariant
    /// during encode, so tests can construct adversarial byte streams.
    #[derive(sbor::BasicSbor)]
    #[sbor(transparent_name)]
    struct CertifiedBlockWire {
        block: Block,
        qc: QuorumCertificate,
    }
}
