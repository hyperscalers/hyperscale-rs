//! Block types for consensus.
//!
//! - [`header`]: [`BlockHeader`] (BFT-voted metadata).
//! - [`block`]: [`Block`] (the Live/Sealed enum + manual SBOR encoding).
//! - [`manifest`]: hash-level [`BlockManifest`] and denormalized [`BlockMetadata`].
//! - [`committed_header`]: [`CommittedBlockHeader`] cross-shard trust attestation.
//! - [`certified`]: [`CertifiedBlock`] pairing of a block with its certifying QC.
//! - [`vote`]: [`BlockVote`] BFT vote.
//! - [`roots`]: per-block merkle root helpers used by [`BlockHeader`] consumers.

#[allow(clippy::module_inception)]
mod block;
pub mod certified;
pub mod committed_header;
pub mod header;
pub mod manifest;
pub mod roots;
pub mod vote;

pub use block::Block;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeader, BlockHeight, Bls12381G2Signature, CertificateRoot,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot, TxHash,
        TxOutcome, ValidatorId, WaveCertificate, WaveId, WeightedTimestamp,
        compute_certificate_root, compute_transaction_root, generate_ed25519_keypair,
        routable_from_notarized_v1, sign_and_notarize,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(1),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
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
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), StateRoot::ZERO);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header().transaction_root, TransactionRoot::ZERO);
        assert_eq!(genesis.header().parent_qc, QuorumCertificate::genesis());
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
        let tx = Arc::new(
            routable_from_notarized_v1(notarized, crate::test_utils::test_validity_range())
                .unwrap(),
        );

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
                    ShardGroupId(0),
                    BlockHeight(10),
                    BTreeSet::from([ShardGroupId(1)]),
                ),
                WeightedTimestamp(11),
                GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 100; 4])),
                vec![TxOutcome {
                    tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
                    outcome: ExecutionOutcome::Executed {
                        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(
                            &[seed + 50; 4],
                        )),
                        success: true,
                    },
                }],
                Bls12381G2Signature([0u8; 96]),
                SignerBitfield::new(4),
            ));
            Arc::new(FinalizedWave {
                certificate: Arc::new(WaveCertificate {
                    wave_id: WaveId::new(
                        ShardGroupId(0),
                        BlockHeight(10),
                        BTreeSet::from([ShardGroupId(1)]),
                    ),
                    execution_certificates: vec![ec],
                }),
                receipts: vec![],
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
            WaveId::new(ShardGroupId(0), BlockHeight(10), BTreeSet::new()),
            WeightedTimestamp(11),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt")),
            vec![TxOutcome {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"rh")),
                    success: true,
                },
            }],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ));
        let cert = Arc::new(WaveCertificate {
            wave_id: WaveId::new(ShardGroupId(0), BlockHeight(10), BTreeSet::new()),
            execution_certificates: vec![ec],
        });
        let expected_receipt_hash = cert.receipt_hash();
        let fw = Arc::new(FinalizedWave {
            certificate: cert,
            receipts: vec![],
        });

        let root = compute_certificate_root(std::slice::from_ref(&fw));
        // Single cert: certificate_root should equal the cert's receipt_hash
        assert_eq!(root.into_raw(), expected_receipt_hash.into_raw());
    }

    #[test]
    fn test_genesis_certificate_root_is_zero() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), StateRoot::ZERO);
        assert_eq!(genesis.header().certificate_root, CertificateRoot::ZERO);
    }
}
