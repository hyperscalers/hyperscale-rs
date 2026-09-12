//! Shard consensus types.
//!
//! - [`block`]: [`Block`] (the Live/Sealed enum).
//! - [`certified`]: [`CertifiedBlock`] pairing of a block with its certifying QC.
//! - [`certified_header`]: [`CertifiedBlockHeader`] cross-shard trust attestation.
//! - [`evidence`]: [`ShardVoteEquivocation`] self-proving double-vote evidence.
//! - [`demands`]: what a block [`Demands`](demands::Demands) be checked
//!   before a vote, and how one [`CheckOutcome`](demands::CheckOutcome) ends.
//! - [`fork_fence`]: [`ForkFence`](fork_fence::ForkFence) — the gossip-timed
//!   quiesce every cross-shard consumer engages against a proven fork.
//! - [`header`]: [`BlockHeader`] (shard-voted metadata).
//! - [`limits`]: protocol-level caps on per-block payload sizes.
//! - [`load`]: [`ShardLoad`](load::ShardLoad) — the attested-work and
//!   stored-byte totals a header attests, which the beacon reweights
//!   emission by.
//! - [`manifest`]: hash-level [`BlockManifest`] and denormalized [`BlockMetadata`].
//! - [`quorum_certificate`]: [`QuorumCertificate`] aggregating shard consensus votes.
//! - [`roots`]: per-block merkle root helpers used by [`BlockHeader`] consumers.
//! - [`storage_commit`]: type-erased [`PreparedCommit`](storage_commit::PreparedCommit)
//!   closure, [`SyncHint`](storage_commit::SyncHint), and
//!   [`BeaconWitnessCommit`](storage_commit::BeaconWitnessCommit) payload
//!   threaded through shard block commits.
//! - [`timeout`]: [`Timeout`] view-change share that drives the pacemaker.
//! - [`vote`]: [`BlockVote`] shard consensus vote.
//! - [`vote_registers`]: snapshot type for the two monotone safe-vote
//!   registers ([`SafeVoteRegisters`](vote_registers::SafeVoteRegisters)).
//! - [`witness_sources`]: [`WitnessSources`] — the proposer-supplied
//!   beacon-witness inputs a block carries.

pub mod abandonment;
pub mod anchor;
#[allow(clippy::module_inception)]
mod block;
pub mod certified;
pub mod certified_header;
pub mod chain_origin;
pub mod commit_proof;
pub mod counterpart_mirror;
pub mod demands;
pub mod evidence;
pub mod fork_fence;
pub mod header;
pub mod inventory;
pub mod limits;
pub mod load;
pub mod manifest;
pub mod proven_anchors;
pub mod proven_cells;
pub mod quorum_certificate;
pub mod reshape;
pub mod roots;
pub mod state_claim;
pub mod storage_commit;
pub mod sweep;
pub mod timeout;
pub mod vote;
pub mod vote_registers;
pub mod witness_sources;

pub use block::{
    Block, SharedCertificates, SharedProvisions, SharedTransactions, TerminalRef,
    VerifiedBlockAssembleError, derive_block_transactions, fees_over_certificates,
};
pub use witness_sources::{SharedWitnessSources, WitnessSources};

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use hyperscale_hbor::{
        DecodeError, Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
    };

    use super::*;
    use crate::test_utils::{
        install_stub_protocol_statics, stub_transaction, test_prefix, test_principal,
        test_validity_range,
    };
    use crate::{
        AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot,
        ChainOrigin, ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, ProposerTimestamp, QuorumCertificate, ShardId, SignerBitfield,
        StateRoot, TickHalf, TickId, TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable,
        Verified, WeightedTimestamp,
    };

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(1, 0),
            height: BlockHeight::new(1),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        });

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight::new(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header().transaction_root(), TransactionRoot::ZERO);
        assert_eq!(
            genesis.header().parent_qc(),
            &QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT)
        );
    }

    #[test]
    fn test_compute_transaction_root_empty() {
        let root = Verified::<TransactionRoot>::compute(&[]).into_inner();
        assert_eq!(root, TransactionRoot::ZERO);
    }

    #[test]
    fn test_compute_transaction_root_deterministic() {
        install_stub_protocol_statics();
        let tx = Arc::new(Verifiable::from(stub_transaction(
            test_principal(1),
            &[test_prefix(2)],
            1_000,
            test_validity_range(),
        )));

        let root1 = Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx)).into_inner();
        let root2 = Verified::<TransactionRoot>::compute(std::slice::from_ref(&tx)).into_inner();
        assert_eq!(root1, root2);
        assert_ne!(root1, TransactionRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_empty() {
        let root = Verified::<CertificateRoot>::compute(&[]).into_inner();
        assert_eq!(root, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_deterministic() {
        let make_fw = |seed: u8| -> Arc<Verifiable<Finalization>> {
            let ec = Arc::new(ExecutionCertificate::new(
                TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10)),
                WeightedTimestamp::from_millis(11),
                GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 100; 4])),
                vec![TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&[seed; 4])),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(
                            &[seed + 50; 4],
                        )),
                    },
                )],
                AggregateSignature::new([0u8; 96]),
                SignerBitfield::new(4),
            ));
            Arc::new(
                Finalization::new(
                    TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10)),
                    TickHalf::Determined,
                    vec![ec],
                    vec![],
                )
                .into(),
            )
        };

        let certs = vec![make_fw(1), make_fw(2)];
        let root1 = Verified::<CertificateRoot>::compute(&certs).into_inner();
        let root2 = Verified::<CertificateRoot>::compute(&certs).into_inner();
        assert_eq!(root1, root2);
        assert_ne!(root1, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_single_cert() {
        let ec = Arc::new(ExecutionCertificate::new(
            TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10)),
            WeightedTimestamp::from_millis(11),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt")),
            vec![TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"tx1")),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"rh")),
                },
            )],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ));
        let cert = Finalization::new(
            TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10)),
            TickHalf::Determined,
            vec![ec],
            vec![],
        );
        let expected_receipt_hash = cert.receipt_hash();
        let fw: Arc<Verifiable<Finalization>> = Arc::new(cert.into());

        let root = Verified::<CertificateRoot>::compute(std::slice::from_ref(&fw)).into_inner();
        // Single cert: certificate_root should equal the cert's receipt_hash
        assert_eq!(root.into_raw(), expected_receipt_hash.into_raw());
    }

    #[test]
    fn test_genesis_certificate_root_is_zero() {
        let genesis = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        assert_eq!(genesis.header().certificate_root(), CertificateRoot::ZERO);
    }

    #[test]
    fn certified_block_decode_rejects_qc_block_hash_mismatch() {
        use crate::CertifiedBlock;

        // Forge a non-genesis block paired with a genesis QC. Without the
        // pairing check at decode this slips past the synced-block apply
        // path's `qc.is_genesis()` quorum-power bypass.
        let mut bad_block = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        )
        .into_sealed()
        .into_live(Arc::new(Vec::new()));
        if let Block::Live { ref mut header, .. } = bad_block {
            *header = BlockHeader::new(BlockHeaderParts {
                shard_id: header.shard_id(),
                height: BlockHeight::new(7),
                parent_block_hash: header.parent_block_hash(),
                parent_qc: header.parent_qc().clone().into(),
                proposer: header.proposer(),
                timestamp: header.timestamp(),
                round: header.round(),
                is_fallback: header.is_fallback(),
                state_root: header.state_root(),
                transaction_root: header.transaction_root(),
                certificate_root: header.certificate_root(),
                local_receipt_root: header.local_receipt_root(),
                provision_root: header.provision_root(),
                provision_tx_roots: header.provision_tx_roots().clone(),
                txs_in_flight: header.txs_in_flight(),
                beacon_witness_root: header.beacon_witness_root(),
                beacon_witness_leaf_count: header.beacon_witness_leaf_count(),
                beacon_witness_base: header.beacon_witness_base(),
                ..Default::default()
            });
        }
        let genesis_qc = QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT);
        let bytes = hbor_to_vec(&CertifiedBlockWire {
            block: bad_block,
            qc: genesis_qc,
        })
        .unwrap();
        let err = hbor_from_slice::<CertifiedBlock>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    /// Wire-shape twin of `CertifiedBlock` that skips the pairing invariant
    /// during encode, so tests can construct adversarial byte streams.
    #[derive(Hbor)]
    struct CertifiedBlockWire {
        block: Block,
        qc: QuorumCertificate,
    }
}
