//! Wave types and utilities for cross-shard execution.
//!
//! Transactions in a block are partitioned into waves by their provision
//! dependency set (the set of remote shards they need provisions from).
//! All validators compute identical wave assignments from block contents,
//! enabling wave-level BLS signature aggregation instead of per-transaction
//! signatures.
//!
//! # Wave Assignment
//!
//! - **Wave ∅** (ZERO): Single-shard txs — no provisions needed
//! - **Wave {B}**: Txs needing provisions only from shard B
//! - **Wave {B,C}**: Txs needing provisions from both B and C
//!
//! Tx ordering within a wave preserves block ordering (stable partition).
//!
//! # Wave Lifecycle
//!
//! 1. [`id::WaveId`] — identity, computed from block contents
//! 2. [`vote::ExecutionVote`] — per-validator BLS vote on wave outcomes
//! 3. [`execution_certificate::ExecutionCertificate`] — aggregated 2f+1 shard-local certificate
//! 4. [`certificate::WaveCertificate`] — cross-shard proof of finalization (holds ECs directly)
//! 5. [`finalized::FinalizedWave`] — all data needed for block commit

pub mod certificate;
pub mod computation;
pub mod execution_certificate;
pub mod finalized;
pub mod id;
pub mod outcome;
pub mod receipt_tree;
pub mod vote;

#[cfg(test)]
mod tests {
    use crate::{
        Attempt, BlockHeight, Bls12381G2Signature, DatabaseUpdates, ExecutionCertificate,
        ExecutionCertificateHash, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, LocalReceipt, NodeId, ProvisionTxRoot, ReceiptBundle,
        ReceiptValidationError, ShardGroupId, SignerBitfield, TopologySnapshot, TransactionOutcome,
        TxHash, TxOutcome, ValidatorId, ValidatorInfo, ValidatorSet, WaveCertificate, WaveId,
        WaveIdHash, WaveReceiptHash, WeightedTimestamp, compute_global_receipt_root,
        compute_global_receipt_root_with_proof, compute_padded_merkle_root,
        compute_provision_tx_roots, decode_wave_cert_vec, encode_wave_cert_vec,
        generate_bls_keypair, test_utils::test_transaction_with_nodes, tx_outcome_leaf,
        wave_leader, wave_leader_at,
    };
    use sbor::prelude::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// Build a 2-shard topology with validator 0 on shard 0.
    fn two_shard_topology() -> TopologySnapshot {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: 1,
            })
            .collect();
        TopologySnapshot::new(ValidatorId(0), 2, ValidatorSet::new(validators))
    }

    /// Find a node seed that routes to `target_shard` under modulo-2 sharding.
    fn node_on_shard(topology: &TopologySnapshot, target_shard: ShardGroupId) -> NodeId {
        for seed in 0u8..=255 {
            let node = NodeId([seed; 30]);
            if topology.shard_for_node_id(&node) == target_shard {
                return node;
            }
        }
        panic!("no node seed routes to {target_shard:?}");
    }

    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
                success: true,
            },
        }
    }

    fn make_wave_id(shard: u64, height: BlockHeight, remote: &[u64]) -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(shard),
            block_height: height,
            remote_shards: remote.iter().map(|&s| ShardGroupId(s)).collect(),
        }
    }

    #[test]
    fn test_wave_id_display() {
        let zero = make_wave_id(0, BlockHeight(42), &[]);
        assert_eq!(zero.to_string(), "Wave(shard=0, h=42, ∅)");

        let wave = make_wave_id(0, BlockHeight(42), &[2, 5]);
        assert_eq!(wave.to_string(), "Wave(shard=0, h=42, {2,5})");
    }

    #[test]
    fn test_wave_id_ordering() {
        let zero = make_wave_id(0, BlockHeight(42), &[]);
        let wave_a = make_wave_id(0, BlockHeight(42), &[1]);
        let wave_b = make_wave_id(0, BlockHeight(42), &[2]);
        let wave_pair = make_wave_id(0, BlockHeight(42), &[1, 2]);

        assert!(zero < wave_a);
        assert!(wave_a < wave_b);
        assert!(wave_a < wave_pair);
    }

    #[test]
    fn test_wave_id_hash_deterministic() {
        let w1 = make_wave_id(0, BlockHeight(42), &[1]);
        let w2 = make_wave_id(0, BlockHeight(42), &[1]);
        assert_eq!(w1.hash(), w2.hash());
        assert_ne!(w1.hash(), WaveIdHash::ZERO);
    }

    #[test]
    fn test_wave_id_hash_differs_by_height() {
        let w1 = make_wave_id(0, BlockHeight(42), &[1]);
        let w2 = make_wave_id(0, BlockHeight(43), &[1]);
        assert_ne!(w1.hash(), w2.hash());
    }

    #[test]
    fn test_compute_provision_tx_roots_empty() {
        let topology = two_shard_topology();
        let map = compute_provision_tx_roots(&topology, &[]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_compute_provision_tx_roots_single_shard_excluded() {
        let topology = two_shard_topology();
        let local_node = node_on_shard(&topology, topology.local_shard());
        let tx = Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![local_node],
            vec![local_node],
        ));
        let map = compute_provision_tx_roots(&topology, &[tx]);
        assert!(map.is_empty(), "single-shard tx must not produce an entry");
    }

    #[test]
    fn test_compute_provision_tx_roots_covers_all_touched_targets() {
        let topology = two_shard_topology();
        let local_node = node_on_shard(&topology, topology.local_shard());
        let remote_node = node_on_shard(&topology, ShardGroupId(1));

        // Cross-shard tx: writes span local shard 0 and remote shard 1.
        let tx_a = Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![],
            vec![local_node, remote_node],
        ));
        let tx_b = Arc::new(test_transaction_with_nodes(
            &[4, 5, 6],
            vec![],
            vec![local_node, remote_node],
        ));

        let roots = compute_provision_tx_roots(&topology, &[tx_a.clone(), tx_b.clone()]);

        // Local shard excluded; only shard 1 receives provisions.
        assert_eq!(roots.len(), 1);
        assert!(roots.contains_key(&ShardGroupId(1)));

        let expected = ProvisionTxRoot::from_raw(compute_padded_merkle_root(&[
            tx_a.hash().into_raw(),
            tx_b.hash().into_raw(),
        ]));
        assert_eq!(roots[&ShardGroupId(1)], expected);
    }

    #[test]
    fn test_global_receipt_root_deterministic() {
        let outcomes = vec![make_outcome(1), make_outcome(2), make_outcome(3)];
        let root1 = compute_global_receipt_root(&outcomes);
        let root2 = compute_global_receipt_root(&outcomes);
        assert_eq!(root1, root2);
        assert_ne!(root1, GlobalReceiptRoot::ZERO);
    }

    #[test]
    fn test_global_receipt_root_single_tx() {
        let outcomes = vec![make_outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let expected = tx_outcome_leaf(&outcomes[0]);
        assert_eq!(root.into_raw(), expected);
    }

    #[test]
    fn test_global_receipt_root_empty() {
        let root = compute_global_receipt_root(&[]);
        assert_eq!(root, GlobalReceiptRoot::ZERO);
    }

    #[test]
    fn test_global_receipt_root_order_matters() {
        let o1 = make_outcome(1);
        let o2 = make_outcome(2);

        let root_12 = compute_global_receipt_root(&[o1.clone(), o2.clone()]);
        let root_21 = compute_global_receipt_root(&[o2, o1]);
        assert_ne!(root_12, root_21);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let outcomes = vec![
            make_outcome(1),
            make_outcome(2),
            make_outcome(3),
            make_outcome(4),
            make_outcome(5),
        ];

        let root = compute_global_receipt_root(&outcomes);

        for i in 0..outcomes.len() {
            let (proof_root, siblings, leaf_index, leaf_hash) =
                compute_global_receipt_root_with_proof(&outcomes, i);

            assert_eq!(proof_root, root.into_raw(), "Root mismatch for index {i}");

            let expected_leaf = tx_outcome_leaf(&outcomes[i]);
            assert_eq!(leaf_hash, expected_leaf, "Leaf hash mismatch for index {i}");

            assert!(
                crate::verify_merkle_inclusion(root.into_raw(), leaf_hash, &siblings, leaf_index),
                "Proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_tx_outcome_leaf_success_matters() {
        let success = TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
                success: true,
            },
        };
        let failure = TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
                success: false,
            },
        };
        assert_ne!(tx_outcome_leaf(&success), tx_outcome_leaf(&failure));
    }

    #[test]
    fn test_tx_outcome_leaf_aborted_differs_from_executed() {
        let executed = TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
                success: true,
            },
        };
        let aborted = TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            outcome: ExecutionOutcome::Aborted,
        };
        assert_ne!(tx_outcome_leaf(&executed), tx_outcome_leaf(&aborted));
    }

    fn make_test_ec(
        signers: SignerBitfield,
        signature: Bls12381G2Signature,
    ) -> ExecutionCertificate {
        ExecutionCertificate::new(
            make_wave_id(0, BlockHeight(10), &[1]),
            WeightedTimestamp(11),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"global_receipt_root")),
            vec![make_outcome(1), make_outcome(2)],
            signature,
            signers,
        )
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let signers = SignerBitfield::new(4);
        let sig = Bls12381G2Signature([0u8; 96]);
        let ec1 = make_test_ec(signers.clone(), sig);
        let ec2 = make_test_ec(signers, sig);
        assert_eq!(ec1.canonical_hash(), ec2.canonical_hash());
        assert_ne!(ec1.canonical_hash(), ExecutionCertificateHash::ZERO);
    }

    #[test]
    fn test_canonical_hash_signer_independent() {
        let mut signers_a = SignerBitfield::new(4);
        signers_a.set(0);
        signers_a.set(1);
        let sig_a = Bls12381G2Signature([1u8; 96]);

        let mut signers_b = SignerBitfield::new(4);
        signers_b.set(2);
        signers_b.set(3);
        let sig_b = Bls12381G2Signature([2u8; 96]);

        let ec_a = make_test_ec(signers_a, sig_a);
        let ec_b = make_test_ec(signers_b, sig_b);

        // Different signers + signatures → same canonical hash
        assert_eq!(ec_a.canonical_hash(), ec_b.canonical_hash());
    }

    #[test]
    fn ec_deadline_is_vote_anchor_ts_plus_retention_horizon() {
        let ec = make_test_wave_ec(0, 1);
        assert_eq!(
            ec.deadline(),
            ec.vote_anchor_ts.plus(crate::RETENTION_HORIZON)
        );
    }

    fn make_test_wave_ec(shard: u64, seed: u8) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            make_wave_id(shard, BlockHeight(42), &[1]),
            WeightedTimestamp(43),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            vec![make_outcome(seed)],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, BlockHeight(42), &[1]),
            execution_certificates: vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        };
        assert_eq!(wc.receipt_hash(), wc.receipt_hash());
        assert_ne!(wc.receipt_hash(), WaveReceiptHash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let wc1 = WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_test_wave_ec(0, 1)],
        };
        let wc2 = WaveCertificate {
            wave_id,
            execution_certificates: vec![make_test_wave_ec(0, 2)],
        };
        assert_ne!(wc1.receipt_hash(), wc2.receipt_hash());
    }

    #[test]
    fn test_wave_cert_sbor_roundtrip() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, BlockHeight(42), &[1]),
            execution_certificates: vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        };
        let encoded = basic_encode(&wc).unwrap();
        let decoded: WaveCertificate = basic_decode(&encoded).unwrap();
        assert_eq!(wc, decoded);
    }

    #[test]
    fn test_arc_vec_sbor_roundtrip() {
        let certs = vec![
            Arc::new(WaveCertificate {
                wave_id: make_wave_id(0, BlockHeight(42), &[1]),
                execution_certificates: vec![make_test_wave_ec(0, 1)],
            }),
            Arc::new(WaveCertificate {
                wave_id: WaveId {
                    shard_group_id: ShardGroupId(0),
                    block_height: BlockHeight(42),
                    remote_shards: BTreeSet::new(),
                },
                execution_certificates: vec![make_test_wave_ec(1, 3)],
            }),
        ];

        // Encode
        let mut buf = Vec::new();
        let mut encoder = sbor::BasicEncoder::new(&mut buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        encode_wave_cert_vec(&mut encoder, &certs).unwrap();

        // Decode
        let mut decoder = sbor::BasicDecoder::new(&buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        let result = decode_wave_cert_vec(&mut decoder, 100).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].as_ref(), certs[0].as_ref());
        assert_eq!(result[1].as_ref(), certs[1].as_ref());
    }

    #[test]
    fn test_wave_leader_is_attempt_zero() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight(100), &[1]);
        assert_eq!(
            wave_leader(&wave_id, &committee),
            wave_leader_at(&wave_id, Attempt::INITIAL, &committee)
        );
    }

    #[test]
    fn test_wave_leader_at_rotates() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight(100), &[1]);
        let mut leaders: std::collections::HashSet<ValidatorId> = std::collections::HashSet::new();
        for attempt in 0..4 {
            leaders.insert(wave_leader_at(&wave_id, Attempt(attempt), &committee));
        }
        // With 4 attempts and 4 committee members, we should get multiple distinct leaders.
        // (Not guaranteed to be all 4 due to hash collisions, but at least 2.)
        assert!(
            leaders.len() >= 2,
            "Expected rotation to produce distinct leaders"
        );
    }

    #[test]
    fn test_wave_leader_at_wraps() {
        let committee = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
        let wave_id = make_wave_id(0, BlockHeight(100), &[1]);
        // Large attempt values should not panic — they wrap via modulo.
        let _ = wave_leader_at(&wave_id, Attempt(1000), &committee);
    }

    #[test]
    fn test_wave_leader_deterministic() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight(100), &[1]);
        let leader1 = wave_leader_at(&wave_id, Attempt(2), &committee);
        let leader2 = wave_leader_at(&wave_id, Attempt(2), &committee);
        assert_eq!(leader1, leader2);
    }

    fn make_local_ec(wave_id: &WaveId, outcomes: Vec<TxOutcome>) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp(wave_id.block_height.0 + 1),
            compute_global_receipt_root(&outcomes),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn make_success_receipt() -> Arc<LocalReceipt> {
        Arc::new(LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        })
    }

    #[test]
    fn reconstruct_from_all_success_outcomes() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b"));

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_b")),
                    success: true,
                },
            },
        ];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()))
            .expect("reconstruction should succeed");
        assert_eq!(fw.tx_count(), 2);
        let hashes: Vec<TxHash> = fw.tx_hashes().collect();
        assert_eq!(hashes, vec![tx_a, tx_b]);
        assert_eq!(fw.receipts.len(), 2);
        assert_eq!(fw.receipts[0].tx_hash, tx_a);
        assert_eq!(fw.receipts[1].tx_hash, tx_b);
    }

    #[test]
    fn reconstruct_skips_aborted_tx_without_receipt() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b_aborted"));

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Aborted,
            },
        ];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        // Lookup returns Some for tx_a, None for tx_b (never persisted — pure abort).
        let fw = FinalizedWave::reconstruct(wc, |h| {
            if *h == tx_a {
                Some(make_success_receipt())
            } else {
                None
            }
        })
        .expect("aborted tx without receipt should be skipped, not fail");

        assert_eq!(fw.tx_count(), 2);
        assert_eq!(fw.receipts.len(), 1);
        assert_eq!(fw.receipts[0].tx_hash, tx_a);
    }

    #[test]
    fn reconstruct_fails_when_non_aborted_receipt_missing() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));

        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                success: true,
            },
        }];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        let fw = FinalizedWave::reconstruct(wc, |_| None);
        assert!(
            fw.is_none(),
            "reconstruction should fail when non-aborted receipt is missing"
        );
    }

    #[test]
    fn reconstruct_fails_when_local_ec_missing() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let remote_wave_id = make_wave_id(1, BlockHeight(42), &[0]);
        let remote_ec = make_local_ec(
            &remote_wave_id,
            vec![TxOutcome {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
                outcome: ExecutionOutcome::Aborted,
            }],
        );
        let wc = Arc::new(WaveCertificate {
            wave_id,
            execution_certificates: vec![remote_ec],
        });

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()));
        assert!(fw.is_none(), "reconstruction requires the local EC");
    }

    fn make_failure_receipt() -> Arc<LocalReceipt> {
        Arc::new(LocalReceipt {
            outcome: TransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        })
    }

    #[test]
    fn validate_accepts_receipts_matching_outcomes() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b_aborted"));
        let tx_c = TxHash::from_raw(Hash::from_bytes(b"tx_c_fail"));

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Aborted,
            },
            TxOutcome {
                tx_hash: tx_c,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    success: false,
                },
            },
        ];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![
                ReceiptBundle {
                    tx_hash: tx_a,
                    local_receipt: make_success_receipt(),
                    execution_output: None,
                },
                ReceiptBundle {
                    tx_hash: tx_c,
                    local_receipt: make_failure_receipt(),
                    execution_output: None,
                },
            ],
        };
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }

    #[test]
    fn validate_rejects_outcome_flip() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_a,
                local_receipt: make_failure_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::OutcomeMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_receipt() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_extra_receipt() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Aborted,
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_a,
                local_receipt: make_success_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::ExtraReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_tx_hash_mismatch() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b"));
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_b,
                local_receipt: make_success_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::TxHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_local_ec() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let remote_wave_id = make_wave_id(1, BlockHeight(42), &[0]);
        let remote_ec = make_local_ec(&remote_wave_id, vec![]);
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![remote_ec],
            }),
            receipts: vec![],
        };
        assert_eq!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingLocalEc)
        );
    }

    #[test]
    fn validate_all_aborted_wave_with_empty_receipts_passes() {
        let wave_id = make_wave_id(0, BlockHeight(42), &[1]);
        let outcomes = vec![TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"aborted")),
            outcome: ExecutionOutcome::Aborted,
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![],
        };
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }
}
