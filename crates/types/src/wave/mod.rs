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
    use std::collections::HashSet;
    use std::sync::Arc;

    use sbor::BASIC_SBOR_V1_MAX_DEPTH;
    use sbor::prelude::*;

    use crate::test_utils::test_transaction_with_nodes;
    use crate::{
        Attempt, BlockHeight, Bls12381G2Signature, ConsensusReceipt, DatabaseUpdates,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, NetworkDefinition, NodeId, ProvisionTxRoot, ProvisionTxRootsMap,
        RETENTION_HORIZON, ReceiptValidationError, ShardGroupId, SignerBitfield, StoredReceipt,
        TopologySnapshot, TxHash, TxOutcome, ValidatorId, ValidatorInfo, ValidatorSet, Verified,
        VotePower, WaveCertificate, WaveId, WaveReceiptHash, WeightedTimestamp,
        compute_global_receipt_root, compute_global_receipt_root_with_proof, compute_merkle_root,
        generate_bls_keypair, tx_outcome_leaf, verify_merkle_inclusion, wave_leader,
        wave_leader_at,
    };

    /// Build a 2-shard topology with validator 0 on shard 0.
    fn two_shard_topology() -> TopologySnapshot {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: VotePower::new(1),
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            ValidatorId::new(0),
            2,
            ValidatorSet::new(validators),
        )
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
        TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            },
        )
    }

    fn make_wave_id(shard: u64, height: BlockHeight, remote: &[u64]) -> WaveId {
        WaveId::new(
            ShardGroupId::new(shard),
            height,
            remote.iter().map(|&s| ShardGroupId::new(s)).collect(),
        )
    }

    #[test]
    fn test_wave_id_display() {
        let zero = make_wave_id(0, BlockHeight::new(42), &[]);
        assert_eq!(zero.to_string(), "Wave(shard=0, h=42, ∅)");

        let wave = make_wave_id(0, BlockHeight::new(42), &[2, 5]);
        assert_eq!(wave.to_string(), "Wave(shard=0, h=42, {2,5})");
    }

    #[test]
    fn test_wave_id_ordering() {
        let zero = make_wave_id(0, BlockHeight::new(42), &[]);
        let wave_a = make_wave_id(0, BlockHeight::new(42), &[1]);
        let wave_b = make_wave_id(0, BlockHeight::new(42), &[2]);
        let wave_pair = make_wave_id(0, BlockHeight::new(42), &[1, 2]);

        assert!(zero < wave_a);
        assert!(wave_a < wave_b);
        assert!(wave_a < wave_pair);
    }

    #[test]
    fn test_wave_id_deterministic() {
        let w1 = make_wave_id(0, BlockHeight::new(42), &[1]);
        let w2 = make_wave_id(0, BlockHeight::new(42), &[1]);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_wave_id_differs_by_height() {
        let w1 = make_wave_id(0, BlockHeight::new(42), &[1]);
        let w2 = make_wave_id(0, BlockHeight::new(43), &[1]);
        assert_ne!(w1, w2);
    }

    #[test]
    fn test_compute_provision_tx_roots_empty() {
        let topology = two_shard_topology();
        let map = Verified::<ProvisionTxRootsMap>::compute(&topology, &[]);
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
        let map = Verified::<ProvisionTxRootsMap>::compute(&topology, &[tx]);
        assert!(map.is_empty(), "single-shard tx must not produce an entry");
    }

    #[test]
    fn test_compute_provision_tx_roots_covers_all_touched_targets() {
        let topology = two_shard_topology();
        let local_node = node_on_shard(&topology, topology.local_shard());
        let remote_node = node_on_shard(&topology, ShardGroupId::new(1));

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

        let roots =
            Verified::<ProvisionTxRootsMap>::compute(&topology, &[tx_a.clone(), tx_b.clone()]);

        // Local shard excluded; only shard 1 receives provisions.
        assert_eq!(roots.len(), 1);
        assert!(roots.contains_key(&ShardGroupId::new(1)));

        let expected = ProvisionTxRoot::from_raw(compute_merkle_root(&[
            tx_a.hash().into_raw(),
            tx_b.hash().into_raw(),
        ]));
        assert_eq!(roots[&ShardGroupId::new(1)], expected);
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
                verify_merkle_inclusion(root.into_raw(), leaf_hash, &siblings, leaf_index),
                "Proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_tx_outcome_leaf_success_matters() {
        let success = TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            },
        );
        let failure = TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Failed,
        );
        assert_ne!(tx_outcome_leaf(&success), tx_outcome_leaf(&failure));
    }

    #[test]
    fn test_tx_outcome_leaf_aborted_differs_from_executed() {
        let executed = TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            },
        );
        let aborted = TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Aborted,
        );
        assert_ne!(tx_outcome_leaf(&executed), tx_outcome_leaf(&aborted));
    }

    #[test]
    fn ec_deadline_is_vote_anchor_ts_plus_retention_horizon() {
        let ec = make_test_wave_ec(0, 1);
        assert_eq!(ec.deadline(), ec.vote_anchor_ts().plus(RETENTION_HORIZON));
    }

    fn make_test_wave_ec(shard: u64, seed: u8) -> Arc<ExecutionCertificate> {
        let outcomes = vec![make_outcome(seed)];
        let global_receipt_root = compute_global_receipt_root(&outcomes);
        Arc::new(ExecutionCertificate::new(
            make_wave_id(shard, BlockHeight::new(42), &[1]),
            WeightedTimestamp::from_millis(43),
            global_receipt_root,
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let wc = WaveCertificate::new(
            make_wave_id(0, BlockHeight::new(42), &[1]),
            vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        );
        assert_eq!(wc.receipt_hash(), wc.receipt_hash());
        assert_ne!(wc.receipt_hash(), WaveReceiptHash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec() {
        // `receipt_hash` commits to `(shard_group_id, wave_id)` pairs, so two
        // ECs with distinct wave_ids must produce distinct receipt hashes.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let wc1 = WaveCertificate::new(wave_id.clone(), vec![make_test_wave_ec(0, 1)]);
        let wc2 = WaveCertificate::new(wave_id, vec![make_test_wave_ec(1, 2)]);
        assert_ne!(wc1.receipt_hash(), wc2.receipt_hash());
    }

    #[test]
    fn test_wave_cert_sbor_roundtrip() {
        let wc = WaveCertificate::new(
            make_wave_id(0, BlockHeight::new(42), &[1]),
            vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        );
        let encoded = basic_encode(&wc).unwrap();
        let decoded: WaveCertificate = basic_decode(&encoded).unwrap();
        assert_eq!(wc, decoded);
    }

    #[test]
    fn decode_rejects_wave_cert_missing_local_ec() {
        use sbor::DecodeError;
        // WC's wave_id has shard=0 but its only EC is for shard=1, so no
        // ec.wave_id() matches wc.wave_id. Pre-fix this decoded successfully
        // and then panicked the IO loop on first call to local_ec().
        let wc = WaveCertificate::new(
            make_wave_id(0, BlockHeight::new(42), &[1]),
            vec![make_test_wave_ec(1, 1)],
        );
        let bytes = basic_encode(&wc).unwrap();
        let err = basic_decode::<WaveCertificate>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    /// The exactly-one-local-EC invariant rejects WCs with more than one
    /// EC matching `wc.wave_id`. Without this, downstream helpers like
    /// `FinalizedWave::local_ec()` would silently pick the first match,
    /// letting two paths disagree on which EC is authoritative.
    #[test]
    fn decode_rejects_wave_cert_with_multiple_local_ecs() {
        use sbor::DecodeError;

        // Build two ECs both keyed to the same wave_id (shard=0, h=42, deps={1}).
        // Distinct seeds yield distinct canonical hashes so the inner
        // EC-decode invariants don't reject before we get to the local-EC
        // count check.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let ec_a = make_local_ec(&wave_id, vec![make_outcome(1)]);
        let ec_b = make_local_ec(&wave_id, vec![make_outcome(2)]);
        let wc = WaveCertificate::new(wave_id, vec![ec_a, ec_b]);
        let bytes = basic_encode(&wc).unwrap();
        let err = basic_decode::<WaveCertificate>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    #[test]
    fn decode_rejects_wave_cert_with_oversized_ec_count() {
        use sbor::{
            BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder, NoCustomValueKind, ValueKind,
            VecEncoder,
        };
        // Hand-roll a WC whose execution_certificates count exceeds the
        // decoder cap, before any per-EC decode work happens.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let mut buf = Vec::with_capacity(64);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(2).unwrap();
            enc.encode(&wave_id).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            // 1024 + 1 — first value above the decoder cap.
            enc.write_size(1025).unwrap();
        }
        let err = basic_decode::<WaveCertificate>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 1024,
                actual: 1025
            }
        ));
    }

    #[test]
    fn decode_rejects_oversized_tx_outcomes_count() {
        use sbor::{
            BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder, NoCustomValueKind, ValueKind,
            VecEncoder,
        };

        use crate::{GlobalReceiptRoot, MAX_TXS_PER_BLOCK, TxOutcome};

        let wave_id = make_wave_id(0, BlockHeight::new(1), &[1]);
        let mut buf = Vec::with_capacity(128);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(6).unwrap();
            enc.encode(&wave_id).unwrap();
            enc.encode(&WeightedTimestamp::ZERO).unwrap();
            enc.encode(&GlobalReceiptRoot::ZERO).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(TxOutcome::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<ExecutionCertificate>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_TXS_PER_BLOCK,
                actual,
            } if actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_tx_outcomes_not_matching_receipt_root() {
        use sbor::{
            BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder, NoCustomValueKind, ValueKind,
            VecEncoder, basic_decode,
        };

        use crate::{Bls12381G2Signature, GlobalReceiptRoot, SignerBitfield, TxOutcome};

        // Encode an EC where global_receipt_root is ZERO but tx_outcomes is
        // a non-empty list whose merkle root is non-zero. The BLS aggregate
        // commits only to (root, count); without the decode-time check a
        // peer could ship this through every downstream consumer.
        let wave_id = make_wave_id(0, BlockHeight::new(7), &[1]);
        let outcomes = vec![make_outcome(1), make_outcome(2)];
        let real_root = compute_global_receipt_root(&outcomes);
        assert_ne!(real_root, GlobalReceiptRoot::ZERO);

        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(6).unwrap();
            enc.encode(&wave_id).unwrap();
            enc.encode(&WeightedTimestamp::from_millis(1)).unwrap();
            enc.encode(&GlobalReceiptRoot::ZERO).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(TxOutcome::value_kind()).unwrap();
            enc.write_size(outcomes.len()).unwrap();
            for outcome in &outcomes {
                enc.encode_deeper_body(outcome).unwrap();
            }
            enc.encode(&Bls12381G2Signature([0u8; 96])).unwrap();
            enc.encode(&SignerBitfield::new(4)).unwrap();
        }
        let err = basic_decode::<ExecutionCertificate>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    /// Decoding a single `FinalizedWave` directly (not through
    /// `decode_finalized_wave_vec`) must still bound the receipts vec.
    /// Without the inline cap a peer could ship a basic-decoded
    /// `FinalizedWave` with billions of claimed receipts.
    #[test]
    fn decode_rejects_finalized_wave_with_oversized_receipts_count() {
        use sbor::{
            BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder, NoCustomValueKind, ValueKind,
            VecEncoder, basic_decode,
        };

        use crate::MAX_TXS_PER_BLOCK;

        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let wc = WaveCertificate::new(wave_id.clone(), vec![make_local_ec(&wave_id, vec![])]);

        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(2).unwrap();
            enc.encode(&wc).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(StoredReceipt::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<FinalizedWave>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_TXS_PER_BLOCK,
                actual,
            } if actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn test_wave_leader_is_attempt_zero() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight::new(100), &[1]);
        assert_eq!(
            wave_leader(&wave_id, &committee),
            wave_leader_at(&wave_id, Attempt::INITIAL, &committee)
        );
    }

    #[test]
    fn test_wave_leader_at_rotates() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight::new(100), &[1]);
        let mut leaders: HashSet<ValidatorId> = HashSet::new();
        for attempt in 0..4 {
            leaders.insert(wave_leader_at(&wave_id, Attempt::new(attempt), &committee));
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
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
        ];
        let wave_id = make_wave_id(0, BlockHeight::new(100), &[1]);
        // Large attempt values should not panic — they wrap via modulo.
        let _ = wave_leader_at(&wave_id, Attempt::new(1000), &committee);
    }

    #[test]
    fn test_wave_leader_deterministic() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let wave_id = make_wave_id(0, BlockHeight::new(100), &[1]);
        let leader1 = wave_leader_at(&wave_id, Attempt::new(2), &committee);
        let leader2 = wave_leader_at(&wave_id, Attempt::new(2), &committee);
        assert_eq!(leader1, leader2);
    }

    fn make_local_ec(wave_id: &WaveId, outcomes: Vec<TxOutcome>) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(wave_id.block_height().inner() + 1),
            compute_global_receipt_root(&outcomes),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn make_success_receipt() -> Arc<ConsensusReceipt> {
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
            beacon_witness_events: Vec::new(),
        })
    }

    #[test]
    fn reconstruct_from_all_success_outcomes() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b"));

        let outcomes = vec![
            TxOutcome::new(
                tx_a,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                },
            ),
            TxOutcome::new(
                tx_b,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_b")),
                },
            ),
        ];
        let wc = Arc::new(WaveCertificate::new(
            wave_id.clone(),
            vec![make_local_ec(&wave_id, outcomes)],
        ));

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()))
            .expect("reconstruction should succeed");
        assert_eq!(fw.tx_count(), 2);
        let hashes: Vec<TxHash> = fw.tx_hashes().collect();
        assert_eq!(hashes, vec![tx_a, tx_b]);
        assert_eq!(fw.receipts().len(), 2);
        assert_eq!(fw.receipts()[0].tx_hash, tx_a);
        assert_eq!(fw.receipts()[1].tx_hash, tx_b);
    }

    #[test]
    fn reconstruct_skips_aborted_tx_without_receipt() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b_aborted"));

        let outcomes = vec![
            TxOutcome::new(
                tx_a,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                },
            ),
            TxOutcome::new(tx_b, ExecutionOutcome::Aborted),
        ];
        let wc = Arc::new(WaveCertificate::new(
            wave_id.clone(),
            vec![make_local_ec(&wave_id, outcomes)],
        ));

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
        assert_eq!(fw.receipts().len(), 1);
        assert_eq!(fw.receipts()[0].tx_hash, tx_a);
    }

    #[test]
    fn reconstruct_fails_when_non_aborted_receipt_missing() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));

        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
            },
        )];
        let wc = Arc::new(WaveCertificate::new(
            wave_id.clone(),
            vec![make_local_ec(&wave_id, outcomes)],
        ));

        let fw = FinalizedWave::reconstruct(wc, |_| None);
        assert!(
            fw.is_none(),
            "reconstruction should fail when non-aborted receipt is missing"
        );
    }

    #[test]
    fn reconstruct_fails_when_local_ec_missing() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let remote_wave_id = make_wave_id(1, BlockHeight::new(42), &[0]);
        let remote_ec = make_local_ec(
            &remote_wave_id,
            vec![TxOutcome::new(
                TxHash::from_raw(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Aborted,
            )],
        );
        let wc = Arc::new(WaveCertificate::new(wave_id, vec![remote_ec]));

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()));
        assert!(fw.is_none(), "reconstruction requires the local EC");
    }

    #[test]
    fn validate_accepts_receipts_matching_outcomes() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b_aborted"));
        let tx_c = TxHash::from_raw(Hash::from_bytes(b"tx_c_fail"));

        let outcomes = vec![
            TxOutcome::new(
                tx_a,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            ),
            TxOutcome::new(tx_b, ExecutionOutcome::Aborted),
            TxOutcome::new(tx_c, ExecutionOutcome::Failed),
        ];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![
                StoredReceipt {
                    tx_hash: tx_a,
                    consensus: Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                        database_updates: DatabaseUpdates::default(),
                        application_events: vec![],
                        beacon_witness_events: Vec::new(),
                    }),
                    metadata: None,
                },
                StoredReceipt {
                    tx_hash: tx_c,
                    consensus: Arc::new(ConsensusReceipt::Failed),
                    metadata: None,
                },
            ],
        );
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }

    #[test]
    fn validate_rejects_unexpected_failure() {
        // EC says Succeeded, receipt says Failed.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Failed),
                metadata: None,
            }],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::UnexpectedFailure { .. })
        ));
    }

    #[test]
    fn validate_rejects_unexpected_success() {
        // EC says Failed, receipt says Succeeded.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(tx_a, ExecutionOutcome::Failed)];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    database_updates: DatabaseUpdates::default(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }),
                metadata: None,
            }],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::UnexpectedSuccess { .. })
        ));
    }

    #[test]
    fn validate_rejects_receipt_hash_mismatch() {
        // Both Succeeded but receipt_hashes disagree — divergent state for the same tx.
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let ec_hash = GlobalReceiptHash::from_raw(Hash::from_bytes(b"ec"));
        let receipt_hash = GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: ec_hash,
            },
        )];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash,
                    database_updates: DatabaseUpdates::default(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }),
                metadata: None,
            }],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::ReceiptHashMismatch { expected, actual, .. })
                if expected == ec_hash && actual == receipt_hash
        ));
    }

    #[test]
    fn validate_rejects_missing_receipt() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_extra_receipt() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(tx_a, ExecutionOutcome::Aborted)];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    database_updates: DatabaseUpdates::default(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }),
                metadata: None,
            }],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::ExtraReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_tx_hash_mismatch() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"tx_b"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![StoredReceipt {
                tx_hash: tx_b,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    database_updates: DatabaseUpdates::default(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }),
                metadata: None,
            }],
        );
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::TxHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_local_ec() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let remote_wave_id = make_wave_id(1, BlockHeight::new(42), &[0]);
        let remote_ec = make_local_ec(&remote_wave_id, vec![]);
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![remote_ec])),
            vec![],
        );
        assert_eq!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingLocalEc)
        );
    }

    #[test]
    fn validate_all_aborted_wave_with_empty_receipts_passes() {
        let wave_id = make_wave_id(0, BlockHeight::new(42), &[1]);
        let outcomes = vec![TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(b"aborted")),
            ExecutionOutcome::Aborted,
        )];
        let fw = FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                wave_id.clone(),
                vec![make_local_ec(&wave_id, outcomes)],
            )),
            vec![],
        );
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }
}
