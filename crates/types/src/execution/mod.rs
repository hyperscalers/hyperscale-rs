//! What a shard attests about the transactions it executes.
//!
//! A shard executes the transactions a block commits as one batch — the
//! tick — and attests the batch's outcomes together, so one aggregate
//! signature and one cross-shard exchange cover every transaction in it
//! rather than one apiece.
//!
//! A batch is not homogeneous. It carries whatever the tick admitted:
//! transactions that reach beyond this shard alongside transactions that
//! do not. Which of the two a transaction is decides whether its
//! contributions are provisional and whether a counterpart's verdict can
//! still abort it, so both are per-transaction facts rather than
//! properties of the batch.
//!
//! # Lifecycle
//!
//! 1. [`tick_id::TickId`] — the batch's identity: its shard, and the
//!    height of the block whose commit chained it onto the last
//! 2. [`vote::ExecutionVote`] — per-validator signed vote on the batch's
//!    outcomes
//! 3. [`execution_certificate::ExecutionCertificate`] — the aggregated
//!    2f+1 shard-local certificate over them
//! 4. [`finalization::Finalization`] — every participating shard's
//!    certificate for one batch, which is what proves a cross-shard
//!    transaction reached the same verdict everywhere, plus the local
//!    receipts: everything a block needs to commit the outcome

pub mod computation;
pub mod execution_certificate;
pub mod finalization;
pub mod outcome;
pub mod receipt_tree;
pub mod tick_id;
pub mod vote;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_hbor::{
        Capped, DecodeError, Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use crate::test_utils::{test_prefix, test_transaction_with_prefixes};
    use crate::{
        Address, AggregateSignature, Attempt, BlockHeight, ConsensusReceipt, ExecutionCertificate,
        ExecutionOutcome, Finalization, FinalizationHash, GlobalReceiptHash, GlobalReceiptRoot,
        Hash, MAX_EXECUTION_CERTIFICATES_PER_TICK, NetworkDefinition, ProvisionTxRoot,
        ProvisionTxRootsMap, RETENTION_HORIZON, ReceiptValidationError, ShardId, SignerBitfield,
        StateWrites, StoredReceipt, TickHalf, TickId, TopologySnapshot, TxHash, TxOutcome,
        ValidatorId, ValidatorInfo, ValidatorSet, Verifiable, Verified, WeightedTimestamp,
        compute_global_receipt_root, compute_global_receipt_root_with_proof, compute_merkle_root,
        tick_leader, tick_leader_at, tx_outcome_leaf, verify_merkle_inclusion,
    };

    /// Build a 2-shard topology with validator 0 on shard 0.
    fn two_shard_topology() -> TopologySnapshot {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        )
    }

    /// Find a node seed that routes to `target_shard` under 2-way sharding.
    fn prefix_on_shard(topology_snapshot: &TopologySnapshot, target_shard: ShardId) -> Address {
        for seed in 0u8..=255 {
            let prefix = test_prefix(seed);
            if topology_snapshot.shard_for_prefix(prefix) == target_shard {
                return prefix;
            }
        }
        panic!("no prefix seed routes to {target_shard:?}");
    }

    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            },
        )
    }

    fn make_tick_id(shard: u64, height: BlockHeight) -> TickId {
        TickId::new(ShardId::leaf(3, shard), height)
    }

    #[test]
    fn tick_id_is_deterministic() {
        let w1 = make_tick_id(0, BlockHeight::new(42));
        let w2 = make_tick_id(0, BlockHeight::new(42));
        assert_eq!(w1, w2);
    }

    #[test]
    fn tick_id_differs_by_height() {
        let w1 = make_tick_id(0, BlockHeight::new(42));
        let w2 = make_tick_id(0, BlockHeight::new(43));
        assert_ne!(w1, w2);
    }

    #[test]
    fn test_compute_provision_tx_roots_empty() {
        let topology_snapshot = two_shard_topology();
        let map = Verified::<ProvisionTxRootsMap>::compute(
            ShardId::leaf(1, 0),
            &topology_snapshot,
            &[],
            &[],
        );
        assert!(map.is_empty());
    }

    #[test]
    fn test_compute_provision_tx_roots_single_shard_excluded() {
        let topology_snapshot = two_shard_topology();
        let local_prefix = prefix_on_shard(&topology_snapshot, ShardId::leaf(1, 0));
        let tx = Arc::new(Verifiable::from(test_transaction_with_prefixes(
            &[1, 2, 3],
            &[local_prefix],
            &[local_prefix],
        )));
        let map = Verified::<ProvisionTxRootsMap>::compute(
            ShardId::leaf(1, 0),
            &topology_snapshot,
            &[tx],
            &[],
        );
        assert!(map.is_empty(), "single-shard tx must not produce an entry");
    }

    #[test]
    fn test_compute_provision_tx_roots_covers_all_touched_targets() {
        let topology_snapshot = two_shard_topology();
        let local_prefix = prefix_on_shard(&topology_snapshot, ShardId::leaf(1, 0));
        let remote_prefix = prefix_on_shard(&topology_snapshot, ShardId::leaf(1, 1));

        // Cross-shard tx: writes span local shard 0 and remote shard 1.
        let tx_a = Arc::new(Verifiable::from(test_transaction_with_prefixes(
            &[1, 2, 3],
            &[],
            &[local_prefix, remote_prefix],
        )));
        let tx_b = Arc::new(Verifiable::from(test_transaction_with_prefixes(
            &[4, 5, 6],
            &[],
            &[local_prefix, remote_prefix],
        )));

        let roots = Verified::<ProvisionTxRootsMap>::compute(
            ShardId::leaf(1, 0),
            &topology_snapshot,
            &[tx_a.clone(), tx_b.clone()],
            &[],
        );

        // Local shard excluded; only shard 1 receives provisions.
        assert_eq!(roots.len(), 1);
        assert!(roots.contains_key(&ShardId::leaf(1, 1)));

        let expected = ProvisionTxRoot::from_raw(compute_merkle_root(&[
            Hash::from(tx_a.hash()),
            Hash::from(tx_b.hash()),
        ]));
        assert_eq!(roots[&ShardId::leaf(1, 1)], expected);
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
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            },
        );
        let failure = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Failed,
        );
        assert_ne!(tx_outcome_leaf(&success), tx_outcome_leaf(&failure));
    }

    #[test]
    fn test_tx_outcome_leaf_aborted_differs_from_executed() {
        let executed = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            },
        );
        let aborted = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Aborted,
        );
        assert_ne!(tx_outcome_leaf(&executed), tx_outcome_leaf(&aborted));
    }

    #[test]
    fn ec_deadline_is_vote_anchor_ts_plus_retention_horizon() {
        let ec = make_test_ec(0, 1);
        assert_eq!(ec.deadline(), ec.vote_anchor_ts().plus(RETENTION_HORIZON));
    }

    fn make_test_ec(shard: u64, seed: u8) -> Arc<ExecutionCertificate> {
        let outcomes = vec![make_outcome(seed)];
        let global_receipt_root = compute_global_receipt_root(&outcomes);
        Arc::new(ExecutionCertificate::new(
            make_tick_id(shard, BlockHeight::new(42)),
            WeightedTimestamp::from_millis(43),
            global_receipt_root,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let fw = Finalization::new(
            make_tick_id(0, BlockHeight::new(42)),
            TickHalf::Determined,
            &Capped::from_array([make_test_ec(0, 1), make_test_ec(1, 2)]),
            Capped::from_array([]),
        );
        assert_eq!(fw.receipt_hash(), fw.receipt_hash());
        assert_ne!(fw.receipt_hash(), FinalizationHash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let fw1 = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_test_ec(0, 1)]),
            Capped::from_array([]),
        );
        let fw2 = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_test_ec(1, 2)]),
            Capped::from_array([]),
        );
        assert_ne!(fw1.receipt_hash(), fw2.receipt_hash());
    }

    /// Narrowing a counterpart's certificate moves the leaf.
    ///
    /// A projected copy is as valid as the copy it came from — same
    /// signed root, same signature — and anyone holding the wider one can
    /// build it. What separates them is which outcomes they carry, and
    /// that decides whether a leg settles its effects or its charge. The
    /// finalization's own receipt check reads the same certificate set on
    /// both sides and so cannot tell, which leaves this leaf as the thing
    /// that does.
    #[test]
    fn a_narrowed_certificate_changes_the_leaf() {
        let local = make_test_ec(0, 1);
        let remote_outcomes = vec![make_outcome(2), make_outcome(3)];
        let remote = Arc::new(ExecutionCertificate::new(
            make_tick_id(1, BlockHeight::new(42)),
            WeightedTimestamp::from_millis(43),
            compute_global_receipt_root(&remote_outcomes),
            Capped::new(remote_outcomes).expect("a list written out in a test"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ));
        let narrowed = Arc::new(
            remote
                .project_to(&std::iter::once(make_outcome(2).tx_hash()).collect())
                .expect("a copy covering one of the two"),
        );
        assert_eq!(
            narrowed.global_receipt_root(),
            remote.global_receipt_root(),
            "the narrower copy verifies under the same signed root",
        );

        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let whole = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([Arc::clone(&local), remote]),
            Capped::from_array([]),
        );
        let partial = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([local, narrowed]),
            Capped::from_array([]),
        );
        assert_ne!(
            whole.receipt_hash(),
            partial.receipt_hash(),
            "a block cannot carry the narrower copy under the wider one's root",
        );
    }

    #[test]
    fn test_finalization_hbor_roundtrip() {
        let fw = Finalization::new(
            make_tick_id(0, BlockHeight::new(42)),
            TickHalf::Determined,
            &Capped::from_array([make_test_ec(0, 1), make_test_ec(1, 2)]),
            Capped::from_array([]),
        );
        let encoded = hbor_to_vec(&fw).unwrap();
        let decoded: Finalization = hbor_from_slice(&encoded).unwrap();
        assert_eq!(fw, decoded);
    }

    #[test]
    fn decode_rejects_finalization_missing_local_ec() {
        // The tick's tick_id has shard=0 but its only EC is for shard=1,
        // so no ec.tick_id() matches. Pre-fix this decoded successfully
        // and then panicked the IO loop on first call to local_ec().
        let fw = Finalization::new(
            make_tick_id(0, BlockHeight::new(42)),
            TickHalf::Determined,
            &Capped::from_array([make_test_ec(1, 1)]),
            Capped::from_array([]),
        );
        let bytes = hbor_to_vec(&fw).unwrap();
        let err = hbor_from_slice::<Finalization>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    /// The exactly-one-local-EC invariant rejects ticks with more than one
    /// EC matching the tick's own `tick_id`. Without this, downstream helpers
    /// like `Finalization::local_ec()` would silently pick the first match,
    /// letting two paths disagree on which EC is authoritative.
    #[test]
    fn decode_rejects_finalization_with_multiple_local_ecs() {
        // Build two ECs both keyed to the same tick_id (shard=0, h=42).
        // Distinct seeds yield distinct canonical hashes so the inner
        // EC-decode invariants don't reject before we get to the local-EC
        // count check.
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let ec_a = make_local_ec(&tick_id, vec![make_outcome(1)]);
        let ec_b = make_local_ec(&tick_id, vec![make_outcome(2)]);
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([ec_a, ec_b]),
            Capped::from_array([]),
        );
        let bytes = hbor_to_vec(&fw).unwrap();
        let err = hbor_from_slice::<Finalization>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    #[test]
    fn decode_rejects_finalization_with_oversized_ec_count() {
        // Forge a tick whose execution_certificates count claims one past
        // the cap, padded to input-satisfiability so the protocol cap is
        // what fires, before any per-EC decode work happens.
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let mut buf = hbor_to_vec(&tick_id).unwrap();
        buf.extend(hbor_to_vec(&TickHalf::Determined).unwrap());
        varint::write(&mut buf, MAX_EXECUTION_CERTIFICATES_PER_TICK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_EXECUTION_CERTIFICATES_PER_TICK + 1) * 256,
        ));
        let err = hbor_from_slice::<Finalization>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_EXECUTION_CERTIFICATES_PER_TICK
                    && actual == MAX_EXECUTION_CERTIFICATES_PER_TICK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_tx_outcomes_count() {
        use crate::{GlobalReceiptRoot, MAX_TXS_PER_BLOCK};

        let tick_id = make_tick_id(0, BlockHeight::new(1));
        let mut buf = hbor_to_vec(&tick_id).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&WeightedTimestamp::ZERO).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&GlobalReceiptRoot::ZERO).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&0u32).unwrap());
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 128));
        let err = hbor_from_slice::<ExecutionCertificate>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_tx_outcomes_not_matching_receipt_root() {
        use crate::{AggregateSignature, GlobalReceiptRoot, SignerBitfield, TxOutcome};

        // A field-for-field twin without the decode check: the only way to
        // spell an EC whose carried outcomes do not hash to its signed
        // root. The signature aggregate commits only to (root, count);
        // without the decode-time check a peer could ship this through
        // every downstream consumer.
        #[derive(Hbor)]
        struct Forged {
            tick_id: TickId,
            vote_anchor_ts: WeightedTimestamp,
            global_receipt_root: GlobalReceiptRoot,
            tx_count: u32,
            tx_outcomes: Vec<TxOutcome>,
            leaf_indices: Vec<u8>,
            proof: Vec<Hash>,
            aggregated_signature: AggregateSignature,
            signers: SignerBitfield,
        }

        let tick_id = make_tick_id(0, BlockHeight::new(7));
        let outcomes = vec![make_outcome(1), make_outcome(2)];
        assert_ne!(
            compute_global_receipt_root(&outcomes),
            GlobalReceiptRoot::ZERO
        );
        let buf = hbor_to_vec(&Forged {
            tick_id,
            vote_anchor_ts: WeightedTimestamp::from_millis(1),
            global_receipt_root: GlobalReceiptRoot::ZERO,
            tx_count: 2,
            tx_outcomes: outcomes,
            leaf_indices: Vec::new(),
            proof: Vec::new(),
            aggregated_signature: AggregateSignature::ZERO,
            signers: SignerBitfield::new(4),
        })
        .unwrap();
        let err = hbor_from_slice::<ExecutionCertificate>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    /// Decoding a single `Finalization` directly must still bound the
    /// receipts vec: without the cap a peer could claim billions of
    /// receipts on one tick.
    #[test]
    fn decode_rejects_finalization_with_oversized_receipts_count() {
        use crate::MAX_TXS_PER_BLOCK;

        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, vec![])]),
            Capped::from_array([]),
        );

        // Everything up to the receipt count, then a forged count.
        let mut buf = hbor_to_vec(&attestation).unwrap();
        buf.truncate(buf.len() - 1);
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 256));
        let err = hbor_from_slice::<Finalization>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn tick_leader_is_attempt_zero() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let tick_id = make_tick_id(0, BlockHeight::new(100));
        assert_eq!(
            tick_leader(&tick_id, &committee),
            tick_leader_at(&tick_id, Attempt::INITIAL, &committee)
        );
    }

    #[test]
    fn tick_leader_at_rotates() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let tick_id = make_tick_id(0, BlockHeight::new(100));
        let mut leaders: HashSet<ValidatorId> = HashSet::new();
        for attempt in 0..4 {
            leaders.insert(tick_leader_at(&tick_id, Attempt::new(attempt), &committee));
        }
        // With 4 attempts and 4 committee members, we should get multiple distinct leaders.
        // (Not guaranteed to be all 4 due to hash collisions, but at least 2.)
        assert!(
            leaders.len() >= 2,
            "Expected rotation to produce distinct leaders"
        );
    }

    #[test]
    fn tick_leader_at_wraps() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
        ];
        let tick_id = make_tick_id(0, BlockHeight::new(100));
        // Large attempt values should not panic — they wrap via modulo.
        let _ = tick_leader_at(&tick_id, Attempt::new(1000), &committee);
    }

    #[test]
    fn tick_leader_is_deterministic() {
        let committee = vec![
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
            ValidatorId::new(4),
        ];
        let tick_id = make_tick_id(0, BlockHeight::new(100));
        let leader1 = tick_leader_at(&tick_id, Attempt::new(2), &committee);
        let leader2 = tick_leader_at(&tick_id, Attempt::new(2), &committee);
        assert_eq!(leader1, leader2);
    }

    fn make_local_ec(tick_id: &TickId, outcomes: Vec<TxOutcome>) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            *tick_id,
            WeightedTimestamp::from_millis(tick_id.block_height().inner() + 1),
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn make_success_receipt() -> Arc<ConsensusReceipt> {
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: StateWrites::default(),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        })
    }

    #[test]
    fn reconstruct_from_all_success_outcomes() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"tx_b"));

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
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([]),
        );

        let fw = Finalization::reconstruct(attestation, |_| Some(make_success_receipt()))
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
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"tx_b_aborted"));

        let outcomes = vec![
            TxOutcome::new(
                tx_a,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
                },
            ),
            TxOutcome::new(tx_b, ExecutionOutcome::Aborted),
        ];
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([]),
        );

        // Lookup returns Some for tx_a, None for tx_b (never persisted — pure abort).
        let fw = Finalization::reconstruct(attestation, |h| {
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
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));

        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r_a")),
            },
        )];
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([]),
        );

        let fw = Finalization::reconstruct(attestation, |_| None);
        assert!(
            fw.is_none(),
            "reconstruction should fail when non-aborted receipt is missing"
        );
    }

    /// A leg that succeeded here and was refused by its counterpart
    /// settles nothing when it owes no charge — so no receipt was ever
    /// stored for it, and a rebuild must not demand one. This is the
    /// ordinary shape on a non-payer shard: the payer settles the charge,
    /// this side settles nothing at all.
    #[test]
    fn reconstruct_skips_a_leg_its_counterpart_refused() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let remote_tick_id = make_tick_id(1, BlockHeight::new(42));
        let settling = TxHash::from(Hash::from_bytes(b"settling"));
        let refused = TxHash::from(Hash::from_bytes(b"refused_by_counterpart"));

        // Locally both succeeded; the counterpart aborted the second.
        let local_ec = make_local_ec(
            &tick_id,
            vec![
                TxOutcome::new(
                    settling,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                ),
                TxOutcome::new(
                    refused,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                ),
            ],
        );
        let remote_ec = make_local_ec(
            &remote_tick_id,
            vec![TxOutcome::new(refused, ExecutionOutcome::Aborted)],
        );
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([local_ec, remote_ec]),
            Capped::from_array([]),
        );

        let fw = Finalization::reconstruct(attestation, |tx_hash| {
            (*tx_hash == settling).then(make_success_receipt)
        })
        .expect("a refused leg owing no charge stored no receipt to find");
        assert_eq!(fw.receipts().len(), 1);
        assert_eq!(fw.receipts()[0].tx_hash, settling);
    }

    #[test]
    fn reconstruct_fails_when_local_ec_missing() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let remote_tick_id = make_tick_id(1, BlockHeight::new(42));
        let remote_ec = make_local_ec(
            &remote_tick_id,
            vec![TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Aborted,
            )],
        );
        let attestation = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([remote_ec]),
            Capped::from_array([]),
        );

        let fw = Finalization::reconstruct(attestation, |_| Some(make_success_receipt()));
        assert!(fw.is_none(), "reconstruction requires the local EC");
    }

    /// Dropping the certificate carrying a counterpart's refusal is
    /// caught, because the tick's own certificate names the counterpart.
    ///
    /// The set left behind is internally consistent — [`settles`] reads
    /// the outcomes in front of it, finds no refusal, and the receipts
    /// built around that reading agree with it — so nothing about the
    /// receipts can tell the two sets apart. What can is that the local
    /// outcome says shard 1 is party to the transaction and no
    /// certificate here speaks for shard 1.
    ///
    /// [`settles`]: crate::settles
    #[test]
    fn dropping_a_refusal_leaves_the_transaction_uncovered() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let counterpart = make_tick_id(1, BlockHeight::new(42));
        let leg = TxHash::from(Hash::from_bytes(b"cross_shard_leg"));

        let local_ec = make_local_ec(
            &tick_id,
            vec![
                TxOutcome::new(
                    leg,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .awaiting([counterpart.shard_id()]),
            ],
        );
        let refusal = make_local_ec(
            &counterpart,
            vec![TxOutcome::new(leg, ExecutionOutcome::Aborted).awaiting([tick_id.shard_id()])],
        );
        let effects = StoredReceipt {
            tx_hash: leg,
            consensus: make_success_receipt(),
            metadata: None,
        };

        let thinned = Finalization::new(
            tick_id,
            TickHalf::Legs,
            &Capped::from_array([Arc::clone(&local_ec)]),
            Capped::from_array([effects]),
        );
        assert_eq!(
            thinned.validate_against_certificates(),
            Err(ReceiptValidationError::IncompleteCoverage {
                tx_hash: leg,
                missing: counterpart.shard_id(),
            }),
            "a set that leaves out a participant decides nothing about its transaction",
        );
        assert!(
            thinned.settling_receipts().is_empty(),
            "and nothing it carries reaches state by another road",
        );

        // The same tick with the refusal present settles the charge its
        // outcome named — here, none — and never the effects.
        let whole = Finalization::new(
            tick_id,
            TickHalf::Legs,
            &Capped::from_array([local_ec, refusal]),
            Capped::from_array([]),
        );
        assert_eq!(whole.validate_against_certificates(), Ok(()));
        assert!(whole.settling_receipts().is_empty());
    }

    /// A transaction reaching no further than its own shard names no
    /// counterpart, so its tick settles on its own certificate.
    #[test]
    fn a_determined_member_needs_no_counterpart() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx = TxHash::from(Hash::from_bytes(b"determined"));
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(
                &tick_id,
                vec![TxOutcome::new(
                    tx,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )],
            )]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx,
                consensus: make_success_receipt(),
                metadata: None,
            }]),
        );
        assert_eq!(fw.validate_against_certificates(), Ok(()));
        assert_eq!(fw.settling_receipts().len(), 1);
    }

    /// A refused transaction needs no completeness: one refusal discards
    /// its effects everywhere, so the shards yet to report can only agree.
    #[test]
    fn a_refused_transaction_settles_without_every_participant() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let absent = make_tick_id(2, BlockHeight::new(42));
        let leg = TxHash::from(Hash::from_bytes(b"refused_leg"));
        let fw = Finalization::new(
            tick_id,
            TickHalf::Legs,
            &Capped::from_array([make_local_ec(
                &tick_id,
                vec![TxOutcome::new(leg, ExecutionOutcome::Aborted).awaiting([absent.shard_id()])],
            )]),
            Capped::from_array([]),
        );
        assert_eq!(fw.validate_against_certificates(), Ok(()));
    }

    /// The awaited shards sit under the signed receipt root, so a set
    /// naming fewer participants is a different certificate rather than
    /// the same one read narrowly.
    #[test]
    fn awaited_shards_change_the_outcome_leaf() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let outcome = TxOutcome::new(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        let awaiting = outcome.clone().awaiting([ShardId::leaf(3, 1)]);
        assert_ne!(tx_outcome_leaf(&outcome), tx_outcome_leaf(&awaiting));
        assert_ne!(
            tx_outcome_leaf(&awaiting),
            tx_outcome_leaf(&outcome.awaiting([ShardId::leaf(3, 2)])),
        );
    }

    #[test]
    fn validate_accepts_receipts_matching_outcomes() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"tx_b_aborted"));
        let tx_c = TxHash::from(Hash::from_bytes(b"tx_c_fail"));

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
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([
                StoredReceipt {
                    tx_hash: tx_a,
                    consensus: Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                        writes: StateWrites::default(),
                        beacon_witness_events: Capped::empty(),
                        events: Capped::empty(),
                    }),
                    metadata: None,
                },
                StoredReceipt {
                    tx_hash: tx_c,
                    consensus: Arc::new(ConsensusReceipt::Failed),
                    metadata: None,
                },
            ]),
        );
        assert_eq!(fw.validate_against_certificates(), Ok(()));
    }

    #[test]
    fn validate_rejects_unexpected_failure() {
        // EC says Succeeded, receipt says Failed.
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Failed),
                metadata: None,
            }]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::UnexpectedFailure { .. })
        ));
    }

    #[test]
    fn validate_rejects_unexpected_success() {
        // EC says Failed, receipt says Succeeded.
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(tx_a, ExecutionOutcome::Failed)];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
                metadata: None,
            }]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::UnexpectedSuccess { .. })
        ));
    }

    #[test]
    fn validate_rejects_receipt_hash_mismatch() {
        // Both Succeeded but receipt_hashes disagree — divergent state for the same tx.
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let ec_hash = GlobalReceiptHash::from_raw(Hash::from_bytes(b"ec"));
        let receipt_hash = GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: ec_hash,
            },
        )];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
                metadata: None,
            }]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::ReceiptHashMismatch { expected, actual, .. })
                if expected == ec_hash && actual == receipt_hash
        ));
    }

    #[test]
    fn validate_rejects_missing_receipt() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::MissingReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_extra_receipt() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let outcomes = vec![TxOutcome::new(tx_a, ExecutionOutcome::Aborted)];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx_a,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
                metadata: None,
            }]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::ExtraReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_tx_hash_mismatch() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let tx_a = TxHash::from(Hash::from_bytes(b"tx_a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"tx_b"));
        let outcomes = vec![TxOutcome::new(
            tx_a,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([StoredReceipt {
                tx_hash: tx_b,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
                metadata: None,
            }]),
        );
        assert!(matches!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::TxHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_local_ec() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let remote_tick_id = make_tick_id(1, BlockHeight::new(42));
        let remote_ec = make_local_ec(&remote_tick_id, vec![]);
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([remote_ec]),
            Capped::from_array([]),
        );
        assert_eq!(
            fw.validate_against_certificates(),
            Err(ReceiptValidationError::MissingLocalEc)
        );
    }

    #[test]
    fn validate_all_aborted_tick_with_empty_receipts_passes() {
        let tick_id = make_tick_id(0, BlockHeight::new(42));
        let outcomes = vec![TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"aborted")),
            ExecutionOutcome::Aborted,
        )];
        let fw = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([make_local_ec(&tick_id, outcomes)]),
            Capped::from_array([]),
        );
        assert_eq!(fw.validate_against_certificates(), Ok(()));
    }
}
