//! Execution handler functions shared between production and simulation runners.

use hyperscale_core::{Action, CrossShardExecutionRequest};
use hyperscale_types::{
    batch_verify_bls_same_message, exec_vote_message, verify_bls12381_v1, zero_bls_signature,
    BlockHash, Bls12381G1PublicKey, Bls12381G2Signature, ExecutionCertificate, ExecutionVote,
    GlobalReceiptRoot, RoutableTransaction, SignerBitfield, StateProvision, StateRoot, TxHash,
    ValidatorId, WaveId, WeightedTimestamp,
};
#[cfg(test)]
use hyperscale_types::{GlobalReceiptHash, Hash};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::wave_state::WaveState;

// ============================================================================
// Wave-based execution voting handlers
// ============================================================================

/// Aggregate verified execution votes into an `ExecutionCertificate`.
///
/// Deduplicates votes by validator, aggregates BLS signatures, and builds a
/// signer bitfield using the committee's indices.
///
/// `tx_outcomes` are extracted from the first vote — all quorum votes carry
/// identical outcomes (they share the same global_receipt_root).
pub fn aggregate_execution_certificate(
    wave_id: &WaveId,
    global_receipt_root: GlobalReceiptRoot,
    votes: &[ExecutionVote],
    committee: &[ValidatorId],
) -> ExecutionCertificate {
    let tx_outcomes = votes
        .first()
        .map(|v| v.tx_outcomes.clone())
        .unwrap_or_default();
    // Deduplicate votes by validator
    let mut seen_validators = HashSet::new();
    let unique_votes: Vec<_> = votes
        .iter()
        .filter(|vote| seen_validators.insert(vote.validator))
        .collect();

    // Aggregate BLS signatures
    let bls_signatures: Vec<Bls12381G2Signature> =
        unique_votes.iter().map(|vote| vote.signature).collect();

    let aggregated_signature = if !bls_signatures.is_empty() {
        Bls12381G2Signature::aggregate(&bls_signatures, true)
            .unwrap_or_else(|_| zero_bls_signature())
    } else {
        zero_bls_signature()
    };

    // Create signer bitfield using committee ordering
    let committee_index: HashMap<ValidatorId, usize> = committee
        .iter()
        .enumerate()
        .map(|(idx, &vid)| (vid, idx))
        .collect();
    let mut signers = SignerBitfield::new(committee.len());
    for vote in &unique_votes {
        if let Some(&idx) = committee_index.get(&vote.validator) {
            signers.set(idx);
        }
    }

    let vote_anchor_ts_ms = votes
        .first()
        .map(|v| v.vote_anchor_ts_ms)
        .unwrap_or(WeightedTimestamp::ZERO);

    ExecutionCertificate::new(
        wave_id.clone(),
        vote_anchor_ts_ms,
        global_receipt_root,
        tx_outcomes,
        aggregated_signature,
        signers,
    )
}

/// Batch verify execution votes.
///
/// Uses BLS same-message batch verification since all votes in a wave
/// should sign the same message (same global_receipt_root). Falls back to
/// individual verification on batch failure.
///
/// Returns an iterator of `(vote, voting_power)` for verified votes.
pub fn batch_verify_execution_votes(
    votes: Vec<(ExecutionVote, Bls12381G1PublicKey, u64)>,
) -> impl Iterator<Item = (ExecutionVote, u64)> {
    if votes.is_empty() {
        return Vec::new().into_iter();
    }

    // Group by signing message (all votes for same wave should share one)
    let mut by_message: HashMap<Vec<u8>, Vec<(ExecutionVote, Bls12381G1PublicKey, u64)>> =
        HashMap::new();
    for (vote, pk, power) in votes {
        let msg = exec_vote_message(
            vote.vote_anchor_ts_ms,
            &vote.wave_id,
            vote.shard_group_id,
            &vote.global_receipt_root,
            vote.tx_count,
        );
        by_message.entry(msg).or_default().push((vote, pk, power));
    }

    let mut verified: Vec<(ExecutionVote, u64)> = Vec::new();

    for (message, group) in by_message {
        if group.len() >= 2 {
            let signatures: Vec<_> = group.iter().map(|(v, _, _)| v.signature).collect();
            let pubkeys: Vec<_> = group.iter().map(|(_, pk, _)| *pk).collect();

            if batch_verify_bls_same_message(&message, &signatures, &pubkeys) {
                for (vote, _, power) in group {
                    verified.push((vote, power));
                }
            } else {
                // Batch failed — verify individually
                for (vote, pk, power) in group {
                    if verify_bls12381_v1(&message, &pk, &vote.signature) {
                        verified.push((vote, power));
                    }
                }
            }
        } else {
            // Single vote — verify directly
            for (vote, pk, power) in group {
                if verify_bls12381_v1(&message, &pk, &vote.signature) {
                    verified.push((vote, power));
                }
            }
        }
    }

    verified.into_iter()
}

/// Verify an execution certificate's aggregated signature.
///
/// Verify an execution certificate's aggregated BLS signature.
pub fn verify_execution_certificate_signature(
    certificate: &ExecutionCertificate,
    public_keys: &[Bls12381G1PublicKey],
) -> bool {
    let msg = exec_vote_message(
        certificate.vote_anchor_ts_ms,
        &certificate.wave_id,
        certificate.shard_group_id(),
        &certificate.global_receipt_root,
        certificate.tx_outcomes.len() as u32,
    );

    let signer_keys: Vec<_> = public_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| certificate.signers.is_set(*i))
        .map(|(_, pk)| *pk)
        .collect();

    if signer_keys.is_empty() {
        certificate.aggregated_signature == zero_bls_signature()
    } else {
        match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
            Ok(aggregated_pk) => {
                verify_bls12381_v1(&msg, &aggregated_pk, &certificate.aggregated_signature)
            }
            Err(_) => false,
        }
    }
}

// ============================================================================
// Wave dispatch
// ============================================================================

/// Build the one-shot execution dispatch action for a fully-provisioned wave.
///
/// Returns `Some(Action::ExecuteTransactions)` for single-shard waves, or
/// `Some(Action::ExecuteCrossShardTransactions)` for cross-shard waves with
/// all required `verified_provisions` present. Returns `None` if a cross-shard
/// tx is missing its provisions, or if every tx in the wave is pre-aborted —
/// caller must not mark the wave dispatched.
///
/// Txs with pre-dispatch explicit aborts (from reverse-conflict detection) are
/// excluded from the dispatch: they produce no state change, so there's no
/// reason to execute them.
pub(crate) fn build_dispatch_action(
    wave: &WaveState,
    verified_provisions: &HashMap<TxHash, Vec<StateProvision>>,
    block_hash: BlockHash,
) -> Option<Action> {
    if wave.wave_id().is_zero() {
        // Single-shard wave: no provisions needed.
        let transactions: Vec<Arc<RoutableTransaction>> = wave
            .tx_hashes()
            .iter()
            .filter(|h| !wave.is_tx_explicitly_aborted(h))
            .filter_map(|h| wave.transaction(h).cloned())
            .collect();
        if transactions.is_empty() {
            return None;
        }
        return Some(Action::ExecuteTransactions {
            wave_id: wave.wave_id().clone(),
            block_hash,
            transactions,
            state_root: StateRoot::ZERO,
        });
    }

    // Cross-shard wave: every non-aborted tx needs its verified provisions assembled.
    let mut requests: Vec<CrossShardExecutionRequest> = Vec::with_capacity(wave.tx_hashes().len());
    for tx_hash in wave.tx_hashes() {
        if wave.is_tx_explicitly_aborted(tx_hash) {
            continue;
        }
        let tx = wave.transaction(tx_hash)?;
        let provisions = verified_provisions.get(tx_hash)?.clone();
        requests.push(CrossShardExecutionRequest {
            tx_hash: *tx_hash,
            transaction: Arc::clone(tx),
            provisions,
        });
    }
    if requests.is_empty() {
        return None;
    }
    Some(Action::ExecuteCrossShardTransactions {
        wave_id: wave.wave_id().clone(),
        block_hash,
        requests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        bls_keypair_from_seed, test_utils::test_transaction, BlockHeight, Bls12381G1PrivateKey,
        ExecutionOutcome, ShardGroupId, TxOutcome,
    };
    use std::collections::BTreeSet;

    fn shard() -> ShardGroupId {
        ShardGroupId(0)
    }

    fn wave_id(height: u64) -> WaveId {
        WaveId {
            shard_group_id: shard(),
            block_height: BlockHeight(height),
            remote_shards: Default::default(),
        }
    }

    fn cross_shard_wave_id(height: u64, remotes: &[ShardGroupId]) -> WaveId {
        WaveId {
            shard_group_id: shard(),
            block_height: BlockHeight(height),
            remote_shards: remotes.iter().copied().collect(),
        }
    }

    fn keypair(seed: u8) -> Bls12381G1PrivateKey {
        bls_keypair_from_seed(&[seed; 32])
    }

    fn outcome(tx: TxHash) -> TxOutcome {
        TxOutcome {
            tx_hash: tx,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }
    }

    fn signed_vote(
        voter: ValidatorId,
        sk: &Bls12381G1PrivateKey,
        wid: &WaveId,
        global_receipt_root: GlobalReceiptRoot,
        anchor: WeightedTimestamp,
        tx_outcomes: Vec<TxOutcome>,
    ) -> ExecutionVote {
        let tx_count = tx_outcomes.len() as u32;
        let msg = exec_vote_message(anchor, wid, shard(), &global_receipt_root, tx_count);
        ExecutionVote {
            block_hash: BlockHash::ZERO,
            block_height: BlockHeight(1),
            vote_anchor_ts_ms: anchor,
            wave_id: wid.clone(),
            shard_group_id: shard(),
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator: voter,
            signature: sk.sign_v1(&msg),
        }
    }

    // ─── aggregate_execution_certificate ─────────────────────────────────

    #[test]
    fn aggregate_produces_signer_bitfield_in_committee_order() {
        // Committee is [V0, V1, V2, V3]; voters are V1 and V3.
        // Expected bits set: 1, 3.
        let committee = vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
        ];
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let outcomes = vec![outcome(tx)];

        let sk1 = keypair(1);
        let sk3 = keypair(3);
        let votes = vec![
            signed_vote(
                ValidatorId(1),
                &sk1,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId(3),
                &sk3,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
        ];

        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);
        assert!(ec.signers.is_set(1));
        assert!(ec.signers.is_set(3));
        assert!(!ec.signers.is_set(0));
        assert!(!ec.signers.is_set(2));
        assert_eq!(ec.tx_outcomes, outcomes);
    }

    #[test]
    fn aggregate_dedups_votes_from_same_validator() {
        let committee = vec![ValidatorId(0), ValidatorId(1)];
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let sk0 = keypair(0);

        // Same voter cast twice.
        let votes = vec![
            signed_vote(
                ValidatorId(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
        ];

        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);
        assert!(ec.signers.is_set(0));
        assert!(!ec.signers.is_set(1));
        assert_eq!(ec.signers.count_ones(), 1, "duplicate votes must collapse");
    }

    #[test]
    fn aggregate_empty_votes_yields_zero_signature() {
        let committee = vec![ValidatorId(0)];
        let ec =
            aggregate_execution_certificate(&wave_id(1), GlobalReceiptRoot::ZERO, &[], &committee);
        assert_eq!(ec.aggregated_signature, zero_bls_signature());
        assert_eq!(ec.signers.count_ones(), 0);
        assert!(ec.tx_outcomes.is_empty());
    }

    // ─── batch_verify_execution_votes ────────────────────────────────────

    #[test]
    fn batch_verify_accepts_all_valid_signatures() {
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let sk0 = keypair(0);
        let sk1 = keypair(1);

        let votes = vec![
            (
                signed_vote(
                    ValidatorId(0),
                    &sk0,
                    &wid,
                    root,
                    WeightedTimestamp(100),
                    outcomes.clone(),
                ),
                sk0.public_key(),
                1u64,
            ),
            (
                signed_vote(
                    ValidatorId(1),
                    &sk1,
                    &wid,
                    root,
                    WeightedTimestamp(100),
                    outcomes.clone(),
                ),
                sk1.public_key(),
                1u64,
            ),
        ];

        let verified: Vec<_> = batch_verify_execution_votes(votes).collect();
        assert_eq!(verified.len(), 2);
    }

    #[test]
    fn batch_verify_falls_back_and_drops_individual_bad_signature() {
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let sk0 = keypair(0);
        let sk1 = keypair(1);
        let sk2 = keypair(2);

        // V1 signs with sk1 but submits a signature over a DIFFERENT message
        // (wrong root) — the batch verify fails, then the individual fallback
        // drops only V1's vote.
        let mut bad_vote = signed_vote(
            ValidatorId(1),
            &sk1,
            &wid,
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"other")),
            WeightedTimestamp(100),
            outcomes.clone(),
        );
        // Re-stamp the vote's visible receipt_root back to the correct one so
        // the batch-verify message computation matches the other votes (and
        // thus groups them), but the signature still covers the wrong root.
        bad_vote.global_receipt_root = root;

        let votes = vec![
            (
                signed_vote(
                    ValidatorId(0),
                    &sk0,
                    &wid,
                    root,
                    WeightedTimestamp(100),
                    outcomes.clone(),
                ),
                sk0.public_key(),
                1u64,
            ),
            (bad_vote, sk1.public_key(), 1u64),
            (
                signed_vote(
                    ValidatorId(2),
                    &sk2,
                    &wid,
                    root,
                    WeightedTimestamp(100),
                    outcomes.clone(),
                ),
                sk2.public_key(),
                1u64,
            ),
        ];

        let verified: Vec<_> = batch_verify_execution_votes(votes).collect();
        let validators: Vec<ValidatorId> = verified.iter().map(|(v, _)| v.validator).collect();
        assert_eq!(validators, vec![ValidatorId(0), ValidatorId(2)]);
    }

    #[test]
    fn batch_verify_empty_input_returns_empty() {
        let verified: Vec<_> = batch_verify_execution_votes(Vec::new()).collect();
        assert!(verified.is_empty());
    }

    // ─── verify_execution_certificate_signature ──────────────────────────

    #[test]
    fn verify_ec_signature_accepts_valid_aggregation() {
        let committee = vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
        ];
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let sks: Vec<_> = (0..4).map(|i| keypair(i as u8)).collect();

        let votes: Vec<ExecutionVote> = (0..4)
            .map(|i| {
                signed_vote(
                    ValidatorId(i as u64),
                    &sks[i],
                    &wid,
                    root,
                    WeightedTimestamp(100),
                    outcomes.clone(),
                )
            })
            .collect();
        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);

        let pubs: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        assert!(verify_execution_certificate_signature(&ec, &pubs));
    }

    #[test]
    fn verify_ec_signature_rejects_wrong_public_keys() {
        let committee = vec![ValidatorId(0), ValidatorId(1)];
        let wid = wave_id(1);
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let sk0 = keypair(0);
        let sk1 = keypair(1);

        let votes = vec![
            signed_vote(
                ValidatorId(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId(1),
                &sk1,
                &wid,
                root,
                WeightedTimestamp(100),
                outcomes.clone(),
            ),
        ];
        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);

        // Provide the wrong public keys — signature must not verify.
        let wrong_pubs = vec![keypair(42).public_key(), keypair(43).public_key()];
        assert!(!verify_execution_certificate_signature(&ec, &wrong_pubs));
    }

    // ─── build_dispatch_action ───────────────────────────────────────────

    fn single_shard_wave_with(tx_seeds: &[u8]) -> WaveState {
        let txs: Vec<_> = tx_seeds
            .iter()
            .map(|s| {
                let mut participating = BTreeSet::new();
                participating.insert(shard());
                (Arc::new(test_transaction(*s)), participating)
            })
            .collect();
        WaveState::new(wave_id(0), BlockHash::ZERO, WeightedTimestamp(0), txs, true)
    }

    fn cross_shard_wave_with(tx_seeds: &[u8], remote: ShardGroupId) -> WaveState {
        let txs: Vec<_> = tx_seeds
            .iter()
            .map(|s| {
                let mut participating = BTreeSet::new();
                participating.insert(shard());
                participating.insert(remote);
                (Arc::new(test_transaction(*s)), participating)
            })
            .collect();
        WaveState::new(
            cross_shard_wave_id(1, &[remote]),
            BlockHash::ZERO,
            WeightedTimestamp(0),
            txs,
            false,
        )
    }

    #[test]
    fn build_dispatch_single_shard_returns_execute_transactions() {
        let wave = single_shard_wave_with(&[1, 2]);
        let provisions = HashMap::new();

        let action = build_dispatch_action(&wave, &provisions, BlockHash::ZERO);
        match action {
            Some(Action::ExecuteTransactions { transactions, .. }) => {
                assert_eq!(transactions.len(), 2);
            }
            other => panic!("expected ExecuteTransactions, got {:?}", other),
        }
    }

    #[test]
    fn build_dispatch_cross_shard_returns_none_when_provisions_missing() {
        let wave = cross_shard_wave_with(&[1], ShardGroupId(1));
        let provisions = HashMap::new();

        assert!(build_dispatch_action(&wave, &provisions, BlockHash::ZERO).is_none());
    }

    #[test]
    fn build_dispatch_cross_shard_succeeds_with_all_provisions() {
        let wave = cross_shard_wave_with(&[1], ShardGroupId(1));
        let tx_hash = wave.tx_hashes()[0];
        let mut provisions = HashMap::new();
        provisions.insert(
            tx_hash,
            vec![StateProvision {
                transaction_hash: tx_hash,
                target_shard: shard(),
                source_shard: ShardGroupId(1),
                block_height: BlockHeight(5),
                entries: Arc::new(vec![]),
            }],
        );

        let action = build_dispatch_action(&wave, &provisions, BlockHash::ZERO);
        match action {
            Some(Action::ExecuteCrossShardTransactions { requests, .. }) => {
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].tx_hash, tx_hash);
            }
            other => panic!("expected ExecuteCrossShardTransactions, got {:?}", other),
        }
    }

    #[test]
    fn build_dispatch_skips_pre_aborted_txs() {
        let mut wave = single_shard_wave_with(&[1, 2]);
        let aborted = wave.tx_hashes()[0];
        wave.record_abort(aborted, WeightedTimestamp(0));

        let action = build_dispatch_action(&wave, &HashMap::new(), BlockHash::ZERO);
        match action {
            Some(Action::ExecuteTransactions { transactions, .. }) => {
                assert_eq!(transactions.len(), 1);
                assert_ne!(transactions[0].hash(), aborted);
            }
            other => panic!("expected ExecuteTransactions, got {:?}", other),
        }
    }

    #[test]
    fn build_dispatch_returns_none_when_all_txs_aborted() {
        let mut wave = single_shard_wave_with(&[1]);
        let aborted = wave.tx_hashes()[0];
        wave.record_abort(aborted, WeightedTimestamp(0));

        assert!(build_dispatch_action(&wave, &HashMap::new(), BlockHash::ZERO).is_none());
    }
}
