//! Pure execution algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core transaction execution, aggregation, and
//! verification algorithms, separated from dispatch (thread pool vs inline)
//! and result delivery (channel vs event queue) concerns.
//!
//! Each execution function is the single-transaction unit of work. Production
//! wraps calls in `rayon::par_iter()` for parallelism; simulation calls sequentially.
//!
//! The `batch_verify_*` functions use [`batch_verify_bls_different_messages`] to
//! verify accumulated signatures across multiple transactions in ~2 pairing
//! operations. These are called from the node loop's time-windowed batch flush.

use hyperscale_engine::RadixExecutor;
use hyperscale_storage::SubstateStore;
use hyperscale_types::{
    batch_verify_bls_different_messages, batch_verify_bls_same_message, exec_vote_message,
    verify_bls12381_v1, zero_bls_signature, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, Hash, NodeId, RoutableTransaction, ShardGroupId, SignerBitfield,
    StateCertificate, StateProvision, StateVoteBlock, Topology, ValidatorId, VotePower,
};
use std::collections::HashMap;
use std::sync::Arc;

/// A state vote with its signer's public key and voting power, awaiting verification.
pub type UnverifiedStateVote = (StateVoteBlock, Bls12381G1PublicKey, u64);

/// Aggregate verified state votes into a `StateCertificate`.
///
/// Deduplicates votes by validator, aggregates BLS signatures, builds a signer
/// bitfield using the topology's committee indices, and extracts state_writes
/// from the first vote.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_state_certificate(
    tx_hash: Hash,
    shard: ShardGroupId,
    writes_commitment: Hash,
    votes: &[StateVoteBlock],
    read_nodes: Vec<NodeId>,
    voting_power: VotePower,
    committee_size: usize,
    topology: &dyn Topology,
) -> StateCertificate {
    // Deduplicate votes by validator to avoid aggregating the same signature multiple times
    let mut seen_validators = std::collections::HashSet::new();
    let unique_votes: Vec<_> = votes
        .iter()
        .filter(|vote| seen_validators.insert(vote.validator))
        .collect();

    // Aggregate BLS signatures from unique votes only
    let bls_signatures: Vec<Bls12381G2Signature> =
        unique_votes.iter().map(|vote| vote.signature).collect();

    let aggregated_signature = if !bls_signatures.is_empty() {
        Bls12381G2Signature::aggregate(&bls_signatures, true)
            .unwrap_or_else(|_| zero_bls_signature())
    } else {
        zero_bls_signature()
    };

    // Create signer bitfield using topology for correct committee index mapping
    let mut signers = SignerBitfield::new(committee_size);
    for vote in &unique_votes {
        if let Some(idx) = topology.committee_index_for_shard(shard, vote.validator) {
            signers.set(idx);
        }
    }

    let success = votes.first().map(|v| v.success).unwrap_or(false);
    // All votes for the same tx should have identical state_writes
    let state_writes = votes
        .first()
        .map(|v| v.state_writes.clone())
        .unwrap_or_default();

    StateCertificate {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        read_nodes,
        state_writes,
        writes_commitment,
        success,
        aggregated_signature,
        signers,
        voting_power: voting_power.0,
    }
}

/// Verify and aggregate state votes for a single transaction.
///
/// Groups votes by signing message (same `(tx_hash, writes_commitment, shard, success)`
/// sign the same message), then uses BLS same-message batch verification for
/// each group. Falls back to individual verification on batch failure.
///
/// For cross-transaction batching, see [`batch_verify_and_aggregate_state_votes`]
/// which uses `batch_verify_bls_different_messages` across accumulated items.
pub fn verify_and_aggregate_state_votes(
    votes: Vec<UnverifiedStateVote>,
) -> Vec<(StateVoteBlock, u64)> {
    let mut by_message: HashMap<Vec<u8>, Vec<UnverifiedStateVote>> = HashMap::new();
    for (vote, pk, power) in votes {
        let msg = vote.signing_message();
        by_message.entry(msg).or_default().push((vote, pk, power));
    }

    let mut verified_votes: Vec<(StateVoteBlock, u64)> = Vec::new();

    for (message, votes_for_root) in by_message {
        if votes_for_root.len() >= 2 {
            // Use BLS same-message batch verification
            let signatures: Vec<Bls12381G2Signature> =
                votes_for_root.iter().map(|(v, _, _)| v.signature).collect();
            let pubkeys: Vec<Bls12381G1PublicKey> =
                votes_for_root.iter().map(|(_, pk, _)| *pk).collect();

            let batch_valid = batch_verify_bls_same_message(&message, &signatures, &pubkeys);

            if batch_valid {
                for (vote, _, power) in votes_for_root {
                    verified_votes.push((vote, power));
                }
            } else {
                // Fallback to individual verification
                for (vote, pk, power) in votes_for_root {
                    if verify_bls12381_v1(&message, &pk, &vote.signature) {
                        verified_votes.push((vote, power));
                    }
                }
            }
        } else {
            // Single vote - verify individually
            let (vote, pk, power) = votes_for_root.into_iter().next().unwrap();
            if verify_bls12381_v1(&message, &pk, &vote.signature) {
                verified_votes.push((vote, power));
            }
        }
    }

    verified_votes
}

/// Verify a state certificate's aggregated BLS signature.
///
/// Filters public keys by the certificate's signer bitfield, aggregates the
/// filtered keys, and verifies the aggregated signature. Handles the zero
/// signature case (single-shard / no signers).
pub fn verify_state_certificate_signature(
    certificate: &StateCertificate,
    public_keys: &[Bls12381G1PublicKey],
) -> bool {
    let msg = certificate.signing_message();

    // Get the public keys of actual signers based on the bitfield
    let signer_keys: Vec<_> = public_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| certificate.signers.is_set(*i))
        .map(|(_, pk)| *pk)
        .collect();

    if signer_keys.is_empty() {
        // No signers - valid only if it's a zero signature (single-shard case)
        certificate.aggregated_signature == zero_bls_signature()
    } else {
        // Aggregate the public keys and verify (skip PK validation - trusted topology)
        match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
            Ok(aggregated_pk) => {
                verify_bls12381_v1(&msg, &aggregated_pk, &certificate.aggregated_signature)
            }
            Err(_) => false,
        }
    }
}

/// Batch verify state votes across multiple transactions.
///
/// Collects all individual (message, signature, pubkey) triples across all
/// tx_hashes and verifies them in ~2 pairing operations via
/// [`batch_verify_bls_different_messages`]. Falls back to individual
/// verification when the batch check fails (to identify which votes failed).
///
/// For a single tx_hash, delegates to [`verify_and_aggregate_state_votes`]
/// which applies same-message grouping (cheaper when many votes share a
/// merkle root).
pub fn batch_verify_and_aggregate_state_votes(
    items: Vec<(Hash, Vec<UnverifiedStateVote>)>,
) -> Vec<(Hash, Vec<(StateVoteBlock, u64)>)> {
    if items.is_empty() {
        return Vec::new();
    }

    // Single tx_hash — use the per-tx function which does same-message optimisation.
    if items.len() == 1 {
        let (tx_hash, votes) = items.into_iter().next().unwrap();
        let verified = verify_and_aggregate_state_votes(votes);
        return vec![(tx_hash, verified)];
    }

    // Flatten all votes across tx_hashes.
    let total_votes: usize = items.iter().map(|(_, v)| v.len()).sum();
    let mut messages = Vec::with_capacity(total_votes);
    let mut signatures = Vec::with_capacity(total_votes);
    let mut pubkeys = Vec::with_capacity(total_votes);
    let mut vote_data: Vec<(usize, StateVoteBlock, u64)> = Vec::with_capacity(total_votes);
    let mut tx_hashes = Vec::with_capacity(items.len());

    for (tx_idx, (tx_hash, votes)) in items.into_iter().enumerate() {
        tx_hashes.push(tx_hash);
        for (vote, pk, power) in votes {
            messages.push(vote.signing_message());
            signatures.push(vote.signature);
            pubkeys.push(pk);
            vote_data.push((tx_idx, vote, power));
        }
    }

    // Cross-transaction batch verification.
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let results = batch_verify_bls_different_messages(&msg_refs, &signatures, &pubkeys);

    // Reconstruct per-tx results.
    let num_items = tx_hashes.len();
    let mut per_tx: Vec<Vec<(StateVoteBlock, u64)>> = (0..num_items).map(|_| Vec::new()).collect();
    for (valid, (tx_idx, vote, power)) in results.into_iter().zip(vote_data) {
        if valid {
            per_tx[tx_idx].push((vote, power));
        }
    }

    tx_hashes.into_iter().zip(per_tx).collect()
}

/// Batch verify state certificate signatures.
///
/// Pre-aggregates signer public keys per certificate (cheap), then verifies
/// all aggregated signatures in ~2 pairing operations via
/// [`batch_verify_bls_different_messages`]. Falls back to individual
/// verification when the batch check fails.
///
/// Certificates with no signers are handled inline (zero-signature check).
pub fn batch_verify_state_certificate_signatures(
    items: &[(StateCertificate, Vec<Bls12381G1PublicKey>)],
) -> Vec<bool> {
    if items.is_empty() {
        return Vec::new();
    }

    if items.len() == 1 {
        return vec![verify_state_certificate_signature(&items[0].0, &items[0].1)];
    }

    let mut results = vec![false; items.len()];

    // Pre-process: aggregate signer keys per cert, collect for batch verify.
    let mut messages = Vec::with_capacity(items.len());
    let mut signatures = Vec::with_capacity(items.len());
    let mut agg_pubkeys = Vec::with_capacity(items.len());
    let mut batch_indices = Vec::with_capacity(items.len());

    for (i, (cert, public_keys)) in items.iter().enumerate() {
        let signer_keys: Vec<_> = public_keys
            .iter()
            .enumerate()
            .filter(|(j, _)| cert.signers.is_set(*j))
            .map(|(_, pk)| *pk)
            .collect();

        if signer_keys.is_empty() {
            // No signers — valid only if zero signature (single-shard case).
            results[i] = cert.aggregated_signature == zero_bls_signature();
            continue;
        }

        match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
            Ok(agg_pk) => {
                messages.push(cert.signing_message());
                signatures.push(cert.aggregated_signature);
                agg_pubkeys.push(agg_pk);
                batch_indices.push(i);
            }
            Err(_) => {
                results[i] = false;
            }
        }
    }

    if !messages.is_empty() {
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let batch_results =
            batch_verify_bls_different_messages(&msg_refs, &signatures, &agg_pubkeys);
        for (valid, &orig_idx) in batch_results.into_iter().zip(&batch_indices) {
            results[orig_idx] = valid;
        }
    }

    results
}

/// Execute a single-shard transaction and sign the vote.
///
/// Calls `executor.execute_single_shard()` with the given transaction,
/// then signs the execution result with the validator's private key.
///
/// Returns a `StateVoteBlock` containing the execution result and signature.
pub fn execute_and_sign_single_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx: &Arc<RoutableTransaction>,
    signing_key: &Bls12381G1PrivateKey,
    local_shard: ShardGroupId,
    validator_id: ValidatorId,
) -> StateVoteBlock {
    let (tx_hash, success, writes_commitment, state_writes) =
        match executor.execute_single_shard(storage, std::slice::from_ref(tx)) {
            Ok(output) => {
                if let Some(r) = output.results().first() {
                    (
                        r.tx_hash,
                        r.success,
                        r.writes_commitment,
                        r.state_writes.clone(),
                    )
                } else {
                    (tx.hash(), false, Hash::ZERO, vec![])
                }
            }
            Err(e) => {
                tracing::warn!(tx_hash = ?tx.hash(), error = %e, "Transaction execution failed");
                (tx.hash(), false, Hash::ZERO, vec![])
            }
        };

    // Sign immediately after execution
    let message = exec_vote_message(&tx_hash, &writes_commitment, local_shard, success);
    let signature = signing_key.sign_v1(&message);

    StateVoteBlock {
        transaction_hash: tx_hash,
        shard_group_id: local_shard,
        writes_commitment,
        success,
        state_writes,
        validator: validator_id,
        signature,
    }
}

/// Execute a cross-shard transaction with provisions and sign the vote.
///
/// Calls `executor.execute_cross_shard()` with the transaction and provisions,
/// using the topology to determine which nodes are local to this shard.
/// Signs the execution result with the validator's private key.
///
/// Returns a `StateVoteBlock` containing the execution result and signature.
#[allow(clippy::too_many_arguments)]
pub fn execute_and_sign_cross_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx_hash: Hash,
    transaction: &Arc<RoutableTransaction>,
    provisions: &[StateProvision],
    signing_key: &Bls12381G1PrivateKey,
    local_shard: ShardGroupId,
    validator_id: ValidatorId,
    topology: &dyn Topology,
) -> StateVoteBlock {
    let is_local_node = |node_id: &hyperscale_types::NodeId| -> bool {
        topology.shard_for_node_id(node_id) == local_shard
    };

    let (result_hash, success, writes_commitment, state_writes) = match executor
        .execute_cross_shard(
            storage,
            std::slice::from_ref(transaction),
            provisions,
            is_local_node,
        ) {
        Ok(output) => {
            if let Some(r) = output.results().first() {
                (
                    r.tx_hash,
                    r.success,
                    r.writes_commitment,
                    r.state_writes.clone(),
                )
            } else {
                (tx_hash, false, Hash::ZERO, vec![])
            }
        }
        Err(e) => {
            tracing::warn!(?tx_hash, error = %e, "Cross-shard execution failed");
            (tx_hash, false, Hash::ZERO, vec![])
        }
    };

    // Sign immediately after execution
    let message = exec_vote_message(&result_hash, &writes_commitment, local_shard, success);
    let signature = signing_key.sign_v1(&message);

    StateVoteBlock {
        transaction_hash: result_hash,
        shard_group_id: local_shard,
        writes_commitment,
        success,
        state_writes,
        validator: validator_id,
        signature,
    }
}
