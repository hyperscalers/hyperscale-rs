//! Pure execution algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core transaction execution, aggregation, and
//! verification algorithms, separated from dispatch (thread pool vs inline)
//! and result delivery (channel vs event queue) concerns.
//!
//! Each execution function is the single-transaction unit of work. Production
//! wraps calls in `rayon::par_iter()` for parallelism; simulation calls sequentially.
//!
//! The `batch_verify_*` functions use BLS batch verification to verify
//! accumulated signatures across multiple transactions in ~2 pairing
//! operations. These are called from the I/O loop's time-windowed batch flush.

use hyperscale_engine::{RadixExecutor, SingleTxResult};
use hyperscale_storage::SubstateStore;
use hyperscale_types::{
    batch_verify_bls_same_message, exec_wave_vote_message, verify_bls12381_v1, zero_bls_signature,
    Bls12381G1PublicKey, Bls12381G2Signature, ExecutionWaveCertificate, ExecutionWaveVote, Hash,
    NodeId, RoutableTransaction, ShardGroupId, SignerBitfield, ValidatorId, WaveId, WaveTxOutcome,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Execute a single-shard transaction.
///
/// Calls `executor.execute_single_shard()` with the given transaction.
/// Returns the `SingleTxResult` with execution output.
pub fn execute_single_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx: &Arc<RoutableTransaction>,
) -> SingleTxResult {
    let result = match executor.execute_single_shard(storage, std::slice::from_ref(tx)) {
        Ok(output) => {
            if let Some(r) = output.results().first() {
                r.clone()
            } else {
                SingleTxResult::failure(tx.hash(), "No execution result returned")
            }
        }
        Err(e) => {
            tracing::warn!(tx_hash = ?tx.hash(), error = %e, "Transaction execution failed");
            SingleTxResult::failure(tx.hash(), e.to_string())
        }
    };

    // Filter out undeclared system state writes
    let mut result = result;
    result.database_updates =
        filter_to_declared_writes(&result.database_updates, &tx.declared_writes);

    result
}

/// Execute a cross-shard transaction with provisions.
///
/// Calls `executor.execute_cross_shard()` with the transaction and provisions.
/// Returns the `SingleTxResult` with execution output.
pub fn execute_cross_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx_hash: Hash,
    transaction: &Arc<RoutableTransaction>,
    provisions: &[hyperscale_types::StateProvision],
) -> SingleTxResult {
    let result = match executor.execute_cross_shard(
        storage,
        std::slice::from_ref(transaction),
        provisions,
    ) {
        Ok(output) => {
            if let Some(r) = output.results().first() {
                r.clone()
            } else {
                SingleTxResult::failure(tx_hash, "No cross-shard execution result returned")
            }
        }
        Err(e) => {
            tracing::warn!(?tx_hash, error = %e, "Cross-shard execution failed");
            SingleTxResult::failure(tx_hash, e.to_string())
        }
    };

    // Filter out undeclared system state writes
    let mut result = result;
    result.database_updates =
        filter_to_declared_writes(&result.database_updates, &transaction.declared_writes);

    result
}

/// Remove writes to NodeIds not in the transaction's declared write set.
///
/// Radix Engine may touch system state (fee vaults, royalty accumulators,
/// transaction tracker) that is not part of the transaction's declared
/// writes. These undeclared writes must be stripped before the result
/// enters the execution cache / JVT.
fn filter_to_declared_writes(
    updates: &hyperscale_storage::DatabaseUpdates,
    declared_writes: &[NodeId],
) -> hyperscale_storage::DatabaseUpdates {
    if declared_writes.is_empty() {
        return updates.clone();
    }
    let allowed: HashSet<NodeId> = declared_writes.iter().copied().collect();
    let mut filtered = hyperscale_storage::DatabaseUpdates::default();
    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(node_id) = hyperscale_storage::keys::db_node_key_to_node_id(db_node_key) else {
            continue;
        };
        if allowed.contains(&node_id) {
            filtered
                .node_updates
                .insert(db_node_key.clone(), node_updates.clone());
        }
    }
    filtered
}

/// Extract wave-ready result data from a SingleTxResult.
///
/// Called on the handler thread (after execution, before returning to state machine)
/// so that write_nodes extraction and success determination happen off the main thread.
/// The returned `WaveTxOutcome` is fed into the wave accumulator by the state machine.
pub fn extract_wave_result(result: &hyperscale_engine::SingleTxResult) -> WaveTxOutcome {
    let write_nodes = extract_write_nodes(&result.database_updates);
    WaveTxOutcome {
        tx_hash: result.tx_hash,
        receipt_hash: result.receipt_hash,
        success: result.success,
        write_nodes,
    }
}

/// Extract deduplicated, deterministically-ordered NodeIds from DatabaseUpdates.
///
/// Uses BTreeSet to ensure all validators within a shard produce identical
/// write_nodes vectors (deterministic ordering from identical execution).
pub fn extract_write_nodes(updates: &hyperscale_storage::DatabaseUpdates) -> Vec<NodeId> {
    updates
        .node_updates
        .keys()
        .filter_map(|db_node_key| hyperscale_storage::keys::db_node_key_to_node_id(db_node_key))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

// ============================================================================
// Wave-based execution voting handlers
// ============================================================================

/// Aggregate verified execution wave votes into an `ExecutionWaveCertificate`.
///
/// Same pattern as `aggregate_execution_certificate` but for wave-level votes.
/// Deduplicates votes by validator, aggregates BLS signatures, and builds a
/// signer bitfield using the committee's indices.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_execution_wave_certificate(
    wave_id: &WaveId,
    shard: ShardGroupId,
    wave_receipt_root: Hash,
    votes: &[ExecutionWaveVote],
    tx_outcomes: Vec<WaveTxOutcome>,
    committee: &[ValidatorId],
) -> ExecutionWaveCertificate {
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
    let mut signers = SignerBitfield::new(committee.len());
    for vote in &unique_votes {
        if let Some(idx) = committee.iter().position(|&v| v == vote.validator) {
            signers.set(idx);
        }
    }

    let block_hash = votes.first().map(|v| v.block_hash).unwrap_or(Hash::ZERO);
    let block_height = votes.first().map(|v| v.block_height).unwrap_or(0);

    ExecutionWaveCertificate {
        block_hash,
        block_height,
        wave_id: wave_id.clone(),
        shard_group_id: shard,
        wave_receipt_root,
        tx_outcomes,
        aggregated_signature,
        signers,
    }
}

/// Batch verify execution wave votes.
///
/// Uses BLS same-message batch verification since all votes in a wave
/// should sign the same message (same wave_receipt_root). Falls back to
/// individual verification on batch failure.
///
/// Returns an iterator of `(vote, voting_power)` for verified votes.
pub fn batch_verify_execution_wave_votes(
    votes: Vec<(ExecutionWaveVote, Bls12381G1PublicKey, u64)>,
) -> impl Iterator<Item = (ExecutionWaveVote, u64)> {
    if votes.is_empty() {
        return Vec::new().into_iter();
    }

    // Group by signing message (all votes for same wave should share one)
    let mut by_message: HashMap<Vec<u8>, Vec<(ExecutionWaveVote, Bls12381G1PublicKey, u64)>> =
        HashMap::new();
    for (vote, pk, power) in votes {
        let msg = exec_wave_vote_message(
            &vote.block_hash,
            vote.block_height,
            &vote.wave_id,
            vote.shard_group_id,
            &vote.wave_receipt_root,
            vote.tx_count,
        );
        by_message.entry(msg).or_default().push((vote, pk, power));
    }

    let mut verified: Vec<(ExecutionWaveVote, u64)> = Vec::new();

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

/// Verify an execution wave certificate's aggregated signature.
///
/// Verifies an execution wave certificate's aggregated BLS signature.
pub fn verify_execution_wave_certificate_signature(
    certificate: &ExecutionWaveCertificate,
    public_keys: &[Bls12381G1PublicKey],
) -> bool {
    let msg = exec_wave_vote_message(
        &certificate.block_hash,
        certificate.block_height,
        &certificate.wave_id,
        certificate.shard_group_id,
        &certificate.wave_receipt_root,
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
