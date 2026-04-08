//! Execution handler functions shared between production and simulation runners.

use hyperscale_types::{
    batch_verify_bls_same_message, exec_vote_message, verify_bls12381_v1, zero_bls_signature,
    Bls12381G1PublicKey, Bls12381G2Signature, ExecutionCertificate, ExecutionVote, Hash,
    ShardGroupId, SignerBitfield, ValidatorId, WaveId,
};
use std::collections::{HashMap, HashSet};

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
    _shard: ShardGroupId,
    global_receipt_root: Hash,
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
    let mut signers = SignerBitfield::new(committee.len());
    for vote in &unique_votes {
        if let Some(idx) = committee.iter().position(|&v| v == vote.validator) {
            signers.set(idx);
        }
    }

    let vote_height = votes.first().map(|v| v.vote_height).unwrap_or(0);

    ExecutionCertificate {
        vote_height,
        wave_id: wave_id.clone(),
        global_receipt_root,
        tx_outcomes,
        aggregated_signature,
        signers,
    }
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
            vote.vote_height,
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
        certificate.vote_height,
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
