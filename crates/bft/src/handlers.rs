//! Pure BFT algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use hyperscale_storage::{CommitStore, SubstateStore};
use hyperscale_types::{
    batch_verify_bls_same_message, compute_transaction_root, verify_bls12381_v1, Block,
    BlockHeader, BlockHeight, BlockVote, Bls12381G1PublicKey, Bls12381G2Signature, CommitmentProof,
    CycleProof, Hash, NodeId, QuorumCertificate, RoutableTransaction, ShardGroupId, SignerBitfield,
    TransactionAbort, TransactionCertificate, TransactionDefer, ValidatorId, VotePower,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Result of QC verification and assembly.
pub struct QcVerificationResult {
    pub block_hash: Hash,
    pub qc: Option<QuorumCertificate>,
    /// Verified votes returned when no QC was formed (for accumulation across rounds).
    /// Empty when a QC is successfully built.
    pub verified_votes: Vec<(usize, BlockVote, u64)>,
}

/// Verify block votes and build a quorum certificate if quorum is reached.
///
/// Algorithm:
/// 1. Start with already-verified votes and their signatures
/// 2. Batch verify new votes using same-message BLS optimization
/// 3. If batch fails, fall back to individual signature verification
/// 4. Check if verified voting power meets quorum threshold
/// 5. If quorum: aggregate signatures, build signer bitfield, compute weighted timestamp
/// 6. Return QC + empty verified_votes on success, or None + all verified_votes if no quorum
#[allow(clippy::too_many_arguments)]
pub fn verify_and_build_qc(
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
    parent_block_hash: Hash,
    signing_message: &[u8],
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
    already_verified: Vec<(usize, BlockVote, u64)>,
    total_voting_power: u64,
) -> QcVerificationResult {
    // Start with already-verified votes (e.g., our own vote)
    let mut all_verified: Vec<(usize, BlockVote, u64)> = already_verified;
    let mut all_signatures: Vec<Bls12381G2Signature> =
        all_verified.iter().map(|(_, v, _)| v.signature).collect();

    // Extract signatures and public keys from votes to verify
    let signatures: Vec<Bls12381G2Signature> = votes_to_verify
        .iter()
        .map(|(_, v, _, _)| v.signature)
        .collect();
    let public_keys: Vec<Bls12381G1PublicKey> =
        votes_to_verify.iter().map(|(_, _, pk, _)| *pk).collect();

    // Batch verify all new signatures (same message optimization)
    let batch_valid = if votes_to_verify.is_empty() {
        true
    } else {
        batch_verify_bls_same_message(signing_message, &signatures, &public_keys)
    };

    if batch_valid {
        // Happy path: all new signatures valid, add them to verified set
        for (idx, vote, _, power) in votes_to_verify {
            all_signatures.push(vote.signature);
            all_verified.push((idx, vote, power));
        }
    } else {
        // Some signatures invalid - verify individually to find valid ones
        tracing::warn!(
            block_hash = ?block_hash,
            vote_count = votes_to_verify.len(),
            "Batch vote verification failed, falling back to individual verification"
        );

        for (idx, vote, pk, power) in &votes_to_verify {
            if verify_bls12381_v1(signing_message, pk, &vote.signature) {
                all_signatures.push(vote.signature);
                all_verified.push((*idx, vote.clone(), *power));
            } else {
                tracing::warn!(
                    voter = ?vote.voter,
                    block_hash = ?block_hash,
                    "Invalid vote signature detected"
                );
            }
        }
    }

    let verified_power: u64 = all_verified.iter().map(|(_, _, power)| power).sum();

    // Check if we have quorum with all verified votes
    if VotePower::has_quorum(verified_power, total_voting_power) && !all_signatures.is_empty() {
        // Build QC - aggregate signatures
        let qc = match Bls12381G2Signature::aggregate(&all_signatures, true) {
            Ok(aggregated_signature) => {
                // Sort votes by committee index for deterministic bitfield
                let mut sorted_votes = all_verified.clone();
                sorted_votes.sort_by_key(|(idx, _, _)| *idx);

                // Build signers bitfield and calculate weighted timestamp
                let max_idx = sorted_votes
                    .iter()
                    .map(|(idx, _, _)| *idx)
                    .max()
                    .unwrap_or(0);
                let mut signers = SignerBitfield::new(max_idx + 1);
                let mut timestamp_weight_sum: u128 = 0;

                for (idx, vote, power) in &sorted_votes {
                    signers.set(*idx);
                    timestamp_weight_sum += vote.timestamp as u128 * *power as u128;
                }

                let weighted_timestamp_ms = if verified_power == 0 {
                    0
                } else {
                    (timestamp_weight_sum / verified_power as u128) as u64
                };

                Some(QuorumCertificate {
                    block_hash,
                    height,
                    parent_block_hash,
                    round,
                    aggregated_signature,
                    signers,
                    voting_power: VotePower(verified_power),
                    weighted_timestamp_ms,
                })
            }
            Err(e) => {
                tracing::warn!("Failed to aggregate BLS signatures for QC: {}", e);
                None
            }
        };

        // Return verified_votes only when QC build failed (for accumulation)
        let return_votes = if qc.is_none() { all_verified } else { vec![] };
        QcVerificationResult {
            block_hash,
            qc,
            verified_votes: return_votes,
        }
    } else {
        // No quorum - return all verified votes for later accumulation
        QcVerificationResult {
            block_hash,
            qc: None,
            verified_votes: all_verified,
        }
    }
}

/// Verify a quorum certificate's aggregated BLS signature.
///
/// Filters public keys by the QC's signer bitfield, aggregates the filtered
/// keys, and verifies the aggregated signature against the signing message.
pub fn verify_qc_signature(
    qc: &QuorumCertificate,
    public_keys: &[Bls12381G1PublicKey],
    signing_message: &[u8],
) -> bool {
    // Get signer keys based on QC's signer bitfield
    let signer_keys: Vec<_> = public_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| qc.signers.is_set(*i))
        .map(|(_, pk)| *pk)
        .collect();

    if signer_keys.is_empty() {
        // No signers - invalid QC (genesis is handled before action is emitted)
        return false;
    }

    // Aggregate the public keys and verify (skip PK validation - trusted topology)
    match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
        Ok(aggregated_pk) => {
            verify_bls12381_v1(signing_message, &aggregated_pk, &qc.aggregated_signature)
        }
        Err(_) => false,
    }
}

/// Verify a cycle proof's aggregated BLS signature and quorum threshold.
///
/// Aggregates all provided public keys, verifies the signature from
/// `cycle_proof.winner_commitment.aggregated_signature`, and checks that
/// the signer count meets the quorum threshold.
pub fn verify_cycle_proof(
    cycle_proof: &CycleProof,
    public_keys: &[Bls12381G1PublicKey],
    signing_message: &[u8],
    quorum_threshold: u64,
) -> bool {
    if public_keys.is_empty() {
        return false;
    }

    // Verify aggregated BLS signature (skip PK validation - trusted topology)
    let sig_valid = match Bls12381G1PublicKey::aggregate(public_keys, false) {
        Ok(aggregated_pk) => verify_bls12381_v1(
            signing_message,
            &aggregated_pk,
            &cycle_proof.winner_commitment.aggregated_signature,
        ),
        Err(_) => false,
    };

    // Also verify quorum threshold
    sig_valid && cycle_proof.winner_commitment.signer_count() as u64 >= quorum_threshold
}

/// Verify that the computed transaction merkle root matches the expected root.
///
/// Pure computation over the three transaction sections (retry, priority, normal).
pub fn verify_transaction_root(
    expected_root: Hash,
    retry_transactions: &[Arc<RoutableTransaction>],
    priority_transactions: &[Arc<RoutableTransaction>],
    transactions: &[Arc<RoutableTransaction>],
) -> bool {
    let computed_root =
        compute_transaction_root(retry_transactions, priority_transactions, transactions);
    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            retry_count = retry_transactions.len(),
            priority_count = priority_transactions.len(),
            tx_count = transactions.len(),
            "Transaction root verification FAILED"
        );
    }

    valid
}

/// Result of state root verification.
pub struct StateRootResult<P: Send> {
    pub valid: bool,
    pub prepared_commit: Option<P>,
}

/// Verify that the computed state root matches the expected root.
///
/// Calls `storage.prepare_block_commit()` to compute the speculative state root
/// from the certificates, then compares against the expected root. Returns the
/// prepared commit handle for caching on success.
pub fn verify_state_root<S: CommitStore>(
    storage: &S,
    parent_state_root: Hash,
    expected_root: Hash,
    certificates: &[Arc<TransactionCertificate>],
    local_shard: ShardGroupId,
) -> StateRootResult<S::PreparedCommit> {
    let (computed_root, prepared) =
        storage.prepare_block_commit(parent_state_root, certificates, local_shard);

    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            ?parent_state_root,
            "State root verification FAILED"
        );
    }

    StateRootResult {
        valid,
        prepared_commit: if valid { Some(prepared) } else { None },
    }
}

/// Result of building a proposal block.
pub struct ProposalResult<P: Send> {
    pub block: Block,
    pub block_hash: Hash,
    pub prepared_commit: Option<P>,
}

/// Build a proposal block, computing the state root if the JMT is ready.
///
/// Algorithm:
/// 1. Check JMT ready: `storage.state_root_hash() == parent_state_root`
/// 2. If ready + certs non-empty: `prepare_block_commit()` for certs, get state_root + handle
/// 3. Else: inherit parent_state_root, empty certs, no handle
/// 4. Compute tx root: `compute_transaction_root(retry, priority, normal)`
/// 5. Build BlockHeader + Block, hash it
/// 6. Return block, hash, optional prepared commit handle
#[allow(clippy::too_many_arguments)]
pub fn build_proposal<S: CommitStore + SubstateStore>(
    storage: &S,
    proposer: ValidatorId,
    height: BlockHeight,
    round: u64,
    parent_hash: Hash,
    parent_qc: QuorumCertificate,
    timestamp: u64,
    is_fallback: bool,
    parent_state_root: Hash,
    parent_state_version: u64,
    retry_transactions: Vec<Arc<RoutableTransaction>>,
    priority_transactions: Vec<Arc<RoutableTransaction>>,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<TransactionCertificate>>,
    commitment_proofs: HashMap<Hash, CommitmentProof>,
    deferred: Vec<TransactionDefer>,
    aborted: Vec<TransactionAbort>,
    local_shard: ShardGroupId,
) -> ProposalResult<S::PreparedCommit> {
    // Check if JMT is at parent_state_root (no waiting - instant check)
    let current_root = storage.state_root_hash();
    let jmt_ready = current_root == parent_state_root;

    // Can include certificates only if JMT is ready
    let include_certs = jmt_ready && !certificates.is_empty();

    let (state_root, state_version, certs_to_include, prepared) = if include_certs {
        // JMT ready - compute speculative root and get prepared commit handle
        let (root, prepared) =
            storage.prepare_block_commit(parent_state_root, &certificates, local_shard);
        let version = parent_state_version + certificates.len() as u64;
        (root, version, certificates, Some(prepared))
    } else {
        // Either no certificates, or JMT not ready - inherit parent state
        if !certificates.is_empty() {
            tracing::debug!(
                height = height.0,
                round = round,
                skipped_certs = certificates.len(),
                ?current_root,
                ?parent_state_root,
                "JMT not ready - proposing without certificates"
            );
        }
        (parent_state_root, parent_state_version, vec![], None)
    };

    // Compute transaction root from all transaction sections
    let transaction_root =
        compute_transaction_root(&retry_transactions, &priority_transactions, &transactions);

    // Build the block
    let header = BlockHeader {
        height,
        parent_hash,
        parent_qc,
        proposer,
        timestamp,
        round,
        is_fallback,
        state_root,
        state_version,
        transaction_root,
    };

    let block = Block {
        header,
        retry_transactions,
        priority_transactions,
        transactions,
        certificates: certs_to_include,
        deferred,
        aborted,
        commitment_proofs,
    };

    let block_hash = block.hash();

    ProposalResult {
        block,
        block_hash,
        prepared_commit: prepared,
    }
}

/// Compute a merkle root hash over sorted state writes.
///
/// Uses a simple hash chain over `(NodeId, value)` pairs sorted by NodeId
/// for determinism.
pub fn compute_merkle_root(writes: &[(NodeId, Vec<u8>)]) -> Hash {
    if writes.is_empty() {
        return Hash::ZERO;
    }

    // Sort writes for determinism
    let mut sorted: Vec<_> = writes.to_vec();
    sorted.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

    // Hash chain
    let mut data = Vec::new();
    for (node_id, value) in &sorted {
        data.extend_from_slice(&node_id.0);
        data.extend_from_slice(value);
    }
    Hash::from_bytes(&data)
}
