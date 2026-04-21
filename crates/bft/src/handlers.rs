//! Pure BFT algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use hyperscale_storage::{ChainWriter, SubstateStore};
use hyperscale_types::{
    batch_verify_bls_same_message, compute_certificate_root, compute_local_receipt_root,
    compute_provision_root, compute_provision_tx_roots, compute_transaction_root, compute_waves,
    verify_bls12381_v1, Block, BlockHeader, BlockHeight, BlockVote, Bls12381G1PublicKey,
    Bls12381G2Signature, FinalizedWave, Hash, ProposerTimestamp, QuorumCertificate, ReceiptBundle,
    RoutableTransaction, ShardGroupId, SignerBitfield, TopologySnapshot, ValidatorId, VotePower,
    WeightedTimestamp,
};
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
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    round: u64,
    parent_block_hash: Hash,
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
    already_verified: Vec<(usize, BlockVote, u64)>,
    total_voting_power: u64,
) -> QcVerificationResult {
    let signing_message =
        hyperscale_types::block_vote_message(shard_group_id, height, round, &block_hash);
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
        batch_verify_bls_same_message(&signing_message, &signatures, &public_keys)
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
            if verify_bls12381_v1(&signing_message, pk, &vote.signature) {
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
                    timestamp_weight_sum += vote.timestamp.as_millis() as u128 * *power as u128;
                }

                let weighted_timestamp_ms = if verified_power == 0 {
                    0
                } else {
                    (timestamp_weight_sum / verified_power as u128) as u64
                };

                Some(QuorumCertificate {
                    block_hash,
                    shard_group_id,
                    height,
                    parent_block_hash,
                    round,
                    aggregated_signature,
                    signers,
                    weighted_timestamp: WeightedTimestamp(weighted_timestamp_ms),
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
pub fn verify_qc_signature(qc: &QuorumCertificate, public_keys: &[Bls12381G1PublicKey]) -> bool {
    let signing_message = qc.signing_message();
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
            verify_bls12381_v1(&signing_message, &aggregated_pk, &qc.aggregated_signature)
        }
        Err(_) => false,
    }
}

/// Verify that the computed transaction merkle root matches the expected root.
pub fn verify_provision_root(expected_root: Hash, batch_hashes: &[Hash]) -> bool {
    let computed_root = compute_provision_root(batch_hashes);
    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            batch_count = batch_hashes.len(),
            "Provision root verification FAILED"
        );
    }

    valid
}

pub fn verify_transaction_root(
    expected_root: Hash,
    transactions: &[Arc<RoutableTransaction>],
) -> bool {
    let computed_root = compute_transaction_root(transactions);
    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            tx_count = transactions.len(),
            "Transaction root verification FAILED"
        );
    }

    valid
}

/// Verify a block's per-target-shard provision-batch commitments.
///
/// Recomputes the per-target merkle roots from the block's transactions and
/// compares against the header's claimed map by full equality. A missing or
/// tampered target-root fails because the recomputed root won't match.
pub fn verify_provision_tx_roots(
    expected: &std::collections::BTreeMap<ShardGroupId, Hash>,
    transactions: &[Arc<RoutableTransaction>],
    topology: &TopologySnapshot,
) -> bool {
    let computed = compute_provision_tx_roots(topology, transactions);
    let valid = &computed == expected;

    if !valid {
        tracing::warn!(
            tx_count = transactions.len(),
            ?expected,
            ?computed,
            "Provision tx-root verification FAILED"
        );
    }

    valid
}

/// Verify a block's receipt root against its wave certificates.
///
/// Pure computation over the certificates' `receipt_hash` values.
pub fn verify_certificate_root(expected_root: Hash, certificates: &[Arc<FinalizedWave>]) -> bool {
    let computed_root = compute_certificate_root(certificates);
    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            cert_count = certificates.len(),
            "Certificate root verification FAILED"
        );
    }

    valid
}

/// Verify a block's local receipt root against its receipt bundles.
///
/// Pure computation over the receipts' `receipt_hash()` values.
pub fn verify_local_receipt_root(expected_root: Hash, receipts: &[ReceiptBundle]) -> bool {
    let computed_root = compute_local_receipt_root(receipts);
    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            receipt_count = receipts.len(),
            "Local receipt root verification FAILED"
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
/// from the wave receipts, then compares against the expected root. Returns the
/// prepared commit handle for caching on success.
pub fn verify_state_root<S: ChainWriter + SubstateStore>(
    storage: &S,
    parent_state_root: Hash,
    parent_block_height: BlockHeight,
    expected_root: Hash,
    finalized_waves: &[Arc<FinalizedWave>],
    block_height: BlockHeight,
    pending_snapshots: &[Arc<hyperscale_storage::JmtSnapshot>],
) -> StateRootResult<S::PreparedCommit> {
    // Use the stable parent_block_height from the verification pipeline, not
    // storage.jmt_height() which is racy — by the time this runs on the
    // ConsensusCrypto pool, other blocks may have committed and advanced the
    // JMT past the parent version.
    // `base_reads=None` lets a `SubstateView` storage drain its own
    // execution-time cache inside its `prepare_block_commit` impl. Raw
    // storage types (no view) fall through to `multi_get_cf`.
    let (computed_root, prepared) = storage.prepare_block_commit(
        parent_state_root,
        parent_block_height,
        finalized_waves,
        block_height,
        pending_snapshots,
        None,
    );

    let valid = computed_root == expected_root;

    if !valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            ?parent_state_root,
            block_height = block_height.0,
            parent_block_height = parent_block_height.0,
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

/// Build a proposal block, always computing the state root via `prepare_block_commit`.
///
/// Uses the overlay (`pending_snapshots`) when the JMT hasn't committed the
/// parent yet, so certificates are always included when available.
///
/// Algorithm:
/// 1. `prepare_block_commit()` with overlay snapshots → state_root + handle
/// 2. Compute tx/cert/receipt/provision roots
/// 3. Build BlockHeader + Block, hash it
/// 4. Return block, hash, prepared commit handle
#[allow(clippy::too_many_arguments)]
pub fn build_proposal<S: ChainWriter + SubstateStore>(
    storage: &S,
    proposer: ValidatorId,
    height: BlockHeight,
    round: u64,
    parent_hash: Hash,
    parent_qc: QuorumCertificate,
    timestamp: ProposerTimestamp,
    is_fallback: bool,
    parent_state_root: Hash,
    parent_block_height: BlockHeight,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<FinalizedWave>>,
    local_shard: ShardGroupId,
    topology: &TopologySnapshot,
    provisions: Vec<Arc<hyperscale_types::Provision>>,
    parent_in_flight: u32,
    finalized_tx_count: u32,
    pending_snapshots: &[Arc<hyperscale_storage::JmtSnapshot>],
) -> ProposalResult<S::PreparedCommit> {
    let (state_root, prepared) = storage.prepare_block_commit(
        parent_state_root,
        parent_block_height,
        &certificates,
        height,
        pending_snapshots,
        None,
    );

    let receipts: Vec<ReceiptBundle> = certificates
        .iter()
        .flat_map(|fw| fw.receipts.iter().cloned())
        .collect();

    let mut provision_hashes: Vec<Hash> = provisions.iter().map(|p| p.hash()).collect();
    provision_hashes.sort();

    let transaction_root = compute_transaction_root(&transactions);
    let certificate_root = compute_certificate_root(&certificates);
    let local_receipt_root = compute_local_receipt_root(&receipts);
    let provision_root = compute_provision_root(&provision_hashes);
    let waves = compute_waves(topology, height, &transactions);
    let provision_tx_roots = compute_provision_tx_roots(topology, &transactions);

    // in_flight is deterministic from chain state:
    // parent's in_flight + new transactions committed - transactions finalized by certificates.
    let in_flight = parent_in_flight
        .saturating_add(transactions.len() as u32)
        .saturating_sub(finalized_tx_count);

    let header = BlockHeader {
        shard_group_id: local_shard,
        height,
        parent_hash,
        parent_qc,
        proposer,
        timestamp,
        round,
        is_fallback,
        state_root,
        transaction_root,
        certificate_root,
        local_receipt_root,
        provision_root,
        waves,
        provision_tx_roots,
        in_flight,
    };

    let block = Block::Live {
        header,
        transactions,
        certificates,
        provisions,
    };

    let block_hash = block.hash();

    ProposalResult {
        block,
        block_hash,
        prepared_commit: Some(prepared),
    }
}
