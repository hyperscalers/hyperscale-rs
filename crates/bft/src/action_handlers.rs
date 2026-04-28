//! Pure BFT algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use hyperscale_storage::{ChainWriter, SubstateStore};
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockVote, Bls12381G1PublicKey,
    Bls12381G2Signature, CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot, ProposerTimestamp,
    ProvisionHash, ProvisionTxRoot, ProvisionsRoot, QuorumCertificate, ReceiptBundle, Round,
    RoutableTransaction, ShardGroupId, SignerBitfield, StateRoot, TopologySnapshot,
    TransactionRoot, ValidatorId, VotePower, WeightedTimestamp, batch_verify_bls_same_message,
    compute_certificate_root, compute_local_receipt_root, compute_provision_root,
    compute_provision_tx_roots, compute_transaction_root, compute_waves, verify_bls12381_v1,
};
use std::sync::Arc;

/// Result of QC verification and assembly.
pub struct QcVerificationResult {
    /// Block being voted on.
    pub block_hash: BlockHash,
    /// Assembled QC, or `None` if quorum wasn't reached or aggregation failed.
    pub qc: Option<QuorumCertificate>,
    /// Verified votes returned when no QC was formed (for accumulation across rounds).
    /// Empty when a QC is successfully built.
    pub verified_votes: Vec<(usize, BlockVote, u64)>,
}

/// Verify block votes and build a quorum certificate if quorum is reached.
///
/// Thin composition of [`verify_vote_batch`] (signature verification) and
/// [`build_qc_from_verified`] (aggregation + bitfield + timestamp) with the
/// quorum-threshold check between them. Returns an empty `verified_votes`
/// vec on success and the full verified set on failure so the caller can
/// accumulate across rounds.
///
/// Called from the dispatch layer via `Action::VerifyAndBuildQuorumCertificate`;
/// the split helpers exist for focused unit testing of each phase.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_and_build_qc(
    block_hash: BlockHash,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
    already_verified: Vec<(usize, BlockVote, u64)>,
    total_voting_power: u64,
) -> QcVerificationResult {
    let signing_message =
        hyperscale_types::block_vote_message(shard_group_id, height, round, &block_hash);

    let all_verified = verify_vote_batch(
        block_hash,
        &signing_message,
        votes_to_verify,
        already_verified,
    );

    let verified_power: u64 = all_verified.iter().map(|(_, _, power)| power).sum();
    if all_verified.is_empty() || !VotePower::has_quorum(verified_power, total_voting_power) {
        return QcVerificationResult {
            block_hash,
            qc: None,
            verified_votes: all_verified,
        };
    }

    let qc = build_qc_from_verified(
        block_hash,
        shard_group_id,
        height,
        round,
        parent_block_hash,
        &all_verified,
    );

    let return_votes = if qc.is_none() { all_verified } else { vec![] };
    QcVerificationResult {
        block_hash,
        qc,
        verified_votes: return_votes,
    }
}

/// Verify a batch of vote signatures, appending the valid ones to
/// `already_verified` and returning the combined verified set.
///
/// Uses the same-message BLS batch check for speed; on batch failure (one
/// or more bad signatures) falls back to individual verification so a
/// single forged vote doesn't poison the whole batch.
pub fn verify_vote_batch(
    block_hash: BlockHash,
    signing_message: &[u8],
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
    already_verified: Vec<(usize, BlockVote, u64)>,
) -> Vec<(usize, BlockVote, u64)> {
    let mut all_verified = already_verified;

    if votes_to_verify.is_empty() {
        return all_verified;
    }

    let signatures: Vec<Bls12381G2Signature> = votes_to_verify
        .iter()
        .map(|(_, v, _, _)| v.signature)
        .collect();
    let public_keys: Vec<Bls12381G1PublicKey> =
        votes_to_verify.iter().map(|(_, _, pk, _)| *pk).collect();

    if batch_verify_bls_same_message(signing_message, &signatures, &public_keys) {
        for (idx, vote, _, power) in votes_to_verify {
            all_verified.push((idx, vote, power));
        }
        return all_verified;
    }

    tracing::warn!(
        ?block_hash,
        vote_count = votes_to_verify.len(),
        "Batch vote verification failed, falling back to individual verification"
    );

    for (idx, vote, pk, power) in votes_to_verify {
        if verify_bls12381_v1(signing_message, &pk, &vote.signature) {
            all_verified.push((idx, vote, power));
        } else {
            tracing::warn!(
                voter = ?vote.voter,
                ?block_hash,
                "Invalid vote signature detected"
            );
        }
    }

    all_verified
}

/// Aggregate a verified vote set into a [`QuorumCertificate`].
///
/// Sorts by committee index so the signer bitfield matches the aggregation
/// order the verifier will use, and computes the stake-weighted timestamp
/// from the vote timestamps.
///
/// Returns `None` only if BLS aggregation itself fails. Caller must ensure
/// `verified_votes` is non-empty and that quorum has been reached.
pub fn build_qc_from_verified(
    block_hash: BlockHash,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    verified_votes: &[(usize, BlockVote, u64)],
) -> Option<QuorumCertificate> {
    let mut sorted: Vec<_> = verified_votes.to_vec();
    sorted.sort_by_key(|(idx, _, _)| *idx);

    let signatures: Vec<Bls12381G2Signature> = sorted.iter().map(|(_, v, _)| v.signature).collect();
    let aggregated_signature = match Bls12381G2Signature::aggregate(&signatures, true) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::warn!("Failed to aggregate BLS signatures for QC: {}", e);
            return None;
        }
    };

    let max_idx = sorted.iter().map(|(idx, _, _)| *idx).max().unwrap_or(0);
    let mut signers = SignerBitfield::new(max_idx + 1);
    let mut timestamp_weight_sum: u128 = 0;
    let mut verified_power: u64 = 0;
    for (idx, vote, power) in &sorted {
        signers.set(*idx);
        timestamp_weight_sum += u128::from(vote.timestamp.as_millis()) * u128::from(*power);
        verified_power += *power;
    }

    let weighted_timestamp_ms = if verified_power == 0 {
        0
    } else {
        // Mean of u64 timestamps weighted by u64 powers always fits in u64.
        u64::try_from(timestamp_weight_sum / u128::from(verified_power)).unwrap_or(u64::MAX)
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

/// Verify a quorum certificate's aggregated BLS signature.
///
/// Filters public keys by the QC's signer bitfield, aggregates the filtered
/// keys, and verifies the aggregated signature against the signing message.
#[must_use]
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
    Bls12381G1PublicKey::aggregate(&signer_keys, false).is_ok_and(|aggregated_pk| {
        verify_bls12381_v1(&signing_message, &aggregated_pk, &qc.aggregated_signature)
    })
}

/// Verify that the computed transaction merkle root matches the expected root.
pub fn verify_provision_root(expected_root: ProvisionsRoot, batch_hashes: &[Hash]) -> bool {
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

/// Verify a block's transaction root and per-tx validity windows.
///
/// Two checks, both load-bearing for block validity:
///
/// 1. The merkle root of `transactions` matches `expected_root`.
/// 2. Every tx's `validity_range` is well-formed against `validity_anchor`
///    AND contains it. `validity_anchor` is the parent QC's
///    `weighted_timestamp` — the BFT-authenticated clock every honest
///    validator agrees on for this block. The check is the same expression
///    the proposer applied during selection, so an honest cluster never
///    sees this fail; a malicious proposer that included an expired tx
///    has the block rejected.
///
/// Half-open semantics: `start_inclusive <= anchor < end_exclusive`.
pub fn verify_transaction_root(
    expected_root: TransactionRoot,
    transactions: &[Arc<RoutableTransaction>],
    validity_anchor: WeightedTimestamp,
) -> bool {
    let computed_root = compute_transaction_root(transactions);
    let root_valid = computed_root == expected_root;

    if !root_valid {
        tracing::warn!(
            ?expected_root,
            ?computed_root,
            tx_count = transactions.len(),
            "Transaction root verification FAILED"
        );
    }

    let mut windows_valid = true;
    for tx in transactions {
        if !tx.validity_range.is_well_formed(validity_anchor)
            || !tx.validity_range.contains(validity_anchor)
        {
            tracing::warn!(
                tx_hash = ?tx.hash(),
                anchor_ms = validity_anchor.as_millis(),
                start_ms = tx.validity_range.start_timestamp_inclusive.as_millis(),
                end_ms = tx.validity_range.end_timestamp_exclusive.as_millis(),
                "Transaction validity range check FAILED"
            );
            windows_valid = false;
        }
    }

    root_valid && windows_valid
}

/// Verify a block's per-target-shard provisions commitments.
///
/// Recomputes the per-target merkle roots from the block's transactions and
/// compares against the header's claimed map by full equality. A missing or
/// tampered target-root fails because the recomputed root won't match.
pub fn verify_provision_tx_roots(
    expected: &std::collections::BTreeMap<ShardGroupId, ProvisionTxRoot>,
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
pub fn verify_certificate_root(
    expected_root: CertificateRoot,
    certificates: &[Arc<FinalizedWave>],
) -> bool {
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
pub fn verify_local_receipt_root(
    expected_root: LocalReceiptRoot,
    receipts: &[ReceiptBundle],
) -> bool {
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
    /// `true` when the computed state root matched the expected root.
    pub valid: bool,
    /// Prepared commit handle from the JMT verifier — `Some` on success so the
    /// commit pipeline can write it back without recomputing.
    pub prepared_commit: Option<P>,
}

/// Verify that the computed state root matches the expected root.
///
/// Calls `storage.prepare_block_commit()` to compute the speculative state root
/// from the wave receipts, then compares against the expected root. Returns the
/// prepared commit handle for caching on success.
pub fn verify_state_root<S: ChainWriter + SubstateStore>(
    storage: &S,
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    expected_root: StateRoot,
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
    /// The constructed proposal block (header + payload).
    pub block: Block,
    /// Hash of the constructed block, cached so callers don't recompute.
    pub block_hash: BlockHash,
    /// JMT prepared-commit handle from the proposer's pre-commit, threaded
    /// to the commit pipeline so the proposer doesn't recompute on commit.
    pub prepared_commit: Option<P>,
}

/// Build a proposal block, always computing the state root via `prepare_block_commit`.
///
/// Uses the overlay (`pending_snapshots`) when the JMT hasn't committed the
/// parent yet, so certificates are always included when available.
///
/// Algorithm:
/// 1. `prepare_block_commit()` with overlay snapshots → `state_root` + handle
/// 2. Compute tx/cert/receipt/provision roots
/// 3. Build `BlockHeader` + `Block`, hash it
/// 4. Return block, hash, prepared commit handle
#[allow(clippy::too_many_arguments)]
pub fn build_proposal<S: ChainWriter + SubstateStore>(
    storage: &S,
    proposer: ValidatorId,
    height: BlockHeight,
    round: Round,
    parent_hash: BlockHash,
    parent_qc: QuorumCertificate,
    timestamp: ProposerTimestamp,
    is_fallback: bool,
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<FinalizedWave>>,
    local_shard: ShardGroupId,
    topology: &TopologySnapshot,
    provisions: Vec<Arc<hyperscale_types::Provisions>>,
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

    let mut provision_hashes: Vec<ProvisionHash> = provisions.iter().map(|p| p.hash()).collect();
    provision_hashes.sort();

    let transaction_root = compute_transaction_root(&transactions);
    let certificate_root = compute_certificate_root(&certificates);
    let local_receipt_root = compute_local_receipt_root(&receipts);
    let raw_provision_hashes: Vec<Hash> = provision_hashes.iter().map(|h| h.into_raw()).collect();
    let provision_root = compute_provision_root(&raw_provision_hashes);
    let waves = compute_waves(topology, height, &transactions);
    let provision_tx_roots = compute_provision_tx_roots(topology, &transactions);

    // in_flight is deterministic from chain state:
    // parent's in_flight + new transactions committed - transactions finalized by certificates.
    let new_tx_count = u32::try_from(transactions.len()).unwrap_or(u32::MAX);
    let in_flight = parent_in_flight
        .saturating_add(new_tx_count)
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

fn collect_finalized_receipts(
    waves: &[Arc<FinalizedWave>],
) -> Vec<Arc<hyperscale_types::LocalReceipt>> {
    waves
        .iter()
        .flat_map(|fw| fw.receipts.iter())
        .map(|b| Arc::clone(&b.local_receipt))
        .collect()
}

/// Handle the BFT-owned delegated [`Action`] variants.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain). Variants
/// owned by other coordinator crates hit `unreachable!()` — the caller
/// (node's dispatcher) routes by variant prefix.
#[allow(clippy::too_many_lines)] // single dispatch over BFT-owned Action variants
pub fn handle_action<S, E>(
    action: hyperscale_core::Action,
    ctx: &hyperscale_core::ActionContext<'_, S, E>,
) where
    S: hyperscale_storage::Storage,
    E: hyperscale_engine::Engine,
{
    use hyperscale_core::{Action, NodeInput, PreparedBlock, ProtocolEvent, VerificationKind};
    use hyperscale_metrics as metrics;

    match action {
        Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_group_id,
            height,
            round,
            parent_block_hash,
            votes_to_verify,
            verified_votes,
            total_voting_power,
        } => {
            let start = std::time::Instant::now();
            let result = verify_and_build_qc(
                block_hash,
                shard_group_id,
                height,
                round,
                parent_block_hash,
                votes_to_verify,
                verified_votes,
                total_voting_power,
            );
            metrics::record_signature_verification_latency("vote", start.elapsed().as_secs_f64());
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::QuorumCertificateResult {
                    block_hash: result.block_hash,
                    qc: result.qc,
                    verified_votes: result.verified_votes,
                },
            ));
        }

        Action::VerifyQcSignature {
            qc,
            public_keys,
            block_hash,
        } => {
            let start = std::time::Instant::now();
            let valid = verify_qc_signature(&qc, &public_keys);
            metrics::record_signature_verification_latency("qc", start.elapsed().as_secs_f64());
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::QcSignatureVerified {
                block_hash,
                valid,
            }));
        }

        Action::VerifyRemoteHeaderQc {
            header,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
            shard,
            height,
        } => {
            let start = std::time::Instant::now();
            let qc_valid = verify_qc_signature(&header.qc, &committee_public_keys);
            let valid = if qc_valid {
                let total_power: u64 = header
                    .qc
                    .signers
                    .set_indices()
                    .filter_map(|idx| committee_voting_power.get(idx).copied())
                    .sum();
                total_power >= quorum_threshold && header.qc.block_hash == header.header.hash()
            } else {
                false
            };
            metrics::record_signature_verification_latency(
                "remote_header_qc",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                header,
                valid,
            }));
        }

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            transactions,
            validity_anchor,
        } => {
            let start = std::time::Instant::now();
            let valid = verify_transaction_root(expected_root, &transactions, validity_anchor);
            metrics::record_signature_verification_latency(
                "transaction_root",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::TransactionRoot,
                block_hash,
                valid,
            }));
        }

        Action::VerifyProvisionTxRoots {
            block_hash,
            expected,
            transactions,
            topology,
        } => {
            let start = std::time::Instant::now();
            let valid = verify_provision_tx_roots(&expected, &transactions, &topology);
            metrics::record_signature_verification_latency(
                "provision_tx_roots",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::ProvisionTxRoots,
                block_hash,
                valid,
            }));
        }

        Action::VerifyProvisionRoot {
            block_hash,
            expected_root,
            batch_hashes,
        } => {
            let start = std::time::Instant::now();
            let raw_batch_hashes: Vec<Hash> = batch_hashes.iter().map(|h| h.into_raw()).collect();
            let valid = verify_provision_root(expected_root, &raw_batch_hashes);
            metrics::record_signature_verification_latency(
                "provision_root",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::ProvisionRoot,
                block_hash,
                valid,
            }));
        }

        Action::VerifyCertificateRoot {
            block_hash,
            expected_root,
            certificates,
        } => {
            let start = std::time::Instant::now();
            let valid = verify_certificate_root(expected_root, &certificates);
            metrics::record_signature_verification_latency(
                "certificate_root",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::CertificateRoot,
                block_hash,
                valid,
            }));
        }

        Action::VerifyLocalReceiptRoot {
            block_hash,
            expected_root,
            receipts,
        } => {
            let start = std::time::Instant::now();
            let valid = verify_local_receipt_root(expected_root, &receipts);
            metrics::record_signature_verification_latency(
                "local_receipt_root",
                start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::LocalReceiptRoot,
                block_hash,
                valid,
            }));
        }

        Action::VerifyStateRoot {
            block_hash,
            // Anchor already applied via ctx.view (see `parent_hash_for`).
            parent_block_hash: _,
            parent_state_root,
            parent_block_height,
            expected_root,
            finalized_waves,
            block_height,
        } => {
            let start = std::time::Instant::now();
            let pending_snapshots = ctx.view.pending_snapshots().to_vec();
            let result = verify_state_root(
                &*ctx.view,
                parent_state_root,
                parent_block_height,
                expected_root,
                &finalized_waves,
                block_height,
                &pending_snapshots,
            );
            metrics::record_signature_verification_latency(
                "state_root",
                start.elapsed().as_secs_f64(),
            );
            if let Some(prepared) = result.prepared_commit {
                (ctx.commit_prepared)(PreparedBlock {
                    block_hash,
                    block_height,
                    prepared,
                    receipts: collect_finalized_receipts(&finalized_waves),
                });
            }
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                kind: VerificationKind::StateRoot,
                block_hash,
                valid: result.valid,
            }));
        }

        Action::BuildProposal {
            shard_group_id,
            proposer,
            height,
            round,
            parent_hash,
            parent_qc,
            timestamp,
            is_fallback,
            parent_state_root,
            parent_block_height,
            transactions,
            finalized_waves,
            provisions,
            parent_in_flight,
            finalized_tx_count,
        } => {
            let pending_snapshots = ctx.view.pending_snapshots().to_vec();
            let result = build_proposal(
                &*ctx.view,
                proposer,
                height,
                round,
                parent_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_block_height,
                transactions,
                finalized_waves.clone(),
                shard_group_id,
                ctx.topology,
                provisions.clone(),
                parent_in_flight,
                finalized_tx_count,
                &pending_snapshots,
            );
            let block_hash = result.block_hash;
            if let Some(prepared) = result.prepared_commit {
                (ctx.commit_prepared)(PreparedBlock {
                    block_hash,
                    block_height: height,
                    prepared,
                    receipts: collect_finalized_receipts(&finalized_waves),
                });
            }
            (ctx.notify)(NodeInput::Protocol(ProtocolEvent::ProposalBuilt {
                height,
                round,
                block: Arc::new(result.block),
                block_hash,
                finalized_waves,
                provisions,
            }));
        }

        _ => unreachable!("hyperscale_bft::handle_action called with non-BFT action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        Bls12381G1PrivateKey, ProposerTimestamp, ReceiptBundle, compute_certificate_root,
        compute_local_receipt_root, compute_provision_root, compute_transaction_root,
        generate_bls_keypair,
    };

    fn shard() -> ShardGroupId {
        ShardGroupId(0)
    }

    fn make_vote(
        keys: &[Bls12381G1PrivateKey],
        voter_index: usize,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
        timestamp_ms: u64,
    ) -> BlockVote {
        BlockVote::new(
            block_hash,
            shard(),
            height,
            round,
            ValidatorId(voter_index as u64),
            &keys[voter_index],
            ProposerTimestamp(timestamp_ms),
        )
    }

    fn keypairs(n: usize) -> Vec<Bls12381G1PrivateKey> {
        (0..n).map(|_| generate_bls_keypair()).collect()
    }

    // ─── verify_vote_batch ──────────────────────────────────────────────

    #[test]
    fn verify_vote_batch_empty_input_returns_already_verified_unchanged() {
        let keys = keypairs(2);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let v = make_vote(&keys, 0, block_hash, BlockHeight(1), Round::INITIAL, 1000);
        let already = vec![(0usize, v, 1u64)];
        let out = verify_vote_batch(block_hash, b"msg", Vec::new(), already.clone());
        assert_eq!(out.len(), already.len());
    }

    #[test]
    fn verify_vote_batch_accepts_all_valid_signatures() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight(1);
        let round = Round::INITIAL;
        let msg = hyperscale_types::block_vote_message(shard(), height, round, &block_hash);

        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), 1u64)
            })
            .collect();

        let out = verify_vote_batch(block_hash, &msg, to_verify, Vec::new());
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn verify_vote_batch_falls_back_when_one_signature_bad() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight(1);
        let round = Round::INITIAL;
        let msg = hyperscale_types::block_vote_message(shard(), height, round, &block_hash);

        // Vote 1's signature is replaced by a signature over a different block.
        let other_hash = BlockHash::from_raw(Hash::from_bytes(b"other"));
        let mut bad_vote = make_vote(&keys, 1, block_hash, height, round, 1000);
        let bad_signing_vote = make_vote(&keys, 1, other_hash, height, round, 1000);
        bad_vote.signature = bad_signing_vote.signature;

        let to_verify = vec![
            (
                0usize,
                make_vote(&keys, 0, block_hash, height, round, 1000),
                keys[0].public_key(),
                1u64,
            ),
            (1usize, bad_vote, keys[1].public_key(), 1u64),
            (
                2usize,
                make_vote(&keys, 2, block_hash, height, round, 1000),
                keys[2].public_key(),
                1u64,
            ),
        ];

        let out = verify_vote_batch(block_hash, &msg, to_verify, Vec::new());
        let indices: Vec<_> = out.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn verify_vote_batch_rejects_all_when_wrong_message() {
        let keys = keypairs(2);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let wrong_msg = b"unrelated";
        let to_verify: Vec<_> = (0..2)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, BlockHeight(1), Round::INITIAL, 1000);
                (i, vote, keys[i].public_key(), 1u64)
            })
            .collect();
        let out = verify_vote_batch(block_hash, wrong_msg, to_verify, Vec::new());
        assert!(out.is_empty());
    }

    // ─── build_qc_from_verified ─────────────────────────────────────────

    #[test]
    fn build_qc_from_verified_produces_round_trippable_qc() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let height = BlockHeight(5);
        let round = Round::INITIAL;
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));

        let verified: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, 1u64)
            })
            .collect();

        let qc = build_qc_from_verified(block_hash, shard(), height, round, parent, &verified)
            .expect("build_qc should succeed");

        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        assert!(verify_qc_signature(&qc, &pubs));
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.height, height);
        assert_eq!(qc.parent_block_hash, parent);
        assert_eq!(qc.signer_count(), 3);
    }

    #[test]
    fn build_qc_from_verified_sorts_signers_bitfield_deterministically() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = [2, 0, 3]
            .into_iter()
            .map(|i: usize| {
                let vote = make_vote(&keys, i, block_hash, BlockHeight(1), Round::INITIAL, 1000);
                (i, vote, 1u64)
            })
            .collect();

        let qc = build_qc_from_verified(
            block_hash,
            shard(),
            BlockHeight(1),
            Round::INITIAL,
            BlockHash::ZERO,
            &verified,
        )
        .unwrap();

        let set: Vec<_> = qc.signers.set_indices().collect();
        assert_eq!(set, vec![0, 2, 3]);
    }

    #[test]
    fn build_qc_from_verified_computes_stake_weighted_timestamp() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        // Votes with different timestamps and powers; weighted mean = (1000*1 + 2000*2 + 3000*3) / 6 = 14000/6 ≈ 2333.
        let verified = vec![
            (
                0,
                make_vote(&keys, 0, block_hash, BlockHeight(1), Round::INITIAL, 1000),
                1u64,
            ),
            (
                1,
                make_vote(&keys, 1, block_hash, BlockHeight(1), Round::INITIAL, 2000),
                2u64,
            ),
            (
                2,
                make_vote(&keys, 2, block_hash, BlockHeight(1), Round::INITIAL, 3000),
                3u64,
            ),
        ];

        let qc = build_qc_from_verified(
            block_hash,
            shard(),
            BlockHeight(1),
            Round::INITIAL,
            BlockHash::ZERO,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp.as_millis(), 2333);
    }

    // ─── verify_and_build_qc (composition) ──────────────────────────────

    #[test]
    fn verify_and_build_qc_returns_none_without_quorum() {
        // 3 votes of power 1 each, total 4 → 3/4 = quorum only if 2f+1 where f=1 (3/4 OK).
        // Use total_voting_power=10 to force failure (3 < 2/3*10 = 6.67).
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), 1u64)
            })
            .collect();

        let result = verify_and_build_qc(
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            to_verify,
            Vec::new(),
            10,
        );

        assert!(result.qc.is_none());
        assert_eq!(result.verified_votes.len(), 3);
    }

    #[test]
    fn verify_and_build_qc_builds_qc_when_quorum_reached() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), 1u64)
            })
            .collect();

        let result = verify_and_build_qc(
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            to_verify,
            Vec::new(),
            4,
        );

        let qc = result.qc.expect("quorum reached, QC expected");
        assert_eq!(qc.signer_count(), 3);
        assert!(result.verified_votes.is_empty());
    }

    // ─── verify_qc_signature ────────────────────────────────────────────

    #[test]
    fn verify_qc_signature_rejects_empty_signer_set() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, BlockHeight(1), Round::INITIAL, 1000);
                (i, vote, 1u64)
            })
            .collect();
        let mut qc = build_qc_from_verified(
            block_hash,
            shard(),
            BlockHeight(1),
            Round::INITIAL,
            BlockHash::ZERO,
            &verified,
        )
        .unwrap();
        qc.signers = SignerBitfield::new(3);

        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        assert!(!verify_qc_signature(&qc, &pubs));
    }

    #[test]
    fn verify_qc_signature_rejects_wrong_public_keys() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, BlockHeight(1), Round::INITIAL, 1000);
                (i, vote, 1u64)
            })
            .collect();
        let qc = build_qc_from_verified(
            block_hash,
            shard(),
            BlockHeight(1),
            Round::INITIAL,
            BlockHash::ZERO,
            &verified,
        )
        .unwrap();

        let wrong_keys = keypairs(3);
        let wrong_pubs: Vec<_> = wrong_keys
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();
        assert!(!verify_qc_signature(&qc, &wrong_pubs));
    }

    // ─── root verifiers ─────────────────────────────────────────────────

    #[test]
    fn verify_transaction_root_accepts_matching_root_and_rejects_otherwise() {
        let txs: Vec<Arc<RoutableTransaction>> = Vec::new();
        let root = compute_transaction_root(&txs);
        let anchor = WeightedTimestamp::ZERO;
        assert!(verify_transaction_root(root, &txs, anchor));
        assert!(!verify_transaction_root(
            TransactionRoot::from_raw(Hash::from_bytes(b"wrong")),
            &txs,
            anchor,
        ));
    }

    #[test]
    fn verify_transaction_root_rejects_expired_tx() {
        use hyperscale_types::test_utils::test_notarized_transaction_v1;
        use hyperscale_types::{TimestampRange, routable_from_notarized_v1};
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(100_000);
        // Range ends at 1_000ms — anchor at 100_000ms is well past
        // end_timestamp_exclusive, so the tx is expired.
        let expired_range = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        let notarized = test_notarized_transaction_v1(&[1]);
        let tx = Arc::new(
            routable_from_notarized_v1(notarized, expired_range).expect("valid notarized fixture"),
        );
        let txs = vec![tx];
        let root = compute_transaction_root(&txs);

        // Merkle root matches but the tx is expired — verification fails.
        assert!(!verify_transaction_root(root, &txs, anchor));

        // Same root, anchor inside the range — verification passes.
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));
        let notarized2 = test_notarized_transaction_v1(&[2]);
        let tx2 = Arc::new(
            routable_from_notarized_v1(notarized2, valid_range).expect("valid notarized fixture"),
        );
        let txs2 = vec![tx2];
        let root2 = compute_transaction_root(&txs2);
        assert!(verify_transaction_root(root2, &txs2, anchor));
    }

    #[test]
    fn verify_transaction_root_rejects_malformed_range() {
        use hyperscale_types::test_utils::test_notarized_transaction_v1;
        use hyperscale_types::{TimestampRange, routable_from_notarized_v1};
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(1_000);
        // Length over MAX_VALIDITY_RANGE.
        let too_wide = TimestampRange::new(
            WeightedTimestamp::ZERO,
            anchor.plus(Duration::from_mins(10)),
        );
        let notarized = test_notarized_transaction_v1(&[3]);
        let tx = Arc::new(
            routable_from_notarized_v1(notarized, too_wide).expect("valid notarized fixture"),
        );
        let txs = vec![tx];
        let root = compute_transaction_root(&txs);

        assert!(
            !verify_transaction_root(root, &txs, anchor),
            "malformed range must reject even when merkle root matches"
        );
    }

    #[test]
    fn verify_provision_root_matches_compute_provision_root() {
        let hashes = vec![Hash::from_bytes(b"a"), Hash::from_bytes(b"b")];
        let root = compute_provision_root(&hashes);
        assert!(verify_provision_root(root, &hashes));
        assert!(!verify_provision_root(
            ProvisionsRoot::from_raw(Hash::from_bytes(b"nope")),
            &hashes
        ));
    }

    #[test]
    fn verify_certificate_root_matches_compute_certificate_root() {
        let certs: Vec<Arc<FinalizedWave>> = Vec::new();
        let root = compute_certificate_root(&certs);
        assert!(verify_certificate_root(root, &certs));
        assert!(!verify_certificate_root(
            CertificateRoot::from_raw(Hash::from_bytes(b"wrong")),
            &certs
        ));
    }

    #[test]
    fn verify_local_receipt_root_matches_compute_local_receipt_root() {
        let receipts: Vec<ReceiptBundle> = Vec::new();
        let root = compute_local_receipt_root(&receipts);
        assert!(verify_local_receipt_root(root, &receipts));
        assert!(!verify_local_receipt_root(
            LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong")),
            &receipts
        ));
    }
}
