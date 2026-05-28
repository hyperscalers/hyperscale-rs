//! Pure shard consensus algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, PreparedBlock, ProtocolEvent};
use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_network::Network;
use hyperscale_storage::{JmtSnapshot, ShardChainWriter, ShardStorage};
use hyperscale_types::network::gossip::CommittedBlockHeaderGossip;
use hyperscale_types::network::notification::{BlockHeaderNotification, BlockVoteNotification};
use hyperscale_types::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BeaconWitnessRootContext, Block, BlockHash,
    BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PublicKey, CertificateRoot,
    CertificateRootContext, CommittedBlockHeader, CommittedHeaderVerifyError, ConsensusReceipt,
    FinalizedWave, Hash, InFlightCount, LocalReceiptRoot, LocalReceiptRootContext,
    NetworkDefinition, PreparedCommit, ProposerTimestamp, ProvisionHash, ProvisionTxRootsContext,
    ProvisionTxRootsMap, Provisions, ProvisionsRoot, ProvisionsRootContext, QcContext,
    QuorumCertificate, ReadySignal, Round, RoutableTransaction, ShardGroupId, StateRoot,
    StateRootContext, StoredReceipt, TopologySnapshot, TransactionRoot, TransactionRootContext,
    ValidatorId, Verifiable, Verified, Verify, VotePower, WeightedTimestamp, block_header_message,
    block_vote_message, committed_block_header_message, compute_waves,
};

/// Result of QC verification and assembly.
pub struct QcVerificationResult {
    /// Block being voted on.
    pub block_hash: BlockHash,
    /// Assembled QC, or `None` if quorum wasn't reached or aggregation failed.
    ///
    /// Carried as a [`Verified<QuorumCertificate>`] because the QC is verified
    /// by construction: every vote that fed into the aggregation was
    /// individually signature-checked, the signer set cleared the quorum
    /// threshold, and [`Verified::<QuorumCertificate>::from_verified_votes`]
    /// produced the typed witness from those preconditions.
    pub qc: Option<Verified<QuorumCertificate>>,
    /// Verified votes returned when no QC was formed (for accumulation across rounds).
    /// Empty when a QC is successfully built.
    pub verified_votes: Vec<(usize, Verified<BlockVote>, VotePower)>,
}

/// Verify block votes and build a quorum certificate if quorum is reached.
///
/// Thin composition of [`verify_vote_batch`] (signature verification) and
/// [`Verified::<QuorumCertificate>::from_verified_votes`] (aggregation +
/// bitfield + timestamp) with the quorum-threshold check between them.
/// Returns an empty `verified_votes` vec on success and the full verified
/// set on failure so the caller can accumulate across rounds.
///
/// Called from the dispatch layer via `Action::VerifyAndBuildQuorumCertificate`;
/// the split helpers exist for focused unit testing of each phase.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_and_build_qc(
    network: &NetworkDefinition,
    block_hash: BlockHash,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    parent_weighted_timestamp: WeightedTimestamp,
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, VotePower)>,
    already_verified: Vec<(usize, Verified<BlockVote>, VotePower)>,
    total_voting_power: VotePower,
) -> QcVerificationResult {
    let signing_message = block_vote_message(network, shard_group_id, height, round, &block_hash);

    let all_verified = verify_vote_batch(
        block_hash,
        &signing_message,
        votes_to_verify,
        already_verified,
    );

    let verified_power: VotePower = all_verified.iter().map(|(_, _, power)| *power).sum();
    if all_verified.is_empty() || !VotePower::has_quorum(verified_power, total_voting_power) {
        return QcVerificationResult {
            block_hash,
            qc: None,
            verified_votes: all_verified,
        };
    }

    let qc = Verified::<QuorumCertificate>::from_verified_votes(
        block_hash,
        shard_group_id,
        height,
        round,
        parent_block_hash,
        parent_weighted_timestamp,
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
/// Wraps [`Verified::<BlockVote>::verify_batch`] with the committee
/// bookkeeping (`(idx, vote, pubkey, power)` tuples → `(idx, verified,
/// power)`); the typed batch verifier owns the BLS work and the
/// individual-verify fallback.
pub fn verify_vote_batch(
    block_hash: BlockHash,
    signing_message: &[u8],
    votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, VotePower)>,
    already_verified: Vec<(usize, Verified<BlockVote>, VotePower)>,
) -> Vec<(usize, Verified<BlockVote>, VotePower)> {
    let mut all_verified = already_verified;

    if votes_to_verify.is_empty() {
        return all_verified;
    }

    // Capture per-vote bookkeeping (`idx`, `power`, and the raw vote for
    // failure logging) alongside the `(vote, pubkey)` pairs the typed
    // verifier consumes.
    let mut bookkeeping: Vec<(usize, VotePower, ValidatorId)> =
        Vec::with_capacity(votes_to_verify.len());
    let mut to_verify: Vec<(BlockVote, Bls12381G1PublicKey)> =
        Vec::with_capacity(votes_to_verify.len());
    for (idx, vote, pk, power) in votes_to_verify {
        bookkeeping.push((idx, power, vote.voter()));
        to_verify.push((vote, pk));
    }

    let results = Verified::<BlockVote>::verify_batch(signing_message, to_verify);

    for ((idx, power, voter), result) in bookkeeping.into_iter().zip(results) {
        if let Some(verified) = result {
            all_verified.push((idx, verified, power));
        } else {
            tracing::warn!(?voter, ?block_hash, "Invalid vote signature detected");
        }
    }

    all_verified
}

/// Result of building a proposal block.
pub struct ProposalResult {
    /// The constructed proposal block (header + payload).
    pub block: Block,
    /// Hash of the constructed block, cached so callers don't recompute.
    pub block_hash: BlockHash,
    /// Manifest carrying the proposer's drained `ready_signals` alongside
    /// the standard tx/cert/provision hash lists. The downstream
    /// gossip + pending-block pathway uses this; `BlockManifest::from_block`
    /// alone can't recover `ready_signals` since the field isn't on
    /// `Block`.
    pub manifest: BlockManifest,
    /// JMT prepared-commit closure from the proposer's pre-commit,
    /// threaded to the commit pipeline so the proposer doesn't recompute
    /// on commit.
    pub prepared_commit: PreparedCommit,
    /// JMT snapshot from the speculative state-root computation.
    /// Inserted into `PendingChain` so child verifications can chain on
    /// top.
    pub jmt_snapshot: Arc<JmtSnapshot>,
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
pub fn build_proposal<S: ShardChainWriter>(
    storage: &Arc<S>,
    proposer: ValidatorId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    parent_qc: QuorumCertificate,
    timestamp: ProposerTimestamp,
    is_fallback: bool,
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<FinalizedWave>>,
    local_shard: ShardGroupId,
    topology: &TopologySnapshot,
    provisions: Vec<Arc<Provisions>>,
    parent_in_flight: InFlightCount,
    finalized_tx_count: u32,
    ready_signals: Vec<ReadySignal>,
    beacon_witness_root: BeaconWitnessRoot,
    beacon_witness_leaf_count: BeaconWitnessLeafCount,
    pending_snapshots: &[Arc<JmtSnapshot>],
) -> ProposalResult {
    let (state_root, jmt_snapshot, prepared) = storage.prepare_block_commit(
        parent_state_root,
        parent_block_height,
        &certificates,
        height,
        pending_snapshots,
        None,
    );

    let receipts: Vec<StoredReceipt> = certificates
        .iter()
        .flat_map(|fw| fw.receipts().iter().cloned())
        .collect();

    let mut provision_hashes: Vec<ProvisionHash> = provisions.iter().map(|p| p.hash()).collect();
    provision_hashes.sort();

    let transaction_root = Verified::<TransactionRoot>::compute(&transactions).into_inner();
    let certificate_root = Verified::<CertificateRoot>::compute(&certificates).into_inner();
    let local_receipt_root = Verified::<LocalReceiptRoot>::compute(&receipts).into_inner();
    let raw_provision_hashes: Vec<Hash> = provision_hashes.iter().map(|h| h.into_raw()).collect();
    let provision_root = Verified::<ProvisionsRoot>::compute(&raw_provision_hashes).into_inner();
    let waves = compute_waves(topology, height, &transactions);
    let provision_tx_roots = Verified::<ProvisionTxRootsMap>::compute(topology, &transactions)
        .into_inner()
        .0;

    // in_flight is deterministic from chain state:
    // parent's in_flight + new transactions committed - transactions finalized by certificates.
    let new_tx_count = u32::try_from(transactions.len()).unwrap_or(u32::MAX);
    let in_flight = parent_in_flight
        .saturating_add(new_tx_count)
        .saturating_sub(finalized_tx_count);

    let header = BlockHeader::new(
        local_shard,
        height,
        parent_block_hash,
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
        beacon_witness_root,
        beacon_witness_leaf_count,
    );

    let block = Block::Live {
        header,
        transactions: Arc::new(transactions.into()),
        certificates: Arc::new(certificates.into()),
        provisions: Arc::new(provisions.into()),
    };

    // Manifest mirrors `BlockManifest::from_block` but carries the
    // proposer's drained `ready_signals` — the manifest field can't be
    // recovered from a `Block` alone, so the proposer threads it forward
    // here for the downstream gossip + pending-block pathway.
    let tx_hashes: Vec<_> = block.transactions().iter().map(|tx| tx.hash()).collect();
    let cert_ids: Vec<_> = block
        .certificates()
        .iter()
        .map(|c| c.wave_id().clone())
        .collect();
    let manifest = BlockManifest::new(tx_hashes, cert_ids, provision_hashes, ready_signals);

    let block_hash = block.hash();

    ProposalResult {
        block,
        block_hash,
        manifest,
        prepared_commit: prepared,
        jmt_snapshot,
    }
}

fn collect_finalized_receipts(
    waves: &[Arc<Verified<FinalizedWave>>],
) -> Vec<Arc<ConsensusReceipt>> {
    waves
        .iter()
        .flat_map(|fw| fw.consensus_receipts())
        .collect()
}

/// Strip the verified marker from each wave for downstream consumers
/// that take raw `Arc<FinalizedWave>` slices (storage writes, wire
/// types, root computations).
fn strip_verified_waves(waves: &[Arc<Verified<FinalizedWave>>]) -> Vec<Arc<FinalizedWave>> {
    waves.iter().map(|v| Arc::new((***v).clone())).collect()
}

/// Handle the shard-owned delegated [`Action`] variants.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain). Variants
/// owned by other coordinator crates hit `unreachable!()` — the caller
/// (node's dispatcher) routes by variant prefix.
#[allow(clippy::too_many_lines)] // single dispatch over shard-owned Action variants
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_group_id,
            height,
            round,
            parent_block_hash,
            parent_weighted_timestamp,
            votes_to_verify,
            verified_votes,
            total_voting_power,
        } => {
            let start = std::time::Instant::now();
            let result = verify_and_build_qc(
                ctx.topology_snapshot.network(),
                block_hash,
                shard_group_id,
                height,
                round,
                parent_block_hash,
                parent_weighted_timestamp,
                votes_to_verify,
                verified_votes,
                total_voting_power,
            );
            record_signature_verification_latency("vote", start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::QuorumCertificateResult {
                block_hash: result.block_hash,
                qc: result.qc,
                verified_votes: result.verified_votes,
            });
        }

        Action::VerifyQcSignature {
            qc,
            public_keys,
            voting_powers,
            quorum_threshold,
            block_hash,
        } => {
            let result = match qc {
                // Short-circuit: caller already holds the verified
                // witness (cached verified QC, local-dispatch from a
                // colocated origin). Skip BLS aggregation.
                Verifiable::Verified(verified) => Ok(verified),
                Verifiable::Unverified(raw) => {
                    let start = std::time::Instant::now();
                    let qc_ctx = QcContext {
                        network: ctx.topology_snapshot.network(),
                        public_keys: &public_keys,
                        voting_powers: &voting_powers,
                        quorum_threshold,
                    };
                    let result = raw.verify(&qc_ctx);
                    record_signature_verification_latency("qc", start.elapsed().as_secs_f64());
                    result
                }
            };
            ctx.notify_protocol(ProtocolEvent::QcSignatureVerified { block_hash, result });
        }

        Action::VerifyRemoteHeaderQc {
            committed_header,
            sender,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
            shard,
            height,
        } => {
            let start = std::time::Instant::now();
            let qc_ctx = QcContext {
                network: ctx.topology_snapshot.network(),
                public_keys: &committee_public_keys,
                voting_powers: &committee_voting_power,
                quorum_threshold,
            };
            // SAFETY for `from_qc_attestation`: the verified QC's source
            // committee accepted the header (and its `parent_qc`) before
            // voting; this node skips local per-root verification because
            // the QC's BFT majority attests on its behalf.
            let result = Box::new(
                committed_header
                    .qc()
                    .verify(&qc_ctx)
                    .map_err(CommittedHeaderVerifyError::from)
                    .and_then(|verified_qc| {
                        Verified::<CommittedBlockHeader>::from_qc_attestation(
                            committed_header.header().clone(),
                            verified_qc,
                        )
                    }),
            );
            record_signature_verification_latency(
                "remote_header_qc",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                sender,
                result,
            });
        }

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            transactions,
            validity_anchor,
        } => {
            let start = std::time::Instant::now();
            let tx_ctx = TransactionRootContext {
                transactions: &transactions,
                validity_anchor,
            };
            let result = expected_root.verify(&tx_ctx);
            record_signature_verification_latency(
                "transaction_root",
                start.elapsed().as_secs_f64(),
            );
            if let Err(e) = &result {
                tracing::warn!(?block_hash, reason = %e, "Transaction root verification FAILED");
            }
            ctx.notify_protocol(ProtocolEvent::TransactionRootVerified { block_hash, result });
        }

        Action::VerifyProvisionTxRoots {
            block_hash,
            expected,
            transactions,
            topology_snapshot,
        } => {
            let start = std::time::Instant::now();
            let ptx_ctx = ProvisionTxRootsContext {
                topology: &topology_snapshot,
                transactions: &transactions,
            };
            let result = expected.verify(&ptx_ctx);
            record_signature_verification_latency(
                "provision_tx_roots",
                start.elapsed().as_secs_f64(),
            );
            if let Err(e) = &result {
                tracing::warn!(?block_hash, reason = %e, "Provision tx-roots verification FAILED");
            }
            ctx.notify_protocol(ProtocolEvent::ProvisionTxRootsVerified { block_hash, result });
        }

        Action::VerifyProvisionRoot {
            block_hash,
            expected_root,
            batch_hashes,
        } => {
            let start = std::time::Instant::now();
            let raw_batch_hashes: Vec<Hash> = batch_hashes.iter().map(|h| h.into_raw()).collect();
            let pr_ctx = ProvisionsRootContext {
                batch_hashes: &raw_batch_hashes,
            };
            let result = expected_root.verify(&pr_ctx);
            record_signature_verification_latency("provision_root", start.elapsed().as_secs_f64());
            if let Err(e) = &result {
                tracing::warn!(?block_hash, reason = %e, "Provision root verification FAILED");
            }
            ctx.notify_protocol(ProtocolEvent::ProvisionsRootVerified { block_hash, result });
        }

        Action::VerifyCertificateRoot {
            block_hash,
            expected_root,
            certificates,
        } => {
            let start = std::time::Instant::now();
            let cert_ctx = CertificateRootContext {
                certificates: &certificates,
            };
            let result = expected_root.verify(&cert_ctx);
            record_signature_verification_latency(
                "certificate_root",
                start.elapsed().as_secs_f64(),
            );
            if let Err(e) = &result {
                tracing::warn!(?block_hash, reason = %e, "Certificate root verification FAILED");
            }
            ctx.notify_protocol(ProtocolEvent::CertificateRootVerified { block_hash, result });
        }

        Action::VerifyBeaconWitnessRoot {
            block_hash,
            expected_root,
            expected_leaf_count,
            parent_witness_leaves,
            parent_round,
            height,
            round,
            ready_signals,
            finalized_waves,
            topology_snapshot,
        } => {
            let start = std::time::Instant::now();
            let receipts: Vec<StoredReceipt> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect();
            let bw_ctx = BeaconWitnessRootContext {
                expected_leaf_count,
                parent_witness_leaves,
                parent_round,
                height,
                round,
                receipts: &receipts,
                ready_signals: &ready_signals,
                topology: &topology_snapshot,
            };
            let result = expected_root.verify(&bw_ctx);
            record_signature_verification_latency(
                "beacon_witness_root",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::BeaconWitnessRootVerified { block_hash, result });
        }

        Action::VerifyStateRoot {
            block_hash,
            parent_block_hash,
            parent_state_root,
            parent_block_height,
            expected_root,
            expected_local_receipt_root,
            finalized_waves,
            block_height,
        } => {
            // Pre-flight: hash the receipts and compare to the QC'd
            // `local_receipt_root`. If they diverge, JMT recomputation
            // can't match `state_root` either (receipts ARE the JMT input),
            // so short-circuit on the receipt-root failure alone — the
            // pipeline rejects the block on the `LocalReceiptRootVerified`
            // error without needing a synthetic state-root failure event.
            let stored_receipts: Vec<StoredReceipt> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect();

            let receipt_start = std::time::Instant::now();
            let receipt_ctx = LocalReceiptRootContext {
                receipts: &stored_receipts,
            };
            let receipt_result = expected_local_receipt_root.verify(&receipt_ctx);
            record_signature_verification_latency(
                "local_receipt_root",
                receipt_start.elapsed().as_secs_f64(),
            );
            let receipt_root_valid = receipt_result.is_ok();
            if let Err(e) = &receipt_result {
                tracing::warn!(?block_hash, reason = %e, "Local receipt root verification FAILED");
            }
            ctx.notify_protocol(ProtocolEvent::LocalReceiptRootVerified {
                block_hash,
                result: receipt_result,
            });

            if !receipt_root_valid {
                return;
            }

            let start = std::time::Instant::now();
            let view = ctx
                .pending_chain
                .view_at(parent_block_hash, parent_block_height);
            let pending_snapshots = view.pending_snapshots().to_vec();
            let raw_waves = strip_verified_waves(&finalized_waves);
            let (computed_root, jmt_snapshot, prepared) = view.prepare_block_commit(
                parent_state_root,
                parent_block_height,
                &raw_waves,
                block_height,
                &pending_snapshots,
                None,
            );
            let verify_result = expected_root.verify(StateRootContext { computed_root });
            record_signature_verification_latency("state_root", start.elapsed().as_secs_f64());
            if verify_result.is_ok() {
                // SAFETY: `prepared` belongs to the same JMT replay that just
                // produced the matching `computed_root` — only routed when
                // verification succeeds.
                (ctx.commit_prepared)(PreparedBlock {
                    block_hash,
                    parent_block_hash,
                    block_height,
                    prepared,
                    jmt_snapshot,
                    receipts: collect_finalized_receipts(&finalized_waves),
                });
            } else if let Err(e) = &verify_result {
                tracing::warn!(
                    block_hash = ?block_hash,
                    block_height = block_height.inner(),
                    parent_block_height = parent_block_height.inner(),
                    reason = %e,
                    "State root verification FAILED"
                );
            }
            ctx.notify_protocol(ProtocolEvent::StateRootVerified {
                block_hash,
                result: verify_result,
            });
        }

        Action::BuildProposal {
            shard_group_id,
            proposer,
            height,
            round,
            parent_block_hash,
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
            ready_signals,
            beacon_witness_root,
            beacon_witness_leaf_count,
        } => {
            let view = ctx
                .pending_chain
                .view_at(parent_block_hash, parent_block_height);
            let pending_snapshots = view.pending_snapshots().to_vec();
            let raw_waves = strip_verified_waves(&finalized_waves);
            let result = build_proposal(
                &view,
                proposer,
                height,
                round,
                parent_block_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_block_height,
                transactions,
                raw_waves,
                shard_group_id,
                ctx.topology_snapshot,
                provisions.clone(),
                parent_in_flight,
                finalized_tx_count,
                ready_signals,
                beacon_witness_root,
                beacon_witness_leaf_count,
                &pending_snapshots,
            );
            let block_hash = result.block_hash;
            (ctx.commit_prepared)(PreparedBlock {
                block_hash,
                parent_block_hash,
                block_height: height,
                prepared: result.prepared_commit,
                jmt_snapshot: result.jmt_snapshot,
                receipts: collect_finalized_receipts(&finalized_waves),
            });
            ctx.notify_protocol(ProtocolEvent::ProposalBuilt {
                height,
                round,
                block: Arc::new(result.block),
                block_hash,
                manifest: result.manifest,
                finalized_waves,
                provisions,
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        Action::BroadcastBlockHeader { header, manifest } => {
            let block_hash = header.hash();
            let msg = block_header_message(
                ctx.topology_snapshot.network(),
                header.shard_group_id(),
                header.height(),
                header.round(),
                &block_hash,
            );
            let sig = ctx.signing_key.sign_v1(&msg);
            let gossip = BlockHeaderNotification::new(*header, *manifest, sig);
            let local_peers: Vec<ValidatorId> = ctx
                .topology_snapshot
                .committee_for_shard(ctx.topology_snapshot.local_shard())
                .iter()
                .filter(|&&v| v != ctx.topology_snapshot.local_validator_id())
                .copied()
                .collect();
            ctx.network.notify(&local_peers, &gossip);
        }

        Action::SignAndBroadcastBlockVote {
            block_hash,
            height,
            round,
            timestamp,
            next_proposers,
        } => {
            let verified = Verified::<BlockVote>::sign_local(
                ctx.topology_snapshot.network(),
                block_hash,
                ctx.topology_snapshot.local_shard(),
                height,
                round,
                ctx.topology_snapshot.local_validator_id(),
                ctx.signing_key,
                timestamp,
            );
            let gossip = BlockVoteNotification::new(verified.clone());
            ctx.network.notify(&next_proposers, &gossip);
            // Feed our own signed vote back for local VoteSet tracking.
            ctx.notify_protocol(ProtocolEvent::BlockVoteReceived {
                vote: verified.into(),
            });
        }

        Action::BroadcastCommittedBlockHeader { committed_header } => {
            let msg = committed_block_header_message(
                ctx.topology_snapshot.network(),
                committed_header.header().shard_group_id(),
                committed_header.header().height(),
                &committed_header.header().hash(),
            );
            let sig = ctx.signing_key.sign_v1(&msg);
            let gossip = CommittedBlockHeaderGossip {
                committed_header: Arc::new(committed_header),
                sender: ctx.topology_snapshot.local_validator_id(),
                sender_signature: sig,
            };
            ctx.network.broadcast_global(&gossip);
        }

        _ => unreachable!("hyperscale_shard::handle_action called with non-shard action"),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{
        Bls12381G1PrivateKey, CertificateRoot, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        StoredReceipt, TimestampRange, TransactionRoot, TxRootVerifyError, generate_bls_keypair,
        routable_from_notarized_v1,
    };

    use super::*;

    fn shard() -> ShardGroupId {
        ShardGroupId::new(0)
    }

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
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
            &net(),
            block_hash,
            shard(),
            height,
            round,
            ValidatorId::new(voter_index as u64),
            &keys[voter_index],
            ProposerTimestamp::from_millis(timestamp_ms),
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
        let v = make_vote(
            &keys,
            0,
            block_hash,
            BlockHeight::new(1),
            Round::INITIAL,
            1000,
        );
        let already = vec![(
            0usize,
            Verified::<BlockVote>::new_unchecked_for_test(v),
            VotePower::new(1),
        )];
        let out = verify_vote_batch(block_hash, b"msg", Vec::new(), already.clone());
        assert_eq!(out.len(), already.len());
    }

    #[test]
    fn verify_vote_batch_accepts_all_valid_signatures() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let msg = block_vote_message(&net(), shard(), height, round, &block_hash);

        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), VotePower::new(1))
            })
            .collect();

        let out = verify_vote_batch(block_hash, &msg, to_verify, Vec::new());
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn verify_vote_batch_falls_back_when_one_signature_bad() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let msg = block_vote_message(&net(), shard(), height, round, &block_hash);

        // Vote 1's signature is replaced by a signature over a different block.
        let other_hash = BlockHash::from_raw(Hash::from_bytes(b"other"));
        let bad_vote = make_vote(&keys, 1, block_hash, height, round, 1000);
        let bad_signing_vote = make_vote(&keys, 1, other_hash, height, round, 1000);
        let (block_hash_v, sg, h, r, voter, _, ts) = bad_vote.into_parts();
        let bad_vote = BlockVote::from_parts(
            block_hash_v,
            sg,
            h,
            r,
            voter,
            bad_signing_vote.signature(),
            ts,
        );

        let to_verify = vec![
            (
                0usize,
                make_vote(&keys, 0, block_hash, height, round, 1000),
                keys[0].public_key(),
                VotePower::new(1),
            ),
            (1usize, bad_vote, keys[1].public_key(), VotePower::new(1)),
            (
                2usize,
                make_vote(&keys, 2, block_hash, height, round, 1000),
                keys[2].public_key(),
                VotePower::new(1),
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
                let vote = make_vote(
                    &keys,
                    i,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                );
                (i, vote, keys[i].public_key(), VotePower::new(1))
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
        let height = BlockHeight::new(5);
        let round = Round::INITIAL;
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));

        let verified: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (
                    i,
                    Verified::<BlockVote>::new_unchecked_for_test(vote),
                    VotePower::new(1),
                )
            })
            .collect();

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            block_hash,
            shard(),
            height,
            round,
            parent,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .expect("build_qc should succeed");

        // build_qc_from_verified wraps with `new_unchecked` under the
        // "votes pre-verified + quorum confirmed" trust source, so the
        // returned QC must round-trip through the Verify impl when fed
        // back its committee context.
        let pubs: Vec<_> = keys.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let powers = vec![VotePower::new(1); keys.len()];
        let net = net();
        let qc_ctx = QcContext {
            network: &net,
            public_keys: &pubs,
            voting_powers: &powers,
            quorum_threshold: VotePower::new(3),
        };
        qc.as_ref()
            .verify(&qc_ctx)
            .expect("freshly built QC must re-verify");
        assert_eq!(qc.block_hash(), block_hash);
        assert_eq!(qc.height(), height);
        assert_eq!(qc.parent_block_hash(), parent);
        assert_eq!(qc.signer_count(), 3);
    }

    #[test]
    fn build_qc_from_verified_sorts_signers_bitfield_deterministically() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = [2, 0, 3]
            .into_iter()
            .map(|i: usize| {
                let vote = make_vote(
                    &keys,
                    i,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                );
                (
                    i,
                    Verified::<BlockVote>::new_unchecked_for_test(vote),
                    VotePower::new(1),
                )
            })
            .collect();

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .unwrap();

        let set: Vec<_> = qc.signers().set_indices().collect();
        assert_eq!(set, vec![0, 2, 3]);
    }

    #[test]
    fn build_qc_from_verified_computes_stake_weighted_timestamp() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        // Votes with different timestamps and powers; weighted mean = (1000*1 + 2000*2 + 3000*3) / 6 = 14000/6 ≈ 2333.
        let verified = vec![
            (
                0usize,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    0,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                )),
                VotePower::new(1),
            ),
            (
                1,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    1,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    2000,
                )),
                VotePower::new(2),
            ),
            (
                2,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    2,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    3000,
                )),
                VotePower::new(3),
            ),
        ];

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp().as_millis(), 2333);
    }

    #[test]
    fn build_qc_from_verified_clamps_vote_timestamps_to_parent_floor() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        // Two voters under the floor (500, 800) and one above (3000); floor=2000.
        // Without clamp the mean would be (500 + 800 + 3000) / 3 = 1433 — below
        // parent. With clamp each below-floor vote rises to 2000, giving a mean
        // of (2000 + 2000 + 3000) / 3 = 2333, monotonically >= parent.
        let verified = vec![
            (
                0usize,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    0,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    500,
                )),
                VotePower::new(1),
            ),
            (
                1,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    1,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    800,
                )),
                VotePower::new(1),
            ),
            (
                2,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    2,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    3000,
                )),
                VotePower::new(1),
            ),
        ];

        let parent_floor = WeightedTimestamp::from_millis(2000);
        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            parent_floor,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp().as_millis(), 2333);
        assert!(qc.weighted_timestamp().as_millis() >= parent_floor.as_millis());
    }

    // ─── verify_and_build_qc (composition) ──────────────────────────────

    #[test]
    fn verify_and_build_qc_returns_none_without_quorum() {
        // 3 votes of power 1 each, total 4 → 3/4 = quorum only if 2f+1 where f=1 (3/4 OK).
        // Use total_voting_power=10 to force failure (3 < 2/3*10 = 6.67).
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), VotePower::new(1))
            })
            .collect();

        let result = verify_and_build_qc(
            &net(),
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            to_verify,
            Vec::new(),
            VotePower::new(10),
        );

        assert!(result.qc.is_none());
        assert_eq!(result.verified_votes.len(), 3);
    }

    #[test]
    fn verify_and_build_qc_builds_qc_when_quorum_reached() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key(), VotePower::new(1))
            })
            .collect();

        let result = verify_and_build_qc(
            &net(),
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            to_verify,
            Vec::new(),
            VotePower::new(4),
        );

        let qc = result.qc.expect("quorum reached, QC expected");
        assert_eq!(qc.signer_count(), 3);
        assert!(result.verified_votes.is_empty());
    }

    // Signature-verification predicate tests live next to the type, in
    // `crates/types/src/shard/quorum_certificate.rs::tests`.

    // ─── root verifiers ─────────────────────────────────────────────────

    #[test]
    fn verify_transaction_root_accepts_matching_root_and_rejects_otherwise() {
        let txs: Vec<Arc<RoutableTransaction>> = Vec::new();
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();
        let anchor = WeightedTimestamp::ZERO;
        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(root.verify(&ctx).is_ok());
        assert!(
            TransactionRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(&ctx)
                .is_err()
        );
    }

    #[test]
    fn verify_transaction_root_rejects_expired_tx() {
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
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();

        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(matches!(
            root.verify(&ctx),
            Err(TxRootVerifyError::ValidityWindowExpired { .. })
        ));

        // Same root, anchor inside the range — verification passes.
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));
        let notarized2 = test_notarized_transaction_v1(&[2]);
        let tx2 = Arc::new(
            routable_from_notarized_v1(notarized2, valid_range).expect("valid notarized fixture"),
        );
        let txs2 = vec![tx2];
        let root2 = Verified::<TransactionRoot>::compute(&txs2).into_inner();
        let ctx2 = TransactionRootContext {
            transactions: &txs2,
            validity_anchor: anchor,
        };
        assert!(root2.verify(&ctx2).is_ok());
    }

    #[test]
    fn verify_transaction_root_rejects_malformed_range() {
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
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();

        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(
            root.verify(&ctx).is_err(),
            "malformed range must reject even when merkle root matches"
        );
    }

    #[test]
    fn verify_provision_root_matches_compute_provision_root() {
        let hashes = vec![Hash::from_bytes(b"a"), Hash::from_bytes(b"b")];
        let root = Verified::<ProvisionsRoot>::compute(&hashes).into_inner();
        let ctx = ProvisionsRootContext {
            batch_hashes: &hashes,
        };
        assert!(root.verify(&ctx).is_ok());
        assert!(
            ProvisionsRoot::from_raw(Hash::from_bytes(b"nope"))
                .verify(&ctx)
                .is_err()
        );
    }

    #[test]
    fn verify_certificate_root_matches_compute_certificate_root() {
        let certs: Vec<Arc<FinalizedWave>> = Vec::new();
        let root = Verified::<CertificateRoot>::compute(&certs).into_inner();
        let ctx = CertificateRootContext {
            certificates: &certs,
        };
        assert!(root.verify(&ctx).is_ok());
        assert!(
            CertificateRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(&ctx)
                .is_err()
        );
    }

    #[test]
    fn verify_local_receipt_root_matches_compute_local_receipt_root() {
        let receipts: Vec<StoredReceipt> = Vec::new();
        let root = Verified::<LocalReceiptRoot>::compute(&receipts).into_inner();
        let ctx = LocalReceiptRootContext {
            receipts: &receipts,
        };
        assert!(root.verify(&ctx).is_ok());
        assert!(
            LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(&ctx)
                .is_err()
        );
    }
}
