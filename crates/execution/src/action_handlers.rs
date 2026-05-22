//! Pure execution functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the asynchronous side of the execution
//! state machine: BLS verification, execution-vote aggregation into
//! [`ExecutionCertificate`]s, transaction execution against a
//! [`SubstateView`], and cross-shard provisioning requests. They are
//! kept free of node/runner concerns so the dispatcher only handles
//! event plumbing — sharing the handlers between production and
//! simulation keeps execution behavior identical across both backends.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, Parallelism, ProtocolEvent};
use hyperscale_engine::{
    CachedSlot, CachedVmOutput, ProcessExecutionCache, SlotStatus, build_cross_shard_ownership,
    project_to_shard, resolve_owned_nodes,
};
use hyperscale_metrics::record_execution_latency;
use hyperscale_network::Network;
use hyperscale_storage::{Storage, SubstateStore, SubstateView};
use hyperscale_types::network::notification::{
    ExecutionCertificatesNotification, ExecutionVotesNotification,
};
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, ExecutionCertificate, ExecutionVote,
    GlobalReceiptRoot, NodeId, RoutableTransaction, ShardGroupId, SignerBitfield, StoredReceipt,
    ValidatorId, VotePower, WaveId, WeightedTimestamp, batch_verify_bls_same_message,
    compute_global_receipt_root, exec_cert_batch_message, exec_vote_batch_message,
    exec_vote_message, shard_for_node, verify_bls12381_v1, zero_bls_signature,
};

// ============================================================================
// Wave-based execution voting handlers
// ============================================================================

/// Aggregate verified execution votes into an `ExecutionCertificate`.
///
/// Deduplicates votes by validator, aggregates BLS signatures, and builds a
/// signer bitfield using the committee's indices.
///
/// `tx_outcomes` are taken from the first vote whose outcomes hash to the
/// signed `global_receipt_root`. The BLS signature only commits to
/// `(global_receipt_root, tx_count)` directly, but the receipt root is itself
/// the Merkle root over `tx_outcomes` — so the unsigned outcomes payload
/// must self-consistently produce the signed root, otherwise an EC's
/// `canonical_hash` would commit to bogus outcomes a Byzantine validator
/// chose. `batch_verify_execution_votes` enforces this at intake by dropping
/// votes whose outcomes don't hash to their claimed root, so every vote
/// reaching this function already satisfies the binding.
///
/// # Panics
///
/// Panics if no vote has outcomes hashing to `global_receipt_root`, or if
/// BLS aggregation of the (already individually-verified) signatures fails.
/// Both indicate an upstream invariant violation (intake filter bypassed,
/// sub-quorum input, or BLS library bug) — neither is recoverable.
#[must_use]
pub fn aggregate_execution_certificate(
    wave_id: &WaveId,
    global_receipt_root: GlobalReceiptRoot,
    votes: &[ExecutionVote],
    committee: &[ValidatorId],
) -> ExecutionCertificate {
    let tx_outcomes = votes
        .iter()
        .find(|v| compute_global_receipt_root(v.tx_outcomes()) == global_receipt_root)
        .map(|v| v.tx_outcomes().to_vec())
        .expect("intake filter guarantees a vote with matching outcomes");

    // Deduplicate votes by validator
    let mut seen_validators = HashSet::new();
    let unique_votes: Vec<_> = votes
        .iter()
        .filter(|vote| seen_validators.insert(vote.validator()))
        .collect();

    // Aggregate BLS signatures
    let bls_signatures: Vec<Bls12381G2Signature> =
        unique_votes.iter().map(|vote| vote.signature()).collect();

    let aggregated_signature = if bls_signatures.is_empty() {
        zero_bls_signature()
    } else {
        Bls12381G2Signature::aggregate(&bls_signatures, true)
            .expect("aggregation of upstream-verified BLS signatures cannot fail")
    };

    // Create signer bitfield using committee ordering
    let committee_index: HashMap<ValidatorId, usize> = committee
        .iter()
        .enumerate()
        .map(|(idx, &vid)| (vid, idx))
        .collect();
    let mut signers = SignerBitfield::new(committee.len());
    for vote in &unique_votes {
        if let Some(&idx) = committee_index.get(&vote.validator()) {
            signers.set(idx);
        }
    }

    let vote_anchor_ts = votes
        .first()
        .map_or(WeightedTimestamp::ZERO, ExecutionVote::vote_anchor_ts);

    ExecutionCertificate::new(
        wave_id.clone(),
        vote_anchor_ts,
        global_receipt_root,
        tx_outcomes,
        aggregated_signature,
        signers,
    )
}

/// Batch verify execution votes.
///
/// Uses BLS same-message batch verification since all votes in a wave
/// should sign the same message (same `global_receipt_root`). Falls back to
/// individual verification on batch failure.
///
/// Drops votes whose `tx_outcomes` don't hash to the claimed
/// `global_receipt_root` before signature verification — the BLS signature
/// covers `(root, tx_count)` but not the unsigned outcomes payload, so a
/// vote that signs an honest root while shipping tampered outcomes is
/// self-inconsistent. Filtering at intake (rather than defending at
/// aggregation) keeps the bucket invariant tight: every verified vote has
/// outcomes that produce its claimed root.
///
/// Returns an iterator of `(vote, voting_power)` for verified votes.
pub fn batch_verify_execution_votes(
    votes: Vec<(ExecutionVote, Bls12381G1PublicKey, VotePower)>,
) -> impl Iterator<Item = (ExecutionVote, VotePower)> {
    let votes: Vec<_> = votes
        .into_iter()
        .filter(|(v, _, _)| compute_global_receipt_root(v.tx_outcomes()) == v.global_receipt_root())
        .collect();

    if votes.is_empty() {
        return Vec::new().into_iter();
    }

    // Group by signing message (all votes for same wave should share one)
    let mut by_message: HashMap<Vec<u8>, Vec<(ExecutionVote, Bls12381G1PublicKey, VotePower)>> =
        HashMap::new();
    for (vote, pk, power) in votes {
        let msg = exec_vote_message(
            vote.vote_anchor_ts(),
            vote.wave_id(),
            vote.shard_group_id(),
            &vote.global_receipt_root(),
            vote.tx_count(),
        );
        by_message.entry(msg).or_default().push((vote, pk, power));
    }

    let mut verified: Vec<(ExecutionVote, VotePower)> = Vec::new();

    for (message, group) in by_message {
        if group.len() >= 2 {
            let signatures: Vec<_> = group.iter().map(|(v, _, _)| v.signature()).collect();
            let pubkeys: Vec<_> = group.iter().map(|(_, pk, _)| *pk).collect();

            if batch_verify_bls_same_message(&message, &signatures, &pubkeys) {
                for (vote, _, power) in group {
                    verified.push((vote, power));
                }
            } else {
                // Batch failed — verify individually
                for (vote, pk, power) in group {
                    if verify_bls12381_v1(&message, &pk, &vote.signature()) {
                        verified.push((vote, power));
                    }
                }
            }
        } else {
            // Single vote — verify directly
            for (vote, pk, power) in group {
                if verify_bls12381_v1(&message, &pk, &vote.signature()) {
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
#[must_use]
pub fn verify_execution_certificate_signature(
    certificate: &ExecutionCertificate,
    public_keys: &[Bls12381G1PublicKey],
) -> bool {
    let msg = exec_vote_message(
        certificate.vote_anchor_ts(),
        certificate.wave_id(),
        certificate.shard_group_id(),
        &certificate.global_receipt_root(),
        u32::try_from(certificate.tx_outcomes().len()).unwrap_or(u32::MAX),
    );

    let signer_keys: Vec<_> = public_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| certificate.signers().is_set(*i))
        .map(|(_, pk)| *pk)
        .collect();

    if signer_keys.is_empty() {
        certificate.aggregated_signature() == zero_bls_signature()
    } else {
        Bls12381G1PublicKey::aggregate(&signer_keys, false).is_ok_and(|aggregated_pk| {
            verify_bls12381_v1(&msg, &aggregated_pk, &certificate.aggregated_signature())
        })
    }
}

/// Handle the execution-owned delegated [`Action`] variants.
///
/// Shards this transaction reads or writes, routed via `shard_for_node`.
///
/// Drives the execution cache's per-entry pending-shards set: the cache
/// narrows this to the host's hosted shards and decrements per-shard as
/// finalised waves arrive.
fn participating_shards(
    tx: &RoutableTransaction,
    num_shards: u64,
) -> impl Iterator<Item = ShardGroupId> + '_ {
    tx.declared_reads()
        .iter()
        .chain(tx.declared_writes().iter())
        .map(move |n| shard_for_node(n, num_shards))
}

/// Plan derived for each position in a batch by classifying its
/// `ProcessExecutionCache` slot up-front. `Done` skips work; `Claimed`
/// runs `compute` and fills the slot; `Pending` blocks on another
/// worker's slot via `get_or_init` (the closure only fires if the
/// claimant abandoned the slot without setting a value).
enum Plan {
    Done(Arc<CachedVmOutput>),
    Claimed(CachedSlot),
    Pending(CachedSlot),
}

/// Two-phase cache acquisition for a batch of transactions.
///
/// Phase 1 classifies every position sequentially via `try_acquire` —
/// cheap `DashMap` lookups that publish all Claimed slots to other
/// concurrent batches before any compute starts. Phase 2 fans out via
/// `par.map`: `Done` returns the cached value, `Claimed` runs `compute`
/// and fills the slot, `Pending` blocks via `OnceLock::get_or_init`
/// (each blocked worker waits only on its own slot, so the wait
/// parallelises across the pool).
fn batch_compute_cached(
    par: Parallelism,
    cache: &ProcessExecutionCache,
    txs: &[Arc<RoutableTransaction>],
    num_shards: u64,
    compute: impl Fn(usize) -> CachedVmOutput + Send + Sync,
) -> Vec<Arc<CachedVmOutput>> {
    let plans: Vec<(usize, Plan)> = txs
        .iter()
        .enumerate()
        .map(
            |(i, tx)| match cache.try_acquire(tx.hash(), participating_shards(tx, num_shards)) {
                SlotStatus::Completed(v) => (i, Plan::Done(v)),
                SlotStatus::Claimed(slot) => (i, Plan::Claimed(slot)),
                SlotStatus::Pending(slot) => (i, Plan::Pending(slot)),
            },
        )
        .collect();

    par.map(plans, |(i, plan)| match plan {
        Plan::Done(v) => v,
        Plan::Claimed(slot) => {
            let value = Arc::new(compute(i));
            let _ = slot.set(Arc::clone(&value));
            value
        }
        Plan::Pending(slot) => Arc::clone(slot.get_or_init(|| Arc::new(compute(i)))),
    })
}

/// Outcomes flow through `ctx.notify`. Variants owned by other coordinator
/// crates hit `unreachable!()` — node's dispatcher routes by variant prefix.
///
/// # Panics
///
/// Panics if the dispatcher routes a variant owned by another crate, or if
/// the executor breaks its "one result per input transaction" contract.
#[allow(clippy::too_many_lines)] // single dispatch over execution-owned Action variants
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: Storage,
    N: Network,
{
    match action {
        Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            let certificate =
                aggregate_execution_certificate(&wave_id, global_receipt_root, &votes, &committee);
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate: Arc::new(certificate),
            });
        }
        Action::VerifyAndAggregateExecutionVotes {
            wave_id,
            block_hash,
            votes,
        } => {
            let verified_votes: Vec<_> = batch_verify_execution_votes(votes).collect();
            ctx.notify_protocol(ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            });
        }
        Action::VerifyExecutionCertificateSignature {
            certificate,
            public_keys,
            ..
        } => {
            let valid = verify_execution_certificate_signature(&certificate, &public_keys);
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateSignatureVerified {
                certificate: Arc::new(certificate),
                valid,
            });
        }
        Action::VerifyFinalizedWave {
            wave,
            ec_public_keys,
        } => {
            let valid = wave
                .execution_certificates()
                .iter()
                .zip(ec_public_keys.iter())
                .all(|(ec, keys)| verify_execution_certificate_signature(ec, keys));
            ctx.notify_protocol(ProtocolEvent::FinalizedWaveVerified { wave, valid });
        }
        Action::ExecuteTransactions {
            wave_id,
            block_hash,
            block_height,
            transactions,
            state_root: _,
        } => {
            let start = std::time::Instant::now();
            let local_shard = ctx.topology_snapshot.local_shard();
            let num_shards = ctx.topology_snapshot.num_shards();
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let view_snap = <SubstateView<_> as SubstateStore>::snapshot(&*view);
            let cached = batch_compute_cached(
                ctx.par,
                ctx.execution_cache.as_ref(),
                transactions.as_slice(),
                num_shards,
                |i| {
                    ctx.executor
                        .compute_vm_output_single_shard(&view_snap, &transactions[i])
                },
            );
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = transactions
                .iter()
                .zip(cached)
                .map(|(tx, cached)| {
                    // Single-shard ownership is purely local: every declared
                    // account lives on this shard. Computed per-call rather
                    // than cached so the cache stays shard-invariant (matches
                    // the cross-shard path).
                    let declared: Vec<NodeId> = tx
                        .declared_reads()
                        .iter()
                        .chain(tx.declared_writes().iter())
                        .copied()
                        .collect();
                    let ownership = resolve_owned_nodes(&view_snap, &declared);
                    let executed =
                        project_to_shard(&cached, tx.hash(), local_shard, num_shards, &ownership);
                    (executed.outcome(), StoredReceipt::from(executed))
                })
                .unzip();
            record_execution_latency(start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            });
        }
        Action::ExecuteCrossShardTransactions {
            wave_id,
            block_hash,
            block_height,
            requests,
        } => {
            let start = std::time::Instant::now();
            let local_shard = ctx.topology_snapshot.local_shard();
            let num_shards = ctx.topology_snapshot.num_shards();
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let view_snap = <SubstateView<_> as SubstateStore>::snapshot(&*view);
            let txs: Vec<Arc<RoutableTransaction>> = requests
                .iter()
                .map(|r| Arc::clone(&r.transaction))
                .collect();

            // Build the per-vnode merged ownership map once per request, then
            // thread the same map through the executor (for `receipt_hash`)
            // and `project_to_shard` (for the shard filter). The map is not
            // cached: cross-shard packed vnodes share a process cache but see
            // different remote provisions, so caching one vnode's map under
            // `tx_hash` would corrupt the shard filter on the other. `Err`
            // means the transaction touches a vault claimed by accounts on
            // both shards — fast-abort below so every committee produces the
            // same `Failed` outcome instead of executing a divergent VM view.
            let ownerships: Vec<Result<HashMap<NodeId, NodeId>, Vec<NodeId>>> = requests
                .iter()
                .map(|req| {
                    let declared: Vec<NodeId> = req
                        .transaction
                        .declared_reads()
                        .iter()
                        .chain(req.transaction.declared_writes().iter())
                        .copied()
                        .collect();
                    build_cross_shard_ownership(
                        &view_snap,
                        &declared,
                        &req.ownership,
                        local_shard,
                        num_shards,
                    )
                })
                .collect();

            let cached = batch_compute_cached(
                ctx.par,
                ctx.execution_cache.as_ref(),
                &txs,
                num_shards,
                |i| {
                    let req = &requests[i];
                    ownerships[i].as_ref().map_or_else(
                        |_| CachedVmOutput::ownership_conflict_aborted(req.transaction.hash()),
                        |ownership| {
                            ctx.executor.compute_vm_output_cross_shard(
                                &view_snap,
                                &req.transaction,
                                &req.provisions,
                                ownership,
                            )
                        },
                    )
                },
            );
            let empty_ownership: HashMap<NodeId, NodeId> = HashMap::new();
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = requests
                .iter()
                .zip(cached)
                .zip(ownerships.iter())
                .map(|((req, cached), ownership)| {
                    let tx_hash = req.transaction.hash();
                    let ownership = ownership.as_ref().unwrap_or(&empty_ownership);
                    let executed =
                        project_to_shard(&cached, tx_hash, local_shard, num_shards, ownership);
                    (executed.outcome(), StoredReceipt::from(executed))
                })
                .unzip();
            record_execution_latency(start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        Action::SignAndSendExecutionVote {
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            global_receipt_root,
            tx_outcomes,
            leader,
        } => {
            let local_shard = ctx.topology_snapshot.local_shard();
            let validator_id = ctx.topology_snapshot.local_validator_id();
            let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
            let msg = exec_vote_message(
                vote_anchor_ts,
                &wave_id,
                local_shard,
                &global_receipt_root,
                tx_count,
            );
            let sig = ctx.signing_key.sign_v1(&msg);
            let vote = ExecutionVote::new(
                block_hash,
                block_height,
                vote_anchor_ts,
                wave_id,
                local_shard,
                global_receipt_root,
                tx_count,
                tx_outcomes,
                validator_id,
                sig,
            );

            // Send vote to the wave leader (unicast).
            if leader != validator_id {
                let batch_msg = exec_vote_batch_message(local_shard, std::slice::from_ref(&vote));
                let batch_sig = ctx.signing_key.sign_v1(&batch_msg);
                let batch =
                    ExecutionVotesNotification::new(vec![vote.clone()], validator_id, batch_sig);
                ctx.network.notify(&[leader], &batch);
            }

            // Feed own vote to state machine only if we are the leader.
            if leader == validator_id {
                ctx.notify_protocol(ProtocolEvent::ExecutionVoteReceived { vote });
            }
        }

        Action::BroadcastExecutionCertificate {
            shard: _,
            certificate,
            recipients,
        } => {
            let cert = Arc::unwrap_or_clone(certificate);
            let msg = exec_cert_batch_message(cert.shard_group_id(), std::slice::from_ref(&cert));
            let sig = ctx.signing_key.sign_v1(&msg);
            let batch = ExecutionCertificatesNotification::new(
                vec![cert],
                ctx.topology_snapshot.local_validator_id(),
                sig,
            );
            ctx.network.notify(&recipients, &batch);
        }

        _ => unreachable!("hyperscale_execution::handle_action called with non-execution action"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BlockHash, BlockHeight, Bls12381G1PrivateKey, ExecutionOutcome, GlobalReceiptHash, Hash,
        ShardGroupId, TxHash, TxOutcome, bls_keypair_from_seed,
    };

    use super::*;

    fn shard() -> ShardGroupId {
        ShardGroupId::new(0)
    }

    fn wave_id(height: u64) -> WaveId {
        WaveId::new(shard(), BlockHeight::new(height), BTreeSet::new())
    }

    fn keypair(seed: u8) -> Bls12381G1PrivateKey {
        bls_keypair_from_seed(&[seed; 32])
    }

    fn outcome(tx: TxHash) -> TxOutcome {
        TxOutcome::new(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
    }

    fn signed_vote(
        voter: ValidatorId,
        sk: &Bls12381G1PrivateKey,
        wid: &WaveId,
        global_receipt_root: GlobalReceiptRoot,
        anchor: WeightedTimestamp,
        tx_outcomes: Vec<TxOutcome>,
    ) -> ExecutionVote {
        let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
        let msg = exec_vote_message(anchor, wid, shard(), &global_receipt_root, tx_count);
        ExecutionVote::new(
            BlockHash::ZERO,
            BlockHeight::new(1),
            anchor,
            wid.clone(),
            shard(),
            global_receipt_root,
            tx_count,
            tx_outcomes,
            voter,
            sk.sign_v1(&msg),
        )
    }

    // ─── aggregate_execution_certificate ─────────────────────────────────

    #[test]
    fn aggregate_produces_signer_bitfield_in_committee_order() {
        // Committee is [V0, V1, V2, V3]; voters are V1 and V3.
        // Expected bits set: 1, 3.
        let committee = vec![
            ValidatorId::new(0),
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
        ];
        let wid = wave_id(1);
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let outcomes = vec![outcome(tx)];
        let root = compute_global_receipt_root(&outcomes);

        let sk1 = keypair(1);
        let sk3 = keypair(3);
        let votes = vec![
            signed_vote(
                ValidatorId::new(1),
                &sk1,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId::new(3),
                &sk3,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes.clone(),
            ),
        ];

        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);
        assert!(ec.signers().is_set(1));
        assert!(ec.signers().is_set(3));
        assert!(!ec.signers().is_set(0));
        assert!(!ec.signers().is_set(2));
        assert_eq!(ec.tx_outcomes(), &outcomes);
    }

    #[test]
    fn aggregate_dedups_votes_from_same_validator() {
        let committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let wid = wave_id(1);
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&outcomes);
        let sk0 = keypair(0);

        // Same voter cast twice.
        let votes = vec![
            signed_vote(
                ValidatorId::new(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId::new(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes,
            ),
        ];

        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);
        assert!(ec.signers().is_set(0));
        assert!(!ec.signers().is_set(1));
        assert_eq!(
            ec.signers().count_ones(),
            1,
            "duplicate votes must collapse"
        );
    }

    // ─── batch_verify_execution_votes ────────────────────────────────────

    #[test]
    fn batch_verify_accepts_all_valid_signatures() {
        let wid = wave_id(1);
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&outcomes);
        let sk0 = keypair(0);
        let sk1 = keypair(1);

        let votes = vec![
            (
                signed_vote(
                    ValidatorId::new(0),
                    &sk0,
                    &wid,
                    root,
                    WeightedTimestamp::from_millis(100),
                    outcomes.clone(),
                ),
                sk0.public_key(),
                VotePower::new(1),
            ),
            (
                signed_vote(
                    ValidatorId::new(1),
                    &sk1,
                    &wid,
                    root,
                    WeightedTimestamp::from_millis(100),
                    outcomes,
                ),
                sk1.public_key(),
                VotePower::new(1),
            ),
        ];

        assert_eq!(batch_verify_execution_votes(votes).count(), 2);
    }

    #[test]
    fn batch_verify_falls_back_and_drops_individual_bad_signature() {
        let wid = wave_id(1);
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&outcomes);
        let sk0 = keypair(0);
        let sk1 = keypair(1);
        let sk2 = keypair(2);

        // V1 signs with sk1 but submits a signature over a DIFFERENT message
        // (wrong root) — the batch verify fails, then the individual fallback
        // drops only V1's vote.
        let bad_vote = signed_vote(
            ValidatorId::new(1),
            &sk1,
            &wid,
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"other")),
            WeightedTimestamp::from_millis(100),
            outcomes.clone(),
        );
        // Re-stamp the vote's visible receipt_root back to the correct one so
        // the batch-verify message computation matches the other votes (and
        // thus groups them), but the signature still covers the wrong root.
        let bad_vote = ExecutionVote::new(
            bad_vote.block_hash(),
            bad_vote.block_height(),
            bad_vote.vote_anchor_ts(),
            bad_vote.wave_id().clone(),
            bad_vote.shard_group_id(),
            root,
            bad_vote.tx_count(),
            bad_vote.tx_outcomes().to_vec(),
            bad_vote.validator(),
            bad_vote.signature(),
        );

        let votes = vec![
            (
                signed_vote(
                    ValidatorId::new(0),
                    &sk0,
                    &wid,
                    root,
                    WeightedTimestamp::from_millis(100),
                    outcomes.clone(),
                ),
                sk0.public_key(),
                VotePower::new(1),
            ),
            (bad_vote, sk1.public_key(), VotePower::new(1)),
            (
                signed_vote(
                    ValidatorId::new(2),
                    &sk2,
                    &wid,
                    root,
                    WeightedTimestamp::from_millis(100),
                    outcomes,
                ),
                sk2.public_key(),
                VotePower::new(1),
            ),
        ];

        let verified: Vec<_> = batch_verify_execution_votes(votes).collect();
        let validators: Vec<ValidatorId> = verified.iter().map(|(v, _)| v.validator()).collect();
        assert_eq!(validators, vec![ValidatorId::new(0), ValidatorId::new(2)]);
    }

    #[test]
    fn batch_verify_empty_input_returns_empty() {
        assert!(batch_verify_execution_votes(Vec::new()).next().is_none());
    }

    #[test]
    fn batch_verify_drops_votes_whose_outcomes_dont_hash_to_claimed_root() {
        // A Byzantine validator signs an honest (root, count) but ships
        // tampered tx_outcomes. The BLS signature is valid for the honest
        // payload — the lie is in the unsigned outcomes vec. Intake must
        // reject such votes so the tracker only buckets self-consistent
        // ones; the aggregator then has no need to defend at find() time.
        let wid = wave_id(1);
        let honest_outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&honest_outcomes);
        let tampered_outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"evil")))];
        let sk0 = keypair(0);
        let sk1 = keypair(1);

        let byzantine = signed_vote(
            ValidatorId::new(0),
            &sk0,
            &wid,
            root,
            WeightedTimestamp::from_millis(100),
            honest_outcomes.clone(),
        );
        let byzantine = ExecutionVote::new(
            byzantine.block_hash(),
            byzantine.block_height(),
            byzantine.vote_anchor_ts(),
            byzantine.wave_id().clone(),
            byzantine.shard_group_id(),
            byzantine.global_receipt_root(),
            byzantine.tx_count(),
            tampered_outcomes,
            byzantine.validator(),
            byzantine.signature(),
        );

        let honest = signed_vote(
            ValidatorId::new(1),
            &sk1,
            &wid,
            root,
            WeightedTimestamp::from_millis(100),
            honest_outcomes,
        );

        let votes = vec![
            (byzantine, sk0.public_key(), VotePower::new(1)),
            (honest, sk1.public_key(), VotePower::new(1)),
        ];

        let verified: Vec<_> = batch_verify_execution_votes(votes).collect();
        let validators: Vec<ValidatorId> = verified.iter().map(|(v, _)| v.validator()).collect();
        assert_eq!(
            validators,
            vec![ValidatorId::new(1)],
            "Byzantine vote with mismatched outcomes must be filtered"
        );
    }

    // ─── verify_execution_certificate_signature ──────────────────────────

    #[test]
    fn verify_ec_signature_accepts_valid_aggregation() {
        let committee = vec![
            ValidatorId::new(0),
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3),
        ];
        let wid = wave_id(1);
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&outcomes);
        let sks: Vec<_> = (0_u8..4).map(keypair).collect();

        let votes: Vec<ExecutionVote> = (0_usize..4)
            .map(|i| {
                signed_vote(
                    ValidatorId::new(u64::try_from(i).unwrap()),
                    &sks[i],
                    &wid,
                    root,
                    WeightedTimestamp::from_millis(100),
                    outcomes.clone(),
                )
            })
            .collect();
        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);

        let pubs: Vec<_> = sks.iter().map(Bls12381G1PrivateKey::public_key).collect();
        assert!(verify_execution_certificate_signature(&ec, &pubs));
    }

    #[test]
    fn verify_ec_signature_rejects_wrong_public_keys() {
        let committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let wid = wave_id(1);
        let outcomes = vec![outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let root = compute_global_receipt_root(&outcomes);
        let sk0 = keypair(0);
        let sk1 = keypair(1);

        let votes = vec![
            signed_vote(
                ValidatorId::new(0),
                &sk0,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes.clone(),
            ),
            signed_vote(
                ValidatorId::new(1),
                &sk1,
                &wid,
                root,
                WeightedTimestamp::from_millis(100),
                outcomes,
            ),
        ];
        let ec = aggregate_execution_certificate(&wid, root, &votes, &committee);

        // Provide the wrong public keys — signature must not verify.
        let wrong_pubs = vec![keypair(42).public_key(), keypair(43).public_key()];
        assert!(!verify_execution_certificate_signature(&ec, &wrong_pubs));
    }
}
