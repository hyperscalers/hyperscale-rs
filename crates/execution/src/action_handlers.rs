//! Pure execution functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the asynchronous side of the execution
//! state machine: BLS verification, execution-vote aggregation into
//! [`ExecutionCertificate`]s, transaction execution against a
//! [`SubstateView`], and cross-shard provisioning requests. They are
//! kept free of node/runner concerns so the dispatcher only handles
//! event plumbing — sharing the handlers between production and
//! simulation keeps execution behavior identical across both backends.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, Parallelism, ProtocolEvent};
use hyperscale_engine::{
    CachedSlot, CachedVmOutput, ProcessExecutionCache, SlotStatus, build_cross_shard_ownership,
    project_to_shard, resolve_owned_nodes,
};
use hyperscale_metrics::record_execution_latency;
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView};
use hyperscale_types::network::notification::{
    ExecutionCertificatesNotification, ExecutionVotesNotification,
};
use hyperscale_types::{
    Bls12381G1PublicKey, ExecutionCertificate, ExecutionCertificateContext, ExecutionVote,
    NetworkDefinition, NodeId, RoutableTransaction, ShardGroupId, StoredReceipt, Verifiable,
    Verified, Verify, exec_cert_batch_message, exec_vote_batch_message, shard_for_node,
};

// ============================================================================
// Wave-based execution voting handlers
// ============================================================================

/// Run the [`ExecutionCertificate`] verification predicate against a
/// committee public-key vector. See [`Verified::<ExecutionCertificate>::verify`].
#[must_use]
pub fn verify_execution_certificate_signature(
    network: &NetworkDefinition,
    certificate: &ExecutionCertificate,
    public_keys: &[Bls12381G1PublicKey],
) -> bool {
    let ctx = ExecutionCertificateContext {
        network,
        public_keys,
    };
    certificate.verify(&ctx).is_ok()
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
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            let certificate = Verified::<ExecutionCertificate>::aggregate(
                &wave_id,
                global_receipt_root,
                &votes,
                &committee,
            );
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
            let verified_votes =
                Verified::<ExecutionVote>::verify_batch(ctx.topology_snapshot.network(), votes);
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
            let ctx_ec = ExecutionCertificateContext {
                network: ctx.topology_snapshot.network(),
                public_keys: &public_keys,
            };
            let result = match certificate {
                Verifiable::Verified(verified) => Ok(Arc::new(verified)),
                Verifiable::Unverified(raw) => match raw.verify(&ctx_ec) {
                    Ok(verified) => Ok(Arc::new(verified)),
                    Err(err) => Err((Arc::new(raw), err)),
                },
            };
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateSignatureVerified { result });
        }
        Action::VerifyFinalizedWave {
            wave,
            ec_public_keys,
        } => {
            let network = ctx.topology_snapshot.network();
            let valid = wave
                .execution_certificates()
                .iter()
                .zip(ec_public_keys.iter())
                .all(|(ec, keys)| verify_execution_certificate_signature(network, ec, keys));
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
            global_receipt_root: _,
            tx_outcomes,
            leader,
        } => {
            let local_shard = ctx.topology_snapshot.local_shard();
            let validator_id = ctx.topology_snapshot.local_validator_id();
            let network = ctx.topology_snapshot.network();

            let verified = Verified::<ExecutionVote>::sign_local(
                network,
                block_hash,
                block_height,
                vote_anchor_ts,
                wave_id,
                local_shard,
                tx_outcomes,
                validator_id,
                ctx.signing_key,
            );

            // Send vote to the wave leader (unicast).
            if leader != validator_id {
                let raw = (*verified).clone();
                let batch_msg =
                    exec_vote_batch_message(network, local_shard, std::slice::from_ref(&raw));
                let batch_sig = ctx.signing_key.sign_v1(&batch_msg);
                let batch = ExecutionVotesNotification::new(vec![raw], validator_id, batch_sig);
                ctx.network.notify(&[leader], &batch);
            }

            // Feed own vote to state machine only if we are the leader.
            if leader == validator_id {
                ctx.notify_protocol(ProtocolEvent::ExecutionVoteReceived {
                    vote: Verifiable::Verified(verified),
                });
            }
        }

        Action::BroadcastExecutionCertificate {
            shard: _,
            certificate,
            recipients,
        } => {
            let cert = Arc::unwrap_or_clone(certificate).into_inner();
            let msg = exec_cert_batch_message(
                ctx.topology_snapshot.network(),
                cert.shard_group_id(),
                std::slice::from_ref(&cert),
            );
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
