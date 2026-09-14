//! Pure execution functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the asynchronous side of the execution
//! state machine: signature verification, execution-vote aggregation into
//! [`ExecutionCertificate`]s, transaction execution against a
//! [`SubstateView`], and cross-shard provisioning requests. They are
//! kept free of node/runner concerns so the dispatcher only handles
//! event plumbing — sharing the handlers between production and
//! simulation keeps execution behavior identical across both backends.
//!
//! [`SubstateView`]: hyperscale_storage::SubstateView

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use hyperscale_core::{
    Action, ActionContext, CrossShardExecutionRequest, ProtocolEvent, TickBatchOutcome,
};
use hyperscale_engine::{ExecutedTx, TickBatchContext, TickTxInput};
use hyperscale_metrics::record_execution_latency;
use hyperscale_network::Network;
use hyperscale_storage::{ProvisionalTx, ShardStorage, TickOutput, fold_state_writes};
use hyperscale_types::network::notification::{
    ExecutionCertificatesNotification, ExecutionVotesNotification,
};
use hyperscale_types::{
    BlockHeight, ConsensusReceipt, DeclaredKey, ExecutionCertificate, ExecutionCertificateContext,
    ExecutionCertificatesSenderMessage, ExecutionVote, ExecutionVotesSenderMessage,
    FinalizationContext, Mode, StateWrites, Stopwatch, StoredReceipt, SubstateKey, TickId, TxHash,
    TxOutcome, Verifiable, Verified, signed_bytes,
};

// ============================================================================
// Tick-based execution voting handlers
// ============================================================================

/// Split a batch's executed records into the three parallel streams the
/// tick consumes: outcomes for the vote, execution receipts, and the fee
/// receipts held in reserve against an abort.
#[must_use]
pub fn split_execution_outputs(executed: Vec<ExecutedTx>) -> ExecutionOutputs {
    let mut outcomes = Vec::with_capacity(executed.len());
    let mut results = Vec::with_capacity(executed.len());
    let mut fee_receipts = Vec::new();
    for mut tx in executed {
        outcomes.push(tx.outcome());
        if let Some(fee) = tx.fee_receipt.take() {
            fee_receipts.push(StoredReceipt::synced(tx.tx_hash, Arc::new(fee)));
        }
        results.push(StoredReceipt::from(tx));
    }
    ExecutionOutputs {
        outcomes,
        results,
        fee_receipts,
    }
}

/// The four per-batch products execution hands the tick: the outcomes it
/// votes, the receipts it stores, the charges an attempt that applied
/// nothing still settles, and what this shard attests it did.
pub struct ExecutionOutputs {
    /// Per-tx outcomes the tick votes.
    pub outcomes: Vec<TxOutcome>,
    /// Per-tx execution receipts.
    pub results: Vec<StoredReceipt>,
    /// Charges held in reserve against a tick abort.
    pub fee_receipts: Vec<StoredReceipt>,
}

/// Fold one tick's executed records into the tick output.
///
/// The local-only tick's writes are determined at commit: each member
/// contributes its execution receipt and its unconditional fee charge,
/// in canonical (tx-hash) order — the order the batch fold ran in. A
/// cross-shard tick's records sit beside them as per-tx provisional
/// entries until the tick resolves: the execution writes on one side,
/// the reserve fee charge on the other, whichever the tick's verdict
/// picks.
///
/// Either way the receipt goes in whole. A receipt states absolutes
/// where an exclusive write named the value and movements where a
/// commutative access said what it moved, and a fee burn is always the
/// second — so a fold that kept only the cells would carry nothing at
/// all for ordinary payment traffic.
pub fn accumulate_tick_output(
    output: &mut TickOutput,
    requests: &[CrossShardExecutionRequest],
    executed: &[ExecutedTx],
) {
    let mut ordered: Vec<&ExecutedTx> = executed.iter().collect();
    ordered.sort_by_key(|tx| tx.tx_hash);

    // A batch carries whatever the tick admitted, so it splits here rather
    // than as a whole: a member a counterpart's verdict can still discard
    // leaves a provisional contribution no later tick may read until that
    // verdict resolves it, and one nothing can retract is determined the
    // moment it executes.
    let abortable: HashSet<TxHash> = requests
        .iter()
        .filter(|r| r.runs.abortable())
        .map(|r| r.tx_hash)
        .collect();
    let (beyond, local): (Vec<&ExecutedTx>, Vec<&ExecutedTx>) = ordered
        .into_iter()
        .partition(|tx| abortable.contains(&tx.tx_hash));

    let mut members: Vec<(TxHash, StateWrites)> = Vec::new();
    for tx in local {
        let mut writes = StateWrites::default();
        for part in [
            tx.consensus.writes(),
            tx.fee_receipt.as_ref().and_then(ConsensusReceipt::writes),
        ]
        .into_iter()
        .flatten()
        {
            fold_state_writes(&mut writes, part);
        }
        if !writes.is_empty() {
            members.push((tx.tx_hash, writes));
        }
    }
    output.determined = members;

    output.provisional = beyond
        .into_iter()
        .map(|tx| ProvisionalTx {
            tx_hash: tx.tx_hash,
            writes: tx.consensus.writes().cloned(),
            reserve: tx
                .fee_receipt
                .as_ref()
                .and_then(|fee| fee.writes())
                .cloned(),
            reserved: granted_reservations(requests, tx),
        })
        .collect();
}

/// What one member of `requests` holds in reservations, by cell.
///
/// Only a leg that ran to completion holds anything. A reservation is
/// granted or refused when the kernel judges it, and an attempt that
/// aborted or failed took none — recording its declaration anyway would
/// hold a vault against value nobody reserved, and would let the held
/// total exceed the balance, which is a state the kernel reads as a
/// corrupt ledger rather than as an infeasible request.
///
/// For a leg that did complete, declared and granted are the same
/// number: the kernel grants a reservation at the amount the declaration
/// named or refuses it outright. Completion is read off the receipt —
/// every abort, a refused reservation included, is a `Failed` receipt,
/// and a `Failed` receipt carries no writes.
///
/// A reservation targets an amount cell, which is a point, so an
/// owner-granular declaration is never one. Cells this shard does not own
/// ride along and are dropped where locality is known — a declaration
/// spans every participating shard, and this one does not.
fn granted_reservations(
    requests: &[CrossShardExecutionRequest],
    executed: &ExecutedTx,
) -> BTreeMap<SubstateKey, u128> {
    let mut reserved = BTreeMap::new();
    if executed.consensus.writes().is_none() {
        return reserved;
    }
    let Some((_, body)) = requests
        .iter()
        .find(|r| r.tx_hash == executed.tx_hash)
        .and_then(CrossShardExecutionRequest::shape)
    else {
        return reserved;
    };
    for (key, mode) in &body.routing().declared_modes {
        if let (DeclaredKey::Cell(cell), Mode::Reserve { amount }) = (key, mode) {
            *reserved.entry(*cell).or_default() += *amount;
        }
    }
    reserved
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
            tick_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            let certificate = Verified::<ExecutionCertificate>::aggregate(
                ctx.verifier,
                &tick_id,
                global_receipt_root,
                &votes,
                &committee,
            );
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateAggregated {
                tick_id,
                certificate: Arc::new(certificate),
            });
        }
        Action::VerifyAndAggregateExecutionVotes {
            tick_id,
            block_hash,
            votes,
        } => {
            let verified_votes = Verified::<ExecutionVote>::verify_batch(
                ctx.verifier,
                ctx.topology_snapshot.network(),
                votes,
            );
            ctx.notify_protocol(ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                tick_id,
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
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                public_keys: &public_keys,
            };
            let result = certificate
                .upgrade(&ctx_ec)
                .map(Arc::new)
                .map_err(|(raw, err)| (Arc::new(raw), err));
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateSignatureVerified { result });
        }
        Action::VerifyFinalization {
            finalization,
            ec_public_keys,
        } => {
            let fw_ctx = FinalizationContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                ec_public_keys: &ec_public_keys,
            };
            let result = Arc::unwrap_or_clone(finalization)
                .upgrade(&fw_ctx)
                .map(Arc::new)
                .map_err(|(raw, err)| (Arc::new(raw), err));
            ctx.notify_protocol(ProtocolEvent::FinalizationVerified { result });
        }
        Action::ExecuteTransactions {
            tick,
            tick_ts,
            env,
            requests,
        } => {
            let start = Stopwatch::start();
            let shard_trie = ctx.topology_snapshot.shard_trie();
            // The previous tick's output over the persisted base is this
            // tick's baseline. Ticks dispatch serially, so every tick at
            // or below `tick - 1` has been appended by now.
            let view = ctx
                .tick_chain
                .view_at(BlockHeight::new(tick.inner().saturating_sub(1)));
            let view_snap = view.snapshot();
            // From the same view as the baseline, so a leg's debit and
            // the hold standing for it are never both visible.
            let holds = view.holds();
            let tick_ctx = TickBatchContext {
                local_shard: ctx.shard,
                shard_trie,
                tick_ts,
                env,
                holds: &holds,
            };
            let inputs: Vec<TickTxInput<'_>> = requests
                .iter()
                .map(|r| TickTxInput {
                    tx_hash: r.tx_hash,
                    transaction: r.transaction.as_ref(),
                    provisions: &r.provisions,
                    clock: r.clock,
                    prices: r.prices,
                    runs: r.runs.clone(),
                    arrivals: &r.arrivals,
                })
                .collect();
            let executed = match ctx
                .executor
                .execute_tick_batch(&tick_ctx, &view_snap, &inputs)
            {
                Ok(executed) => executed,
                // Nothing ran and nothing was attested, so the tick is
                // still whole. It goes back to the dispatch head rather
                // than taking the shard down with it.
                Err(unavailable) => {
                    // The members travel back with the tick, so the
                    // borrow the inputs hold on them ends here.
                    drop(inputs);
                    ctx.notify_protocol(ProtocolEvent::ExecutionBatchUnavailable {
                        tick,
                        tick_ts,
                        env: tick_ctx.env,
                        requests,
                        package: unavailable.package,
                    });
                    return;
                }
            };
            record_execution_latency(start.elapsed().as_secs_f64());

            let tick_id = TickId::new(ctx.shard, tick);
            let mut output = TickOutput::default();
            accumulate_tick_output(&mut output, &requests, &executed);
            let ExecutionOutputs {
                outcomes: tx_outcomes,
                results,
                fee_receipts,
            } = split_execution_outputs(executed);

            // Append before notifying: the coordinator dispatches the next
            // tick on this event, and its baseline must include this one.
            ctx.tick_chain.append(tick, output);
            ctx.notify_protocol(ProtocolEvent::ExecutionBatchCompleted {
                tick,
                outcome: TickBatchOutcome {
                    tick_id,
                    results,
                    tx_outcomes,
                    fee_receipts,
                },
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        Action::SignAndSendExecutionVote {
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
            global_receipt_root: _,
            tx_outcomes,
            leader,
        } => {
            let local_shard = ctx.shard;
            let validator_id = ctx.me;
            let network = ctx.topology_snapshot.network();

            let Ok(verified) = Verified::<ExecutionVote>::sign_local(
                network,
                block_hash,
                block_height,
                vote_anchor_ts,
                tick_id,
                local_shard,
                tx_outcomes,
                validator_id,
                ctx.signer.as_ref(),
            ) else {
                tracing::error!(?block_hash, "cannot sign execution vote; abstaining");
                return;
            };

            // Send vote to the tick leader (unicast). When the leader is a
            // colocated vnode the local-dispatch fast path preserves the
            // `Verifiable::Verified` marker, letting the handler skip
            // re-verification of our own signature.
            if leader != validator_id {
                let batch_msg = signed_bytes(
                    &ExecutionVotesSenderMessage::new(local_shard, std::iter::once(&*verified)),
                    network,
                );
                let Ok(batch_sig) = ctx.signer.sign(&batch_msg) else {
                    tracing::error!(
                        ?block_hash,
                        "cannot sign execution vote batch; skipping send"
                    );
                    return;
                };
                let batch = ExecutionVotesNotification::new(
                    vec![Verifiable::from(verified.clone())],
                    validator_id,
                    batch_sig,
                );
                ctx.network.notify(&[leader], &batch);
            }

            // Feed own vote to state machine only if we are the leader.
            if leader == validator_id {
                ctx.notify_protocol(ProtocolEvent::VerifiedExecutionVoteReceived {
                    vote: verified,
                });
            }
        }

        Action::BroadcastExecutionCertificate {
            shard: _,
            certificate,
            recipients,
        } => {
            let cert = Arc::unwrap_or_clone(certificate).into_inner();
            let msg = signed_bytes(
                &ExecutionCertificatesSenderMessage::new(
                    cert.shard_id(),
                    std::slice::from_ref(&cert),
                ),
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!("cannot sign execution certificate batch; skipping broadcast");
                return;
            };
            let batch = ExecutionCertificatesNotification::new(vec![cert], ctx.me, sig);
            ctx.network.notify(&recipients, &batch);
        }

        _ => unreachable!("hyperscale_execution::handle_action called with non-execution action"),
    }
}
