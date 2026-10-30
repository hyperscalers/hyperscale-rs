//! Pure provision functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the source-side work for `FetchAndBroadcastProvisions`:
//! looping over target shards and calling [`build_provisions`] for each so
//! that gossip emit and fetch serve share one assembly path.
//!
//! [`build_provisions`]: crate::build::build_provisions

use std::collections::HashMap;
use std::hash::BuildHasher;

use hyperscale_core::{Action, ActionContext, ProtocolEvent, ProvisionsRequest};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_metrics::{record_fetch_response_refused, record_signature_verification_latency};
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::notification::ProvisionsNotification;
use hyperscale_types::{
    BlockHeight, Provisions, ProvisionsContext, ProvisionsSenderMessage, ShardId, Stopwatch,
    ValidatorId, Verified, Verify, WeightedTimestamp, signed_bytes,
};
use tracing::warn;

use crate::build::build_provisions;
use crate::crossing_push::push_crossing_readings;

/// One outbound provision batch destined for a single target shard.
pub(crate) type ProvisionBatch = (Provisions, Vec<ValidatorId>);

/// Build per-target-shard provision batches for the cross-shard broadcast.
///
/// Loops over the recipient map (sorted by shard id for deterministic
/// ordering) and delegates each target to [`build_provisions`]. Shards
/// whose build returns `None` (JMT version unavailable) or has no
/// matching transactions are silently skipped — callers still emit an
/// `OutboundProvisionBroadcast` event so the state machine can mark the
/// action complete.
pub(crate) fn fetch_and_broadcast_provision<S, H>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    block_height: BlockHeight,
    source_block_ts: WeightedTimestamp,
    requests: &[ProvisionsRequest],
    shard_recipients: &HashMap<ShardId, Vec<ValidatorId>, H>,
) -> Vec<ProvisionBatch>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
    H: BuildHasher,
{
    let mut sorted_recipients: Vec<_> = shard_recipients.iter().collect();
    sorted_recipients.sort_by_key(|(shard, _)| **shard);

    let mut batches = Vec::with_capacity(sorted_recipients.len());
    for (target_shard, recipients) in sorted_recipients {
        let Some(provisions) = build_provisions(
            view,
            source_shard,
            *target_shard,
            block_height,
            source_block_ts,
            requests,
        ) else {
            continue;
        };
        if provisions.transactions().is_empty() {
            continue;
        }
        batches.push((provisions, recipients.clone()));
    }
    batches
}

/// Handle the provisions-owned delegated [`Action`] variants.
///
/// Outcomes flow through `ctx.notify`. Variants owned by other coordinator
/// crates hit `unreachable!()` — node's dispatcher routes by variant prefix.
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::VerifyProvisions { provisions, anchor } => {
            let merkle_start = Stopwatch::start();
            let ctx_verify = ProvisionsContext { anchor };
            let result = match provisions.verify(&ctx_verify) {
                Ok(verified) => Ok(verified),
                Err(err) => {
                    warn!(
                        source_shard = provisions.source_shard().inner(),
                        block_height = provisions.block_height().inner(),
                        anchor_height = anchor.height.inner(),
                        anchor_state_root = ?anchor.state_root,
                        proof_len = provisions.proof().as_bytes().len(),
                        error = ?err,
                        "Provision merkle proof verification failed"
                    );
                    // The inclusion proof is what holds a bundle's entries
                    // to the state root its source header committed, so a
                    // failure here is a responder that answered with values
                    // its own chain never held.
                    record_fetch_response_refused("provision", "unproven_entries");
                    Err((provisions, err))
                }
            };
            record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::StateProvisionsVerified { result, anchor });
        }
        Action::FetchAndBroadcastProvisions {
            block_hash,
            requests,
            source_shard,
            block_height,
            source_block_ts,
            shard_recipients,
            signer: _,
        } => {
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let batches = fetch_and_broadcast_provision(
                &view,
                source_shard,
                block_height,
                source_block_ts,
                &requests,
                &shard_recipients,
            );
            if batches.is_empty() && !requests.is_empty() {
                warn!(
                    source_shard = source_shard.inner(),
                    block_height = block_height.inner(),
                    requests = requests.len(),
                    "provision broadcast built no batches"
                );
            }
            let Some(signing) = &ctx.signing else {
                tracing::error!("provisions broadcast dispatched without a signer; skipping");
                return;
            };
            let Some(_entry) = signing.enter("FetchAndBroadcastProvisions") else {
                return;
            };
            let validator_id = signing.me;
            for (provisions, recipients) in batches {
                // Provisions built from the local JMT view satisfy their
                // own merkle-proof predicate by construction; wrap as
                // `Verified` so the local-dispatch fast path can let a
                // target-shard replica on this host admit without
                // re-running `Action::VerifyProvisions`.
                let verified = Verified::<Provisions>::from_local(provisions);

                let msg = signed_bytes(
                    &ProvisionsSenderMessage::new(&verified),
                    ctx.topology_snapshot.network(),
                );
                let Ok(sig) = signing.key.sign(&msg) else {
                    tracing::error!("cannot sign provisions broadcast; skipping");
                    return;
                };

                // Register with the outbound tracker (populates the
                // serving cache) on the main thread. A peer's
                // provision.request that arrives between this notify and
                // the main thread draining it will miss the cache and
                // either hit RocksDB regen (post-persist) or trigger a
                // fetch retry (pre-persist) — recoverable both ways.
                ctx.notify_protocol(ProtocolEvent::OutboundProvisionBroadcast {
                    provisions: verified.clone(),
                    target_shard: verified.target_shard(),
                });

                let notification = ProvisionsNotification::new(verified, validator_id, sig);
                ctx.network.notify(&recipients, &notification);
            }
        }
        Action::PushCrossingReadings {
            block_hash,
            anchor,
            targets,
            shard_recipients,
            signer: _,
        } => push_crossing_readings(ctx, block_hash, anchor, &targets, &shard_recipients),
        _ => unreachable!("hyperscale_provisions::handle_action called with non-provisions action"),
    }
}
