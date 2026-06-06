//! Pure provision functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the source-side work for `FetchAndBroadcastProvisions`:
//! looping over target shards and calling [`build_provisions`] for each so
//! that gossip emit and fetch serve share one assembly path.
//!
//! [`build_provisions`]: crate::build::build_provisions

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::Instant;

use hyperscale_core::{Action, ActionContext, ProtocolEvent, ProvisionsRequest};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::notification::ProvisionsNotification;
use hyperscale_types::{
    BlockHeight, Provisions, ProvisionsContext, ShardId, ValidatorId, Verifiable, Verified, Verify,
    state_provisions_message,
};
use tracing::warn;

use crate::build::build_provisions;

/// One outbound provision batch destined for a single target shard.
pub type ProvisionBatch = (Arc<Provisions>, Vec<ValidatorId>);

/// Build per-target-shard provision batches for the cross-shard broadcast.
///
/// Loops over the recipient map (sorted by shard id for deterministic
/// ordering) and delegates each target to [`build_provisions`]. Shards
/// whose build returns `None` (JMT version unavailable) or has no
/// matching transactions are silently skipped — callers still emit an
/// `OutboundProvisionBroadcast` event so the state machine can mark the
/// action complete.
pub fn fetch_and_broadcast_provision<S, H>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    block_height: BlockHeight,
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
        let Some(provisions) =
            build_provisions(view, source_shard, *target_shard, block_height, requests)
        else {
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
        Action::VerifyProvisions {
            provisions,
            certified_header,
        } => {
            let merkle_start = Instant::now();
            let ctx_verify = ProvisionsContext {
                certified_header: &certified_header,
            };
            let result = match provisions.verify(&ctx_verify) {
                Ok(verified) => Ok(Arc::new(verified)),
                Err(err) => {
                    warn!(
                        source_shard = provisions.source_shard().inner(),
                        block_height = provisions.block_height().inner(),
                        header_height = certified_header.height().inner(),
                        header_state_root = ?certified_header.state_root(),
                        proof_len = provisions.proof().as_bytes().len(),
                        error = ?err,
                        "Provision merkle proof verification failed"
                    );
                    Err((Arc::new(provisions), err))
                }
            };
            record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::StateProvisionsVerified {
                result,
                certified_header,
            });
        }
        Action::FetchAndBroadcastProvisions {
            block_hash,
            requests,
            source_shard,
            block_height,
            shard_recipients,
        } => {
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let batches = fetch_and_broadcast_provision(
                &view,
                source_shard,
                block_height,
                &requests,
                &shard_recipients,
            );
            let validator_id = ctx.me;
            for (provisions, recipients) in batches {
                // Provisions built from the local JMT view satisfy their
                // own merkle-proof predicate by construction; wrap as
                // `Verified` so the local-dispatch fast path can let a
                // colocated target-shard vnode admit without re-running
                // `Action::VerifyProvisions`.
                let verified = Arc::new(Verified::<Provisions>::from_local(Arc::unwrap_or_clone(
                    provisions,
                )));

                let msg = state_provisions_message(ctx.topology_snapshot.network(), &verified);
                let sig = ctx.signing_key.sign_v1(&msg);

                // Register with the outbound tracker (populates the
                // serving cache) on the main thread. A peer's
                // provision.request that arrives between this notify and
                // the main thread draining it will miss the cache and
                // either hit RocksDB regen (post-persist) or trigger a
                // fetch retry (pre-persist) — recoverable both ways.
                ctx.notify_protocol(ProtocolEvent::OutboundProvisionBroadcast {
                    provisions: Arc::clone(&verified),
                    target_shard: verified.target_shard(),
                });

                let notification = ProvisionsNotification::new(
                    Arc::new(Verifiable::from((*verified).clone())),
                    validator_id,
                    sig,
                );
                ctx.network.notify(&recipients, &notification);
            }
        }
        _ => unreachable!("hyperscale_provisions::handle_action called with non-provisions action"),
    }
}
