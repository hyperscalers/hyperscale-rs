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
use hyperscale_storage::tree::proofs::verify_proof;
use hyperscale_storage::{Storage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::notification::ProvisionsNotification;
use hyperscale_types::{
    BlockHeight, Provisions, ShardGroupId, ValidatorId, state_provisions_message,
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
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    requests: &[ProvisionsRequest],
    shard_recipients: &HashMap<ShardGroupId, Vec<ValidatorId>, H>,
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
    S: Storage,
    N: Network,
{
    match action {
        Action::VerifyProvisions {
            provisions,
            committed_header,
        } => {
            let merkle_start = Instant::now();
            let all_valid = {
                let all_entries = provisions.all_entries_deduped();
                if all_entries.is_empty() {
                    true
                } else {
                    let valid = verify_proof(
                        provisions.proof(),
                        &all_entries,
                        committed_header.state_root(),
                        |e| &e.storage_key,
                    );
                    if !valid {
                        warn!(
                            source_shard = provisions.source_shard().inner(),
                            block_height = provisions.block_height().inner(),
                            header_height = committed_header.height().inner(),
                            header_state_root = ?committed_header.state_root(),
                            entry_count = all_entries.len(),
                            proof_len = provisions.proof().as_bytes().len(),
                            "Provision merkle proof verification failed"
                        );
                    }
                    valid
                }
            };
            record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::StateProvisionsVerified {
                provisions: Arc::new(provisions),
                committed_header: Some(committed_header),
                valid: all_valid,
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
            let validator_id = ctx.topology_snapshot.local_validator_id();
            for (provisions, recipients) in batches {
                // Register with the outbound tracker (populates the
                // serving cache) on the main thread. A peer's
                // provision.request that arrives between this notify and
                // the main thread draining it will miss the cache and
                // either hit RocksDB regen (post-persist) or trigger a
                // fetch retry (pre-persist) — recoverable both ways.
                ctx.notify_protocol(ProtocolEvent::OutboundProvisionBroadcast {
                    provisions: Arc::clone(&provisions),
                    target_shard: provisions.target_shard(),
                });

                let msg = state_provisions_message(&provisions);
                let sig = ctx.signing_key.sign_v1(&msg);
                let notification =
                    ProvisionsNotification::new(Arc::clone(&provisions), validator_id, sig);
                ctx.network.notify(&recipients, &notification);
            }
        }
        _ => unreachable!("hyperscale_provisions::handle_action called with non-provisions action"),
    }
}
