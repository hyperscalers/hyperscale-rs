//! Pure provision functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the source-side work for `FetchAndBroadcastProvisions`:
//! looping over target shards and calling [`build_provisions`] for each so
//! that gossip emit and fetch serve share one assembly path.
//!
//! [`build_provisions`]: crate::build::build_provisions

use std::collections::HashMap;
use std::hash::BuildHasher;

use hyperscale_core::{
    ActionContext, ProtocolEvent, ProvisionAction, ProvisionRefusal, ProvisionVerdict,
    ProvisionsRequest,
};
use hyperscale_hbor::Capped;
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_metrics::{record_fetch_response_refused, record_signature_verification_latency};
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::encoded_len;
use hyperscale_types::network::notification::ProvisionsNotification;
use hyperscale_types::{
    Anchor, BlockHeight, MAX_TXS_PER_BLOCK, MAX_WIRE_MESSAGE_BYTES, PROVISION_FRAMING_BYTES,
    Provision, ProvisionContext, ProvisionsSenderMessage, ShardId, Stopwatch, ValidatorId,
    Verifiable, Verified, Verify, WeightedTimestamp, signed_bytes,
};
use tracing::warn;

use crate::build::build_provisions;
use crate::crossing_push::push_crossing_readings;

/// One target shard's parts, packed into notifications, and who receives
/// them.
pub(crate) struct ProvisionBatch {
    pub(crate) target_shard: ShardId,
    pub(crate) packs: Vec<Vec<Provision>>,
    pub(crate) recipients: Vec<ValidatorId>,
}

/// The bytes of parts one notification packs, leaving its frame room for
/// the scope, sender and signature around them.
const PACK_BYTES: usize = MAX_WIRE_MESSAGE_BYTES - PROVISION_FRAMING_BYTES;

/// `parts` in order, cut into packs of at most [`PACK_BYTES`] each. A part
/// always fits alone: the builder refuses one past
/// [`MAX_PROVISION_PART_BYTES`](hyperscale_types::MAX_PROVISION_PART_BYTES).
pub(crate) fn pack(parts: Vec<Provision>) -> Vec<Vec<Provision>> {
    let mut packs: Vec<Vec<Provision>> = Vec::new();
    let mut current: Vec<Provision> = Vec::new();
    let mut spent = 0usize;
    for part in parts {
        let size = encoded_len(&part);
        if !current.is_empty()
            && (spent.saturating_add(size) > PACK_BYTES || current.len() >= MAX_TXS_PER_BLOCK)
        {
            packs.push(std::mem::take(&mut current));
            spent = 0;
        }
        spent = spent.saturating_add(size);
        current.push(part);
    }
    if !current.is_empty() {
        packs.push(current);
    }
    packs
}

/// Build per-target-shard parts for the cross-shard broadcast.
///
/// Loops over the recipient map (sorted by shard id for deterministic
/// ordering) and delegates each target to [`build_provisions`]. A target
/// none of whose parts builds is skipped — callers still emit an
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
        let parts = build_provisions(
            view,
            source_shard,
            *target_shard,
            block_height,
            source_block_ts,
            requests,
            |_| true,
        );
        if parts.is_empty() {
            continue;
        }
        batches.push(ProvisionBatch {
            target_shard: *target_shard,
            packs: pack(parts),
            recipients: recipients.clone(),
        });
    }
    batches
}

/// Each of `parts`' proofs checked against `anchor`, one verdict per part.
fn verify_parts(parts: Vec<Provision>, anchor: Anchor) -> Vec<ProvisionVerdict> {
    let merkle_start = Stopwatch::start();
    let ctx_verify = ProvisionContext { anchor };
    let results = parts
        .into_iter()
        .map(|part| match part.verify(&ctx_verify) {
            Ok(verified) => Ok(verified),
            Err(err) => {
                warn!(
                    source_shard = part.source_shard().inner(),
                    block_height = part.block_height().inner(),
                    tx_hash = %part.tx_hash(),
                    anchor_height = anchor.height.inner(),
                    anchor_state_root = ?anchor.state_root,
                    proof_len = part.proof().as_bytes().len(),
                    error = ?err,
                    "Provision merkle proof verification failed"
                );
                // The inclusion proof is what holds a part's entries to the
                // state root its source header committed, so a failure here
                // is a responder that answered with values its own chain
                // never held.
                record_fetch_response_refused("provision", "unproven_entries");
                Err((part, ProvisionRefusal::Unproven(err)))
            }
        })
        .collect();
    record_signature_verification_latency("inclusion_proof", merkle_start.elapsed().as_secs_f64());
    results
}

/// Run provision work. Outcomes flow through `ctx.notify`.
pub fn handle_action<S, N>(action: ProvisionAction, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        ProvisionAction::VerifyProvisions { parts, anchor } => {
            let results = verify_parts(parts, anchor);
            ctx.notify_protocol(ProtocolEvent::StateProvisionsVerified { results, anchor });
        }
        ProvisionAction::FetchAndBroadcastProvisions {
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
            for batch in batches {
                for pack in batch.packs {
                    // Parts built from the local JMT view satisfy their
                    // own merkle-proof predicate by construction; wrap as
                    // `Verified` so the local-dispatch fast path can let a
                    // target-shard replica on this host admit without
                    // re-running `ProvisionAction::VerifyProvisions`.
                    let parts: Vec<Verified<Provision>> = pack
                        .into_iter()
                        .map(Verified::<Provision>::from_local)
                        .collect();

                    let msg = signed_bytes(
                        &ProvisionsSenderMessage::new(
                            source_shard,
                            batch.target_shard,
                            block_height,
                            parts.iter().map(|part| &**part),
                        ),
                        ctx.topology_snapshot.network(),
                    );
                    let Ok(sig) = signing.key.sign(&msg) else {
                        tracing::error!("cannot sign provisions broadcast; skipping");
                        return;
                    };

                    // Register with the outbound tracker (populates the
                    // serving cache) on the main thread. A peer's
                    // provision.request that arrives between this notify
                    // and the main thread draining it will miss the cache
                    // and either hit RocksDB regen (post-persist) or
                    // trigger a fetch retry (pre-persist) — recoverable
                    // both ways.
                    ctx.notify_protocol(ProtocolEvent::OutboundProvisionBroadcast {
                        parts: parts.clone(),
                        target_shard: batch.target_shard,
                    });

                    let Ok(packed) = Capped::new(parts.into_iter().map(Verifiable::from).collect())
                    else {
                        tracing::error!("a pack holds more parts than a notification; skipping");
                        continue;
                    };
                    let notification = ProvisionsNotification::new(
                        source_shard,
                        batch.target_shard,
                        block_height,
                        packed,
                        validator_id,
                        sig,
                    );
                    ctx.network.notify(&batch.recipients, &notification);
                }
            }
        }
        ProvisionAction::PushCrossingReadings {
            block_hash,
            anchor,
            targets,
            shard_recipients,
            signer: _,
        } => push_crossing_readings(ctx, block_hash, anchor, &targets, &shard_recipients),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Hash, LeafPath, MAX_MERKLE_PROOF_LEN, MerkleInclusionProof, ProvisionParts, TxHash,
    };

    use super::*;

    /// A part carrying a proof at its decode cap.
    fn heavy(index: u32) -> Provision {
        Provision::new(ProvisionParts {
            source_shard: ShardId::leaf(1, 0),
            target_shard: ShardId::leaf(1, 1),
            block_height: BlockHeight::new(3),
            source_block_ts: WeightedTimestamp::ZERO,
            tx_hash: TxHash::from(Hash::from_bytes(&index.to_le_bytes())),
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(vec![0x5A; MAX_MERKLE_PROOF_LEN]),
            leaf: LeafPath {
                count: 3,
                index,
                siblings: Capped::empty(),
            },
        })
    }

    /// A block's parts for one target ride as many notifications as the
    /// frame needs, in leaf order, each pack under the frame and none
    /// empty.
    #[test]
    fn parts_pack_into_frames_in_order() {
        let packs = pack((0..3).map(heavy).collect());
        let indices: Vec<Vec<u32>> = packs
            .iter()
            .map(|pack| pack.iter().map(|part| part.leaf().index).collect())
            .collect();
        assert_eq!(indices, vec![vec![0, 1], vec![2]]);
        for pack in &packs {
            assert!(pack.iter().map(encoded_len).sum::<usize>() <= PACK_BYTES);
        }
        assert!(pack(Vec::new()).is_empty());
    }
}
