//! Pure provision functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the source-side work for `FetchAndBroadcastProvisions`:
//! looping over target shards, holding each target's leaves to the block's
//! own root and building its parts through [`build_part`], so that gossip
//! emit and fetch serve share one assembly path.
//!
//! [`build_part`]: crate::build::build_part

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::ops::ControlFlow;

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
    Anchor, MAX_FETCH_RESPONSE_BYTES, MAX_TXS_PER_BLOCK, PROVISION_FRAMING_BYTES, Provision,
    ProvisionContext, ProvisionTxRootsMap, ProvisionsSenderMessage, ShardId, Stopwatch,
    ValidatorId, Verifiable, Verified, Verify, WeightedTimestamp, signed_bytes,
};
use tracing::warn;

use crate::build::{Owed, build_owed_until};
use crate::content::keys_over_requests;
use crate::crossing_push::push_crossing_readings;

/// One target shard's parts, packed into notifications, and who receives
/// them.
pub(crate) struct ProvisionBatch {
    pub(crate) target_shard: ShardId,
    pub(crate) packs: Vec<Vec<Provision>>,
    pub(crate) recipients: Vec<ValidatorId>,
}

/// The bytes of parts one notification packs, leaving room for the scope,
/// sender and signature around them within a fetch response's budget. The
/// frame caps the compressed length, and the slack that budget leaves
/// under the frame covers what compression adds to bytes it cannot
/// shrink.
const PACK_BYTES: usize = MAX_FETCH_RESPONSE_BYTES - PROVISION_FRAMING_BYTES;

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
/// ordering) and builds each target's parts out of `view`, the view
/// anchored at the source block, once the leaves its served keys make
/// walk to `claimed`, the block header's own roots. A target whose
/// leaves do not, or none of whose parts builds, is skipped, and so is
/// every target where the view does not hold the block's state: nothing
/// leaves this source that its own header does not commit.
pub(crate) fn fetch_and_broadcast_provision<S, H>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    source_block_ts: WeightedTimestamp,
    requests: &[ProvisionsRequest],
    claimed: &ProvisionTxRootsMap,
    shard_recipients: &HashMap<ShardId, Vec<ValidatorId>, H>,
) -> Vec<ProvisionBatch>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
    H: BuildHasher,
{
    let mut sorted_recipients: Vec<_> = shard_recipients.iter().collect();
    sorted_recipients.sort_by_key(|(shard, _)| **shard);

    let Some(state) = view.served_snapshot() else {
        warn!(
            source_shard = source_shard.inner(),
            block_height = view.anchor_height().inner(),
            "provision broadcast: the block's state is not held here; sending none"
        );
        return Vec::new();
    };
    let keys = keys_over_requests(&state, requests);
    let mut batches = Vec::with_capacity(sorted_recipients.len());
    for (target_shard, recipients) in sorted_recipients {
        let owed = Owed::over(requests, &keys, *target_shard);
        if owed.root() != claimed.get(target_shard).copied() {
            warn!(
                source_shard = source_shard.inner(),
                target_shard = target_shard.inner(),
                block_height = view.anchor_height().inner(),
                "provision broadcast: parts do not walk to the block's own root; sending none"
            );
            continue;
        }
        let mut parts = Vec::new();
        build_owed_until(
            view,
            &state,
            source_shard,
            *target_shard,
            source_block_ts,
            &owed,
            |_, build| {
                parts.extend(build());
                ControlFlow::Continue(())
            },
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
            claimed,
            shard_recipients,
            signer: _,
        } => {
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let batches = fetch_and_broadcast_provision(
                &view,
                source_shard,
                source_block_ts,
                &requests,
                &claimed,
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
    use std::sync::Arc;

    use hyperscale_network::compression::compress;
    use hyperscale_storage::test_helpers::{make_settled_writes, state_key};
    use hyperscale_storage::{GenesisCommit, PendingChain};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BlockHeight, Hash, LeafPath, MAX_WIRE_MESSAGE_BYTES, MerkleInclusionProof, ProvisionParts,
        ProvisionTxRoot, TxHash, provision_leaf, served_digest,
    };

    use super::*;

    /// A part carrying a three MiB proof: two fit one pack, three do not.
    fn heavy(index: u32) -> Provision {
        Provision::new(ProvisionParts {
            source_shard: ShardId::leaf(1, 0),
            target_shard: ShardId::leaf(1, 1),
            block_height: BlockHeight::new(3),
            source_block_ts: WeightedTimestamp::ZERO,
            tx_hash: TxHash::from(Hash::from_bytes(&index.to_le_bytes())),
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(vec![0x5A; 3 * 1024 * 1024]),
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

    /// A source whose parts' leaves do not walk to its own header's root
    /// for a target sends that target nothing, so nothing reaches the
    /// outbound cache either; the same parts under the root they make
    /// are sent.
    #[test]
    fn a_proposer_whose_parts_fail_its_own_root_sends_nothing() {
        let target = ShardId::leaf(1, 1);
        let storage = SimShardStorage::default();
        let seeded = make_settled_writes(7, 1, vec![1]);
        storage.install_genesis(&seeded, &seeded);
        let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
        let view = chain.view_at_persisted_tip();
        let request = ProvisionsRequest {
            tx_hash: TxHash::from(Hash::from_bytes(b"tx")),
            targets: vec![target],
            local_keys: vec![state_key(7, 1)],
            local_ranges: Vec::new(),
        };
        let requests = std::slice::from_ref(&request);
        let recipients = HashMap::from([(target, vec![ValidatorId::new(1)])]);
        let roots = |root| ProvisionTxRootsMap::new([(target, root)].into()).expect("one target");
        let send = |claimed: &ProvisionTxRootsMap| {
            fetch_and_broadcast_provision(
                &view,
                ShardId::leaf(1, 0),
                WeightedTimestamp::ZERO,
                requests,
                claimed,
                &recipients,
            )
        };

        let stripped = roots(ProvisionTxRoot::over(&[provision_leaf(
            request.tx_hash,
            served_digest(std::iter::empty()),
        )]));
        assert!(send(&stripped).is_empty(), "a root over a stripped part");
        assert!(
            send(&ProvisionTxRootsMap::default()).is_empty(),
            "a header owing the target nothing"
        );

        let state = view.served_snapshot().expect("genesis is held");
        let owed = Owed::of(&state, requests, target);
        let honest = roots(owed.root().expect("the target is owed a part"));
        let [batch] = &send(&honest)[..] else {
            panic!("the target's parts are sent under its own root")
        };
        assert_eq!(batch.target_shard, target);
        assert_eq!(batch.packs.concat().len(), 1);
    }

    /// The frame caps a notification's compressed length, and compression
    /// grows bytes it cannot shrink: a pack at its budget, framed, still
    /// fits the frame once compressed, whatever its bytes.
    #[test]
    fn a_full_pack_fits_the_frame_compressed() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let incompressible: Vec<u8> = (0..PACK_BYTES + PROVISION_FRAMING_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let compressed = compress(&incompressible).len();
        assert!(
            compressed <= MAX_WIRE_MESSAGE_BYTES,
            "{compressed} bytes compressed past the {MAX_WIRE_MESSAGE_BYTES} byte frame",
        );
    }
}
