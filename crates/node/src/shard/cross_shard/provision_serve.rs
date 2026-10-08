//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_execution::provision_request;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{Derivation, ShardId, ShardTrie, derive_block_transactions};
use tracing::warn;

/// Serve an inbound provision request from a target shard needing our state.
///
/// Reads the source block through [`PendingChain`] so heights still inside
/// the shard-committed / JMT-persisted window are reachable; reconstructs
/// per-tx [`ProvisionsRequest`]s from the block's declared reads + writes;
/// then hands them to [`build_provisions`], which is the same function the
/// gossip emit path runs. Receivers therefore absorb byte-identical
/// `entries`, `target_nodes`, and `owned_nodes` regardless of which
/// transport delivered the provision — without this, fetched-provision
/// recipients would have empty `owned_nodes` maps and diverge on
/// `filter_updates_for_shard` downstream, breaking `local_receipt_root`
/// agreement.
///
/// `derivation` is this node's: routing is a derived fact, and a block
/// read back out of storage carries none.
///
/// Takes `local_shard` and the active `ShardTrie` instead of
/// `&TopologyCoordinator` to avoid a topology dependency in the I/O layer.
/// The caller loads the trie at serve time so routing always resolves
/// against the current partition.
pub fn serve_provision_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let height = req.height;
    let Some(certified) = pending_chain.certified_block(height) else {
        warn!(
            block_height = height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let block = certified.block();
    // A block read back out of storage carries no derivations, and a
    // transaction this node has not derived names no provisions.
    derive_block_transactions(block, derivation);

    // The same derivation the gossip emit path runs, narrowed to the
    // requester: a transaction is served exactly when the requester is
    // among the targets the emit path would have broadcast to.
    let mut requests: Vec<ProvisionsRequest> = Vec::new();
    for tx in block.transactions().iter() {
        let Some(mut request) = provision_request(shard_trie, tx, local_shard) else {
            continue;
        };
        if !request.targets.contains(&req.target_shard) {
            continue;
        }
        request.targets = vec![req.target_shard];
        requests.push(request);
    }
    let view = pending_chain.view_at_persisted_tip();
    let provisions = build_provisions(
        &view,
        local_shard,
        req.target_shard,
        height,
        block.header().parent_qc().weighted_timestamp(),
        &requests,
    );

    if let Some(p) = &provisions {
        record_fetch_response_sent("provision", p.transactions().len());
    }
    GetProvisionResponse { provisions }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{
        StubVmStatics, install_stub_protocol_statics, stub_transaction,
    };
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeight, ChainOrigin,
        PrincipalAddr, TimestampRange, Transaction, Verifiable, WeightedTimestamp,
    };

    use super::*;

    /// A committed block read back without its transactions' derivations
    /// still serves the provisions they owe.
    ///
    /// A store hands back what it decoded, and a decoded transaction
    /// carries no derivation: routing it is the serving node's answer. A
    /// serve that read the stored block as it came would find every
    /// transaction unrouted and answer nothing, and the requester would
    /// ask again for as long as it waits.
    #[test]
    fn a_block_read_back_underived_still_serves_its_provisions() {
        install_stub_protocol_statics();
        let trie = ShardTrie::uniform(1);
        let (local, payer_shard) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        // A payer on the other shard: this shard owes it the engagement
        // its vote waits for.
        let payer = PrincipalAddr::new([0x80; 31]);
        let routed = stub_transaction(
            payer,
            &[payer.address()],
            1_000,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        );
        assert_eq!(trie.shard_for_prefix(payer.address()), payer_shard);
        let hash = routed.hash();
        let decoded = Transaction::new(routed.body().clone());
        assert!(!decoded.is_routed());

        let height = BlockHeight::new(1);
        let Block::Live {
            header,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            witness_sources,
            ..
        } = make_test_block(height)
        else {
            unreachable!("the fixture builds a live block")
        };
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(decoded))])),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            witness_sources,
        };
        let storage = Arc::new(SimShardStorage::default());
        commit_settled_at(
            &*storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let pending_chain = Arc::new(PendingChain::new(storage, ChainOrigin::ROOT));

        let served = serve_provision_request(
            &pending_chain,
            &StubVmStatics,
            local,
            &trie,
            &GetProvisionsRequest::new(height, payer_shard),
        );
        assert_eq!(
            served.provisions.map(|provisions| provisions.tx_hashes()),
            Some(vec![hash]),
            "the stored block's transaction owes the payer shard its engagement",
        );
    }
}
