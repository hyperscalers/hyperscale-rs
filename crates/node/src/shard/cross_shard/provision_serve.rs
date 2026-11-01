//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_execution::provision_request;
use hyperscale_provisions::{ProvisionStore, build_provisions, provision_count};
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::encoded_len;
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    BlockHeight, Derivation, MAX_FETCH_RESPONSE_BYTES, MAX_TXS_PER_BLOCK, Provision,
    ProvisionCount, ShardId, ShardTrie, derive_block_transactions,
};
use tracing::warn;

use crate::serve::Answer;

/// What this node serves of one source block for one target: every part
/// it could build, in leaf order, and the count witness.
#[derive(Clone)]
pub struct ServedProvisions {
    parts: Vec<Provision>,
    count: Option<ProvisionCount>,
}

impl ServedProvisions {
    /// The answer to an ask for `indices`: the built parts among them, as
    /// many as a fetch response's budget carries past the first, and the
    /// count witness whatever was built. An index left out is asked
    /// again elsewhere.
    #[must_use]
    pub fn answer(&self, indices: &[u32]) -> GetProvisionResponse {
        let mut answer = Answer::<Provision, MAX_TXS_PER_BLOCK>::of(indices.len())
            .within(MAX_FETCH_RESPONSE_BYTES);
        answer.offer_all(
            self.parts
                .iter()
                .filter(|part| indices.contains(&part.leaf().index))
                .cloned(),
            encoded_len,
        );
        GetProvisionResponse {
            parts: answer.finish(),
            count: self.count,
        }
    }
}

/// Build what this node serves of its block at `height` for
/// `target_shard`, or `None` where it does not hold the block.
///
/// Reads the source block through [`PendingChain`] so heights still inside
/// the shard-committed / JMT-persisted window are reachable; reconstructs
/// per-tx [`ProvisionsRequest`]s from the block's declared reads + writes;
/// then hands them to [`build_provisions`], which is the same function the
/// gossip emit path runs, so a receiver absorbs byte-identical parts
/// regardless of which transport delivered them.
///
/// `derivation` is this node's: routing is a derived fact, and a block
/// read back out of storage carries none.
///
/// Takes `local_shard` and the active `ShardTrie` rather than a topology
/// handle. The caller loads the trie at serve time so routing always resolves
/// against the current partition.
pub fn build_served_provisions<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    height: BlockHeight,
    target_shard: ShardId,
) -> Option<ServedProvisions> {
    let Some(certified) = pending_chain.certified_block(height) else {
        warn!(
            block_height = height.inner(),
            "Provision request: block not found"
        );
        return None;
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
        if !request.targets.contains(&target_shard) {
            continue;
        }
        request.targets = vec![target_shard];
        requests.push(request);
    }
    let view = pending_chain.view_at_persisted_tip();
    let parts = build_provisions(
        &view,
        local_shard,
        target_shard,
        height,
        block.header().parent_qc().weighted_timestamp(),
        &requests,
        |_| true,
    );
    Some(ServedProvisions {
        parts,
        count: provision_count(&requests, target_shard),
    })
}

/// The answer to `req` from the parts this node built as the source
/// block's proposer, if it still holds every one asked. Any held part's
/// path states the count witness.
#[must_use]
pub fn outbound_answer(
    store: &ProvisionStore,
    req: &GetProvisionsRequest,
) -> Option<GetProvisionResponse> {
    let parts = req
        .indices
        .iter()
        .map(|index| store.get_outbound(req.height, req.target_shard, *index))
        .collect::<Option<Vec<Provision>>>()?;
    let first = parts.first()?;
    let count = ProvisionCount {
        count: first.leaf().count,
        merkle_root: first.leaf().merkle_root(first.leaf_hash())?,
    };
    Some(
        ServedProvisions {
            parts,
            count: Some(count),
        }
        .answer(&req.indices),
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::Request;
    use hyperscale_types::test_utils::{
        StubVmStatics, install_stub_protocol_statics, stub_transaction,
    };
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeight, Hash, PrincipalAddr,
        ProvisionTxRoot, TimestampRange, Transaction, TxHash, Verifiable, WeightedTimestamp,
        provision_leaf,
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
            terms,
            witness_sources,
            ..
        } = make_test_block(height)
        else {
            unreachable!("the fixture builds a live block")
        };
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::from_array([Verifiable::from(decoded)])),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            terms,
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
        let pending_chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));

        let served = build_served_provisions(
            &pending_chain,
            &StubVmStatics,
            local,
            &trie,
            height,
            payer_shard,
        )
        .expect("the block is held")
        .answer(&[0]);
        assert_eq!(
            served
                .parts
                .iter()
                .map(Provision::tx_hash)
                .collect::<Vec<_>>(),
            vec![hash],
            "the stored block's transaction owes the payer shard its engagement",
        );
        assert_eq!(
            served.count.map(|count| count.root()),
            Some(ProvisionTxRoot::over(&[provision_leaf(hash)])),
            "and the count witness states the one leaf",
        );
    }

    /// The count witness rides every answer from a holder of the block,
    /// one that builds no asked part included; an index past the count
    /// is simply not answered.
    #[test]
    fn the_count_rides_an_answer_with_no_part() {
        let tx = |seed: &[u8]| TxHash::from(Hash::from_bytes(seed));
        let leaves: Vec<Hash> = [tx(b"a"), tx(b"b")]
            .into_iter()
            .map(provision_leaf)
            .collect();
        let count = ProvisionCount::over(&leaves);
        let served = ServedProvisions {
            parts: Vec::new(),
            count: Some(count),
        };
        let answer = served.answer(&[0, 1, 7]);
        assert!(answer.parts.is_empty());
        assert_eq!(answer.count, Some(count));
        assert!(!GetProvisionsRequest::is_empty_response(&answer));
    }
}
