//! Inbound provision-request handling for cross-shard fetches.

use std::ops::ControlFlow;
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_provisions::{
    ProvisionStore, build_provisions_until, provision_count, provision_request,
};
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

/// The bytes of served parts kept per hosted shard seat, so a host with
/// k seats keeps up to k times this.
///
/// Thirty-two full fetch responses: the parts a target committee is
/// still asking for are those of the few newest blocks, and a part the
/// cache let go is built again when next asked.
pub const PROVISION_CACHE_BYTES: usize = 32 * MAX_FETCH_RESPONSE_BYTES;

/// What this node serves at one leaf index of a source block for one
/// target: the part, or `None` where this node cannot build it, beside
/// the block's count witness.
#[derive(Clone)]
pub struct ServedPart {
    part: Option<Provision>,
    bytes: usize,
    count: ProvisionCount,
}

impl ServedPart {
    /// `part` as served at its index of the block `count` states.
    #[must_use]
    pub fn new(part: Option<Provision>, count: ProvisionCount) -> Self {
        Self {
            bytes: part.as_ref().map_or(0, encoded_len),
            part,
            count,
        }
    }

    /// What it costs the serve cache: its part's encoding and its slot.
    pub const fn weight(&self) -> usize {
        self.bytes.saturating_add(size_of::<Self>())
    }
}

/// What one build of a held block made for an ask.
pub struct BuiltParts {
    /// The block's count witness, or `None` where it owes the target
    /// nothing.
    pub count: Option<ProvisionCount>,
    /// A served part for each index built, in leaf order.
    pub parts: Vec<(u32, ServedPart)>,
}

/// The answer to an ask from what was served at its indices, in leaf
/// order: the built parts, as many as a fetch response's budget carries
/// past the first, and the count witness — taken from any of them, else
/// `count`. An index left out is asked again elsewhere.
pub fn provision_answer(
    asked: usize,
    served: impl IntoIterator<Item = ServedPart>,
    count: Option<ProvisionCount>,
) -> GetProvisionResponse {
    let mut answer =
        Answer::<Provision, MAX_TXS_PER_BLOCK>::of(asked).within(MAX_FETCH_RESPONSE_BYTES);
    let mut count = count;
    for served in served {
        count = Some(served.count);
        if let Some(part) = served.part
            && answer.offer(part, served.bytes).is_break()
        {
            break;
        }
    }
    GetProvisionResponse {
        parts: answer.finish(),
        count,
    }
}

/// Build what this node serves at `indices` (ascending) of its block at
/// `height` for `target_shard`, or `None` where it does not hold the
/// block.
///
/// Builds in leaf order and stops once what it built fills a fetch
/// response, so one ask costs at most a response's worth of parts
/// whatever it names; an index past that point is not built, and is
/// asked again.
///
/// Values and proofs both come from the view anchored at the block
/// itself, so a block committed here but not yet persisted builds like
/// any other, and no part pairs one height's values with another's
/// proof. An owed index that view cannot build never will be, and is
/// served as `None`; a height below the store's retention floor reads
/// nothing, so only its keyless parts build. A block whose state this
/// node does not hold yet builds nothing, which is not kept.
///
/// Reads the source block through [`PendingChain`] so heights still inside
/// the shard-committed / JMT-persisted window are reachable; reconstructs
/// per-tx [`ProvisionsRequest`]s from the block's declared reads + writes;
/// then builds through [`build_provisions_until`], the builder the gossip
/// emit path runs, so a receiver absorbs byte-identical parts regardless
/// of which transport delivered them.
///
/// `derivation` is this node's: routing is a derived fact, and a block
/// read back out of storage carries none.
///
/// Takes `local_shard` and the active `ShardTrie` rather than a topology
/// handle. The caller loads the trie at serve time so routing always resolves
/// against the current partition.
pub fn build_served_parts<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    height: BlockHeight,
    target_shard: ShardId,
    indices: &[u32],
) -> Option<BuiltParts> {
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
    let Some(count) = provision_count(&requests, target_shard) else {
        return Some(BuiltParts {
            count: None,
            parts: Vec::new(),
        });
    };
    let view = pending_chain.view_at(block.hash(), height);
    if !view.holds(height) {
        return Some(BuiltParts {
            count: Some(count),
            parts: Vec::new(),
        });
    }
    let mut parts = Vec::new();
    let mut spent = 0usize;
    build_provisions_until(
        &view,
        local_shard,
        target_shard,
        block.header().parent_qc().weighted_timestamp(),
        &requests,
        |index, build| {
            if indices.binary_search(&index).is_err() {
                return ControlFlow::Continue(());
            }
            let served = ServedPart::new(build(), count);
            spent = spent.saturating_add(served.bytes);
            parts.push((index, served));
            if spent >= MAX_FETCH_RESPONSE_BYTES {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    Some(BuiltParts {
        count: Some(count),
        parts,
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
    let served = parts
        .into_iter()
        .map(|part| ServedPart::new(Some(part), count));
    Some(provision_answer(req.indices.len(), served, Some(count)))
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::{
        ChainEntry, ChainWrites, JmtSnapshot, MemberInputs, ParentAnchor, ShardChainWriter,
        SubstateStore,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::Request;
    use hyperscale_types::test_utils::{
        StubVmStatics, install_stub_protocol_statics, stub_transaction, stub_transaction_with_reads,
    };
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, CertifiedBlock,
        FrontierInputs, Hash, PrincipalAddr, ProvisionTxRoot, SubstateEntry, SubstateKey,
        SweepFrontier, TimestampRange, Transaction, TxHash, Verifiable, Verified,
        WeightedTimestamp, provision_leaf,
    };

    use super::*;

    /// A live test block at `height` carrying `tx` as a store hands a
    /// transaction back: decoded, with no derivation.
    fn block_carrying(height: BlockHeight, tx: &Transaction) -> Block {
        let decoded = Transaction::new(tx.body().clone());
        assert!(!decoded.is_routed());
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
        Block::Live {
            header,
            transactions: Arc::new(Capped::from_array([Verifiable::from(decoded)])),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
        }
    }

    fn validity() -> TimestampRange {
        TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(60_000),
        )
    }

    const HEIGHT: BlockHeight = BlockHeight::new(1);
    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const PAYER_SHARD: ShardId = ShardId::leaf(1, 1);

    /// A block at height 1 whose one transaction reads a cell here for a
    /// payer on the other shard, and writes `value` to it, committed over
    /// an empty store that has not persisted it.
    struct Unpersisted {
        trie: ShardTrie,
        pending_chain: Arc<PendingChain<SimShardStorage>>,
        certified: Arc<Verified<CertifiedBlock>>,
        jmt_snapshot: Arc<JmtSnapshot>,
        /// The cell the transaction reads here.
        key: SubstateKey,
    }

    impl Unpersisted {
        fn new(value: &[u8]) -> Self {
            install_stub_protocol_statics();
            let trie = ShardTrie::uniform(1);
            let payer = PrincipalAddr::new([0x80; 31]);
            let held = PrincipalAddr::new([0x10; 31]);
            assert_eq!(trie.shard_for_prefix(held.address()), LOCAL);
            assert_eq!(trie.shard_for_prefix(payer.address()), PAYER_SHARD);
            let tx = stub_transaction_with_reads(
                payer,
                &[held.address()],
                &[payer.address()],
                1_000,
                validity(),
            );
            let request = provision_request(&trie, &Verifiable::from(tx.clone()), LOCAL)
                .expect("the transaction reads a cell here");
            let [key] = request.local_keys[..] else {
                panic!("one cell read here: {:?}", request.local_keys)
            };
            let storage = Arc::new(SimShardStorage::default());
            let (_, jmt_snapshot, _) = storage.prepare_block_commit(
                ParentAnchor {
                    state_root: storage.state_root(),
                    height: BlockHeight::GENESIS,
                    state: &storage.snapshot(),
                    pending: &[],
                    base_reads: None,
                },
                &[],
                ChainWrites {
                    creations: &[(key, value.to_vec())],
                    removals: &[],
                    sweep_frontier: SweepFrontier::ZERO,
                    frontier: &FrontierInputs::still(ShardId::ROOT),
                    state_claims: &[],
                    members: &MemberInputs::still(ShardId::ROOT),
                },
                HEIGHT,
            );
            Self {
                trie,
                pending_chain: Arc::new(PendingChain::new(storage, BlockHeight::GENESIS)),
                certified: make_test_certified(block_carrying(HEIGHT, &tx)),
                jmt_snapshot,
                key,
            }
        }

        /// Hold the block committed, its prepared state under `hash`.
        fn hold_under(&self, hash: BlockHash) {
            self.pending_chain.insert(
                hash,
                ChainEntry {
                    parent_block_hash: self.certified.block().header().parent_block_hash(),
                    height: HEIGHT,
                    settled_txs: Vec::new(),
                    jmt_snapshot: Arc::clone(&self.jmt_snapshot),
                    certified_block: Some(Arc::clone(&self.certified)),
                },
            );
        }

        /// Hold the block committed with its prepared state.
        fn hold(&self) {
            self.hold_under(self.certified.block().hash());
        }

        /// Build the payer shard's part at index 0.
        fn build(&self) -> BuiltParts {
            build_served_parts(
                &self.pending_chain,
                &StubVmStatics,
                LOCAL,
                &self.trie,
                HEIGHT,
                PAYER_SHARD,
                &[0],
            )
            .expect("the block is held")
        }
    }

    /// A block committed here but not yet persisted serves the parts it
    /// owes from its own state: the value it wrote, proven against its
    /// own root.
    #[test]
    fn a_committed_block_not_yet_persisted_serves_its_parts() {
        let block = Unpersisted::new(&[7]);
        block.hold();
        assert_eq!(
            block.pending_chain.view_at_persisted_tip().anchor_height(),
            BlockHeight::GENESIS,
            "nothing is persisted",
        );

        let built = block.build();
        let [(0, served)] = &built.parts[..] else {
            panic!("index 0 is built")
        };
        let part = served
            .part
            .as_ref()
            .expect("the block's own state builds the part");
        assert_eq!(
            part.entries(),
            [SubstateEntry::new(
                block.key,
                Some(Bytes::new(vec![7]).expect("a small value"))
            )],
            "the value the block wrote, not the persisted tip's",
        );
    }

    /// A committed block whose state this node does not hold yet builds
    /// nothing, rather than an unbuildable part a serve cache would keep
    /// after the state lands.
    #[test]
    fn a_block_whose_state_is_not_held_yet_builds_nothing() {
        let block = Unpersisted::new(&[7]);
        block.hold_under(BlockHash::from_raw(Hash::from_bytes(b"another prep")));

        let early = block.build();
        assert!(early.count.is_some(), "the count still rides");
        assert!(early.parts.is_empty(), "no index is tried");

        block.hold();
        let [(0, served)] = &block.build().parts[..] else {
            panic!("index 0 is built")
        };
        assert!(served.part.is_some(), "and it builds once the state lands");
    }

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
        // A payer on the other shard, and a write here: this shard owes
        // the payer the engagement its vote waits for.
        let payer = PrincipalAddr::new([0x80; 31]);
        let held = PrincipalAddr::new([0x10; 31]);
        let routed = stub_transaction(payer, &[payer.address(), held.address()], 1_000, validity());
        assert_eq!(trie.shard_for_prefix(payer.address()), payer_shard);
        assert_eq!(trie.shard_for_prefix(held.address()), local);
        let hash = routed.hash();

        let height = BlockHeight::new(1);
        let block = block_carrying(height, &routed);
        let storage = Arc::new(SimShardStorage::default());
        commit_settled_at(
            &*storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let pending_chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));

        let build = |indices: &[u32]| {
            build_served_parts(
                &pending_chain,
                &StubVmStatics,
                local,
                &trie,
                height,
                payer_shard,
                indices,
            )
            .expect("the block is held")
        };
        let past = build(&[1]);
        assert!(
            past.parts.is_empty(),
            "an index past the count builds nothing"
        );
        assert!(past.count.is_some(), "and still states the count");

        let first = build(&[0]);
        let served = provision_answer(
            1,
            first.parts.into_iter().map(|(_, served)| served),
            first.count,
        );
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
        let unbuildable = ServedPart::new(None, count);
        for answer in [
            provision_answer(3, [unbuildable], None),
            provision_answer(3, [], Some(count)),
        ] {
            assert!(answer.parts.is_empty());
            assert_eq!(answer.count, Some(count));
            assert!(!GetProvisionsRequest::is_empty_response(&answer));
        }
    }
}
