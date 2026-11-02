//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_provisions::{
    Owed, ProvisionStore, build_part, provision_request, served_keys, served_leaf,
};
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::encoded_len;
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    Block, BlockHeight, BlockResolution, CertifiedBlock, Derivation, Hash, LeafPath,
    MAX_FETCH_RESPONSE_BYTES, MAX_TXS_PER_BLOCK, Provision, ProvisionCount, ScheduleLookup,
    ShardId, ShardTrie, TopologySchedule, Verified, derive_block_transactions,
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

/// The leaves a held source block's header commits to one target, and
/// the routing whose requests make them out of the block's own state:
/// what every part this node serves of the block is built under.
///
/// Only ever made by matching the header's root, so it is a function of
/// the committed header and kept for as long as the cache likes: a later
/// change of partition cannot make it stale.
#[derive(Clone)]
pub struct OwedLeaves {
    count: ProvisionCount,
    leaves: Arc<[Hash]>,
    trie: ShardTrie,
}

impl OwedLeaves {
    /// `leaves`, whose root matched, made under `trie`.
    #[must_use]
    pub fn new(leaves: Vec<Hash>, trie: ShardTrie) -> Self {
        Self {
            count: ProvisionCount::over(&leaves),
            leaves: leaves.into(),
            trie,
        }
    }

    /// The count witness the leaves make.
    #[must_use]
    pub const fn count(&self) -> ProvisionCount {
        self.count
    }
}

/// What a held source block's header commits to one target.
#[derive(Clone)]
pub enum Owing {
    /// The header commits the target nothing.
    Nothing,
    /// The header commits these leaves.
    Leaves(OwedLeaves),
}

impl Owing {
    /// The leaves owed, if any.
    #[must_use]
    pub const fn leaves(&self) -> Option<&OwedLeaves> {
        match self {
            Self::Nothing => None,
            Self::Leaves(owed) => Some(owed),
        }
    }

    /// What it costs the serve cache: its leaves and its slot.
    pub fn weight(&self) -> usize {
        let leaves = self.leaves().map_or(0, |owed| owed.leaves.len());
        (leaves * size_of::<Hash>()).saturating_add(size_of::<Self>())
    }
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

/// What this node's committed block at `height` owes `target_shard`:
/// [`Owing::Nothing`] where its header commits the target nothing,
/// [`Owing::Leaves`] once the leaves the block's routing makes out of
/// its own state walk to the header's root, and `None` where this node
/// does not hold the block or its state, its routing is not resolvable
/// here, or the leaves do not match. Only an answer is kept.
///
/// The routing is the trie of the window whose committee certified the
/// block, keyed by the epoch its stored QC signed: the copy its child's
/// header pins, which the commit stores. The proposer made the header's
/// roots under the live committee of the block's committee anchor, and
/// every honest voter checked them under the committee it signed for, so
/// that window is the one the roots were made under for every certified
/// block whichever QC copy a replica holds (every QC over one block
/// states one epoch). A recovery folded since, or a reshape of the
/// target, moves nothing.
///
/// A signed window this node's beacon has evicted falls back to the
/// block's own anchor's window. The two differ only on a chain that
/// stalled across the eviction floor between the block's committee
/// anchor and its own, and the root match keeps the guess honest. An
/// own anchor evicted too lies past the tx-artifact horizon, so every
/// part of the block is past its deadline, and the answer is `None`. A
/// signed window not yet committed here is `None` as well. A `None`
/// answers the request empty, which the requester takes as "not held"
/// and asks another holder.
///
/// A chain's genesis block, the one block whose QC no committee signed,
/// carries no transactions, so its header commits no target anything.
///
/// `derivation` is this node's: routing is a derived fact, and a block
/// read back out of storage carries none.
pub fn owed_leaves<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    local_shard: ShardId,
    schedule: &TopologySchedule,
    height: BlockHeight,
    target_shard: ShardId,
) -> Option<Owing> {
    let certified = held_block(pending_chain, derivation, height)?;
    let block = certified.block();
    let Some(claimed) = block
        .header()
        .provision_tx_roots()
        .get(&target_shard)
        .copied()
    else {
        return Some(Owing::Nothing);
    };
    let view = pending_chain.view_at(block.hash(), height);
    let state = view.served_snapshot()?;

    let epoch = certified.qc().committee_epoch();
    let trie = match schedule.signed_committee(local_shard, epoch) {
        BlockResolution::Committee(committee) => committee.snapshot.shard_trie(),
        BlockResolution::NotYetCommitted => return None,
        BlockResolution::Evicted => {
            let own_anchor = block.header().parent_qc().weighted_timestamp();
            match schedule.lookup_for_shard(local_shard, own_anchor).0 {
                ScheduleLookup::Committee(snapshot) => snapshot.shard_trie(),
                ScheduleLookup::NotYetCommitted | ScheduleLookup::Evicted => {
                    warn!(
                        local_shard = local_shard.inner(),
                        target_shard = target_shard.inner(),
                        block_height = height.inner(),
                        epoch = epoch.inner(),
                        "Provision request: the block's windows are evicted; serving none"
                    );
                    return None;
                }
            }
        }
    };
    let requests = requests_under(trie, block, local_shard, target_shard);
    let owed = Owed::of(&state, &requests, target_shard);
    if owed.root() == Some(claimed) {
        return Some(Owing::Leaves(OwedLeaves::new(
            owed.leaves().to_vec(),
            trie.clone(),
        )));
    }
    warn!(
        local_shard = local_shard.inner(),
        target_shard = target_shard.inner(),
        block_height = height.inner(),
        epoch = epoch.inner(),
        "Provision request: the block's routing does not walk to its own root; serving none"
    );
    None
}

/// Build what this node serves at `indices` (ascending) of its block at
/// `height` for `target_shard`, under `owed`, the leaves its header's
/// root was matched to: nothing where it no longer holds the block or
/// its state.
///
/// Builds in leaf order and stops once what it built fills a fetch
/// response, so one ask costs at most a response's worth of parts
/// whatever it names; an index past that point is not built, and is
/// asked again. Only the asked indices read state.
///
/// Values and proofs both come from the view anchored at the block
/// itself, so a block committed here but not yet persisted builds like
/// any other, and no part pairs one height's values with another's
/// proof. An owed index that view cannot build, or whose served keys
/// no longer make its committed leaf, never will be, and is served as
/// `None`.
///
/// Builds through [`build_part`], the builder the gossip emit path runs,
/// so a receiver absorbs byte-identical parts regardless of which
/// transport delivered them.
pub fn build_served_parts<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    local_shard: ShardId,
    owed: &OwedLeaves,
    height: BlockHeight,
    target_shard: ShardId,
    indices: &[u32],
) -> Vec<(u32, ServedPart)> {
    let Some(certified) = held_block(pending_chain, derivation, height) else {
        return Vec::new();
    };
    let block = certified.block();
    let view = pending_chain.view_at(block.hash(), height);
    let Some(state) = view.served_snapshot() else {
        return Vec::new();
    };
    let requests = requests_under(&owed.trie, block, local_shard, target_shard);
    if requests.len() != owed.leaves.len() {
        return Vec::new();
    }
    let paths = LeafPath::all(&owed.leaves);
    let source_block_ts = block.header().parent_qc().weighted_timestamp();
    let mut parts = Vec::new();
    let mut spent = 0usize;
    for &index in indices {
        let Some(((request, path), leaf)) = requests
            .get(index as usize)
            .zip(paths.get(index as usize))
            .zip(owed.leaves.get(index as usize))
        else {
            break;
        };
        let keys = served_keys(&state, request);
        let part = (served_leaf(request, &keys) == *leaf)
            .then(|| {
                build_part(
                    &view,
                    &state,
                    local_shard,
                    target_shard,
                    source_block_ts,
                    request,
                    &keys,
                    path.clone(),
                )
            })
            .flatten();
        let served = ServedPart::new(part, owed.count);
        spent = spent.saturating_add(served.bytes);
        parts.push((index, served));
        if spent >= MAX_FETCH_RESPONSE_BYTES {
            break;
        }
    }
    parts
}

/// This node's committed block at `height`, its transactions derived
/// here: a block read back out of storage carries no derivations, and a
/// transaction this node has not derived names no provisions.
fn held_block<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    derivation: &dyn Derivation,
    height: BlockHeight,
) -> Option<Arc<Verified<CertifiedBlock>>> {
    let Some(certified) = pending_chain.certified_block(height) else {
        warn!(
            block_height = height.inner(),
            "Provision request: block not found"
        );
        return None;
    };
    derive_block_transactions(certified.block(), derivation);
    Some(certified)
}

/// The requests `block`'s transactions owe `target_shard` routed under
/// `trie`, in block order, each narrowed to that one target: the same
/// rule the proposer committed the header's root by.
fn requests_under(
    trie: &ShardTrie,
    block: &Block,
    local_shard: ShardId,
    target_shard: ShardId,
) -> Vec<ProvisionsRequest> {
    block
        .transactions()
        .iter()
        .filter_map(|tx| provision_request(trie, tx, local_shard))
        .filter(|request| request.targets.contains(&target_shard))
        .map(|mut request| {
            request.targets = vec![target_shard];
            request
        })
        .collect()
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
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_provisions::provision_tx_roots;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block_with_anchor_wt, make_test_certified,
        make_test_certified_signed,
    };
    use hyperscale_storage::{
        ChainEntry, ChainWrites, JmtSnapshot, MemberInputs, ParentAnchor, PreparedBlockView,
        ShardChainWriter, SubstateStore, Substates,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::Request;
    use hyperscale_types::test_utils::{
        StubVmStatics, install_stub_protocol_statics, stub_transaction, stub_transaction_with_reads,
    };
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHash, BlockHeader, BlockHeaderParts,
        Epoch, EpochWindows, FrontierInputs, NetworkDefinition, PrincipalAddr, ProvisionTxRoot,
        ProvisionTxRootsMap, RecoveryCause, ShardRecovery, SubstateEntry, SubstateKey,
        SweepFrontier, TimestampRange, TopologySnapshot, Transaction, TxHash, ValidatorSet,
        Verifiable, WeightedTimestamp, provision_leaf, served_digest,
    };

    use super::*;

    /// A schedule of one window whose trie is `trie`.
    fn one_window(trie: &ShardTrie) -> TopologySchedule {
        TopologySchedule::single(snapshot_of(trie))
    }

    /// A committee-less window over `trie`'s shards.
    fn snapshot_of(trie: &ShardTrie) -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            trie.leaves().map(|shard| (shard, Vec::new())).collect(),
            HashMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        ))
    }

    /// The provision roots `tx` owes at `state` from [`LOCAL`] routed
    /// under `trie`.
    fn roots_of(state: &impl Substates, trie: &ShardTrie, tx: &Transaction) -> ProvisionTxRootsMap {
        provision_tx_roots(state, trie, LOCAL, &[Verifiable::from(tx.clone())])
            .expect("the test derives its transaction")
    }

    /// A live test block at `height` anchored at `anchor_ms` carrying `tx`
    /// as a store hands a transaction back, decoded, with no derivation,
    /// its header committing `roots`.
    fn block_committing(
        height: BlockHeight,
        anchor_ms: u64,
        tx: &Transaction,
        roots: ProvisionTxRootsMap,
    ) -> Block {
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
        } = make_test_block_with_anchor_wt(height, anchor_ms)
        else {
            unreachable!("the fixture builds a live block")
        };
        let header = BlockHeader::new(BlockHeaderParts {
            provision_tx_roots: roots,
            ..header.into_parts()
        });
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
        schedule: TopologySchedule,
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
            let roots = roots_of(
                &PreparedBlockView {
                    parent: &storage.snapshot(),
                    block: &jmt_snapshot,
                },
                &trie,
                &tx,
            );
            Self {
                schedule: one_window(&trie),
                pending_chain: Arc::new(PendingChain::new(storage, BlockHeight::GENESIS)),
                certified: make_test_certified(block_committing(HEIGHT, 0, &tx, roots)),
                jmt_snapshot,
                key,
            }
        }

        /// What the block owes the payer shard, or `None` where this
        /// node cannot say.
        fn owed(&self) -> Option<OwedLeaves> {
            owed_leaves(
                &self.pending_chain,
                &StubVmStatics,
                LOCAL,
                &self.schedule,
                HEIGHT,
                PAYER_SHARD,
            )
            .map(|owing| {
                owing
                    .leaves()
                    .expect("the block owes the payer shard")
                    .clone()
            })
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
        fn build(&self) -> Vec<(u32, ServedPart)> {
            build_served_parts(
                &self.pending_chain,
                &StubVmStatics,
                LOCAL,
                &self.owed().expect("the block and its state are held"),
                HEIGHT,
                PAYER_SHARD,
                &[0],
            )
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
        let [(0, served)] = &built[..] else {
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

    /// A committed block whose state this node does not hold yet matches
    /// nothing and builds nothing, rather than an answer a serve cache
    /// would keep after the state lands: its leaves need the state's
    /// range reads.
    #[test]
    fn a_block_whose_state_is_not_held_yet_builds_nothing() {
        let block = Unpersisted::new(&[7]);
        block.hold_under(BlockHash::from_raw(Hash::from_bytes(b"another prep")));

        assert!(block.owed().is_none(), "nothing is said, and nothing kept");

        block.hold();
        let [(0, served)] = &block.build()[..] else {
            panic!("index 0 is built")
        };
        assert!(served.part.is_some(), "and it builds once the state lands");
    }

    /// A block whose header commits another root than the one this
    /// node's routings make out of the block's own state is served by
    /// nothing, under no routing: its leaves match no candidate, so no
    /// part is built and no proof generated.
    #[test]
    fn a_serve_with_no_matching_routing_builds_no_proof() {
        install_stub_protocol_statics();
        let mut block = Unpersisted::new(&[7]);
        let tx = block.certified.block().transactions()[0]
            .as_unverified()
            .clone();
        let forged = ProvisionTxRootsMap::new(BTreeMap::from([(
            PAYER_SHARD,
            ProvisionTxRoot::over(&[provision_leaf(tx.hash(), served_digest(std::iter::empty()))]),
        )]))
        .expect("one target");
        block.certified = make_test_certified(block_committing(HEIGHT, 0, &tx, forged));
        block.hold();

        assert!(
            block.owed().is_none(),
            "a root over a stripped part matches no routing"
        );
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
        let storage = Arc::new(SimShardStorage::default());
        let roots = roots_of(&storage.snapshot(), &trie, &routed);
        let claimed = roots[&payer_shard];
        let block = block_committing(height, 0, &routed, roots);
        commit_settled_at(
            &*storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let pending_chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));

        let Some(Owing::Leaves(owed)) = owed_leaves(
            &pending_chain,
            &StubVmStatics,
            local,
            &one_window(&trie),
            height,
            payer_shard,
        ) else {
            panic!("the held block owes the payer shard")
        };
        let build = |indices: &[u32]| {
            build_served_parts(
                &pending_chain,
                &StubVmStatics,
                local,
                &owed,
                height,
                payer_shard,
                indices,
            )
        };
        assert!(
            build(&[1]).is_empty(),
            "an index past the count builds nothing"
        );

        let served = provision_answer(
            1,
            build(&[0]).into_iter().map(|(_, served)| served),
            Some(owed.count()),
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
            Some(claimed),
            "and the count witness wraps to the header's root",
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
            .map(|tx| provision_leaf(tx, served_digest(std::iter::empty())))
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

    /// A schedule cut at 1000 ms where [`PAYER_SHARD`] grows into two
    /// children while [`LOCAL`] survives.
    fn payer_shard_grown_at_1000() -> TopologySchedule {
        let after = ShardTrie::from_leaves([LOCAL, ShardId::leaf(2, 2), ShardId::leaf(2, 3)]);
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(0),
            snapshot_of(&ShardTrie::uniform(1)),
        );
        let head = snapshot_of(&after);
        schedule.insert(Epoch::new(1), Arc::clone(&head));
        schedule.set_head(Epoch::new(1), head);
        schedule
    }

    /// What a surviving source owes [`PAYER_SHARD`] for its first block
    /// anchored past the cut, whose transaction reads a cell here for a
    /// payer there. Its committee signed the window before the cut, where
    /// its proposer classified it, so its header names the payer shard as
    /// it stood. The parent, anchored before the cut, is held when
    /// `parent_held`; otherwise the block is the chain's first past
    /// genesis, whose header this store does not hold.
    fn owed_at_the_cut(parent_held: bool) -> Option<Owing> {
        let schedule = payer_shard_grown_at_1000();
        assert_eq!(
            schedule
                .head()
                .shard_trie()
                .shard_for_prefix(PAYER.address()),
            ShardId::leaf(2, 2),
            "past the cut the payer is a child's",
        );
        owed_of_block(
            &schedule,
            parent_held.then_some(500),
            1_500,
            Epoch::new(0),
            &ShardTrie::uniform(1),
            PAYER_SHARD,
        )
    }

    /// The payer of the transaction [`owed_of_block`] carries.
    const PAYER: PrincipalAddr = PrincipalAddr::new([0x80; 31]);

    /// What this node owes `target` for a committed block anchored at
    /// `anchor_ms` and certified under `signed`, whose transaction reads a
    /// cell here for [`PAYER`], its header's roots routed under
    /// `classified`. Its parent, anchored at `parent_anchor_ms`, is held
    /// when that is given; otherwise the block is the chain's first past
    /// genesis, whose header this store does not hold.
    fn owed_of_block(
        schedule: &TopologySchedule,
        parent_anchor_ms: Option<u64>,
        anchor_ms: u64,
        signed: Epoch,
        classified: &ShardTrie,
        target: ShardId,
    ) -> Option<Owing> {
        install_stub_protocol_statics();
        let held = PrincipalAddr::new([0x10; 31]);
        let tx = stub_transaction_with_reads(
            PAYER,
            &[held.address()],
            &[PAYER.address()],
            1_000,
            validity(),
        );

        let storage = Arc::new(SimShardStorage::default());
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        let height = parent_anchor_ms.map_or(HEIGHT, |parent_anchor_ms| {
            commit_settled_at(
                &*storage,
                &make_test_certified(make_test_block_with_anchor_wt(HEIGHT, parent_anchor_ms)),
                &[],
                &[],
                &witness,
            );
            HEIGHT.next()
        });
        let roots = roots_of(&storage.snapshot(), classified, &tx);
        assert!(roots.contains_key(&target));
        commit_settled_at(
            &*storage,
            &make_test_certified_signed(block_committing(height, anchor_ms, &tx, roots), signed),
            &[],
            &[],
            &witness,
        );
        let pending_chain = Arc::new(PendingChain::new(storage, BlockHeight::GENESIS));
        assert_eq!(
            pending_chain
                .certified_header(height.prev().expect("past genesis"))
                .is_some(),
            parent_anchor_ms.is_some(),
        );
        owed_leaves(
            &pending_chain,
            &StubVmStatics,
            LOCAL,
            schedule,
            height,
            target,
        )
    }

    /// A surviving source's block at the cut where its target grows is
    /// served under the window its committee signed, the one routing
    /// that names the target as the header does: the block's own anchor
    /// and the head both route its transaction to a child.
    #[test]
    fn a_block_at_the_cut_where_its_target_grows_serves_under_its_signed_window() {
        let Some(Owing::Leaves(owed)) = owed_at_the_cut(true) else {
            panic!("the signed window's routing matches the header")
        };
        assert_eq!(owed.trie, ShardTrie::uniform(1));
        assert_eq!(owed.count().count, 1);
    }

    /// The signed window is read off the block's own QC, so a block whose
    /// parent's header this store does not hold serves all the same.
    #[test]
    fn a_block_whose_parent_header_is_absent_serves_under_its_signed_window() {
        let Some(Owing::Leaves(owed)) = owed_at_the_cut(false) else {
            panic!("the signed window needs no parent header")
        };
        assert_eq!(owed.trie, ShardTrie::uniform(1));
    }

    /// Three windows of one trie, [`PAYER_SHARD`] whole in each, with
    /// every window below `floor` evicted.
    fn uniform_evicted_below(floor: Epoch) -> TopologySchedule {
        let uniform = snapshot_of(&ShardTrie::uniform(1));
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(0),
            Arc::clone(&uniform),
        );
        schedule.insert(Epoch::new(1), Arc::clone(&uniform));
        schedule.insert(Epoch::new(2), Arc::clone(&uniform));
        schedule.set_head(Epoch::new(2), uniform);
        schedule.evict_below(floor);
        schedule
    }

    /// A block signed under an evicted window, anchored in a window still
    /// held, is served under its own anchor's routing once that walks to
    /// the header's root: a chain that stalled across the floor.
    #[test]
    fn an_evicted_signed_window_serves_under_the_retained_own_anchor() {
        let schedule = uniform_evicted_below(Epoch::new(1));
        let trie = ShardTrie::uniform(1);
        let Some(Owing::Leaves(owed)) = owed_of_block(
            &schedule,
            Some(500),
            1_500,
            Epoch::new(0),
            &trie,
            PAYER_SHARD,
        ) else {
            panic!("the own anchor's routing matches the header")
        };
        assert_eq!(owed.trie, trie);
    }

    /// A block whose signed window and own anchor's window are both
    /// evicted answers nothing, though the head would route it as the
    /// header does: its parts are past their deadline, and the requester
    /// takes the empty answer as "not held".
    #[test]
    fn a_block_whose_windows_are_evicted_answers_none() {
        let schedule = uniform_evicted_below(Epoch::new(2));
        assert!(
            owed_of_block(
                &schedule,
                Some(500),
                1_500,
                Epoch::new(0),
                &ShardTrie::uniform(1),
                PAYER_SHARD,
            )
            .is_none()
        );
    }

    /// The first block past a halt recovery extends the halted tip, so
    /// its committee anchor sits below the bridge and its committee
    /// signed the window the fresh committee was seated in, where
    /// [`PAYER_SHARD`] has grown and the proposer classified it. Neither
    /// the committee anchor's own window, nor the block's own (past the
    /// bridge, where the payer shard has merged back), nor the head names
    /// the target the header does; the signed window does, and serves.
    #[test]
    fn a_block_past_a_recovery_bridge_serves_under_its_signed_window() {
        let grown = ShardTrie::from_leaves([LOCAL, ShardId::leaf(2, 2), ShardId::leaf(2, 3)]);
        let recovering = |trie: &ShardTrie| {
            Arc::new(
                snapshot_of(trie).as_ref().clone().with_pending_recoveries(
                    std::iter::once((
                        LOCAL,
                        ShardRecovery {
                            cause: RecoveryCause::Halt,
                            rotated_at: Epoch::new(20),
                            retained: Vec::new(),
                            attested_frontier: BlockHeight::GENESIS,
                        },
                    ))
                    .collect(),
                ),
            )
        };
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            snapshot_of(&ShardTrie::uniform(1)),
        );
        schedule.insert(Epoch::new(21), recovering(&grown));
        let head = recovering(&ShardTrie::uniform(1));
        schedule.insert(Epoch::new(22), Arc::clone(&head));
        schedule.set_head(Epoch::new(22), head);
        let target = ShardId::leaf(2, 2);
        assert_eq!(grown.shard_for_prefix(PAYER.address()), target);

        let Some(Owing::Leaves(owed)) = owed_of_block(
            &schedule,
            Some(2_500),
            22_500,
            Epoch::new(21),
            &grown,
            target,
        ) else {
            panic!("the signed window's routing matches the header")
        };
        assert_eq!(owed.trie, grown);
        assert_eq!(owed.count().count, 1);
    }
}
