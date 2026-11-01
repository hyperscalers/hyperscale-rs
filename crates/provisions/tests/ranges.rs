//! A declared collection interval, provisioned: served from the versioned
//! index as the entry leaves it holds, proven against the source state
//! root, and re-derived by the receiver into the interval the executor
//! materializes. And the parts a block's transactions build into, each
//! at its own leaf and each standing alone.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_jmt::{Key as JmtKey, MultiProof, NibblePath};
use hyperscale_provisions::{build_provisions, leaves_over_requests};
use hyperscale_storage::test_helpers::{
    entry_key, make_settled_entries, make_settled_writes, state_key,
};
use hyperscale_storage::tree::Jmt;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateStore, entry_from_leaf};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, BlockHeight, DeclaredRange, Hash, MAX_PROVISION_WEIGHT, Provision, ProvisionContext,
    ProvisionParts, ProvisionTxRoot, ProvisionVerifyError, SettledWrites, ShardId, SubstateEntry,
    SubstateKey, TxHash, TypedHash, Verify, WeightedTimestamp,
};

/// A request from the transaction `seed` names, owed to the one target
/// these tests build for.
fn request(
    seed: &[u8],
    local_keys: Vec<SubstateKey>,
    ranges: Vec<DeclaredRange>,
) -> ProvisionsRequest {
    ProvisionsRequest {
        tx_hash: TxHash::from_raw(Hash::from_bytes(seed)),
        targets: vec![ShardId::leaf(1, 1)],
        local_keys,
        local_ranges: ranges,
    }
}

/// Every entry of collection `owner_seed`, up to `cap`.
fn whole_collection(owner_seed: u8, cap: usize) -> DeclaredRange {
    let probe = entry_key(owner_seed, 0);
    DeclaredRange {
        owner: probe.owner,
        collection: probe.collection,
        lo: 0,
        hi: u128::MAX,
        cap: u32::try_from(cap).expect("the cap fits"),
    }
}

/// The interval Alice's collection holds at genesis, served whole.
#[test]
fn a_range_serves_its_leaves_and_the_receiver_rederives_the_interval() {
    let storage = SimShardStorage::default();
    let seeded = make_settled_entries(
        7,
        &[
            (5, Some(vec![5])),
            (10, Some(vec![10])),
            (20, Some(vec![20])),
        ],
    );
    storage.install_genesis(&seeded, &seeded);
    let source_root = SubstateStore::state_root(&storage);

    let probe = entry_key(7, 5);
    let request = request(
        b"range-tx",
        Vec::new(),
        vec![whole_collection(7, MAX_PROVISION_WEIGHT)],
    );

    let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
    let view = chain.view_at_persisted_tip();
    let [part] = build_provisions(
        &view,
        ShardId::leaf(1, 0),
        ShardId::leaf(1, 1),
        WeightedTimestamp::from_millis(0),
        std::slice::from_ref(&request),
        |_| true,
    )
    .try_into()
    .expect("the source height is available, and one transaction builds one part");

    // Every served leaf is proven against the source root — the same
    // multiproof predicate the wire-admission path runs.
    let entries = part.entries();
    assert_eq!(entries.len(), 3, "the interval's three entries serve");
    let proof = MultiProof::decode(part.proof().as_bytes()).expect("proof decodes");
    let expected: Vec<(JmtKey, Option<[u8; 32]>)> = entries
        .iter()
        .map(|e| {
            (
                e.key.to_bytes(),
                e.value.as_ref().map(|v| jmt_value_hash(v)),
            )
        })
        .collect();
    Jmt::verify(
        &proof,
        *source_root.as_raw().as_bytes(),
        &NibblePath::empty(),
        &expected,
    )
    .expect("every entry leaf verifies against the source root");

    // The receiver re-derives the interval from the self-describing
    // leaves alone — the merge the executor's baseline performs.
    let mut rederived: Vec<(u128, Vec<u8>)> = entries
        .iter()
        .filter_map(|e| {
            let value = e.value.as_ref()?;
            let (key, value) = entry_from_leaf(e.key, value)?;
            (key.owner == probe.owner && key.collection == probe.collection)
                .then_some((key.order, value))
        })
        .collect();
    rederived.sort_unstable();
    assert_eq!(
        rederived,
        vec![(5, vec![5]), (10, vec![10]), (20, vec![20])],
    );
}

/// A source holding `seeded` at genesis, and the anchor its genesis root
/// is checked under.
fn source_of(seeded: &SettledWrites) -> (Arc<PendingChain<SimShardStorage>>, Anchor) {
    let storage = SimShardStorage::default();
    storage.install_genesis(seeded, seeded);
    let anchor = Anchor {
        shard: ShardId::ROOT,
        height: BlockHeight::GENESIS,
        state_root: SubstateStore::state_root(&storage),
        ts: WeightedTimestamp::from_millis(0),
    };
    let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
    (chain, anchor)
}

/// A source holding one cell, `state_key(7, 1)`.
fn one_cell_source() -> (Arc<PendingChain<SimShardStorage>>, Anchor) {
    source_of(&make_settled_writes(7, 1, vec![1]))
}

/// The parts `chain` builds at genesis for `requests`.
fn parts_of(
    chain: &Arc<PendingChain<SimShardStorage>>,
    requests: &[ProvisionsRequest],
) -> Vec<Provision> {
    build_provisions(
        &chain.view_at_persisted_tip(),
        ShardId::ROOT,
        ShardId::leaf(1, 1),
        WeightedTimestamp::from_millis(0),
        requests,
        |_| true,
    )
}

/// The leaves `chain`'s header would commit at genesis for what
/// `requests` owe their one target.
fn leaves_of(
    chain: &Arc<PendingChain<SimShardStorage>>,
    requests: &[ProvisionsRequest],
) -> Vec<Hash> {
    let view = chain.view_at_persisted_tip();
    let state = view.served_snapshot().expect("genesis is held");
    leaves_over_requests(&state, requests)
        .remove(&ShardId::leaf(1, 1))
        .expect("every request owes the one target")
}

/// The part `chain` builds for one transaction reading `local_keys`.
fn cells_part(
    chain: &Arc<PendingChain<SimShardStorage>>,
    local_keys: Vec<SubstateKey>,
) -> Provision {
    let [part] = parts_of(chain, &[request(b"cells-tx", local_keys, Vec::new())])
        .try_into()
        .expect("the source height is available");
    part
}

/// A declared cell the source does not hold is carried as `None`, once
/// however often it is declared, and the proof shows it absent.
#[test]
fn an_absent_cell_is_carried_as_none_and_verifies() {
    let (chain, anchor) = one_cell_source();
    let present = state_key(7, 1);
    let absent = state_key(7, 2);
    let part = cells_part(&chain, vec![absent, present, absent]);

    let carried: Vec<(SubstateKey, Option<Vec<u8>>)> = part
        .entries()
        .iter()
        .map(|entry| (entry.key, entry.value.as_ref().map(|v| v.to_vec())))
        .collect();
    let mut expected = vec![(present, Some(vec![1])), (absent, None)];
    expected.sort_by_key(|(key, _)| *key);
    assert_eq!(
        carried, expected,
        "each declared cell once, the absent one as None"
    );

    part.verify(&ProvisionContext { anchor })
        .expect("the proof shows the absent cell absent");
}

/// Claiming a held cell absent contradicts the proof's reading of it.
#[test]
fn none_claimed_for_a_present_cell_is_misstated() {
    let (chain, anchor) = one_cell_source();
    let present = state_key(7, 1);
    let honest = cells_part(&chain, vec![present, state_key(7, 2)]);

    let entries: Vec<SubstateEntry> = honest
        .entries()
        .iter()
        .map(|entry| SubstateEntry::new(entry.key, None))
        .collect();
    let forged = Provision::new(ProvisionParts {
        source_shard: honest.source_shard(),
        target_shard: honest.target_shard(),
        block_height: honest.block_height(),
        source_block_ts: honest.source_block_ts(),
        tx_hash: honest.tx_hash(),
        entries: Capped::new(entries).expect("within the cap"),
        proof: honest.proof().clone(),
        leaf: honest.leaf().clone(),
    });

    assert_eq!(
        forged.verify(&ProvisionContext { anchor }).err(),
        Some(ProvisionVerifyError::EntryMisstated { key: present }),
    );
}

/// A transaction whose every declared cell is absent still carries a
/// proof: the absence is proven, not left unsaid.
#[test]
fn an_all_absent_part_carries_a_proof() {
    let (chain, anchor) = one_cell_source();
    let part = cells_part(&chain, vec![state_key(7, 2), state_key(7, 3)]);

    assert!(!part.proof().as_bytes().is_empty());
    assert_eq!(part.entries().len(), 2);
    assert!(part.entries().iter().all(|entry| entry.value.is_none()));
    part.verify(&ProvisionContext { anchor })
        .expect("both absences verify");
}

/// A block's transactions build one part each, in request order, and
/// each part's leaf walks its path to the root over the whole list.
#[test]
fn each_transaction_builds_its_own_part_at_its_own_leaf() {
    let (chain, anchor) = one_cell_source();
    let requests: Vec<ProvisionsRequest> = [b"t0", b"t1", b"t2"]
        .iter()
        .map(|seed| request(*seed, vec![state_key(7, 1)], Vec::new()))
        .collect();
    let parts = parts_of(&chain, &requests);
    let root = ProvisionTxRoot::over(&leaves_of(&chain, &requests));

    assert_eq!(parts.len(), 3);
    for (index, (part, req)) in parts.iter().zip(&requests).enumerate() {
        assert_eq!(part.tx_hash(), req.tx_hash);
        assert_eq!(part.leaf().index as usize, index);
        assert_eq!(part.leaf().count, 3);
        assert_eq!(
            ProvisionTxRoot::through(part.leaf_hash(), part.leaf()),
            Some(root)
        );
        part.verify(&ProvisionContext { anchor })
            .expect("each part proves its own entries");
    }

    let wanted = parts_of(&chain, &requests)
        .into_iter()
        .filter(|part| part.leaf().index == 1)
        .collect::<Vec<_>>();
    let asked = build_provisions(
        &chain.view_at_persisted_tip(),
        ShardId::ROOT,
        ShardId::leaf(1, 1),
        WeightedTimestamp::from_millis(0),
        &requests,
        |index| index == 1,
    );
    assert_eq!(asked, wanted, "a build of one index builds that part alone");
}

/// A transaction whose part no frame can carry costs only itself: its
/// neighbours build at their own leaves, under the count of the whole
/// list.
#[test]
fn an_unbuildable_part_leaves_its_neighbours_whole() {
    // Fifty entries near the widest a cell may hold pass a fetch response.
    let seeded = SettledWrites::from_parts(
        BTreeMap::from([(state_key(7, 1), Some(vec![1]))]),
        (0..50u128)
            .map(|order| (entry_key(9, order), Some(vec![0xAB; 200 * 1024])))
            .collect(),
    );
    let (chain, anchor) = source_of(&seeded);

    let requests = vec![
        request(b"t0", vec![state_key(7, 1)], Vec::new()),
        request(b"t1", Vec::new(), vec![whole_collection(9, 50)]),
        request(b"t2", vec![state_key(7, 1)], Vec::new()),
    ];
    let parts = parts_of(&chain, &requests);
    let root = ProvisionTxRoot::over(&leaves_of(&chain, &requests));

    let indices: Vec<u32> = parts.iter().map(|part| part.leaf().index).collect();
    assert_eq!(
        indices,
        vec![0, 2],
        "the wide transaction alone is left out"
    );
    for part in &parts {
        assert_eq!(part.leaf().count, 3);
        assert_eq!(
            ProvisionTxRoot::through(part.leaf_hash(), part.leaf()),
            Some(root)
        );
        part.verify(&ProvisionContext { anchor })
            .expect("a neighbour proves its own entries");
    }
}
