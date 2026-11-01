//! A declared collection interval, provisioned: served from the versioned
//! index as the entry leaves it holds, proven against the source state
//! root, and re-derived by the receiver into the interval the executor
//! materializes.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_jmt::{Key as JmtKey, MultiProof, NibblePath};
use hyperscale_provisions::build_provisions;
use hyperscale_storage::test_helpers::{
    entry_key, make_settled_entries, make_settled_writes, state_key,
};
use hyperscale_storage::tree::Jmt;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateStore, entry_from_leaf};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, BlockHeight, DeclaredRange, Hash, MAX_STATE_ENTRIES_PER_TX, ProvisionEntry, Provisions,
    ProvisionsContext, ProvisionsVerifyError, ShardId, SubstateEntry, SubstateKey, TxHash,
    TypedHash, Verify, WeightedTimestamp,
};

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
    let request = ProvisionsRequest {
        tx_hash: TxHash::from_raw(Hash::from_bytes(b"range-tx")),
        targets: vec![ShardId::leaf(1, 1)],
        local_keys: Vec::new(),
        local_ranges: vec![DeclaredRange {
            owner: probe.owner,
            collection: probe.collection,
            lo: 0,
            hi: u128::MAX,
            cap: u32::try_from(MAX_STATE_ENTRIES_PER_TX).expect("the per-tx cap fits"),
        }],
    };

    let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
    let view = chain.view_at_persisted_tip();
    let provisions = build_provisions(
        &view,
        ShardId::leaf(1, 0),
        ShardId::leaf(1, 1),
        BlockHeight::GENESIS,
        WeightedTimestamp::from_millis(0),
        std::slice::from_ref(&request),
    )
    .expect("the source height is available");

    // Every served leaf is proven against the source root — the same
    // multiproof predicate the wire-admission path runs.
    let entries = provisions.all_entries_deduped();
    assert_eq!(entries.len(), 3, "the interval's three entries serve");
    let proof = MultiProof::decode(provisions.proof().as_bytes()).expect("proof decodes");
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

/// A source holding one cell, `state_key(7, 1)`, and the anchor its
/// genesis root is checked under.
fn one_cell_source() -> (Arc<PendingChain<SimShardStorage>>, Anchor) {
    let storage = SimShardStorage::default();
    let seeded = make_settled_writes(7, 1, vec![1]);
    storage.install_genesis(&seeded, &seeded);
    let anchor = Anchor {
        shard: ShardId::ROOT,
        height: BlockHeight::GENESIS,
        state_root: SubstateStore::state_root(&storage),
        ts: WeightedTimestamp::from_millis(0),
    };
    let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
    (chain, anchor)
}

/// The bundle `chain` builds for one transaction reading `local_keys`.
fn cells_bundle(
    chain: &Arc<PendingChain<SimShardStorage>>,
    local_keys: Vec<SubstateKey>,
) -> Provisions {
    let request = ProvisionsRequest {
        tx_hash: TxHash::from_raw(Hash::from_bytes(b"cells-tx")),
        targets: vec![ShardId::leaf(1, 1)],
        local_keys,
        local_ranges: Vec::new(),
    };
    build_provisions(
        &chain.view_at_persisted_tip(),
        ShardId::ROOT,
        ShardId::leaf(1, 1),
        BlockHeight::GENESIS,
        WeightedTimestamp::from_millis(0),
        std::slice::from_ref(&request),
    )
    .expect("the source height is available")
}

/// A declared cell the source does not hold is carried as `None`, once
/// however often it is declared, and the proof shows it absent.
#[test]
fn an_absent_cell_is_carried_as_none_and_verifies() {
    let (chain, anchor) = one_cell_source();
    let present = state_key(7, 1);
    let absent = state_key(7, 2);
    let provisions = cells_bundle(&chain, vec![absent, present, absent]);

    let [tx] = provisions.transactions().as_slice() else {
        panic!("one transaction is staged");
    };
    let carried: Vec<(SubstateKey, Option<Vec<u8>>)> = tx
        .entries
        .iter()
        .map(|entry| (entry.key, entry.value.as_ref().map(|v| v.to_vec())))
        .collect();
    let mut expected = vec![(present, Some(vec![1])), (absent, None)];
    expected.sort_by_key(|(key, _)| *key);
    assert_eq!(
        carried, expected,
        "each declared cell once, the absent one as None"
    );

    provisions
        .verify(&ProvisionsContext { anchor })
        .expect("the proof shows the absent cell absent");
}

/// Claiming a held cell absent contradicts the proof's reading of it.
#[test]
fn none_claimed_for_a_present_cell_is_misstated() {
    let (chain, anchor) = one_cell_source();
    let present = state_key(7, 1);
    let honest = cells_bundle(&chain, vec![present, state_key(7, 2)]);

    let transactions = honest
        .transactions()
        .iter()
        .map(|tx| {
            let entries = tx
                .entries
                .iter()
                .map(|entry| SubstateEntry::new(entry.key, None))
                .collect();
            ProvisionEntry::new(tx.tx_hash, Capped::new(entries).expect("within the cap"))
        })
        .collect();
    let forged = Provisions::new(
        honest.source_shard(),
        honest.target_shard(),
        honest.block_height(),
        honest.source_block_ts(),
        honest.proof().clone(),
        Capped::new(transactions).expect("within the cap"),
    );

    assert_eq!(
        forged.verify(&ProvisionsContext { anchor }).err(),
        Some(ProvisionsVerifyError::EntryMisstated { key: present }),
    );
}

/// A transaction whose every declared cell is absent still carries a
/// proof: the absence is proven, not left unsaid.
#[test]
fn an_all_absent_bundle_carries_a_proof() {
    let (chain, anchor) = one_cell_source();
    let provisions = cells_bundle(&chain, vec![state_key(7, 2), state_key(7, 3)]);

    assert!(!provisions.proof().as_bytes().is_empty());
    let entries = provisions.all_entries_deduped();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| entry.value.is_none()));
    provisions
        .verify(&ProvisionsContext { anchor })
        .expect("both absences verify");
}
