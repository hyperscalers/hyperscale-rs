//! A declared collection interval, provisioned: served from the versioned
//! index as the entry leaves it holds, proven against the source state
//! root, and re-derived by the receiver into the interval the executor
//! materializes.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_jmt::{Key as JmtKey, MultiProof, NibblePath};
use hyperscale_provisions::build_provisions;
use hyperscale_storage::test_helpers::{entry_key, make_settled_entries};
use hyperscale_storage::tree::Jmt;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateStore, entry_from_leaf};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    BlockHeight, ChainOrigin, DeclaredRange, Hash, MAX_STATE_ENTRIES_PER_TX, ShardId, TxHash,
    TypedHash, WeightedTimestamp,
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

    let chain = Arc::new(PendingChain::new(Arc::new(storage), ChainOrigin::ROOT));
    let view = chain.view_at_committed_tip();
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
