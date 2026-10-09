//! Which transactions a shard writes a committed-transaction cell for,
//! checked from outside the derivation.
//!
//! The rule is that a block writes one for every transaction it carries
//! and reads no placement, which is what lets a split child following
//! its parent's block recompose the parent's root. Both halves of that
//! are asserted here rather than beside the derivation, because the
//! second needs a store to follow a block into.

use hyperscale_hbor::Capped;
use hyperscale_storage::committed_tx_cells;
use hyperscale_types::{
    AddressClass, Block, FrontierInputs, ShardId, StoredReceipt, SubstateKey, TickManifest,
    Transaction,
};
use hyperscale_vm_effects::Hash32;
use hyperscale_vm_types::{Address, IntentHash, LegRole, LegShape, ValueEdge};

/// A component on the leaf at `path` of a four-leaf trie.
const fn on(path: u8, seed: u8) -> Address {
    let mut body = [seed; 31];
    body[0] = (path << 6) | (seed & 0x3F);
    Address::new(body, AddressClass::Component)
}

fn leg(target: Address, role: LegRole, edges: &[(u32, u32)]) -> LegShape {
    LegShape {
        target,
        role,
        edges: edges
            .iter()
            .map(|&(source, output)| ValueEdge {
                source,
                output,
                non_fungible: false,
            })
            .collect(),
        presents: Vec::new(),
        declares: vec![target],
        intent: IntentHash(Hash32([7; 32])),
        local: 0,
    }
}

/// Every transaction writes the cell, whatever shape it has and
/// whatever the trie says about where its nodes sit.
///
/// A derivation that read the shape would make a block's creations a
/// function of placement, and so of which window the reader
/// classified under. Nothing here reads a trie, so there is no
/// window to get wrong.
#[test]
fn every_transaction_writes_the_cell_under_any_window() {
    use hyperscale_types::test_utils::{StubVmStatics, test_transaction};

    let alice = on(0, 0x11);
    let bob = on(1, 0x22);
    let venue = on(2, 0x33);
    let other = on(3, 0x44);

    let transfer = vec![
        leg(alice, LegRole::Attesting, &[]),
        leg(alice, LegRole::Inbound, &[]),
        leg(bob, LegRole::Outbound, &[(1, 0)]),
    ];
    let route = vec![
        leg(alice, LegRole::Attesting, &[]),
        leg(alice, LegRole::Inbound, &[]),
        leg(venue, LegRole::Core, &[(1, 0)]),
        leg(other, LegRole::Core, &[(2, 0)]),
        leg(alice, LegRole::Outbound, &[(3, 0)]),
    ];

    for (label, legs) in [("a transfer", transfer), ("a route", route)] {
        let tx = test_transaction(1).with_legs(&StubVmStatics, legs);
        for shard in (0..4).map(|path| ShardId::leaf(2, path)) {
            assert_eq!(
                committed_tx_cells(shard, [&tx]).len(),
                1,
                "{label} writes one cell on {shard:?}",
            );
        }
    }
}

/// A split child following its parent's block derives the parent's
/// creations and its half recomposes the parent's root, under the
/// child's own window — the window a following child classifies
/// under being the one a placement-dependent derivation gets wrong.
#[test]
fn a_followed_block_recomposes_under_the_childs_own_window() {
    use std::sync::Arc;

    use hyperscale_storage::BoundaryStore;
    use hyperscale_storage::test_helpers::{block_settling, make_state_writes};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        Block, BlockHeight, ConsensusReceipt, GlobalReceiptHash, SplitChildRoots, StoredReceipt,
        TxHash, Verifiable, shard_prefix_path,
    };

    let parent = ShardId::leaf(2, 2);
    let (left, right) = parent.children();
    let tx = test_transaction(1);
    let committed = committed_tx_cells(parent, [&tx]);
    assert_eq!(committed.len(), 1);

    // The cell lands on the parent's left half; a settled write on
    // the right half keeps both subtrees populated, so the halves
    // recompose as internal nodes rather than a lone leaf.
    let right_half = StoredReceipt::new(
        TxHash::ZERO,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: make_state_writes(0xA0, 1, vec![1; 4]),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    let Block::Live {
        header,
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        witness_sources,
        ..
    } = block_settling(BlockHeight::new(1), vec![right_half])
    else {
        unreachable!("the fixture builds a live block");
    };
    let block = Block::Live {
        header,
        transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(tx))])),
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        tick_manifest: Arc::new(Capped::empty()),
        witness_sources,
    };

    let parent_root = SimShardStorage::new(shard_prefix_path(parent))
        .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
        .expect("the parent commits its block");
    let children = SplitChildRoots {
        left: SimShardStorage::new(shard_prefix_path(left))
            .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
            .expect("a child follows"),
        right: SimShardStorage::new(shard_prefix_path(right))
            .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
            .expect("a child follows"),
    };
    assert!(children.composes_to(parent_root));
}

/// A split child following its parent's block folds the parent's tick
/// membership over its own half: the rows sit under the parent's owner,
/// which is the left child's, so the left child holds them and the
/// right child holds none, and the halves recompose the parent's root.
#[test]
fn a_followed_block_recomposes_the_parents_member_rows() {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{block_settling, make_state_writes};
    use hyperscale_storage::{BoundaryStore, MemberIndex, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{stub_abort_charge, test_transaction};
    use hyperscale_types::{
        Block, BlockHeader, BlockHeaderParts, BlockHeight, ConsensusReceipt, GlobalReceiptHash,
        Joins, Settlement, SplitChildRoots, StoredReceipt, TickLine, TxHash, Verifiable,
        shard_prefix_path,
    };

    let parent = ShardId::leaf(2, 2);
    let (left, right) = parent.children();
    let tx = test_transaction(1);
    let committed = committed_tx_cells(parent, [&tx]);
    let right_half = StoredReceipt::new(
        TxHash::ZERO,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: make_state_writes(0xA0, 1, vec![1; 4]),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    let Block::Live {
        header,
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        witness_sources,
        ..
    } = block_settling(BlockHeight::new(1), vec![right_half])
    else {
        unreachable!("the fixture builds a live block");
    };
    let block = Block::Live {
        header: BlockHeader::new(BlockHeaderParts {
            shard_id: parent,
            ..header.into_parts()
        }),
        transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(tx.clone()))])),
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        tick_manifest: Arc::new(Capped::from_array([TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Executes,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: stub_abort_charge(1),
        }])),
        witness_sources,
    };

    let whole = SimShardStorage::new(shard_prefix_path(parent));
    let parent_root = whole
        .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
        .expect("the parent commits its block");
    let rows = MemberIndex::load(&whole.snapshot(), parent);
    assert_eq!(rows.members.len(), 1, "the block puts its member in flight");
    assert_eq!(rows.ticks.len(), 1);

    let left_store = SimShardStorage::new(shard_prefix_path(left));
    let right_store = SimShardStorage::new(shard_prefix_path(right));
    let children = SplitChildRoots {
        left: left_store
            .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
            .expect("a child follows"),
        right: right_store
            .follow_block_writes(&block, &committed, &FrontierInputs::still(ShardId::ROOT))
            .expect("a child follows"),
    };
    assert_eq!(MemberIndex::load(&left_store.snapshot(), parent), rows);
    assert_eq!(
        MemberIndex::load(&right_store.snapshot(), parent),
        MemberIndex::empty(parent)
    );
    assert!(children.composes_to(parent_root));
}

/// A receipt crediting `vault` a hundred of the protocol resource.
fn funding(vault: SubstateKey) -> StoredReceipt {
    use std::sync::Arc;

    use hyperscale_types::{
        ConsensusReceipt, GlobalReceiptHash, Movement, ProtocolHasher, StateWrites, StoredReceipt,
        TxHash,
    };
    use hyperscale_vm_effects::protocol_resource;

    let mut writes = StateWrites::default();
    writes.movements.insert(
        vault,
        Movement {
            resource: protocol_resource(&ProtocolHasher),
            credit: 100,
            debit: 0,
            unjudged_debit: 0,
        },
    );
    StoredReceipt::new(
        TxHash::ZERO,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    )
}

/// A block of `shard`'s chain at `height` settling `receipts`, carrying
/// `transactions` and naming `manifest`.
fn on_chain(
    shard: ShardId,
    height: u64,
    receipts: Vec<StoredReceipt>,
    transactions: &[Transaction],
    manifest: TickManifest,
) -> Block {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::block_settling;
    use hyperscale_types::{BlockHeader, BlockHeaderParts, BlockHeight, Verifiable};

    let Block::Live {
        header,
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        witness_sources,
        ..
    } = block_settling(BlockHeight::new(height), receipts)
    else {
        unreachable!("the fixture builds a live block");
    };
    Block::Live {
        header: BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            ..header.into_parts()
        }),
        transactions: Arc::new(
            Capped::new(
                transactions
                    .iter()
                    .map(|tx| Arc::new(Verifiable::from(tx.clone())))
                    .collect(),
            )
            .expect("a list written out in a test"),
        ),
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        tick_manifest: Arc::new(manifest),
        witness_sources,
    }
}

/// A split child's follower applies its half of the parent's terminal:
/// the left child, holding the parent's rows, drops them; the right
/// child, holding the fated member's vault, burns its charge; and the
/// halves still recompose the parent's root.
#[test]
fn a_follower_applies_its_half_of_the_terminal() {
    use hyperscale_storage::{BoundaryStore, MemberIndex, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        AbortCharge, Joins, LocalKey, Settlement, SplitChildRoots, TickLine, shard_prefix_path,
    };

    let parent = ShardId::leaf(2, 2);
    let (left, right) = parent.children();
    let tx = test_transaction(1);
    let charge = AbortCharge {
        vault: SubstateKey {
            owner: Address::new([0xA0; 31], AddressClass::Component),
            local: LocalKey([1; 16]),
        },
        amount: 13,
    };
    let naming = on_chain(
        parent,
        1,
        vec![funding(charge.vault)],
        std::slice::from_ref(&tx),
        Capped::from_array([TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Executes,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge,
        }]),
    );
    let terminal = on_chain(
        parent,
        2,
        Vec::new(),
        &[],
        Capped::from_array([TickLine::Fate {
            tx: tx.hash(),
            charge,
        }]),
    );

    let committed = committed_tx_cells(parent, [&tx]);
    let still = FrontierInputs::still(ShardId::ROOT);
    let stores = [parent, left, right].map(|shard| SimShardStorage::new(shard_prefix_path(shard)));
    let roots = |block: &Block, creations: &[_]| {
        stores.each_ref().map(|store| {
            store
                .follow_block_writes(block, creations, &still)
                .expect("followed")
        })
    };
    let [_, left_before, right_before] = roots(&naming, &committed);
    let [whole, left_after, right_after] = roots(&terminal, &[]);

    for store in &stores {
        assert_eq!(
            MemberIndex::load(&store.snapshot(), parent),
            MemberIndex::empty(parent),
            "the terminal leaves no row on any store",
        );
    }
    assert_ne!(left_after, left_before, "the left child drops the rows");
    assert_ne!(
        right_after, right_before,
        "the right child burns the charge"
    );
    assert!(
        SplitChildRoots {
            left: left_after,
            right: right_after,
        }
        .composes_to(whole)
    );

    // A replica syncing the terminal sealed recomputes the same root: the
    // sealed form keeps the manifest its fates ride.
    let synced = SimShardStorage::new(shard_prefix_path(parent));
    synced
        .follow_block_writes(&naming, &committed, &still)
        .expect("followed");
    assert_eq!(
        synced
            .follow_block_writes(&terminal.into_sealed(), &[], &still)
            .expect("followed"),
        whole,
    );
}

/// A split child following its parent's block folds the parent's fee
/// holds over its own half: a hold and its vault's total sit under the
/// vault's owner, so a cut puts each on its vault's side, and the halves
/// recompose the parent's root through an inclusion on one child and a
/// release on the other.
#[test]
fn a_split_child_recomposes_the_parents_fee_holds() {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{block_settling, make_state_writes};
    use hyperscale_storage::{BoundaryStore, FeeTerms, SubstateStore, Substates};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::stub_transaction;
    use hyperscale_types::{
        BlockHeight, ConsensusReceipt, GlobalReceiptHash, PrincipalAddr, SplitChildRoots,
        StateWrites, TimestampRange, TxHash, Verifiable, WeightedTimestamp, shard_prefix_path,
    };

    let parent = ShardId::leaf(2, 2);
    let (left, right) = parent.children();
    // Payers on each child's half of the parent's `10` prefix.
    let payer = |top: u8| {
        let mut body = [0x11; 31];
        body[0] = top;
        PrincipalAddr::new(body)
    };
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO,
        WeightedTimestamp::from_millis(60_000),
    );
    let on_right = payer(0xA1);
    let on_left = payer(0x81);
    let t0 = stub_transaction(on_right, &[on_right.address()], 500, validity);
    let t1 = stub_transaction(on_left, &[on_left.address()], 700, validity);
    let t0_hold = FeeTerms::of(&t0);
    let t1_hold = FeeTerms::of(&t1);

    let carrying = |height: u64, tx: &Transaction, receipts: Vec<StoredReceipt>| {
        let Block::Live {
            header,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } = block_settling(BlockHeight::new(height), receipts)
        else {
            unreachable!("the fixture builds a live block");
        };
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(tx.clone()))])),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest: Arc::new(TickManifest::empty()),
            witness_sources,
        };
        (block, committed_tx_cells(parent, [tx]))
    };
    // The release: T0's burn deletes its hold in the receipt that
    // settles it; a write on each half keeps both subtrees populated.
    let mut release = make_state_writes(0xA0, 1, vec![1; 4]);
    release.cells.insert(t0_hold.hold_key(), None);
    let settling = |writes: StateWrites| {
        StoredReceipt::new(
            TxHash::ZERO,
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes,
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        )
    };
    let first = carrying(
        1,
        &t0,
        vec![settling(make_state_writes(0x80, 1, vec![1; 4]))],
    );
    let second = carrying(2, &t1, vec![settling(release)]);

    let still = FrontierInputs::still(ShardId::ROOT);
    let stores = [parent, left, right].map(|shard| SimShardStorage::new(shard_prefix_path(shard)));
    let mut roots = Vec::new();
    for (block, committed) in [&first, &second] {
        roots = stores
            .iter()
            .map(|store| {
                store
                    .follow_block_writes(block, committed, &still)
                    .expect("each store follows")
            })
            .collect();
    }
    let [parent_store, left_store, right_store] = &stores;
    assert!(
        parent_store.snapshot().cell(t1_hold.hold_key()).is_some()
            && parent_store.snapshot().cell(t0_hold.hold_key()).is_none(),
        "the parent holds T1's fee and has released T0's",
    );
    assert!(left_store.snapshot().cell(t1_hold.hold_key()).is_some());
    assert!(right_store.snapshot().cell(t0_hold.hold_key()).is_none());
    assert!(
        SplitChildRoots {
            left: roots[1],
            right: roots[2],
        }
        .composes_to(roots[0])
    );
}
