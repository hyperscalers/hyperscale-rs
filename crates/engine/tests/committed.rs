//! Which transactions a shard writes a committed-transaction cell for,
//! checked from outside the derivation.
//!
//! The rule is that a block writes one for every transaction it carries
//! and reads no placement, which is what lets a split child following
//! its parent's block recompose the parent's root. Both halves of that
//! are asserted here rather than beside the derivation, because the
//! second needs a store to follow a block into.

use hyperscale_storage::committed_tx_cells;
use hyperscale_types::{AddressClass, ShardId};
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
        expiry_ms: 1_000,
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
    let right_half = StoredReceipt::synced(
        TxHash::ZERO,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: make_state_writes(0xA0, 1, vec![1; 4]),
            beacon_witness_events: Vec::new(),
            events: Vec::new(),
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
        transactions: Arc::new(vec![Arc::new(Verifiable::from(tx))]),
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        witness_sources,
    };

    let parent_root = SimShardStorage::new(shard_prefix_path(parent))
        .follow_block_writes(&block, &committed)
        .expect("the parent commits its block");
    let children = SplitChildRoots {
        left: SimShardStorage::new(shard_prefix_path(left))
            .follow_block_writes(&block, &committed)
            .expect("a child follows"),
        right: SimShardStorage::new(shard_prefix_path(right))
            .follow_block_writes(&block, &committed)
            .expect("a child follows"),
    };
    assert!(children.composes_to(parent_root));
}
