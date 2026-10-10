//! Which transactions a shard writes a committed-transaction cell for,
//! checked from outside the derivation.
//!
//! The rule is that a block writes one for every transaction it carries
//! and reads no placement, which is what lets a split child following
//! its parent's block recompose the parent's root. Both halves of that
//! are asserted here rather than beside the derivation, because the
//! second needs a store to follow a block into.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_effects_bridge::{ProtocolHasher, account_address};
use hyperscale_engine::genesis::{
    GenesisPackages, genesis_world_with_pools, pool_address, stake_unit,
};
use hyperscale_engine::legs::{Classified, Member, Runs};
use hyperscale_engine::tick_select::{CommittedSets, MemberFacts, member_lines};
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PROTOCOL_RESOURCE, TickBatchContext, TickEnvironment,
    TickTxInput, genesis_writes,
};
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_storage::{
    Anchored, MemberIndex, MemberInputs, NoFeeHolds, ProvisionalTx, SubstateStore, Substates,
    TickChain, TickOutput, VersionedStore, committed_tx_cells, fold_state_writes, settle_writes,
};
use hyperscale_transactions::{Ceilings, Client, Terms, principal_of};
use hyperscale_types::{
    AbortCharge, AddressClass, Block, BlockHeight, CollectionId, ComponentAddr, ConsensusReceipt,
    DeclaredKey, DeclaredRange, Ed25519PrivateKey, Evidence, FrontierInputs, Joins,
    MAX_INTENT_VALIDITY_RANGE, Mode, NetworkId, PriceTable, PrincipalAddr, ProvisionalHolds,
    Settlement, ShardId, ShardTrie, StakePoolId, StakePoolSeat, StateRoot, StateWrites,
    StoredReceipt, SubstateEntry, SubstateKey, TickLine, TickManifest, Transaction, TxHash,
    Verified, WeightedTimestamp, absorb_committed_cells,
};
use hyperscale_vm_effects::{Composed, Hash32, InstanceMeta, IntentHeader, Value, package_hash};
use hyperscale_vm_fixtures::{peg, peg_package_hash};
use hyperscale_vm_manifest_builder::IntentBuilder;
use hyperscale_vm_stdlib::{account, instantiate, staking_artifact};
use hyperscale_vm_types::{
    Address, IntentHash, LegRole, LegShape, Moves, ValueEdge, encode_amount,
};

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
        terms: Arc::new(Capped::empty()),
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
        terms,
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
        terms,
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
        terms,
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
        terms,
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
            terms,
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
            terms,
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

/// Every cell of the world at one version: the base a tick chain layers
/// its ticks over.
struct MapDb(BTreeMap<SubstateKey, Vec<u8>>);

impl Substates for MapDb {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.0.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        _owner: Address,
        _collection: CollectionId,
        _lo: u128,
        _hi: u128,
        _limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        Vec::new()
    }
}

impl Anchored for MapDb {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }
}

impl SubstateStore for MapDb {
    type Snapshot<'a> = Self;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        Self(self.0.clone())
    }

    fn jmt_height(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }

    fn state_root(&self) -> StateRoot {
        StateRoot::ZERO
    }

    fn get_entries_at_height(
        &self,
        _range: DeclaredRange,
        _block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>> {
        Some(Vec::new())
    }

    fn get_substate_at_height(
        &self,
        _key: SubstateKey,
        _block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>> {
        None
    }
}

impl VersionedStore for MapDb {
    fn retention_floor(&self) -> u64 {
        0
    }

    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
        (height <= self.jmt_height()).then(|| self.snapshot_at(height))
    }

    fn snapshot_at(&self, _height: BlockHeight) -> Self::Snapshot<'_> {
        Self(self.0.clone())
    }

    fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
        None
    }

    fn hold_retention_at(&self, _height: BlockHeight) {}
}

/// What the window's backing holds, and what each redemption hands in:
/// at parity it takes the same amount out.
const BACKING: u128 = 1_000;

/// The clock every block and tick of the window case reads.
const ANCHOR: WeightedTimestamp = WeightedTimestamp::from_millis(1_000);

/// A window's backing that an in-flight redemption took is not taken
/// again until that redemption's verdict.
///
/// A redemption debits the backing by a delta, whose amount no
/// declaration states, and a member a counterpart's verdict can still
/// discard keeps its writes out of every later tick's view. So nothing a
/// later tick reads says what the first redemption took, and a second
/// named beside it would be paid out of the whole backing: here each
/// takes all of it, and the two could never settle onto the one cell.
///
/// Each redemption is a redeemer's on the window's shard, paid for by a
/// sponsor on another, so the shape runs whole on both shards and each
/// awaits the other's certificate. Tick 1 names the first and it
/// completes provisionally. Tick 2's lines are named over the rows tick
/// 1 left, with the second committed, and whatever they name runs over
/// the tick view. Both ticks' receipts then settle onto the base.
#[test]
fn a_till_a_pending_member_took_is_not_taken_again_below_its_verdict() {
    let world = Window::new();
    let mut store = world.sealed();
    let first = world.redeem(world.redeemers[0], BACKING);
    let second = world.redeem(world.redeemers[1], BACKING);
    let backing = world.backing(&first);
    store.0.insert(backing, encode_amount(BACKING).to_vec());
    let provisions = world.provisioned(&store);
    let base = Arc::new(store);
    let chain = TickChain::new(Arc::clone(&base));
    let mut naming = Naming::over(&world, [&**first, &**second]);
    let mut settling = StateWrites::default();

    assert_eq!(naming.name(1, &first), vec![first.hash()]);
    let (ran, took) = world.run(&chain, &provisions, 0, &first);
    assert_eq!(took.movements[&backing].debit, BACKING);
    fold_state_writes(&mut settling, &took);
    chain.append(
        BlockHeight::new(1),
        TickOutput {
            determined: Vec::new(),
            provisional: vec![provisional(&first, &ran)],
        },
        BlockHeight::GENESIS,
    );

    for tx in naming.name(2, &second) {
        assert_eq!(tx, second.hash(), "the first is in flight and named once");
        let (_, took) = world.run(&chain, &provisions, 1, &second);
        fold_state_writes(&mut settling, &took);
    }

    let settled = settle_writes(&settling, &*base);
    assert_eq!(
        settling.movements[&backing].debit, BACKING,
        "the backing is taken once below the first's verdict",
    );
    assert_eq!(settled.cells()[&backing], None, "and settles drained");
}

/// What a completed member a counterpart can still discard leaves its
/// tick: its writes and its abort charge, both provisional, and its
/// declared reservations held.
fn provisional(tx: &Transaction, ran: &ExecutedTx) -> ProvisionalTx {
    ProvisionalTx {
        tx_hash: ran.tx_hash,
        writes: ran.consensus.writes().cloned(),
        reserve: ran
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes)
            .cloned(),
        reserved: tx
            .routing()
            .declared_modes
            .iter()
            .filter_map(|(key, mode)| match (key, mode) {
                (DeclaredKey::Cell(cell), Mode::Reserve { amount }) => Some((*cell, *amount)),
                _ => None,
            })
            .collect(),
    }
}

/// The member rows of the window's shard, and what names lines over
/// them: the facts of every redemption, and the sponsor's shard's
/// bundles committed for each.
struct Naming<'w> {
    world: &'w Window,
    rows: MemberIndex,
    facts: BTreeMap<TxHash, MemberFacts>,
    inputs: CommittedSets,
}

impl<'w> Naming<'w> {
    fn over<'t>(
        world: &'w Window,
        transactions: impl IntoIterator<Item = &'t Transaction>,
    ) -> Self {
        let facts: BTreeMap<TxHash, MemberFacts> = transactions
            .into_iter()
            .map(|tx| {
                let member = world.member(tx);
                assert!(
                    member.abortable(),
                    "the sponsor's shard can still discard the redemption"
                );
                let charge = AbortCharge::of(tx, &PriceTable::GENESIS);
                (
                    tx.hash(),
                    MemberFacts::of_member(&member, tx, &world.trie, charge),
                )
            })
            .collect();
        Self {
            world,
            rows: MemberIndex::empty(world.near),
            inputs: CommittedSets {
                engaged: facts.keys().map(|tx| (world.far, *tx)).collect(),
                ..CommittedSets::default()
            },
            facts,
        }
    }

    /// Commit the block at `height` carrying `carried`, its lines named
    /// over the rows with its own content folded in, and return the
    /// members those lines name to run.
    fn name(&mut self, height: u64, carried: &Transaction) -> Vec<TxHash> {
        let content = |manifest: TickManifest| {
            MemberInputs::from_parts(
                self.world.near,
                BlockHeight::new(height),
                ANCHOR,
                [carried],
                &[],
                &[],
                Arc::new(manifest),
            )
        };
        let mut carrying = self.rows.clone();
        carrying.advance(&content(Capped::empty()));
        let (lines, missing) = member_lines(
            &carrying,
            ANCHOR,
            &|tx| self.facts.get(&tx),
            &self.inputs,
            &|_| Evidence::Readable,
            None,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty(), "every member's facts are held");
        let manifest = content(Capped::new(lines.clone()).expect("a line a member at most"));
        self.rows.advance(&manifest);
        lines
            .into_iter()
            .filter_map(|line| match line {
                TickLine::Member {
                    tx,
                    joins: Joins::Executes,
                    settlement: Settlement::Shared,
                    ..
                } => Some(tx),
                _ => None,
            })
            .collect()
    }
}

/// A redemption window retiring the protocol resource against a seated
/// pool's stake unit under a two-leaf trie, two redeemers on its shard,
/// and a sponsor on the other.
struct Window {
    trie: ShardTrie,
    /// The window's shard, and the redeemers'.
    near: ShardId,
    /// The sponsor's shard.
    far: ShardId,
    seat: StakePoolSeat,
    meta: InstanceMeta,
    address: ComponentAddr,
    /// The redeemers' signing seeds.
    redeemers: [u8; 2],
    /// The sponsor's signing seed.
    sponsor: u8,
    executor: Executor,
    client: Client,
}

impl Window {
    const NETWORK: NetworkId = NetworkId(242);
    const HEADER: IntentHeader = IntentHeader {
        network: Self::NETWORK,
        validity_start_ms: 0,
        validity_end_ms: MAX_INTENT_VALIDITY_RANGE.as_secs() * 1_000,
        discriminator: 0,
    };

    fn key(seed: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
    }

    fn account(seed: u8) -> PrincipalAddr {
        account_address(&Self::key(seed).public_key().0)
    }

    const fn terms() -> Terms {
        Terms {
            max_fee: 1_000_000,
            ceilings: Ceilings::Guessed,
            priority_bp: 0,
            message: Vec::new(),
        }
    }

    fn new() -> Self {
        let trie = ShardTrie::uniform(1);
        let seat = StakePoolSeat {
            id: StakePoolId::new(1),
            operator: Self::account(1),
            founding: Vec::new(),
        };
        let unit = stake_unit(pool_address(
            package_hash(&ProtocolHasher, staking_artifact()),
            &seat,
        ));
        // Stable, reserve, oracle and band, in the order the window's
        // terms name them. Nothing posts a deviation, so it quotes parity.
        let meta = InstanceMeta {
            package: peg_package_hash(&ProtocolHasher),
            config: Capped::new(vec![
                Value::Address(PROTOCOL_RESOURCE.address()),
                Value::Address(unit.address()),
                Value::Address(Self::account(1).address()),
                Value::U128(0),
            ])
            .expect("four terms"),
            salt: Hash32([0x4D; 32]),
        };
        let address = meta.address(&ProtocolHasher);
        let near = trie.shard_for_prefix(address);
        let far = near.sibling().expect("a leaf of two has a sibling");
        let seeds_on = |shard: ShardId| -> Vec<u8> {
            (2..=u8::MAX)
                .filter(|seed| trie.shard_for_prefix(Self::account(*seed)) == shard)
                .collect()
        };
        let near_seeds = seeds_on(near);
        let redeemers = [near_seeds[0], near_seeds[1]];
        let sponsor = seeds_on(far)[0];

        let packages = GenesisPackages::with_fixtures();
        let seats = std::slice::from_ref(&seat);
        let executor = Executor::with_genesis(seats, &packages, ExecutionMode::Serial);
        let client = Client::new(genesis_world_with_pools(seats, &packages), Self::NETWORK);
        Self {
            trie,
            near,
            far,
            seat,
            meta,
            address,
            redeemers,
            sponsor,
            executor,
            client,
        }
    }

    /// Genesis with the window sealed: by a transaction of the first
    /// redeemer's, run where one shard holds everything.
    fn sealed(&self) -> MapDb {
        let funded: Vec<(PrincipalAddr, u128)> = self
            .redeemers
            .iter()
            .chain([&self.sponsor])
            .map(|seed| (Self::account(*seed), 100_000_000))
            .collect();
        let mut store = MapDb(
            genesis_writes(
                &funded,
                std::slice::from_ref(&self.seat),
                &GenesisPackages::with_fixtures(),
            )
            .cells()
            .iter()
            .map(|(key, value)| (*key, value.clone().expect("genesis sets every cell")))
            .collect(),
        );
        let founder = self.redeemers[0];
        let chain = self.client.records();
        let composed = Composed::new(&chain, std::slice::from_ref(&self.meta), &ProtocolHasher);
        let mut root = IntentBuilder::new(
            &composed,
            &ProtocolHasher,
            Self::account(founder),
            Self::HEADER,
        );
        instantiate(&mut root, self.address, ()).expect("a derivable window answers its seal");
        let tree = root
            .build_presenting(vec![self.meta.clone()], Vec::new())
            .expect("the intent declares no hole");
        let seal = Arc::new(Verified::<Transaction>::from_persisted(Transaction::new(
            self.client
                .sign_tree(&tree, &[&Self::key(founder)], Self::terms()),
        )));
        seal.try_derived(self.executor.derivation().as_ref())
            .expect("the seal derives");
        let single = ShardTrie::single();
        let sealed = self
            .executor
            .execute_batch(
                &TickBatchContext {
                    local_shard: ShardId::ROOT,
                    shard_trie: &single,
                    tick_ts: ANCHOR,
                    env: TickEnvironment::unfolded(),
                    holds: &ProvisionalHolds::new(),
                    fee_holds: &NoFeeHolds,
                },
                PriceTable::GENESIS,
                &store,
                std::slice::from_ref(&seal),
            )
            .expect("the engine holds the window's package")
            .remove(0);
        let ConsensusReceipt::Succeeded { writes, .. } = &sealed.consensus else {
            panic!("the seal settles: {:?}", sealed.metadata);
        };
        for (key, change) in settle_writes(writes, &store).cells() {
            match change {
                Some(value) => store.0.insert(*key, value.clone()),
                None => store.0.remove(key),
            };
        }
        absorb_committed_cells([&sealed.consensus], self.executor.derivation().as_ref());
        store
    }

    /// `redeemer` handing `amount` of the protocol resource to the window
    /// and banking what it pays out, the sponsor paying the fee.
    fn redeem(&self, redeemer: u8, amount: u128) -> Arc<Verified<Transaction>> {
        let chain = self.client.records();
        let composed = Composed::new(&chain, std::slice::from_ref(&self.meta), &ProtocolHasher);
        let from = Self::account(redeemer);
        let mut root = IntentBuilder::new(&composed, &ProtocolHasher, from, Self::HEADER);
        let funds = account::withdraw(&mut root, from, *PROTOCOL_RESOURCE, amount)
            .expect("an account withdraws");
        let paid = peg::Peg::at(self.address)
            .redeem(&mut root, funds)
            .expect("a window answers a redemption");
        account::deposit(&mut root, from, paid).expect("an account deposits");
        let mut tree = root.build().expect("the intent declares no hole");
        // The sponsor attests the root first, which makes it the payer.
        let sponsor = Self::key(self.sponsor);
        tree.root.attested_by =
            Capped::new(vec![principal_of(&sponsor), from]).expect("two attesters");
        let tx = Arc::new(Verified::<Transaction>::from_persisted(Transaction::new(
            self.client
                .sign_tree(&tree, &[&sponsor, &Self::key(redeemer)], Self::terms()),
        )));
        tx.try_derived(self.executor.derivation().as_ref())
            .expect("a sponsored redemption derives");
        tx
    }

    /// The backing, at the cell a redemption declares it debits.
    fn backing(&self, redemption: &Transaction) -> SubstateKey {
        redemption
            .routing()
            .declared_modes
            .iter()
            .find_map(|(key, mode)| match (key, mode) {
                (DeclaredKey::Cell(cell), Mode::Delta { moves: Moves::Out })
                    if cell.owner == self.address.address() =>
                {
                    Some(*cell)
                }
                _ => None,
            })
            .expect("a redemption debits the backing by a delta")
    }

    /// The member the window's shard runs of `tx`.
    fn member(&self, tx: &Transaction) -> Member {
        let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &self.trie);
        Member::of(classified, self.near, BTreeSet::from([self.near, self.far]))
    }

    /// What the sponsor's shard provisions: every cell of `store` it
    /// holds.
    fn provisioned(&self, store: &MapDb) -> [Arc<Vec<SubstateEntry>>; 1] {
        [Arc::new(
            store
                .0
                .iter()
                .filter(|(key, _)| self.trie.shard_for_prefix(key.owner) == self.far)
                .map(|(key, value)| {
                    SubstateEntry::new(
                        *key,
                        Some(Bytes::new(value.clone()).expect("a genesis cell fits a leaf")),
                    )
                })
                .collect(),
        )]
    }

    /// Run the window's shard's member of `tx` to completion as the tick
    /// after `below`, over the view `chain` gives it, with the block at
    /// `below` written and nothing settled.
    fn run(
        &self,
        chain: &TickChain<MapDb>,
        provisions: &[Arc<Vec<SubstateEntry>>],
        below: u64,
        tx: &Arc<Verified<Transaction>>,
    ) -> (ExecutedTx, StateWrites) {
        chain.prune_persisted(BlockHeight::new(below), BlockHeight::GENESIS);
        let view = chain.view_at(BlockHeight::new(below));
        let holds = view.holds();
        let ctx = TickBatchContext {
            local_shard: self.near,
            shard_trie: &self.trie,
            tick_ts: ANCHOR,
            env: TickEnvironment::unfolded(),
            holds: &holds,
            fee_holds: &NoFeeHolds,
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: Some(tx),
            provisions,
            clock: ANCHOR,
            runs: Runs::Shape(self.member(tx)),
            arrivals: &[],
        };
        let executed = self
            .executor
            .execute_tick_batch(&ctx, &view.snapshot(), &[input])
            .expect("the engine holds the window's package")
            .remove(0);
        let ConsensusReceipt::Succeeded { writes, .. } = &executed.consensus else {
            panic!("the redemption completes: {:?}", executed.metadata);
        };
        let writes = writes.clone();
        (executed, writes)
    }
}
