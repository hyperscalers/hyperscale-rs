//! What a declared interval's cap does to the baseline a batch executes
//! over, on one shard with nothing in flight.
//!
//! `materialize_declared` lifts one entry past each declared interval's
//! cap out of the tick snapshot, and a probe at an instance's own order
//! reads this shard's store beneath that map. Every case here runs over
//! a store holding more entries in the interval than the declaration's
//! cap, and asserts what the full store says is true.

use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::account_address;
use hyperscale_engine::genesis::{GenesisPackages, draw_key, genesis_world_with_pools};
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PROTOCOL_RESOURCE, PointReads, TickBatchContext,
    TickEnvironment, genesis_writes,
};
use hyperscale_hbor::{Capped, from_slice};
use hyperscale_storage::test_helpers::block_settling;
use hyperscale_storage::{BoundaryStore, GenesisCommit, NoFeeHolds, SubstateStore, Substates};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_transactions::{Ceilings, Client, Terms};
use hyperscale_types::{
    BlockHeight, ComponentAddr, ConsensusReceipt, Ed25519PrivateKey, EntryKey, Epoch, EpochSeed,
    EpochWindows, FrontierInputs, MAX_INTENT_VALIDITY_RANGE, NetworkId, PriceTable, PrincipalAddr,
    ProtocolHasher, ProvisionalHolds, Randomness, ResourceAddr, SeedRing, SeedSource,
    SettledWrites, ShardId, ShardTrie, StoredReceipt, SubstateKey, TimestampRange, Transaction,
    Verified, WeightedTimestamp, absorb_committed_cells, encode_amount,
};
use hyperscale_vm_effects::{
    Composed, Hash32, InstanceMeta, IntentHeader, IntentTree, SlotId, Value, child_key,
    collection_id, holdings_collection, order_key,
};
use hyperscale_vm_fixtures::book::{self, FILL_CAP};
use hyperscale_vm_fixtures::{book_package_hash, lottery, lottery_package_hash};
use hyperscale_vm_manifest_builder::IntentBuilder;
use hyperscale_vm_sdk::client::VaultField;
use hyperscale_vm_stdlib::{account, instantiate};
use hyperscale_vm_types::{Address, CollectionId};

/// The widest window an intent may stand for.
const OFFER_MS: u64 = MAX_INTENT_VALIDITY_RANGE.as_secs() * 1_000;

const ALICE: u8 = 1;
const BOB: u8 = 2;
const FUNDED: u128 = 10_000;
/// The non-fungible resource Alice's holdings are seeded with.
const NF: ResourceAddr = ResourceAddr::new([0xE7; 31]);

fn key_of(seed: u8) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
}

fn principal(seed: u8) -> PrincipalAddr {
    account_address(&key_of(seed).public_key().0)
}

fn nf_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| Client::genesis(NetworkId(242)));
    &CLIENT
}

const fn terms(max_fee: u128) -> Terms {
    Terms {
        max_fee,
        ceilings: Ceilings::Guessed,
        priority_bp: 0,
        message: Vec::new(),
    }
}

const fn validity() -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::from_millis(0),
        WeightedTimestamp::from_millis(OFFER_MS),
    )
}

fn holdings(who: PrincipalAddr, resource: ResourceAddr) -> CollectionId {
    holdings_collection(&ProtocolHasher, who, resource)
}

/// The ids in `who`'s holdings of `resource`, read from the full store.
fn held_ids(storage: &SimShardStorage, who: PrincipalAddr, resource: ResourceAddr) -> Vec<u128> {
    storage
        .entries_in_range(who.address(), holdings(who, resource), 0, u128::MAX, 16)
        .into_iter()
        .map(|(order, _)| order)
        .collect()
}

/// Genesis over `packages`, with `entries` seeded beside the cells.
fn storage_with(
    packages: &GenesisPackages,
    accounts: &[(PrincipalAddr, u128)],
    entries: Vec<(EntryKey, Option<Vec<u8>>)>,
) -> SimShardStorage {
    storage_seeding(packages, accounts, Vec::new(), entries)
}

/// [`storage_with`], with `cells` seeded beside genesis's own.
fn storage_seeding(
    packages: &GenesisPackages,
    accounts: &[(PrincipalAddr, u128)],
    seeded_cells: Vec<(SubstateKey, Vec<u8>)>,
    entries: Vec<(EntryKey, Option<Vec<u8>>)>,
) -> SimShardStorage {
    let genesis = genesis_writes(accounts, &[], packages);
    let (mut cells, _) = genesis.into_parts();
    cells.extend(
        seeded_cells
            .into_iter()
            .map(|(key, value)| (key, Some(value))),
    );
    let seeded = SettledWrites::from_parts(cells, entries.into_iter().collect());
    let storage = SimShardStorage::default();
    storage.install_genesis(&seeded, &seeded);
    storage
}

/// The store's point reads at its tip, which is the snapshot a tick here
/// executes over: each tick commits before the next one runs.
struct TipPoints(SimShardStorage);

impl std::fmt::Debug for TipPoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TipPoints")
    }
}

impl PointReads for TipPoints {
    fn entry(&self, owner: Address, collection: CollectionId, order: u128) -> Option<Vec<u8>> {
        self.0.entry(owner, collection, order)
    }
}

/// Execute one transaction as one tick's batch over the store's current
/// snapshot under `env`, commit its receipts, and return them.
fn run_tick(
    executor: &Executor,
    storage: &SimShardStorage,
    height: u64,
    env: TickEnvironment,
    tx: Transaction,
) -> Vec<ExecutedTx> {
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env,
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
        points: Some(Arc::new(TipPoints(storage.clone()))),
    };
    tx.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let verified = Arc::new(Verified::<Transaction>::from_persisted(tx));
    let executed = executor
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &storage.snapshot(),
            std::slice::from_ref(&verified),
        )
        .expect("the harness engine holds every package it runs");

    let mut receipts: Vec<StoredReceipt> = Vec::new();
    for tx in &executed {
        let mut tx = tx.clone();
        if let Some(fee) = tx.refusal_receipt.take() {
            receipts.push(StoredReceipt::new(tx.tx_hash, Arc::new(fee)));
        }
        receipts.push(StoredReceipt::from(tx));
    }
    storage
        .follow_block_writes(
            &block_settling(BlockHeight::new(height), receipts),
            &[],
            &FrontierInputs::still(ShardId::ROOT),
        )
        .expect("committed receipts apply");
    executed
}

/// `from.withdraw-nf(NF, ids) -> to.deposit-nf(..)`, signed by `from`.
fn signed_nf_transfer(from: u8, to: u8, ids: &[u64]) -> Transaction {
    let chain = nf_client().records();
    let mut b = nf_client().builder(&chain, principal(from));
    let funds = account::withdraw_nf(&mut b, principal(from), NF, ids).expect("withdraw-nf types");
    account::deposit_nf(&mut b, principal(to), funds).expect("deposit-nf types");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(nf_client().sign(graph, &key_of(from), validity(), terms(1_000)))
}

/// Genesis funding Alice and Bob, each holding the [`NF`] ids named.
fn holding_nf(alice: &[u128], bob: &[u128]) -> SimShardStorage {
    let held = |who: PrincipalAddr, ids: &[u128]| {
        ids.iter()
            .map(|id| {
                (
                    EntryKey {
                        owner: who.address(),
                        collection: holdings(who, NF),
                        order: *id,
                    },
                    Some(vec![1]),
                )
            })
            .collect::<Vec<_>>()
    };
    let mut entries = held(principal(ALICE), alice);
    entries.extend(held(principal(BOB), bob));
    let storage = storage_with(
        &GenesisPackages::protocol(),
        &[(principal(ALICE), FUNDED), (principal(BOB), FUNDED)],
        entries,
    );
    assert_eq!(held_ids(&storage, principal(ALICE), NF), alice);
    assert_eq!(held_ids(&storage, principal(BOB), NF), bob);
    storage
}

/// Alice's holdings of [`NF`] seeded with instances 1 and 2.
fn alice_holding_two() -> SimShardStorage {
    holding_nf(&[1, 2], &[])
}

/// Alice withdraws `id` of the two she holds and deposits it with Bob.
fn withdraw_one(id: u64) -> (SimShardStorage, ExecutedTx) {
    let executor = Executor::new(ExecutionMode::Serial);
    let storage = alice_holding_two();
    let mut executed = run_tick(
        &executor,
        &storage,
        1,
        TickEnvironment::unfolded(),
        signed_nf_transfer(ALICE, BOB, &[id]),
    );
    (storage, executed.remove(0))
}

/// The lowest id rides inside the cap's first entry, so it settles.
#[test]
fn a_withdrawal_of_the_lowest_id_takes_it() {
    let (storage, executed) = withdraw_one(1);
    assert!(
        matches!(&executed.consensus, ConsensusReceipt::Succeeded { .. }),
        "Alice holds id 1, so withdrawing it settles: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![2]);
    assert_eq!(held_ids(&storage, principal(BOB), NF), vec![1]);
}

/// A holder withdraws an instance that is not the lowest id it holds.
///
/// `withdraw-nf` declares the whole holdings interval at a cap of the
/// count of ids named, and the take asks for each id at its own key so
/// that a holder past the cap can move its later ids. Alice holds 1 and
/// 2 and names 2: the declaration is `[0, MAX]` at cap 1, and id 2 is
/// held.
#[test]
fn a_withdrawal_of_a_later_id_takes_it() {
    let (storage, executed) = withdraw_one(2);
    assert!(
        matches!(&executed.consensus, ConsensusReceipt::Succeeded { .. }),
        "Alice holds id 2, so withdrawing it settles: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![1]);
    assert_eq!(held_ids(&storage, principal(BOB), NF), vec![2]);
}

/// A filing over an id its holder already holds past the cap is refused.
///
/// `deposit-nf` declares Bob's holdings at a cap of one, so the baseline
/// lifts his two lowest ids and not the third. The filing probes the id
/// at its own key, which reads this shard's store beneath the lift and
/// finds it held: the instance would otherwise exist twice.
#[test]
fn filing_an_id_held_past_the_cap_is_refused() {
    let executor = Executor::new(ExecutionMode::Serial);
    let storage = holding_nf(&[3], &[1, 2, 3]);
    let executed = run_tick(
        &executor,
        &storage,
        1,
        TickEnvironment::unfolded(),
        signed_nf_transfer(ALICE, BOB, &[3]),
    )
    .remove(0);
    assert!(
        matches!(&executed.consensus, ConsensusReceipt::Failed),
        "Bob already holds id 3, so filing it again is refused: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
    assert!(
        format!("{:?}", executed.metadata).contains("HeldTwice"),
        "refused as a second copy of the instance: {:?}",
        executed.metadata
    );
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![3]);
    assert_eq!(held_ids(&storage, principal(BOB), NF), vec![1, 2, 3]);
}

/// The network the lottery envelopes are signed for.
const LOTTERY_NETWORK: NetworkId = NetworkId(243);

const HEADER: IntentHeader = IntentHeader {
    network: LOTTERY_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: OFFER_MS,
    discriminator: 0,
};

/// Who instantiates, closes and settles the round.
const SETTLER: u8 = 0x5E;

/// The packages the lottery cases run on: the protocol's and the
/// fixtures beside them.
fn lottery_packages() -> GenesisPackages {
    GenesisPackages::with_fixtures()
}

fn lottery_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        Client::new(
            genesis_world_with_pools(&[], &lottery_packages()),
            LOTTERY_NETWORK,
        )
    });
    &CLIENT
}

fn lottery_meta() -> InstanceMeta {
    InstanceMeta {
        package: lottery_package_hash(&ProtocolHasher),
        config: Capped::empty(),
        salt: Hash32([0x4C; 32]),
    }
}

fn lottery_addr() -> ComponentAddr {
    lottery_meta().address(&ProtocolHasher)
}

fn tickets() -> CollectionId {
    collection_id(&ProtocolHasher, lottery_addr(), lottery::TICKETS, &[])
}

fn ticket_order(who: PrincipalAddr) -> u128 {
    order_key(
        &ProtocolHasher,
        lottery_addr(),
        lottery::TICKETS,
        &[Value::Address(who.address()).canonical_bytes()],
    )
}

/// `build` over the lottery, signed by the settler.
fn signed_lottery(build: impl FnOnce(IntentBuilder<'_>) -> IntentTree) -> Transaction {
    let key = key_of(SETTLER);
    let chain = lottery_client().records();
    let composed = Composed::new(&chain, &[lottery_meta()], &ProtocolHasher);
    let root = IntentBuilder::new(&composed, &ProtocolHasher, principal(SETTLER), HEADER);
    let tree = build(root);
    Transaction::new(lottery_client().sign_tree(&tree, &[&key], terms(1_000_000)))
}

/// The environment a round sealed at epoch zero opens under: the tick's
/// clock falls in epoch 4 of a 250 ms grid, whose window holds the
/// reveal-folded seeds of epochs 1 to 3, the seal's maturity among them.
fn sealed_env() -> TickEnvironment {
    let windows = EpochWindows::new(0, 250);
    let mut seeds = SeedRing::default();
    for epoch in 1..=3 {
        seeds.record(
            Epoch::new(epoch),
            EpochSeed {
                randomness: Randomness::new([0x5E; 32]),
                source: SeedSource::Reveals,
            },
            windows,
        );
    }
    TickEnvironment { seeds, windows }
}

/// A closed round holding one ticket per seed in `entrants`, every
/// ticket seeded at genesis where its entrant's `enter` would file it.
fn closed_round(executor: &Executor, entrants: &[u8]) -> SimShardStorage {
    let entries = entrants
        .iter()
        .map(|seed| {
            let who = principal(*seed);
            (
                EntryKey {
                    owner: lottery_addr().into(),
                    collection: tickets(),
                    order: ticket_order(who),
                },
                Some(who.address().to_bytes().to_vec()),
            )
        })
        .collect();
    let storage = storage_with(
        &lottery_packages(),
        &[(principal(SETTLER), 1_000_000)],
        entries,
    );

    let seal = signed_lottery(|mut root| {
        instantiate(&mut root, lottery_addr(), ()).expect("a derivable round answers its seal");
        root.build_presenting(vec![lottery_meta()], Vec::new())
            .expect("the intent declares no hole")
    });
    let executed = run_tick(executor, &storage, 1, TickEnvironment::unfolded(), seal);
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the instantiation settles: {:?} {:?}",
        executed[0].consensus,
        executed[0].metadata
    );
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());

    let close = signed_lottery(|mut root| {
        lottery::Lottery::at(lottery_addr())
            .close(&mut root)
            .expect("a lottery answers a close");
        root.build().expect("the intent declares no hole")
    });
    let executed = run_tick(executor, &storage, 2, TickEnvironment::unfolded(), close);
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the close settles: {:?} {:?}",
        executed[0].consensus,
        executed[0].metadata
    );
    let held = storage.entries_in_range(lottery_addr().into(), tickets(), 0, u128::MAX, 16);
    assert_eq!(held.len(), entrants.len(), "every ticket is in the store");
    storage
}

/// Settle the round at `cap` and return the receipt.
fn settle_at(executor: &Executor, storage: &SimShardStorage, cap: u64) -> ExecutedTx {
    let settle = signed_lottery(|mut root| {
        lottery::Lottery::at(lottery_addr())
            .settle(&mut root, cap)
            .expect("a lottery answers a settlement");
        root.build().expect("the intent declares no hole")
    });
    run_tick(executor, storage, 3, sealed_env(), settle).remove(0)
}

/// The outcome a receipt wrote, if any.
fn outcome_of(executed: &ExecutedTx) -> Option<lottery::Outcome> {
    let bytes = executed
        .consensus
        .writes()?
        .cells
        .get(&draw_key(lottery_addr()))
        .cloned()
        .flatten()?;
    Some(from_slice(&bytes).expect("the lottery writes its own outcome type"))
}

/// Three entrants, three tickets in the store.
const ENTRANTS: [u8; 3] = [0x31, 0x32, 0x33];

/// A page the round's own size covers it, and the round settles.
#[test]
fn a_page_the_rounds_size_settles_it() {
    let executor = Executor::with_genesis(&[], &lottery_packages(), ExecutionMode::Serial);
    let storage = closed_round(&executor, &ENTRANTS);
    let executed = settle_at(&executor, &storage, 3);
    let outcome = outcome_of(&executed).unwrap_or_else(|| {
        panic!(
            "a covering page settles: {:?} {:?}",
            executed.consensus, executed.metadata
        )
    });
    assert!(outcome.winner.is_some(), "an entered round names a winner");
}

/// A page shorter than the round does not cover it, and the round
/// declines `RoundTruncated` rather than drawing over the first `cap`
/// tickets.
///
/// Three tickets are in the store and the settlement buys two. The
/// baseline lifts three, so the kernel's page reads the third as the
/// successor past its cap.
#[test]
fn a_page_shorter_than_the_round_declines_it() {
    let executor = Executor::with_genesis(&[], &lottery_packages(), ExecutionMode::Serial);
    let storage = closed_round(&executor, &ENTRANTS);
    let executed = settle_at(&executor, &storage, 2);

    // Which tickets a two-entry page holds, read from the full store:
    // the two lowest orders. The third is the one a truncated draw
    // silently excludes.
    let mut orders: Vec<(u128, u8)> = ENTRANTS
        .iter()
        .map(|seed| (ticket_order(principal(*seed)), *seed))
        .collect();
    orders.sort_unstable();
    let excluded = principal(orders[2].1);

    assert_eq!(
        outcome_of(&executed),
        None,
        "a truncated round must not settle; {excluded:?} holds a ticket past the page: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
    assert!(
        matches!(&executed.consensus, ConsensusReceipt::Failed),
        "the settlement declines RoundTruncated: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
}

/// What the book sells; it is paid in the protocol resource.
const BOOK_BASE_RESOURCE: ResourceAddr = ResourceAddr::new([0xB5; 31]);

/// Asks resting on the book: two past what one fill's page declares.
const RESTING: u64 = FILL_CAP as u64 + 2;

/// One quote subunit per tick, at the scale a book's stored tick holds.
const ONE_QUOTE_PER_TICK: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

fn book_meta() -> InstanceMeta {
    let mut tick = [0u8; 32];
    tick[..16].copy_from_slice(&ONE_QUOTE_PER_TICK.to_le_bytes());
    InstanceMeta {
        package: book_package_hash(&ProtocolHasher),
        config: Capped::new(vec![
            Value::Address(BOOK_BASE_RESOURCE.address()),
            Value::Address(PROTOCOL_RESOURCE.address()),
            Value::U256(tick),
        ])
        .unwrap(),
        salt: Hash32([0xB0; 32]),
    }
}

fn book_addr() -> ComponentAddr {
    book_meta().address(&ProtocolHasher)
}

/// The book's ladder, read from the full store, as tick counts.
fn standing_ticks(storage: &SimShardStorage) -> Vec<u128> {
    storage
        .entries_in_range(
            book_addr().into(),
            collection_id(&ProtocolHasher, book_addr(), book::ASKS, &[]),
            0,
            u128::MAX,
            usize::try_from(RESTING).unwrap() + 1,
        )
        .into_iter()
        .map(|(order, _)| order >> 64)
        .collect()
}

/// `build` over the book, signed by the settler, with a compute ceiling
/// a whole capped walk fits under.
fn signed_book(build: impl FnOnce(IntentBuilder<'_>) -> IntentTree) -> Transaction {
    let key = key_of(SETTLER);
    let chain = lottery_client().records();
    let composed = Composed::new(&chain, &[book_meta()], &ProtocolHasher);
    let root = IntentBuilder::new(&composed, &ProtocolHasher, principal(SETTLER), HEADER);
    let tree = build(root);
    let ceilings = Ceilings::Measured(vec![2_000_000; tree.node_count()]);
    Transaction::new(lottery_client().sign_tree(
        &tree,
        &[&key],
        Terms {
            max_fee: 100_000_000,
            ceilings,
            priority_bp: 0,
            message: Vec::new(),
        },
    ))
}

/// A walk that removes every ask its page shows stops at the page: the
/// ask past the cap was the successor its lift read, never an entry the
/// page holds, so the walk never reaches for a sixty-fifth write.
///
/// The ladder rests one ask of one base unit at each tick from one, two
/// more of them than the walk's cap of sixty-four, and the budget would
/// buy every one.
#[test]
fn a_removal_from_a_full_page_counts_within_its_first_lift() {
    let executor = Executor::with_genesis(&[], &lottery_packages(), ExecutionMode::Serial);
    let owner = Address::from(book_addr());
    let asks = (1..=RESTING)
        .map(|ticks| {
            (
                EntryKey {
                    owner,
                    collection: collection_id(&ProtocolHasher, book_addr(), book::ASKS, &[]),
                    order: u128::from(ticks) << 64,
                },
                Some(1u128.to_le_bytes().to_vec()),
            )
        })
        .collect();
    let escrow = child_key(
        &ProtocolHasher,
        owner,
        SlotId(<book::Base as VaultField>::SLOT),
        &[Value::Address(BOOK_BASE_RESOURCE.address()).canonical_bytes()],
    );
    let storage = storage_seeding(
        &lottery_packages(),
        &[(principal(SETTLER), 1_000_000_000_000)],
        vec![(escrow, encode_amount(u128::from(RESTING)).to_vec())],
        asks,
    );

    let seal = signed_book(|mut root| {
        instantiate(&mut root, book_addr(), ()).expect("a derivable book answers its seal");
        root.build_presenting(vec![book_meta()], Vec::new())
            .expect("the intent declares no hole")
    });
    let executed = run_tick(&executor, &storage, 1, TickEnvironment::unfolded(), seal);
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the instantiation settles: {:?} {:?}",
        executed[0].consensus,
        executed[0].metadata
    );
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());

    let fill = signed_book(|mut root| {
        let payment = account::withdraw(&mut root, principal(SETTLER), *PROTOCOL_RESOURCE, 10_000)
            .expect("withdraw types");
        let [bought, change] = book::Book::at(book_addr())
            .fill_asks(&mut root, 1, u64::MAX, payment)
            .expect("a book answers a fill");
        account::deposit(&mut root, principal(SETTLER), bought).expect("deposit types");
        account::deposit(&mut root, principal(SETTLER), change).expect("deposit types");
        root.build().expect("every output is consumed")
    });
    let executed = run_tick(&executor, &storage, 2, TickEnvironment::unfolded(), fill).remove(0);
    assert!(
        matches!(&executed.consensus, ConsensusReceipt::Succeeded { .. }),
        "a walk inside its first lift writes no entry past its cap: {:?} {:?}",
        executed.consensus,
        executed.metadata
    );
    assert_eq!(
        standing_ticks(&storage),
        vec![u128::from(FILL_CAP) + 1, u128::from(FILL_CAP) + 2],
        "the two asks past the page still stand"
    );
}
