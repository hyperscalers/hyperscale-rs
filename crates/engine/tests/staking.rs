//! The beacon's control plane on the engine: a delegation to a seated
//! stake pool arrives in the executing shard's `beacon_witness_events`.
//!
//! Every case here runs against a world with a stake pool seated in it,
//! which is what makes the delegation's events beacon facts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::genesis::genesis_world_with_pools;
use hyperscale_effects_bridge::records::committed_instance;
use hyperscale_effects_bridge::vm_statics::config_key;
use hyperscale_effects_bridge::{ProtocolHasher, account_address};
use hyperscale_engine::genesis::{
    GenesisPackages, OWNER_BADGE_ID, pool_address, pool_meta, pool_owner_badge, stake_unit,
    staking_artifact,
};
use hyperscale_engine::legs::{Classified, Member, Runs, never_answer};
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PROTOCOL_RESOURCE, TickBatchContext, TickEnvironment,
    TickTxInput, genesis_writes,
};
use hyperscale_hbor::Bytes;
use hyperscale_storage::{Substates, entry_leaf_rows};
use hyperscale_transactions::{Ceilings, Client, Terms};
use hyperscale_types::{
    BeaconWitnessEvent, ComponentAddr, ConsensusReceipt, Ed25519PrivateKey, EntryKey,
    EscrowedValue, MAX_INTENT_VALIDITY_RANGE, NetworkId, PriceTable, PrincipalAddr,
    ProvisionalHolds, SettledEntries, ShardId, ShardTrie, Stake, StakePoolId, StakePoolSeat,
    SubstateEntry, SubstateKey, TimestampRange, Transaction, Verified, WeightedTimestamp,
    absorb_committed_cells,
};
use hyperscale_vm_effects::{
    Answered, ChainRecords, Composed, CrossingCell, CrossingEdge, IntentHeader, Kind,
    holdings_collection, instance_data_key, package_hash, resource_record_key,
};
use hyperscale_vm_manifest_builder::{IntentBuilder, TypedError};
use hyperscale_vm_stdlib::{account, instantiate, staking};
use hyperscale_vm_types::{Address, CallTarget, CollectionId};

/// The network every envelope in these tests is signed for.
const NETWORK: NetworkId = NetworkId(242);

/// The widest window an intent may stand for, which these fixtures use
/// wherever they mean "does not expire during the test".
const OFFER_MS: u64 = MAX_INTENT_VALIDITY_RANGE.as_secs() * 1_000;

/// The terms every intent in these tests is sealed under. The window is
/// the widest an intent may name, so nothing here narrows a transaction.
const HEADER: IntentHeader = IntentHeader {
    network: NETWORK,
    validity_start_ms: 0,
    validity_end_ms: OFFER_MS,
    discriminator: 0,
};

/// The identifier the beacon folds the seated pool under.
const POOL_ID: u32 = 7;
/// The delegator's signing seed.
const DELEGATOR: u8 = 7;
/// The signing seed of the principal the pool's operator surface admits.
const OPERATOR: u8 = 8;
/// The signing seed of a funded account that operates nothing.
const OUTSIDER: u8 = 9;

/// A snapshot over the flattened genesis updates.
struct MapDb {
    cells: BTreeMap<SubstateKey, Vec<u8>>,
    entries: BTreeMap<EntryKey, Vec<u8>>,
}

impl MapDb {
    fn genesis(accounts: &[(PrincipalAddr, u128)], pools: &[StakePoolSeat]) -> Self {
        let (cells, entries) =
            genesis_writes(accounts, pools, &GenesisPackages::protocol()).into_parts();
        Self {
            cells: cells
                .into_iter()
                .map(|(key, change)| (key, change.expect("genesis writes are Set-only")))
                .collect(),
            entries: entries
                .into_iter()
                .map(|(key, change)| (key, change.expect("genesis writes are Set-only")))
                .collect(),
        }
    }
}

impl Substates for MapDb {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if lo > hi {
            return Vec::new();
        }
        let lo_key = EntryKey {
            owner,
            collection,
            order: lo,
        };
        let hi_key = EntryKey {
            owner,
            collection,
            order: hi,
        };
        self.entries
            .range(lo_key..=hi_key)
            .take(limit)
            .map(|(key, value)| (key.order, value.clone()))
            .collect()
    }
}

fn key_of(seed: u8) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
}

fn account_of(seed: u8) -> PrincipalAddr {
    account_address(&key_of(seed).public_key().0)
}

fn delegator() -> PrincipalAddr {
    account_of(DELEGATOR)
}

/// A pool seat; genesis deposits the pool's owner badge into the named
/// account, and presenting that badge is what operates the pool.
fn seat(id: u32) -> StakePoolSeat {
    StakePoolSeat {
        id: StakePoolId::new(id),
        operator: account_of(OPERATOR),
        founding: Vec::new(),
    }
}

/// Where genesis seats the pool with this identifier — derived from the
/// record, so a test names it the way genesis places it.
fn pool_at(id: u32) -> ComponentAddr {
    pool_address(package_hash(&ProtocolHasher, staking_artifact()), &seat(id))
}

/// The client this binary builds through.
///
/// Its world seats every pool the file names, which is not the same world
/// any one executor installs: what a builder must resolve is the target it
/// is writing, and what an executor recognises is the network's own
/// decision.
fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        Client::new(
            genesis_world_with_pools(&[seat(POOL_ID), seat(99)], &GenesisPackages::protocol()),
            NetworkId(242),
        )
    });
    &CLIENT
}

/// The signing terms every transaction here shares: a window nothing
/// falls outside, and no message.
const fn terms(max_fee: u128) -> Terms {
    Terms {
        max_fee,
        ceilings: Ceilings::Guessed,
        priority_bp: 0,
        message: Vec::new(),
    }
}

/// The window every envelope here is signed for: the widest an intent
/// may name, so nothing narrows a transaction.
const fn validity() -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::from_millis(0),
        WeightedTimestamp::from_millis(OFFER_MS),
    )
}

/// `delegator.withdraw(*PROTOCOL_RESOURCE) -> pool.stake -> delegator.deposit(units)`.
fn signed_stake(pool: ComponentAddr, amount: u128) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[DELEGATOR; 32]).unwrap();
    let from = account_address(&key.public_key().0);
    let chain = client().records();
    let mut b = client().builder(&chain, from);
    let funds =
        account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount).expect("an account withdraws");
    let units = staking::Staking::at(pool)
        .stake(&mut b, funds)
        .expect("a pool takes a delegation");
    account::deposit(&mut b, from, units).expect("an account banks its position");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, validity(), terms(1_000)))
}

/// The same delegation, typed against a record the base chain does not
/// hold: a composer needs the record to type the call locally, and the
/// envelope carries nothing, because the pool's seal has committed and
/// the chain answers for the target itself.
fn signed_stake_composed(seat: &StakePoolSeat, amount: u128) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[DELEGATOR; 32]).unwrap();
    let from = account_address(&key.public_key().0);
    let meta = pool_meta(package_hash(&ProtocolHasher, staking_artifact()), seat);
    let pool = meta.address(&ProtocolHasher);
    let chain = client().records();
    let composed = Composed::new(&chain, std::slice::from_ref(&meta), &ProtocolHasher);
    let mut b = IntentBuilder::new(&composed, &ProtocolHasher, from, HEADER);
    let funds =
        account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount).expect("an account withdraws");
    let units = staking::Staking::at(pool)
        .stake(&mut b, funds)
        .expect("a pool takes a delegation");
    account::deposit(&mut b, from, units).expect("an account banks its position");
    let tree = b.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, &[&key], terms(1_000)))
}

fn execute(executor: &Executor, tx: Transaction) -> Vec<ExecutedTx> {
    let store = MapDb::genesis(
        &[
            (delegator(), 10_000),
            (account_of(OPERATOR), 10_000),
            (account_of(OUTSIDER), 10_000),
        ],
        &[seat(POOL_ID), seat(99)],
    );
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
    };
    tx.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let verified = Arc::new(Verified::<Transaction>::from_persisted(tx));
    executor
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &store,
            std::slice::from_ref(&verified),
        )
        .expect("the harness engine holds every package it runs")
}

fn witnesses(executed: &ExecutedTx) -> Vec<BeaconWitnessEvent> {
    match &executed.consensus {
        ConsensusReceipt::Succeeded {
            beacon_witness_events,
            ..
        } => beacon_witness_events.clone().into_inner(),
        other @ ConsensusReceipt::Failed => {
            panic!("the delegation must succeed; receipt = {other:?}")
        }
    }
}

/// The whole channel in one assertion: a delegation to a seated pool is a
/// beacon fact by the time it leaves the engine, with the pool named by
/// the instance that emitted it and the amount carried across as quanta.
/// A record the cache answers for is the record the cell that sealed it
/// holds, whether genesis wrote the cell or a transaction did.
///
/// The claim a state-backed instance store rests on. A node's registry is
/// a second copy of a projection of its own state: the `CONFIG` leaf is
/// where a component's record lives, and the cache is grown from the
/// commits that write it. If a reader consulting the store for a prefix
/// this shard owns answered anything but what the cache answers, two
/// nodes would derive one envelope two ways — a fork rather than a
/// stall, which is why it is pinned here rather than assumed.
///
/// The principal blueprint is the one record with no cell, and needs
/// none: a principal's address derives from a key, so it is resolved by
/// its address class and never looked up.
#[test]
fn a_record_the_cache_answers_for_is_the_record_its_cell_holds() {
    let genesis_seated = seat(POOL_ID);
    let sealed_here = seat(55);
    let executor = seated(std::slice::from_ref(&genesis_seated), ExecutionMode::Serial);
    let mut store = MapDb::genesis(
        &[(account_of(OPERATOR), 10_000)],
        std::slice::from_ref(&genesis_seated),
    );
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
    };
    // The second pool becomes actual the way the chain makes one actual:
    // a transaction seals it, and the commit path offers its cells to
    // the cache.
    let raw = signed_instantiate(OPERATOR, &sealed_here);
    raw.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let executed = executor
        .execute_batch(&ctx, PriceTable::GENESIS, &store, std::slice::from_ref(&tx))
        .expect("the harness engine holds every package it runs");
    absorb(&mut store, &executed[0], &executor);

    let staking = package_hash(&ProtocolHasher, staking_artifact());
    let chain = executor.records();
    for seat in [&genesis_seated, &sealed_here] {
        let pool = pool_address(staking, seat);
        let answered = chain
            .instance(pool.into())
            .expect("the cache answers for a sealed pool");

        let key = config_key(pool);
        let cell = store
            .cell(key)
            .expect("a sealed component's record lives in its configuration leaf");
        let from_state = committed_instance(pool.address(), key.local.0, &cell)
            .expect("the leaf holds the record its own address derives");

        assert_eq!(
            *answered, from_state,
            "the cache and the cell disagree about pool {:?}",
            seat.id
        );
    }

    // And the one record with no cell behind it resolves all the same.
    assert!(
        chain
            .instance(CallTarget::Principal(account_of(OPERATOR)))
            .is_some(),
        "a principal resolves by its address class, with no leaf to read"
    );
}

/// A member holding no record for the target executes the call the same
/// way as one that holds it.
///
/// What lets execution stop consulting anything a node accumulated. What
/// a node holds for a component is its own: a record it never committed
/// and never fetched is absent, and a bounded cache lets go of records
/// on a schedule no two members share. If a target that would not
/// resolve became a failed receipt, one member would hand up a receipt
/// root of its own for a transaction every other member settled.
///
/// The two engines here are forked from one world and then differ in
/// exactly one thing: the seal commits on one of them. The other holds
/// no record for the pool at all and has to read the leaf out of the
/// state it is executing against.
#[test]
fn a_member_holding_no_record_executes_the_call_alike() {
    let unseated = seat(56);
    let holder = seated(std::slice::from_ref(&seat(POOL_ID)), ExecutionMode::Serial);
    // Forked before the seal, so what the holder goes on to absorb is
    // the holder's alone — the way two processes would hold it.
    let reader = holder.peer(ExecutionMode::Serial);
    let mut store = MapDb::genesis(
        &[(account_of(OPERATOR), 10_000), (delegator(), 10_000)],
        std::slice::from_ref(&seat(POOL_ID)),
    );
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
    };

    let raw = signed_instantiate(OPERATOR, &unseated);
    raw.try_derived(holder.derivation().as_ref())
        .expect("a fixture transaction derives");
    let seal = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let sealed = holder
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &store,
            std::slice::from_ref(&seal),
        )
        .expect("the harness engine holds every package it runs");
    absorb(&mut store, &sealed[0], &holder);

    let pool = pool_address(package_hash(&ProtocolHasher, staking_artifact()), &unseated);
    assert!(
        holder.instance_known(pool.address()),
        "the sealing member absorbed the record its own commit wrote"
    );
    assert!(
        !reader.instance_known(pool.address()),
        "and the other holds none of it"
    );

    // Derived once, by the member that can resolve the pool from what it
    // holds — the routed facts a block carries into execution are
    // settled before it, and never re-asked.
    let raw = signed_stake_composed(&unseated, 500);
    raw.try_derived(holder.derivation().as_ref())
        .expect("a fixture transaction derives");
    let call = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let by_holder = holder
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &store,
            std::slice::from_ref(&call),
        )
        .expect("the harness engine holds every package it runs");
    let by_reader = reader
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &store,
            std::slice::from_ref(&call),
        )
        .expect("the harness engine holds every package it runs");

    // Stated before the comparison, so a pair of matching refusals
    // cannot pass for agreement.
    assert!(
        matches!(by_reader[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the member that read the leaf settled the call; receipt = {:?}",
        by_reader[0].consensus
    );
    assert_eq!(
        by_holder[0].consensus, by_reader[0].consensus,
        "a member that holds the record and one that reads it produce one receipt"
    );
}

/// An executor over a network seating `pools`, on the protocol's own
/// packages — the staking surface reaches no fixture.
fn seated(pools: &[StakePoolSeat], mode: ExecutionMode) -> Executor {
    Executor::with_genesis(pools, &GenesisPackages::protocol(), mode)
}

/// Apply what a settled transaction wrote, so the next one reads it as
/// committed state.
fn absorb(store: &mut MapDb, executed: &ExecutedTx, executor: &Executor) {
    let ConsensusReceipt::Succeeded { writes, .. } = &executed.consensus else {
        panic!("the transaction must settle: {:?}", executed.consensus);
    };
    // What the commit path does with a block's receipts: every committed
    // cell is offered to the caches, so a seal that settled is a
    // component the next transaction can name with nothing presented.
    absorb_committed_cells([&executed.consensus], executor.derivation().as_ref());
    for (key, change) in &writes.cells {
        match change {
            Some(value) => store.cells.insert(*key, value.clone()),
            None => store.cells.remove(key),
        };
    }
    for (key, change) in &writes.entries {
        match change {
            Some(value) => store.entries.insert(*key, value.clone()),
            None => store.entries.remove(key),
        };
    }
}

/// One envelope that brings an unseated pool up: it presents the pool's
/// instance record, seals it as the configured founder, and files the
/// owner badge the seal minted in that founder's account.
///
/// One transaction, because bringing up is one invocation: the seal, the
/// record of each mark the pool issues, and the one issuance a body may
/// hold all sit in the node that makes the component actual.
fn signed_instantiate(seed: u8, seat: &StakePoolSeat) -> Transaction {
    let key = key_of(seed);
    let from = account_address(&key.public_key().0);
    let chain = client().records();
    let meta = pool_meta(package_hash(&ProtocolHasher, staking_artifact()), seat);
    // The composer types the call against a record the chain does not
    // answer for yet: the seal is what makes it answer.
    let composed = Composed::new(&chain, std::slice::from_ref(&meta), &ProtocolHasher);
    let pool = meta.address(&ProtocolHasher);
    let mut root = IntentBuilder::new(&composed, &ProtocolHasher, from, HEADER);
    // The composition every bring-up writes: the seal, and the supply it
    // yields filed where the founder keeps it. Which method seals and
    // which of those nodes exist are the package's own declaration to
    // say.
    instantiate(&mut root, pool, ()).expect("a derivable pool answers its seal");
    let tree = root
        .build_presenting(vec![meta], Vec::new())
        .expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, &[&key], terms(1_000)))
}

/// A pool nobody seated brings itself up, and the cells it ends holding
/// are the cells genesis writes for a seated one, byte for byte — two
/// writers of one object, held to each other.
#[test]
fn an_instantiated_pool_holds_the_cells_genesis_writes_for_a_seated_one() {
    let unseated = seat(55);
    let executor = seated(&[], ExecutionMode::Serial);
    let mut store = MapDb::genesis(&[(account_of(OPERATOR), 10_000)], &[]);
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
    };
    let raw = signed_instantiate(OPERATOR, &unseated);
    raw.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let executed = executor
        .execute_batch(&ctx, PriceTable::GENESIS, &store, std::slice::from_ref(&tx))
        .expect("the harness engine holds every package it runs");
    absorb(&mut store, &executed[0], &executor);

    let (genesis_cells, genesis_entries) = genesis_writes(
        &[],
        std::slice::from_ref(&unseated),
        &GenesisPackages::protocol(),
    )
    .into_parts();
    let pool = pool_address(package_hash(&ProtocolHasher, staking_artifact()), &unseated);
    let badge = pool_owner_badge(pool);
    // What a pool is, cell by cell: the seal, a record per mark it
    // issues, and the badge instance its instantiation minted.
    for key in [
        config_key(pool),
        resource_record_key(&ProtocolHasher, pool, badge),
        resource_record_key(&ProtocolHasher, pool, stake_unit(pool)),
        instance_data_key(&ProtocolHasher, pool, badge, OWNER_BADGE_ID),
    ] {
        assert!(genesis_cells.contains_key(&key), "genesis writes the cell");
        assert_eq!(store.cells.get(&key), genesis_cells[&key].as_ref());
    }
    // And nothing beside them, either way. The list above says what the
    // two writers agree on; this says neither writes a cell the other
    // does not — which is the half a named list cannot check, and the
    // half that catches a drift when one side grows a cell.
    let under_pool = |cells: &BTreeMap<SubstateKey, Option<Vec<u8>>>| {
        cells
            .iter()
            .filter(|(key, _)| key.owner == pool.address())
            .map(|(key, value)| (*key, value.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let seeded = under_pool(&genesis_cells);
    let executed: BTreeMap<_, _> = store
        .cells
        .iter()
        .filter(|(key, _)| key.owner == pool.address())
        .map(|(key, value)| (*key, Some(value.clone())))
        .collect();
    assert_eq!(
        seeded.keys().collect::<Vec<_>>(),
        executed.keys().collect::<Vec<_>>(),
        "a seated pool and an instantiated one hold the same cells",
    );
    assert_eq!(seeded, executed, "and the same bytes in each");
    let entry = EntryKey {
        owner: unseated.operator.address(),
        collection: holdings_collection(&ProtocolHasher, unseated.operator, badge),
        order: u128::from(OWNER_BADGE_ID),
    };
    assert!(
        genesis_entries.contains_key(&entry),
        "genesis writes the entry"
    );
    assert_eq!(store.entries.get(&entry), genesis_entries[&entry].as_ref());
}

/// A pool nobody instantiated cannot be called at all.
///
/// Its address derives — anybody can compute it — but the chain answers
/// for no such component, and a caller may not supply the answer: a
/// record stands for the seal that makes a component actual and for no
/// other call. So the composition fails where it is cheapest to fail,
/// with nothing signed and nothing priced.
#[test]
fn a_pool_nobody_instantiated_answers_nothing() {
    let unseated = seat(56);
    let pool = pool_address(package_hash(&ProtocolHasher, staking_artifact()), &unseated);
    let chain = client().records();
    let mut root = IntentBuilder::new(&chain, &ProtocolHasher, delegator(), HEADER);
    let funds = account::withdraw(&mut root, delegator(), *PROTOCOL_RESOURCE, 500)
        .expect("an account withdraws");
    let refusal = staking::Staking::at(pool)
        .stake(&mut root, funds)
        .expect_err("a pool nobody sealed resolves nothing");
    assert!(
        matches!(refusal, TypedError::UnknownInstance(address) if address == pool.address()),
        "refused as an address the chain answers nothing for: {refusal:?}"
    );
}

#[test]
fn a_delegation_to_a_seated_pool_reaches_the_witness_channel() {
    let executor = Executor::with_genesis(
        &[seat(POOL_ID), seat(99)],
        &GenesisPackages::protocol(),
        ExecutionMode::Serial,
    );
    let executed = execute(&executor, signed_stake(pool_at(POOL_ID), 500));
    assert_eq!(
        witnesses(&executed[0]),
        vec![BeaconWitnessEvent::StakeDeposit {
            pool_id: StakePoolId::new(POOL_ID),
            amount: Stake::from_quanta(500),
        }],
    );
}

/// The same package, an instance nobody seated: it runs, it moves funds,
/// it emits — and the beacon never hears about it. Seating a pool is a
/// decision the network makes, not one a transaction can make for it.
#[test]
fn an_unseated_instance_of_the_same_package_reaches_nobody() {
    let executor = seated(&[seat(POOL_ID)], ExecutionMode::Serial);
    // `pool_at(99)` is not in the pool set, so it was never registered as an
    // instance either and the delegation cannot even be routed to it —
    // which is the outer of the two guards. The inner one is covered by
    // the codec's own tests, where an instance exists and is unrecognised.
    let executed = execute(&executor, signed_stake(pool_at(POOL_ID), 500));
    assert_eq!(
        witnesses(&executed[0]).len(),
        1,
        "only the seated pool spoke"
    );
}

/// An ordinary transfer between accounts emits events and no facts: the
/// channel carries what a stake pool says and nothing else.
#[test]
fn an_ordinary_transfer_is_not_a_beacon_fact() {
    let executor = seated(&[seat(POOL_ID)], ExecutionMode::Serial);
    let key = Ed25519PrivateKey::from_bytes(&[DELEGATOR; 32]).unwrap();
    let from = account_address(&key.public_key().0);
    let graph = client()
        .transfer_graph(from, from, 100)
        .expect("an account answers a transfer");
    let tx = Transaction::new(client().sign(graph, &key, validity(), terms(1_000)));
    let executed = execute(&executor, tx);
    assert!(
        witnesses(&executed[0]).is_empty(),
        "an account's own events are not the beacon's business",
    );
}

/// `pool.register-validator(id, pubkey, proof)`, signed and paid for by
/// `seed`, presenting the pool's owner badge from their own account —
/// whether or not they hold it.
fn signed_registration(pool: ComponentAddr, seed: u8) -> Transaction {
    let key = key_of(seed);
    let signer = account_address(&key.public_key().0);
    let chain = client().records();
    let mut b = client().builder(&chain, signer);
    let proof = account::present_instance(&mut b, signer, pool_owner_badge(pool), OWNER_BADGE_ID)
        .expect("a presentation types");
    b.presenting(proof, |b| {
        staking::Staking::at(pool).register_validator(b, 11, [0xC1; 48], [0xC2; 96])
    })
    .expect("a pool answers a registration");
    let graph = b.build().expect("a registration produces nothing");
    Transaction::new(client().sign(graph, &key, validity(), terms(1_000)))
}

/// A pool instance is owned by nobody, so its own authority is
/// unsatisfiable and the surface would be uncallable if it asked for
/// one. It admits whoever presents the pool's owner badge instead, and
/// genesis seats that badge in the seat's operator account.
#[test]
fn only_the_badge_holder_may_register_a_validator() {
    let executor = seated(&[seat(POOL_ID)], ExecutionMode::Serial);

    // Well-formed: the outsider presents a badge from their own
    // account, which is what admission asks of a custodial call. The
    // badge is what they do not hold, and the gate says so when the
    // call reaches it.
    let outsider = signed_registration(pool_at(POOL_ID), OUTSIDER);
    assert!(
        outsider.try_derived(executor.derivation().as_ref()).is_ok(),
        "the shape is well-formed"
    );
    let executed = execute(&executor, outsider);
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Failed),
        "an outsider's registration must not settle: {:?}",
        executed[0].consensus
    );

    // The control: the same manifest, the same fee, one signature
    // different. What bites is whose key signed it and not the shape.
    let executed = execute(&executor, signed_registration(pool_at(POOL_ID), OPERATOR));
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the badge holder's own registration settles: {:?}",
        executed[0].consensus
    );
}

/// The delegation surface is unmoved: `stake` supplies its own authority
/// in the funds it carries, so anyone may delegate to any seated pool.
#[test]
fn a_delegation_needs_no_operator() {
    let executor = seated(&[seat(POOL_ID)], ExecutionMode::Serial);
    assert!(
        signed_stake(pool_at(POOL_ID), 500)
            .try_derived(executor.derivation().as_ref())
            .is_ok()
    );
}

/// Two pool seats whose addresses fall on different leaves of `trie`,
/// so a delegation into both is a core spanning two shards.
fn seats_apart(trie: &ShardTrie) -> [u32; 2] {
    let first = trie.shard_for_prefix(pool_at(POOL_ID).address());
    let other = (1..=64u32)
        .find(|id| *id != POOL_ID && trie.shard_for_prefix(pool_at(*id).address()) != first)
        .expect("some seat sits on another leaf");
    [POOL_ID, other]
}

/// A signing seed whose account sits on none of `taken`'s leaves.
fn seed_away_from(trie: &ShardTrie, taken: &[ShardId]) -> u8 {
    (1..=u8::MAX)
        .find(|seed| !taken.contains(&trie.shard_for_prefix(account_of(*seed))))
        .expect("some key's account sits on a third leaf")
}

/// `payer.withdraw -> pool.stake -> payer.deposit(units)` once into each
/// of two seats: the payer's withdraws are inbound legs, the two stakes
/// a core, the deposits deliveries back.
fn signed_double_stake(seed: u8, seats: [u32; 2], amount: u128) -> Transaction {
    let key = key_of(seed);
    let from = account_of(seed);
    let staking = package_hash(&ProtocolHasher, staking_artifact());
    let metas = seats.map(|id| pool_meta(staking, &seat(id)));
    let chain = client().records();
    let composed = Composed::new(&chain, &metas, &ProtocolHasher);
    let mut b = IntentBuilder::new(&composed, &ProtocolHasher, from, HEADER);
    for meta in &metas {
        let pool = meta.address(&ProtocolHasher);
        let funds = account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount)
            .expect("an account withdraws");
        let units = staking::Staking::at(pool)
            .stake(&mut b, funds)
            .expect("a pool takes a delegation");
        account::deposit(&mut b, from, units).expect("an account banks its position");
    }
    let tree = b.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, &[&key], terms(1_000)))
}

/// A delegation divided across a four-leaf trie: the payer on one leaf,
/// the two pools it delegates to on two others, so the core spans two
/// shards and each core member consumes what the payer's legs hand
/// across, awaits its sibling, and holds no vault. A core of one shard
/// awaits nobody, and a core's own nodes run on every core shard, so
/// nothing short of this shape can be refused by a sibling.
struct DividedStake {
    executor: Executor,
    trie: ShardTrie,
    seats: [u32; 2],
    payer: u8,
    tx: Arc<Verified<Transaction>>,
    classified: Classified,
    /// The payer's shard: the legs.
    payer_shard: ShardId,
    /// The shard whose pool `seats[0]` is: the core member under test.
    core: ShardId,
    /// The other core shard, whose certificate `core` awaits.
    sibling: ShardId,
}

fn divided_stake() -> DividedStake {
    let trie = ShardTrie::uniform(2);
    let seats = seats_apart(&trie);
    let core = trie.shard_for_prefix(pool_at(seats[0]).address());
    let sibling = trie.shard_for_prefix(pool_at(seats[1]).address());
    let payer = seed_away_from(&trie, &[core, sibling]);
    let payer_shard = trie.shard_for_prefix(account_of(payer));
    let executor = seated(&seats.map(seat), ExecutionMode::Serial);
    let raw = signed_double_stake(payer, seats, 500);
    raw.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(
        classified.decomposed(),
        "a payer's legs into a core of two divide"
    );
    assert_eq!(
        classified.core(),
        &BTreeSet::from([core, sibling]),
        "the two stakes are a core spanning two leaves",
    );
    DividedStake {
        executor,
        trie,
        seats,
        payer,
        tx,
        classified,
        payer_shard,
        core,
        sibling,
    }
}

impl DividedStake {
    /// The genesis store, with `pools` seated.
    fn store(&self, pools: &[u32]) -> MapDb {
        let seats: Vec<StakePoolSeat> = pools.iter().map(|id| seat(*id)).collect();
        MapDb::genesis(&[(account_of(self.payer), 10_000)], &seats)
    }

    /// What a counterpart provisions a member with: every cell and entry
    /// `store` holds under `shard`'s prefixes, as the leaves a bundle
    /// carries them. A core runs every core node, so a member of a core
    /// of two reads its sibling's pool through what the sibling
    /// provisioned.
    fn provisioned(&self, store: &MapDb, shard: ShardId) -> Vec<Arc<Vec<SubstateEntry>>> {
        let cells = store
            .cells
            .iter()
            .filter(|(key, _)| self.trie.shard_for_prefix(key.owner) == shard)
            .map(|(key, value)| (*key, Some(value.clone())));
        let entries: SettledEntries = store
            .entries
            .iter()
            .filter(|(key, _)| self.trie.shard_for_prefix(key.owner) == shard)
            .map(|(key, value)| (*key, Some(value.clone())))
            .collect();
        let leaves = cells
            .chain(entry_leaf_rows(&entries))
            .map(|(key, value)| {
                SubstateEntry::new(
                    key,
                    value.map(|bytes| Bytes::new(bytes).expect("a genesis leaf fits a cell")),
                )
            })
            .collect();
        vec![Arc::new(leaves)]
    }

    /// Run `local`'s member on its first side against `store`, handed
    /// `arrivals` and `provisions`.
    fn run(
        &self,
        store: &MapDb,
        local: ShardId,
        arrivals: &[EscrowedValue],
        provisions: &[Arc<Vec<SubstateEntry>>],
    ) -> ExecutedTx {
        let ctx = TickBatchContext {
            local_shard: local,
            shard_trie: &self.trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: self.tx.hash(),
            transaction: Some(&self.tx),
            provisions,
            clock: WeightedTimestamp::from_millis(1_000),
            runs: Runs::Shape(Member::of(
                self.classified.clone(),
                local,
                BTreeSet::from([self.payer_shard, self.core, self.sibling]),
            )),
            arrivals,
        };
        self.executor
            .execute_tick_batch(&ctx, store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0)
    }

    /// What the payer's shard hands across: one withdraw per pool, read
    /// off the record cells its legs wrote, as a consumer's arrival index
    /// reads the proven record.
    fn handed(&self, store: &MapDb) -> Vec<EscrowedValue> {
        let legs = self.run(store, self.payer_shard, &[], &[]);
        let ConsensusReceipt::Succeeded { writes, .. } = &legs.consensus else {
            panic!("the payer's legs must succeed: {:?}", legs.metadata);
        };
        let handed: Vec<EscrowedValue> = self
            .classified
            .edges()
            .iter()
            .filter_map(|edge| {
                let record = edge.crossing.id.record_key(&ProtocolHasher);
                let cell = CrossingCell::from_bytes(writes.cells.get(&record)?.as_deref()?)?;
                Some(EscrowedValue {
                    node: edge.producer,
                    output: edge.output,
                    resource: cell.resource,
                    amount: cell.amount,
                    record,
                })
            })
            .collect();
        assert_eq!(handed.len(), 2, "one withdraw crosses to each pool");
        handed
    }

    /// The edge `core` consumes whose decline cell it holds: the
    /// withdraw into its own pool. The other withdraw arrives too, but
    /// its claim and decline sit under the sibling's pool.
    fn own_edge(&self) -> CrossingEdge<ShardId> {
        let edges: Vec<_> = self
            .classified
            .refusable_consumed(self.core)
            .filter(|edge| {
                self.trie.shard_for_prefix(
                    edge.crossing
                        .id
                        .answer_key(&ProtocolHasher, Answered::Taken)
                        .owner,
                ) == self.core
            })
            .cloned()
            .collect();
        assert_eq!(
            edges.len(),
            1,
            "the core holds one of the two crossings' answers"
        );
        edges.into_iter().next().expect("one edge")
    }

    /// The one `Never` the core member writes: for the crossing it
    /// consumes, may refuse, and holds the decline cell of.
    fn never(&self) -> (SubstateKey, Vec<u8>) {
        never_answer(
            self.tx.hash(),
            self.tx.validity_range().end_timestamp_exclusive.as_millis(),
            &self.own_edge(),
        )
    }
}

/// The `Never` cells a refusal receipt writes, with the movements beside
/// them.
fn answers_of(executed: &ExecutedTx) -> (Vec<(SubstateKey, Vec<u8>)>, usize) {
    let writes = executed
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("the member names a refusal receipt with writes");
    let cells = writes
        .cells
        .iter()
        .map(|(key, value)| (*key, value.clone().expect("an answer is an absolute write")))
        .collect();
    (cells, writes.movements.len())
}

/// A multi-core member that completes here, holds no vault here and can
/// still be refused by its sibling names a refusal receipt carrying its
/// `Never`, byte-equal to the one derivation, and nothing else; the
/// refusal receipt is what settles once the sibling's certificate
/// refuses the transaction.
#[test]
fn a_consumer_completed_here_and_refused_elsewhere_writes_never() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);

    let core = divided.run(
        &store,
        divided.core,
        &handed,
        &divided.provisioned(&store, divided.sibling),
    );
    assert!(
        matches!(core.consensus, ConsensusReceipt::Succeeded { .. }),
        "the core member's stakes complete: {:?}",
        core.metadata,
    );
    assert_eq!(
        answers_of(&core),
        (vec![divided.never()], 0),
        "one Never for the crossing whose decline cell it holds, and no charge: the vault \
         is not here",
    );
}

/// A core member that aborts names a refusal receipt whose writes are
/// one `Never` per escrowed crossing it consumes, whether the kernel
/// refused it or the plan could not be built before the kernel ran.
#[test]
fn an_aborted_consumer_writes_never_at_each_refusable_edge() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);

    // The core's own pool is seated in the executor's records and absent
    // from the state it runs against, so the stake fails inside the
    // kernel.
    let sibling_only = divided.store(&divided.seats[1..]);
    let refused = divided.run(
        &sibling_only,
        divided.core,
        &handed,
        &divided.provisioned(&sibling_only, divided.sibling),
    );
    assert!(
        matches!(refused.consensus, ConsensusReceipt::Failed),
        "a stake into a pool the state does not hold fails: {:?}",
        refused.consensus,
    );
    assert_eq!(
        answers_of(&refused),
        (vec![divided.never()], 0),
        "the kernel path writes the one Never",
    );

    // Handed nothing, the member's plan cannot be built: refused before
    // the kernel ran, and answering the same way.
    let unbuilt = divided.run(
        &store,
        divided.core,
        &[],
        &divided.provisioned(&store, divided.sibling),
    );
    assert!(
        matches!(unbuilt.consensus, ConsensusReceipt::Failed),
        "a member whose arrival never came is refused before the kernel: {:?}",
        unbuilt.consensus,
    );
    assert_eq!(
        answers_of(&unbuilt),
        (vec![divided.never()], 0),
        "the pre-kernel path writes the one Never",
    );
}

/// Where an answer already stands at the claim key or the decline key,
/// the refusal receipt carries no `Never` for that edge and the member
/// does not trap: it fails with the one "already answered" outcome and
/// names no receipt, since nothing else is settled apart here.
#[test]
fn never_is_skipped_where_an_answer_stands() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);
    let edge = divided.own_edge();
    let (never, bytes) = divided.never();

    for (name, key, value) in [
        (
            "the claim",
            edge.crossing
                .id
                .answer_key(&ProtocolHasher, Answered::Taken),
            vec![1u8],
        ),
        ("the decline", never, bytes),
    ] {
        let mut answered = divided.store(&divided.seats);
        answered.cells.insert(key, value);
        let executed = divided.run(
            &answered,
            divided.core,
            &handed,
            &divided.provisioned(&answered, divided.sibling),
        );
        assert!(
            matches!(executed.consensus, ConsensusReceipt::Failed),
            "with {name} standing the take is refused: {:?}",
            executed.consensus,
        );
        assert!(
            executed.refusal_receipt.is_none(),
            "with {name} standing no Never is written and nothing else is owed here",
        );
    }
}

/// For every edge of a frozen star, the producer's departure is
/// escrowed exactly where the consumer may refuse it: the two are read
/// off one flag, so an owed crossing is never answered `Never` and an
/// escrowed one always can be.
#[test]
fn a_departure_is_escrowed_exactly_where_its_consumer_may_refuse() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);
    let plans = [
        divided
            .classified
            .plan(
                &[],
                divided.payer_shard,
                divided.tx.validity_range().end_timestamp_exclusive,
            )
            .expect("the payer's shard plans its legs"),
        divided
            .classified
            .plan(
                &handed,
                divided.core,
                divided.tx.validity_range().end_timestamp_exclusive,
            )
            .expect("the core plans on what it was handed"),
    ];

    let mut kinds = BTreeSet::new();
    for edge in divided.classified.edges() {
        let Some(departure) = plans
            .iter()
            .find_map(|plan| plan.legs.departure(edge.producer, edge.output))
        else {
            continue;
        };
        let refusable = edge.to.iter().any(|shard| {
            divided
                .classified
                .refusable_consumed(*shard)
                .any(|named| named == edge)
        });
        assert_eq!(
            departure.crossing.kind == Kind::Escrowed,
            refusable,
            "edge {}:{} departs {:?} and is refusable: {refusable}",
            edge.producer,
            edge.output,
            departure.crossing.kind,
        );
        kinds.insert(departure.crossing.kind == Kind::Escrowed);
    }
    assert_eq!(
        kinds,
        BTreeSet::from([false, true]),
        "the fixture departs one of each kind",
    );
}
