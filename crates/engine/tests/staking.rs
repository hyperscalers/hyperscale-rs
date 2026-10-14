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
use hyperscale_engine::legs::{
    Classified, Member, Runs, Unclaimable, abandoned_never, never_answer,
};
use hyperscale_engine::sharding::writes_root;
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PROTOCOL_RESOURCE, RecordStore, TickBatchContext,
    TickEnvironment, TickTxInput, build_refusal_receipt, genesis_writes, receipt_hash_of,
};
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_storage::{
    FetchedInstanceStore, NoFeeHolds, Substates, crossing_settlements, entry_leaf_rows,
    member_row_leaf, owed_credits, unclaimed_declines,
};
use hyperscale_storage_memory::SimBeaconStorage;
use hyperscale_transactions::{Ceilings, Client, Terms};
use hyperscale_types::test_utils::state_and_proof_holding;
use hyperscale_types::{
    Anchor, BeaconWitnessEvent, BeaconWitnessRoot, BlockHeight, ComponentAddr, ConsensusReceipt,
    Deadline, Ed25519PrivateKey, EntryKey, EscrowedValue, EventExt, EventRoot, ExecutionOutcome,
    GlobalReceipt, Hash, Inclusion, Issuer, MAX_INTENT_VALIDITY_RANGE, MerkleInclusionProof,
    NetworkId, PriceTable, PrincipalAddr, ProvisionalHolds, SettledEntries, SettledWrites, ShardId,
    ShardTrie, Stake, StakePoolId, StakePoolSeat, StateClaim, StateRoot, Stated, SubstateEntry,
    SubstateKey, TimestampRange, Transaction, TxHash, UnsettledCredits, Verified,
    WeightedTimestamp, absorb_committed_cells, answer_hashes, compute_merkle_root,
};
use hyperscale_vm_effects::{
    Answered, ChainRecords, Composed, CrossingCell, CrossingEdge, CrossingId, IntentHeader, Kind,
    Terms as CrossingTerms, fee_hold_key, holdings_collection, instance_data_key, package_hash,
    resource_record_key,
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
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

/// The copy a node kept of a record it fetched, read through its beacon
/// store.
struct Kept(SimBeaconStorage);

impl RecordStore for Kept {
    fn instance_record(&self, instance: Address) -> Option<Vec<u8>> {
        self.0.fetched_instance(instance)
    }
}

/// A record a node fetched routes a call on an engine holding none of it
/// in memory, once the node keeps the copy.
///
/// What a restart leaves, and what the bounded registry letting the
/// record go leaves: an engine that answers for a foreign component from
/// nothing it seated. A transaction routed before has to route again
/// when its block is replayed, and nothing re-admits a committed block —
/// so the kept copy is the only thing that can answer.
#[test]
fn a_kept_record_routes_a_call_on_an_engine_that_never_seated_it() {
    let unseated = seat(56);
    let holder = seated(std::slice::from_ref(&seat(POOL_ID)), ExecutionMode::Serial);
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
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
    let pool = pool_address(package_hash(&ProtocolHasher, staking_artifact()), &unseated).address();
    // What the owning shard serves a record fetch from.
    let record = store
        .cell(Executor::instance_record_key(pool))
        .expect("the seal committed the pool's record");

    // Rebuilt from genesis, as a restarted process is.
    let restarted = seated(std::slice::from_ref(&seat(POOL_ID)), ExecutionMode::Serial);
    let call = signed_stake_composed(&unseated, 500);
    let Err(gap) = call.try_derived(restarted.derivation().as_ref()) else {
        panic!("an engine holding nothing for the pool cannot route a call to it");
    };
    assert!(
        gap.unresolved()
            .is_some_and(|wanted| wanted.instances.contains(&pool)),
        "the gap is the pool's record; error = {gap:?}"
    );

    let kept = SimBeaconStorage::new();
    kept.store_fetched_instances(&[(pool, record)]);
    restarted.install_store(Arc::new(Kept(kept)));
    signed_stake_composed(&unseated, 500)
        .try_derived(restarted.derivation().as_ref())
        .expect("the kept record routes the call");
    assert!(
        restarted.instance_known(pool),
        "and is seated, so the next derivation reads it from memory"
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
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
    let divided = stake_paid_by(seed_away_from(&trie, &[core, sibling]));
    assert!(
        divided.classified.decomposed(),
        "a payer's legs into a core of two divide"
    );
    assert_eq!(
        divided.classified.core(),
        &BTreeSet::from([core, sibling]),
        "the two stakes are a core spanning two leaves",
    );
    divided
}

/// The delegation of [`divided_stake`] signed and paid for by the
/// account of seed `payer`, wherever that account sits.
fn stake_paid_by(payer: u8) -> DividedStake {
    let trie = ShardTrie::uniform(2);
    let seats = seats_apart(&trie);
    let core = trie.shard_for_prefix(pool_at(seats[0]).address());
    let sibling = trie.shard_for_prefix(pool_at(seats[1]).address());
    let payer_shard = trie.shard_for_prefix(account_of(payer));
    let executor = seated(&seats.map(seat), ExecutionMode::Serial);
    let raw = signed_double_stake(payer, seats, 500);
    raw.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(raw));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(
        classified
            .core()
            .is_superset(&BTreeSet::from([core, sibling])),
        "the two stakes are in a core spanning two leaves",
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
            fee_holds: &NoFeeHolds,
            unsettled_credits: &UnsettledCredits::new(),
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
        never_answer(self.tx.hash(), self.validity_end_ms(), &self.own_edge())
    }

    /// The record the payer's leg writes for the crossing whose answers
    /// the core holds.
    fn record(&self, store: &MapDb) -> CrossingCell {
        let legs = self.run(store, self.payer_shard, &[], &[]);
        let ConsensusReceipt::Succeeded { writes, .. } = &legs.consensus else {
            panic!("the payer's legs must succeed: {:?}", legs.metadata);
        };
        let record = self.own_edge().crossing.id.record_key(&ProtocolHasher);
        CrossingCell::from_bytes(
            writes.cells[&record]
                .as_deref()
                .expect("the leg writes the record"),
        )
        .expect("a record decodes")
    }

    /// The transaction's validity end, which its records and its
    /// answers state.
    fn validity_end_ms(&self) -> u64 {
        self.tx.validity_range().end_timestamp_exclusive.as_millis()
    }

    /// The claim cell of the crossing whose answers the core holds, and
    /// the `Taken` the core member's take writes there.
    fn taken(&self) -> (SubstateKey, Vec<u8>) {
        let id = self.own_edge().crossing.id;
        (
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(self.tx.hash(), Answered::Taken, self.validity_end_ms())
                .to_bytes(),
        )
    }

    /// The answers a transaction carrying the same intent earlier left
    /// at the cells of the crossing the core holds: its `Taken` at the
    /// claim, and its `Never`, seen and unseen, at the decline.
    fn earlier_answers(&self) -> [(&'static str, SubstateKey, Vec<u8>); 3] {
        let id = self.own_edge().crossing.id;
        let earlier = TxHash::from(Hash::from_bytes(b"an earlier transaction"));
        let end = self.validity_end_ms();
        let (claim, _) = self.taken();
        let (never, _) = self.never();
        [
            (
                "an earlier Taken",
                claim,
                id.answer(earlier, Answered::Taken, end).to_bytes(),
            ),
            (
                "an earlier Never",
                never,
                id.answer(earlier, Answered::Never, end).to_bytes(),
            ),
            (
                "an earlier unseen Never",
                never,
                id.unseen_never(earlier, end).to_bytes(),
            ),
        ]
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

/// The answer keys name the edge and no transaction. An answer an
/// earlier transaction carrying the same intent left at the claim or
/// the decline refuses nothing of this one: the core member runs,
/// writes its own `Taken` at the claim, over the earlier one where it
/// stood there, and its refusal receipt carries its own `Never`.
#[test]
fn a_take_is_not_refused_under_another_transactions_answer() {
    let divided = divided_stake();
    let handed = divided.handed(&divided.store(&divided.seats));
    let (claim, taken) = divided.taken();

    for (name, key, standing) in divided.earlier_answers() {
        let mut store = divided.store(&divided.seats);
        store.cells.insert(key, standing);
        let core = divided.run(
            &store,
            divided.core,
            &handed,
            &divided.provisioned(&store, divided.sibling),
        );
        let ConsensusReceipt::Succeeded { writes, .. } = &core.consensus else {
            panic!("under {name} the take still runs: {:?}", core.metadata);
        };
        assert_eq!(
            writes.cells.get(&claim),
            Some(&Some(taken.clone())),
            "under {name} the member writes its own Taken",
        );
        assert_eq!(
            answers_of(&core),
            (vec![divided.never()], 0),
            "under {name} the refusal a sibling can still force carries its own Never",
        );
    }
}

/// A refused member writes its own `Never` whatever an earlier
/// transaction carrying the same intent left at either answer cell: over
/// the earlier `Never` at the decline, and beside the earlier `Taken`
/// at the claim. Whether the kernel refused it or its plan could not be
/// built before the kernel ran.
#[test]
fn a_refusal_writes_its_never_over_another_transactions_answer() {
    let divided = divided_stake();
    let handed = divided.handed(&divided.store(&divided.seats));

    for (name, key, standing) in divided.earlier_answers() {
        // The core's own pool is absent from the state, so the stake
        // fails inside the kernel.
        let mut sibling_only = divided.store(&divided.seats[1..]);
        sibling_only.cells.insert(key, standing.clone());
        let refused = divided.run(
            &sibling_only,
            divided.core,
            &handed,
            &divided.provisioned(&sibling_only, divided.sibling),
        );
        assert!(
            matches!(refused.consensus, ConsensusReceipt::Failed),
            "under {name}: {:?}",
            refused.consensus,
        );
        assert_eq!(
            answers_of(&refused),
            (vec![divided.never()], 0),
            "under {name} the kernel path writes this transaction's Never",
        );

        let mut store = divided.store(&divided.seats);
        store.cells.insert(key, standing);
        let unbuilt = divided.run(
            &store,
            divided.core,
            &[],
            &divided.provisioned(&store, divided.sibling),
        );
        assert!(
            matches!(unbuilt.consensus, ConsensusReceipt::Failed),
            "under {name}: {:?}",
            unbuilt.consensus,
        );
        assert_eq!(
            answers_of(&unbuilt),
            (vec![divided.never()], 0),
            "under {name} the pre-kernel path writes this transaction's Never",
        );
    }
}

/// A claim of `shard`'s state reading `key` present off a tree that
/// holds `value` there, named for `id`.
fn read_off_a_tree(shard: ShardId, key: SubstateKey, value: &[u8], id: CrossingId) -> StateClaim {
    let (state_root, proof) = state_and_proof_holding(shard, &[(key, value.to_vec())], &[key]);
    let cells = proof
        .inclusions(state_root, shard, &[key])
        .expect("the proof answers for its key");
    StateClaim::new(
        Anchor {
            shard,
            height: BlockHeight::new(5),
            state_root,
            ts: WeightedTimestamp::from_millis(5_000),
        },
        cells,
        proof,
    )
    .naming([(key, id)])
}

/// The `Taken` the consumer's commit fold writes on reading the owed
/// record `owed` of `id` with its value, at an anchor of `producer`'s,
/// into a state holding no answer.
fn credited_taken(id: CrossingId, owed: &CrossingCell, producer: ShardId) -> Vec<u8> {
    let record_key = id.record_key(&ProtocolHasher);
    let reading = StateClaim::new(
        Anchor {
            shard: producer,
            height: BlockHeight::new(4),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(4_000),
        },
        [(
            record_key,
            Stated::Held(Bytes::new(owed.to_bytes()).expect("a record fits")),
        )],
        MerkleInclusionProof::dummy(),
    )
    .naming([(record_key, id)]);
    let empty = MapDb {
        cells: BTreeMap::new(),
        entries: BTreeMap::new(),
    };
    owed_credits(&[reading], &empty)
        .cells
        .remove(&id.answer_key(&ProtocolHasher, Answered::Taken))
        .flatten()
        .expect("the fold writes the Taken it credits on")
}

/// The `Never` the commit fold of `consumer`'s chain rewrites where the
/// unseen `abandoned` stands at `decline` and a block carries `record`
/// of `id` read present at an anchor of `producer`'s: the decline
/// marked seen.
fn marked_seen(
    id: CrossingId,
    record: &CrossingCell,
    producer: ShardId,
    consumer: ShardId,
    decline: SubstateKey,
    abandoned: &[u8],
) -> Vec<u8> {
    let record_key = id.record_key(&ProtocolHasher);
    let reading = StateClaim::new(
        Anchor {
            shard: producer,
            height: BlockHeight::new(4),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(4_000),
        },
        [(
            record_key,
            Stated::Held(Bytes::new(record.to_bytes()).expect("a record fits")),
        )],
        MerkleInclusionProof::dummy(),
    )
    .naming([(record_key, id)]);
    let standing = MapDb {
        cells: BTreeMap::from([(decline, abandoned.to_vec())]),
        entries: BTreeMap::new(),
    };
    let settled = crossing_settlements(
        &[reading],
        consumer,
        WeightedTimestamp::from_millis(4_000),
        &SettledWrites::default(),
        &standing,
    );
    let [(rewritten_at, seen)] = settled.seen.as_slice() else {
        panic!("the fold marks the one unseen Never seen: {settled:?}");
    };
    assert_eq!(*rewritten_at, decline);
    seen.clone()
}

/// The `Never` the commit fold of `consumer`'s chain writes over
/// `standing` on reading `record` of `id` with its value, at an anchor
/// of `producer`'s, in a block at the record's validity end that reads
/// the chain's own row of the record's transaction absent: `None` where
/// it declines nothing.
fn declined_never(
    id: CrossingId,
    record: &CrossingCell,
    producer: ShardId,
    consumer: ShardId,
    standing: &MapDb,
) -> Option<Vec<u8>> {
    let record_key = id.record_key(&ProtocolHasher);
    let at = |shard: ShardId| Anchor {
        shard,
        height: BlockHeight::new(4),
        state_root: StateRoot::ZERO,
        ts: WeightedTimestamp::from_millis(4_000),
    };
    let reading = StateClaim::new(
        at(producer),
        [(
            record_key,
            Stated::Held(Bytes::new(record.to_bytes()).expect("a record fits")),
        )],
        MerkleInclusionProof::dummy(),
    )
    .naming([(record_key, id)]);
    let rowless = StateClaim::new(
        at(consumer),
        [(member_row_leaf(consumer, record.tx), Inclusion::Absent)],
        MerkleInclusionProof::new(Vec::new()),
    );
    unclaimed_declines(
        &[reading, rowless],
        consumer,
        WeightedTimestamp::from_millis(record.validity_end_ms),
        standing,
    )
    .cells
    .remove(&id.answer_key(&ProtocolHasher, Answered::Never))
    .flatten()
}

/// Every writer of an answer writes bytes whose hash is one the binding
/// derives from the record it answers: the kernel's take, the refusal's
/// `Never`, the abandonment's unseen `Never`, the fold's rewrite of
/// that `Never` as seen, the fold's own decline, and the fold's `Taken`
/// for an owed record.
/// Each is proven present in a tree, and the hash
/// that presence states is held to [`answer_hashes`] over the record
/// the producer's leg wrote, so a producer holding the record reads the
/// answer as its own.
#[test]
fn every_answer_writer_writes_the_bytes_the_binding_hashes() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);
    let edge = divided.own_edge();
    let id = edge.crossing.id;

    let record = divided.record(&store);
    assert_eq!(
        Issuer::from(&record),
        Issuer {
            tx: divided.tx.hash(),
            validity_end_ms: divided.validity_end_ms(),
        },
        "the record states its transaction and that transaction's validity end",
    );

    // The kernel's take: the core member completes and writes the claim.
    let took = divided.run(
        &store,
        divided.core,
        &handed,
        &divided.provisioned(&store, divided.sibling),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &took.consensus else {
        panic!("the core member's stakes complete: {:?}", took.metadata);
    };
    let claim = id.answer_key(&ProtocolHasher, Answered::Taken);
    let taken = writes.cells[&claim].clone().expect("the take writes it");

    // The refusal's `Never`: the stake fails inside the kernel.
    let sibling_only = divided.store(&divided.seats[1..]);
    let refused = divided.run(
        &sibling_only,
        divided.core,
        &handed,
        &divided.provisioned(&sibling_only, divided.sibling),
    );
    let (refusals, _) = answers_of(&refused);
    let [(decline, never)] = refusals.as_slice() else {
        panic!("the refusal writes one Never: {refusals:?}");
    };

    // The abandonment's unseen `Never`, off the validity end the
    // abandoning shard reads back from the deadline it holds.
    let deadline = Deadline::of(divided.tx.validity_range().end_timestamp_exclusive);
    let (abandoned_at, abandoned) =
        abandoned_never(divided.tx.hash(), deadline.validity_end().as_millis(), id);
    assert_eq!(abandoned_at, *decline);
    assert_ne!(&abandoned, never, "unseen, where the refusal's is seen");

    // The fold's rewrite of that `Never` as seen, on the record read
    // present.
    let seen = marked_seen(
        id,
        &record,
        divided.payer_shard,
        divided.core,
        *decline,
        &abandoned,
    );
    assert_ne!(seen, abandoned, "the rewrite changes the cell");

    // The fold's own decline, for the record read past its validity
    // end with no member of its transaction on the consumer's chain.
    let empty = MapDb {
        cells: BTreeMap::new(),
        entries: BTreeMap::new(),
    };
    let declined = declined_never(id, &record, divided.payer_shard, divided.core, &empty)
        .expect("the fold declines a record nobody here can take");
    assert_eq!(&declined, never, "seen, as the refusal's is");

    // The fold's `Taken` for an owed record: the same crossing on owed
    // terms.
    let owed = CrossingCell {
        terms: CrossingTerms::Owed,
        ..record
    };
    let credited = credited_taken(id, &owed, divided.payer_shard);

    for (writer, key, value, answered, against) in [
        ("the kernel's take", claim, &taken, Answered::Taken, &record),
        ("the refusal", *decline, never, Answered::Never, &record),
        (
            "the abandonment",
            *decline,
            &abandoned,
            Answered::Never,
            &record,
        ),
        (
            "the seen rewrite",
            *decline,
            &seen,
            Answered::Never,
            &record,
        ),
        (
            "the fold's decline",
            *decline,
            &declined,
            Answered::Never,
            &record,
        ),
        ("the owed credit", claim, &credited, Answered::Taken, &owed),
    ] {
        assert_bound(writer, divided.core, (key, value), id, answered, against);
    }
}

/// Hold `value`, proven present at `key` in a tree of `shard`'s, to the
/// binding: its hash is one [`answer_hashes`] derives from `against`,
/// the record it answers, on the producer's test and the consumer's
/// alike, and it is no answer to a record another transaction issued.
fn assert_bound(
    writer: &str,
    shard: ShardId,
    (key, value): (SubstateKey, &[u8]),
    id: CrossingId,
    answered: Answered,
    against: &CrossingCell,
) {
    let proven = read_off_a_tree(shard, key, value, id);
    assert_eq!(proven.verify(), Ok(()), "{writer}");
    let Some(Inclusion::Present(stated)) = proven.reading(key) else {
        panic!("{writer}: the tree holds the answer");
    };
    assert!(
        answer_hashes(&id, against.into(), answered).contains(&stated),
        "{writer} writes bytes the binding does not hash",
    );
    assert!(proven.answers(&id, against, answered), "{writer}");
    assert!(
        Issuer::from(against).answered_by(&id, answered, value),
        "{writer}: the consumer-side test reads the same bytes as its own",
    );
    let stranger = Issuer {
        tx: TxHash::from(Hash::from_bytes(b"an earlier transaction")),
        ..Issuer::from(against)
    };
    assert!(!proven.answers(&id, stranger, answered), "{writer}");
}

/// Two transactions carrying one intent name one decline key. Where the
/// consumer's chain abandons both, each abandonment's receipt writes its
/// own transaction's `Never` there and the later is written over the
/// earlier. The cell then states the later transaction's answer alone,
/// so read present it binds nothing of the record the first transaction
/// issued: no answer at the key speaks for that record, and no reading
/// of the key takes it back.
#[test]
fn a_decline_another_transaction_wrote_over_binds_nothing_of_the_first_record() {
    let divided = divided_stake();
    let id = divided.own_edge().crossing.id;
    let first = divided.record(&divided.store(&divided.seats));
    let record_key = id.record_key(&ProtocolHasher);
    let end = divided.validity_end_ms();
    let second = Issuer {
        tx: TxHash::from(Hash::from_bytes(b"a second transaction")),
        validity_end_ms: end,
    };

    let (decline, first_never) = abandoned_never(first.tx, end, id);
    let (second_decline, second_never) = abandoned_never(second.tx, end, id);
    assert_eq!(second_decline, decline, "one decline key for both");
    assert_ne!(second_never, first_never);

    // The consumer's state, as each abandonment's receipt lands on it.
    let mut consumer: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
    let bound_to = |standing: &[u8]| {
        let proven = read_off_a_tree(divided.core, decline, standing, id);
        let Some(Inclusion::Present(stated)) = proven.reading(decline) else {
            panic!("the tree holds the decline");
        };
        let licence = Unclaimable::Never {
            read: decline,
            stated,
        };
        (
            proven.answers(&id, &first, Answered::Never) && licence.binds(record_key, &first),
            proven.answers(&id, second, Answered::Never),
        )
    };
    for (abandoned, never, bound) in [
        (first.tx, &first_never, (true, false)),
        (second.tx, &second_never, (false, true)),
    ] {
        let receipt = build_refusal_receipt(
            divided.core,
            &divided.trie,
            abandoned,
            None,
            &[(decline, never.clone())],
        )
        .expect("an abandonment naming a crossing names a receipt");
        let writes = receipt.writes().expect("which writes the Never");
        for (key, value) in &writes.cells {
            consumer.insert(*key, value.clone().expect("an answer is an absolute write"));
        }
        assert_eq!(consumer.get(&decline), Some(never));
        assert_eq!(bound_to(&consumer[&decline]), bound);
    }
}

/// A decline the fold wrote for one transaction's record takes back
/// nothing of a record a later transaction issues on the same edge.
///
/// The consumer's chain never commits the first transaction and
/// declines its record in the fold; that `Never`, read present, is the
/// licence the producer takes the first record back on. The edge is then
/// issued again by a second transaction carrying the same intent. The
/// proof of the first decline, replayed, still verifies and still reads
/// the decline key present, and binds nothing of the second record: no
/// reclaim is licensed against it. The consumer's fold declines the
/// second record in its own right, over the first transaction's
/// `Never`, and only that answer binds it.
#[test]
fn a_replayed_decline_cannot_take_back_a_reissued_record() {
    let divided = divided_stake();
    let id = divided.own_edge().crossing.id;
    let first = divided.record(&divided.store(&divided.seats));
    let reissued = CrossingCell {
        tx: TxHash::from(Hash::from_bytes(b"a second transaction")),
        ..first
    };
    let record_key = id.record_key(&ProtocolHasher);
    let decline = id.answer_key(&ProtocolHasher, Answered::Never);
    let (producer, consumer) = (divided.payer_shard, divided.core);
    let licence_of = |standing: &[u8]| {
        let proven = read_off_a_tree(consumer, decline, standing, id);
        assert_eq!(proven.verify(), Ok(()));
        let Some(Inclusion::Present(stated)) = proven.reading(decline) else {
            panic!("the tree holds the decline");
        };
        (
            proven,
            Unclaimable::Never {
                read: decline,
                stated,
            },
        )
    };

    let mut state = MapDb {
        cells: BTreeMap::new(),
        entries: BTreeMap::new(),
    };
    let first_never = declined_never(id, &first, producer, consumer, &state)
        .expect("the fold declines the first record");
    state.cells.insert(decline, first_never.clone());
    let (proven, licence) = licence_of(&first_never);
    assert!(proven.answers(&id, &first, Answered::Never));
    assert!(
        licence.binds(record_key, &first),
        "the decline licenses taking the first record back",
    );

    assert!(!proven.answers(&id, &reissued, Answered::Never));
    assert!(
        !licence.binds(record_key, &reissued),
        "replayed, it licenses nothing against the record issued again",
    );

    let second_never = declined_never(id, &reissued, producer, consumer, &state)
        .expect("the first transaction's Never refuses no decline of the second record");
    assert_ne!(second_never, first_never);
    state.cells.insert(decline, second_never.clone());
    let (proven, licence) = licence_of(&second_never);
    assert!(
        proven.answers(&id, &reissued, Answered::Never) && licence.binds(record_key, &reissued)
    );
    assert!(!licence.binds(record_key, &first));
    assert_eq!(
        declined_never(id, &reissued, producer, consumer, &state),
        None,
        "and its own Never standing, the second record is declined once",
    );
}

/// Where this transaction's own answer already stands at the claim key
/// or the decline key, the refusal receipt carries no `Never` for that
/// edge and the member does not trap: it fails with the one "already
/// answered" outcome and names no receipt, since nothing else is
/// settled apart here.
#[test]
fn never_is_skipped_where_an_answer_stands() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);
    let edge = divided.own_edge();
    let (never, bytes) = divided.never();

    let (claim, taken) = divided.taken();
    let unseen = edge
        .crossing
        .id
        .unseen_never(divided.tx.hash(), divided.validity_end_ms())
        .to_bytes();
    for (name, key, value) in [
        ("the claim", claim, taken),
        ("the decline", never, bytes),
        ("the unseen decline", never, unseen),
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

/// The leaves a receipt's event root is taken over.
fn event_leaves(receipt: &ConsensusReceipt) -> Vec<Hash> {
    let ConsensusReceipt::Succeeded { events, .. } = receipt else {
        panic!("the transaction must settle: {receipt:?}");
    };
    events.iter().map(EventExt::hash).collect()
}

/// Two receipts alike in everything but one beacon fact hash apart, so a
/// receipt cannot gain or lose a fact under the hash a quorum signed.
///
/// The pair comes from two engines running one call against one state:
/// one seats the pool the call delegates to and lifts its event into a
/// fact, the other holds the pool only as an instance a transaction
/// sealed, and lifts nothing.
#[test]
fn a_receipt_with_a_stripped_witness_event_hashes_apart() {
    let sealed = seat(56);
    let unrecognising = seated(std::slice::from_ref(&seat(POOL_ID)), ExecutionMode::Serial);
    let recognising = seated(&[seat(POOL_ID), sealed.clone()], ExecutionMode::Serial);
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
        fee_holds: &NoFeeHolds,
        unsettled_credits: &UnsettledCredits::new(),
    };
    let run = |executor: &Executor, store: &MapDb, raw: Transaction| {
        raw.try_derived(executor.derivation().as_ref())
            .expect("a fixture transaction derives");
        let tx = Arc::new(Verified::<Transaction>::from_persisted(raw));
        executor
            .execute_batch(&ctx, PriceTable::GENESIS, store, std::slice::from_ref(&tx))
            .expect("the harness engine holds every package it runs")
            .remove(0)
    };

    let seal = run(
        &unrecognising,
        &store,
        signed_instantiate(OPERATOR, &sealed),
    );
    absorb(&mut store, &seal, &unrecognising);

    let carrying = run(&recognising, &store, signed_stake_composed(&sealed, 500));
    let stripped = run(&unrecognising, &store, signed_stake_composed(&sealed, 500));

    assert_eq!(
        witnesses(&carrying),
        vec![BeaconWitnessEvent::StakeDeposit {
            pool_id: sealed.id,
            amount: Stake::from_quanta(500),
        }],
    );
    assert!(witnesses(&stripped).is_empty());
    // Stated before the comparison, so the fact is the only thing the two
    // hashes can differ over.
    assert_eq!(carrying.consensus.writes(), stripped.consensus.writes());
    assert_eq!(
        event_leaves(&carrying.consensus),
        event_leaves(&stripped.consensus)
    );
    assert_ne!(
        carrying.consensus.receipt_hash(),
        stripped.consensus.receipt_hash(),
        "one hash names a receipt with the fact and a receipt without it",
    );
}

/// A member reaching beyond its shard hashes over exactly what its
/// receipt carries, so the hash is recomputable from the receipt alone:
/// for the core member, which runs both stakes and keeps the one fact
/// its own pool emitted, for the payer's legs, and for a refusal receipt.
/// A success hashed under whole locality is not, and says so.
#[test]
fn a_projected_receipt_recomputes_the_hash_the_executor_gave_it() {
    let divided = divided_stake();
    let store = divided.store(&divided.seats);
    let handed = divided.handed(&store);

    let core = divided.run(
        &store,
        divided.core,
        &handed,
        &divided.provisioned(&store, divided.sibling),
    );
    assert_eq!(
        witnesses(&core),
        vec![BeaconWitnessEvent::StakeDeposit {
            pool_id: StakePoolId::new(divided.seats[0]),
            amount: Stake::from_quanta(500),
        }],
        "of the two stakes it ran, the core keeps its own pool's fact",
    );
    assert_eq!(
        receipt_hash_of(&core.consensus, true),
        Some(core.consensus.receipt_hash()),
    );
    let refusal = core
        .refusal_receipt
        .as_ref()
        .expect("the core member names a refusal receipt");
    assert_eq!(receipt_hash_of(refusal, true), Some(refusal.receipt_hash()));

    let legs = divided.run(&store, divided.payer_shard, &[], &[]);
    assert!(legs.consensus.is_success());
    assert_eq!(
        receipt_hash_of(&legs.consensus, true),
        Some(legs.consensus.receipt_hash()),
    );

    // The fact is among what the recomputation reads.
    let ConsensusReceipt::Succeeded {
        receipt_hash,
        writes,
        events,
        ..
    } = core.consensus.clone()
    else {
        panic!("the core member's stakes complete");
    };
    let stripped = ConsensusReceipt::Succeeded {
        receipt_hash,
        writes,
        beacon_witness_events: Capped::empty(),
        events,
    };
    assert_ne!(receipt_hash_of(&stripped, true), Some(receipt_hash));

    assert_eq!(receipt_hash_of(&core.consensus, false), None);
    assert_eq!(
        receipt_hash_of(&ConsensusReceipt::Failed, false),
        Some(ConsensusReceipt::Failed.receipt_hash()),
    );
}

/// A core member's effects receipt recomputes, from what the receipt
/// holds on its own shard, to the hash its outcome attests, wherever the
/// payer's vault sits: on a third shard that runs only the legs, or on
/// the other core shard.
///
/// The payer's fee hold ends under the payer's vault, in the writes of
/// the member on the vault's shard and of no other member. So a core
/// shard that does not hold the vault hashes over no hold key, stores
/// none, and its receipt answers for its hash alone; the shard holding
/// the vault hashes over the key and keeps it.
#[test]
fn an_accept_recomputes_for_a_member_whose_payer_is_elsewhere() {
    let trie = ShardTrie::uniform(2);
    let seats = seats_apart(&trie);
    let core = trie.shard_for_prefix(pool_at(seats[0]).address());
    let sibling = trie.shard_for_prefix(pool_at(seats[1]).address());
    let beside_the_legs = seed_away_from(&trie, &[core, sibling]);
    let on_the_sibling = (1..=u8::MAX)
        .find(|seed| trie.shard_for_prefix(account_of(*seed)) == sibling)
        .expect("some key's account sits on the sibling's leaf");

    for payer in [beside_the_legs, on_the_sibling] {
        let staked = stake_paid_by(payer);
        let store = staked.store(&staked.seats);
        let vault = staked.tx.fee_vault();
        let hold = fee_hold_key(&ProtocolHasher, vault, staked.tx.hash());
        assert_eq!(
            staked.trie.shard_for_prefix(vault.owner),
            staked.payer_shard
        );
        assert_eq!(staked.trie.shard_for_prefix(hold.owner), staked.payer_shard);
        assert_ne!(staked.payer_shard, staked.core, "the payer is elsewhere");
        assert_eq!(
            staked.classified.core(),
            &BTreeSet::from([staked.core, staked.sibling]),
            "both shards are core members, wherever the payer sits",
        );
        assert_eq!(
            staked.classified.decomposed(),
            staked.payer_shard != staked.sibling,
            "a payer beside the core divides into legs; one inside it runs whole",
        );

        let handed = if staked.payer_shard == staked.sibling {
            Vec::new()
        } else {
            staked.handed(&store)
        };
        let run = |local: ShardId, other: ShardId| {
            let executed = staked.run(&store, local, &handed, &staked.provisioned(&store, other));
            assert!(
                executed.is_success(),
                "the member on {local:?} completes: {:?}",
                executed.metadata,
            );
            executed
        };
        let members = [
            run(staked.core, staked.sibling),
            run(staked.sibling, staked.core),
        ];
        for (member, local) in members.iter().zip([staked.core, staked.sibling]) {
            // The hash a stating half's certificate attests for the
            // member, and so the one its stated row records.
            let ExecutionOutcome::Succeeded {
                receipt_hash: attested,
            } = *member.outcome().outcome()
            else {
                panic!("a completed member attests a success");
            };
            assert_eq!(
                receipt_hash_of(&member.consensus, true),
                Some(attested),
                "the receipt {local:?} holds recomputes to its attested hash",
            );
            let writes = member.consensus.writes().expect("a success has writes");
            assert_eq!(
                writes.cells.contains_key(&hold),
                local == staked.payer_shard,
                "the hold ends on the vault's shard and nowhere else",
            );
            assert!(
                writes
                    .cells
                    .keys()
                    .all(|key| staked.trie.shard_for_prefix(key.owner) == local),
                "every cell the hash covers is one {local:?} stores",
            );
        }

        if staked.payer_shard != staked.sibling {
            // The legs, on the vault's shard, are what end the hold.
            let legs = staked.run(&store, staked.payer_shard, &[], &[]);
            let writes = legs.consensus.writes().expect("the legs succeed");
            assert_eq!(writes.cells.get(&hold), Some(&None));
            assert_eq!(
                receipt_hash_of(&legs.consensus, true),
                Some(legs.consensus.receipt_hash()),
            );
        }
    }
}

/// A receipt carrying no beacon fact hashes over the root of nothing in
/// the witness term: the outcome, its event root and its writes root are
/// the whole of what moves it.
#[test]
fn a_receipt_without_witness_events_keeps_its_hash() {
    let executor = seated(&[seat(POOL_ID)], ExecutionMode::Serial);
    let key = key_of(DELEGATOR);
    let from = delegator();
    let graph = client()
        .transfer_graph(from, from, 100)
        .expect("an account answers a transfer");
    let tx = Transaction::new(client().sign(graph, &key, validity(), terms(1_000)));
    let executed = execute(&executor, tx).remove(0);

    assert!(witnesses(&executed).is_empty());
    let leaves = event_leaves(&executed.consensus);
    assert!(!leaves.is_empty(), "a transfer emits");
    let writes = executed.consensus.writes().expect("a transfer settles");
    assert_eq!(
        executed.consensus.receipt_hash(),
        GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&leaves)),
            BeaconWitnessRoot::ZERO,
            writes_root(writes),
        )
        .receipt_hash(),
    );
}
