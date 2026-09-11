//! The beacon's control plane on the engine: a delegation to a seated
//! stake pool arrives in the executing shard's `beacon_witness_events`.
//!
//! Every case here runs against a world with a stake pool seated in it,
//! which is what makes the delegation's events beacon facts.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::genesis::genesis_world_with_pools;
use hyperscale_effects_bridge::records::committed_instance;
use hyperscale_effects_bridge::vm_statics::config_key;
use hyperscale_effects_bridge::{ProtocolHasher, account_address};
use hyperscale_engine::genesis::{
    GenesisPackages, OWNER_BADGE_ID, pool_address, pool_meta, pool_owner_badge, stake_unit,
    staking_artifact,
};
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, TickBatchContext, TickEnvironment, XRD, genesis_writes,
};
use hyperscale_storage::Substates;
use hyperscale_transactions::{Client, Terms};
use hyperscale_types::{
    BeaconWitnessEvent, ComponentAddr, ConsensusReceipt, Ed25519PrivateKey, EntryKey, EnvelopeExt,
    MAX_SUBINTENT_VALIDITY_RANGE, NetworkId, PrincipalAddr, ProvisionalHolds, ShardId, ShardTrie,
    Stake, StakePoolId, StakePoolSeat, SubstateKey, TimestampRange, Transaction, Verified,
    WeightedTimestamp, absorb_committed_cells,
};
use hyperscale_vm_effects::{
    ChainRecords, Composed, IntentHeader, holdings_collection, instance_data_key, package_hash,
    resource_record_key,
};
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, TypedError};
use hyperscale_vm_stdlib::{account, instantiate, staking};
use hyperscale_vm_types::{Address, CallTarget, CollectionId};

/// The network every envelope in these tests is signed for.
const NETWORK: NetworkId = NetworkId(242);

/// The widest window an intent may stand for, which these fixtures use
/// wherever they mean "does not expire during the test".
const OFFER_MS: u64 = MAX_SUBINTENT_VALIDITY_RANGE.as_secs() * 1_000;

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
        validity: TimestampRange::new(
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(OFFER_MS),
        ),
        message: Vec::new(),
    }
}

/// `delegator.withdraw(*XRD) -> pool.stake -> delegator.deposit(units)`.
fn signed_stake(pool: ComponentAddr, amount: u128) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[DELEGATOR; 32]).unwrap();
    let from = account_address(&key.public_key().0);
    let chain = client().records();
    let mut b = client().builder(&chain, from);
    let funds = account::withdraw(&mut b, from, *XRD, amount).expect("an account withdraws");
    let units = staking::Staking::at(pool)
        .stake(&mut b, funds)
        .expect("a pool takes a delegation");
    account::deposit(&mut b, from, units).expect("an account banks its position");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, terms(1_000)))
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
    let (mut env, mut b) = EnvelopeBuilder::new(&composed, &ProtocolHasher, from, HEADER);
    let funds = account::withdraw(&mut b, from, *XRD, amount).expect("an account withdraws");
    let units = staking::Staking::at(pool)
        .stake(&mut b, funds)
        .expect("a pool takes a delegation");
    account::deposit(&mut b, from, units).expect("an account banks its position");
    env.seal(b)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, Vec::new(), &key, terms(1_000)))
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
    executor.execute_batch(&ctx, &store, std::slice::from_ref(&verified))
}

fn witnesses(executed: &ExecutedTx) -> Vec<BeaconWitnessEvent> {
    match &executed.consensus {
        ConsensusReceipt::Succeeded {
            beacon_witness_events,
            ..
        } => beacon_witness_events.clone(),
        other @ ConsensusReceipt::Failed => {
            panic!("the delegation must succeed; receipt = {other:?}")
        }
    }
}

/// The whole channel in one assertion: a delegation to a seated pool is a
/// beacon fact by the time it leaves the engine, with the pool named by
/// the instance that emitted it and the amount carried across as attos.
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
    let executed = executor.execute_batch(&ctx, &store, std::slice::from_ref(&tx));
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
    let sealed = holder.execute_batch(&ctx, &store, std::slice::from_ref(&seal));
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
    let by_holder = holder.execute_batch(&ctx, &store, std::slice::from_ref(&call));
    let by_reader = reader.execute_batch(&ctx, &store, std::slice::from_ref(&call));

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
    let (mut env, mut root) = EnvelopeBuilder::new(&composed, &ProtocolHasher, from, HEADER);
    // The composition every bring-up writes: the seal, and the supply it
    // yields filed where the founder keeps it. Which method seals and
    // which of those nodes exist are the package's own declaration to
    // say.
    instantiate(&mut root, from, pool, ()).expect("a derivable pool answers its seal");
    env.register_instance(meta);
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, Vec::new(), &key, terms(1_000)))
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
    let executed = executor.execute_batch(&ctx, &store, std::slice::from_ref(&tx));
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
    let (_, mut root) = EnvelopeBuilder::new(&chain, &ProtocolHasher, delegator(), HEADER);
    let funds = account::withdraw(&mut root, delegator(), *XRD, 500).expect("an account withdraws");
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
            amount: Stake::from_attos(500),
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
        .transfer_graph(from, from, from, 100)
        .expect("an account answers a transfer");
    let tx = Transaction::new(client().sign(graph, &key, terms(1_000)));
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
    Transaction::new(client().sign(graph, &key, terms(1_000)))
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
    assert!(outsider.body().signature_is_valid());
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
