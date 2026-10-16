//! The VM engine end to end at the seam: signed transfer graphs through
//! derivation, the batch executor, and the movement fold, against a
//! genesis-seeded snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::vm_statics::{config_key, package_key};
use hyperscale_effects_bridge::{
    ProtocolHasher, account_address, admit_package, admit_protocol_package, attach_metadata,
    decode_tree,
};
use hyperscale_engine::genesis::{
    GenesisPackages, account_artifact, draw_key, genesis_world_with_pools, vault_key,
};
use hyperscale_engine::legs::{Classified, Member, PlanDefect};
use hyperscale_engine::{
    Availability, ExecutedTx, ExecutionMode, Executor, FetchedCells, Holds, PROTOCOL_RESOURCE,
    PreviewGrants, PreviewInputs, PreviewOutcome, PreviewReport, ResourceChange, TickBatchContext,
    TickEnvironment, TickTxInput, build_refusal_receipt, genesis_writes,
};
use hyperscale_hbor::{Bytes, Capped, Name, TypeShape};
use hyperscale_storage::{
    Anchored, FeeTerms, NoFeeHolds, SubstateStore, Substates, TickChain, TickOutput,
    VersionedStore, crossing_settlements, fold_state_writes, reclaim_credits, reclaimed,
    with_fee_holds,
};
use hyperscale_transactions::{Ceilings, Client, Terms, default_gas_limits};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, BeaconWitnessRoot, BlockHeight, ComponentAddr, ConsensusReceipt, DeclaredRange,
    Ed25519PrivateKey, EnvelopeExt, EpochWindows, EscrowedValue, EventExt, EventRoot,
    GlobalReceipt, Hash, Inclusion, MAX_DECLARED_RESERVE, MAX_INTENT_VALIDITY_RANGE,
    MerkleInclusionProof, Movement, NetworkId, PriceTable, PrincipalAddr, ProvisionalHolds,
    RETENTION_HORIZON, SettledWrites, ShardId, ShardTrie, StateClaim, StateRoot, StateWrites,
    Stated, SubstateEntry, SubstateKey, TimestampRange, Transaction, TxHash, Verified,
    WeightedTimestamp, absorb_committed_cells, compute_merkle_root, shard_prefix_path, writes_root,
};
use hyperscale_vm_effects::{
    AbiParam, Answered, Composed, CrossingCell, CrossingId, CrossingLeaf, Hash32, InstanceMeta,
    Intent, IntentHash, IntentHeader, IntentTree, Kind, PackageHash, PackageMetadata, ResourceKind,
    Terms as CrossingTerms, Value, fee_hold_key, issued_resource, package_hash,
};
use hyperscale_vm_fixtures::{lottery, lottery_package_hash};
use hyperscale_vm_manifest_builder::{GraphBuilder, IntentBuilder, signing};
use hyperscale_vm_stdlib::{STAKING_MODULE, account, instantiate, staking};
use hyperscale_vm_types::{
    Address, CollectionId, LocalKey, ResourceAddr, SEAL_MATURITY_EPOCHS, SeedWindow, amount_cell,
    attestation_work, encode_amount,
};
use proptest::prelude::*;
use proptest::test_runner::TestRunner;

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

/// The two accounts the transfer cases move funds between, as signing
/// seeds rather than as literal addresses: a withdrawing node admits only
/// the signature its target's address derives from, so an account that
/// spends has to be one a key here derives.
const ALICE_SEED: u8 = 41;
const BOB_SEED: u8 = 42;

/// The ceiling the plain transfer cases sign: above what a transfer
/// prices, so admission would hold and the burn is the declared price
/// rather than the clamp.
const TRANSFER_FEE: u128 = 100;

fn alice() -> PrincipalAddr {
    fee_payer(ALICE_SEED)
}

fn bob() -> PrincipalAddr {
    fee_payer(BOB_SEED)
}

/// A snapshot over the flattened genesis updates.
struct MapDb(BTreeMap<SubstateKey, Vec<u8>>);

impl MapDb {
    fn genesis(accounts: &[(PrincipalAddr, u128)]) -> Self {
        let writes = genesis_writes(accounts, &[], &packages());
        let mut map = BTreeMap::new();
        for (key, change) in writes.cells() {
            let value = change.clone().expect("genesis writes are Set-only");
            map.insert(*key, value);
        }
        Self(map)
    }
}

impl MapDb {
    /// Apply a receipt's committed writes, as the commit path would —
    /// resolving what it moved against what this map holds, which is
    /// what settlement does.
    fn apply(&mut self, writes: &StateWrites) {
        let writes = writes
            .resolve(&mut |key| self.0.get(&key).cloned())
            .expect("the debit fits");
        for (key, change) in writes.cells() {
            match change {
                Some(value) => {
                    self.0.insert(*key, value.clone());
                }
                None => {
                    self.0.remove(key);
                }
            }
        }
    }
}

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

/// The map is the whole world at one version, so every anchor reads the
/// same and the snapshot is a copy of it.
impl Anchored for MapDb {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }
}

/// The store surface a [`TickChain`] needs.
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
        // The map holds no entries at any height.
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

/// The genesis package set this binary runs on.
///
/// The fixture set rather than the protocol's: the randomness cases
/// below settle a lottery round, and a package the state seeds but the
/// world cannot route to — or the reverse — is a chain that cannot call
/// its own code.
fn packages() -> GenesisPackages {
    GenesisPackages::with_fixtures()
}

/// The executor every case here runs on, over that same set.
fn executor(mode: ExecutionMode) -> Executor {
    Executor::with_genesis(&[], &packages(), mode)
}

/// The client this binary builds through: the genesis world, on the one
/// network its envelopes name.
fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> =
        LazyLock::new(|| Client::new(genesis_world_with_pools(&[], &packages()), NETWORK));
    &CLIENT
}

/// The lottery this binary settles rounds on.
///
/// Computed rather than created: the envelope carries the record, and
/// every node composes the same registry from it. What the store holds
/// for it is the seal alone — see [`MapDb::genesis`].
/// The salt every round that needs only one uses.
const ROUND: u8 = 0x4C;

/// A round of its own: a settled round is settled, so a case that
/// settles more than once names a round per settlement.
fn lottery_meta(salt: u8) -> InstanceMeta {
    InstanceMeta {
        package: lottery_package_hash(&ProtocolHasher),
        config: Capped::empty(),
        salt: Hash32([salt; 32]),
    }
}

fn lottery_addr(salt: u8) -> ComponentAddr {
    lottery_meta(salt).address(&ProtocolHasher)
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

fn signed_transfer(seed: u8, from: PrincipalAddr, to: PrincipalAddr, amount: u128) -> Transaction {
    signed_transfer_with_fee(seed, from, to, amount, TRANSFER_FEE)
}

/// A transfer whose recipient signs a floor the withdrawal cannot meet.
fn signed_transfer_under_bound(
    seed: u8,
    from: PrincipalAddr,
    to: PrincipalAddr,
    amount: u128,
    min: u128,
    max_fee: u128,
) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let chain = client().records();
    let mut b = client().builder(&chain, from);
    let funds =
        account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount).expect("an account withdraws");
    account::deposit(&mut b, to, funds.min(min)).expect("an account deposits");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, validity(), terms(max_fee)))
}

/// A transfer drawing on an instance nothing registered.
///
/// The untyped builder writes it because the typed one cannot: refusing a
/// target that resolves to nothing is the gate under test, so a graph that
/// trips it has to be constructed without consulting the world.
fn signed_transfer_from_unknown(
    seed: u8,
    from: ComponentAddr,
    to: PrincipalAddr,
    amount: u128,
    max_fee: u128,
) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let mut b = GraphBuilder::new();
    let [funds] = b.call_signed(
        fee_payer(seed),
        from,
        "withdraw",
        (*PROTOCOL_RESOURCE, amount),
    );
    let [] = b.call(to, "deposit", (funds.resource_is(*PROTOCOL_RESOURCE),));
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, validity(), terms(max_fee)))
}

fn signed_transfer_with_fee(
    seed: u8,
    from: PrincipalAddr,
    to: PrincipalAddr,
    amount: u128,
    max_fee: u128,
) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let graph = client()
        .transfer_graph(from, to, amount)
        .expect("an account answers a transfer");
    Transaction::new(client().sign(graph, &key, validity(), terms(max_fee)))
}

/// The account address the fee-paying tests derive from their signing key.
fn fee_payer(seed: u8) -> PrincipalAddr {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    account_address(&key.public_key().0)
}

/// The opening balances every test in this binary starts from.
///
/// Funding only — an address needs nothing registered before a test can
/// transact with it, so this names who holds what and not who exists.
/// The balances reach a test through the snapshot `execute_on` builds.
fn world_accounts() -> Vec<(PrincipalAddr, u128)> {
    vec![
        (alice(), 1_000),
        (bob(), 50),
        (fee_payer(7), 1_000),
        (fee_payer(11), 110),
        (fee_payer(23), 1_000),
        (fee_payer(31), 1_000),
        (fee_payer(32), 1_000),
    ]
}

/// What `tx` is charged, derived under the executor's own derivation:
/// the figure a test pins a balance against.
fn price_of(executor: &Executor, tx: &Transaction) -> u128 {
    tx.price_under(executor.derivation().as_ref(), &PriceTable::GENESIS)
        .expect("a test transaction derives")
}

fn execute(executor: &Executor, transactions: &[Arc<Verified<Transaction>>]) -> Vec<ExecutedTx> {
    execute_on(&[(alice(), 1_000), (bob(), 50)], executor, transactions)
}

fn signed_settle_with_fee(seed: u8, max_fee: u128, salt: u8) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let chain = client().records();
    let composed = Composed::new(&chain, &[lottery_meta(salt)], &ProtocolHasher);
    let lottery_addr = lottery_meta(salt).address(&ProtocolHasher);
    let mut root = IntentBuilder::new(&composed, &ProtocolHasher, fee_payer(seed), HEADER);
    lottery::Lottery::at(lottery_addr)
        .settle(&mut root, 64)
        .expect("a lottery answers a settlement");
    let tree = root.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, &[&key], terms(max_fee)))
}

/// Genesis state with the lottery this binary draws on made actual.
///
/// Sealed by a transaction rather than seeded, because that is the only
/// way a component becomes actual: the seal commits, and the commit is
/// what teaches the chain to answer for the round every draw below
/// names without carrying anything.
fn with_lottery(accounts: &[(PrincipalAddr, u128)], executor: &Executor) -> MapDb {
    with_rounds(accounts, executor, &[ROUND])
}

/// Genesis state with one round per salt made actual and closed.
///
/// Closed in the setup because these cases are about what a settlement
/// costs its payer, not about when a round ends — and a settlement needs
/// a seal to open.
fn with_rounds(accounts: &[(PrincipalAddr, u128)], executor: &Executor, salts: &[u8]) -> MapDb {
    // Paid by a signer of its own, so the ledger a caller is asserting
    // about carries nothing the setup spent.
    const SEALER_SEED: u8 = 0x5E;
    let mut funded = accounts.to_vec();
    funded.push((fee_payer(SEALER_SEED), 1_000_000));
    let mut store = MapDb::genesis(&funded);
    let key = Ed25519PrivateKey::from_bytes(&[SEALER_SEED; 32]).unwrap();
    for salt in salts {
        let chain = client().records();
        let composed = Composed::new(&chain, &[lottery_meta(*salt)], &ProtocolHasher);
        let round = lottery_meta(*salt).address(&ProtocolHasher);
        let mut root =
            IntentBuilder::new(&composed, &ProtocolHasher, fee_payer(SEALER_SEED), HEADER);
        instantiate(&mut root, round, ()).expect("a derivable round answers its seal");
        let tree = root
            .build_presenting(vec![lottery_meta(*salt)], Vec::new())
            .expect("the intent declares no hole");
        let seal = Transaction::new(client().sign_tree(&tree, &[&key], terms(1_000_000)));
        let executed = execute_batch_on(
            &store,
            executor,
            &[Arc::new(Verified::<Transaction>::from_persisted(seal))],
        );
        let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
            panic!("the seal must settle: {:?}", executed[0].consensus);
        };
        store.apply(writes);
        absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());

        let close = Transaction::new(client().sign_tree(
            &closing_tree(*salt, fee_payer(SEALER_SEED)),
            &[&key],
            terms(1_000_000),
        ));
        let executed = execute_batch_on(
            &store,
            executor,
            &[Arc::new(Verified::<Transaction>::from_persisted(close))],
        );
        let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
            panic!("the close must settle: {:?}", executed[0].consensus);
        };
        store.apply(writes);
    }
    store
}

/// The intent that closes the round at `salt`, for `signer` to sign.
fn closing_tree(salt: u8, signer: PrincipalAddr) -> IntentTree {
    let chain = client().records();
    let composed = Composed::new(&chain, &[lottery_meta(salt)], &ProtocolHasher);
    let mut root = IntentBuilder::new(&composed, &ProtocolHasher, signer, HEADER);
    lottery::Lottery::at(lottery_meta(salt).address(&ProtocolHasher))
        .close(&mut root)
        .expect("a lottery answers a close");
    root.build().expect("the intent declares no hole")
}

/// The environment a round sealed in this file's epoch grid opens
/// under. The grid folds every timestamp to genesis, so a seal records
/// epoch zero and matures two past it.
fn sealed_env(byte: u8) -> TickEnvironment {
    TickEnvironment {
        seeds: SeedWindow::new(
            BTreeMap::from([(SEAL_MATURITY_EPOCHS, [byte; 32])]),
            Some(SEAL_MATURITY_EPOCHS),
        ),
        windows: EpochWindows::new(0),
    }
}

/// Execute `transactions` as a single-shard batch over `store`, under a
/// seed window the caller states.
fn execute_seeded(
    executor: &Executor,
    store: &MapDb,
    env: TickEnvironment,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env,
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
    };
    derived_through(executor, transactions);
    executor
        .execute_batch(&ctx, PriceTable::GENESIS, store, transactions)
        .expect("the harness engine holds every package it runs")
}

/// The settled round a draw wrote, if any.
fn draw_cell(executed: &ExecutedTx) -> Option<Vec<u8>> {
    let writes = executed.consensus.writes()?;
    writes
        .cells
        .get(&draw_key(lottery_addr(ROUND)))
        .cloned()
        .flatten()
}

/// A round settles on what its seal fixed, and on nothing about the
/// attempt that settles it: two transactions, two hashes, two fees —
/// one word.
///
/// This is the whole property. A draw that moved between attempts is a
/// draw a loser can try again for, and every attempt at a settlement is
/// its own transaction.
#[test]
fn a_round_settles_on_what_its_seal_fixed() {
    let executor = executor(ExecutionMode::Serial);
    // The round arrives closed: what varies here is which attempt
    // settles it, never when it ended.
    let store = with_lottery(&[(alice(), 1_000), (bob(), 50)], &executor);

    let settle = |fee: u128| {
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_settle_with_fee(ALICE_SEED, fee, ROUND),
        ))
    };
    let first = settle(20);
    let second = settle(21);
    assert_ne!(first.hash(), second.hash(), "two attempts, two hashes");

    let one = execute_seeded(
        &executor,
        &store,
        sealed_env(0x5E),
        std::slice::from_ref(&first),
    );
    let settled = draw_cell(&one[0]).expect("the settlement wrote the round");
    // Nobody entered, so the round holds the draw and no winner: the
    // draw's thirty-two bytes at the width the record states, and one
    // byte saying there is no winner.
    assert_eq!(settled.len(), 33);

    let other = execute_seeded(
        &executor,
        &store,
        sealed_env(0x5E),
        std::slice::from_ref(&second),
    );
    assert_eq!(
        draw_cell(&other[0]),
        Some(settled.clone()),
        "one seal, one word — whichever attempt asks"
    );

    // And the seed is what the seal committed to, so a chain that rolled
    // a different one settles the round differently.
    let elsewhere = execute_seeded(
        &executor,
        &store,
        sealed_env(0x77),
        std::slice::from_ref(&first),
    );
    assert_ne!(
        draw_cell(&elsewhere[0]),
        Some(settled),
        "a different seed is a different draw"
    );
}

/// Two independent payments into one account, each in its own batch.
///
/// The recipient's vault is a `delta` on both sides, which the mode
/// lattice calls compatible — so nothing defers the second behind the
/// first, and the two may legitimately be included in different blocks.
/// What each receipt then carries is an *absolute* value for the cell,
/// derived from whatever baseline its batch read.
///
/// Threaded, that is right: the second batch reads the first's applied
/// credit and writes the sum. Against a shared baseline it is not: both
/// batches read the same starting balance, both write the same absolute,
/// and whichever settles last silently discards the other's credit.
///
/// Both halves assert threading. The first threads by hand, applying each
/// receipt before the next batch reads; the second threads the way the
/// shard does, through the tick chain, where the payments land in
/// consecutive blocks and the earlier one is committed but not yet
/// settled when the later one executes — the case that used to read a
/// shared baseline.
#[test]
fn consecutive_payments_thread_through_the_tick_chain() {
    let payer_a = fee_payer(31);
    let payer_b = fee_payer(32);
    let hot = bob();
    let accounts = [(payer_a, 1_000), (payer_b, 1_000), (hot, 10)];
    let executor = executor(ExecutionMode::Serial);

    let pay = |seed: u8, from: PrincipalAddr| {
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(seed, from, hot, 100, 10),
        ))
    };

    // Threaded by hand: each batch reads what the previous one committed.
    let mut store = MapDb::genesis(&accounts);
    let mut threaded = Vec::new();
    for (seed, from) in [(31u8, payer_a), (32, payer_b)] {
        let executed = execute_batch_on(&store, &executor, &[pay(seed, from)]);
        let updates = executed[0]
            .consensus
            .writes()
            .expect("a completed payment commits updates");
        threaded.push(vault_cell(&settled_on(updates, &store), hot));
        store.apply(updates);
    }
    assert_eq!(
        threaded,
        vec![
            Some(encode_amount(110).to_vec()),
            Some(encode_amount(210).to_vec())
        ],
        "each payment must land on top of the last"
    );

    // Threaded by the tick chain: two blocks inside one unsettled window.
    // Nothing settles between them, so each block is written carrying
    // neither payment; tick 2's baseline is tick 1's output over it.
    let chain = TickChain::new(Arc::new(MapDb::genesis(&accounts)));
    let mut chained = Vec::new();
    for (height, (seed, from)) in [(31u8, payer_a), (32, payer_b)].into_iter().enumerate() {
        let tick = BlockHeight::new(height as u64 + 1);
        let below = BlockHeight::new(height as u64);
        chain.prune_persisted(below, BlockHeight::GENESIS);
        let baseline = chain.view_at(below);
        let executed = execute_batch_on(&baseline.snapshot(), &executor, &[pay(seed, from)]);
        let updates = executed[0]
            .consensus
            .writes()
            .expect("a completed payment commits updates");
        // Against this tick's own baseline — the state it lands on.
        chained.push(vault_cell(&settled_on(updates, &baseline.snapshot()), hot));
        chain.append(
            tick,
            TickOutput {
                determined: vec![(executed[0].tx_hash, updates.clone())],
                provisional: Vec::new(),
            },
            &[],
        );
    }
    assert_eq!(
        chained, threaded,
        "a payment committed while an earlier one is unsettled must still \
         read the earlier one's credit"
    );
}

/// Derive every member the way admission would, so the engine reads the
/// routed facts off the same caches it executes against.
fn derived_through(executor: &Executor, transactions: &[Arc<Verified<Transaction>>]) {
    for tx in transactions {
        tx.try_derived(executor.derivation().as_ref())
            .expect("a fixture transaction derives");
    }
}

fn execute_on(
    accounts: &[(PrincipalAddr, u128)],
    executor: &Executor,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    execute_batch_on(&MapDb::genesis(accounts), executor, transactions)
}

/// Execute one batch against an explicit store, so a caller can thread
/// committed state between batches the way the commit path does.
fn execute_batch_on(
    snapshot_store: &(dyn Substates + Sync),
    executor: &Executor,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        // A round sealed under this grid records genesis, so the window
        // holds the epoch such a seal matures into — every settlement
        // here opens rather than waiting.
        env: sealed_env(0x5E),
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
    };
    derived_through(executor, transactions);
    executor
        .execute_batch(&ctx, PriceTable::GENESIS, snapshot_store, transactions)
        .expect("the harness engine holds every package it runs")
}

/// A receipt's writes as they settle onto `accounts`.
///
/// A receipt says what it moved, not what the cell ends at, so an
/// assertion about a balance has to name the state the movement lands
/// on. These tests start from `accounts` and settle one batch onto it.
/// A receipt's writes as they settle onto the state they land on.
fn settled_on(writes: &StateWrites, state: &impl Substates) -> SettledWrites {
    writes
        .resolve(&mut |key| state.cell(key))
        .expect("the debit fits")
}

/// The arrivals `consumer` takes, read off the record cells the
/// producer's `writes` hold, as a consumer's arrival index reads the
/// proven record.
fn arrivals_written(
    classified: &Classified,
    writes: &StateWrites,
    consumer: ShardId,
) -> Vec<EscrowedValue> {
    classified
        .edges()
        .iter()
        .filter(|edge| edge.to.contains(&consumer))
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
        .collect()
}

fn settled(writes: &StateWrites, accounts: &[(PrincipalAddr, u128)]) -> SettledWrites {
    eprintln!(
        "SETTLEDBG cells={:?} movements={:?} accounts={:?}",
        writes.cells.keys().collect::<Vec<_>>(),
        writes.movements,
        accounts
            .iter()
            .map(|(o, a)| (vault_key(*o, *PROTOCOL_RESOURCE), a))
            .collect::<Vec<_>>()
    );
    writes
        .resolve(&mut |key| {
            accounts
                .iter()
                .find(|(owner, _)| vault_key(*owner, *PROTOCOL_RESOURCE) == key)
                .and_then(|(_, amount)| amount_cell(*amount).map(|cell| cell.to_vec()))
        })
        .expect("the debit fits")
}

fn vault_cell(writes: &SettledWrites, owner: impl Into<Address>) -> Option<Vec<u8>> {
    writes
        .cells()
        .get(&vault_key(owner, *PROTOCOL_RESOURCE))
        .cloned()
        .flatten()
}

/// Whether the batch removed the vault cell outright — a drain, never a
/// zero write.
fn vault_removed(writes: &SettledWrites, owner: impl Into<Address>) -> bool {
    writes.cells().get(&vault_key(owner, *PROTOCOL_RESOURCE)) == Some(&None)
}

#[test]
fn a_transfer_folds_to_identity_keyed_absolute_updates() {
    let executor = executor(ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
    let executed = execute(&executor, &[Arc::clone(&tx)]);
    assert_eq!(executed.len(), 1);
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        receipt_hash,
        ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };
    assert_ne!(receipt_hash.as_raw(), &Hash::ZERO);
    // Withdraw settled 100 off the sender and the declared price on
    // top — the sender signs, so the sender pays. Deposit credited the
    // recipient. Absolute values, identity-keyed.
    assert_eq!(
        vault_cell(&settled(database_updates, &world_accounts()), alice()),
        Some(encode_amount(1_000 - 100 - price_of(&executor, &tx)).to_vec())
    );
    assert_eq!(
        vault_cell(&settled(database_updates, &world_accounts()), bob()),
        Some(encode_amount(150).to_vec())
    );
}

/// A root acting as two accounts is attested by both, and the client
/// signs it with both keys in the order the root declares: what reaches
/// the chain is the set the builder wrote, each account's sign-in is
/// judged over it, and both commit.
#[test]
fn a_two_account_root_signed_through_the_client_keeps_both_attesters() {
    let executor = executor(ExecutionMode::Serial);
    let alice_key = Ed25519PrivateKey::from_bytes(&[ALICE_SEED; 32]).unwrap();
    let bob_key = Ed25519PrivateKey::from_bytes(&[BOB_SEED; 32]).unwrap();
    let chain = client().records();
    let mut root = IntentBuilder::acting_as(&chain, &ProtocolHasher, &[alice(), bob()], HEADER)
        .expect("two accounts");
    let to_bob = account::withdraw(&mut root, alice(), *PROTOCOL_RESOURCE, 100).unwrap();
    account::deposit(&mut root, bob(), to_bob).unwrap();
    let to_alice = account::withdraw(&mut root, bob(), *PROTOCOL_RESOURCE, 10).unwrap();
    account::deposit(&mut root, alice(), to_alice).unwrap();
    let tree = root.build().expect("one intent, two accounts");
    let tx =
        Transaction::new(client().sign_tree(&tree, &[&alice_key, &bob_key], terms(TRANSFER_FEE)));
    assert_eq!(
        decode_tree(&tx.body().tree).unwrap().root.attested_by,
        [alice(), bob()]
    );
    assert_eq!(tx.body().signatures.len(), 2);

    let tx = Arc::new(Verified::<Transaction>::from_persisted(tx));
    let price = price_of(&executor, &tx);
    let executed = execute(&executor, &[Arc::clone(&tx)]);
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("both sign-ins hold: {:?}", executed[0].consensus);
    };
    let settled = settled(writes, &world_accounts());
    assert_eq!(
        vault_cell(&settled, alice()),
        Some(encode_amount(1_000 - 100 + 10 - price).to_vec())
    );
    assert_eq!(
        vault_cell(&settled, bob()),
        Some(encode_amount(50 + 100 - 10).to_vec())
    );
}

#[test]
fn an_uncovered_withdrawal_aborts_and_the_batch_carries_on() {
    let executor = executor(ExecutionMode::Serial);
    let over = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        BOB_SEED,
        bob(),
        alice(),
        500,
    )));
    let price = price_of(&executor, &over);
    let fine = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        25,
    )));
    let executed = execute(&executor, &[Arc::clone(&over), Arc::clone(&fine)]);
    assert_eq!(executed.len(), 2);
    // Input order is preserved: the infeasible reservation aborts its
    // own transaction only.
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
    assert!(
        matches!(executed[1].consensus, ConsensusReceipt::Succeeded { .. }),
        "the covered transfer must succeed"
    );

    // Commit the batch the way the settlement path does — every settled
    // receipt's writes merged in hash order, later receipts winning per
    // cell. Whichever side of the failure the transfer's hash lands on,
    // the committed end state carries both its movement and the
    // failure's price debit.
    let mut store = MapDb::genesis(&[(alice(), 1_000), (bob(), 50)]);
    let mut ordered: Vec<&ExecutedTx> = executed.iter().collect();
    ordered.sort_by_key(|e| e.tx_hash);
    for e in &ordered {
        if let Some(writes) = e.consensus.writes() {
            store.apply(writes);
        }
        if let Some(writes) = e
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes)
        {
            store.apply(writes);
        }
    }
    assert_eq!(
        store.cell(vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(1_000 - 25 - price_of(&executor, &fine)).to_vec())
    );
    assert_eq!(
        store.cell(vault_key(bob(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(75 - price).to_vec()),
        "the credit lands and the failure's price stays charged"
    );
}

/// A charged failure's debit survives a sibling folded after it.
///
/// Each records what it moved on the vault — the failure its price, the
/// credit its amount — so settling both leaves the vault holding the
/// sum. Neither receipt has to know about the other, which is what a
/// movement buys: an absolute would have had to carry the sibling's
/// debit to avoid reverting it.
#[test]
fn a_failed_charge_survives_a_later_sibling_credit() {
    let executor = executor(ExecutionMode::Serial);
    let failed = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        BOB_SEED,
        bob(),
        alice(),
        500,
    )));
    let price = price_of(&executor, &failed);
    // Receipts fold and commit hash-ascending, and only a credit landing
    // after the failure can revert its debit — so pick a transfer amount
    // whose hash does.
    let (amount, credit) = (100u128..200)
        .map(|amount| {
            let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
                ALICE_SEED,
                alice(),
                bob(),
                amount,
            )));
            (amount, tx)
        })
        .find(|(_, tx)| tx.hash() > failed.hash())
        .expect("some amount in range hashes after the failure");

    let executed = execute(&executor, &[Arc::clone(&failed), Arc::clone(&credit)]);
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[1].consensus else {
        panic!("the credit must succeed");
    };
    // Settle both, in commit order, and the debit is still there.
    let mut db = MapDb::genesis(&world_accounts());
    let charge = executed[0]
        .refusal_receipt
        .as_ref()
        .and_then(|receipt| receipt.writes())
        .expect("a charged failure settles its price");
    db.apply(charge);
    db.apply(writes);
    assert_eq!(
        db.cell(vault_key(bob(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(50 + amount - price).to_vec()),
        "a later sibling's credit must compose with the charged price, not revert it"
    );
}

#[test]
fn serial_and_parallel_scheduling_produce_identical_receipts() {
    let serial = executor(ExecutionMode::Serial);
    let parallel = executor(ExecutionMode::Parallel);
    let txs: Vec<Arc<Verified<Transaction>>> = (0..4u128)
        .map(|i| {
            Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
                ALICE_SEED,
                alice(),
                bob(),
                10 + i,
            )))
        })
        .collect();
    let a = execute(&serial, &txs);
    let b = execute(&parallel, &txs);
    assert_eq!(a.len(), b.len());
    for (left, right) in a.iter().zip(&b) {
        assert_eq!(left.tx_hash, right.tx_hash);
        assert_eq!(left.consensus, right.consensus);
    }
}

/// A completed transfer burns its declared price from the payer's vault
/// as part of the receipt's own writes, so the burn rides the attested
/// `writes_root` and the sync-replayable work items.
#[test]
fn a_completed_transfer_burns_the_fee_ceiling_from_its_payer() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    // A ceiling below the declared price is refused at admission; one
    // that bypassed it burns the ceiling — the backstop clamp working.
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(7, payer, bob(), 100, 10),
    ));
    let executed = execute_on(&accounts, &executor, &[tx]);
    assert_eq!(executed.len(), 1);
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        vault_cell(&settled(database_updates, &accounts), payer),
        Some(encode_amount(1_000 - 100 - 10).to_vec())
    );
    assert_eq!(
        vault_cell(&settled(database_updates, &accounts), bob()),
        Some(encode_amount(150).to_vec())
    );
}

/// A fee-paying call whose manifest never touches the payer's own vault
/// still pays: the batch baseline pre-reads every local payer's vault,
/// so the burn has a cell to debit even when no declared effect loads
/// one. The stamp is the canonical shape — it writes only the entropy
/// leaf.
#[test]
fn a_call_that_never_touches_its_payers_vault_still_pays() {
    let executor = executor(ExecutionMode::Serial);
    // A ceiling below the declared price, bypassing admission, burns
    // exactly the ceiling.
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_settle_with_fee(ALICE_SEED, 10, ROUND),
    ));
    let store = with_lottery(&[(alice(), 1_000), (bob(), 50)], &executor);
    let executed = execute_batch_on(&store, &executor, &[tx]);
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    } = &executed[0].consensus
    else {
        panic!("the draw must succeed: {:?}", executed[0].consensus);
    };
    assert!(
        database_updates
            .cells
            .contains_key(&draw_key(lottery_addr(ROUND))),
        "the draw settled its round"
    );
    assert_eq!(
        vault_cell(&settled(database_updates, &world_accounts()), alice()),
        Some(encode_amount(1_000 - 10).to_vec()),
        "the payer's vault carries the burn even though the manifest never loaded it"
    );
}

/// A batch with two distinct payers keeps each burn in its own receipt:
/// a receipt is one transaction's effect record, so a sibling payer's
/// vault never appears in it — however the batch's canonical fold
/// happens to order the two.
#[test]
fn a_receipt_carries_only_its_own_payers_burn() {
    let payer_a = fee_payer(31);
    let payer_b = fee_payer(32);
    let accounts = [(payer_a, 1_000), (payer_b, 1_000), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    let txs = vec![
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(31, payer_a, bob(), 100, 10),
        )),
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(32, payer_b, bob(), 100, 10),
        )),
    ];
    let executed = execute_on(&accounts, &executor, &txs);

    for (own, sibling, tx) in [
        (payer_a, payer_b, &executed[0]),
        (payer_b, payer_a, &executed[1]),
    ] {
        let ConsensusReceipt::Succeeded { writes, .. } = &tx.consensus else {
            panic!("both transfers must succeed: {:?}", tx.consensus);
        };
        assert_eq!(
            vault_cell(&settled(writes, &accounts), own),
            Some(encode_amount(1_000 - 100 - 10).to_vec()),
            "a receipt carries its own payer's burn"
        );
        assert!(
            !writes
                .cells
                .contains_key(&vault_key(sibling, *PROTOCOL_RESOURCE)),
            "a receipt never carries a sibling payer's vault"
        );
    }
}

/// Three transactions sharing one payer settle to the sum of their
/// burns: each receipt's vault write carries the cumulative debit at its
/// position in the batch's canonical order, so applying the receipts in
/// block order — which is that same order, blocks being strictly
/// hash-sorted — loses none of them.
#[test]
fn shared_payer_burns_accumulate_across_a_batch() {
    // Distinct ceilings make three distinct draws; a draw's fuel
    // exceeds all of them, so each burns exactly its ceiling. Each
    // settles a round of its own, since a settled round is settled.
    const ROUNDS: [u8; 3] = [0x4D, 0x4E, 0x4F];

    let executor = executor(ExecutionMode::Serial);
    let mut txs: Vec<Arc<Verified<Transaction>>> = [10u128, 11, 12]
        .into_iter()
        .zip(ROUNDS)
        .map(|(fee, salt)| {
            Arc::new(Verified::<Transaction>::from_persisted(
                signed_settle_with_fee(ALICE_SEED, fee, salt),
            ))
        })
        .collect();
    txs.sort_by_key(|tx| tx.hash());

    let mut store = with_rounds(&[(alice(), 1_000), (bob(), 50)], &executor, &ROUNDS);
    let executed = execute_batch_on(&store, &executor, &txs);
    for tx in &executed {
        let ConsensusReceipt::Succeeded { writes, .. } = &tx.consensus else {
            panic!("every draw must succeed: {:?}", tx.consensus);
        };
        store.apply(writes);
    }
    assert_eq!(
        store.cell(vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(1_000 - 10 - 11 - 12).to_vec()),
        "every burn in the batch reaches the committed balance"
    );
}

/// A missed edge bound is an infeasibility, not a defect: the sender
/// declared what it would accept and the world moved between signing and
/// execution, and it settles the one declared price like every attempt.
#[test]
fn a_missed_edge_bound_charges_its_payer_the_price() {
    let payer = fee_payer(23);
    let funded = 1_000;
    let accounts = [(payer, funded), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    // The withdrawal is covered and the guest is honest — it returns the
    // 100 it reserved. What fails is the recipient's signed price.
    let tx = signed_transfer_under_bound(23, payer, bob(), 100, 150, 1_000);
    let price = price_of(&executor, &tx);
    let executed = execute_on(
        &accounts,
        &executor,
        &[Arc::new(Verified::<Transaction>::from_persisted(tx))],
    );
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "a missed bound must not apply: {:?}",
        executed[0].consensus
    );

    // The charge stands in for the receipt the execution never produced,
    // which is what keeps state moving through receipts alone.
    let Some(ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    }) = executed[0].refusal_receipt.as_ref()
    else {
        panic!("a charged abort settles a refusal receipt");
    };
    assert_eq!(
        vault_cell(&settled(database_updates, &accounts), payer),
        Some(encode_amount(funded - price).to_vec()),
        "the price and nothing else"
    );
    assert_eq!(
        vault_cell(&settled(database_updates, &accounts), bob()),
        None,
        "the transfer's own effects are discarded"
    );
}

#[test]
fn a_payer_drained_by_its_own_fee_deletes_its_vault() {
    // The burn folds outside the kernel store, so it has to apply the
    // store's delete-on-zero rule itself — otherwise the commonest way a
    // vault empties leaves sixteen zero bytes behind, and a storage bond
    // that can never be refunded.
    let payer = fee_payer(11);
    // Exactly the transfer plus the ceiling: nothing survives the burn.
    let accounts = [(payer, 110), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(11, payer, bob(), 100, 10),
    ));
    let executed = execute_on(&accounts, &executor, &[tx]);
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };

    assert!(
        vault_removed(&settled(database_updates, &accounts), payer),
        "a drained payer vault is deleted, not zeroed"
    );
    // The recipient is untouched by the rule.
    assert_eq!(
        vault_cell(&settled(database_updates, &accounts), bob()),
        Some(encode_amount(150).to_vec())
    );
}

/// An account whose prefix routes to the other half of a two-shard trie
/// from [`alice`], derived by flipping the bit that trie splits on so the
/// pair straddles it whatever address derivation produces.
fn far() -> PrincipalAddr {
    let mut body = alice().body();
    body[0] ^= 0x80;
    PrincipalAddr::new(body)
}

/// The record keys of the crossings `local` issues, in edge order: every
/// one, or those of one `kind`.
fn issued(classified: &Classified, local: ShardId, kind: Option<Kind>) -> Vec<SubstateKey> {
    classified
        .crossings()
        .filter(|(edge, _)| {
            edge.from == local && kind.is_none_or(|kind| edge.crossing.kind == kind)
        })
        .map(|(edge, _)| edge.crossing.id.record_key(&ProtocolHasher))
        .collect()
}

/// Execute one batch as `local_shard` under a two-leaf trie.
fn execute_on_shard(
    executor: &Executor,
    local_shard: ShardId,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let trie = ShardTrie::uniform(1);
    let ctx = TickBatchContext {
        local_shard,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
    };
    derived_through(executor, transactions);
    executor
        .execute_batch(&ctx, PriceTable::GENESIS, &snapshot_store, transactions)
        .expect("the harness engine holds every package it runs")
}

fn events_of(executed: &ExecutedTx) -> Vec<(Address, u32)> {
    let ConsensusReceipt::Succeeded { events, .. } = &executed.consensus else {
        panic!("transfer must succeed: {:?}", executed.consensus);
    };
    events
        .iter()
        .map(|event| (event.emitter, event.event_type))
        .collect()
}

/// A transfer's withdrawal emits from an account on another shard than
/// its recipient. Each shard's receipt keeps only the events its own
/// instances emitted.
#[test]
fn an_event_lands_only_on_its_emitters_home_shard() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    assert_ne!(
        near_shard, far_shard,
        "the two accounts must sit on different shards"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    let sender_side = execute_on_shard(&executor, near_shard, std::slice::from_ref(&tx));
    let recipient_side = execute_on_shard(&executor, far_shard, &[tx]);

    // The deposit is the kernel's and emits nothing, so the recipient's
    // shard keeps no event: the withdrawal's is not its emitter's to hold.
    assert_eq!(events_of(&sender_side[0]), vec![(alice().address(), 0)]);
    assert_eq!(events_of(&recipient_side[0]), vec![]);
}

/// A hundred from alice to `far()`, whose fee `far()` pays.
fn transfer_paid_by_the_recipient() -> Arc<Verified<Transaction>> {
    let key = Ed25519PrivateKey::from_bytes(&[ALICE_SEED; 32]).unwrap();
    let graph = client()
        .transfer_graph(alice(), far(), 100)
        .expect("an account answers a transfer");
    let gas_limits = default_gas_limits(graph.nodes.len());
    let envelope = signing::wrap(
        &IntentTree::of_one(Intent::leaf(HEADER, alice(), graph)),
        signing::Terms {
            fee_payer: far(),
            max_fee: TRANSFER_FEE,
            gas_limits: gas_limits
                .try_into()
                .expect("one ceiling per node, under the node cap"),
            priority_bp: 0,
            message: Bytes::empty(),
        },
    )
    .expect("a transfer fits the tree cap");
    Arc::new(Verified::<Transaction>::from_persisted(Transaction::new(
        signing::sign(envelope, &key, &ProtocolHasher).expect("a transfer signs"),
    )))
}

/// A transfer whose fee payer sits on the recipient's shard never leaves
/// that shard only delivering: the payer's home bears the verdict, so it
/// commits as the core and the fee burns there, once. The sender's shard
/// runs the withdrawal and pays the payment alone, and the crossing into
/// the core is escrowed: the core takes it and credits the recipient.
#[test]
fn a_payer_on_the_recipients_shard_is_the_core_and_pays_once() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let tx = transfer_paid_by_the_recipient();
    derived_through(&executor, std::slice::from_ref(&tx));
    assert_eq!(tx.fee_payer(), far().address());

    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(classified.decomposed());
    assert_eq!(
        classified.core(),
        &BTreeSet::from([far_shard]),
        "the payer's home is the core"
    );
    assert!(classified.commits_at(near_shard) && classified.commits_at(far_shard));
    let edge = classified.edges()[0].clone();
    assert_eq!(
        edge.crossing.kind,
        Kind::Escrowed,
        "a consumer on the core is escrowed, never owed",
    );

    let price = price_of(&executor, &tx);
    let run = |local_shard: ShardId, arrivals: &[EscrowedValue]| {
        let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
        let no_holds = ProvisionalHolds::new();
        let ctx = tick_context(local_shard, &trie, &no_holds);
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: &tx,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            member: Member::of(
                classified.clone(),
                local_shard,
                BTreeSet::from([near_shard, far_shard]),
            ),
            arrivals,
        };
        let executed = executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0);
        let ConsensusReceipt::Succeeded { writes, .. } = &executed.consensus else {
            panic!(
                "{local_shard:?}'s member succeeds: {:?} {:?}",
                executed.consensus, executed.metadata
            );
        };
        // A completed abortable run carries its hold's release in its
        // writes and in its refusal receipt, of which its finalization
        // settles one.
        let released = releases_hold(writes, far(), tx.hash());
        let refusal = executed
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes);
        assert_eq!(
            refusal.is_some_and(|writes| releases_hold(writes, far(), tx.hash())),
            released && refusal.is_some(),
            "{local_shard:?}'s refusal receipt releases exactly where its run does",
        );
        (
            settled(writes, &[(alice(), 1_000), (far(), 50)]),
            arrivals_written(&classified, writes, far_shard),
            released,
        )
    };

    let (sender, escrowed, sender_released) = run(near_shard, &[]);
    assert!(
        !sender_released,
        "the sender's shard charges nothing and releases nothing"
    );
    assert_eq!(
        vault_cell(&sender, alice()),
        Some(encode_amount(1_000 - 100).to_vec()),
        "the sender's shard pays the payment and no fee",
    );
    assert_eq!(
        vault_cell(&sender, far()),
        None,
        "and burns nothing of the payer's"
    );

    let (core, _, core_released) = run(far_shard, &escrowed);
    assert!(
        core_released,
        "the charging member releases its payer's hold"
    );
    assert_eq!(
        vault_cell(&core, far()),
        Some(encode_amount(50 + 100 - price).to_vec()),
        "the core takes the payment and burns the fee from the payer once",
    );
    assert_eq!(
        vault_cell(&core, alice()),
        None,
        "and moves nothing of the sender's"
    );
}

/// A real transfer divides as the classifier says: the sender's shard
/// runs the sign-in and the withdraw and issues one crossing from the
/// withdraw's reserved vault; the recipient's shard runs the deposit
/// against that crossing's attested value, and cannot plan without it.
#[test]
fn a_transfer_plans_one_leg_each_side_of_the_trie() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let divided = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(divided.decomposed(), "a transfer decomposes");
    assert_eq!(divided.core(), &BTreeSet::from([near_shard]));

    let edges = divided.edges();
    assert_eq!(edges.len(), 1, "one value edge crosses");
    let edge = &edges[0];
    assert_eq!(edge.from, near_shard);
    assert_eq!(edge.to, BTreeSet::from([far_shard]));

    let validity_end = tx.validity_range().end_timestamp_exclusive;
    let sender = divided
        .plan(&[], near_shard, validity_end)
        .expect("the sender's legs take no arrival");
    assert!(!sender.legs.is_whole());
    assert!(
        sender.legs.departure(edge.producer, edge.output).is_some(),
        "the withdraw departs",
    );
    assert!(sender.judges.covers(alice()) && !sender.judges.covers(far()));

    // The deposit is the recipient's shard's commit fold, off the
    // record's reading: that shard runs no member of the transfer.
    assert!(!divided.commits_at(far_shard));
    assert!(matches!(
        divided.plan(&[], far_shard, validity_end),
        Err(PlanDefect::NotAParticipant),
    ));
}

/// A shard's share under a classification is the shares of the owners it
/// holds, the terms of the nodes its member runs, and what every shard
/// bears. A divided transfer is committed by the payer's shard alone: it
/// runs the withdraw beside its verification and carries the whole
/// retention, and the recipient's vault, which the recipient's fold
/// credits, is outside its footprint.
#[test]
fn local_shares_cover_what_the_committing_shard_runs() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    assert_ne!(
        near_shard, far_shard,
        "the ends must sit apart for the shares to split"
    );
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, TRANSFER_FEE),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let whole = tx.work();

    let divided = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(
        !divided.commits_at(far_shard),
        "the recipient's shard commits nothing"
    );
    let mine = divided.local_work(&tx, near_shard);
    let verification = attestation_work(&tx.body().signatures).compute;
    assert!(
        mine.compute > verification,
        "the payer's shard runs the withdraw beside its verification"
    );
    assert!(mine.compute < whole.compute + verification);
    assert!(
        mine.footprint < whole.footprint,
        "the recipient's vault is the recipient's fold's"
    );
    assert_eq!(mine.retention, whole.retention);

    let one = ShardTrie::from_leaves([ShardId::ROOT]);
    assert_eq!(
        Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &one)
            .local_work(&tx, ShardId::ROOT),
        *whole,
        "one shard holding everything bears the whole"
    );

    // A package's artifact is read by every shard that instantiates it,
    // and once by each however many of its nodes that shard runs. Borne
    // by one node instead, a shard running only the manifest's later
    // nodes reserves nothing for code it still loads.
    let artifacts = tx.artifacts();
    assert_eq!(
        artifacts.len(),
        1,
        "the transfer calls one package: {artifacts:?}"
    );
    let artifact = artifacts[0].read_bytes;
    assert!(artifact > 0, "the fixture publishes the account's artifact");
    assert!(
        mine.read_bytes >= artifact,
        "the payer's shard reserves the artifact it instantiates: {} against {artifact}",
        mine.read_bytes,
    );

    // And a classification that read no placement bears the whole
    // wherever it is asked. Standing in a single-leaf trie for "no
    // placement" answers that only at the root and drops every owner
    // share anywhere else, which is a price missing its whole footprint.
    let unplaced = Classified::whole();
    for shard in [ShardId::ROOT, near_shard, far_shard] {
        assert_eq!(
            unplaced.local_work(&tx, shard),
            *whole,
            "a shape that runs whole bears the whole on {shard:?}"
        );
    }
}

/// A transfer executed divided, end to end through the engine: the
/// sender's shard runs the withdraw and escrows the value into the record
/// cell the plan filed, which is what the recipient reads. The recipient's shard
/// runs nothing: its fold credits the deposit off the record.
#[test]
fn a_transfer_executes_divided_on_the_payers_shard() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(classified.decomposed());
    let edge = classified.edges()[0].clone();

    let run = |local_shard: ShardId, arrivals: &[EscrowedValue]| {
        let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
        let ctx = TickBatchContext {
            local_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
            fee_holds: &NoFeeHolds,
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: &tx,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            // A leg awaiting nobody but its own shard: nothing retracts
            member: Member::of(
                classified.clone(),
                local_shard,
                BTreeSet::from([near_shard, far_shard]),
            ),
            arrivals,
        };
        executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0)
    };

    let sender = run(near_shard, &[]);
    let ConsensusReceipt::Succeeded { writes, .. } = &sender.consensus else {
        panic!("the sender's legs must succeed: {:?}", sender.metadata);
    };
    assert_eq!(
        arrivals_written(&classified, writes, far_shard),
        vec![EscrowedValue {
            node: edge.producer,
            output: edge.output,
            resource: *PROTOCOL_RESOURCE,
            amount: 100,
            record: edge.crossing.id.record_key(&ProtocolHasher),
        }],
        "the withdraw's value left into the record cell the plan filed, and the recipient reads it there",
    );
    let record = writes
        .cells
        .get(&edge.crossing.id.record_key(&ProtocolHasher))
        .and_then(|value| CrossingCell::from_bytes(value.as_deref()?))
        .expect("the record cell is among the sender's writes");
    assert_eq!(
        record.validity_end_ms,
        tx.validity_range().end_timestamp_exclusive.as_millis(),
        "the record states the transaction's own validity end"
    );
    assert_ne!(record.validity_end_ms, 0, "and never nothing");
    assert_eq!(
        CrossingId::of_record(edge.crossing.id.producer, &record),
        edge.crossing.id,
        "the record rebuilds the crossing the plan filed"
    );
    assert!(
        !writes
            .movements
            .keys()
            .any(|key| key.owner == far().address()),
        "the sender ran no leg of the recipient's"
    );

    let recipient = run(far_shard, &arrivals_written(&classified, writes, far_shard));
    assert_eq!(
        recipient.consensus,
        ConsensusReceipt::Failed,
        "the recipient's shard has no plan: nothing it runs takes the crossing",
    );
}

/// A transfer's crossing is the recipient's, so nothing takes it back:
/// the sender's shard issues it owed, names no escrowed record of it,
/// and the record stands holding the value for whoever claims it.
#[test]
fn a_delivered_crossing_is_no_ones_to_take_back() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(classified.decomposed());
    let edge = classified.edges()[0].clone();

    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let run = |store: &MapDb, member: Member| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
            fee_holds: &NoFeeHolds,
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: &tx,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            member,
            arrivals: &[],
        };
        executor
            .execute_tick_batch(&ctx, store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0)
    };

    let sent = run(
        &store,
        Member::of(
            classified.clone(),
            near_shard,
            std::iter::once(near_shard)
                .chain(edge.to.iter().copied())
                .collect(),
        ),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    store.apply(writes);
    assert_eq!(
        store.cell(vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(900).to_vec()),
        "the escrow debited the vault"
    );

    assert!(
        issued(&classified, near_shard, Some(Kind::Escrowed)).is_empty(),
        "the sender settles none of it under the transaction's own name",
    );

    assert!(
        store
            .cell(edge.crossing.id.record_key(&ProtocolHasher))
            .is_some(),
        "and the record stands, holding the value for whoever claims it"
    );
}

/// The claim a block of the producer's shard carries once the
/// consumer's `Taken` for `id` is read present at some anchor of the
/// consumer's, named for the crossing and stating the answer the
/// consumer writes on reading `record`: what licenses the fold to
/// remove that record.
fn taken_read_present(id: CrossingId, consumer: ShardId, record: &[u8]) -> StateClaim {
    let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
    let cell = CrossingCell::from_bytes(record).expect("the record decodes");
    let took = id
        .answer(cell.tx, Answered::Taken, cell.validity_end_ms)
        .to_bytes();
    StateClaim::new(
        Anchor {
            shard: consumer,
            height: BlockHeight::new(5),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(5_000),
        },
        [(taken, Inclusion::Present(jmt_value_hash(&took)))],
        MerkleInclusionProof::dummy(),
    )
    .naming([(taken, id)])
}

/// Apply to `store` what the commit fold does for `claims`, and return
/// what it removed.
fn fold_settlements(store: &mut MapDb, claims: &[StateClaim]) -> Vec<SubstateKey> {
    let fresh = claims
        .iter()
        .map(|claim| claim.anchor.ts)
        .max()
        .unwrap_or(WeightedTimestamp::ZERO);
    let settled = crossing_settlements(
        claims,
        ShardId::ROOT,
        fresh,
        &SettledWrites::default(),
        store,
    );
    let mut writes = StateWrites::default();
    for key in &settled.removed {
        writes.cells.insert(*key, None);
    }
    for (key, value) in settled.seen {
        writes.cells.insert(key, Some(value));
    }
    store.apply(&writes);
    settled.removed
}

/// Once the recipient's claim is on record, the sender's shard removes
/// the record it held for it in its commit fold: the block carries the
/// consumer's `Taken` read present, named for the crossing, and that
/// reading is the whole licence. No node, no fee, nothing moved, and a
/// later block with the same reading finds nothing left to remove.
#[test]
fn a_consumers_taken_read_present_retires_the_record_in_the_fold() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let far_shard = trie.shard_for_prefix(far());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    let edge = classified.edges()[0].clone();

    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let ctx = TickBatchContext {
        local_shard: near_shard,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
    };
    let input = TickTxInput {
        prices: PriceTable::GENESIS,
        tx_hash: tx.hash(),
        transaction: &tx,
        provisions: &[],
        clock: WeightedTimestamp::from_millis(1_000),
        member: Member::of(
            classified,
            near_shard,
            std::iter::once(near_shard)
                .chain(edge.to.iter().copied())
                .collect(),
        ),
        arrivals: &[],
    };
    let sent = executor
        .execute_tick_batch(&ctx, &store, &[input])
        .expect("the harness engine holds every package it runs")
        .remove(0);
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    store.apply(writes);
    let record = edge.crossing.id.record_key(&ProtocolHasher);
    let written = store.cell(record).expect("the record is written");

    let claim = taken_read_present(edge.crossing.id, far_shard, &written);
    assert_eq!(
        fold_settlements(&mut store, std::slice::from_ref(&claim)),
        vec![record],
        "the Taken read present licenses removing the record and nothing else",
    );
    assert!(
        store.cell(record).is_none(),
        "the record is removed where it is retired; its consumer reads it gone at an \
         anchor at or above its read frontier"
    );
    assert_eq!(
        store.cell(vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(900).to_vec()),
        "and the value stays where the claim took it"
    );
    assert!(
        fold_settlements(&mut store, &[claim]).is_empty(),
        "a second block carrying the reading has nothing left to remove",
    );
}

/// A store holding the record an outbound leg wrote — what a reshape
/// successor inherits: leaves, and no ledger to read them beside.
struct Inherited {
    trie: ShardTrie,
    store: MapDb,
    record: SubstateKey,
    crossing: CrossingId,
}

/// Run the sending half over a fresh store, so the record stands with
/// the value behind it.
fn inherited_record() -> Inherited {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    let edge = classified.edges()[0].clone();
    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let ctx = TickBatchContext {
        local_shard: shard,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
    };
    let input = TickTxInput {
        prices: PriceTable::GENESIS,
        tx_hash: tx.hash(),
        transaction: &tx,
        provisions: &[],
        clock: WeightedTimestamp::from_millis(1_000),
        member: Member::of(
            classified,
            shard,
            std::iter::once(shard)
                .chain(edge.to.iter().copied())
                .collect(),
        ),
        arrivals: &[],
    };
    let sent = executor
        .execute_tick_batch(&ctx, &store, &[input])
        .expect("the harness engine holds every package it runs")
        .remove(0);
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    store.apply(writes);
    Inherited {
        trie,
        store,
        record: edge.crossing.id.record_key(&ProtocolHasher),
        crossing: edge.crossing.id,
    }
}

/// A record a shard inherited with a prefix is removed in the commit
/// fold where its consumer claimed: the block carries the consumer's
/// `Taken` read present, named for the crossing, and the value stays
/// where the claim took it.
///
/// No member runs at all, which is the point — a merge successor's
/// store arrives as a prefix of leaves and its ledger begins empty, so
/// the leaf and the reading are the whole of what the removal works
/// from. The licence is a presence its own chain committed.
#[test]
fn an_inherited_record_is_retired_in_the_fold_where_its_consumer_claimed() {
    let mut held = inherited_record();
    let consumer = held.trie.shard_for_prefix(far());
    let written = Substates::cell(&held.store, held.record).expect("the record stands");
    let claim = taken_read_present(held.crossing, consumer, &written);
    assert_eq!(
        fold_settlements(&mut held.store, &[claim]),
        vec![held.record]
    );
    assert!(
        Substates::cell(&held.store, held.record).is_none(),
        "a claimed crossing's record is removed"
    );
    assert_eq!(
        Substates::cell(&held.store, vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(900).to_vec()),
        "and the value stays where the claim took it"
    );
}

/// The context of a tick on `local_shard` at the fixtures' clock, over a
/// baseline with `holds` standing on it.
fn tick_context<'a>(
    local_shard: ShardId,
    trie: &'a ShardTrie,
    holds: &'a ProvisionalHolds,
) -> TickBatchContext<'a> {
    TickBatchContext {
        local_shard,
        shard_trie: trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds,
        fee_holds: &NoFeeHolds,
    }
}

/// One member alone through a tick over `snapshot`, at the fixtures'
/// clock and the genesis prices.
fn run_alone(
    executor: &Executor,
    ctx: &TickBatchContext<'_>,
    snapshot: &(dyn Substates + Sync),
    transaction: &Arc<Verified<Transaction>>,
    member: Member,
) -> ExecutedTx {
    let input = TickTxInput {
        prices: PriceTable::GENESIS,
        tx_hash: transaction.hash(),
        transaction,
        provisions: &[],
        clock: WeightedTimestamp::from_millis(1_000),
        member,
        arrivals: &[],
    };
    executor
        .execute_tick_batch(ctx, snapshot, &[input])
        .expect("the harness engine holds every package it runs")
        .remove(0)
}

/// A tick chain over `accounts` whose tick at `height` ran `spending`,
/// a payment between two accounts of one shard, and has not settled it:
/// its determined writes stand in the chain and not in the base.
fn chain_owing_a_payment(
    executor: &Executor,
    trie: &ShardTrie,
    accounts: &[(PrincipalAddr, u128)],
    spending: &Arc<Verified<Transaction>>,
    height: BlockHeight,
) -> TickChain<MapDb> {
    let shard = trie.shard_for_prefix(spending.fee_payer());
    let chain = TickChain::new(Arc::new(MapDb::genesis(accounts)));
    let no_holds = ProvisionalHolds::new();
    let ran = run_alone(
        executor,
        &tick_context(shard, trie, &no_holds),
        &chain.view_at(BlockHeight::GENESIS).snapshot(),
        spending,
        Member::of(
            Classified::freeze(
                spending.legs(),
                spending.fee_payer(),
                spending.accounts(),
                trie,
            ),
            shard,
            BTreeSet::from([shard]),
        ),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &ran.consensus else {
        panic!("the payment completes: {:?}", ran.metadata);
    };
    chain.append(
        height,
        TickOutput {
            determined: vec![(ran.tx_hash, writes.clone())],
            provisional: Vec::new(),
        },
        &[],
    );
    chain.prune_persisted(height, BlockHeight::GENESIS);
    chain
}

/// Whether the determined half of the tick that ran `executed` settles
/// a `Taken` and a `Never` for `id`, in that order: read off the
/// member's effects where it completed, and off its refusal receipt
/// where it did not.
fn answers_settled(executed: &ExecutedTx, id: CrossingId) -> (bool, bool) {
    let settled = match &executed.consensus {
        ConsensusReceipt::Succeeded { writes, .. } => Some(writes),
        ConsensusReceipt::Failed => executed
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes),
    };
    let written = |answered: Answered| {
        let key = id.answer_key(&ProtocolHasher, answered);
        settled.is_some_and(|writes| writes.cells.get(&key).is_some_and(Option::is_some))
    };
    (written(Answered::Taken), written(Answered::Never))
}

/// The consumer's shard of a payment escrowed on its producer's shard,
/// halted: the core alone of the payment, whose payer's vault holds one
/// payment and its price, and the tick at [`HaltedOverASpentVault::FRONTIER`]
/// running that payer's own payment, its determined writes unsettled.
struct HaltedOverASpentVault {
    executor: Executor,
    trie: ShardTrie,
    consumer: ShardId,
    taking: Arc<Verified<Transaction>>,
    core: Member,
    arrivals: Vec<EscrowedValue>,
    crossing: CrossingId,
    chain: TickChain<MapDb>,
}

impl HaltedOverASpentVault {
    /// The recovery's attested frontier, the tick that spent the vault.
    const FRONTIER: BlockHeight = BlockHeight::new(1);

    fn new() -> Self {
        let executor = executor(ExecutionMode::Serial);
        let trie = ShardTrie::uniform(1);
        let (producer, consumer) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
        let seeds = seeds_on(&trie, consumer);
        let (payer, recipient, creditor) = (
            fee_payer(seeds[0]),
            fee_payer(seeds[1]),
            fee_payer(seeds[2]),
        );

        let taking = transfer_paid_by(ALICE_SEED, alice(), recipient, 100, payer);
        let spending = verified(signed_transfer(seeds[0], payer, creditor, 100));
        derived_through(&executor, &[Arc::clone(&taking), Arc::clone(&spending)]);
        let classified =
            Classified::freeze(taking.legs(), taking.fee_payer(), taking.accounts(), &trie);
        assert_eq!(classified.core(), &BTreeSet::from([consumer]));
        let edge = classified.edges()[0].clone();
        assert_eq!(edge.crossing.kind, Kind::Escrowed);
        let both = BTreeSet::from([producer, consumer]);
        let core = Member::of(classified.clone(), consumer, both.clone());
        assert!(!core.abortable(), "the core settles on its own certificate");

        let accounts = [
            (alice(), 1_000),
            (payer, 100 + price_of(&executor, &spending)),
        ];
        let no_holds = ProvisionalHolds::new();

        // The producer's leg, whose record the consumer's chain read live.
        let escrowing = run_alone(
            &executor,
            &tick_context(producer, &trie, &no_holds),
            &MapDb::genesis(&accounts),
            &taking,
            Member::of(classified.clone(), producer, both),
        );
        let arrivals = arrivals_written(
            &classified,
            escrowing
                .consensus
                .writes()
                .expect("the producer's shard escrows the payment"),
            consumer,
        );
        assert_eq!(arrivals.len(), 1, "the payment crossed once");

        let chain = chain_owing_a_payment(&executor, &trie, &accounts, &spending, Self::FRONTIER);
        Self {
            executor,
            trie,
            consumer,
            taking,
            core,
            arrivals,
            crossing: edge.crossing.id,
            chain,
        }
    }

    /// The core member run over the chain's reads at `at`.
    fn run_at(&self, at: BlockHeight) -> ExecutedTx {
        let view = self.chain.view_at(at);
        let holds = view.holds();
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: self.taking.hash(),
            transaction: &self.taking,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            member: self.core.clone(),
            arrivals: &self.arrivals,
        };
        self.executor
            .execute_tick_batch(
                &tick_context(self.consumer, &self.trie, &holds),
                &view.snapshot(),
                &[input],
            )
            .expect("the harness engine holds every package it runs")
            .remove(0)
    }
}

/// A run of a tick over a baseline a halt recovery withdrew is not the
/// run its chain made, which is why a recovery runs no tick a second
/// time.
///
/// The tick above the frontier runs the core over a vault the frontier
/// tick already spent: its price is not covered, it is refused, and the
/// refusal receipt its determined half settles answers the crossing
/// `Never`, which is what the producer credits the value back on. With
/// the frontier tick's writes withdrawn from the chain's reads, the same
/// member off the same arrival takes the crossing instead.
#[test]
fn a_run_over_a_withdrawn_baseline_is_not_the_run_its_chain_made() {
    let halted = HaltedOverASpentVault::new();
    let at = HaltedOverASpentVault::FRONTIER;

    let (taken, never) = answers_settled(&halted.run_at(at), halted.crossing);
    assert!(
        never && !taken,
        "the halted chain's own run declines the crossing: taken {taken}, never {never}",
    );

    halted.chain.raise_floor(at);
    let (taken, never) = answers_settled(&halted.run_at(at), halted.crossing);
    assert!(
        taken && !never,
        "a run over the withdrawn baseline takes what its chain declined: taken {taken}, \
         never {never}",
    );
}

/// A core member the halted chain's own run declined lands no take once
/// its shard recovers: no tick below the bridge runs again, so what
/// stands past the crossing block answers the crossing neither way.
///
/// The halted chain holds the declining run of the tick above the
/// frontier. The crossing block raises the floor to its parent, a coast
/// block above that tick, so every run below it is withdrawn and none
/// is made again: the chain past the crossing reads no answer of the
/// crossing, the decline its lost tail settled is not read as one, and
/// no take reaches the payer's shard.
#[test]
fn a_harvested_tick_lands_no_take_its_abandoned_tail_declined() {
    let halted = HaltedOverASpentVault::new();
    let tail = HaltedOverASpentVault::FRONTIER.next();
    let declined = halted.run_at(HaltedOverASpentVault::FRONTIER);
    assert_eq!(answers_settled(&declined, halted.crossing), (false, true));
    let refused = declined
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a refused core settles its refusal receipt");
    halted.chain.append(
        tail,
        TickOutput {
            determined: vec![(declined.tx_hash, refused.clone())],
            provisional: Vec::new(),
        },
        &[],
    );

    let crossing_parent = tail.next();
    halted.chain.raise_floor(crossing_parent);
    halted
        .chain
        .prune_persisted(crossing_parent, BlockHeight::GENESIS);
    let past = halted.chain.view_at(crossing_parent).snapshot();
    for answered in [Answered::Taken, Answered::Never] {
        assert_eq!(
            past.cell(halted.crossing.answer_key(&ProtocolHasher, answered)),
            None,
            "the chain past the crossing reads no {answered:?} for the crossing",
        );
    }
}

/// A divided batch attests only what it ran. Each side's event root
/// covers the events its own emitters produced — what its receipt
/// stores — so the hash a shard signs is recomputable from exactly what
/// it keeps. A participant running only its own legs could not assemble
/// a union, and two attesting different unions under one signed root
/// would contradict each other.
#[test]
fn a_divided_batch_hashes_only_its_own_emitters_events() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let run = |local_shard: ShardId| {
        let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
        let ctx = TickBatchContext {
            local_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
            fee_holds: &NoFeeHolds,
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: &tx,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            member: Member::of(
                Classified::whole(),
                local_shard,
                BTreeSet::from([near_shard, far_shard]),
            ),
            arrivals: &[],
        };
        executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0)
    };
    let (sender_side, recipient_side) = (run(near_shard), run(far_shard));

    // The deposit is the kernel's and emits nothing, so the recipient's
    // root covers no event.
    assert_eq!(events_of(&sender_side), vec![(alice().address(), 0)]);
    assert_eq!(events_of(&recipient_side), vec![]);
    for side in [&sender_side, &recipient_side] {
        let ConsensusReceipt::Succeeded {
            receipt_hash,
            writes,
            events,
            ..
        } = &side.consensus
        else {
            panic!("the leg must succeed: {:?}", side.consensus);
        };
        let event_hashes: Vec<Hash> = events.iter().map(EventExt::hash).collect();
        let recomputed = GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            BeaconWitnessRoot::ZERO,
            writes_root(writes),
        )
        .receipt_hash();
        assert_eq!(
            *receipt_hash, recomputed,
            "the hash a divided member signs covers exactly what it stores",
        );
    }
}

/// A reservation is judged against committed balance less what
/// unresolved legs already hold, and a refusal fails the leg whole: the
/// receipt is `Failed` and carries no writes, exactly like any other
/// abort. The same transfer with nothing held completes, so the hold is
/// what refused it.
#[test]
fn a_provisional_hold_refuses_a_reservation_and_fails_the_leg() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        far(),
        100,
    )));
    let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let mut holds = ProvisionalHolds::new();
    holds
        .entry(vault_key(alice(), *PROTOCOL_RESOURCE))
        .or_default()
        .insert(Hash::from_bytes(b"an unresolved leg").into(), 950);
    let ctx = TickBatchContext {
        local_shard: near_shard,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &holds,
        fee_holds: &NoFeeHolds,
    };
    derived_through(&executor, std::slice::from_ref(&tx));
    let executed = executor
        .execute_batch(
            &ctx,
            PriceTable::GENESIS,
            &snapshot_store,
            std::slice::from_ref(&tx),
        )
        .expect("the harness engine holds every package it runs");
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "a reservation the hold leaves uncovered must fail its leg: {:?}",
        executed[0].consensus
    );

    let unheld = TickBatchContext {
        holds: &ProvisionalHolds::new(),
        fee_holds: &NoFeeHolds,
        ..ctx
    };
    let executed = executor
        .execute_batch(&unheld, PriceTable::GENESIS, &snapshot_store, &[tx])
        .expect("the harness engine holds every package it runs");
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "with nothing held the same transfer completes: {:?}",
        executed[0].consensus
    );
}

/// `amount` from `from` to `to`, signed by `seed`, whose fee `payer`
/// pays.
fn transfer_paid_by(
    seed: u8,
    from: PrincipalAddr,
    to: PrincipalAddr,
    amount: u128,
    payer: PrincipalAddr,
) -> Arc<Verified<Transaction>> {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let graph = client()
        .transfer_graph(from, to, amount)
        .expect("an account answers a transfer");
    let gas_limits = default_gas_limits(graph.nodes.len());
    let envelope = signing::wrap(
        &IntentTree::of_one(Intent::leaf(HEADER, from, graph)),
        signing::Terms {
            fee_payer: payer,
            max_fee: TRANSFER_FEE,
            gas_limits: gas_limits
                .try_into()
                .expect("one ceiling per node, under the node cap"),
            priority_bp: 0,
            message: Bytes::empty(),
        },
    )
    .expect("a transfer fits the tree cap");
    verified(Transaction::new(
        signing::sign(envelope, &key, &ProtocolHasher).expect("a transfer signs"),
    ))
}

/// Every reservation of a batch is judged against the batch's baseline
/// before any body runs, so no credit a batch-mate makes funds one:
/// what the batch's determined members reserve and take from a vault
/// settles onto the state below the batch.
///
/// The vault holds a hundred. One batch runs a transfer of fifty into
/// it, paid for from another shard and so awaiting that shard's verdict,
/// beside two transfers of sixty out of it that nothing can retract. A
/// transfer's withdrawal is a reservation, so the second is refused
/// against the hundred whatever the crediting member is: this holds
/// with no credit withheld, and pins that order of judgement.
#[test]
fn a_reservation_is_judged_before_a_batch_mates_credit_lands() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near = trie.shard_for_prefix(alice());
    let far_shard = trie.shard_for_prefix(far());
    let near_seeds: Vec<u8> = (50..=u8::MAX)
        .filter(|seed| trie.shard_for_prefix(fee_payer(*seed)) == near)
        .collect();
    let (holder_seed, sponsor_seed) = (near_seeds[0], near_seeds[1]);
    let (holder, sponsor) = (fee_payer(holder_seed), fee_payer(sponsor_seed));
    let vault = vault_key(holder, *PROTOCOL_RESOURCE);
    let accounts = [
        (alice(), 1_000),
        (far(), 1_000),
        (holder, 100),
        (sponsor, 1_000),
    ];
    let store = MapDb::genesis(&accounts);

    let crediting = transfer_paid_by(ALICE_SEED, alice(), holder, 50, far());
    // Receipts apply in canonical order, so the debits are two that fall
    // behind the credit.
    let debiting: Vec<Arc<Verified<Transaction>>> = near_seeds[2..]
        .iter()
        .map(|seed| transfer_paid_by(holder_seed, holder, fee_payer(*seed), 60, sponsor))
        .filter(|tx| tx.hash() > crediting.hash())
        .take(2)
        .collect();
    assert_eq!(debiting.len(), 2, "two debits fall behind the credit");
    let batch: Vec<Arc<Verified<Transaction>>> = std::iter::once(crediting.clone())
        .chain(debiting.iter().cloned())
        .collect();
    derived_through(&executor, &batch);

    let member_of = |tx: &Transaction| {
        let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
        let reach: BTreeSet<ShardId> = [near, trie.shard_for_prefix(tx.fee_payer())].into();
        Member::of(classified, near, reach)
    };
    assert!(
        member_of(&crediting).abortable(),
        "the payer's shard can still discard the credit"
    );
    for tx in &debiting {
        let member = member_of(tx);
        assert_eq!(member.reach(), &BTreeSet::from([near]));
        assert!(!member.abortable(), "nothing retracts a debit");
    }

    let provisions = [Arc::new(
        store
            .0
            .iter()
            .filter(|(key, _)| trie.shard_for_prefix(key.owner) == far_shard)
            .map(|(key, value)| {
                SubstateEntry::new(
                    *key,
                    Some(Bytes::new(value.clone()).expect("a genesis cell fits a leaf")),
                )
            })
            .collect::<Vec<_>>(),
    )];
    let no_holds = ProvisionalHolds::new();
    let ctx = tick_context(near, &trie, &no_holds);
    let inputs: Vec<TickTxInput<'_>> = batch
        .iter()
        .map(|tx| TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: tx,
            provisions: &provisions,
            clock: WeightedTimestamp::from_millis(1_000),
            member: member_of(tx),
            arrivals: &[],
        })
        .collect();
    let executed = executor
        .execute_tick_batch(&ctx, &store, &inputs)
        .expect("the harness engine holds every package it runs");

    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!(
            "the crediting member completes: {:?} {:?}",
            executed[0].consensus, executed[0].metadata
        );
    };
    assert_eq!(writes.movements[&vault].credit, 50);

    // The determined half: every member nothing can retract, in
    // canonical order, settled onto the state below the batch.
    let mut determined = StateWrites::default();
    for ran in &executed[1..] {
        if let Some(writes) = ran.consensus.writes() {
            fold_state_writes(&mut determined, writes);
        }
    }
    let debited = determined
        .movements
        .get(&vault)
        .map_or(0, |movement| movement.debit);
    assert!(
        determined.resolve(&mut |key| store.cell(key)).is_ok(),
        "the determined members debit {debited} from a vault holding 100 below the batch"
    );
}

/// The accounts [`fee_payer`] derives that sit on `shard`, by seed.
fn seeds_on(trie: &ShardTrie, shard: ShardId) -> Vec<u8> {
    (50..=u8::MAX)
        .filter(|seed| trie.shard_for_prefix(fee_payer(*seed)) == shard)
        .collect()
}

/// One member of a batch: its name, its body and what it runs as.
type Seated<'a> = (TxHash, &'a Arc<Verified<Transaction>>, Member);

/// One batch through a tick on the sender's shard over `store`, with
/// every cell of the far shard provisioned. Answers in the order given.
fn run_beside(
    executor: &Executor,
    trie: &ShardTrie,
    store: &MapDb,
    members: &[Seated<'_>],
) -> Vec<ExecutedTx> {
    let (near, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let provisions = [Arc::new(
        store
            .0
            .iter()
            .filter(|(key, _)| trie.shard_for_prefix(key.owner) == far_shard)
            .map(|(key, value)| {
                SubstateEntry::new(
                    *key,
                    Some(Bytes::new(value.clone()).expect("a genesis cell fits a leaf")),
                )
            })
            .collect::<Vec<_>>(),
    )];
    let no_holds = ProvisionalHolds::new();
    let ctx = tick_context(near, trie, &no_holds);
    let inputs: Vec<TickTxInput<'_>> = members
        .iter()
        .map(|(tx_hash, transaction, member)| TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: *tx_hash,
            transaction,
            provisions: &provisions,
            clock: WeightedTimestamp::from_millis(1_000),
            member: member.clone(),
            arrivals: &[],
        })
        .collect();
    let mut executed = executor
        .execute_tick_batch(&ctx, store, &inputs)
        .expect("the harness engine holds every package it runs");
    let place = |tx_hash| members.iter().position(|(named, _, _)| *named == tx_hash);
    executed.sort_by_key(|ran| place(ran.tx_hash));
    executed
}

/// What `tx` runs as on the sender's shard, reaching its payer's.
fn member_beside(tx: &Transaction, trie: &ShardTrie) -> Member {
    let near = trie.shard_for_prefix(alice());
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
    let reach: BTreeSet<ShardId> = [near, trie.shard_for_prefix(tx.fee_payer())].into();
    Member::of(classified, near, reach)
}

/// The members of `executed` behind its first: how many completed, and
/// everything they settle, a refused one's charge included.
fn settled_behind(executed: &[ExecutedTx]) -> (usize, StateWrites) {
    let mut settled = StateWrites::default();
    let mut completed = 0;
    for ran in &executed[1..] {
        completed += usize::from(matches!(ran.consensus, ConsensusReceipt::Succeeded { .. }));
        let refusal = ran.refusal_receipt.as_ref();
        for writes in [
            ran.consensus.writes(),
            refusal.and_then(ConsensusReceipt::writes),
        ]
        .into_iter()
        .flatten()
        {
            fold_state_writes(&mut settled, writes);
        }
    }
    (completed, settled)
}

/// One batch over a sponsor's vault holding exactly one member's price:
/// a transfer of a second price into it, whose own fee `credit_payer`
/// pays, ahead of two transfers between other accounts that the sponsor
/// pays for. A fee is burned by delta, so each burn is judged in its
/// own session over the batch's baseline and again where the batch's
/// receipts are applied in canonical order, behind the credit.
///
/// Answers what ran, the crediting member first, and the state below
/// the batch.
fn two_burns_behind_a_credit(credit_payer: PrincipalAddr) -> (Vec<ExecutedTx>, MapDb) {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let seeds = seeds_on(&trie, trie.shard_for_prefix(alice()));
    let (holder, sponsor) = (fee_payer(seeds[0]), fee_payer(seeds[1]));
    let paid_by_sponsor =
        |seed: &u8| transfer_paid_by(seeds[0], holder, fee_payer(*seed), 1, sponsor);
    let price = price_of(&executor, &paid_by_sponsor(&seeds[2]));
    let store = MapDb::genesis(&[
        (alice(), 1_000),
        (far(), 1_000),
        (holder, 1_000),
        (sponsor, price),
    ]);

    let crediting = transfer_paid_by(ALICE_SEED, alice(), sponsor, price, credit_payer);
    let burning: Vec<Arc<Verified<Transaction>>> = seeds[2..]
        .iter()
        .map(paid_by_sponsor)
        .filter(|tx| tx.hash() > crediting.hash())
        .take(2)
        .collect();
    assert_eq!(burning.len(), 2, "two burns fall behind the credit");
    let batch: Vec<Arc<Verified<Transaction>>> = std::iter::once(crediting.clone())
        .chain(burning.iter().cloned())
        .collect();
    derived_through(&executor, &batch);
    for tx in &burning {
        assert_eq!(price_of(&executor, tx), price, "one price for each burn");
        assert!(!member_beside(tx, &trie).abortable());
    }
    assert_eq!(
        member_beside(&crediting, &trie).abortable(),
        credit_payer == far(),
        "a counterpart can discard the credit only where its payer is elsewhere",
    );

    let members: Vec<Seated<'_>> = batch
        .iter()
        .map(|tx| (tx.hash(), tx, member_beside(tx, &trie)))
        .collect();
    let executed = run_beside(&executor, &trie, &store, &members);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the crediting member completes: {:?}",
        executed[0].metadata
    );
    (executed, store)
}

/// A member a counterpart's verdict can still discard funds no burn of
/// its batch: the fees the batch's determined members burn from a vault
/// settle onto the state below the batch without that member's credit.
/// A credit nothing can discard settles in the half that settles the
/// burns, and funds them.
#[test]
fn a_fee_burn_does_not_spend_a_provisional_credit_of_its_batch() {
    let (executed, below) = two_burns_behind_a_credit(far());
    let (completed, settled) = settled_behind(&executed);
    assert_eq!(completed, 1, "the vault covers one burn without the credit");
    assert!(
        settled.resolve(&mut |key| below.cell(key)).is_ok(),
        "the determined members burn past what the vault holds below the batch"
    );

    let (executed, _) = two_burns_behind_a_credit(alice());
    assert_eq!(
        settled_behind(&executed).0,
        2,
        "a credit that settles beside the burns funds both"
    );
}

/// A fan-out: two withdrawals from one account funding two deposits in
/// a single manifest — the shape a multi-recipient cross-shard payment
/// takes.
#[test]
fn a_two_recipient_fan_out_executes() {
    let executor = executor(ExecutionMode::Serial);
    let key = Ed25519PrivateKey::from_bytes(&[ALICE_SEED; 32]).unwrap();
    let chain = client().records();
    let mut b = client().builder(&chain, alice());
    for (to, amount) in [(bob(), 5u128), (fee_payer(7), 6)] {
        let funds = account::withdraw(&mut b, alice(), *PROTOCOL_RESOURCE, amount)
            .expect("an account withdraws");
        account::deposit(&mut b, to, funds).expect("an account deposits");
    }
    let graph = b.build().expect("every output is consumed");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(Transaction::new(
        client().sign(graph, &key, validity(), terms(10)),
    )));
    let executed = execute_on(
        &[(alice(), 1_000), (bob(), 50), (fee_payer(7), 1_000)],
        &executor,
        &[tx],
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("the fan-out must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        vault_cell(&settled(writes, &world_accounts()), alice()),
        Some(encode_amount(1_000 - 5 - 6 - 10).to_vec())
    );
    assert_eq!(
        vault_cell(&settled(writes, &world_accounts()), bob()),
        Some(encode_amount(55).to_vec())
    );
    assert_eq!(
        vault_cell(&settled(writes, &world_accounts()), fee_payer(7)),
        Some(encode_amount(1_006).to_vec())
    );
}

/// A signed publish of `artifact`, paid for by `seed`'s account.
fn signed_publish(seed: u8, artifact: Vec<u8>) -> Transaction {
    signed_publish_under(seed, artifact, 1_000_000)
}

/// The same, under a ceiling the caller names.
fn signed_publish_under(seed: u8, artifact: Vec<u8>, max_fee: u128) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let publisher = account_address(&key.public_key().0);
    let vm = signing::wrap_publish(
        artifact.try_into().expect("an artifact under the wire cap"),
        publisher,
        HEADER,
        signing::Terms {
            fee_payer: publisher,
            max_fee,
            gas_limits: Capped::from_array([1_000_000]),
            priority_bp: 0,
            message: Bytes::empty(),
        },
    )
    .sign(&key);
    Transaction::new(vm)
}

/// The raw update a batch made to an artifact's own package cell.
fn package_cell(writes: &StateWrites, artifact: &[u8]) -> Option<Vec<u8>> {
    let key = package_key(package_hash(&ProtocolHasher, artifact));
    writes.cells.get(&key).cloned().flatten()
}

#[test]
fn a_publish_writes_the_artifact_under_its_own_address() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);
    let artifact = published_artifact();
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7,
        artifact.clone(),
    )));
    // Funded well above the burn: at the placeholder rate of one unit
    // per artifact byte, publishing the stdlib guest costs more than the
    // balances the transfer fixtures use.
    let executed = execute_on(&[(payer, 1_000_000)], &executor, std::slice::from_ref(&tx));

    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        beacon_witness_events,
        ..
    } = &executed[0].consensus
    else {
        panic!("a publish must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        package_cell(database_updates, &artifact).as_deref(),
        Some(artifact.as_slice()),
        "the artifact lands whole in its content-addressed cell"
    );
    // A publish raises nothing globally: the cell's key follows from the
    // artifact's own address, which is the whole of what a node needs to
    // ask for it.
    assert!(
        beacon_witness_events.is_empty(),
        "a publish is a fact about a shard's state, not about the beacon"
    );
    // The publisher paid what the table prices its declaration at — the
    // artifact's bytes as writes and retention — and the fee is the only
    // other thing a publish writes.
    let price = tx
        .price_under(executor.derivation().as_ref(), &PriceTable::GENESIS)
        .expect("a publish derives");
    let paid = vault_cell(&settled(database_updates, &[(payer, 1_000_000)]), payer)
        .expect("the payer's vault was written");
    assert_eq!(
        paid,
        encode_amount(1_000_000 - price).to_vec(),
        "the publisher paid the declaration's price"
    );
}

/// A publish whose package cell sits on another shard than its payer is
/// one the package's shard can still refuse after the payer's shard
/// completed it. The payer's shard burns the price inside the publish's
/// writes and builds the same charge apart, so the refusal that discards
/// those writes settles the price and ends the hold; the package's shard
/// holds no vault of the payer's and builds neither.
#[test]
fn a_completed_publish_a_counterpart_can_refuse_carries_its_charge_apart() {
    const FUNDED: u128 = 1_000_000;
    let executor = executor(ExecutionMode::Serial);
    let artifact = published_artifact();
    let trie = ShardTrie::uniform(1);
    let package_shard =
        trie.shard_for_prefix(package_key(package_hash(&ProtocolHasher, &artifact)).owner);
    let seed = (1..=u8::MAX)
        .find(|seed| trie.shard_for_prefix(fee_payer(*seed)) != package_shard)
        .expect("some account sits across the trie from the package");
    let payer = fee_payer(seed);
    let payer_shard = trie.shard_for_prefix(payer);
    let tx = verified(signed_publish(seed, artifact.clone()));
    derived_through(&executor, std::slice::from_ref(&tx));
    let price = price_of(&executor, &tx);

    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie);
    assert!(!classified.decomposed(), "a publish runs whole");
    let run = |local_shard: ShardId| {
        let member = Member::of(
            classified.clone(),
            local_shard,
            BTreeSet::from([payer_shard, package_shard]),
        );
        assert!(member.abortable(), "either shard's verdict binds the other");
        let snapshot_store = MapDb::genesis(&[(payer, FUNDED)]);
        let ctx = TickBatchContext {
            local_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
            fee_holds: &NoFeeHolds,
        };
        let input = TickTxInput {
            prices: PriceTable::GENESIS,
            tx_hash: tx.hash(),
            transaction: &tx,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            member,
            arrivals: &[],
        };
        executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .expect("the harness engine holds every package it runs")
            .remove(0)
    };
    let vault = vault_key(payer, *PROTOCOL_RESOURCE);

    let paying = run(payer_shard);
    let ConsensusReceipt::Succeeded { writes, .. } = &paying.consensus else {
        panic!("the payer's shard completes: {:?}", paying.consensus);
    };
    assert_eq!(
        writes.movements.get(&vault),
        Some(&Movement::debit(*PROTOCOL_RESOURCE, price)),
        "the price burns inside the publish's own writes"
    );
    assert!(releases_hold(writes, payer, tx.hash()));
    assert_eq!(package_cell(writes, &artifact), None);
    let apart = paying
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a completed publish a counterpart can refuse settles its price apart");
    assert_eq!(
        apart.movements,
        BTreeMap::from([(vault, Movement::debit(*PROTOCOL_RESOURCE, price))]),
        "the charge apart is the judged burn and nothing else"
    );
    assert!(releases_hold(apart, payer, tx.hash()));
    assert_eq!(apart.cells.len(), 1, "{:?}", apart.cells);

    let housing = run(package_shard);
    let ConsensusReceipt::Succeeded { writes, .. } = &housing.consensus else {
        panic!("the package's shard completes: {:?}", housing.consensus);
    };
    assert_eq!(
        package_cell(writes, &artifact).as_deref(),
        Some(artifact.as_slice())
    );
    assert!(writes.movements.is_empty() && !releases_hold(writes, payer, tx.hash()));
    assert!(
        housing.refusal_receipt.is_none(),
        "a shard holding no vault of the payer's charges nothing apart"
    );
}

/// A publish no counterpart can refuse burns inside its writes alone.
#[test]
fn a_publish_nothing_can_refuse_names_no_charge_apart() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);
    let tx = verified(signed_publish(7, published_artifact()));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, std::slice::from_ref(&tx));
    assert!(matches!(
        executed[0].consensus,
        ConsensusReceipt::Succeeded { .. }
    ));
    assert!(executed[0].refusal_receipt.is_none());
}

/// A publish priced past its signed ceiling reports the ceiling, and
/// reports what it burned.
///
/// Admission refuses this at the table it read, but a block anchored the
/// other side of a fold prices under its own — so the two figures can
/// differ by the time the burn happens, and the ceiling is what the
/// vault loses. A charge reported above it would claim emission weight
/// for quanta nobody paid, `cumulative_fees` being the sum of what each
/// block says it charged.
#[test]
fn a_publish_charges_no_more_than_the_ceiling_it_signed() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);
    let artifact = published_artifact();

    // The ceiling is derived from the price rather than pinned, so this
    // keeps saying the same thing as the table moves under it.
    let priced = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7,
        artifact.clone(),
    )));
    let price = priced
        .price_under(executor.derivation().as_ref(), &PriceTable::GENESIS)
        .expect("a publish derives");
    let ceiling = price / 2;
    assert!(
        ceiling > 0 && ceiling < price,
        "the fixture only says anything where the declaration outprices the \
         ceiling: price {price}"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_publish_under(7, artifact, ceiling),
    ));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, std::slice::from_ref(&tx));
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    } = &executed[0].consensus
    else {
        panic!("a publish must succeed: {:?}", executed[0].consensus);
    };

    let paid = vault_cell(&settled(database_updates, &[(payer, 1_000_000)]), payer)
        .expect("the payer's vault was written");
    assert_eq!(
        paid,
        encode_amount(1_000_000 - ceiling).to_vec(),
        "the vault loses the ceiling, never the price above it"
    );
    assert_eq!(
        executed[0].metadata.fee_summary.total_execution_cost,
        Some(ceiling),
        "and the receipt names the figure that moved beside it"
    );
}

/// The stdlib artifact's ABI bindings survive the round trip through the
/// metadata section, which is what makes the account guest callable
/// through them rather than through a table that knows its method names.
#[test]
fn the_stdlib_artifact_carries_resolvable_bindings() {
    let metadata = admit_protocol_package(account_artifact()).expect("the stdlib artifact admits");
    // The grant is the bucket, so the amount the manifest asked for
    // reaches the declaration and never the body.
    assert_eq!(
        metadata.methods["withdraw"].abi,
        vec![AbiParam::Handle { clause: 1, site: 0 }],
        "the binding decoded is the binding authored: the gate's condition \
         is the first clause, and the vault access it names is the second"
    );
    assert_eq!(
        metadata.methods["deposit"].abi,
        vec![AbiParam::Handle { clause: 0, site: 0 }, AbiParam::Bucket(0),],
        "one handle for the one cell a deposit reaches, naming the clause \
         that declared it rather than a position"
    );
}

/// A gap and a refusal are different answers, and derivation says which.
///
/// Both stop a transaction here, but only one of them stops it
/// everywhere. A malformed envelope is refused by every node that reads
/// it; a target this node has not seen sealed resolves fine wherever the
/// seal committed, and names what it would need so a fetch can close the
/// gap. Collapsing the two would make a node's own cold start look like
/// the sender's fault.
#[test]
fn derivation_tells_a_gap_from_a_refusal() {
    // The engine's own derivation is what these answers come from.
    let engine = executor(ExecutionMode::Serial);
    let payer = fee_payer(7);
    let key = Ed25519PrivateKey::from_bytes(&[7; 32]).unwrap();

    // A component nobody sealed, named by an envelope that is otherwise
    // well formed.
    let meta = InstanceMeta {
        package: lottery_package_hash(&ProtocolHasher),
        config: Capped::empty(),
        salt: Hash32([0xA1; 32]),
    };
    let unsealed = meta.address(&ProtocolHasher);
    let mut b = GraphBuilder::new();
    let [] = b.call(unsealed, "draw", (64u64,));
    let graph = b.build().expect("every output is consumed");
    let gap = Transaction::new(client().sign_tree(
        &IntentTree::of_one(Intent::leaf(
            HEADER,
            account_address(&key.public_key().0),
            graph,
        )),
        &[&key],
        terms(TRANSFER_FEE),
    ));
    let error = gap
        .try_derived(engine.derivation().as_ref())
        .expect_err("nothing answers for it yet");
    assert_eq!(
        error.unresolved().map(|wanted| wanted.instances.as_slice()),
        Some([unsealed.address()].as_slice()),
        "the record a fetch would ask for: {error}"
    );

    // The second link of the same chain. This node holds the record —
    // the envelope carries it — and does not hold the code it names, so
    // derivation names the package rather than refusing. The two are
    // reported in turn and not together: a record is what says which
    // package a target runs, so what is missing behind one is only
    // knowable once it is in hand.
    let protocol = Executor::with_genesis(&[], &GenesisPackages::protocol(), ExecutionMode::Serial);
    let mut b = GraphBuilder::new();
    let [] = b.call(unsealed, "draw", (64u64,));
    let graph = b.build().expect("every output is consumed");
    let carried = Transaction::new(client().sign_tree(
        &IntentTree {
            root: Intent::leaf(HEADER, account_address(&key.public_key().0), graph),
            instances: Capped::new(vec![meta]).unwrap(),
            resources: Capped::empty(),
        },
        &[&key],
        terms(TRANSFER_FEE),
    ));
    let error = carried
        .try_derived(protocol.derivation().as_ref())
        .expect_err("a node holding no fixture code cannot say what this declares");
    let wanted = error.unresolved().expect("a gap, not a refusal");
    assert!(
        wanted.instances.is_empty(),
        "the carried record answers for the target: {error}"
    );
    assert_eq!(
        wanted.packages,
        [Hash::from(lottery_package_hash(&ProtocolHasher).0)],
        "the package a fetch would ask for: {error}"
    );

    // A refusal, by contrast, names nothing to fetch: the account
    // resolves, and no record would make a deposit taking no bucket
    // admissible.
    let mut b = GraphBuilder::new();
    let [] = b.call(payer, "deposit", ());
    let graph = b.build().expect("every output is consumed");
    let refused = Transaction::new(client().sign_tree(
        &IntentTree::of_one(Intent::leaf(
            HEADER,
            account_address(&key.public_key().0),
            graph,
        )),
        &[&key],
        terms(TRANSFER_FEE),
    ));
    let error = refused
        .try_derived(engine.derivation().as_ref())
        .expect_err("a deposit takes a bucket");
    assert!(
        error.unresolved().is_none(),
        "a refusal names nothing to fetch: {error}"
    );
}

#[test]
fn a_publish_that_is_not_a_package_never_reaches_execution() {
    // The whole publish verdict is a function of the artifact's bytes,
    // so it is reached at admission: derivation refuses, the transaction
    // is never included, and nobody pays for it or stores it.
    let junk = b"\0asm\x01\0\0\0".to_vec();
    assert!(
        admit_package(&junk).is_err(),
        "well-formed wasm framing is not a package"
    );
    assert!(
        admit_protocol_package(account_artifact()).is_ok(),
        "the stdlib artifact is one"
    );
}

#[test]
fn a_committed_publish_grows_the_cache_that_routing_reads() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);

    // A package the world has never seen: the stdlib artifact with its
    // metadata attached a second time under a different publisher would
    // be the same bytes, so vary the metadata to vary the address.
    let mut metadata = staking::metadata();
    naming(&mut metadata, "republished");
    let artifact = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);

    let cache = executor.packages();
    assert!(
        cache.load().get(package).is_none(),
        "the package is unknown before its block commits"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7, artifact,
    )));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);
    let ConsensusReceipt::Succeeded { .. } = &executed[0].consensus else {
        panic!("the publish must succeed: {:?}", executed[0].consensus);
    };

    // Executing is not committing: the cache learns the package from the
    // committed receipt, which is what a synced replica also replays.
    assert!(
        cache.load().get(package).is_none(),
        "execution alone does not publish"
    );
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());
    assert_eq!(
        cache.load().get(package),
        Some(&metadata),
        "the committed cell published exactly the metadata the artifact declares"
    );
}

/// The staking package's artifact, as a publisher submits it.
///
/// The staking package rather than the account's: a published package
/// serves instances, and the gate holds one to declaring the seal its
/// components come up through — which the account, serving principals,
/// has no reason to carry.
fn published_artifact() -> Vec<u8> {
    attach_metadata(STAKING_MODULE, &staking::metadata()).expect("attaches")
}

/// Vary `metadata`, and so the address of any artifact carrying it, by
/// naming one more event.
///
/// A package is content-addressed, so republishing one is the same bytes
/// at the same address; one more name is the smallest thing that moves
/// it. An event is a name *and* a shape, so the name arrives with the
/// empty one — what an event carrying nothing declares.
fn naming(metadata: &mut PackageMetadata, event: &str) {
    let named = Name::declared(event);
    let unit = metadata
        .types
        .push(TypeShape::Tuple(Vec::new()))
        .expect("the empty shape joins any table");
    metadata
        .types
        .push(TypeShape::Named {
            name: named.clone(),
            shape: unit,
        })
        .expect("a name the package does not already hold");
    metadata.events.push(named);
}

/// Wait out the compile worker; the bound is a harness valve, not a
/// verdict — consensus never reads a clock here.
fn await_code_runnable(executor: &Executor, package: PackageHash) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while executor.package_standing(package) != Availability::Runnable {
        assert!(
            std::time::Instant::now() < deadline,
            "the package's code never became resolvable"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn a_committed_publish_compiles_ahead_of_its_first_call() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);

    let mut metadata = staking::metadata();
    naming(&mut metadata, "compiled");
    let artifact = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    assert_eq!(
        executor.package_standing(package),
        Availability::Absent,
        "the code is unknown before its block commits"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7, artifact,
    )));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);
    let ConsensusReceipt::Succeeded { .. } = &executed[0].consensus else {
        panic!("the publish must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        executor.package_standing(package),
        Availability::Absent,
        "execution alone compiles nothing"
    );

    // The same committed-cell walk that grows the metadata cache hands
    // the artifact to the compile worker: the code is on its way from
    // the commit, not from the first call that needs it.
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());
    await_code_runnable(&executor, package);
}

#[test]
fn an_indexed_artifact_reseeds_metadata_and_code_at_boot() {
    let executor = executor(ExecutionMode::Serial);

    let mut metadata = staking::metadata();
    naming(&mut metadata, "reseeded");
    let artifact = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);

    // What a restarting host replays from its stores' package indices:
    // one call re-learns the metadata and queues the compile.
    executor.install_artifact(&artifact);
    assert_eq!(
        executor.packages().load().get(package),
        Some(&metadata),
        "the reseeded artifact's metadata is routable"
    );
    await_code_runnable(&executor, package);

    // Junk in the index is refused, not trusted: the cells are the
    // authority and the index is derived.
    executor.install_artifact(b"\0asm\x01\0\0\0");

    // And a refusal costs nothing that follows it: the next artifact in
    // the index still reaches the compile worker. A restart replays
    // whatever the store holds, so one unreadable entry must not be the
    // end of the reseed.
    naming(&mut metadata, "after_the_refusal");
    let next = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    executor.install_artifact(&next);
    await_code_runnable(&executor, package_hash(&ProtocolHasher, &next));
}

#[test]
fn only_a_cell_that_addresses_its_own_contents_publishes() {
    // A package cell is self-identifying: its key is the content address
    // of the value it holds. Without that check, any committed cell
    // whose bytes happened to parse as an artifact would publish a
    // package — no publish transaction, no fee, no cell of its own.
    let executor = executor(ExecutionMode::Serial);
    let cache = executor.packages();

    let mut metadata = staking::metadata();
    naming(&mut metadata, "smuggled");
    let artifact = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    let publisher = fee_payer(11);

    // The right bytes at the wrong key: a vault slot, not the content
    // address. Refused.
    let vault = vault_key(publisher, *PROTOCOL_RESOURCE);
    cache.absorb_cell(publisher, vault.local.0, &artifact);
    assert!(
        cache.load().get(package).is_none(),
        "an artifact stored anywhere but its own address is not a package"
    );

    // The right local key under the wrong owner: the cell's owner is the
    // package's address, so a publisher's own prefix cannot carry it.
    let cell = package_key(package);
    cache.absorb_cell(publisher, cell.local.0, &artifact);
    assert!(
        cache.load().get(package).is_none(),
        "an artifact under any owner but its own address is not a package"
    );

    // The same bytes at the whole key their own hash builds. Published.
    cache.absorb_cell(cell.owner, cell.local.0, &artifact);
    assert_eq!(cache.load().get(package), Some(&metadata));
}

/// Preview `tx` against a genesis snapshot of `accounts`, committing
/// nothing.
fn preview_on(
    accounts: &[(PrincipalAddr, u128)],
    executor: &Executor,
    tx: &Transaction,
    grants: PreviewGrants,
) -> PreviewReport {
    let snapshot_store = MapDb::genesis(accounts);
    executor.preview(
        &snapshot_store,
        tx,
        &PreviewInputs {
            prices: PriceTable::GENESIS,
            clock: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            // One shard, so nothing a transaction declares is off it.
            holds: Holds {
                trie: ShardTrie::single(),
                shards: BTreeSet::from([ShardId::ROOT]),
                fetched: FetchedCells::default(),
            },
            grants,
        },
    )
}

/// A fan-out asks for exactly the shards the preview would otherwise
/// refuse for, and for nothing the node reads itself.
///
/// The two have to agree or the feature does not work: what
/// `preview_reads` gathers is what lifts `Holds::missing`, so a split
/// that named one shard too few would fetch and still refuse, and one
/// too many would ask a shard for cells the node already holds.
#[test]
fn a_fan_out_asks_for_what_the_refusal_would_have_named() {
    let PreviewFixture { accounts, tx, .. } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let _ = MapDb::genesis(&accounts);
    let trie = ShardTrie::uniform_from_count(2);
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));

    // Holding everything, there is nobody to ask.
    let whole = BTreeSet::from([left, right]);
    assert!(
        executor
            .preview_reads(&tx, &trie, &whole)
            .expect("the fixture derives")
            .is_empty(),
        "a node holding every shard the declaration reaches fetches nothing"
    );

    // Holding half, the asks are the other half and only that.
    let half = BTreeSet::from([right]);
    let asks = executor
        .preview_reads(&tx, &trie, &half)
        .expect("the fixture derives");
    assert!(
        !asks.is_empty(),
        "the fixture has to straddle for this to have teeth"
    );
    assert!(
        asks.keys().all(|shard| !half.contains(shard)),
        "nothing the node reads itself is asked of anyone else"
    );
    assert!(
        asks.values()
            .all(|reads| !reads.keys.is_empty() || !reads.ranges.is_empty()),
        "a shard named in the split is a shard with something to answer"
    );
}

/// The fee payer's vault is fetched though no declaration names it.
///
/// The charge reads it and the report says what the charge would leave,
/// so a preview that asked nobody for it reports a payer holding zero —
/// for a cell this node proved nothing about. A publish is the shape
/// with nothing else to fan out for: it writes its own two cells and
/// reads no declared state at all, so the vault is the whole of its
/// split and an empty one would mean the report was guessing.
#[test]
fn a_fan_out_asks_for_the_fee_payers_vault() {
    let payer = fee_payer(7);
    let tx = signed_publish(7, account_artifact().to_vec());
    let executor = executor(ExecutionMode::Serial);
    let _ = MapDb::genesis(&[(payer, 1_000)]);
    let trie = ShardTrie::uniform_from_count(2);
    let vault = vault_key(payer, *PROTOCOL_RESOURCE);

    let asks = executor
        .preview_reads(&tx, &trie, &BTreeSet::new())
        .expect("a publish needs no derivation to name its payer");
    let keys: Vec<_> = asks.values().flat_map(|reads| reads.keys.clone()).collect();
    assert_eq!(
        keys,
        vec![vault],
        "the payer's vault is asked for, and it is the whole of the ask"
    );

    // And a node that holds it asks nobody, the same rule the declared
    // cells answer to.
    let home = trie.shard_for_prefix(vault.owner);
    assert!(
        executor
            .preview_reads(&tx, &trie, &BTreeSet::from([home]))
            .expect("a publish needs no derivation to name its payer")
            .is_empty(),
        "a node holding the payer's shard fetches nothing"
    );
}

/// A cell a transaction reaches under two modes is one cell to fetch.
///
/// The declaration folds by target and carries the modes on it, so the
/// flattened view names a target once per mode — the right reading for a
/// price, which charges each access, and the wrong one for a fan-out,
/// which fetches a leaf. Alice paying Alice is the smallest shape that
/// tells them apart: the withdrawal reserves out of her vault and the
/// deposit credits into it, so one cell carries `Reserve` and `Delta`.
/// The same fold is behind every round trip — a swap handing back the
/// resource it took, change returning to its payer.
///
/// Asking twice costs twice: two entries in the request, two leaves in
/// the server's proof, and two spends against its query budget.
#[test]
fn a_cell_reached_under_two_modes_is_asked_for_once() {
    let payer = fee_payer(7);
    let accounts = vec![(payer, 1_000)];
    let tx = signed_transfer_with_fee(7, payer, payer, 100, PREVIEW_CEILING);
    let executor = executor(ExecutionMode::Serial);
    let _ = MapDb::genesis(&accounts);
    let trie = ShardTrie::uniform_from_count(2);

    // Holding nothing, so every cell the declaration reaches is asked of
    // whoever does hold it and the whole split is visible here.
    let asks = executor
        .preview_reads(&tx, &trie, &BTreeSet::new())
        .expect("the self-transfer derives");
    let keys: Vec<_> = asks.values().flat_map(|reads| reads.keys.clone()).collect();
    let mut distinct = keys.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        keys.len(),
        distinct.len(),
        "the vault the transfer reserves out of and credits back into is \
         one leaf, and the fan-out asks for it once: {keys:?}"
    );
}

/// A shard a fan-out answered for is one the preview can speak for.
///
/// The companion to [`a_preview_refuses_what_this_node_cannot_see`]:
/// the same node, the same half-held trie, and the same transaction —
/// the only thing that changes is that the far shard was asked and
/// replied. What that buys is the run, so the refusal naming a shard
/// must stop firing.
#[test]
fn a_preview_speaks_for_a_shard_a_fan_out_answered() {
    let PreviewFixture { accounts, tx, .. } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let snapshot_store = MapDb::genesis(&accounts);
    let trie = ShardTrie::uniform_from_count(2);
    let held = ShardId::leaf(1, 1);
    // Whatever the declaration reaches on the other half, a fan-out
    // would have asked that shard and been answered at some committed
    // height. Naming the height is what says so.
    let mut fetched = FetchedCells::default();
    fetched
        .anchors
        .insert(ShardId::leaf(1, 0), BlockHeight::new(4));

    let report = executor.preview(
        &snapshot_store,
        &tx,
        &PreviewInputs {
            prices: PriceTable::GENESIS,
            clock: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: Holds {
                trie,
                shards: BTreeSet::from([held]),
                fetched,
            },
            grants: PreviewGrants::default(),
        },
    );
    assert!(
        !matches!(
            &report.outcome,
            PreviewOutcome::Refused { reason } if reason.contains("reads cells on")
        ),
        "a shard that answered is not a shard this node cannot see: {:?}",
        report.outcome
    );
    // And the height it answered at comes back out. The ceilings beside
    // it are what a composer signs, so a report taken over state far
    // behind the tip yields ceilings a real run can trip — a caller that
    // cannot see the age cannot see that coming.
    assert_eq!(
        report.anchors,
        BTreeMap::from([(ShardId::leaf(1, 0), BlockHeight::new(4))]),
    );
}

/// A preview that read no shard's state names no anchor: there is no
/// moment to disclose.
#[test]
fn a_refused_preview_names_no_anchor() {
    let PreviewFixture { accounts, tx, .. } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let snapshot_store = MapDb::genesis(&accounts);
    let report = executor.preview(
        &snapshot_store,
        &tx,
        &PreviewInputs {
            prices: PriceTable::GENESIS,
            clock: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: Holds {
                trie: ShardTrie::uniform_from_count(2),
                shards: BTreeSet::from([ShardId::leaf(1, 1)]),
                fetched: FetchedCells::default(),
            },
            grants: PreviewGrants::default(),
        },
    );
    assert!(matches!(report.outcome, PreviewOutcome::Refused { .. }));
    assert!(report.anchors.is_empty());
}

/// A preview reaches the kernel without deriving, and what it reports
/// has to be the verdict the chain would reach: a declaration a
/// derivation refuses never enters a block, so a preview that ran it
/// would quote an outcome and a fee for a transaction nobody admits.
#[test]
fn a_preview_refuses_the_declaration_a_derivation_refuses() {
    let payer = fee_payer(7);
    let accounts = vec![(payer, 1_000), (bob(), 50)];
    let tx = signed_transfer_with_fee(7, payer, bob(), MAX_DECLARED_RESERVE + 1, TRANSFER_FEE);
    let executor = executor(ExecutionMode::Serial);

    let refusal = tx
        .try_derived(executor.derivation().as_ref())
        .expect_err("a reservation past the bound derives nothing");
    assert!(refusal.unresolved().is_none(), "a verdict, not a gap");

    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    assert_eq!(
        report.outcome,
        PreviewOutcome::Refused {
            reason: refusal.to_string()
        },
    );
    assert_eq!(report.fee, 0);
}

/// A cell this node does not hold is not an empty cell.
///
/// A kernel cannot tell the two apart — it reads the absence, refuses
/// the withdrawal over it, and the report would name a verdict the
/// chain never reaches. So a preview of a transaction reaching past what
/// the node holds refuses, and says which shards it would have needed.
#[test]
fn a_preview_refuses_what_this_node_cannot_see() {
    let PreviewFixture { accounts, tx, .. } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let snapshot_store = MapDb::genesis(&accounts);
    // A two-shard trie the node holds only half of.
    let report = executor.preview(
        &snapshot_store,
        &tx,
        &PreviewInputs {
            prices: PriceTable::GENESIS,
            clock: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: Holds {
                trie: ShardTrie::uniform_from_count(2),
                shards: BTreeSet::from([ShardId::leaf(1, 1)]),
                fetched: FetchedCells::default(),
            },
            grants: PreviewGrants::default(),
        },
    );
    match report.outcome {
        PreviewOutcome::Refused { reason } => assert!(
            reason.contains("reads cells on"),
            "the refusal names what it would have needed: {reason}"
        ),
        other => panic!("a preview over state this node lacks must refuse: {other:?}"),
    }
}

/// The reported change to `owner`'s native vault.
fn change_for(report: &PreviewReport, owner: impl Into<Address>) -> ResourceChange {
    let owner = owner.into();
    let key = vault_key(owner, *PROTOCOL_RESOURCE);
    *report
        .changes
        .iter()
        .find(|change| change.key == key)
        .unwrap_or_else(|| panic!("no reported change for {owner:?}: {:?}", report.changes))
}

/// The preview fixture: a payer who funds the transfer and its fee, and a
/// recipient. The ceiling sits far below the fuel a transfer burns, so the
/// charge is the cap rather than the actual.
const PREVIEW_CEILING: u128 = 10;

struct PreviewFixture {
    payer: PrincipalAddr,
    accounts: Vec<(PrincipalAddr, u128)>,
    tx: Transaction,
}

fn preview_fixture() -> PreviewFixture {
    let payer = fee_payer(7);
    PreviewFixture {
        payer,
        accounts: vec![(payer, 1_000), (bob(), 50)],
        tx: signed_transfer_with_fee(7, payer, bob(), 100, PREVIEW_CEILING),
    }
}

/// A preview reports the transfer's resource changes: what leaves the
/// sender's vault, what reaches the recipient's, and what the fee costs on
/// top — read off the receipt's settles and movements without committing
/// anything.
#[test]
fn a_preview_reports_the_resource_changes_a_transfer_would_make() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    assert_eq!(report.outcome, PreviewOutcome::Completed);
    assert_eq!(
        report.fee, PREVIEW_CEILING,
        "a ceiling below the price is the burn"
    );
    assert_eq!(report.changes.len(), 2, "two vaults move: {report:?}");

    let sender = change_for(&report, payer);
    assert_eq!((sender.before, sender.after), (1_000, 1_000 - 100 - 10));
    assert_eq!(
        (sender.settled, sender.credit, sender.debit),
        (100, 0, 0),
        "a withdrawal leaves through its reservation's settle"
    );

    let recipient = change_for(&report, bob());
    assert_eq!((recipient.before, recipient.after), (50, 150));
    assert_eq!(
        (recipient.credit, recipient.debit, recipient.settled),
        (100, 0, 0),
        "a deposit arrives as a commutative credit"
    );

    // Nothing moved: the same preview twice reports the same thing.
    assert_eq!(
        preview_on(&accounts, &executor, &tx, PreviewGrants::default()),
        report,
        "a preview commits nothing, so it is repeatable"
    );
}

/// The preview's arithmetic is the tick's arithmetic: what it says a
/// vault would hold is what the committed receipt writes there.
#[test]
fn a_preview_agrees_with_the_tick_that_would_commit_it() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let verified = Arc::new(Verified::<Transaction>::from_persisted(tx));
    let executed = execute_on(&accounts, &executor, &[verified]);
    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        ..
    } = &executed[0].consensus
    else {
        panic!("the transfer must succeed: {:?}", executed[0].consensus);
    };

    for owner in [payer, bob()] {
        assert_eq!(
            vault_cell(&settled(database_updates, &world_accounts()), owner),
            Some(encode_amount(change_for(&report, owner).after).to_vec()),
            "the preview's figure for {owner:?} is what the tick commits"
        );
    }
}

/// Free credit: the fee is still priced and reported, but it never
/// reaches the payer's vault, so a wallet can price an envelope its payer
/// could not cover.
#[test]
fn free_credit_reports_the_fee_without_charging_it() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = executor(ExecutionMode::Serial);
    let charged = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    let credited = preview_on(
        &accounts,
        &executor,
        &tx,
        PreviewGrants { free_credit: true },
    );

    assert_eq!(credited.fee, charged.fee, "the fee is priced either way");
    assert_eq!(
        change_for(&credited, payer).after,
        change_for(&charged, payer).after + charged.fee,
        "credit keeps exactly the fee off the payer's vault"
    );
    assert_eq!(
        change_for(&credited, bob()),
        change_for(&charged, bob()),
        "a grant to the payer moves nobody else"
    );
}

/// A member's fee is weighed at the table its own committing block
/// anchored to, never at the table the executing node happens to hold.
///
/// The burn lands in a receipt every participant of the transaction
/// derives, so a table read off the head would price one transaction
/// two ways — across two shards folding an epoch at different moments,
/// and across one shard replaying a tick after a fold moved the level.
#[test]
fn a_members_fee_follows_the_table_it_carries() {
    let executor = executor(ExecutionMode::Serial);
    let payer = alice();
    let funded = [(payer, 1_000_000u128)];

    // Two tables an epoch apart; the member carries one of them.
    let moved = PriceTable {
        compute: PriceTable::GENESIS.compute * 3,
        ..PriceTable::GENESIS
    };
    let burn = |prices: PriceTable| {
        let tx = Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(ALICE_SEED, payer, bob(), 100, TRANSFER_FEE),
        ));
        derived_through(&executor, std::slice::from_ref(&tx));
        let trie = ShardTrie::single();
        let ctx = TickBatchContext {
            local_shard: ShardId::ROOT,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: sealed_env(0x5E),
            holds: &ProvisionalHolds::new(),
            fee_holds: &NoFeeHolds,
        };
        let executed = executor
            .execute_batch(
                &ctx,
                prices,
                &MapDb::genesis(&funded),
                std::slice::from_ref(&tx),
            )
            .expect("the harness engine holds every package it runs");
        let ConsensusReceipt::Succeeded {
            writes: database_updates,
            ..
        } = &executed[0].consensus
        else {
            panic!("a funded transfer succeeds: {:?}", executed[0].consensus);
        };
        let held = vault_cell(&settled(database_updates, &funded), payer)
            .expect("the payer's vault was written");
        // The vault carries the transfer beside the fee, so the fee is
        // what moves between two runs that differ only in the table.
        (tx.price(&prices), held)
    };

    let (genesis_price, genesis_held) = burn(PriceTable::GENESIS);
    let (moved_price, moved_held) = burn(moved);
    assert!(
        moved_price > genesis_price,
        "the two tables price the transfer differently, or the pin \
         would hold whatever the member carried"
    );
    assert_eq!(
        genesis_held,
        encode_amount(decode_held(&moved_held) + (moved_price - genesis_price)).to_vec(),
        "the burn moves by exactly what the carried table moved"
    );
}

/// An amount cell's figure, for an assertion that has to do arithmetic
/// on a balance rather than compare it.
fn decode_held(cell: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&cell[..16]);
    u128::from_le_bytes(bytes)
}

/// An uncovered withdrawal previews as the abort it would be, priced at
/// the one declared price: the sender lost a deterministic race, and an
/// attempt settles the price whatever refused it.
#[test]
fn a_preview_prices_an_abort_at_the_declared_price() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    let tx = signed_transfer_with_fee(7, payer, bob(), 5_000, TRANSFER_FEE);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let PreviewOutcome::Aborted { reason } = &report.outcome else {
        panic!("an uncovered withdrawal must abort: {:?}", report.outcome);
    };
    assert!(reason.contains("infeasible"), "reason = {reason}");
    assert_eq!(report.fee, price_of(&executor, &tx), "the declared price");
    assert_eq!(
        report.changes,
        vec![ResourceChange {
            key: vault_key(payer, *PROTOCOL_RESOURCE),
            before: 1_000,
            after: 1_000 - report.fee,
            credit: 0,
            debit: 0,
            settled: 0,
        }],
        "an abort moves nothing but the price"
    );
}

/// An envelope admission would refuse previews as refused, and costs
/// nothing: it could never enter a block, so nobody would pay for it.
///
/// The refusal is the instance gate, which only a component can trip: a
/// principal is served by its class, so no principal address is unknown.
/// The reason is asserted because the outcome alone cannot tell this
/// gate from the authority one, and a preview that refused for the wrong
/// reason would still pass a bare `Refused` check.
#[test]
fn a_preview_refuses_what_admission_would_refuse() {
    let unknown = ComponentAddr::new([0xAB; 31]);
    let executor = executor(ExecutionMode::Serial);
    let tx = signed_transfer_from_unknown(7, unknown, bob(), 10, PREVIEW_CEILING);
    let report = preview_on(&[(bob(), 50)], &executor, &tx, PreviewGrants::default());

    let PreviewOutcome::Refused { reason } = &report.outcome else {
        panic!("an unknown instance must refuse: {:?}", report.outcome);
    };
    assert!(reason.contains("no instance"), "reason = {reason}");
    assert_eq!(report.fee, 0);
    assert!(report.changes.is_empty());
}

/// An envelope carrying no ceilings at all previews as refused.
///
/// The kernel reads an unset ceiling vector as every node unbounded,
/// which is the in-crate fixture's reading. A preview answers for a
/// body nobody signed for and nobody pays for, so it is the one caller
/// that reaches the kernel without deriving — and an envelope that
/// declares no compute is priced at none while running without limit.
#[test]
fn a_preview_refuses_an_envelope_that_signed_no_ceilings() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);
    let key = Ed25519PrivateKey::from_bytes(&[7; 32]).unwrap();
    let graph = client()
        .transfer_graph(payer, bob(), 100)
        .expect("an account answers a transfer");
    let mut vm = client().sign(graph, &key, validity(), terms(PREVIEW_CEILING));
    vm.terms.gas_limits.clear();
    let tx = Transaction::new(vm);

    let report = preview_on(
        &[(payer, 1_000), (bob(), 50)],
        &executor,
        &tx,
        PreviewGrants::default(),
    );
    let PreviewOutcome::Refused { reason } = &report.outcome else {
        panic!(
            "an envelope with no ceilings must refuse: {:?}",
            report.outcome
        );
    };
    assert!(reason.contains("manifest nodes"), "reason = {reason}");
    assert_eq!(report.fee, 0);
    assert!(report.changes.is_empty());
}

/// A preview holds a node to its target's authority exactly as the chain
/// does, and nothing a caller may grant moves it.
///
/// The withdrawal names Alice and the intent acts as the payer; both are
/// signed content, so admission compares them itself and the shape never
/// becomes a transaction. There is nothing to assume past: acting as
/// Alice means an intent Alice signed, so an envelope without one is not
/// an envelope waiting for a signature — it is a different envelope, and
/// a wallet composing a two-party trade assembles that one instead.
#[test]
fn a_node_reaching_for_another_partys_authority_never_previews() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (alice(), 1_000), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    // Signed by 7 and reaching for Alice's account: the withdrawal
    // presents Alice, and the intent acts as 7 alone, so admission
    // refuses the presentation before any gate is asked.
    let tx = signed_transfer_with_fee(7, alice(), bob(), 100, PREVIEW_CEILING);

    let held = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    let PreviewOutcome::Refused { reason } = &held.outcome else {
        panic!("outcome = {:?}", held.outcome);
    };
    assert!(reason.contains("does not act as"), "reason = {reason}");
    // Nothing is priced and nothing moves: a shape admission refuses is
    // not a transaction, so there is no attempt for the payer to fund.
    assert_eq!(held.fee, 0);
    assert!(held.changes.is_empty(), "{:?}", held.changes);
}

/// A publish previews too, and it prices through the table like
/// anything else: its artifact is bytes written and retained, so the
/// declared vector already says what it costs and no rule of its own is
/// needed.
#[test]
fn a_preview_prices_a_publish_through_the_table() {
    let payer = fee_payer(7);
    let artifact = published_artifact();
    let executor = executor(ExecutionMode::Serial);
    let tx = signed_publish(7, artifact.clone());
    let report = preview_on(
        &[(payer, 1_000_000)],
        &executor,
        &tx,
        PreviewGrants::default(),
    );

    assert_eq!(report.outcome, PreviewOutcome::Completed);
    let quoted = tx
        .price_under(executor.derivation().as_ref(), &PriceTable::GENESIS)
        .expect("a publish derives");
    assert_eq!(report.fee, quoted);
    let work = tx
        .try_derived(executor.derivation().as_ref())
        .expect("a publish derives")
        .work;
    assert!(
        work.write_bytes >= artifact.len() as u64
            && work.retention >= artifact.len() as u64
            && quoted > 0,
        "the artifact's bytes are both written and retained, and the \
         table charges for each"
    );
    let vault = change_for(&report, payer);
    assert_eq!((vault.before, vault.after), (1_000_000, 1_000_000 - quoted));

    // An artifact that is not a package is refused at admission, so it
    // never enters a block and costs its publisher nothing.
    let junk = signed_publish(7, b"\0asm\x01\0\0\0".to_vec());
    let refused = preview_on(
        &[(payer, 1_000_000)],
        &executor,
        &junk,
        PreviewGrants::default(),
    );
    assert!(matches!(refused.outcome, PreviewOutcome::Refused { .. }));
    assert_eq!(refused.fee, 0);
}

#[test]
fn a_committed_cell_that_is_not_a_package_is_ignored() {
    // The other half: ordinary traffic cannot grow the cache by
    // accident, whatever it writes.
    let executor = executor(ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
    let executed = execute(&executor, &[tx]);
    let bogus = package_hash(&ProtocolHasher, encode_amount(900).as_ref());
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());
    assert!(
        executor.packages().load().get(bogus).is_none(),
        "vault writes are not packages"
    );
}

/// The full pipeline a runtime-published package rides: its cell
/// commits, its code compiles, and a presented instance of it — an
/// address computed by a client, created nowhere — answers a call whose
/// invocation runs the freshly compiled guest.
///
/// The call is the component's own seal, which is the first call any
/// published package answers: nothing else can run until the leaf whose
/// presence admission fences every component call on is there.
#[test]
fn a_presented_instance_of_a_published_package_answers_a_call() {
    let payer = fee_payer(7);
    let key = Ed25519PrivateKey::from_bytes(&[7; 32]).unwrap();
    let executor = executor(ExecutionMode::Serial);

    // The staking package rather than the account's: a published package
    // serves instances, so its components come up through the seal its
    // own package declares.
    let mut metadata = staking::metadata();
    naming(&mut metadata, "instantiable");
    let artifact = attach_metadata(STAKING_MODULE, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    let publish = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7, artifact,
    )));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[publish]);
    let ConsensusReceipt::Succeeded { .. } = &executed[0].consensus else {
        panic!("the publish must succeed: {:?}", executed[0].consensus);
    };
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());

    // The instance is computed, not created: a package hash, a
    // configuration, and a salt derive the address, and the presented
    // record carrying them is what resolves the call.
    let meta = InstanceMeta {
        package,
        config: Capped::new(vec![
            Value::Address((*PROTOCOL_RESOURCE).address()),
            Value::Address(payer.address()),
        ])
        .unwrap(),
        salt: Hash32([7; 32]),
    };
    let component = meta.address(&ProtocolHasher);

    // The seal answers its gate from the founder's own signature, and
    // the owner badge it mints is filed in that same account: bringing up
    // is one node, and the supply a component comes up holding leaves
    // with whoever composed it.
    let mut b = GraphBuilder::new();
    let [badge] = b.call_signed(payer, component, "instantiate", ());
    let owner_badge = issued_resource(
        &ProtocolHasher,
        component,
        ResourceKind::NonFungible,
        staking::OWNER_BADGE,
    );
    let [] = b.call(payer, "deposit_nf", (badge.resource_is(owner_badge),));
    let graph = b.build().expect("every output is consumed");
    let tree = IntentTree {
        root: Intent::leaf(HEADER, account_address(&key.public_key().0), graph),
        instances: Capped::new(vec![meta.clone()]).unwrap(),
        resources: Capped::empty(),
    };

    // The same call without its record: nothing committed answers for a
    // component nobody sealed, so derivation names the address it would
    // need rather than refusing the envelope. A gap, not a verdict —
    // which is the difference between an envelope that is wrong and one
    // this node cannot yet judge.
    let mut unpresented = tree.clone();
    unpresented.instances.clear();
    let bare = Transaction::new(client().sign_tree(&unpresented, &[&key], terms(TRANSFER_FEE)));
    let refusal = bare
        .try_derived(executor.derivation().as_ref())
        .expect_err("an unresolved instance target does not derive");
    assert_eq!(
        refusal
            .unresolved()
            .map(|wanted| wanted.instances.as_slice()),
        Some([component.address()].as_slice()),
        "the record this node would need, named: {refusal}"
    );

    // Claim: the call admits, the invocation resolves the freshly
    // compiled package — waiting out the compile if it is still in
    // flight — and the leaf holds the record the address derives from.
    let call = Transaction::new(client().sign_tree(&tree, &[&key], terms(TRANSFER_FEE)));
    let executed = execute_on(
        &[(payer, 1_000)],
        &executor,
        &[Arc::new(Verified::<Transaction>::from_persisted(call))],
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!(
            "the presented call must succeed: {:?}",
            executed[0].consensus
        );
    };
    assert_eq!(
        settled(writes, &[(payer, 1_000)])
            .cells()
            .get(&config_key(component))
            .cloned()
            .flatten(),
        Some(meta.leaf_bytes().expect("the record encodes")),
        "the seal writes the record the component's address derives"
    );
}

/// One declaration is one execution, whatever terms carry it.
///
/// The fee ceiling is signed content and the composer's key is not, so a
/// resubmission at a higher ceiling enters the transaction hash while the
/// signature does not — two identities over one graph, which dedup never
/// sees. What holds them to one execution is the nullifier under the
/// composer's own prefix, the rule every subintent is already held to. A
/// transaction that runs whole writes no escrow record, so there is
/// nothing else under that prefix to say the declaration already ran.
#[test]
fn a_resubmit_at_a_higher_ceiling_runs_the_declaration_once() {
    let executor = executor(ExecutionMode::Serial);
    let bump = |max_fee| {
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(ALICE_SEED, alice(), bob(), 100, max_fee),
        ))
    };
    let first = bump(TRANSFER_FEE);
    let second = bump(TRANSFER_FEE + 1);
    assert_eq!(
        decode_tree(&first.body().tree).unwrap().root.graph,
        decode_tree(&second.body().tree).unwrap().root.graph,
        "the premise: one declaration under two sets of terms",
    );
    assert_ne!(first.hash(), second.hash(), "which dedup cannot collapse");

    let accounts = [(alice(), 1_000), (bob(), 50)];
    let mut store = MapDb::genesis(&accounts);
    let mut outcomes = Vec::new();
    for tx in [&first, &second] {
        let executed = execute_batch_on(&store, &executor, &[Arc::clone(tx)]);
        outcomes.push(matches!(
            executed[0].consensus,
            ConsensusReceipt::Succeeded { .. }
        ));
        for e in &executed {
            if let Some(writes) = e.consensus.writes() {
                store.apply(writes);
            }
            if let Some(writes) = e
                .refusal_receipt
                .as_ref()
                .and_then(ConsensusReceipt::writes)
            {
                store.apply(writes);
            }
        }
    }
    assert_eq!(outcomes, vec![true, false], "the second is already spent");
    assert_eq!(
        store.cell(vault_key(bob(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(150).to_vec()),
        "the recipient is paid once",
    );
}

/// Whether `writes` delete the fee hold `tx` placed on `payer`'s vault.
fn releases_hold(writes: &StateWrites, payer: PrincipalAddr, tx: TxHash) -> bool {
    let hold = fee_hold_key(&ProtocolHasher, vault_key(payer, *PROTOCOL_RESOURCE), tx);
    writes.cells.get(&hold) == Some(&None)
}

/// Every write set that burns a transaction's price deletes the hold its
/// commit placed, whatever the burn comes to: a completed run's own
/// writes, a refused run's refusal receipt, a publish, and a charge built
/// apart.
#[test]
fn every_charge_carries_its_hold_release() {
    let executor = executor(ExecutionMode::Serial);
    let payer = fee_payer(7);

    let completed = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(7, payer, bob(), 100, 10),
    ));
    let executed = execute_on(
        &[(payer, 1_000), (bob(), 50)],
        &executor,
        std::slice::from_ref(&completed),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("the transfer succeeds: {:?}", executed[0].consensus);
    };
    assert!(releases_hold(writes, payer, completed.hash()));

    let refused = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        BOB_SEED,
        bob(),
        alice(),
        500,
    )));
    let executed = execute(&executor, std::slice::from_ref(&refused));
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
    let charge = executed[0]
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a refused run settles its price apart");
    assert!(releases_hold(charge, bob(), refused.hash()));

    let publish = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7,
        published_artifact(),
    )));
    let executed = execute_on(
        &[(payer, 1_000_000)],
        &executor,
        std::slice::from_ref(&publish),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("a publish succeeds: {:?}", executed[0].consensus);
    };
    assert!(releases_hold(writes, payer, publish.hash()));

    let vault = vault_key(payer, *PROTOCOL_RESOURCE);
    let apart = build_refusal_receipt(
        ShardId::ROOT,
        &ShardTrie::single(),
        TxHash::ZERO,
        Some((vault, Movement::unjudged(*PROTOCOL_RESOURCE, 0))),
        &[],
    )
    .expect("a charge names a receipt");
    assert!(
        apart
            .writes()
            .is_some_and(|writes| releases_hold(writes, payer, TxHash::ZERO)),
        "a charge of nothing still ends the hold"
    );
}

/// A receipt that charges nothing ends no hold: a member answering its
/// refusable crossings apart, with its price burned elsewhere or already.
#[test]
fn a_member_that_charges_nothing_releases_nothing() {
    let never = (vault_key(alice(), *PROTOCOL_RESOURCE), vec![1, 2, 3]);
    let receipt = build_refusal_receipt(
        ShardId::ROOT,
        &ShardTrie::single(),
        TxHash::ZERO,
        None,
        std::slice::from_ref(&never),
    )
    .expect("a Never names a receipt");
    let writes = receipt.writes().expect("a receipt of writes");
    assert_eq!(writes.cells.len(), 1, "{:?}", writes.cells);
    assert!(writes.movements.is_empty());
}

/// A payer's publish in the block after its own unsettled transfer
/// settles beside it without either debit running past the vault.
///
/// The transfer moves everything but its own price in tick 1. The
/// publish runs in tick 2 over that tick's output, where the vault holds
/// nothing: its burn is judged like every other debit, finds nothing to
/// take, and the publish is refused rather than recorded as a debit
/// nothing weighed.
///
/// What this pins is the engine's half: no judged debit leaves it past
/// the vault. It does not pin that the publish pays. The engine here is
/// handed a pair no admission covered, a publish whose hold the vault
/// could not stand behind once the transfer ran, so the publish rides
/// free. On a chain the pair never commits, since a block adds a hold
/// only where the settled balance covers it beside what its payer has in
/// flight; `a_payer_publishes_behind_its_unsettled_spend_sim` is the
/// test of that.
#[test]
fn a_publish_behind_its_payers_unsettled_spend_settles_within_the_vault() {
    const SEED: u8 = 31;
    const PUBLISH_FEE: u128 = 1_000_000;
    let payer = fee_payer(SEED);
    let executor = executor(ExecutionMode::Serial);
    let funded = TRANSFER_FEE + PUBLISH_FEE;
    let spend_of = |amount| signed_transfer_with_fee(SEED, payer, bob(), amount, TRANSFER_FEE);
    let price = price_of(&executor, &spend_of(1));
    let spend = verified(spend_of(funded - price));
    let publish = verified(signed_publish_under(
        SEED,
        published_artifact(),
        PUBLISH_FEE,
    ));

    let store = Arc::new(MapDb::genesis(&[(payer, funded), (bob(), 10)]));
    let chain = TickChain::new(Arc::clone(&store));
    let vault = vault_key(payer, *PROTOCOL_RESOURCE);
    let mut merged = StateWrites::default();

    chain.prune_persisted(BlockHeight::GENESIS, BlockHeight::GENESIS);
    let baseline = chain.view_at(BlockHeight::GENESIS);
    let moved = execute_batch_on(&baseline.snapshot(), &executor, &[spend]).remove(0);
    let ConsensusReceipt::Succeeded { writes, .. } = &moved.consensus else {
        panic!("the transfer completes: {:?}", moved.metadata);
    };
    fold_state_writes(&mut merged, writes);
    chain.append(
        BlockHeight::new(1),
        TickOutput {
            determined: vec![(moved.tx_hash, writes.clone())],
            provisional: Vec::new(),
        },
        &[],
    );

    chain.prune_persisted(BlockHeight::new(1), BlockHeight::GENESIS);
    let baseline = chain.view_at(BlockHeight::new(1));
    let published = execute_batch_on(&baseline.snapshot(), &executor, &[publish]).remove(0);
    assert!(
        matches!(published.consensus, ConsensusReceipt::Failed),
        "a publish its vault cannot pay for is refused: {:?}",
        published.consensus,
    );
    assert_eq!(charged(&published), 0);
    let apart = published
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a refused publish ends its hold apart");
    assert_eq!(
        apart.movements.get(&vault),
        Some(&Movement::unjudged(*PROTOCOL_RESOURCE, 0)),
        "the charge is what the floor left, which is nothing",
    );
    assert!(releases_hold(apart, payer, published.tx_hash));
    fold_state_writes(&mut merged, apart);

    let debit = merged.movements[&vault].debit;
    assert_eq!(
        debit,
        funded,
        "the transfer of {} at a price of {price} is the whole of what the two ticks debit",
        funded - price,
    );
    let settled = merged
        .resolve(&mut |key| store.cell(key))
        .expect("both ticks settle onto the funded vault");
    assert_eq!(vault_cell(&settled, payer), None, "the vault is spent");
}

fn verified(tx: Transaction) -> Arc<Verified<Transaction>> {
    Arc::new(Verified::<Transaction>::from_persisted(tx))
}

/// What a member's receipt reports it was charged.
const fn charged(executed: &ExecutedTx) -> u128 {
    executed
        .metadata
        .fee_summary
        .total_execution_cost
        .expect("an executed member reports its charge")
}

/// What a refused member's refusal receipt takes from `payer`'s vault.
fn charged_apart(executed: &ExecutedTx, payer: PrincipalAddr) -> Movement {
    *executed
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a refused member settles its price apart")
        .movements
        .get(&vault_key(payer, *PROTOCOL_RESOURCE))
        .expect("the charge names the payer's vault")
}

impl MapDb {
    /// Fold the fee holds a block carrying `block` includes, as its
    /// commit does.
    fn include(&mut self, executor: &Executor, block: &[Arc<Verified<Transaction>>]) {
        derived_through(executor, block);
        let fees: Vec<FeeTerms> = block.iter().map(|tx| FeeTerms::of(tx)).collect();
        let settled = with_fee_holds(
            SettledWrites::default(),
            &fees,
            &*self,
            &shard_prefix_path(ShardId::ROOT),
        );
        for (key, change) in settled.cells() {
            match change {
                Some(value) => self.0.insert(*key, value.clone()),
                None => self.0.remove(key),
            };
        }
    }
}

/// Run `members` as the tick of a block carrying `block`, over the
/// baseline `chain` gives the tick after `below` and under the fee holds
/// standing for it.
fn execute_under_holds(
    chain: &TickChain<MapDb>,
    below: BlockHeight,
    executor: &Executor,
    block: &[Arc<Verified<Transaction>>],
    members: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    derived_through(executor, block);
    derived_through(executor, members);
    let view = chain.view_at(below);
    let fees: Vec<FeeTerms> = block.iter().map(|tx| FeeTerms::of(tx)).collect();
    let fee_holds = view.fee_holds(&fees, &shard_prefix_path(ShardId::ROOT));
    let holds = view.holds();
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: sealed_env(0x5E),
        holds: &holds,
        fee_holds: &fee_holds,
    };
    executor
        .execute_batch(&ctx, PriceTable::GENESIS, &view.snapshot(), members)
        .expect("the harness engine holds every package it runs")
}

/// [`execute_under_holds`] for the first tick over `store`.
fn execute_first_tick(
    store: MapDb,
    executor: &Executor,
    block: &[Arc<Verified<Transaction>>],
    members: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let chain = TickChain::new(Arc::new(store));
    execute_under_holds(&chain, BlockHeight::GENESIS, executor, block, members)
}

/// The payer of the fee hold cases.
const HELD_SEED: u8 = 31;

fn held_payer() -> PrincipalAddr {
    fee_payer(HELD_SEED)
}

/// A transfer of `amount` from the held payer to Bob under `max_fee`.
fn held_transfer(amount: u128, max_fee: u128) -> Arc<Verified<Transaction>> {
    verified(signed_transfer_with_fee(
        HELD_SEED,
        held_payer(),
        bob(),
        amount,
        max_fee,
    ))
}

/// A vault holding exactly its payer's signed ceiling still burns the
/// price: the member's own hold ends where its burn is judged, so the
/// burn comes out of the value the hold kept.
#[test]
fn a_payer_holding_only_its_ceiling_burns_its_price() {
    let executor = executor(ExecutionMode::Serial);
    let mut store = with_lottery(&[(bob(), 50)], &executor);
    let price = price_of(&executor, &signed_settle_with_fee(ALICE_SEED, 1_000, ROUND));
    let ceiling = price + 50;
    let draw = verified(signed_settle_with_fee(ALICE_SEED, ceiling, ROUND));
    store.0.insert(
        vault_key(alice(), *PROTOCOL_RESOURCE),
        encode_amount(ceiling).to_vec(),
    );
    let executed = execute_first_tick(
        store,
        &executor,
        std::slice::from_ref(&draw),
        std::slice::from_ref(&draw),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("the draw completes: {:?}", executed[0].metadata);
    };
    assert_eq!(charged(&executed[0]), price);
    assert_eq!(
        writes.movements[&vault_key(alice(), *PROTOCOL_RESOURCE)],
        Movement::debit(*PROTOCOL_RESOURCE, price),
    );
    assert!(releases_hold(writes, alice(), draw.hash()));
}

/// A member nothing can abort holds its price against its own body and
/// no more, so a transfer moves everything its vault holds but the
/// price, whatever ceiling it signed.
#[test]
fn a_transfer_spends_its_own_slack_down_to_its_price() {
    let executor = executor(ExecutionMode::Serial);
    let funded = 1_000;
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    assert!(price < TRANSFER_FEE, "the ceiling leaves slack: {price}");
    let accounts = [(held_payer(), funded), (bob(), 10)];

    let all = held_transfer(funded - price, TRANSFER_FEE);
    let executed = execute_first_tick(
        MapDb::genesis(&accounts),
        &executor,
        std::slice::from_ref(&all),
        std::slice::from_ref(&all),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!(
            "a transfer down to its price completes: {:?}",
            executed[0].metadata
        );
    };
    assert!(vault_removed(&settled(writes, &accounts), held_payer()));

    let past = held_transfer(funded - price + 1, TRANSFER_FEE);
    let executed = execute_first_tick(
        MapDb::genesis(&accounts),
        &executor,
        std::slice::from_ref(&past),
        std::slice::from_ref(&past),
    );
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
    assert_eq!(
        charged_apart(&executed[0], held_payer()),
        Movement::unjudged(*PROTOCOL_RESOURCE, price),
        "a transfer into its own price is refused and charged it",
    );
}

/// A transaction the block carries that is no member of the batch holds
/// its whole ceiling against every member: a transfer moves the vault
/// down to that ceiling and its own price, and not one unit further.
#[test]
fn a_transfer_leaves_another_transactions_hold() {
    let executor = executor(ExecutionMode::Serial);
    let funded = 1_000;
    let other_ceiling = 300;
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    let accounts = [(held_payer(), funded), (bob(), 10)];
    // Committed by this block and run by a later tick.
    let other = held_transfer(7, other_ceiling);

    let within = held_transfer(funded - other_ceiling - price, TRANSFER_FEE);
    let executed = execute_first_tick(
        MapDb::genesis(&accounts),
        &executor,
        &[Arc::clone(&other), Arc::clone(&within)],
        std::slice::from_ref(&within),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!(
            "a transfer down to the other hold completes: {:?}",
            executed[0].metadata
        );
    };
    assert_eq!(
        vault_cell(&settled(writes, &accounts), held_payer()),
        Some(encode_amount(other_ceiling).to_vec()),
        "the other transaction's ceiling is what is left",
    );

    let past = held_transfer(funded - other_ceiling - price + 1, TRANSFER_FEE);
    let executed = execute_first_tick(
        MapDb::genesis(&accounts),
        &executor,
        &[Arc::clone(&other), Arc::clone(&past)],
        std::slice::from_ref(&past),
    );
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "one unit into the other hold is refused: {:?}",
        executed[0].consensus,
    );
    assert_eq!(
        charged_apart(&executed[0], held_payer()),
        Movement::unjudged(*PROTOCOL_RESOURCE, price),
        "and charged its whole price, which its own hold kept",
    );

    // The same hold standing in the base, from an earlier block.
    let mut store = MapDb::genesis(&accounts);
    store.include(&executor, std::slice::from_ref(&other));
    let executed = execute_first_tick(
        store,
        &executor,
        std::slice::from_ref(&past),
        std::slice::from_ref(&past),
    );
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
}

/// A hold whose member already ran, its burn in a layer the base does
/// not carry yet, is not held twice: the next tick reads the vault less
/// the burn and spends it down to its own price.
#[test]
fn a_hold_the_overlay_released_is_not_held() {
    let executor = executor(ExecutionMode::Serial);
    let funded = 1_000;
    let first_ceiling = 300;
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    let first = held_transfer(100, first_ceiling);
    let mut store = MapDb::genesis(&[(held_payer(), funded), (bob(), 10)]);
    store.include(&executor, std::slice::from_ref(&first));
    let chain = TickChain::new(Arc::new(store));

    let ran = execute_under_holds(
        &chain,
        BlockHeight::GENESIS,
        &executor,
        std::slice::from_ref(&first),
        std::slice::from_ref(&first),
    )
    .remove(0);
    let ConsensusReceipt::Succeeded { writes, .. } = &ran.consensus else {
        panic!("the first transfer completes: {:?}", ran.metadata);
    };
    chain.append(
        BlockHeight::new(1),
        TickOutput {
            determined: vec![(ran.tx_hash, writes.clone())],
            provisional: Vec::new(),
        },
        &[],
    );
    chain.prune_persisted(BlockHeight::new(1), BlockHeight::GENESIS);

    let left = funded - 100 - price;
    let rest = held_transfer(left - price, TRANSFER_FEE);
    let executed = execute_under_holds(
        &chain,
        BlockHeight::new(1),
        &executor,
        std::slice::from_ref(&rest),
        std::slice::from_ref(&rest),
    );
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "the released hold keeps nothing back: {:?}",
        executed[0].metadata,
    );
}

/// Two members of one payer in one batch, the vault holding exactly
/// their two ceilings: each burn comes out of its own hold and leaves
/// the other's standing, so both complete.
#[test]
fn two_members_of_one_payer_both_burn() {
    const ROUNDS: [u8; 2] = [0x4D, 0x4E];
    let executor = executor(ExecutionMode::Serial);
    let mut store = with_rounds(&[(bob(), 50)], &executor, &ROUNDS);
    let price = price_of(
        &executor,
        &signed_settle_with_fee(ALICE_SEED, 1_000, ROUNDS[0]),
    );
    let ceilings = [price + 7, price + 9];
    let draws: Vec<Arc<Verified<Transaction>>> = ROUNDS
        .into_iter()
        .zip(ceilings)
        .map(|(salt, ceiling)| verified(signed_settle_with_fee(ALICE_SEED, ceiling, salt)))
        .collect();
    let funded = ceilings[0] + ceilings[1];
    store.0.insert(
        vault_key(alice(), *PROTOCOL_RESOURCE),
        encode_amount(funded).to_vec(),
    );
    let chain = TickChain::new(Arc::new(MapDb(store.0.clone())));
    let executed = execute_under_holds(&chain, BlockHeight::GENESIS, &executor, &draws, &draws);
    for member in &executed {
        let ConsensusReceipt::Succeeded { writes, .. } = &member.consensus else {
            panic!("both draws complete: {:?}", member.metadata);
        };
        assert_eq!(charged(member), price);
        store.apply(writes);
    }
    assert_eq!(
        store.cell(vault_key(alice(), *PROTOCOL_RESOURCE)),
        Some(encode_amount(funded - 2 * price).to_vec()),
    );
}

/// A vault holding nothing has no cell and still has the holds standing
/// on it. A credit landing on it in the batch is spoken for by them: the
/// charge of a member refused there finds only what the credit leaves
/// past the other hold.
#[test]
fn a_vault_at_zero_keeps_its_floor() {
    let executor = executor(ExecutionMode::Serial);
    let other_ceiling = 100;
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    let vault = vault_key(held_payer(), *PROTOCOL_RESOURCE);
    // Committed by this block and run by a later tick.
    let other = held_transfer(7, other_ceiling);

    let charged_over = |credit: u128, block_holds_other: bool| {
        let store = MapDb::genesis(&[(alice(), 1_000), (bob(), 10)]);
        assert_eq!(store.cell(vault), None, "the vault holds no cell");
        let fund = verified(signed_transfer(ALICE_SEED, alice(), held_payer(), credit));
        let spend = held_transfer(credit, TRANSFER_FEE);
        let mut block = vec![Arc::clone(&fund), Arc::clone(&spend)];
        if block_holds_other {
            block.push(Arc::clone(&other));
        }
        let executed = execute_first_tick(
            store,
            &executor,
            &block,
            &[Arc::clone(&fund), Arc::clone(&spend)],
        );
        assert!(
            matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
            "the credit lands: {:?}",
            executed[0].metadata,
        );
        assert!(
            matches!(executed[1].consensus, ConsensusReceipt::Failed),
            "the member reserving from the empty vault is refused: {:?}",
            executed[1].consensus,
        );
        assert_eq!(
            charged(&executed[1]),
            charged_apart(&executed[1], held_payer()).unjudged_debit
        );
        charged_apart(&executed[1], held_payer())
    };

    assert_eq!(
        charged_over(other_ceiling - 40, true),
        Movement::unjudged(*PROTOCOL_RESOURCE, 0),
        "a credit short of the other hold leaves the charge nothing",
    );
    assert_eq!(
        charged_over(other_ceiling + 3, true),
        Movement::unjudged(*PROTOCOL_RESOURCE, 3),
        "a credit past it leaves the charge the difference",
    );
    assert_eq!(
        charged_over(other_ceiling - 40, false),
        Movement::unjudged(*PROTOCOL_RESOURCE, price),
        "with no other hold standing the same credit pays the whole price",
    );
}

/// A member that applied nothing is charged what the floor leaves once
/// its own hold has ended: its whole price where the vault covers the
/// holds standing on it, and no more than is left past the others where
/// it does not.
#[test]
fn a_refused_members_charge_is_what_the_floor_leaves() {
    let executor = executor(ExecutionMode::Serial);
    let other_ceiling = 300;
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    let other = held_transfer(7, other_ceiling);
    // A transfer of more than any funding below holds.
    let refused = held_transfer(10_000, TRANSFER_FEE);

    let refused_over = |funded: u128| {
        let executed = execute_first_tick(
            MapDb::genesis(&[(held_payer(), funded), (bob(), 10)]),
            &executor,
            &[Arc::clone(&other), Arc::clone(&refused)],
            std::slice::from_ref(&refused),
        )
        .remove(0);
        assert!(matches!(executed.consensus, ConsensusReceipt::Failed));
        let apart = executed
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes)
            .expect("a refused member settles its price apart");
        assert!(releases_hold(apart, held_payer(), refused.hash()));
        (charged(&executed), charged_apart(&executed, held_payer()))
    };

    // Covered: the vault holds both ceilings, as admission requires.
    assert_eq!(
        refused_over(other_ceiling + TRANSFER_FEE),
        (price, Movement::unjudged(*PROTOCOL_RESOURCE, price)),
    );
    // Short: three units past the other transaction's hold.
    assert_eq!(
        refused_over(other_ceiling + 3),
        (3, Movement::unjudged(*PROTOCOL_RESOURCE, 3)),
    );
    // Nothing past it.
    assert_eq!(
        refused_over(other_ceiling),
        (0, Movement::unjudged(*PROTOCOL_RESOURCE, 0)),
    );
}

/// A publish burns through the same judgement as every other price: one
/// the vault covers under the other holds standing on it is a judged
/// debit in its writes, and one it does not cover is a refused publish
/// that writes no artifact and is charged what is left.
#[test]
fn a_publish_past_the_floor_is_refused() {
    const PUBLISH_FEE: u128 = 1_000_000;
    let executor = executor(ExecutionMode::Serial);
    let other_ceiling = 300;
    let other = held_transfer(7, other_ceiling);
    let artifact = published_artifact();
    let publish = verified(signed_publish_under(
        HELD_SEED,
        artifact.clone(),
        PUBLISH_FEE,
    ));
    derived_through(&executor, std::slice::from_ref(&publish));
    let price = price_of(&executor, &publish);
    let vault = vault_key(held_payer(), *PROTOCOL_RESOURCE);

    let published_over = |funded: u128| {
        execute_first_tick(
            MapDb::genesis(&[(held_payer(), funded), (bob(), 10)]),
            &executor,
            &[Arc::clone(&other), Arc::clone(&publish)],
            std::slice::from_ref(&publish),
        )
        .remove(0)
    };

    let paid = published_over(other_ceiling + price);
    let ConsensusReceipt::Succeeded { writes, .. } = &paid.consensus else {
        panic!("a publish its vault covers completes: {:?}", paid.metadata);
    };
    assert_eq!(
        writes.movements[&vault],
        Movement::debit(*PROTOCOL_RESOURCE, price),
        "the burn is a judged debit",
    );
    assert!(package_cell(writes, &artifact).is_some());
    assert!(releases_hold(writes, held_payer(), publish.hash()));
    assert!(paid.refusal_receipt.is_none());
    assert_eq!(charged(&paid), price);

    let short = published_over(other_ceiling + price - 1);
    assert!(
        matches!(short.consensus, ConsensusReceipt::Failed),
        "one unit short of its price under the other hold is refused: {:?}",
        short.consensus,
    );
    assert_eq!(
        charged_apart(&short, held_payer()),
        Movement::unjudged(*PROTOCOL_RESOURCE, price - 1),
        "and charged what the floor left",
    );
    assert_eq!(charged(&short), price - 1);
    let apart = short
        .refusal_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("a refused publish settles apart");
    assert!(releases_hold(apart, held_payer(), publish.hash()));
    assert!(package_cell(apart, &artifact).is_none());
}

/// Where one payer's transactions stand relative to the batch under
/// test.
#[derive(Clone, Copy, Debug)]
enum Standing {
    /// Committed by the tick's block and run by its batch.
    Member,
    /// Committed by the tick's block and run by a later tick.
    Included,
    /// Committed by an earlier block, its hold in the base.
    Base,
}

/// What admission covers, execution burns: with the vault holding at
/// least every ceiling standing on it, each member of the batch is
/// charged its whole price, whatever its body tried to move and however
/// the payer's transactions fall across the batch, its block and the
/// base. No charge is capped, and what the batch leaves still covers
/// every hold it did not end.
#[test]
fn what_admission_covers_execution_burns() {
    let executor = executor(ExecutionMode::Serial);
    let price = price_of(&executor, &held_transfer(1, TRANSFER_FEE));
    let standing = prop_oneof![
        Just(Standing::Member),
        Just(Standing::Member),
        Just(Standing::Included),
        Just(Standing::Base),
    ];
    // Each transaction: the share of the vault its body reaches for, in
    // twentieths, the room its ceiling leaves over its price, and where
    // it stands.
    let payers_transactions = prop::collection::vec((0u128..=21, 0u128..200, standing), 1..5);
    let mut runner = TestRunner::new(ProptestConfig::with_cases(64));
    runner
        .run(&(payers_transactions, 0u128..300), |(drawn, slack)| {
            let ceilings: u128 = drawn.iter().map(|(_, room, _)| price + room).sum();
            let funded = ceilings + slack;
            let transactions: Vec<(Arc<Verified<Transaction>>, u128, Standing)> = drawn
                .into_iter()
                .enumerate()
                .map(|(index, (share, room, standing))| {
                    // Distinct amounts keep the transactions distinct.
                    let amount = 1 + funded * share / 20 + index as u128;
                    let ceiling = price + room;
                    (held_transfer(amount, ceiling), ceiling, standing)
                })
                .collect();
            let of = |wanted: fn(Standing) -> bool| -> Vec<Arc<Verified<Transaction>>> {
                transactions
                    .iter()
                    .filter(|(_, _, standing)| wanted(*standing))
                    .map(|(tx, _, _)| Arc::clone(tx))
                    .collect()
            };
            let members = of(|standing| matches!(standing, Standing::Member));
            let block = of(|standing| !matches!(standing, Standing::Base));
            let based = of(|standing| matches!(standing, Standing::Base));

            let mut store = MapDb::genesis(&[(held_payer(), funded), (bob(), 10)]);
            store.include(&executor, &based);
            let chain = TickChain::new(Arc::new(MapDb(store.0.clone())));
            let executed =
                execute_under_holds(&chain, BlockHeight::GENESIS, &executor, &block, &members);

            for member in &executed {
                prop_assert_eq!(charged(member), price, "{:?}", member.metadata);
                match &member.consensus {
                    ConsensusReceipt::Succeeded { writes, .. } => store.apply(writes),
                    ConsensusReceipt::Failed => {
                        let apart = charged_apart(member, held_payer());
                        prop_assert_eq!(apart, Movement::unjudged(*PROTOCOL_RESOURCE, price));
                        store.apply(
                            member
                                .refusal_receipt
                                .as_ref()
                                .and_then(ConsensusReceipt::writes)
                                .expect("a refused member settles apart"),
                        );
                    }
                }
            }
            let left = store
                .cell(vault_key(held_payer(), *PROTOCOL_RESOURCE))
                .map_or(0, |cell| decode_held(&cell));
            let still_held: u128 = transactions
                .iter()
                .filter(|(_, _, standing)| !matches!(standing, Standing::Member))
                .map(|(_, ceiling, _)| ceiling)
                .sum();
            prop_assert!(
                left >= still_held,
                "the batch left {left} under holds of {still_held}",
            );
            Ok(())
        })
        .expect("every covered burn completes");
}

/// What the record key of a reclaim case holds below the fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keyed {
    /// The record.
    Record,
    /// Nothing: not yet written, or already disposed.
    Nothing,
    /// Bytes that are no record.
    Bytes,
}

/// Where a record under test says its value goes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recourse {
    /// Nowhere: an owed record.
    Owed,
    /// The producer's vault for the record's resource.
    Vault,
    /// A cell of the producer's holding bytes that are no amount.
    Bytes,
    /// A vault under the other shard's prefix.
    Elsewhere,
    /// The record's own cell.
    Itself,
}

/// The consumer's `Never` a case reads for its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Declined {
    /// The record's own decline cell, stating its own transaction's
    /// `Never`.
    Own,
    /// The record's own decline cell, stating another transaction's.
    Stranger,
    /// Another crossing's decline cell.
    OtherCrossing,
}

/// The transaction that issued a case's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Issuer {
    /// One whose fee payer is on the other shard.
    PaidElsewhere,
    /// One whose fee payer is the producer.
    PaidHere,
}

/// One record a block asks the fold to take back, with the state it is
/// asked against.
#[derive(Clone, Copy, Debug)]
struct ReclaimCase {
    keyed: Keyed,
    recourse: Recourse,
    resource: ResourceAddr,
    amount: u128,
    /// What the credited cell holds below the reclaim.
    prior: Option<u128>,
    declined: Declined,
    issuer: Issuer,
}

/// The fixed parts of every reclaim case.
struct ReclaimFixture {
    near: ShardId,
    home: ShardId,
    genesis: BTreeMap<SubstateKey, Vec<u8>>,
    paid_elsewhere: Arc<Verified<Transaction>>,
    paid_here: Arc<Verified<Transaction>>,
    id: CrossingId,
}

impl ReclaimFixture {
    fn new() -> Self {
        let executor = executor(ExecutionMode::Serial);
        let trie = ShardTrie::uniform(1);
        let paid_elsewhere = transfer_paid_by_the_recipient();
        let paid_here = verified(signed_transfer_with_fee(
            ALICE_SEED,
            alice(),
            far(),
            100,
            TRANSFER_FEE,
        ));
        derived_through(&executor, &[paid_elsewhere.clone(), paid_here.clone()]);
        Self {
            near: trie.shard_for_prefix(alice()),
            home: trie.shard_for_prefix(far()),
            genesis: MapDb::genesis(&[(alice(), 1_000), (far(), 50)]).0,
            paid_elsewhere,
            paid_here,
            id: CrossingId {
                producer: alice().address(),
                consumer: far().address(),
                intent: IntentHash(Hash32([0x5A; 32])),
                local: 0,
                output: 0,
            },
        }
    }

    /// The transaction `issuer` names.
    fn issuer(&self, issuer: Issuer) -> TxHash {
        match issuer {
            Issuer::PaidElsewhere => self.paid_elsewhere.hash(),
            Issuer::PaidHere => self.paid_here.hash(),
        }
    }

    /// The cell `case`'s record credits, where it credits one.
    fn credit(&self, case: &ReclaimCase) -> Option<SubstateKey> {
        match case.recourse {
            Recourse::Owed => None,
            Recourse::Vault => Some(vault_key(alice(), case.resource)),
            Recourse::Bytes => Some(SubstateKey {
                owner: alice().address(),
                local: LocalKey([0x9C; 16]),
            }),
            Recourse::Elsewhere => Some(vault_key(far(), case.resource)),
            Recourse::Itself => Some(self.id.record_key(&ProtocolHasher)),
        }
    }

    /// The state below `case`'s reclaim, and the record key it names.
    fn state(&self, case: &ReclaimCase) -> (MapDb, SubstateKey) {
        let issuer = self.issuer(case.issuer);
        let record = self.id.record_key(&ProtocolHasher);
        let mut store = MapDb(self.genesis.clone());
        let credit = self.credit(case);
        let terms = credit.map_or(CrossingTerms::Owed, |credit| CrossingTerms::Escrowed {
            credit,
        });
        let cell = self
            .id
            .cell(issuer, case.resource, case.amount, OFFER_MS, terms);
        if let Some(credit) = credit {
            match (case.recourse, case.prior) {
                (Recourse::Bytes, _) => {
                    store.0.insert(credit, vec![1, 2, 3]);
                }
                (_, Some(prior)) => {
                    store.0.insert(credit, encode_amount(prior).to_vec());
                }
                (_, None) => {
                    store.0.remove(&credit);
                }
            }
        }
        match case.keyed {
            Keyed::Record => {
                store.0.insert(record, cell.to_bytes());
            }
            Keyed::Nothing => {
                store.0.remove(&record);
            }
            Keyed::Bytes => {
                store.0.insert(record, vec![0xFF; 7]);
            }
        }
        (store, record)
    }

    /// The decline cell `case` reads, the crossing it is named for, and
    /// the hash of the `Never` it states.
    fn declined(&self, case: &ReclaimCase) -> (SubstateKey, CrossingId, [u8; 32]) {
        let issuer = self.issuer(case.issuer);
        let stranger = TxHash::from(Hash::from_bytes(b"stranger"));
        let (id, tx) = match case.declined {
            Declined::Own => (self.id, issuer),
            Declined::Stranger => (self.id, stranger),
            Declined::OtherCrossing => (
                CrossingId {
                    output: 99,
                    ..self.id
                },
                issuer,
            ),
        };
        let never = id.answer(tx, Answered::Never, OFFER_MS).to_bytes();
        (
            id.answer_key(&ProtocolHasher, Answered::Never),
            id,
            jmt_value_hash(&never),
        )
    }

    /// What the producer's commit fold returns for `case` over `store`:
    /// the record as the block's parent holds it, read beside the
    /// consumer's `Never` at a boundary of the consumer's shard.
    fn fold(&self, store: &MapDb, record: SubstateKey, case: &ReclaimCase) -> StateWrites {
        let held = store.cell(record).map_or_else(
            || Inclusion::Absent.into(),
            |bytes| {
                if matches!(
                    CrossingLeaf::read(&ProtocolHasher, record, &bytes),
                    Some(CrossingLeaf::Record { .. })
                ) {
                    Stated::Held(Bytes::new(bytes).expect("a record fits"))
                } else {
                    Inclusion::Present(jmt_value_hash(&bytes)).into()
                }
            },
        );
        let parent = StateClaim::new(
            Anchor {
                shard: self.near,
                height: BlockHeight::new(4),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::ZERO,
            },
            [(record, held)],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, self.id)]);
        let (read, id, stated) = self.declined(case);
        let never = StateClaim::new(
            Anchor {
                shard: self.home,
                height: BlockHeight::new(2),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(1_000),
            },
            [(read, Inclusion::Present(stated))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(read, id)]);
        let block = WeightedTimestamp::from_millis(1_001).plus(RETENTION_HORIZON);
        reclaim_credits(
            &reclaimed(&[parent, never], self.near, block),
            self.near,
            &StateWrites::default(),
            store,
        )
    }
}

/// Every single-record case: each record shape, each state its credited
/// cell can stand in, each `Never` a block can read beside it and each
/// transaction issuing the record.
fn reclaim_cases() -> Vec<ReclaimCase> {
    let other_resource = ResourceAddr::new([0xE1; 31]);
    let mut cases = Vec::new();
    for keyed in [Keyed::Record, Keyed::Nothing, Keyed::Bytes] {
        for recourse in [
            Recourse::Owed,
            Recourse::Vault,
            Recourse::Bytes,
            Recourse::Elsewhere,
            Recourse::Itself,
        ] {
            for resource in [*PROTOCOL_RESOURCE, other_resource] {
                for amount in [0, 1, 100, u128::MAX] {
                    let priors: BTreeSet<Option<u128>> =
                        [None, Some(1), Some(u128::MAX - amount), Some(u128::MAX)]
                            .into_iter()
                            .filter(|prior| *prior != Some(0))
                            .collect();
                    for prior in priors {
                        for declined in [Declined::Own, Declined::Stranger, Declined::OtherCrossing]
                        {
                            for issuer in [Issuer::PaidElsewhere, Issuer::PaidHere] {
                                cases.push(ReclaimCase {
                                    keyed,
                                    recourse,
                                    resource,
                                    amount,
                                    prior,
                                    declined,
                                    issuer,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    cases
}

/// What the fold writes for `case`: the record removed and its amount
/// credited, as one movement of its resource, where the record stands
/// and its own transaction's `Never` is read beside it; nothing anywhere
/// else.
///
/// The credit lands at the producer's vault for the record's resource
/// whatever cell the record names: that vault is the cell itself where
/// the record names it, whether it lands whole there or the excess
/// burns, and the vault a return goes to where the cell it names holds
/// bytes that are no amount, is the record itself, or sits under the
/// other shard's prefix.
fn returned_by_the_fold(fixture: &ReclaimFixture, case: &ReclaimCase) -> StateWrites {
    let mut writes = StateWrites::default();
    if case.keyed == Keyed::Record
        && case.recourse != Recourse::Owed
        && case.declined == Declined::Own
    {
        writes
            .cells
            .insert(fixture.id.record_key(&ProtocolHasher), None);
        writes.movements.insert(
            vault_key(alice(), case.resource),
            Movement {
                resource: case.resource,
                credit: case.amount,
                debit: 0,
                unjudged_debit: 0,
            },
        );
    }
    writes
}

/// A record the producer's commit fold takes back is a removal and one
/// credit, over every case of [`reclaim_cases`]: the record removed and
/// its amount credited to the producer's vault, where its own
/// transaction's `Never` is read beside it, and nothing in every other
/// case.
#[test]
fn a_fold_reclaim_writes_a_removal_and_one_credit() {
    let fixture = ReclaimFixture::new();
    let mut taken = 0u32;
    let mut differing: BTreeMap<String, u32> = BTreeMap::new();
    let cases = reclaim_cases();
    for case in &cases {
        let (store, record) = fixture.state(case);
        let fold = fixture.fold(&store, record, case);
        taken += u32::from(!fold.is_empty());
        let expected = returned_by_the_fold(&fixture, case);
        if fold != expected {
            *differing
                .entry(format!("{case:?}: wrote {fold:?}, expected {expected:?}"))
                .or_default() += 1;
        }
    }
    assert!(taken > 0, "some case takes its record back");
    assert!(
        differing.is_empty(),
        "{} of {} cases differ ({taken} taken back): {differing:#?}",
        differing.values().sum::<u32>(),
        cases.len(),
    );
}
