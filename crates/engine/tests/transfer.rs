//! The VM engine end to end at the seam: signed transfer graphs through
//! derivation, the batch executor, and the movement fold, against a
//! genesis-seeded snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::vm_statics::{config_key, package_key};
use hyperscale_effects_bridge::{
    ProtocolHasher, account_address, admit_package, admit_protocol_package, attach_metadata,
};
use hyperscale_engine::genesis::{
    GenesisPackages, account_artifact, draw_key, genesis_world_with_pools, vault_key,
};
use hyperscale_engine::legs::{Classified, Licence, Member, PlanDefect, Runs, Side};
use hyperscale_engine::sharding::writes_root;
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PreviewGrants, PreviewInputs, PreviewOutcome,
    PreviewReport, ResourceChange, TickBatchContext, TickEnvironment, TickTxInput, XRD,
    genesis_writes,
};
use hyperscale_hbor::TypeShape;
use hyperscale_storage::{
    Anchored, SubstateStore, Substates, TickChain, TickOutput, VersionedStore,
};
use hyperscale_transactions::{Client, Terms};
use hyperscale_types::{
    BeaconWitnessEvent, BeaconWitnessRoot, BlockHeight, ComponentAddr, ConsensusReceipt, Deadline,
    DeclaredRange, Ed25519PrivateKey, EnvelopeExt, EpochWindows, EscrowedValue, EventExt,
    EventRoot, GlobalReceipt, Hash, MAX_SUBINTENT_VALIDITY_RANGE, NetworkId, PrincipalAddr,
    ProvisionalHolds, SchemeId, SettledWrites, ShardId, ShardTrie, StateRoot, StateWrites,
    SubstateKey, TimestampRange, Transaction, TransactionBody, TransactionEnvelope, TxHash,
    Verified, WeightedTimestamp, Window, absorb_committed_cells, compute_merkle_root,
};
use hyperscale_vm_effects::{
    AbiParam, Composed, CrossingCell, EnvelopeTree, Hash32, InstanceMeta, IntentDecl, IntentHeader,
    PackageHash, PackageMetadata, ResourceKind, Totality, Value, issued_resource, package_hash,
};
use hyperscale_vm_fixtures::{lottery, lottery_package_hash};
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, GraphBuilder};
use hyperscale_vm_stdlib::{STAKING_COMPONENT, account, instantiate, staking};
use hyperscale_vm_types::{
    Address, CollectionId, SEAL_MATURITY_EPOCHS, SeedWindow, amount_cell, encode_amount,
};

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
        config: Vec::new(),
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
        validity: TimestampRange::new(
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(OFFER_MS),
        ),
        message: Vec::new(),
    }
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
    let funds = account::withdraw(&mut b, from, *XRD, amount).expect("an account withdraws");
    account::deposit(&mut b, to, funds.min(min)).expect("an account deposits");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, terms(max_fee)))
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
    let [funds] = b.call_signed(from, "withdraw", (*XRD, amount));
    let [] = b.call(to, "deposit", (funds.resource_is(*XRD),));
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key, terms(max_fee)))
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
    Transaction::new(client().sign(graph, &key, terms(max_fee)))
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
    tx.price_under(executor.derivation().as_ref())
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
    let (mut env, mut root) =
        EnvelopeBuilder::new(&composed, &ProtocolHasher, fee_payer(seed), HEADER);
    lottery::Lottery::at(lottery_addr)
        .settle(&mut root, 64)
        .expect("a lottery answers a settlement");
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");
    Transaction::new(client().sign_tree(&tree, Vec::new(), &key, terms(max_fee)))
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
        let (mut env, mut root) =
            EnvelopeBuilder::new(&composed, &ProtocolHasher, fee_payer(SEALER_SEED), HEADER);
        instantiate(&mut root, fee_payer(SEALER_SEED), round)
            .expect("a derivable round answers its seal");
        env.register_instance(lottery_meta(*salt));
        env.seal(root)
            .expect("the root declares nothing to discharge")
            .none()
            .expect("the root declares no socket");
        let tree = env.build().expect("the intent declares no hole");
        let seal = Transaction::new(client().sign_tree(&tree, Vec::new(), &key, terms(1_000_000)));
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
            Vec::new(),
            &key,
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
fn closing_tree(salt: u8, signer: PrincipalAddr) -> EnvelopeTree {
    let chain = client().records();
    let composed = Composed::new(&chain, &[lottery_meta(salt)], &ProtocolHasher);
    let (mut env, mut root) = EnvelopeBuilder::new(&composed, &ProtocolHasher, signer, HEADER);
    lottery::Lottery::at(lottery_meta(salt).address(&ProtocolHasher))
        .close(&mut root)
        .expect("a lottery answers a close");
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    env.build().expect("the intent declares no hole")
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
    };
    derived_through(executor, transactions);
    executor.execute_batch(&ctx, store, transactions)
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
    // Nothing settles between them, so the base never moves; tick 2's
    // baseline is tick 1's output over it.
    let chain = TickChain::new(Arc::new(MapDb::genesis(&accounts)));
    let mut chained = Vec::new();
    for (height, (seed, from)) in [(31u8, payer_a), (32, payer_b)].into_iter().enumerate() {
        let tick = BlockHeight::new(height as u64 + 1);
        let baseline = chain.view_at(BlockHeight::new(height as u64));
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
    };
    derived_through(executor, transactions);
    executor.execute_batch(&ctx, snapshot_store, transactions)
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

fn settled(writes: &StateWrites, accounts: &[(PrincipalAddr, u128)]) -> SettledWrites {
    eprintln!(
        "SETTLEDBG cells={:?} movements={:?} accounts={:?}",
        writes.cells.keys().collect::<Vec<_>>(),
        writes.movements,
        accounts
            .iter()
            .map(|(o, a)| (vault_key(*o, *XRD), a))
            .collect::<Vec<_>>()
    );
    writes
        .resolve(&mut |key| {
            accounts
                .iter()
                .find(|(owner, _)| vault_key(*owner, *XRD) == key)
                .and_then(|(_, amount)| amount_cell(*amount).map(|cell| cell.to_vec()))
        })
        .expect("the debit fits")
}

fn vault_cell(writes: &SettledWrites, owner: impl Into<Address>) -> Option<Vec<u8>> {
    writes
        .cells()
        .get(&vault_key(owner, *XRD))
        .cloned()
        .flatten()
}

/// Whether the batch removed the vault cell outright — a drain, never a
/// zero write.
fn vault_removed(writes: &SettledWrites, owner: impl Into<Address>) -> bool {
    writes.cells().get(&vault_key(owner, *XRD)) == Some(&None)
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
        if let Some(writes) = e.fee_receipt.as_ref().and_then(ConsensusReceipt::writes) {
            store.apply(writes);
        }
    }
    assert_eq!(
        store.cell(vault_key(alice(), *XRD)),
        Some(encode_amount(1_000 - 25 - price_of(&executor, &fine)).to_vec())
    );
    assert_eq!(
        store.cell(vault_key(bob(), *XRD)),
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
        .fee_receipt
        .as_ref()
        .and_then(|receipt| receipt.writes())
        .expect("a charged failure settles its price");
    db.apply(charge);
    db.apply(writes);
    assert_eq!(
        db.cell(vault_key(bob(), *XRD)),
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
/// An attempt that applies nothing still attests the declaration it made,
/// and a completed one attests strictly more.
///
/// This is the half of attested work that fuel alone misses. A shard that
/// executes a leg it does not own can burn almost no fuel while holding the
/// exclusivity its declaration claimed, so pricing on compute alone would
/// under-pay exactly the participants cross-shard compensation exists for.
/// Here the same shape is visible within one shard: the uncovered
/// withdrawal never applies an effect, and its work is still positive
/// because the declaration was admitted, routed, and locked regardless.
#[test]
fn an_unapplied_attempt_still_attests_its_declaration() {
    let executor = executor(ExecutionMode::Serial);
    let over = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        1_000_000,
    )));
    let executed = execute(&executor, &[over]);
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "an uncovered withdrawal must not apply"
    );
    let unapplied = executed[0].attested_work;
    assert!(
        unapplied > 0,
        "an attempt that applied nothing still declared, routed, and locked"
    );

    // A completed transfer of the same shape attests the same declaration
    // plus the compute it actually consumed.
    let fine = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
    let executed = execute(&executor, &[fine]);
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "a covered transfer must apply"
    );
    assert!(
        executed[0].attested_work > unapplied,
        "a completed execution attests its compute on top of its declaration: \
         completed = {}, unapplied = {unapplied}",
        executed[0].attested_work,
    );
}

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
            !writes.cells.contains_key(&vault_key(sibling, *XRD)),
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
        store.cell(vault_key(alice(), *XRD)),
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
    }) = executed[0].fee_receipt.as_ref()
    else {
        panic!("a charged abort settles a fee receipt");
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
    };
    derived_through(executor, transactions);
    executor.execute_batch(&ctx, &snapshot_store, transactions)
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

fn hash_of(executed: &ExecutedTx) -> Hash {
    let ConsensusReceipt::Succeeded { receipt_hash, .. } = &executed.consensus else {
        panic!("transfer must succeed");
    };
    *receipt_hash.as_raw()
}

/// A transfer's two legs emit from accounts on different shards. Each
/// shard's receipt keeps only the events its own instances emitted,
/// while the receipt hash stays identical under whole locality — this
/// batch has no abortable member, so the writes root covers the full
/// fold on both sides. On the abortable path the roots are per shard by
/// design; the union event root is what both paths share.
#[test]
fn an_event_lands_only_on_its_emitters_home_shard() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    assert_ne!(
        near_shard, far_shard,
        "the two accounts must sit on different shards"
    );

    // A zero ceiling: the fee burn is a payer-shard write, so a nonzero
    // fee would make the union differ by exactly that cell between the
    // two sides. Events are the subject here; the fee stays out of it.
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    let sender_side = execute_on_shard(&executor, near_shard, std::slice::from_ref(&tx));
    let recipient_side = execute_on_shard(&executor, far_shard, &[tx]);

    assert_eq!(events_of(&sender_side[0]), vec![(alice().address(), 0)]);
    assert_eq!(events_of(&recipient_side[0]), vec![(far().address(), 1)]);
    assert_eq!(
        hash_of(&sender_side[0]),
        hash_of(&recipient_side[0]),
        "under whole locality the hash covers the full fold, so it cannot differ by shard",
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
    let divided = Classified::freeze(tx.legs(), tx.owners(), &trie);
    assert!(divided.decomposed(), "a transfer decomposes");
    assert_eq!(divided.core(), &BTreeSet::from([near_shard]));

    let edges = divided.edges();
    assert_eq!(edges.len(), 1, "one value edge crosses");
    let edge = &edges[0];
    assert_eq!(edge.from, near_shard);
    assert_eq!(edge.to, BTreeSet::from([far_shard]));

    let sender = divided
        .plan(&[], near_shard, Side::Issuing)
        .expect("the sender's legs take no arrival");
    assert!(!sender.legs.is_whole());
    assert!(
        sender.legs.departure(edge.producer, edge.output).is_some(),
        "the withdraw departs",
    );
    assert!(sender.judges.covers(alice()) && !sender.judges.covers(far()));

    let arrived = EscrowedValue {
        node: edge.producer,
        output: edge.output,
        resource: *XRD,
        amount: 100,
        record: edge.record.key(),
    };
    let recipient = divided
        .plan(std::slice::from_ref(&arrived), far_shard, Side::Delivering)
        .expect("the recipient's leg has its arrival");
    assert!(recipient.legs.arrival(edge.producer, edge.output).is_some());
    assert!(
        recipient
            .legs
            .departure(edge.producer, edge.output)
            .is_none()
    );
    assert!(recipient.judges.covers(far()) && !recipient.judges.covers(alice()));

    assert!(matches!(
        divided.plan(&[], far_shard, Side::Delivering),
        Err(PlanDefect::MissingArrival { .. }),
    ));
}

/// A transfer executed divided, end to end through the engine: the
/// sender's shard runs the sign-in and the withdraw, escrows the value
/// into the record cell the plan filed, and attests exactly that; the
/// recipient's shard runs the deposit against the attested arrival and
/// escrows nothing. Neither side runs the other's leg.
#[test]
fn a_transfer_executes_divided_on_both_shards() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.owners(), &trie);
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
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            // A leg awaiting nobody but its own shard: nothing retracts
            runs: Runs::Shape(Member::of(
                classified.clone(),
                local_shard,
                classified.first_side_at(local_shard),
                BTreeSet::from([near_shard, far_shard]),
            )),
            arrivals,
        };
        executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .remove(0)
    };

    let sender = run(near_shard, &[]);
    let ConsensusReceipt::Succeeded { writes, .. } = &sender.consensus else {
        panic!("the sender's legs must succeed: {:?}", sender.metadata);
    };
    assert_eq!(
        sender.escrowed,
        vec![EscrowedValue {
            node: edge.producer,
            output: edge.output,
            resource: *XRD,
            amount: 100,
            record: edge.record.key(),
        }],
        "the withdraw's value left into the record cell the plan filed",
    );
    assert!(
        writes.cells.contains_key(&edge.record.key()),
        "the record cell is among the sender's writes"
    );
    assert!(
        !writes
            .movements
            .keys()
            .any(|key| key.owner == far().address()),
        "the sender ran no leg of the recipient's"
    );

    let recipient = run(far_shard, &sender.escrowed);
    let ConsensusReceipt::Succeeded { writes, .. } = &recipient.consensus else {
        panic!("the recipient's leg must succeed: {:?}", recipient.metadata);
    };
    assert!(recipient.escrowed.is_empty(), "a deposit hands nothing on");
    assert!(
        writes
            .movements
            .keys()
            .any(|key| key.owner == far().address()),
        "the deposit credited the recipient"
    );
    assert!(
        !writes
            .movements
            .keys()
            .any(|key| key.owner == alice().address()),
        "the recipient ran no leg of the sender's"
    );
}

/// A refused transfer's escrow comes back. The sender's shard runs the
/// reclaim — no node, no nullifier, a declaration of its own over the
/// record, the claim and the origin — and the vault is back at its
/// pre-escrow balance exactly, read off the cell; the record goes with
/// it, since the value it held is back where it left.
#[test]
fn a_reclaim_restores_the_senders_vault_exactly() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.owners(), &trie);
    assert!(classified.decomposed());
    let edge = classified.edges()[0].clone();

    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let run = |store: &MapDb, runs: Runs| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            runs,
            arrivals: &[],
        };
        executor.execute_tick_batch(&ctx, store, &[input]).remove(0)
    };

    let sent = run(
        &store,
        Runs::Shape(Member::of(
            classified.clone(),
            near_shard,
            Side::Issuing,
            std::iter::once(near_shard)
                .chain(edge.to.iter().copied())
                .collect(),
        )),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    store.apply(writes);
    assert_eq!(
        store.cell(vault_key(alice(), *XRD)),
        Some(encode_amount(900).to_vec()),
        "the escrow debited the vault"
    );

    let reclaimed = run(
        &store,
        Runs::Settle {
            member: Member::whole(near_shard),
            records: classified.records_issued(near_shard),
            on: Licence::Unclaimed,
            charged: true,
        },
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &reclaimed.consensus else {
        panic!("the reclaim must succeed: {:?}", reclaimed.metadata);
    };
    assert!(reclaimed.escrowed.is_empty(), "a reclaim issues nothing");
    assert!(
        reclaimed.fee_receipt.is_none(),
        "the leg's own certificate settled the price; the reclaim owes none"
    );
    store.apply(writes);
    assert_eq!(
        store.cell(vault_key(alice(), *XRD)),
        Some(encode_amount(1_000).to_vec()),
        "and the reclaim restores it exactly"
    );
    assert!(
        store.cell(edge.record.key()).is_none(),
        "the record goes with the value it held"
    );
}

/// Once the recipient's claim is on record, the sender's shard retires
/// the record it held for it: no node, no fee, nothing moved, and the
/// record deleted. A second retirement finds nothing and is refused
/// before the kernel runs.
#[test]
fn a_retirement_deletes_the_record_and_moves_nothing() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.owners(), &trie);
    let edge = classified.edges()[0].clone();

    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let run = |store: &MapDb, runs: Runs| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            runs,
            arrivals: &[],
        };
        executor.execute_tick_batch(&ctx, store, &[input]).remove(0)
    };

    let sent = run(
        &store,
        Runs::Shape(Member::of(
            classified.clone(),
            near_shard,
            Side::Issuing,
            std::iter::once(near_shard)
                .chain(edge.to.iter().copied())
                .collect(),
        )),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    store.apply(writes);
    assert!(
        store.cell(edge.record.key()).is_some(),
        "the record is written"
    );

    let retired = run(
        &store,
        Runs::Settle {
            member: Member::whole(near_shard),
            records: classified.records_issued(near_shard),
            on: Licence::Accepted,
            charged: true,
        },
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &retired.consensus else {
        panic!("the retirement must succeed: {:?}", retired.metadata);
    };
    assert!(retired.escrowed.is_empty(), "a retirement issues nothing");
    assert!(retired.fee_receipt.is_none(), "and charges nothing");
    store.apply(writes);
    assert!(
        store.cell(edge.record.key()).is_none(),
        "the record is gone"
    );
    assert_eq!(
        store.cell(vault_key(alice(), *XRD)),
        Some(encode_amount(900).to_vec()),
        "and the value stays where the claim took it"
    );

    let again = run(
        &store,
        Runs::Settle {
            member: Member::whole(near_shard),
            records: classified.records_issued(near_shard),
            on: Licence::Accepted,
            charged: true,
        },
    );
    assert!(
        matches!(again.consensus, ConsensusReceipt::Failed),
        "a second retirement finds no record and is refused: {:?}",
        again.metadata
    );
}

/// A record a shard inherited with a prefix decides itself, against the
/// claim cell the record names: absent, the value goes back to the cell
/// it left; present, the record is deleted and nothing moves.
///
/// The member runs with no body at all, which is the point — a merge
/// successor's store arrives as a prefix of leaves and its ledger begins
/// empty, so the leaf is the whole of what a reclaim has to work from.
#[test]
#[allow(clippy::too_many_lines)] // one member over one fixture, in both its states
fn an_inherited_record_decides_itself_against_its_claim() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 0),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let classified = Classified::freeze(tx.legs(), tx.owners(), &trie);
    let edge = classified.edges()[0].clone();

    // The sending half, which writes the record the successor inherits.
    let issued = |store: &MapDb| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            runs: Runs::Shape(Member::of(
                classified.clone(),
                near_shard,
                Side::Issuing,
                std::iter::once(near_shard)
                    .chain(edge.to.iter().copied())
                    .collect(),
            )),
            arrivals: &[],
        };
        executor.execute_tick_batch(&ctx, store, &[input]).remove(0)
    };

    // The housekeeping half: no body, and a clock inside the window an
    // absent claim answers in.
    let settle = |store: &MapDb, at: u64| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(at),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            tx_hash: TxHash::from(Hash::from_bytes(b"housekeeping")),
            transaction: None,
            provisions: &[],
            clock: WeightedTimestamp::from_millis(at),
            runs: Runs::Settle {
                member: Member::whole(near_shard),
                records: vec![edge.record.key()],
                on: Licence::OwnLeaf,
                charged: true,
            },
            arrivals: &[],
        };
        executor.execute_tick_batch(&ctx, store, &[input]).remove(0)
    };

    let mut unclaimed = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let sent = issued(&unclaimed);
    let ConsensusReceipt::Succeeded { writes, .. } = &sent.consensus else {
        panic!("the sender's legs must succeed: {:?}", sent.metadata);
    };
    unclaimed.apply(writes);
    let record = CrossingCell::from_bytes(
        &Substates::cell(&unclaimed, edge.record.key()).expect("the record is written"),
    )
    .expect("a record decodes");
    // The engine reads the claim cell alone; that the reading is taken
    // inside the lapse, where an absence means something, is admission's
    // business, and this clock sits inside it.
    let inside = record.expiry_ms - 1;
    assert!(
        Window::Lapse
            .of(Deadline::from_expiry(record.expiry_ms))
            .contains(&WeightedTimestamp::from_millis(inside))
    );

    // A store where the claim is present is the same store plus that one
    // cell, so the two runs differ in nothing else.
    let mut claimed = MapDb(unclaimed.0.clone());
    claimed.0.insert(record.consumer_claim, vec![0xAA]);

    let taken_back = settle(&unclaimed, inside);
    let ConsensusReceipt::Succeeded { writes, .. } = &taken_back.consensus else {
        panic!("the reclaim must succeed: {:?}", taken_back.metadata);
    };
    assert!(
        taken_back.fee_receipt.is_none(),
        "the chain that issued the crossing settled the price before it ended"
    );
    unclaimed.apply(writes);
    assert_eq!(
        Substates::cell(&unclaimed, vault_key(alice(), *XRD)),
        Some(encode_amount(1_000).to_vec()),
        "an unclaimed crossing returns to the cell it left"
    );
    assert!(
        Substates::cell(&unclaimed, edge.record.key()).is_none(),
        "and the record goes with it"
    );

    let retired = settle(&claimed, inside);
    let ConsensusReceipt::Succeeded { writes, .. } = &retired.consensus else {
        panic!("the retirement must succeed: {:?}", retired.metadata);
    };
    claimed.apply(writes);
    assert!(
        Substates::cell(&claimed, edge.record.key()).is_none(),
        "a claimed crossing's record is deleted"
    );
    assert_eq!(
        Substates::cell(&claimed, vault_key(alice(), *XRD)),
        Some(encode_amount(900).to_vec()),
        "and the value stays where the claim took it"
    );
}

/// The reclaim of a leg that never ran finds no record to reclaim from,
/// and is refused before the kernel runs. The refusal is the sender's
/// terminal on this shard and the one receipt left to carry the price:
/// it settles the charge apart, debiting exactly the declared price and
/// nothing else. The same reclaim of a leg that ran owes nothing.
#[test]
fn a_reclaim_of_a_leg_that_never_ran_charges_the_price() {
    let executor = executor(ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let near_shard = trie.shard_for_prefix(alice());
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(ALICE_SEED, alice(), far(), 100, 1_000),
    ));
    derived_through(&executor, std::slice::from_ref(&tx));
    let price = tx.price();
    assert!(price > 0, "a priced fixture, or the charge proves nothing");

    let mut store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
    let run = |store: &MapDb, charged: bool| {
        let ctx = TickBatchContext {
            local_shard: near_shard,
            shard_trie: &trie,
            tick_ts: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            holds: &ProvisionalHolds::new(),
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            runs: Runs::Settle {
                member: Member::whole(near_shard),
                records: Classified::freeze(tx.legs(), tx.owners(), &trie)
                    .records_issued(near_shard),
                on: Licence::Unclaimed,
                charged,
            },
            arrivals: &[],
        };
        executor.execute_tick_batch(&ctx, store, &[input]).remove(0)
    };

    let owed = run(&store, false);
    assert!(
        !matches!(owed.consensus, ConsensusReceipt::Succeeded { .. }),
        "with no record to read, the reclaim is refused: {:?}",
        owed.metadata
    );
    let charge = owed
        .fee_receipt
        .as_ref()
        .and_then(ConsensusReceipt::writes)
        .expect("the refusal settles the price apart");
    store.apply(charge);
    assert_eq!(
        store.cell(vault_key(alice(), *XRD)),
        Some(encode_amount(1_000 - price).to_vec()),
        "exactly the declared price leaves the vault"
    );

    let paid = run(&store, true);
    assert!(
        !matches!(paid.consensus, ConsensusReceipt::Succeeded { .. }),
        "the same refusal for a leg that ran"
    );
    assert!(
        paid.fee_receipt.is_none(),
        "owes nothing more: its own certificate settled the price"
    );
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
        };
        let input = TickTxInput {
            tx_hash: tx.hash(),
            transaction: Some(&tx),
            provisions: &[],
            clock: WeightedTimestamp::from_millis(1_000),
            runs: Runs::Shape(Member::of(
                Classified::whole(),
                local_shard,
                Side::Issuing,
                BTreeSet::from([near_shard, far_shard]),
            )),
            arrivals: &[],
        };
        executor
            .execute_tick_batch(&ctx, &snapshot_store, &[input])
            .remove(0)
    };
    let (sender_side, recipient_side) = (run(near_shard), run(far_shard));

    assert_eq!(events_of(&sender_side), vec![(alice().address(), 0)]);
    assert_eq!(events_of(&recipient_side), vec![(far().address(), 1)]);
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
        .entry(vault_key(alice(), *XRD))
        .or_default()
        .insert(Hash::from_bytes(b"an unresolved leg").into(), 950);
    let ctx = TickBatchContext {
        local_shard: near_shard,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &holds,
    };
    derived_through(&executor, std::slice::from_ref(&tx));
    let executed = executor.execute_batch(&ctx, &snapshot_store, std::slice::from_ref(&tx));
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "a reservation the hold leaves uncovered must fail its leg: {:?}",
        executed[0].consensus
    );

    let unheld = TickBatchContext {
        holds: &ProvisionalHolds::new(),
        ..ctx
    };
    let executed = executor.execute_batch(&unheld, &snapshot_store, &[tx]);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "with nothing held the same transfer completes: {:?}",
        executed[0].consensus
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
        let funds = account::withdraw(&mut b, alice(), *XRD, amount).expect("an account withdraws");
        account::deposit(&mut b, to, funds).expect("an account deposits");
    }
    let graph = b.build().expect("every output is consumed");
    let tx = Arc::new(Verified::<Transaction>::from_persisted(Transaction::new(
        client().sign(graph, &key, terms(10)),
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
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let vm = TransactionEnvelope {
        body: TransactionBody::Publish(artifact),
        subintent_sigs: Vec::new(),
        fee_payer: account_address(&key.public_key().0),
        max_fee: 1_000_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: OFFER_MS,
        message: Vec::new(),
        network: NETWORK,
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
    .sign(&key);
    Transaction::new(vm)
}

/// The raw update a batch made to a package's cell under `publisher`.
fn package_cell(
    writes: &StateWrites,
    publisher: impl Into<Address>,
    artifact: &[u8],
) -> Option<Vec<u8>> {
    let key = package_key(publisher, package_hash(&ProtocolHasher, artifact));
    writes.cells.get(&key).cloned().flatten()
}

#[test]
fn a_publish_writes_the_artifact_under_its_publisher() {
    let payer = fee_payer(7);
    let executor = executor(ExecutionMode::Serial);
    let artifact = published_account_artifact();
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7,
        artifact.clone(),
    )));
    // Funded well above the burn: at the placeholder rate of one unit
    // per artifact byte, publishing the stdlib guest costs more than the
    // balances the transfer fixtures use.
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);

    let ConsensusReceipt::Succeeded {
        writes: database_updates,
        beacon_witness_events,
        ..
    } = &executed[0].consensus
    else {
        panic!("a publish must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        package_cell(database_updates, payer, &artifact).as_deref(),
        Some(artifact.as_slice()),
        "the artifact lands whole in its content-addressed cell"
    );
    // The publish is a beacon fact: one witness, from the shard owning
    // the publisher's prefix, carrying the content address the world
    // prefetches on.
    assert_eq!(
        beacon_witness_events.as_slice(),
        &[BeaconWitnessEvent::PackagePublished {
            package: Hash::from(package_hash(&ProtocolHasher, &artifact).0),
            publisher: payer.address(),
        }],
        "the publish settles with its beacon fact"
    );
    // The publisher paid: the vault carries the burn, and the fee is the
    // only other thing a publish writes.
    let paid = vault_cell(&settled(database_updates, &[(payer, 1_000_000)]), payer)
        .expect("the payer's vault was written");
    assert_eq!(
        paid,
        encode_amount(1_000_000 - artifact.len() as u128).to_vec(),
        "the publisher paid exactly what judging its artifact cost"
    );
    assert!(
        executed[0].attested_work > 0,
        "judging the artifact is attested work"
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
        vec![
            AbiParam::Handle { clause: 0, site: 0 },
            AbiParam::Handle { clause: 1, site: 0 },
            AbiParam::Handle { clause: 2, site: 0 },
            AbiParam::Bucket(0),
        ],
        "one handle per cell the deposit may reach — the flag it reads, the \
         vault, and the quarantine beside it — each naming the clause that \
         declared it rather than a position"
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
        config: Vec::new(),
        salt: Hash32([0xA1; 32]),
    };
    let unsealed = meta.address(&ProtocolHasher);
    let mut b = GraphBuilder::new();
    let [] = b.call(unsealed, "draw", (64u64,));
    let graph = b.build().expect("every output is consumed");
    let gap = Transaction::new(client().sign_tree(
        &EnvelopeTree {
            root: IntentDecl {
                header: HEADER,
                graph,
                sockets: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
            instances: Vec::new(),
            resources: Vec::new(),
        },
        Vec::new(),
        &key,
        terms(TRANSFER_FEE),
    ));
    let error = gap
        .try_derived(engine.derivation().as_ref())
        .expect_err("nothing answers for it yet");
    assert_eq!(
        error.unresolved(),
        [unsealed.address()],
        "the record a fetch would ask for: {error}"
    );

    // A refusal, by contrast, names nothing to fetch: the account
    // resolves, and no record would make a deposit taking no bucket
    // admissible.
    let mut b = GraphBuilder::new();
    let [] = b.call(payer, "deposit", ());
    let graph = b.build().expect("every output is consumed");
    let refused = Transaction::new(client().sign_tree(
        &EnvelopeTree {
            root: IntentDecl {
                header: HEADER,
                graph,
                sockets: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
            instances: Vec::new(),
            resources: Vec::new(),
        },
        Vec::new(),
        &key,
        terms(TRANSFER_FEE),
    ));
    let error = refused
        .try_derived(engine.derivation().as_ref())
        .expect_err("a deposit takes a bucket");
    assert!(
        error.unresolved().is_empty(),
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
    let mut metadata = published_metadata();
    naming(&mut metadata, "republished");
    let artifact = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
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

/// Wait out the compile worker; the bound is a harness valve, not a
/// verdict — consensus never reads a clock here.
/// The stdlib account's metadata as a *publisher* could submit it.
///
/// These tests publish through the ordinary transaction path, and that
/// path refuses a claim to totality — the mark is the protocol's, granted
/// to what genesis seeds. The account declares one total method, so the
/// fixture drops the claim rather than the tests asserting a publish the
/// gate does not allow.
fn published_account_artifact() -> Vec<u8> {
    attach_metadata(STAKING_COMPONENT, &published_metadata()).expect("attaches")
}

/// The metadata a publisher's artifact carries.
///
/// The staking package rather than the account's: a published package
/// serves instances, and the gate holds one to declaring the seal its
/// components come up through — which the account, serving principals,
/// has no reason to carry.
/// Vary `metadata`, and so the address of any artifact carrying it, by
/// naming one more event.
///
/// A package is content-addressed, so republishing one is the same bytes
/// at the same address; one more name is the smallest thing that moves
/// it. An event is a name *and* a shape, so the name arrives with the
/// empty one — what an event carrying nothing declares.
fn naming(metadata: &mut PackageMetadata, event: &str) {
    metadata.events.push(event.to_owned());
    metadata
        .types
        .insert(event.to_owned(), TypeShape::Tuple(Vec::new()));
}

fn published_metadata() -> PackageMetadata {
    let mut metadata = staking::metadata();
    for signature in metadata.methods.values_mut() {
        if signature.totality == Totality::Total {
            signature.totality = Totality::Infallible;
        }
    }
    metadata
}

fn await_code_settled(executor: &Executor, package: PackageHash) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !executor.package_code_settled(package) {
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

    let mut metadata = published_metadata();
    naming(&mut metadata, "compiled");
    let artifact = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    assert!(
        !executor.package_code_settled(package),
        "the code is unknown before its block commits"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7, artifact,
    )));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);
    let ConsensusReceipt::Succeeded { .. } = &executed[0].consensus else {
        panic!("the publish must succeed: {:?}", executed[0].consensus);
    };
    assert!(
        !executor.package_code_settled(package),
        "execution alone compiles nothing"
    );

    // The same committed-cell walk that grows the metadata cache hands
    // the artifact to the compile worker: the code is on its way from
    // the commit, not from the first call that needs it.
    absorb_committed_cells([&executed[0].consensus], executor.derivation().as_ref());
    await_code_settled(&executor, package);
}

#[test]
fn an_indexed_artifact_reseeds_metadata_and_code_at_boot() {
    let executor = executor(ExecutionMode::Serial);

    let mut metadata = published_metadata();
    naming(&mut metadata, "reseeded");
    let artifact = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);

    // What a restarting host replays from its stores' package indices:
    // one call re-learns the metadata and queues the compile.
    executor.install_artifact(&artifact);
    assert_eq!(
        executor.packages().load().get(package),
        Some(&metadata),
        "the reseeded artifact's metadata is routable"
    );
    await_code_settled(&executor, package);

    // Junk in the index is refused, not trusted: the cells are the
    // authority and the index is derived.
    executor.install_artifact(b"\0asm\x01\0\0\0");

    // And a refusal costs nothing that follows it: the next artifact in
    // the index still reaches the compile worker. A restart replays
    // whatever the store holds, so one unreadable entry must not be the
    // end of the reseed.
    naming(&mut metadata, "after the refusal");
    let next = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
    executor.install_artifact(&next);
    await_code_settled(&executor, package_hash(&ProtocolHasher, &next));
}

#[test]
fn only_a_cell_that_addresses_its_own_contents_publishes() {
    // A package cell is self-identifying: its key is the content address
    // of the value it holds. Without that check, any committed cell
    // whose bytes happened to parse as an artifact would publish a
    // package — no publish transaction, no fee, no cell of its own.
    let executor = executor(ExecutionMode::Serial);
    let cache = executor.packages();

    let mut metadata = published_metadata();
    naming(&mut metadata, "smuggled");
    let artifact = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    let publisher = fee_payer(11);

    // The right bytes at the wrong key: a vault slot, not the content
    // address. Refused.
    let vault = vault_key(publisher, *XRD);
    cache.absorb_cell(publisher, vault.local.0, &artifact);
    assert!(
        cache.load().get(package).is_none(),
        "an artifact stored anywhere but its own address is not a package"
    );

    // The same bytes at the key their own hash builds. Published.
    let cell = package_key(publisher, package);
    cache.absorb_cell(publisher, cell.local.0, &artifact);
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
            clock: WeightedTimestamp::from_millis(1_000),
            env: TickEnvironment::unfolded(),
            grants,
        },
    )
}

/// The reported change to `owner`'s native vault.
fn change_for(report: &PreviewReport, owner: impl Into<Address>) -> ResourceChange {
    let owner = owner.into();
    let key = vault_key(owner, *XRD);
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
        PreviewGrants {
            free_credit: true,
            ..PreviewGrants::default()
        },
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
            key: vault_key(payer, *XRD),
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

/// A preview holds a node to its target's authority like the chain does,
/// and the grant is what a wallet reaches for when it wants an answer
/// about an envelope its counterparties have not signed yet.
///
/// Without it, a wallet composing a two-party trade would be told
/// "refused" and have nothing to show the user. With it, the report is
/// what the composition would do once signed — which is exactly the
/// question being asked.
#[test]
fn a_preview_holds_a_node_to_its_targets_authority_unless_granted() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (alice(), 1_000), (bob(), 50)];
    let executor = executor(ExecutionMode::Serial);
    // Signed by 7, withdrawing from Alice: the shape the gate refuses.
    let tx = signed_transfer_with_fee(7, alice(), bob(), 100, PREVIEW_CEILING);

    let held = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    assert!(
        matches!(held.outcome, PreviewOutcome::Aborted { .. }),
        "outcome = {:?}",
        held.outcome
    );
    // Only the payer's own fee is reported: nothing of Alice's moves
    // without her.
    assert!(
        held.changes
            .iter()
            .all(|change| change.key.owner != alice().address())
    );

    let granted = preview_on(
        &accounts,
        &executor,
        &tx,
        PreviewGrants {
            assume_target_auth: true,
            ..PreviewGrants::default()
        },
    );
    assert_eq!(granted.outcome, PreviewOutcome::Completed);
    assert_eq!(change_for(&granted, alice()).debit, 0);
    assert_eq!(change_for(&granted, alice()).settled, 100);
    assert_eq!(change_for(&granted, bob()).credit, 100);
}

/// A publish previews too, and its price needs no state: judging an
/// artifact costs one unit per byte, which is the whole answer.
#[test]
fn a_preview_prices_a_publish_by_its_artifact() {
    let payer = fee_payer(7);
    let artifact = published_account_artifact();
    let executor = executor(ExecutionMode::Serial);
    let tx = signed_publish(7, artifact.clone());
    let report = preview_on(
        &[(payer, 1_000_000)],
        &executor,
        &tx,
        PreviewGrants::default(),
    );

    assert_eq!(report.outcome, PreviewOutcome::Completed);
    assert_eq!(report.fee, artifact.len() as u128);
    let vault = change_for(&report, payer);
    assert_eq!(
        (vault.before, vault.after),
        (1_000_000, 1_000_000 - artifact.len() as u128)
    );

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
    for signature in metadata.methods.values_mut() {
        if signature.totality == Totality::Total {
            signature.totality = Totality::Infallible;
        }
    }
    let artifact = attach_metadata(STAKING_COMPONENT, &metadata).expect("attaches");
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
        config: vec![
            Value::Address((*XRD).address()),
            Value::Address(payer.address()),
        ],
        salt: Hash32([7; 32]),
    };
    let component = meta.address(&ProtocolHasher);

    // The founder its configuration names signs in, and the owner badge
    // the seal mints is filed in that same account: bringing up is one
    // node, and the supply a component comes up holding leaves with
    // whoever composed it.
    let mut b = GraphBuilder::new();
    let signed_in = 0;
    let [] = b.call_signed(payer, "authorize", ());
    let [badge] = b.call_bearing(component, "instantiate", (), signed_in);
    let owner_badge = issued_resource(
        &ProtocolHasher,
        component,
        ResourceKind::NonFungible,
        staking::OWNER_BADGE,
    );
    let [] = b.call(payer, "deposit-nf", (badge.resource_is(owner_badge),));
    let graph = b.build().expect("every output is consumed");
    let tree = EnvelopeTree {
        root: IntentDecl {
            header: HEADER,
            graph,
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: vec![meta.clone()],
        resources: Vec::new(),
    };

    // The same call without its record: nothing committed answers for a
    // component nobody sealed, so derivation names the address it would
    // need rather than refusing the envelope. A gap, not a verdict —
    // which is the difference between an envelope that is wrong and one
    // this node cannot yet judge.
    let mut unpresented = tree.clone();
    unpresented.instances.clear();
    let bare =
        Transaction::new(client().sign_tree(&unpresented, Vec::new(), &key, terms(TRANSFER_FEE)));
    let refusal = bare
        .try_derived(executor.derivation().as_ref())
        .expect_err("an unresolved instance target does not derive");
    assert_eq!(
        refusal.unresolved(),
        [component.address()],
        "the record this node would need, named: {refusal}"
    );

    // Claim: the call admits, the invocation resolves the freshly
    // compiled package — waiting out the compile if it is still in
    // flight — and the leaf holds the record the address derives from.
    let call = Transaction::new(client().sign_tree(&tree, Vec::new(), &key, terms(TRANSFER_FEE)));
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
