//! Ordered-collection custody end to end: NF holdings moved through the
//! batch executor over `storage-memory`, receipts committing between
//! ticks, and the custody gate reading possession from the materialized
//! baseline.
//!
//! Every case here runs against one world of funded, registered
//! accounts, with one of them seeded holding instances at genesis.

use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::account_address;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, TickBatchContext, TickEnvironment, genesis_writes,
};
use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_storage::test_helpers::block_settling;
use hyperscale_storage::{BoundaryStore, GenesisCommit, SubstateStore, Substates};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_transactions::{Client, Terms};
use hyperscale_types::{
    BlockHeight, ConsensusReceipt, Ed25519PrivateKey, EntryKey, MAX_SUBINTENT_VALIDITY_RANGE,
    NetworkId, PriceTable, PrincipalAddr, ProtocolHasher, ProvisionalHolds, ResourceAddr,
    SettledWrites, ShardId, ShardTrie, StoredReceipt, TimestampRange, Transaction, Verified,
    WeightedTimestamp,
};
use hyperscale_vm_effects::holdings_collection;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::CollectionId;

/// The widest window an intent may stand for, which these fixtures use
/// wherever they mean "does not expire during the test".
const OFFER_MS: u64 = MAX_SUBINTENT_VALIDITY_RANGE.as_secs() * 1_000;

/// The two signing seeds this world funds.
const ALICE: u8 = 1;
const BOB: u8 = 2;
/// What both accounts hold at genesis.
const FUNDED: u128 = 10_000;
/// The non-fungible resource Alice's holdings are seeded with.
const NF: ResourceAddr = ResourceAddr::new([0xE7; 31]);
/// A resource nobody possesses, for the refusal case.
const UNHELD: ResourceAddr = ResourceAddr::new([0xE8; 31]);

fn key_of(seed: u8) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
}

fn principal(seed: u8) -> PrincipalAddr {
    account_address(&key_of(seed).public_key().0)
}

fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| Client::genesis(NetworkId(242)));
    &CLIENT
}

const fn terms() -> Terms {
    Terms {
        max_fee: 1_000,
        validity: TimestampRange::new(
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(OFFER_MS),
        ),
        message: Vec::new(),
    }
}

/// The holdings interval of `who`'s instances of `resource`.
fn holdings(who: PrincipalAddr, resource: ResourceAddr) -> CollectionId {
    holdings_collection(&ProtocolHasher, who, resource)
}

/// The ids currently in `who`'s holdings of `resource`, as the store
/// serves them.
fn held_ids(storage: &SimShardStorage, who: PrincipalAddr, resource: ResourceAddr) -> Vec<u128> {
    storage
        .entries_in_range(who.address(), holdings(who, resource), 0, u128::MAX, 16)
        .into_iter()
        .map(|(order, _)| order)
        .collect()
}

/// Genesis: both accounts funded, and Alice's holdings of [`NF`] seeded
/// with instances 1 and 2 — the entries the first tick moves.
fn storage() -> SimShardStorage {
    let genesis = genesis_writes(
        &[(principal(ALICE), FUNDED), (principal(BOB), FUNDED)],
        &[],
        &GenesisPackages::protocol(),
    );
    let entries = [1u128, 2]
        .into_iter()
        .map(|id| {
            (
                EntryKey {
                    owner: principal(ALICE).address(),
                    collection: holdings(principal(ALICE), NF),
                    order: id,
                },
                Some(vec![1]),
            )
        })
        .collect();
    let (cells, _) = genesis.into_parts();
    let seeded = SettledWrites::from_parts(cells, entries);
    let storage = SimShardStorage::default();
    storage.install_genesis(&seeded, &seeded);
    storage
}

/// `from.withdraw-nf(NF, ids) -> to.deposit-nf(..)`, signed by `from`.
fn signed_nf_transfer(from: u8, to: u8, ids: &[u64]) -> Transaction {
    let chain = client().records();
    let mut b = client().builder(&chain, principal(from));
    let funds = account::withdraw_nf(&mut b, principal(from), NF, ids).expect("withdraw-nf types");
    account::deposit_nf(&mut b, principal(to), funds).expect("deposit-nf types");
    let graph = b.build().expect("every output is consumed");
    Transaction::new(client().sign(graph, &key_of(from), terms()))
}

/// `who.present-instance(badge, id)`: custody presented as evidence,
/// consumed by nothing — the gate's own verdict is the assertion.
fn signed_present(who: u8, badge: ResourceAddr, id: u64) -> Transaction {
    let chain = client().records();
    let mut b = client().builder(&chain, principal(who));
    // The proof stays unpresented: nothing here needs its authority —
    // the gate's own verdict is what the test reads.
    let _ = account::present_instance(&mut b, principal(who), badge, id)
        .expect("present-instance types");
    let graph = b.build().expect("a dangling proof is not an output");
    Transaction::new(client().sign(graph, &key_of(who), terms()))
}

/// Execute one transaction as one tick's batch over the store's current
/// snapshot, commit its receipts, and return them.
fn run_tick(
    executor: &Executor,
    storage: &SimShardStorage,
    height: u64,
    tx: Transaction,
) -> Vec<ExecutedTx> {
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        prices: PriceTable::GENESIS,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds: &ProvisionalHolds::new(),
    };
    tx.try_derived(executor.derivation().as_ref())
        .expect("a fixture transaction derives");
    let verified = Arc::new(Verified::<Transaction>::from_persisted(tx));
    let executed =
        executor.execute_batch(&ctx, &storage.snapshot(), std::slice::from_ref(&verified));

    let before = storage.state_root();
    // Execution and fee receipts both, as the tick stores them: a failed
    // attempt applies nothing itself but its charge still settles.
    let mut receipts: Vec<StoredReceipt> = Vec::new();
    for tx in &executed {
        let mut tx = tx.clone();
        if let Some(fee) = tx.fee_receipt.take() {
            receipts.push(StoredReceipt::synced(tx.tx_hash, Arc::new(fee)));
        }
        receipts.push(StoredReceipt::from(tx));
    }
    let after = storage
        .follow_block_writes(&block_settling(BlockHeight::new(height), receipts), &[])
        .expect("committed receipts apply");
    assert_ne!(before, after, "a settling tick moves the state root");
    executed
}

/// The whole loop: entries move under receipts, each tick reads what the
/// last one committed, and the wire form round-trips.
#[test]
fn holdings_move_between_ticks_and_round_trip_receipts() {
    let executor = Executor::new(ExecutionMode::Serial);
    let storage = storage();
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![1, 2]);

    // Tick 1: Alice moves both instances to Bob.
    let executed = run_tick(
        &executor,
        &storage,
        1,
        signed_nf_transfer(ALICE, BOB, &[1, 2]),
    );
    let ConsensusReceipt::Succeeded { writes, .. } = &executed[0].consensus else {
        panic!("the transfer must settle: {:?}", executed[0].consensus);
    };
    assert_eq!(writes.entries.len(), 4, "two removals and two inserts");
    // The receipt is wire content, entries included.
    let bytes = to_vec(&executed[0].consensus).expect("a receipt encodes");
    assert_eq!(
        from_slice::<ConsensusReceipt>(&bytes).expect("a receipt decodes"),
        executed[0].consensus,
    );

    assert_eq!(held_ids(&storage, principal(ALICE), NF), Vec::<u128>::new());
    assert_eq!(held_ids(&storage, principal(BOB), NF), vec![1, 2]);

    // Tick 2 reads what tick 1 wrote: Bob returns instance 1.
    run_tick(&executor, &storage, 2, signed_nf_transfer(BOB, ALICE, &[1]));
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![1]);
    assert_eq!(held_ids(&storage, principal(BOB), NF), vec![2]);
}

/// The custody gate reads possession from the materialized baseline: a
/// held badge opens it, an unheld one refuses, and an unheld withdrawal
/// traps as the sender's own error.
#[test]
fn custody_opens_for_the_holder_and_refuses_the_rest() {
    let executor = Executor::new(ExecutionMode::Serial);
    let storage = storage();

    // Alice holds instance 1 of NF, so her presentation settles.
    let executed = run_tick(&executor, &storage, 1, signed_present(ALICE, NF, 1));
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "possession opens the gate: {:?}",
        executed[0].consensus
    );

    // Bob holds nothing of UNHELD — no vault, no holdings — so the gate
    // refuses, and refuses deterministically.
    let executed = run_tick(&executor, &storage, 2, signed_present(BOB, UNHELD, 1));
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Failed),
        "no possession, no proof: {:?}",
        executed[0].consensus
    );

    // Withdrawing an instance the holdings do not contain traps in the
    // guest — the sender's own defect, and priced like every attempt.
    let executed = run_tick(&executor, &storage, 3, signed_nf_transfer(BOB, ALICE, &[9]));
    assert!(
        matches!(&executed[0].consensus, ConsensusReceipt::Failed),
        "an unheld id traps: {:?}",
        executed[0].consensus
    );
}
