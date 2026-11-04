//! What a declared interval's cap does to the baseline a batch executes
//! over, on one shard with nothing in flight.
//!
//! `materialize_declared` lifts at most `cap` entries of each declared
//! interval out of the tick snapshot, and the kernel reads that map and
//! nothing beneath it. Every case here runs over a store holding more
//! entries in the interval than the declaration's cap, and asserts what
//! the full store says is true.

use std::sync::{Arc, LazyLock};

use hyperscale_effects_bridge::account_address;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, TickBatchContext, TickEnvironment, genesis_writes,
};
use hyperscale_storage::test_helpers::block_settling;
use hyperscale_storage::{BoundaryStore, GenesisCommit, NoFeeHolds, SubstateStore, Substates};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_transactions::{Ceilings, Client, Terms};
use hyperscale_types::{
    BlockHeight, ConsensusReceipt, Ed25519PrivateKey, EntryKey, FrontierInputs,
    MAX_INTENT_VALIDITY_RANGE, NetworkId, PriceTable, PrincipalAddr, ProtocolHasher,
    ProvisionalHolds, ResourceAddr, SettledWrites, ShardId, ShardTrie, StoredReceipt,
    TimestampRange, Transaction, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::holdings_collection;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::CollectionId;

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
    let genesis = genesis_writes(accounts, &[], packages);
    let (cells, _) = genesis.into_parts();
    let seeded = SettledWrites::from_parts(cells, entries.into_iter().collect());
    let storage = SimShardStorage::default();
    storage.install_genesis(&seeded, &seeded);
    storage
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

/// Alice's holdings of [`NF`] seeded with instances 1 and 2.
fn alice_holding_two() -> SimShardStorage {
    let alice = principal(ALICE).address();
    let entries = [1u128, 2]
        .into_iter()
        .map(|id| {
            (
                EntryKey {
                    owner: alice,
                    collection: holdings(principal(ALICE), NF),
                    order: id,
                },
                Some(vec![1]),
            )
        })
        .collect();
    let storage = storage_with(
        &GenesisPackages::protocol(),
        &[(principal(ALICE), FUNDED), (principal(BOB), FUNDED)],
        entries,
    );
    assert_eq!(held_ids(&storage, principal(ALICE), NF), vec![1, 2]);
    storage
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
#[ignore = "baseline lifts only the lowest cap entries; withdraw of id 2 traps InstanceNotHeld"]
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
