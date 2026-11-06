//! What an in-flight member's reservation does to the ticks after it.
//!
//! A member a counterpart can still discard keeps its writes out of every
//! later tick's view, so a later tick cannot see what the member will
//! take. What it sees instead is the member's declared reservation, held
//! provisionally: the coordinator records it when the member's tick
//! completes, the tick chain carries it in the holds of every baseline
//! above that tick until the member resolves, and the kernel judges a
//! later debit of the vault against what the holds leave. That is what
//! lets the queue name a debit beside an in-flight reservation of its
//! cell: the debit is judged with the reservation already subtracted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use hyperscale_core::CrossShardExecutionRequest;
use hyperscale_effects_bridge::{ProtocolHasher, account_address};
use hyperscale_engine::genesis::{
    GenesisPackages, genesis_world_with_pools, genesis_writes, vault_key,
};
use hyperscale_engine::legs::{Classified, Member};
use hyperscale_engine::{
    ExecutedTx, ExecutionMode, Executor, PROTOCOL_RESOURCE, TickBatchContext, TickEnvironment,
};
use hyperscale_execution::action_handlers::accumulate_tick_output;
use hyperscale_hbor::Bytes;
use hyperscale_storage::{
    Anchored, NoFeeHolds, SubstateStore, Substates, TickChain, TickOutput, VersionedStore,
};
use hyperscale_transactions::{Client, default_gas_limits};
use hyperscale_types::{
    BlockHeight, ConsensusReceipt, DeclaredRange, Ed25519PrivateKey, MAX_INTENT_VALIDITY_RANGE,
    NetworkId, PriceTable, PrincipalAddr, ProvisionalHolds, ShardId, ShardTrie, StateRoot,
    SubstateKey, Transaction, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::{Intent, IntentHeader, IntentTree};
use hyperscale_vm_manifest_builder::signing;
use hyperscale_vm_types::{Address, CollectionId};

const NETWORK: NetworkId = NetworkId(242);

const HEADER: IntentHeader = IntentHeader {
    network: NETWORK,
    validity_start_ms: 0,
    validity_end_ms: MAX_INTENT_VALIDITY_RANGE.as_secs() * 1_000,
    discriminator: 0,
};

/// The ceiling every transfer here signs, above what a transfer prices.
const MAX_FEE: u128 = 100;

/// The account whose vault the reservation and the debit share.
const HOLDER: u8 = 41;
/// Where every transfer here lands.
const PAYEE: u8 = 42;
/// The sender of the debiting member's own transfer.
const SENDER: u8 = 43;
/// Pays for the reserving member, so the holder's vault carries only
/// the reservation.
const SPONSOR: u8 = 44;

fn key(seed: u8) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
}

fn account(seed: u8) -> PrincipalAddr {
    account_address(&key(seed).public_key().0)
}

fn packages() -> GenesisPackages {
    GenesisPackages::with_fixtures()
}

fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> =
        LazyLock::new(|| Client::new(genesis_world_with_pools(&[], &packages()), NETWORK));
    &CLIENT
}

/// `amount` from `from`'s account to the payee, signed by `from`, its
/// fee paid by `payer`.
fn transfer(executor: &Executor, from: u8, amount: u128, payer: u8) -> Verified<Transaction> {
    let graph = client()
        .transfer_graph(account(from), account(PAYEE), amount)
        .expect("an account answers a transfer");
    let gas_limits = default_gas_limits(graph.nodes.len());
    let envelope = signing::wrap(
        &IntentTree::of_one(Intent::leaf(HEADER, account(from), graph)),
        signing::Terms {
            fee_payer: account(payer),
            max_fee: MAX_FEE,
            gas_limits: gas_limits
                .try_into()
                .expect("one ceiling per node, under the node cap"),
            priority_bp: 0,
            message: Bytes::empty(),
        },
    )
    .expect("a transfer fits the tree cap");
    let tx = Verified::<Transaction>::from_persisted(Transaction::new(
        signing::sign(envelope, &key(from), &ProtocolHasher).expect("a transfer signs"),
    ));
    tx.try_derived(executor.derivation().as_ref())
        .expect("a transfer derives");
    tx
}

/// The holder's vault of the protocol resource.
fn vault() -> SubstateKey {
    vault_key(account(HOLDER), *PROTOCOL_RESOURCE)
}

/// Run `tx` alone over `base` under `holds`.
fn run(
    executor: &Executor,
    base: &impl Substates,
    holds: &ProvisionalHolds,
    tx: &Verified<Transaction>,
) -> ExecutedTx {
    let trie = ShardTrie::single();
    let ctx = TickBatchContext {
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        tick_ts: WeightedTimestamp::from_millis(1_000),
        env: TickEnvironment::unfolded(),
        holds,
        fee_holds: &NoFeeHolds,
        points: None,
    };
    executor
        .execute_batch(&ctx, PriceTable::GENESIS, base, std::slice::from_ref(tx))
        .expect("the harness engine holds every package it runs")
        .remove(0)
}

/// What `executed`, a run of `tx`, takes from the holder's vault.
fn debited(executed: &ExecutedTx) -> u128 {
    let ConsensusReceipt::Succeeded { writes, .. } = &executed.consensus else {
        panic!("the run completes: {:?}", executed.consensus);
    };
    writes.movements[&vault()].debit
}

/// A request for `tx` as a whole shape reaching a counterpart: a member
/// whose verdict that counterpart can still discard.
fn abortable(tx: &Verified<Transaction>) -> CrossShardExecutionRequest {
    let (local, counterpart) = ShardId::ROOT.children();
    CrossShardExecutionRequest {
        prices: PriceTable::GENESIS,
        tx_hash: tx.hash(),
        transaction: tx.clone(),
        provisions: Vec::new(),
        clock: WeightedTimestamp::from_millis(1_000),
        member: Member::of(
            Classified::whole(),
            local,
            BTreeSet::from([local, counterpart]),
        ),
        arrivals: Vec::new(),
        served_at: None,
    }
}

/// A reservation the reserving member ran with in tick 1 stands in the
/// holds of the baseline of every tick after it while the member is
/// unresolved, and a later member's debit of the same vault is judged
/// with it subtracted.
///
/// The debit is the later member's fee burn on the vault it pays from.
/// The vault holds one less than the reservation and the burn together,
/// so the burn fits the vault and does not fit what the reservation
/// leaves of it.
#[test]
fn an_inflight_reservation_is_subtracted_from_a_later_debit_of_its_vault() {
    let executor = Executor::with_genesis(&[], &packages(), ExecutionMode::Serial);
    let reserved = 500;
    let reserving = transfer(&executor, HOLDER, reserved, SPONSOR);
    let debiting = transfer(&executor, SENDER, 1, HOLDER);

    let funded = |holder: u128| {
        Store::genesis(&[
            (account(HOLDER), holder),
            (account(SENDER), 1_000),
            (account(SPONSOR), 1_000),
        ])
    };
    let burn = debited(&run(
        &executor,
        &funded(1_000),
        &ProvisionalHolds::new(),
        &debiting,
    ));
    assert!(burn > 0, "the debiting member burns its fee on the vault");
    let balance = reserved + burn - 1;
    let base = Arc::new(funded(balance));

    let ran = run(&executor, &*base, &ProvisionalHolds::new(), &reserving);
    assert!(
        matches!(ran.consensus, ConsensusReceipt::Succeeded { .. }),
        "the reservation fits the vault: {:?}",
        ran.consensus,
    );
    let mut output = TickOutput::default();
    accumulate_tick_output(&mut output, &[abortable(&reserving)], &[ran]);
    assert_eq!(
        output.provisional.len(),
        1,
        "the reserving member is in flight"
    );
    assert_eq!(
        output.provisional[0].reserved,
        BTreeMap::from([(vault(), reserved)]),
        "its declared reservation is held",
    );

    let chain = TickChain::new(Arc::clone(&base));
    chain.append(BlockHeight::new(1), output, &[]);
    for tick in 2..=4 {
        let below = BlockHeight::new(tick - 1);
        chain.prune_persisted(below, BlockHeight::GENESIS, None, WeightedTimestamp::MAX);
        let view = chain.view_at(below);
        let holds = view.holds();
        assert_eq!(
            holds
                .get(&vault())
                .map(|by_tx| by_tx.get(&reserving.hash())),
            Some(Some(&reserved)),
            "tick {tick}'s baseline holds the reservation",
        );
        let executed = run(&executor, &view.snapshot(), &holds, &debiting);
        assert!(
            !matches!(executed.consensus, ConsensusReceipt::Succeeded { .. }),
            "tick {tick} judges the debit past what the reservation leaves: {:?}",
            executed.consensus,
        );
        assert_eq!(
            debited(&run(
                &executor,
                &view.snapshot(),
                &ProvisionalHolds::new(),
                &debiting,
            )),
            burn,
            "the same debit over tick {tick}'s baseline with nothing held fits",
        );
        chain.append(BlockHeight::new(tick), TickOutput::default(), &[]);
    }
}

/// A store over the flattened genesis writes, one version at every
/// height.
struct Store(BTreeMap<SubstateKey, Vec<u8>>);

impl Store {
    fn genesis(accounts: &[(PrincipalAddr, u128)]) -> Self {
        Self(
            genesis_writes(accounts, &[], &packages())
                .cells()
                .iter()
                .map(|(key, value)| (*key, value.clone().expect("genesis sets every cell")))
                .collect(),
        )
    }
}

impl Substates for Store {
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

impl Anchored for Store {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }
}

impl SubstateStore for Store {
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

impl VersionedStore for Store {
    type Versioned = Self;

    fn retention_floor(&self) -> u64 {
        0
    }

    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self> {
        Some(self.snapshot_at(height))
    }

    fn snapshot_at(&self, _height: BlockHeight) -> Self {
        Self(self.0.clone())
    }

    fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
        None
    }

    fn hold_retention_at(&self, _height: BlockHeight, _clock: WeightedTimestamp) {}
}
