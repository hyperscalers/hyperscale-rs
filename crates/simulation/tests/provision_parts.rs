//! A block's provisions travel as one part per transaction, each fetched
//! by its own index, so what one part suffers costs only its own
//! transaction.
//!
//! Each case cuts the provision gossip between the two shards and works
//! on the fallback fetch's answers in flight: a part left out of an
//! answer is a part its responder could not, or would not, build.
//!
//! Sim-only. The rewrite hooks the in-memory transport's response leg.

mod support;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_scenarios::tx::{
    account_routing_to, build_composed_tx, payment_request_for, validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{
    Cluster, FaultHandle, FaultableCluster, ScenarioConfig, committees_on_separate_hosts, epochs,
};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, PrincipalAddr, ShardId, TransactionDecision, TransactionStatus,
    TxHash,
};
use support::SimCluster;

const PAYER_SHARD: ShardId = ShardId::leaf(1, 0);
const RECIPIENT_SHARD: ShardId = ShardId::leaf(1, 1);

/// How many transfers ride one source block: enough parts that the
/// index under attack has neighbours on both sides.
const TRANSFERS: usize = 4;

/// Two shards, four validators each, resharding disarmed, every
/// committee on hosts of its own so provisions cross the wire.
const fn config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: std::time::Duration::from_millis(150),
    }
}

/// One payer on the payer shard per transfer, each paying its own
/// recipient on the other shard.
struct Transfers {
    payers: Vec<Payment>,
}

/// A payer and the recipient it pays.
struct Payment {
    payer_key: Ed25519PrivateKey,
    from: PrincipalAddr,
    recipient_key: Ed25519PrivateKey,
    to: PrincipalAddr,
}

impl Transfers {
    fn new() -> Self {
        let mut taken = Vec::new();
        let payers = (0..TRANSFERS)
            .map(|_| {
                let (payer_key, from) = account_routing_to(PAYER_SHARD, &mut taken);
                let (recipient_key, to) = account_routing_to(RECIPIENT_SHARD, &mut taken);
                Payment {
                    payer_key,
                    from,
                    recipient_key,
                    to,
                }
            })
            .collect();
        Self { payers }
    }

    fn genesis(&self) -> Vec<(PrincipalAddr, u128)> {
        self.payers
            .iter()
            .flat_map(|payment| [(payment.from, 10_000), (payment.to, 10)])
            .collect()
    }

    /// Submit every transfer at once, so they commit in one block.
    ///
    /// The recipient signs the deposit as a request the payer composes,
    /// so both shards commit the transaction: the payer's part crosses to
    /// the recipient's shard and the recipient's engagement crosses back.
    /// A plain transfer crosses only as a record read, which no part
    /// carries.
    fn submit(&self, c: &mut SimCluster) -> Vec<TxHash> {
        let validity = validity_around(c.now());
        self.payers
            .iter()
            .map(|payment| {
                let tx = build_composed_tx(
                    &payment.payer_key,
                    payment.from,
                    &payment.recipient_key,
                    &payment_request_for(payment.to, 100, validity),
                    100,
                    validity,
                );
                let hash = tx.hash();
                c.submit(tx);
                hash
            })
            .collect()
    }
}

fn cluster(transfers: &Transfers) -> SimCluster {
    SimCluster::with_grown_accounts_on_dedicated_pool_hosts(&config(), 42, &transfers.genesis())
}

/// Cut provision gossip between the two committees, both ways, so every
/// part is fetched.
fn cut_gossip(c: &mut SimCluster) -> [FaultHandle; 2] {
    let (payers, recipients) = committees_on_separate_hosts(c, PAYER_SHARD, RECIPIENT_SHARD);
    [
        c.drop_type_between(&payers, &recipients, "provisions.broadcast"),
        c.drop_type_between(&recipients, &payers, "provisions.broadcast"),
    ]
}

/// What one host answers in place of `honest`: the parts `keep` keeps,
/// the count witness untouched. A dropped part is recorded by the
/// transaction it provisions.
fn filter_parts(
    honest: &[u8],
    dropped: &Mutex<BTreeSet<TxHash>>,
    keep: impl Fn(u32) -> bool,
) -> Vec<u8> {
    let Ok(response) = hbor_from_slice::<GetProvisionResponse>(honest) else {
        return honest.to_vec();
    };
    let mut held = dropped.lock().unwrap_or_else(PoisonError::into_inner);
    let parts = response
        .parts
        .into_inner()
        .into_iter()
        .filter(|part| {
            let kept = keep(part.leaf().index);
            if !kept {
                held.insert(part.tx_hash());
            }
            kept
        })
        .collect();
    hbor_to_vec(&GetProvisionResponse {
        parts: Capped::new(parts).expect("no more parts than the honest answer"),
        count: response.count,
    })
    .expect("an answer encodes")
}

/// Every host of the payer shard answers a provision fetch without the
/// part at `index`: as if no peer could build the payer's part the
/// recipient's shard engages against.
fn unbuildable_everywhere(
    c: &mut SimCluster,
    index: u32,
) -> (Vec<FaultHandle>, Arc<Mutex<BTreeSet<TxHash>>>) {
    let dropped = Arc::new(Mutex::new(BTreeSet::new()));
    let handles = c
        .committee_hosts(PAYER_SHARD)
        .into_iter()
        .map(|host| {
            let dropped = Arc::clone(&dropped);
            c.rewrite_responses(
                host,
                "provision.request",
                Arc::new(move |_asked: &[u8], honest: &[u8]| {
                    filter_parts(honest, &dropped, |at| at != index)
                }),
            )
        })
        .collect();
    (handles, dropped)
}

const fn accepted(status: Option<&TransactionStatus>) -> bool {
    matches!(
        status,
        Some(TransactionStatus::Completed(TransactionDecision::Accept))
    )
}

/// Wait for every transfer to finish, and return each one's status.
fn settle(c: &mut SimCluster, hashes: &[TxHash]) -> Vec<(TxHash, Option<TransactionStatus>)> {
    hashes
        .iter()
        .map(|hash| (*hash, await_tx_terminal(c, *hash, epochs(3))))
        .collect()
}

/// Split `outcomes` into the transfers whose part was dropped and the
/// rest, asserting the attack reached at least one and spared at least
/// one.
fn split(
    outcomes: &[(TxHash, Option<TransactionStatus>)],
    dropped: &Mutex<BTreeSet<TxHash>>,
) -> (
    Vec<Option<TransactionStatus>>,
    Vec<Option<TransactionStatus>>,
) {
    let dropped = dropped.lock().unwrap_or_else(PoisonError::into_inner);
    let (hit, spared): (Vec<_>, Vec<_>) = outcomes
        .iter()
        .partition(|(hash, _)| dropped.contains(hash));
    assert!(
        !hit.is_empty(),
        "no part at the attacked index was ever served, so nothing was attacked: {outcomes:?}",
    );
    assert!(
        !spared.is_empty(),
        "every transfer's part was dropped, so nothing shows the rest survive: {outcomes:?}",
    );
    (
        hit.into_iter().map(|(_, status)| status.clone()).collect(),
        spared
            .into_iter()
            .map(|(_, status)| status.clone())
            .collect(),
    )
}

/// One part no peer can build costs its own transaction and no other:
/// its neighbours are fetched by index and execute, it aborts at its
/// deadline, and the orphan sweep lets go of its index, so no fetch id
/// is left pending anywhere.
#[test]
fn an_unbuildable_part_costs_only_its_own_transaction() {
    let transfers = Transfers::new();
    let mut cluster = cluster(&transfers);
    cluster.run_faultable(|c| {
        cut_gossip(c);
        let (handles, dropped) = unbuildable_everywhere(c, 1);
        let hosts = c.committee_hosts(RECIPIENT_SHARD);
        let pending = |c: &SimCluster| -> Vec<Option<usize>> {
            hosts
                .iter()
                .map(|&host| c.provision_fetch_pending(host, RECIPIENT_SHARD))
                .collect()
        };
        let hashes = transfers.submit(c);

        // The unbuildable index stays asked on the recipient's shard,
        // rotating peers, while its transaction waits.
        let asked = Cell::new(false);
        c.run_until(epochs(3), |c| {
            if pending(c).iter().any(|count| count.is_some_and(|n| n > 0)) {
                asked.set(true);
            }
            hashes
                .iter()
                .all(|hash| c.tx_status(*hash).is_some_and(|s| s.is_final()))
        });
        assert!(
            asked.get(),
            "the unbuildable index was never asked, so the sweep shows nothing",
        );
        let outcomes = settle(c, &hashes);
        assert!(handles.iter().any(|handle| handle.fired() > 0));
        let (hit, spared) = split(&outcomes, &dropped);
        assert!(
            spared.iter().all(|status| accepted(status.as_ref())),
            "every transfer with a buildable part executes: {outcomes:?}",
        );
        assert!(
            hit.iter().all(|status| !accepted(status.as_ref())),
            "the transfer whose part nobody builds does not: {outcomes:?}",
        );

        // Past the orphan sweep it is abandoned, and no fetch id is left
        // pending anywhere.
        let drained = c.run_until(epochs(4), |c| {
            pending(c).iter().all(|count| *count == Some(0))
        });
        assert!(
            drained,
            "provision fetch ids still pending after the orphan sweep: {:?}",
            pending(c),
        );
    });
}

/// Index 0 built by nobody and the gossip lost: the count witness every
/// holder of the block states teaches how many parts there are, so the
/// other indices are asked, admitted and executed, and only index 0's
/// transaction aborts.
#[test]
fn the_count_witness_reaches_past_an_unbuildable_index_zero() {
    let transfers = Transfers::new();
    let mut cluster = cluster(&transfers);
    cluster.run_faultable(|c| {
        let cut = cut_gossip(c);
        let (handles, dropped) = unbuildable_everywhere(c, 0);
        let hashes = transfers.submit(c);
        let outcomes = settle(c, &hashes);
        assert!(
            handles.iter().any(|handle| handle.fired() > 0),
            "no fetch was answered: {outcomes:?} cut {:?} now {:?}",
            cut.iter().map(FaultHandle::fired).collect::<Vec<_>>(),
            c.now(),
        );
        let (hit, spared) = split(&outcomes, &dropped);
        assert!(
            spared.iter().all(|status| accepted(status.as_ref())),
            "every transfer past index 0 executes: {outcomes:?}",
        );
        assert!(
            hit.iter().all(|status| !accepted(status.as_ref())),
            "index 0's transfer does not: {outcomes:?}",
        );
    });
}

/// Make the payer-shard host first asked about each source block — the
/// block's proposer, which the fetch prefers — answer every fetch for
/// that block with only the parts `keep` keeps. Every other host answers
/// honestly. Returns the transactions whose parts it left out.
fn first_asked_lies(c: &mut SimCluster, keep: fn(u32) -> bool) -> Arc<Mutex<BTreeSet<TxHash>>> {
    let left_out = Arc::new(Mutex::new(BTreeSet::new()));
    let liars: Arc<Mutex<BTreeMap<BlockHeight, usize>>> = Arc::new(Mutex::new(BTreeMap::new()));
    for host in c.committee_hosts(PAYER_SHARD) {
        let left_out = Arc::clone(&left_out);
        let liars = Arc::clone(&liars);
        let _ = c.rewrite_responses(
            host,
            "provision.request",
            Arc::new(move |asked: &[u8], honest: &[u8]| {
                let Ok(request) = hbor_from_slice::<GetProvisionsRequest>(asked) else {
                    return honest.to_vec();
                };
                let liar = *liars
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(request.height)
                    .or_insert(host);
                if liar == host {
                    filter_parts(honest, &left_out, keep)
                } else {
                    honest.to_vec()
                }
            }),
        );
    }
    left_out
}

/// The block's proposer withholds its gossip and answers the fallback
/// with index 0 alone, however often it is asked. The fetch prefers the
/// proposer, so it is asked first; every other index is fetched from the
/// committee's other members, and every transfer executes.
#[test]
fn a_proposer_withholding_its_parts_is_fetched_around() {
    let transfers = Transfers::new();
    let mut cluster = cluster(&transfers);
    cluster.run_faultable(|c| {
        cut_gossip(c);
        let withheld = first_asked_lies(c, |at| at == 0);
        let hashes = transfers.submit(c);
        let outcomes = settle(c, &hashes);
        assert!(
            !withheld
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "no answer withheld a part, so nothing was attacked",
        );
        assert!(
            outcomes.iter().all(|(_, status)| accepted(status.as_ref())),
            "every withheld part is fetched elsewhere: {outcomes:?}",
        );
    });
}

/// A responder that always leaves index 1 out of its answers is asked
/// again elsewhere for it, and the transfer at index 1 executes.
#[test]
fn a_responder_omitting_an_index_is_asked_around() {
    let transfers = Transfers::new();
    let mut cluster = cluster(&transfers);
    cluster.run_faultable(|c| {
        cut_gossip(c);
        let omitted = first_asked_lies(c, |at| at != 1);
        let hashes = transfers.submit(c);
        let outcomes = settle(c, &hashes);
        let omitted = omitted.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            outcomes.iter().any(|(hash, _)| omitted.contains(hash)),
            "the liar never left a part out, so nothing was attacked: {outcomes:?}",
        );
        assert!(
            outcomes.iter().all(|(_, status)| accepted(status.as_ref())),
            "every omitted index is fetched from an honest peer: {outcomes:?}",
        );
    });
}
