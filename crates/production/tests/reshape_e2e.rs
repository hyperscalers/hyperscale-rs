//! Production resharding end-to-end scenarios.
//!
//! Drives real beacon folds over a real libp2p cluster on real
//! `RocksDbShardStorage` to cover the production-only reshape wiring the
//! simulation suite never touches: the beacon fold → `ParticipationChange`
//! → `ShardSupervisor` duty chain and the `RocksDbShardStorage` flips.
//! Like the rest of the production e2e tests these are `#[serial]`,
//! real-time, and bounded by `timeout` — never fixed sleeps for the
//! wait-for-condition assertions.

mod cluster;

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use cluster::{Cluster, ClusterSpec, HostSpec};
use hyperscale_engine::GenesisConfig;
use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{LocalValidator, ProductionRunner};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::RocksDbBeaconStorage;
use hyperscale_test_helpers::fixtures::TestFixtures;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BeaconChainConfig, BlockHeight, Ed25519PrivateKey, NodeId, ReshapeThresholds,
    RoutableTransaction, ShardId, ShardTrie, TransactionDecision, TransactionStatus, TxHash,
    ValidatorId, ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use serial_test::serial;
use tempfile::TempDir;
use tokio::time::{Instant, sleep};
use tracing_subscriber::fmt;

/// Real-time epoch length: short enough to fold the many epochs a split
/// takes inside the test budget, long enough for beacon PC/SPC to commit
/// each block over localhost QUIC well under its production-sized SPC
/// timeout.
const EPOCH_MS: u64 = 2000;

fn validator(fixtures: &TestFixtures, idx: u32) -> LocalValidator {
    LocalValidator {
        validator_id: ValidatorId::new(u64::from(idx)),
        signing_key: fixtures.signing_key(idx),
    }
}

/// A custom `beacon_chain_config` threads through the builder into the
/// committed beacon genesis state. This is the single production hook the
/// rest of the suite depends on: the default path (every other production
/// e2e test) leaves the setter unused and is unaffected, so a custom
/// `epoch_duration_ms` + reshape `split_bytes` reach the genesis state
/// only when set explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: 400,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 50_000,
        },
        ..BeaconChainConfig::default()
    };

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let runner = ProductionRunner::builder(
        vec![validator(&fixtures, 0)],
        fixtures.topology(),
        ShardConsensusConfig::default(),
        beacon_reader,
        network_config,
        cluster::temp_storage_factory(&temp_dir),
        cluster::temp_storage_dir(&temp_dir),
    )
    .beacon_chain_config(chain_config)
    .build();
    assert!(
        runner.is_ok(),
        "runner builds with a custom beacon chain config"
    );

    // Build commits the genesis (block, state) pair into the beacon store.
    let (_block, state) = beacon_storage
        .latest_committed()
        .expect("genesis pair committed at build time");
    assert_eq!(
        state.chain_config.epoch_duration_ms, 400,
        "custom epoch duration reaches the beacon genesis state"
    );
    assert_eq!(
        state.params.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold seeds the live network params at genesis"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Straddler settlement across a production reshape boundary
// ════════════════════════════════════════════════════════════════════════════

/// A fresh keypair whose preallocated account `route`s to `shard` — the same
/// routing genesis uses, threaded through so a non-uniform partition can use
/// its trie rather than the uniform `num_shards` rule.
fn account_in(
    route: impl Fn(&NodeId) -> ShardId,
    shard: ShardId,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, ComponentAddress) {
    for seed in 1u8..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let key = ed25519_keypair_from_seed(&[seed; 32]);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId(
            address.into_node_id().0[..30]
                .try_into()
                .expect("account address carries a 30-byte node id"),
        );
        if route(&node) == shard {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {shard:?}");
}

/// A payer-to-recipient XRD transfer, signed and routable.
fn transfer(
    payer_key: &Ed25519PrivateKey,
    payer: ComponentAddress,
    recipient: ComponentAddress,
) -> Arc<RoutableTransaction> {
    let manifest = ManifestBuilder::new()
        .lock_fee(payer, Decimal::from(10))
        .withdraw_from_account(payer, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(recipient, None)
        .build();
    let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 1, payer_key)
        .expect("transfer signs");
    Arc::new(routable_from_notarized_v1(notarized, test_validity_range()).expect("routable"))
}

/// Poll host `idx`'s status cache until every probe reaches a terminal
/// `Completed` verdict, or `within` elapses.
async fn await_all_completed(
    cluster: &Cluster,
    idx: usize,
    probes: &[TxHash],
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    loop {
        let done = probes.iter().all(|hash| {
            matches!(
                cluster.tx_status(idx, hash),
                Some(TransactionStatus::Completed(_))
            )
        });
        if done {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// The cross-chain fate of a batch of straddlers at a reshape boundary.
///
/// Atomicity turns on *decision consistency*, not on a specific verdict: a
/// cross-shard transfer the terminating shard rejected and the survivor also
/// rejected is settled atomically, exactly as one both accepted is. Only a
/// disagreement — the survivor reaching a decision the terminating shard
/// never settled, or settling a different one — breaks the fence.
struct StraddlerTally {
    /// The terminating shard settled it (a non-abort finalize by its terminal
    /// block) and the survivor reached the same decision — atomic end to end.
    consistent: u32,
    /// The survivor reached a non-abort decision the terminating shard never
    /// settled — a one-sided cross-shard application.
    one_sided: u32,
    /// The survivor's decision disagreed with the terminating shard's settled
    /// one (a settled half discarded, or the opposite verdict applied).
    mismatch: u32,
    /// The terminating shard never settled it and the survivor aborted it,
    /// releasing the straddler's locks.
    doomed_aborted: u32,
    report: String,
}

/// Classify each straddler against the terminating shard's committed chain
/// (the settled decision it reached by its terminal block) and the survivor's
/// authoritative status verdict.
fn assess_straddlers(
    cluster: &Cluster,
    terminating: ShardId,
    survivor: ShardId,
    terminal_b: BlockHeight,
    survivor_host: usize,
    probes: &[TxHash],
    header: &str,
) -> StraddlerTally {
    let mut tally = StraddlerTally {
        consistent: 0,
        one_sided: 0,
        mismatch: 0,
        doomed_aborted: 0,
        report: header.to_string(),
    };
    for (idx, hash) in probes.iter().enumerate() {
        let (t_committed, t_finalized) = cluster.chain_fate(terminating, *hash);
        let (v_committed, v_finalized) = cluster.chain_fate(survivor, *hash);
        // The terminating shard settled the straddler iff it finalized a
        // non-abort decision at or before its terminal block.
        let settled = t_finalized
            .and_then(|(h, d)| (h <= terminal_b && d != TransactionDecision::Aborted).then_some(d));
        // The survivor's status cache holds its authoritative final verdict.
        let verdict = match cluster.tx_status(survivor_host, hash) {
            Some(TransactionStatus::Completed(d)) => Some(d),
            _ => None,
        };
        let _ = write!(
            tally.report,
            "\n  #{idx}: terminating committed={:?} finalized={:?} settled={settled:?}; \
             survivor committed={:?} finalized={:?} verdict={verdict:?}",
            t_committed.map(BlockHeight::inner),
            t_finalized.map(|(h, d)| (h.inner(), d)),
            v_committed.map(BlockHeight::inner),
            v_finalized.map(|(h, d)| (h.inner(), d)),
        );
        match (settled, verdict) {
            (Some(_), Some(TransactionDecision::Aborted)) => tally.mismatch += 1, // settled half discarded
            (Some(t), Some(v)) if t == v => tally.consistent += 1,
            (Some(_), Some(_)) => tally.mismatch += 1, // opposite verdicts
            (None, Some(TransactionDecision::Aborted)) => tally.doomed_aborted += 1,
            (None, Some(_)) => tally.one_sided += 1, // applied with no settlement
            (_, None) => {} // unresolved — the all-completed gate catches it
        }
    }
    tally
}

/// Assert the settled-waves fence held for a batch of straddlers: every one
/// reached a terminal verdict, none applied one-sided or mismatched the
/// terminating shard's settlement, and at least one settled atomically.
fn assert_fence_held(tally: &StraddlerTally, all_done: bool) {
    let report = &tally.report;
    assert!(
        all_done,
        "every straddler must reach a terminal verdict on the survivor — none may hang on \
         the settled-waves fence:\n{report}",
    );
    assert_eq!(
        tally.one_sided, 0,
        "the survivor reached a decision the terminating shard never settled — one-sided \
         cross-shard application:\n{report}",
    );
    assert_eq!(
        tally.mismatch, 0,
        "the survivor's verdict disagreed with the terminating shard's settlement:\n{report}",
    );
    assert!(
        tally.consistent > 0,
        "no straddler settled atomically between the survivor and the terminating shard — \
         submission timing needs retuning:\n{report}",
    );
}

/// Merge-side straddlers. Submitted in a tight burst right after pairing so
/// all land early in the long merge grow phase — every one has the full
/// coast to settle or be counterpart-aborted, none stranded mid-flight past
/// the merging shard's terminal.
const MERGE_STRADDLERS: usize = 4;

/// Spacing between merge-straddler submissions.
const MERGE_STRADDLE_SPACING_MS: u64 = 1000;

/// `merge_bytes = split_bytes / 8`. The merging `leaf(2,2)`/`leaf(2,3)` pair
/// sits under it and the surviving `leaf(1,0)` over it, so only the right-half
/// pair merges while `leaf(1,0)` keeps the left half alive. Bracketed against
/// the measured production genesis totals: `leaf(1,0)` carries the heavier
/// engine-bootstrap left half (~611k), the merging pair the right-half
/// quarters (~317k / ~56k).
const MERGE_SPLIT_BYTES: u64 = 3_360_000;

/// A surviving shard reconstructs a *merged* shard's settled set over the
/// real network. A non-uniform genesis partition: the surviving `leaf(1,0)`
/// spans the whole left half at depth 1, while the merging `leaf(2,2)` and
/// `leaf(2,3)` (both under the merge threshold) sit at depth 2 in the right
/// half and collapse into `leaf(1,1)`. Cross-shard transfers run from the
/// survivor `leaf(1,0)` into the merging `leaf(2,2)`, so the survivor's wave
/// names a shard that terminates at the merge. After the merge the survivor
/// must read `leaf(2,2)`'s beacon-attested `settled_waves_root`, fetch and
/// verify `S_{leaf(2,2)}`, and finalize a straddler only because `leaf(2,2)`
/// settled it — never one-sided — while aborting the ones it never settled.
/// Exercises the merge-child terminal's settled-waves attestation, the path a
/// split child's terminal cannot cover.
///
/// Real-time and `#[serial]`. Three shards rather than the four a uniform
/// depth-2 partition would force: the survivor at depth 1 absorbs the whole
/// left half, so the beacon folds one fewer chain and the cluster keeps
/// twelve pinned consensus threads under the core count — the headroom the
/// merge's two live child chains need to fold their ready signals before the
/// readiness TTL churns the pairing. Four hosts, each running one member of
/// every shard; the merging pair co-host so their keepers coalesce onto one
/// shared parent store.
///
/// `#[ignore]` by default: even at three shards this lands around a two in
/// three pass rate. The merge pairing churns when the beacon cannot fold both
/// merging children's assertions within the readiness TTL under the live
/// survivor-shard load, and the merged parent occasionally stalls at its
/// genesis seating — the same merge fragility the keeper merge e2e and the
/// simulation `reshape_merge_straddle` already exercise reliably. When it does
/// complete it validates the whole settled-waves path end to end, so it stays
/// here as a manual / dedicated-lane check rather than a green CI guard. The
/// split-side `surviving_sibling_settles_a_split_straddler` covers the
/// settled-waves acquisition over libp2p reliably.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
#[ignore = "load-fragile real-time merge straddle; ~2/3 pass rate, run manually"]
#[allow(clippy::too_many_lines)] // one merge-straddler lifecycle asserted end to end
async fn survivor_settles_a_merge_straddler() {
    let _ = fmt().with_test_writer().try_init();

    let survivor = ShardId::leaf(1, 0);
    let merge_parent = ShardId::leaf(1, 1);
    let (merge_left, merge_right) = merge_parent.children(); // leaf(2,2), leaf(2,3)
    let merging = merge_left; // the straddler's far half terminates here

    let committee = |base: u64| (base..base + 4).map(ValidatorId::new).collect::<Vec<_>>();
    let fixtures = TestFixtures::with_explicit_shards(
        13,
        vec![
            (survivor, committee(0)),
            (merge_left, committee(4)),
            (merge_right, committee(8)),
        ],
    );
    let trie = ShardTrie::from_leaves([survivor, merge_left, merge_right]);
    let route = |node: &NodeId| trie.shard_for(node);

    // Straddler pairs: payer in the surviving leaf(1,0), recipient in the
    // merging leaf(2,2) — a cross-shard transfer whose wave on the survivor
    // names the terminating leaf(2,2).
    let mut taken = Vec::new();
    let mut balances: Vec<(ComponentAddress, Decimal)> = Vec::new();
    let straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = (0
        ..MERGE_STRADDLERS)
        .map(|_| {
            let (payer_key, payer) = account_in(route, survivor, &mut taken);
            let (_, recipient) = account_in(route, merging, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    for (_, payer, recipient) in &straddlers {
        balances.push((*payer, Decimal::from(10_000)));
        balances.push((*recipient, Decimal::from(10_000)));
    }
    let genesis_config = GenesisConfig {
        xrd_balances: balances,
        ..GenesisConfig::production()
    };

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: EPOCH_MS,
        num_shards: 3,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: MERGE_SPLIT_BYTES,
        },
        ..BeaconChainConfig::default()
    };

    // Four hosts, each running one member of every shard. The merging pair
    // (leaf(2,2)/leaf(2,3)) co-host so their drawn keepers coalesce onto one
    // shared parent store (the merge store-lock rule), and the survivor rides
    // along — three shards on four libp2p endpoints.
    let hosts: Vec<HostSpec> = (0..4)
        .map(|h| {
            HostSpec::new(vec![
                validator(&fixtures, h),
                validator(&fixtures, h + 4),
                validator(&fixtures, h + 8),
            ])
        })
        .collect();

    let cluster = Cluster::start(ClusterSpec {
        topology: fixtures.topology(),
        hosts,
        beacon_chain_config: chain_config,
        genesis_config: Some(genesis_config),
        simulated_outbound_latency: Duration::from_millis(60),
    })
    .await;

    // The funded genesis byte totals must bracket the merge threshold: the
    // survivor over, the merging pair under.
    let merge_bytes = MERGE_SPLIT_BYTES / 8;
    cluster
        .await_committed_height(survivor, 2, Duration::from_secs(30))
        .await;
    cluster
        .await_committed_height(merging, 2, Duration::from_secs(30))
        .await;
    let survivor_bytes = cluster.substate_bytes(survivor);
    let left_bytes = cluster.substate_bytes(merge_left);
    let right_bytes = cluster.substate_bytes(merge_right);
    assert!(
        survivor_bytes.is_some_and(|b| b > merge_bytes),
        "survivor genesis bytes {survivor_bytes:?} must exceed merge_bytes={merge_bytes}",
    );
    assert!(
        left_bytes.is_some_and(|b| b < merge_bytes),
        "merge-left genesis bytes {left_bytes:?} must stay under merge_bytes={merge_bytes}",
    );
    assert!(
        right_bytes.is_some_and(|b| b < merge_bytes),
        "merge-right genesis bytes {right_bytes:?} must stay under merge_bytes={merge_bytes}",
    );

    // The beacon pairs the merge for leaf(1,1) with four keepers; the
    // survivor `leaf(1,0)` never pairs because it stays above the threshold.
    // Pairing needs both merging children's merge assertions folded within
    // the readiness TTL or it cancels and re-pairs; the window rides out a
    // couple of such re-pairs under the live load.
    cluster
        .await_merge_paired(merge_parent, 4, Duration::from_secs(90))
        .await;

    // Submit the straddlers across the grow phase from a survivor host.
    let survivor_host = cluster
        .host_serving(survivor)
        .expect("a host serves the survivor");
    let mut probes: Vec<TxHash> = Vec::new();
    for (payer_key, payer, recipient) in &straddlers {
        let tx = transfer(payer_key, *payer, *recipient);
        probes.push(tx.hash());
        assert!(
            cluster.submit_transaction(survivor_host, tx),
            "the survivor host accepts the straddler",
        );
        sleep(Duration::from_millis(MERGE_STRADDLE_SPACING_MS)).await;
    }

    // The merge executes: the merged parent seats and commits past genesis.
    // The flip seats four keepers, arms the pacemaker, and hands off the
    // beacon signer, all while three shards share the runtime — give it a
    // wide window before declaring the seated store stuck.
    cluster
        .await_any_host_serves(merge_parent, Duration::from_secs(150))
        .await;
    cluster
        .await_height_advances(merge_parent, Duration::from_secs(120))
        .await;

    // The merging child's terminal block sits one below the merged genesis.
    let state = cluster.beacon_state().expect("post-merge beacon state");
    let genesis_height = state.boundaries[&merge_parent].height;
    let terminal_b = genesis_height
        .prev()
        .expect("terminal below merged genesis");

    // The survivor reconstructs S_{leaf(2,2)} and resolves each straddler.
    let all_done =
        await_all_completed(&cluster, survivor_host, &probes, Duration::from_secs(180)).await;

    let header = format!(
        "survivor_bytes={survivor_bytes:?} merge_left_bytes={left_bytes:?} \
         merge_right_bytes={right_bytes:?} merged_genesis=h{} terminal_B=h{}",
        genesis_height.inner(),
        terminal_b.inner(),
    );
    let tally = assess_straddlers(
        &cluster,
        merging,
        survivor,
        terminal_b,
        survivor_host,
        &probes,
        &header,
    );
    assert_fence_held(&tally, all_done);

    cluster.shutdown().await;
}
