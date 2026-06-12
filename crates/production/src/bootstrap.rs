//! Async pump for the sans-io shard bootstrap sequencer.
//!
//! [`ShardBootstrap`] owns the sequencing — state assembly, import +
//! anchor verification, witness history, recovery seeding. This driver
//! owns what the sequencer can't: dispatching its requests through
//! [`Network::request`] (verification verdicts feed the peer-health
//! tracker from inside the response callbacks), writing the import into
//! the joiner's store, wall-clock pacing between fruitless rounds, and
//! re-reading the anchor from the live topology when the state assembly
//! starves (serving peers may have evicted the boundary it targets).
//! It never gives up on its own; the join stands until the supervisor
//! tears it down.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_node::SharedTopologySnapshot;
use hyperscale_node::bootstrap::observer::{ObserverBootstrap, ObserverTail, TailOutcome};
use hyperscale_node::bootstrap::split_flip::split_genesis_from_terminal;
use hyperscale_node::bootstrap::{BootstrapOutcome, BootstrapRequest, ShardBootstrap};
use hyperscale_storage::{RecoveredState, ShardStorage};
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, ChainOrigin, Request, ShardAnchor, ShardId, StateRoot,
};
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Pause between rounds that made no progress, so an unreachable or
/// still-syncing committee isn't hammered.
const FRUITLESS_ROUND_PAUSE: Duration = Duration::from_secs(1);

/// Fruitless rounds before the anchor is re-read from the live
/// topology — serving peers may have evicted the targeted boundary, in
/// which case the assembly restarts against the newer one.
const ROUNDS_BEFORE_ANCHOR_REFRESH: u32 = 30;

/// Bootstrap a joining vnode's shard state against the beacon-attested
/// boundary anchor, returning the [`RecoveredState`] its state machines
/// boot from. The caller has already established that `storage` is
/// fresh and an anchor exists.
///
/// # Errors
///
/// Returns a description of the failure. Errors are terminal for this
/// join attempt — the import wrote into `storage`, or the store wasn't
/// fresh to begin with; the operator decides whether to wipe and retry.
pub async fn bootstrap_shard_state<S, N>(
    network: &Arc<N>,
    topology: &SharedTopologySnapshot,
    storage: &Arc<S>,
    shard: ShardId,
) -> Result<RecoveredState, String>
where
    S: ShardStorage,
    N: Network,
{
    'anchor: loop {
        let Some(anchor) = topology.load().boundary(shard) else {
            return Err(format!("shard {shard:?} has no attested anchor"));
        };
        info!(
            ?shard,
            height = anchor.height.inner(),
            "Snap-sync bootstrap starting against attested anchor"
        );
        let bootstrap = Arc::new(Mutex::new(ShardBootstrap::new(shard, anchor)));
        let mut fruitless = 0u32;
        while !lock(&bootstrap).is_complete() {
            let import = lock(&bootstrap).take_import();
            if let Some((height, leaves)) = import {
                let root = storage
                    .import_boundary_state(height, leaves)
                    .map_err(|error| format!("boundary import failed: {error}"))?;
                lock(&bootstrap).on_imported(root)?;
                continue;
            }

            let requests = lock(&bootstrap).next_requests();
            let accepted = run_round(network, shard, &bootstrap, requests).await;
            if accepted == 0 {
                fruitless += 1;
                if fruitless >= ROUNDS_BEFORE_ANCHOR_REFRESH {
                    fruitless = 0;
                    // Only the state assembly depends on peers still
                    // pinning the targeted boundary (and only there is
                    // a restart sound — nothing has been imported yet);
                    // the witness history serves from the live chain.
                    if lock(&bootstrap).is_assembling_state()
                        && topology
                            .load()
                            .boundary(shard)
                            .is_some_and(|latest| latest != anchor)
                    {
                        warn!(
                            ?shard,
                            stale = anchor.height.inner(),
                            "Snap-sync starved; restarting against the advanced anchor"
                        );
                        continue 'anchor;
                    }
                    warn!(
                        ?shard,
                        height = anchor.height.inner(),
                        "Shard bootstrap making no progress; continuing"
                    );
                }
                sleep(FRUITLESS_ROUND_PAUSE).await;
            } else {
                fruitless = 0;
            }
        }

        let bootstrap = Arc::try_unwrap(bootstrap)
            .map_err(|_| ())
            .expect("all request callbacks resolved before completion")
            .into_inner()
            .expect("bootstrap mutex unpoisoned");
        info!(
            ?shard,
            height = bootstrap.anchor().height.inner(),
            "Snap-sync bootstrap complete; state verified against the anchor"
        );
        return Ok(bootstrap.into_recovered_state());
    }
}

/// Bootstrap an observer's pending-child span against the splitting
/// shard's beacon-attested boundary anchor, returning the anchor the
/// assembly completed against, the imported child subtree root, and
/// the imported substate count. Requests route to `via`'s committee;
/// pacing and the starved-assembly anchor refresh mirror
/// [`bootstrap_shard_state`].
///
/// # Errors
///
/// Returns a description of the failure. Errors are terminal for this
/// duty — the import wrote into `storage`, or the store wasn't fresh
/// to begin with.
pub async fn bootstrap_observer_state<S, N>(
    network: &Arc<N>,
    topology: &SharedTopologySnapshot,
    storage: &Arc<S>,
    via: ShardId,
    child: ShardId,
) -> Result<(ShardAnchor, StateRoot, u64), String>
where
    S: ShardStorage,
    N: Network,
{
    'anchor: loop {
        let Some(anchor) = topology.load().boundary(via) else {
            return Err(format!("splitting shard {via:?} has no attested anchor"));
        };
        info!(
            ?via,
            ?child,
            height = anchor.height.inner(),
            "Observer bootstrap starting against the splitting shard's anchor"
        );
        let bootstrap = Arc::new(Mutex::new(ObserverBootstrap::new(via, anchor, child)));
        let mut fruitless = 0u32;
        while !lock(&bootstrap).is_complete() {
            let import = lock(&bootstrap).take_import();
            if let Some((height, leaves)) = import {
                let root = storage
                    .import_boundary_state(height, leaves)
                    .map_err(|error| format!("child-span import failed: {error}"))?;
                lock(&bootstrap).on_imported(root);
                continue;
            }

            let requests = lock(&bootstrap).next_requests();
            let accepted = run_observer_round(network, via, &bootstrap, requests).await;
            if accepted == 0 {
                fruitless += 1;
                if fruitless >= ROUNDS_BEFORE_ANCHOR_REFRESH {
                    fruitless = 0;
                    // A restart is sound only while nothing has been
                    // imported; past that, the duty stands on its anchor.
                    if lock(&bootstrap).is_assembling_state()
                        && topology
                            .load()
                            .boundary(via)
                            .is_some_and(|latest| latest != anchor)
                    {
                        warn!(
                            ?via,
                            ?child,
                            stale = anchor.height.inner(),
                            "Observer assembly starved; restarting against the advanced anchor"
                        );
                        continue 'anchor;
                    }
                    warn!(
                        ?via,
                        ?child,
                        height = anchor.height.inner(),
                        "Observer bootstrap making no progress; continuing"
                    );
                }
                sleep(FRUITLESS_ROUND_PAUSE).await;
            } else {
                fruitless = 0;
            }
        }

        let bootstrap = Arc::try_unwrap(bootstrap)
            .map_err(|_| ())
            .expect("all request callbacks resolved before completion")
            .into_inner()
            .expect("bootstrap mutex unpoisoned");
        let root = bootstrap.imported_root().expect("complete bootstrap");
        info!(
            ?via,
            ?child,
            height = anchor.height.inner(),
            substates = bootstrap.imported_substate_count(),
            "Observer bootstrap complete; child span imported"
        );
        return Ok((anchor, root, bootstrap.imported_substate_count()));
    }
}

/// Pace between follow rounds that found no new block — the parent
/// chain commits on its own cadence, and the boundary handoff waits on
/// beacon folds.
const FOLLOW_PAUSE: Duration = Duration::from_millis(200);

/// Keep an observer's synced child store current with the splitting
/// parent's chain until the beacon seeds the child's own anchor, then
/// catch up through the parent's terminal block and derive the
/// deterministic genesis from the terminal pair.
///
/// Requests target `via` while the parent lives; once the child anchor
/// projects they target `child` instead — the parent committee
/// dissolves at the boundary, while the child committee's parent-half
/// members serve the parent's blocks from their hard-linked
/// checkpoints. Never gives up on its own; the duty stands until the
/// supervisor tears it down.
///
/// Returns the derived genesis block, the chain origin, and the
/// followed root (the caller adopts the store and verifies the root
/// against the child anchor).
///
/// # Errors
///
/// Returns a description when a follow application contradicts a
/// followed header's `split_child_roots` or the store write fails —
/// the duty fails closed and the flip falls back to a fresh snap-sync.
pub async fn follow_observer_store<S, N>(
    network: &Arc<N>,
    topology: &SharedTopologySnapshot,
    storage: &Arc<S>,
    via: ShardId,
    child: ShardId,
    anchor: ShardAnchor,
    imported_root: StateRoot,
) -> Result<(Block, ChainOrigin, StateRoot), String>
where
    S: ShardStorage,
    N: Network,
{
    let tail = Arc::new(Mutex::new(ObserverTail::new(anchor, child, imported_root)));
    loop {
        let pending = lock(&tail).take_apply();
        if let Some((height, receipts)) = pending {
            let root = storage
                .follow_block_writes(height, &receipts)
                .map_err(|e| format!("follow application failed: {e}"))?;
            lock(&tail).on_applied(root)?;
            continue;
        }
        let child_anchor = topology.load().boundary(child);
        if let Some(child_anchor) = child_anchor
            && lock(&tail).next_height() >= child_anchor.height
        {
            // Caught up through the parent's terminal block. The tail
            // retains no headers, so the terminal pair is fetched by
            // height — self-verifying: the coast header must certify
            // the terminal one and the derived genesis must reproduce
            // the beacon-anchored hash.
            let terminal_height = child_anchor
                .height
                .prev()
                .ok_or("child anchor at the absolute height floor")?;
            let terminal = fetch_followed_header(network, child, terminal_height).await;
            let coast = fetch_followed_header(network, child, child_anchor.height).await;
            let (genesis, origin) =
                split_genesis_from_terminal(child, &terminal, &coast, &child_anchor)?;
            let root = lock(&tail).root();
            info!(
                ?via,
                ?child,
                height = child_anchor.height.inner(),
                "Observer follow reached the parent's crossing"
            );
            return Ok((genesis, origin, root));
        }

        let target = if child_anchor.is_some() { child } else { via };
        let request = lock(&tail)
            .next_request()
            .expect("a tail with no pending application always wants a fetch");
        let outcome = Arc::new(Mutex::new(TailOutcome::NotYetAvailable));
        let sequencer = Arc::clone(&tail);
        let slot = Arc::clone(&outcome);
        let waiter = send(network, target, request, move |result| {
            result.map_or_else(
                |_| {
                    lock(&sequencer).on_failure();
                    ResponseVerdict::Accept
                },
                |response| {
                    let outcome = lock(&sequencer).on_response(&response);
                    *lock(&slot) = outcome;
                    match outcome {
                        TailOutcome::Accepted | TailOutcome::NotYetAvailable => {
                            ResponseVerdict::Accept
                        }
                        TailOutcome::Rejected(_) => ResponseVerdict::Reject,
                    }
                },
            )
        });
        let _ = waiter.await;
        let outcome = *lock(&outcome);
        match outcome {
            TailOutcome::Accepted => {}
            TailOutcome::NotYetAvailable => sleep(FOLLOW_PAUSE).await,
            TailOutcome::Rejected(reason) => {
                debug!(?via, ?child, reason, "Follow response rejected");
                sleep(FOLLOW_PAUSE).await;
            }
        }
    }
}

/// Fetch one committed header of the followed chain by height from
/// `shard`'s committee, retrying until a peer serves it. Headers ride
/// inline on every block response; the caller's derivation
/// self-verifies the pair, so no body rehydration is needed.
async fn fetch_followed_header<N: Network>(
    network: &Arc<N>,
    shard: ShardId,
    height: BlockHeight,
) -> BlockHeader {
    loop {
        let slot: Arc<Mutex<Option<BlockHeader>>> = Arc::new(Mutex::new(None));
        let out = Arc::clone(&slot);
        let waiter = send(
            network,
            shard,
            GetBlockRequest::new(height, height),
            move |result| {
                if let Ok(response) = result
                    && let Some(elided) = &response.certified
                {
                    *lock(&out) = Some(elided.header().clone());
                }
                ResponseVerdict::Accept
            },
        );
        let _ = waiter.await;
        let fetched = lock(&slot).take();
        if let Some(header) = fetched {
            return header;
        }
        sleep(FOLLOW_PAUSE).await;
    }
}

/// Dispatch one round of an observer's state-range requests and await
/// every response callback. Returns how many responses the sequencer
/// accepted.
async fn run_observer_round<N: Network>(
    network: &Arc<N>,
    via: ShardId,
    bootstrap: &Arc<Mutex<ObserverBootstrap>>,
    requests: Vec<BootstrapRequest>,
) -> usize {
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut waiters = Vec::with_capacity(requests.len());
    for request in requests {
        let BootstrapRequest::StateRange(id, request) = request else {
            unreachable!("observer bootstrap emits only state ranges");
        };
        let sequencer = Arc::clone(bootstrap);
        let accepted = Arc::clone(&accepted);
        waiters.push(send(network, via, request, move |result| {
            result.map_or_else(
                |_| {
                    lock(&sequencer).on_state_range_failure(id);
                    ResponseVerdict::Accept
                },
                |response| {
                    judge(
                        &lock(&sequencer).on_state_range(id, &response),
                        &accepted,
                        via,
                    )
                },
            )
        }));
    }
    for waiter in waiters {
        let _ = waiter.await;
    }
    accepted.load(Ordering::Relaxed)
}

/// Dispatch one round of requests and await every response callback.
/// Returns how many responses the sequencer accepted.
async fn run_round<N: Network>(
    network: &Arc<N>,
    shard: ShardId,
    bootstrap: &Arc<Mutex<ShardBootstrap>>,
    requests: Vec<BootstrapRequest>,
) -> usize {
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut waiters = Vec::with_capacity(requests.len());
    for request in requests {
        let sequencer = Arc::clone(bootstrap);
        let accepted = Arc::clone(&accepted);
        let waiter = match request {
            BootstrapRequest::StateRange(id, request) => {
                send(network, shard, request, move |result| {
                    result.map_or_else(
                        |_| {
                            lock(&sequencer).on_state_range_failure(id);
                            // Verdict is ignored on the Err path — the
                            // network already recorded the failure.
                            ResponseVerdict::Accept
                        },
                        |response| {
                            judge(
                                &lock(&sequencer).on_state_range(id, &response),
                                &accepted,
                                shard,
                            )
                        },
                    )
                })
            }
            BootstrapRequest::WitnessHistory(request) => {
                send(network, shard, request, move |result| {
                    result.map_or_else(
                        |_| {
                            lock(&sequencer).on_witness_history_failure();
                            ResponseVerdict::Accept
                        },
                        |response| {
                            judge(
                                &lock(&sequencer).on_witness_history(&response),
                                &accepted,
                                shard,
                            )
                        },
                    )
                })
            }
        };
        waiters.push(waiter);
    }
    for waiter in waiters {
        let _ = waiter.await;
    }
    accepted.load(Ordering::Relaxed)
}

/// Issue one request whose verdict `judge_response` decides; the
/// returned receiver resolves when the callback has run.
fn send<N: Network, R: Request + Clone + 'static>(
    network: &Arc<N>,
    shard: ShardId,
    request: R,
    judge_response: impl FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send + 'static,
) -> oneshot::Receiver<()> {
    let (done_tx, done_rx) = oneshot::channel();
    network.request(
        shard,
        None,
        request,
        None,
        Box::new(move |result| {
            let verdict = judge_response(result);
            let _ = done_tx.send(());
            verdict
        }),
    );
    done_rx
}

/// Translate a sequencer outcome into the peer verdict, counting
/// accepts for the round's progress tracking.
fn judge(outcome: &BootstrapOutcome, accepted: &AtomicUsize, shard: ShardId) -> ResponseVerdict {
    match outcome {
        BootstrapOutcome::Accepted => {
            accepted.fetch_add(1, Ordering::Relaxed);
            ResponseVerdict::Accept
        }
        BootstrapOutcome::Rejected(reason) => {
            debug!(?shard, reason, "Bootstrap response rejected");
            ResponseVerdict::Reject
        }
    }
}

fn lock<B>(bootstrap: &Mutex<B>) -> std::sync::MutexGuard<'_, B> {
    bootstrap.lock().expect("bootstrap mutex unpoisoned")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use arc_swap::ArcSwap;
    use hyperscale_network::{GossipHandler, NotificationHandler, RequestHandler};
    use hyperscale_node::{serve_state_range_request, serve_witness_history_request};
    use hyperscale_storage::test_helpers::pin_snap_sync_replica;
    use hyperscale_storage::{PendingChain, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::{GetStateRangeRequest, GetWitnessHistoryRequest};
    use hyperscale_types::{
        GossipMessage, MessageClass, NetworkDefinition, NetworkMessage, ShardAnchor,
        TopologySnapshot, ValidatorId, ValidatorSet,
    };
    use sbor::{basic_decode, basic_encode};

    use super::*;

    const ENTRIES: u8 = 12;

    /// A committed replica: `ENTRIES` substate blocks, then a boundary
    /// block whose header carries the (empty) witness commitment, pinned
    /// for serving.
    fn replica() -> (Arc<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let anchor = pin_snap_sync_replica(&storage, ENTRIES, &[]);
        (Arc::new(storage), anchor)
    }

    /// Serves bootstrap requests from `honest`, except the first
    /// `flaky_failures` requests which fail at the transport level.
    /// Requests are matched by `message_type_id` and round-tripped
    /// through SBOR to erase the generic.
    struct StubNetwork {
        honest: Arc<SimShardStorage>,
        pending_chain: PendingChain<SimShardStorage>,
        flaky_failures: AtomicUsize,
    }

    impl StubNetwork {
        fn new(storage: Arc<SimShardStorage>, flaky_failures: usize) -> Self {
            Self {
                honest: Arc::clone(&storage),
                pending_chain: PendingChain::new(storage),
                flaky_failures: AtomicUsize::new(flaky_failures),
            }
        }
    }

    impl Network for StubNetwork {
        fn request<R: Request + Clone + 'static>(
            &self,
            _shard: ShardId,
            _preferred_peer: Option<ValidatorId>,
            request: R,
            _class_override: Option<MessageClass>,
            on_response: Box<
                dyn FnOnce(Result<<R as Request>::Response, RequestError>) -> ResponseVerdict
                    + Send,
            >,
        ) {
            if self
                .flaky_failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                on_response(Err(RequestError::Timeout));
                return;
            }
            let encoded = basic_encode(&request).expect("request encodes");
            let response = match R::message_type_id() {
                "state_range.request" => {
                    let req: GetStateRangeRequest = basic_decode(&encoded).expect("decode");
                    basic_encode(&serve_state_range_request(&self.honest, &req)).expect("encode")
                }
                "witness_history.request" => {
                    let req: GetWitnessHistoryRequest = basic_decode(&encoded).expect("decode");
                    basic_encode(&serve_witness_history_request(&self.pending_chain, &req))
                        .expect("encode")
                }
                other => panic!("unexpected bootstrap request type {other}"),
            };
            on_response(Ok(basic_decode(&response).expect("response decodes")));
        }

        fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _shard: ShardId, _message: &M) {
            unimplemented!("bootstrap never gossips")
        }
        fn broadcast_global<M: GossipMessage + 'static>(&self, _message: &M) {
            unimplemented!("bootstrap never gossips")
        }
        fn register_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _handler: impl GossipHandler<M>,
        ) {
            unimplemented!("bootstrap registers no handlers")
        }
        fn register_request_handler<R: Request + Send + 'static>(
            &self,
            _shard: ShardId,
            _handler: impl RequestHandler<R>,
        ) {
            unimplemented!("bootstrap registers no handlers")
        }
        fn notify<M: NetworkMessage + 'static>(&self, _recipients: &[ValidatorId], _message: &M) {
            unimplemented!("bootstrap never notifies")
        }
        fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
            &self,
            _handler: impl NotificationHandler<M>,
        ) {
            unimplemented!("bootstrap registers no handlers")
        }
        fn subscribe_shard(&self, _shard: ShardId) {}
        fn unsubscribe_shard(&self, _shard: ShardId) {}
    }

    fn shared_topology(anchor: ShardAnchor, shard: ShardId) -> SharedTopologySnapshot {
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            HashMap::from([(shard, Vec::new())]),
            HashMap::new(),
            HashMap::from([(shard, anchor)]),
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        );
        Arc::new(ArcSwap::from_pointee(snapshot))
    }

    /// The observer pump end to end: both child spans import from the
    /// splitting shard's replica into child-rooted stores — healing
    /// transport failures on the way — and together they partition the
    /// parent's population at the anchor the assembly completed against.
    #[tokio::test]
    async fn observer_pump_imports_the_child_span() {
        use hyperscale_types::shard_prefix_path;

        let (serving, anchor) = replica();
        let via = ShardId::ROOT;
        let children: [ShardId; 2] = via.children().into();
        let network = Arc::new(StubNetwork::new(Arc::clone(&serving), 3));
        let topology = shared_topology(anchor, via);

        let mut total = 0u64;
        for child in children {
            let store: Arc<SimShardStorage> =
                Arc::new(SimShardStorage::new(shard_prefix_path(child)));
            let (used_anchor, root, count) =
                bootstrap_observer_state(&network, &topology, &store, via, child)
                    .await
                    .expect("observer bootstrap succeeds");
            assert_eq!(used_anchor, anchor);
            assert_eq!(store.state_root(), root);
            total += count;
        }
        assert_eq!(total, u64::from(ENTRIES));
    }

    /// The pump end to end over the sequencer: request dispatch with
    /// verdicts, the import write, and the seeded recovery — healing
    /// transport failures on the way.
    #[tokio::test]
    async fn pump_drives_the_sequencer_to_a_seeded_recovery() {
        let (serving, anchor) = replica();
        let shard = ShardId::ROOT;
        let network = Arc::new(StubNetwork::new(Arc::clone(&serving), 3));
        let topology = shared_topology(anchor, shard);
        let fresh: Arc<SimShardStorage> = Arc::new(SimShardStorage::default());

        let recovered = bootstrap_shard_state(&network, &topology, &fresh, shard)
            .await
            .expect("bootstrap succeeds");

        assert_eq!(recovered.committed_height, anchor.height);
        assert_eq!(recovered.committed_hash, Some(anchor.block_hash));
        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        assert!(recovered.beacon_witness_leaf_hashes.is_empty());
        // The imported store reproduces the attested root.
        assert_eq!(fresh.state_root(), anchor.state_root);
    }
}
