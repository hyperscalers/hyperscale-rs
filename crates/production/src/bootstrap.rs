//! Async pump for the sans-io shard bootstrap sequencer.
//!
//! [`ShardBootstrap`] owns the sequencing — state assembly, staged
//! import + anchor verification, witness history, recovery seeding.
//! This driver owns what the sequencer can't: dispatching its requests
//! through [`Network::request`] (verification verdicts feed the
//! peer-health tracker from inside the response callbacks), staging
//! each verified chunk and finalizing the import into the joiner's
//! store, wall-clock pacing between fruitless rounds, and re-reading
//! the anchor from the live topology when the state assembly starves
//! (serving peers may have evicted the boundary it targets). It never
//! gives up on its own; the join stands until the supervisor tears it
//! down.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_node::SharedTopologySnapshot;
use hyperscale_node::bootstrap::{
    BootstrapOutcome, BootstrapRequest, ShardBootstrap, StateRangeOutcome,
};
use hyperscale_storage::{RecoveredState, ShardStorage};
use hyperscale_types::{Request, ShardId};
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
    topology_snapshot: &SharedTopologySnapshot,
    storage: &Arc<S>,
    shard: ShardId,
) -> Result<RecoveredState, String>
where
    S: ShardStorage,
    N: Network,
{
    'anchor: loop {
        let Some(anchor) = topology_snapshot.load().boundary(shard) else {
            return Err(format!("shard {shard:?} has no attested anchor"));
        };
        // Resume a staged assembly an earlier process left behind when
        // its progress record binds the currently attested anchor and
        // fetch geometry; anything else is staged data proven against a
        // root this assembly no longer targets — wipe it and start
        // fresh. The anchor-refresh restart lands back here, where the
        // stale record fails the binding and is wiped the same way.
        let resumed = storage
            .read_import_progress()
            .and_then(|progress| ShardBootstrap::resume(shard, anchor, progress));
        let bootstrap = if let Some(bootstrap) = resumed {
            info!(
                ?shard,
                height = anchor.height.inner(),
                staged_bytes = bootstrap.imported_substate_bytes(),
                "Snap-sync bootstrap resuming a staged assembly against attested anchor"
            );
            bootstrap
        } else {
            info!(
                ?shard,
                height = anchor.height.inner(),
                "Snap-sync bootstrap starting against attested anchor"
            );
            storage
                .wipe_import_staging()
                .map_err(|error| format!("import staging wipe failed: {error}"))?;
            ShardBootstrap::new(shard, anchor)
        };
        let bootstrap = Arc::new(Mutex::new(bootstrap));
        let mut fruitless = 0u32;
        while !lock(&bootstrap).is_complete() {
            let finalize = lock(&bootstrap).take_finalize();
            if let Some((height, witnesses)) = finalize {
                let root = storage
                    .finalize_boundary_import(height, witnesses)
                    .map_err(|error| format!("boundary import failed: {error}"))?;
                lock(&bootstrap).on_imported(root)?;
                continue;
            }

            let requests = lock(&bootstrap).next_requests();
            let accepted = run_round(network, shard, storage, &bootstrap, requests).await?;
            if accepted == 0 {
                fruitless += 1;
                if fruitless >= ROUNDS_BEFORE_ANCHOR_REFRESH {
                    fruitless = 0;
                    // Restart is sound in either pre-finalize assembly —
                    // the store proper is untouched, and the staging
                    // area is wiped before the new assembly begins. The
                    // state ranges depend on peers still pinning the
                    // targeted boundary; the witness history binds to the
                    // anchor header, which peers may equally have pruned
                    // past.
                    if lock(&bootstrap).pre_finalize()
                        && topology_snapshot
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

/// Dispatch one round of requests and await every response callback,
/// staging each verified state chunk into `storage` from inside its
/// callback (under the sequencer lock, so chunk and progress writes
/// land in cursor order). Returns how many responses the sequencer
/// accepted.
///
/// # Errors
///
/// Returns a description when a staging write failed — the join cannot
/// make durable progress on this store.
async fn run_round<S: ShardStorage, N: Network>(
    network: &Arc<N>,
    shard: ShardId,
    storage: &Arc<S>,
    bootstrap: &Arc<Mutex<ShardBootstrap>>,
    requests: Vec<BootstrapRequest>,
) -> Result<usize, String> {
    let accepted = Arc::new(AtomicUsize::new(0));
    let stage_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut waiters = Vec::with_capacity(requests.len());
    for request in requests {
        let sequencer = Arc::clone(bootstrap);
        let accepted = Arc::clone(&accepted);
        let waiter = match request {
            BootstrapRequest::StateRange(id, request) => {
                let storage = Arc::clone(storage);
                let stage_error = Arc::clone(&stage_error);
                send(network, shard, request, move |result| {
                    result.map_or_else(
                        |_| {
                            lock(&sequencer).on_state_range_failure(id);
                            // Verdict is ignored on the Err path — the
                            // network already recorded the failure.
                            ResponseVerdict::Accept
                        },
                        |response| {
                            let mut sequencer = lock(&sequencer);
                            match sequencer.on_state_range(id, &response) {
                                StateRangeOutcome::Staged { leaves, progress } => {
                                    if let Err(error) =
                                        storage.stage_import_chunk(&progress, &leaves)
                                    {
                                        *lock(&stage_error) = Some(error);
                                    }
                                    accepted.fetch_add(1, Ordering::Relaxed);
                                    ResponseVerdict::Accept
                                }
                                StateRangeOutcome::Rejected(reason) => {
                                    debug!(?shard, reason, "Bootstrap response rejected");
                                    ResponseVerdict::Reject
                                }
                            }
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
    let stage_error = lock(&stage_error).take();
    if let Some(error) = stage_error {
        return Err(format!("staging write failed: {error}"));
    }
    Ok(accepted.load(Ordering::Relaxed))
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
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use arc_swap::ArcSwap;
    use hyperscale_network::{GossipHandler, NotificationHandler, RequestHandler};
    use hyperscale_node::{serve_state_range_request, serve_witness_history_request};
    use hyperscale_storage::test_helpers::{completed_import_progress, pin_snap_sync_replica};
    use hyperscale_storage::{BoundaryStore, ImportLeaf, PendingChain, SubstateStore};
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
        state_ranges_served: AtomicUsize,
    }

    impl StubNetwork {
        fn new(storage: Arc<SimShardStorage>, flaky_failures: usize) -> Self {
            Self {
                honest: Arc::clone(&storage),
                pending_chain: PendingChain::new(storage),
                flaky_failures: AtomicUsize::new(flaky_failures),
                state_ranges_served: AtomicUsize::new(0),
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
                    self.state_ranges_served.fetch_add(1, Ordering::Relaxed);
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
        fn register_host_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _handler: impl Fn(M) + Send + Sync + 'static,
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
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        Arc::new(ArcSwap::from_pointee(snapshot))
    }

    /// The pump end to end over the sequencer: request dispatch with
    /// verdicts, the import write, and the seeded recovery — healing
    /// transport failures on the way.
    #[tokio::test]
    async fn pump_drives_the_sequencer_to_a_seeded_recovery() {
        let (serving, anchor) = replica();
        let shard = ShardId::ROOT;
        let network = Arc::new(StubNetwork::new(Arc::clone(&serving), 3));
        let topology_snapshot = shared_topology(anchor, shard);
        let fresh: Arc<SimShardStorage> = Arc::new(SimShardStorage::default());

        let recovered = bootstrap_shard_state(&network, &topology_snapshot, &fresh, shard)
            .await
            .expect("bootstrap succeeds");

        assert_eq!(recovered.committed_height, anchor.height);
        assert_eq!(recovered.committed_hash, Some(anchor.block_hash));
        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        assert!(recovered.beacon_witness_leaf_hashes.is_empty());
        // The imported store reproduces the attested root.
        assert_eq!(fresh.state_root(), anchor.state_root);
    }

    /// The pump resumes a staged assembly a previous process left
    /// behind: finished sub-ranges are not refetched, and the finalize
    /// still reproduces the attested root.
    #[tokio::test]
    async fn pump_resumes_a_staged_assembly() {
        let (serving, anchor) = replica();
        let shard = ShardId::ROOT;
        let fresh: Arc<SimShardStorage> = Arc::new(SimShardStorage::default());

        // The "previous process": witness, then stage three sub-ranges
        // of the fan-out before dying.
        let pending_chain = PendingChain::new(Arc::clone(&serving));
        let mut first = ShardBootstrap::new(shard, anchor);
        let mut staged = 0usize;
        'outer: for _ in 0..1_000 {
            for request in first.next_requests() {
                match request {
                    BootstrapRequest::WitnessHistory(request) => {
                        let response = serve_witness_history_request(&pending_chain, &request);
                        first.on_witness_history(&response);
                    }
                    BootstrapRequest::StateRange(id, request) => {
                        if staged >= 3 {
                            break 'outer;
                        }
                        let response = serve_state_range_request(&serving, &request);
                        if let StateRangeOutcome::Staged { leaves, progress } =
                            first.on_state_range(id, &response)
                        {
                            fresh.stage_import_chunk(&progress, &leaves).unwrap();
                            staged += 1;
                        }
                    }
                }
            }
        }
        drop(first);
        assert!(fresh.read_import_progress().is_some());

        let network = Arc::new(StubNetwork::new(Arc::clone(&serving), 0));
        let topology_snapshot = shared_topology(anchor, shard);
        let recovered = bootstrap_shard_state(&network, &topology_snapshot, &fresh, shard)
            .await
            .expect("bootstrap succeeds");

        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        assert_eq!(fresh.state_root(), anchor.state_root);
        assert_eq!(fresh.read_import_progress(), None);
        // Only the unfinished sub-ranges were refetched.
        assert_eq!(network.state_ranges_served.load(Ordering::Relaxed), 16 - 3);
    }

    /// A progress record from a different anchor is wiped, not resumed:
    /// the join re-syncs from scratch and still verifies.
    #[tokio::test]
    async fn pump_wipes_a_mismatched_progress_record() {
        let (serving, anchor) = replica();
        let shard = ShardId::ROOT;
        let fresh: Arc<SimShardStorage> = Arc::new(SimShardStorage::default());

        // A stale attempt against a different anchor left a poisoned
        // chunk behind; its record binds neither this anchor's root nor
        // the fetch geometry.
        let poisoned = ImportLeaf {
            leaf_key: [0x42; 32],
            storage_key: vec![0x42; 40],
            value: vec![0xEE; 8],
        };
        fresh
            .stage_import_chunk(
                &completed_import_progress(anchor.height, 8),
                std::slice::from_ref(&poisoned),
            )
            .unwrap();

        let network = Arc::new(StubNetwork::new(Arc::clone(&serving), 0));
        let topology_snapshot = shared_topology(anchor, shard);
        let recovered = bootstrap_shard_state(&network, &topology_snapshot, &fresh, shard)
            .await
            .expect("bootstrap succeeds");

        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        // The wipe removed the poisoned chunk; the full fan-out ran.
        assert_eq!(fresh.state_root(), anchor.state_root);
        assert_eq!(network.state_ranges_served.load(Ordering::Relaxed), 16);
    }
}
