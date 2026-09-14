//! Package artifact acquisition: the fetch that makes the beacon's
//! package registry locally runnable.
//!
//! Every beacon commit reconciles the global registry against what the
//! engine holds; anything missing is fetched from the shard owning its
//! publisher's prefix, verified by hashing the returned bytes, installed
//! into the engine, and persisted beside the beacon store so a restart
//! reconciles instead of refetching the world.
//!
//! Acquisition is pure prefetch and says nothing about what may execute:
//! a package's maturity window is what decides that, and it is a fact
//! about the beacon registry rather than about this node's holdings.

use std::collections::BTreeMap;
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::FetchIds;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::{Executor, artifact_package};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetPackageArtifactsRequest, MAX_PACKAGE_ARTIFACTS_PER_REQUEST,
};
use hyperscale_types::{Address, BeaconState, Hash, MessageClass, ShardId, ValidatorId};

use crate::config::NodeConfig;
use crate::fetch::{Fetch, FetchBinding, FetchInput, partition_solicited};
use crate::shard::{HostEvent, ShardIo, ShardLoop, ShardScopedInput, push_shard_input};

/// Per-package artifact fetch keyed by content address.
pub type PackageArtifactFetch = Fetch<Hash>;

/// The prefix a package's artifact is kept under: the cell's own owner,
/// which its content address derives. The shard holding that prefix is
/// the one obliged to answer for it.
fn custodian(package: Hash) -> Address {
    Executor::package_artifact_key(package).owner
}

/// Per-shard package-acquisition state: the artifact fetch instance.
pub struct PackagesState {
    pub(crate) fetch: PackageArtifactFetch,
}

impl PackagesState {
    pub fn new(config: &NodeConfig) -> Self {
        // The wire caps the batch far below the generic default: an
        // artifact runs to a transaction's whole byte budget.
        let mut fetch_config = config.package_artifact_fetch.clone();
        fetch_config.max_ids_per_request = fetch_config
            .max_ids_per_request
            .min(MAX_PACKAGE_ARTIFACTS_PER_REQUEST);
        Self {
            fetch: PackageArtifactFetch::new("package_artifact", fetch_config),
        }
    }

    /// Whether the artifact fetch has work the tick loop should drive.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.fetch.has_pending()
    }
}

/// Marker type for the package artifact fetch.
pub struct PackageArtifactBinding;

impl FetchBinding for PackageArtifactBinding {
    type Id = Hash;

    const NAME: &'static str = "package_artifact";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::PackageArtifacts(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Hash> {
        &mut shard.packages.fetch
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Hash>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        let es = sender.clone();
        let requested = ids.clone();
        network.request(
            shard,
            preferred,
            GetPackageArtifactsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    // Hashing the bytes is the whole verification: an
                    // artifact either is the one asked for or is dropped
                    // here, before anything installs it. The address
                    // travels on beside the bytes, so nothing downstream
                    // derives it a second time.
                    let addressed: Vec<(Hash, Vec<u8>)> = resp
                        .artifacts
                        .into_iter()
                        .map(|artifact| (artifact_package(&artifact), artifact))
                        .collect();
                    let split =
                        partition_solicited(addressed, &requested, |(package, _)| [*package]);
                    if !split.kept.is_empty() {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::PackageArtifactsFetched {
                                artifacts: split.kept,
                            },
                        );
                    }
                    if !split.missing.is_empty() {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFailed(Self::ids(split.missing.clone())),
                        );
                    }
                    if split.unsolicited > 0 || !split.missing.is_empty() {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::FetchFailed(Self::ids(requested)),
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Reconcile the beacon's package registry against what the engine
    /// holds, fetching anything missing from the shard obliged to keep
    /// it.
    ///
    /// Which shard that is follows from the content address alone: the
    /// artifact's cell sits under its own address, so a node asking for
    /// a package it can name needs nothing else to know who to ask.
    ///
    /// Runs on every beacon commit and tolerates arbitrary staleness:
    /// content addressing makes every enqueue idempotent, and a newly
    /// seated or restarted node catches the whole backlog on its first
    /// commit.
    pub(crate) fn reconcile_packages(&mut self, state: &BeaconState) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let snapshot = self.process.topology_snapshot.load();
        let mut by_shard: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
        for package in state.packages.keys() {
            if executor.needs_artifact(*package) {
                by_shard
                    .entry(snapshot.shard_trie().shard_for_prefix(custodian(*package)))
                    .or_default()
                    .push(*package);
            }
        }
        drop(snapshot);
        self.request_artifacts(by_shard);
    }

    /// Ask for the artifacts an envelope's derivation named and this
    /// node cannot resolve.
    ///
    /// The demand-driven half of the same acquisition the registry walk
    /// prefetches: a package reaches a node either because the chain
    /// registered it or because something asked to run it, and both ask
    /// the shard the content address picks.
    pub(crate) fn fetch_wanted_packages(&mut self, packages: Vec<Hash>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let snapshot = self.process.topology_snapshot.load();
        let mut by_shard: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
        for package in packages {
            if executor.needs_artifact(package) {
                by_shard
                    .entry(snapshot.shard_trie().shard_for_prefix(custodian(package)))
                    .or_default()
                    .push(package);
            }
        }
        drop(snapshot);
        self.request_artifacts(by_shard);
    }

    /// Drive one artifact fetch per shard asked.
    fn request_artifacts(&mut self, by_shard: BTreeMap<ShardId, Vec<Hash>>) {
        for (shard, ids) in by_shard {
            self.drive_fetch::<PackageArtifactBinding>(FetchInput::Request {
                ids,
                shard,
                preferred: None,
                class: None,
            });
        }
    }

    /// Install verified fetched artifacts: code into the engine, bytes
    /// into the node-level cache a restart reconciles from.
    ///
    /// Both halves run off the shard loop. Admitting an artifact means
    /// clearing the deterministic wasm profile and parsing every export
    /// it declares, and persisting it means a synchronous store write —
    /// per artifact, at a transaction's whole byte budget each. The loop
    /// this would otherwise run on drives vnode state machines and
    /// consensus timers, and nothing here is on the path of a verdict:
    /// the bytes were verified against their content address before this
    /// was ever posted, and the maturity window means no transaction
    /// naming the package can reach a tick for another two epochs.
    ///
    /// The engine is the node's, not the shard's, so a host carrying
    /// several shards can be handed one artifact once per shard that
    /// asked for it. Installing is idempotent either way; skipping what
    /// the engine already holds is what keeps the second copy from
    /// paying for a full re-validation of bytes already judged.
    pub(crate) fn handle_package_artifacts_fetched(&mut self, artifacts: Vec<(Hash, Vec<u8>)>) {
        let ids: Vec<Hash> = artifacts.iter().map(|(package, _)| *package).collect();
        let handles = Arc::clone(&self.process.dispatch_handles);
        let events = self.event_sender().clone();
        let shard = self.shard;
        let installed = ids.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                for (package, artifact) in artifacts {
                    if !handles.executor.needs_artifact(package) {
                        continue;
                    }
                    handles.executor.install_artifact(&artifact);
                    handles
                        .beacon_storage
                        .store_fetched_package(package, &artifact);
                }
                // From inside the install: an envelope waiting on this
                // package derives on the strength of this, and the
                // metadata has to be seated before that is true.
                push_shard_input(
                    &events,
                    shard,
                    ShardScopedInput::PackagesInstalled {
                        packages: installed,
                    },
                );
            });
        self.drive_fetch::<PackageArtifactBinding>(FetchInput::Admitted { ids });
    }

    /// Offer the envelopes that were waiting on `packages` again.
    ///
    /// Runs on the loop, like the record seating it mirrors: what
    /// follows is the re-admission, which has to see the cache the
    /// install just grew.
    pub(crate) fn handle_packages_installed(&mut self, packages: &[Hash]) {
        let arrived: Vec<Address> = packages.iter().copied().map(custodian).collect();
        self.release_deferred(&arrived);
    }
}
