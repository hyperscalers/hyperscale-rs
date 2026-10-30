//! Record and code acquisition: the fetch that lets a host resolve a
//! component whose seal it never committed and run code it never
//! published.
//!
//! What it fetches belongs to the host, not to any one loop on it: the
//! executor's registry, its package cache and the copies kept beside the
//! beacon store are one per process. So the host asks once, on the loop
//! every host runs whether or not it is seated, and each loop that wanted
//! an id is told when it arrives.
//!
//! A component's record is committed on the shard owning its own prefix
//! and a package's artifact under its content address, so what to ask
//! and whom follows from the name alone. Both answers verify themselves:
//! a component's address is the hash of its record, and a package's
//! content address the hash of its bytes, so a reply deriving anything
//! else is dropped at the response boundary. Discovery is demand-driven:
//! components have no registry and could not have one, so what a host
//! asks for is what a derivation or a commit just told it was missing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::{BeaconFetchIds, FetchIds};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::{Executor, artifact_package, instance_of_record};
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{GetInstanceRecordsRequest, GetPackageArtifactsRequest};
use hyperscale_types::network::response::{
    GetInstanceRecordsResponse, GetPackageArtifactsResponse,
};
use hyperscale_types::{Address, Hash, ShardId};

use super::interest::AskRoute;
use super::{Asked, Askers, BeaconLoop, Interest};
use crate::beacon::{BeaconFetchState, BeaconReply};
use crate::event::{BeaconOwner, BeaconScopedInput, HostEvent};
use crate::fetch::{
    Fetch, FetchBinding, FetchInput, FetchedBy, Route, Settles, SolicitedAnswer, dispatch_solicited,
};
use crate::shard::ShardScopedInput;

/// The prefix a package's artifact is kept under: the cell's own owner,
/// which its content address derives. The shard holding that prefix is
/// the one obliged to answer for it, and a wait on the package is indexed
/// by it.
pub fn custodian(package: Hash) -> Address {
    Executor::package_artifact_key(package).owner
}

/// Marker type for the instance record fetch.
pub struct InstanceRecordBinding;

impl FetchBinding for InstanceRecordBinding {
    type Id = Address;

    const NAME: &'static str = "instance_record";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::InstanceRecords(ids))
    }
}

impl FetchedBy<BeaconFetchState> for InstanceRecordBinding {
    fn fetch_mut(owner: &mut BeaconFetchState) -> &mut Fetch<Address> {
        &mut owner.instance_record
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Address>,
        route: Route,
        network: &N,
        reply: &BeaconReply,
    ) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// Re-deriving the address from the record is the whole verification: a
/// component's address is the hash of its record. Bytes deriving no
/// record answer for nothing asked, so a peer handing them over is
/// rejected like one answering with a record nobody asked for. The
/// address travels on beside the bytes, so nothing downstream derives it
/// again. The fetch stays in flight until the records are seated.
impl SolicitedAnswer for InstanceRecordBinding {
    type Request = GetInstanceRecordsRequest;
    type Item = (Option<Address>, Vec<u8>);
    type Input = BeaconScopedInput;
    const SETTLES: Settles = Settles::OnVerdict;

    fn request(ids: &[Address]) -> GetInstanceRecordsRequest {
        GetInstanceRecordsRequest::new(
            Capped::new(ids.to_vec()).expect("the fetch config clamps a chunk to the record cap"),
        )
    }

    fn items(response: GetInstanceRecordsResponse) -> Vec<Self::Item> {
        response
            .records
            .into_iter()
            .map(Bytes::into_inner)
            .map(|record| (instance_of_record(&record), record))
            .collect()
    }

    fn answers_for(
        (address, _): &(Option<Address>, Vec<u8>),
    ) -> impl IntoIterator<Item = Address> + use<> {
        *address
    }

    fn deliver(kept: Vec<Self::Item>) -> Vec<BeaconScopedInput> {
        vec![BeaconScopedInput::InstanceRecordsFetched {
            records: kept
                .into_iter()
                .filter_map(|(address, record)| Some((address?, record)))
                .collect(),
        }]
    }
}

/// Marker type for the package artifact fetch.
pub struct PackageArtifactBinding;

impl FetchBinding for PackageArtifactBinding {
    type Id = Hash;

    const NAME: &'static str = "package_artifact";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::PackageArtifacts(ids))
    }
}

impl FetchedBy<BeaconFetchState> for PackageArtifactBinding {
    fn fetch_mut(owner: &mut BeaconFetchState) -> &mut Fetch<Hash> {
        &mut owner.package_artifact
    }

    fn dispatch_chunk<N: Network>(ids: Vec<Hash>, route: Route, network: &N, reply: &BeaconReply) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// Hashing the bytes is the whole verification: an artifact either is the
/// one asked for or answers for nothing asked. The address travels on
/// beside the bytes, so nothing downstream derives it a second time. The
/// fetch stays in flight until the install reports.
impl SolicitedAnswer for PackageArtifactBinding {
    type Request = GetPackageArtifactsRequest;
    type Item = (Hash, Vec<u8>);
    type Input = BeaconScopedInput;
    const SETTLES: Settles = Settles::OnVerdict;

    fn request(ids: &[Hash]) -> GetPackageArtifactsRequest {
        GetPackageArtifactsRequest::new(
            Capped::new(ids.to_vec()).expect("the fetch config clamps a chunk to the artifact cap"),
        )
    }

    fn items(response: GetPackageArtifactsResponse) -> Vec<Self::Item> {
        response
            .artifacts
            .into_iter()
            .map(Bytes::into_inner)
            .map(|artifact| (artifact_package(&artifact), artifact))
            .collect()
    }

    fn answers_for((package, _): &(Hash, Vec<u8>)) -> impl IntoIterator<Item = Hash> + use<> {
        [*package]
    }

    fn deliver(artifacts: Vec<Self::Item>) -> Vec<BeaconScopedInput> {
        vec![BeaconScopedInput::PackageArtifactsFetched { artifacts }]
    }
}

impl Asked for InstanceRecordBinding {
    const ROUTE: AskRoute = AskRoute::ChainsOnly;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.records
    }
}

impl Asked for PackageArtifactBinding {
    const ROUTE: AskRoute = AskRoute::ChainsOnly;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.packages
    }
}

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// `owner` wants these records and this code.
    ///
    /// What derivation already reads here is answered at once, so an ask
    /// queued behind its own answer costs no round trip; the answer comes
    /// after the asks, since it can settle what `owner` holds and give up
    /// what it asked for. A package whose bytes this host holds and whose
    /// metadata it does not is neither asked for nor answered: fetching
    /// bytes already held seats nothing. Code a store this host serves
    /// holds is installed from there, since a store filled by an import
    /// or an adoption holds code the engine never saw, and a host alone on
    /// the custodian's committee has no peer to ask; the stores are read
    /// off the loop, and only what none holds is asked of a peer.
    pub(super) fn want_records(
        &mut self,
        owner: BeaconOwner,
        instances: Vec<Address>,
        packages: Vec<Hash>,
    ) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let snapshot = self.process.topology_snapshot.load();
        let mut arrived: Vec<Address> = Vec::new();
        let mut records: BTreeMap<ShardId, Vec<Address>> = BTreeMap::new();
        let instances: BTreeSet<Address> = instances.into_iter().collect();
        for instance in instances {
            if executor.instance_known(instance) {
                arrived.push(instance);
            } else {
                records
                    .entry(snapshot.shard_trie().shard_for_prefix(instance))
                    .or_default()
                    .push(instance);
            }
        }
        let mut from_stores: Vec<(Hash, Option<Vec<u8>>)> = Vec::new();
        let packages: BTreeSet<Hash> = packages.into_iter().collect();
        for package in packages {
            if !executor.needs_artifact(package) {
                if executor.package_known(package) {
                    arrived.push(custodian(package));
                }
                continue;
            }
            PackageArtifactBinding::askers(&mut self.interest)
                .entry(package)
                .or_default()
                .insert(owner);
            if self.installing.insert(package) {
                from_stores.push((package, None));
            }
        }
        drop(snapshot);
        for (shard, ids) in records {
            self.ask_for::<InstanceRecordBinding>(owner, ids, shard, None, None);
        }
        self.install_artifacts(from_stores);
        self.notify_arrived(owner, arrived);
    }

    /// Nothing `owner` holds waits on these any more.
    pub(super) fn abandon_records(
        &mut self,
        owner: BeaconOwner,
        instances: Vec<Address>,
        packages: Vec<Hash>,
    ) {
        if !instances.is_empty() {
            self.abandon_for::<InstanceRecordBinding>(owner, instances);
        }
        if !packages.is_empty() {
            self.abandon_for::<PackageArtifactBinding>(owner, packages);
        }
    }

    /// Keep verified fetched records on disk and seat them in the
    /// registry derivation reads, then tell every owner that asked.
    ///
    /// Kept before they are seated, and durably: a transaction this host
    /// routes on one of them can commit, and replaying that commit after
    /// a restart — or deriving it again after the bounded registry lets
    /// the record go — reads the record back from this copy. Nothing
    /// else would bring it back; a committed block is not re-admitted,
    /// and what it books is decided by the derivation its replay reaches.
    ///
    /// Runs on the loop rather than off it, unlike the artifact install
    /// beside it: a record is small, and what follows is the arrival that
    /// has to find the registry it grew.
    pub(super) fn on_instance_records_fetched(&mut self, records: Vec<(Address, Vec<u8>)>) {
        let handles = Arc::clone(&self.process.dispatch_handles);
        handles.beacon_storage.store_fetched_instances(&records);
        for (instance, record) in &records {
            handles.executor.install_instance(*instance, record);
        }
        let ids: Vec<Address> = records.into_iter().map(|(address, _)| address).collect();
        let askers = take_askers(&mut self.interest.records, &ids);
        self.drive_fetch::<InstanceRecordBinding>(FetchInput::Admitted { ids });
        for (owner, arrived) in askers {
            self.notify_arrived(owner, arrived);
        }
    }

    /// Install verified fetched artifacts. The fetch stays in flight
    /// until the install reports, so an ask in between joins it rather
    /// than asking again.
    pub(super) fn on_package_artifacts_fetched(&self, artifacts: Vec<(Hash, Vec<u8>)>) {
        self.install_artifacts(
            artifacts
                .into_iter()
                .map(|(package, artifact)| (package, Some(artifact)))
                .collect(),
        );
    }

    /// Install artifacts: code into the engine, bytes into the copy
    /// beside the beacon store a restart reconciles from, which outlives
    /// this host serving the store it may have read them from. Each comes
    /// with bytes already checked against its content address, or none,
    /// to be read from a store this host serves; one no store holds is
    /// reported unheld.
    ///
    /// All of it runs off the loop. Reading an artifact and persisting it
    /// are synchronous store reads and writes, and admitting one means
    /// clearing the deterministic wasm profile and parsing every export it
    /// declares — per artifact, at a transaction's whole byte budget each
    /// — while this loop drives the host's beacon participation and its
    /// timers.
    fn install_artifacts(&self, artifacts: Vec<(Hash, Option<Vec<u8>>)>) {
        if artifacts.is_empty() {
            return;
        }
        let handles = Arc::clone(&self.process.dispatch_handles);
        let reply = self.reply.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let hosted = handles.per_shard.load_full();
                let mut installed = Vec::with_capacity(artifacts.len());
                let mut unheld = Vec::new();
                for (package, artifact) in artifacts {
                    if !handles.executor.needs_artifact(package) {
                        installed.push(package);
                        continue;
                    }
                    let Some(artifact) = artifact.or_else(|| {
                        hosted
                            .values()
                            .find_map(|shard| shard.storage.package_artifact(package))
                    }) else {
                        unheld.push(package);
                        continue;
                    };
                    handles.executor.install_artifact(&artifact);
                    handles
                        .beacon_storage
                        .store_fetched_package(package, &artifact);
                    installed.push(package);
                }
                // From inside the install: an envelope waiting on this
                // package derives on the strength of this, and the
                // metadata has to be seated before that is true.
                reply.push(BeaconScopedInput::PackagesInstalled {
                    packages: installed,
                    unheld,
                });
            });
    }

    /// Retire the installed packages' fetch and tell every owner that
    /// asked, and ask a peer for what no store here held and someone
    /// still wants.
    pub(super) fn on_packages_installed(&mut self, packages: Vec<Hash>, unheld: Vec<Hash>) {
        for package in packages.iter().chain(&unheld) {
            self.installing.remove(package);
        }
        let snapshot = self.process.topology_snapshot.load();
        let mut asks: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
        for package in unheld {
            if self.interest.packages.contains_key(&package) {
                asks.entry(snapshot.shard_trie().shard_for_prefix(custodian(package)))
                    .or_default()
                    .push(package);
            }
        }
        drop(snapshot);
        for (shard, ids) in asks {
            self.drive_fetch::<PackageArtifactBinding>(FetchInput::Request {
                ids,
                shard,
                preferred: None,
                class: None,
            });
        }
        let askers = take_askers(&mut self.interest.packages, &packages);
        self.drive_fetch::<PackageArtifactBinding>(FetchInput::Admitted { ids: packages });
        for (owner, arrived) in askers {
            self.notify_arrived(owner, arrived.into_iter().map(custodian).collect());
        }
    }

    /// Point every pending record and code ask at the shard that owns its
    /// prefix now. A split or a merge moves that owner, and an ask left on
    /// a retired committee would retry against nobody until abandoned. A
    /// request already in flight keeps its route until it is answered or
    /// fails.
    pub(super) fn reroute_record_asks(&mut self) {
        let snapshot = self.process.topology_snapshot.load();
        let mut records: BTreeMap<ShardId, Vec<Address>> = BTreeMap::new();
        for &instance in self.fetches.instance_record.pending_ids() {
            records
                .entry(snapshot.shard_trie().shard_for_prefix(instance))
                .or_default()
                .push(instance);
        }
        let mut artifacts: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
        for &package in self.fetches.package_artifact.pending_ids() {
            artifacts
                .entry(snapshot.shard_trie().shard_for_prefix(custodian(package)))
                .or_default()
                .push(package);
        }
        drop(snapshot);
        for (shard, ids) in records {
            self.drive_fetch::<InstanceRecordBinding>(FetchInput::Request {
                ids,
                shard,
                preferred: None,
                class: None,
            });
        }
        for (shard, ids) in artifacts {
            self.drive_fetch::<PackageArtifactBinding>(FetchInput::Request {
                ids,
                shard,
                preferred: None,
                class: None,
            });
        }
    }

    /// Tell `owner` what it asked for now resolves: a chain's loop over
    /// its channel, unless it has closed since it asked, and this loop's
    /// own submissions in place.
    fn notify_arrived(&mut self, owner: BeaconOwner, arrived: Vec<Address>) {
        if arrived.is_empty() {
            return;
        }
        match owner {
            BeaconOwner::Chain(chain) => {
                if let Some((shard, sender)) = self.shard_senders.get(&chain) {
                    let _ = sender.send(HostEvent::shard(
                        *shard,
                        ShardScopedInput::RecordsArrived { arrived },
                    ));
                }
            }
            BeaconOwner::Submissions => self.release_submissions(&arrived),
            BeaconOwner::Fold | BeaconOwner::Participant(_) => {}
        }
    }
}

/// Remove `ids` from `askers`, returning what each owner had asked for
/// among them.
fn take_askers<Id: Ord + Clone>(
    askers: &mut Askers<Id>,
    ids: &[Id],
) -> BTreeMap<BeaconOwner, Vec<Id>> {
    let mut by_owner: BTreeMap<BeaconOwner, Vec<Id>> = BTreeMap::new();
    for id in ids {
        for owner in askers.remove(id).unwrap_or_default() {
            by_owner.entry(owner).or_default().push(id.clone());
        }
    }
    by_owner
}
