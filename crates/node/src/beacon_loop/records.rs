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
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{GetInstanceRecordsRequest, GetPackageArtifactsRequest};
use hyperscale_types::{Address, Hash, ShardId};

use super::{Asked, Askers, BeaconLoop, Interest};
use crate::beacon::{BeaconFetchState, BeaconReply};
use crate::event::{BeaconOwner, BeaconScopedInput, HostEvent};
use crate::fetch::{
    Fetch, FetchBinding, FetchInput, FetchReply, FetchedBy, Route, partition_solicited,
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
        let reply = reply.clone();
        let requested = ids.clone();
        route.request(
            network,
            GetInstanceRecordsRequest::new(
                Capped::new(ids).expect("the fetch config clamps a chunk to the record cap"),
            ),
            Box::new(move |result| {
                let resp = match result {
                    Ok(resp) => resp,
                    Err(error) => {
                        reply.failed(Self::ids(requested), &error);
                        return ResponseVerdict::Accept;
                    }
                };
                // Re-deriving the address from the record is the whole
                // verification: a component's address is the hash of its
                // record, so bytes deriving nothing are a lie and bytes
                // deriving anything else are dropped here, before the
                // registry sees them. The address travels on beside the
                // bytes, so nothing downstream derives it again.
                let mut underived = 0usize;
                let addressed: Vec<(Address, Vec<u8>)> = resp
                    .records
                    .into_iter()
                    .map(Bytes::into_inner)
                    .filter_map(|record| {
                        let address = instance_of_record(&record);
                        underived += usize::from(address.is_none());
                        address.map(|address| (address, record))
                    })
                    .collect();
                let split = partition_solicited(addressed, &requested, |(address, _)| [*address]);
                if !split.kept.is_empty() {
                    reply.push(BeaconScopedInput::InstanceRecordsFetched {
                        records: split.kept,
                    });
                }
                if !split.missing.is_empty() {
                    reply.refused(Self::ids(split.missing));
                }
                // A peer that does not hold a record says so by leaving
                // it out, and is asked again like any miss; one that
                // hands over bytes no record derives, or a record nobody
                // asked for, answered with something it made up.
                if split.unsolicited > 0 || underived > 0 {
                    ResponseVerdict::Reject
                } else {
                    ResponseVerdict::Accept
                }
            }),
        );
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
        let reply = reply.clone();
        let requested = ids.clone();
        route.request(
            network,
            GetPackageArtifactsRequest::new(
                Capped::new(ids).expect("the fetch config clamps a chunk to the artifact cap"),
            ),
            Box::new(move |result| {
                let resp = match result {
                    Ok(resp) => resp,
                    Err(error) => {
                        reply.failed(Self::ids(requested), &error);
                        return ResponseVerdict::Accept;
                    }
                };
                // Hashing the bytes is the whole verification: an
                // artifact either is the one asked for or is dropped
                // here, before anything installs it. The address
                // travels on beside the bytes, so nothing downstream
                // derives it a second time.
                let addressed: Vec<(Hash, Vec<u8>)> = resp
                    .artifacts
                    .into_iter()
                    .map(Bytes::into_inner)
                    .map(|artifact| (artifact_package(&artifact), artifact))
                    .collect();
                let split = partition_solicited(addressed, &requested, |(package, _)| [*package]);
                if !split.kept.is_empty() {
                    reply.push(BeaconScopedInput::PackageArtifactsFetched {
                        artifacts: split.kept,
                    });
                }
                if !split.missing.is_empty() {
                    reply.refused(Self::ids(split.missing));
                }
                if split.unsolicited > 0 {
                    ResponseVerdict::Reject
                } else {
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

impl Asked for InstanceRecordBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.records
    }
}

impl Asked for PackageArtifactBinding {
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
    /// queued behind its own answer costs no round trip. A package whose
    /// bytes this host holds and whose metadata it does not is neither
    /// asked for nor answered: fetching bytes already held seats nothing.
    /// Code a store this host serves holds is installed from there, since
    /// a store filled by an import or an adoption holds code the engine
    /// never saw, and a host alone on the custodian's committee has no
    /// peer to ask.
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
        let hosted = self.process.dispatch_handles.per_shard.load_full();
        let mut held: Vec<(Hash, Vec<u8>)> = Vec::new();
        let mut artifacts: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
        let packages: BTreeSet<Hash> = packages.into_iter().collect();
        for package in packages {
            if !executor.needs_artifact(package) {
                if executor.package_known(package) {
                    arrived.push(custodian(package));
                }
                continue;
            }
            if let Some(artifact) = hosted
                .values()
                .find_map(|handles| handles.storage.package_artifact(package))
            {
                PackageArtifactBinding::askers(&mut self.interest)
                    .entry(package)
                    .or_default()
                    .insert(owner);
                held.push((package, artifact));
            } else {
                artifacts
                    .entry(snapshot.shard_trie().shard_for_prefix(custodian(package)))
                    .or_default()
                    .push(package);
            }
        }
        drop(snapshot);
        self.notify_arrived(owner, arrived);
        for (shard, ids) in records {
            self.ask_for::<InstanceRecordBinding>(owner, ids, shard, None, None);
        }
        for (shard, ids) in artifacts {
            self.ask_for::<PackageArtifactBinding>(owner, ids, shard, None, None);
        }
        self.install_artifacts(held);
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
        self.install_artifacts(artifacts);
    }

    /// Install artifacts already checked against their content address:
    /// code into the engine, bytes into the copy beside the beacon store
    /// a restart reconciles from, which outlives this host serving the
    /// store it may have read them from.
    ///
    /// Both halves run off the loop. Admitting an artifact means clearing
    /// the deterministic wasm profile and parsing every export it
    /// declares, and persisting it means a synchronous store write — per
    /// artifact, at a transaction's whole byte budget each — while this
    /// loop drives the host's beacon participation and its timers.
    fn install_artifacts(&self, artifacts: Vec<(Hash, Vec<u8>)>) {
        if artifacts.is_empty() {
            return;
        }
        let installed: Vec<Hash> = artifacts.iter().map(|(package, _)| *package).collect();
        let handles = Arc::clone(&self.process.dispatch_handles);
        let reply = self.reply.clone();
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
                reply.push(BeaconScopedInput::PackagesInstalled {
                    packages: installed,
                });
            });
    }

    /// Retire the installed packages' fetch and tell every owner that
    /// asked.
    pub(super) fn on_packages_installed(&mut self, packages: Vec<Hash>) {
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

    /// Tell `owner` what it asked for now resolves. Only a chain's loop
    /// holds envelopes waiting on records; one that has closed since it
    /// asked is told nothing.
    fn notify_arrived(&self, owner: BeaconOwner, arrived: Vec<Address>) {
        if arrived.is_empty() {
            return;
        }
        let BeaconOwner::Chain(chain) = owner else {
            return;
        };
        if let Some((shard, sender)) = self.shard_senders.get(&chain) {
            let _ = sender.send(HostEvent::shard(
                *shard,
                ShardScopedInput::RecordsArrived { arrived },
            ));
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
