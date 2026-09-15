//! Instance record acquisition: the fetch that lets a node resolve a
//! component whose seal it never committed.
//!
//! A component's record is committed on the shard owning its own prefix,
//! so every other shard holds none of it — yet each has to resolve the
//! target to say what a transaction naming it declares. What closes the
//! gap is a fetch keyed by the component's address, verified by
//! re-deriving that address from the record's own contents, and seated
//! in the registry derivation reads.
//!
//! Discovery is demand-driven, unlike the artifact fetch beside it.
//! Packages reconcile against the beacon's registry, which lists every
//! one of them; components have no such registry and could not have one,
//! so what a node asks for is what a derivation just told it was
//! missing.

use std::collections::BTreeMap;
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::FetchIds;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::instance_of_record;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetInstanceRecordsRequest, MAX_INSTANCE_RECORDS_PER_REQUEST,
};
use hyperscale_types::{Address, Hash, LocalTimestamp, MessageClass, ShardId, TxHash, ValidatorId};

use crate::config::NodeConfig;
use crate::fetch::{Fetch, FetchBinding, FetchInput, partition_solicited};
use crate::shard::mempool::{DeferredOrigin, DeferredTransaction, Orphaned};
use crate::shard::packages::PackageArtifactBinding;
use crate::shard::{HostEvent, ShardIo, ShardLoop, ShardScopedInput, push_shard_input};

/// Per-component record fetch, keyed by the address the record derives.
pub type InstanceRecordFetch = Fetch<Address>;

/// Per-shard record-acquisition state: the record fetch instance.
pub struct InstancesState {
    pub(crate) fetch: InstanceRecordFetch,
}

impl InstancesState {
    pub(crate) fn new(config: &NodeConfig) -> Self {
        let mut fetch_config = config.instance_record_fetch.clone();
        fetch_config.max_ids_per_request = fetch_config
            .max_ids_per_request
            .min(MAX_INSTANCE_RECORDS_PER_REQUEST);
        Self {
            fetch: InstanceRecordFetch::new("instance_record", fetch_config),
        }
    }

    /// Whether the record fetch has work the tick loop should drive.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.fetch.has_pending()
    }
}

/// Marker type for the instance record fetch.
pub struct InstanceRecordBinding;

impl FetchBinding for InstanceRecordBinding {
    type Id = Address;

    const NAME: &'static str = "instance_record";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::InstanceRecords(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Address> {
        &mut shard.instances.fetch
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Address>,
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
            GetInstanceRecordsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    // Re-deriving the address from the record is the
                    // whole verification: a component's address is the
                    // hash of its record, so bytes deriving anything
                    // else are dropped here, before the registry sees
                    // them. The address travels on beside the bytes, so
                    // nothing downstream derives it again.
                    let addressed: Vec<(Address, Vec<u8>)> = resp
                        .records
                        .into_iter()
                        .filter_map(|record| {
                            instance_of_record(&record).map(|address| (address, record))
                        })
                        .collect();
                    let split =
                        partition_solicited(addressed, &requested, |(address, _)| [*address]);
                    if !split.kept.is_empty() {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::InstanceRecordsFetched {
                                records: split.kept,
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
    /// Hold `wanted` back and ask for what each envelope's derivation
    /// could not resolve: a component's record from the shard owning its
    /// prefix, a package's artifact from the shard obliged to keep it.
    ///
    /// The envelopes wait rather than being dropped because the gap is
    /// this node's, not theirs: every node that could propose one has
    /// the same gap, so dropping them all would leave the arriving
    /// record with nothing to admit.
    ///
    /// A record and the code it names are asked for in turn, not
    /// together: the record is what says which package a target runs, so
    /// what is missing behind one is only knowable once it lands. An
    /// envelope wanting both comes back here after the first arrival.
    pub(crate) fn defer_for_records(&mut self, wanted: Vec<DeferredTransaction>) {
        let mut evicted: Vec<TxHash> = Vec::new();
        let mut instances: Vec<Address> = Vec::new();
        let mut packages: Vec<Hash> = Vec::new();
        for deferred in wanted {
            for instance in &deferred.wanted.instances {
                if !instances.contains(instance) {
                    instances.push(*instance);
                }
            }
            for package in &deferred.wanted.packages {
                if !packages.contains(package) {
                    packages.push(*package);
                }
            }
            // Held under the same dedup guard a queued envelope is, so a
            // gossip echo of one that is waiting does not enqueue a
            // second copy behind it.
            self.io
                .mempool
                .pending_validation
                .insert(deferred.tx.hash());
            let (dropped, orphaned) = self.io.mempool.deferred_records.defer(deferred);
            evicted.extend(dropped);
            self.retire_orphaned(orphaned);
        }
        // An evicted envelope leaves the pipeline entirely: nothing will
        // offer it again unless it is gossiped or fetched afresh, and
        // that has to find the dedup guard clear.
        self.handle_transaction_validations_failed(&evicted);
        self.fetch_instance_records(instances);
        self.fetch_wanted_packages(packages);
    }

    /// Ask the shard owning each component's prefix for its record.
    ///
    /// Idempotent: a record is immutable once sealed and self-verifying
    /// on arrival, so asking twice costs a round trip and settles the
    /// same way.
    fn fetch_instance_records(&mut self, instances: Vec<Address>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let snapshot = self.process.topology_snapshot.load();
        let mut by_shard: BTreeMap<ShardId, Vec<Address>> = BTreeMap::new();
        for instance in instances {
            if executor.instance_known(instance) {
                continue;
            }
            by_shard
                .entry(snapshot.shard_trie().shard_for_prefix(instance))
                .or_default()
                .push(instance);
        }
        drop(snapshot);
        for (shard, ids) in by_shard {
            self.drive_fetch::<InstanceRecordBinding>(FetchInput::Request {
                ids,
                shard,
                preferred: None,
                class: None,
            });
        }
    }

    /// Seat verified fetched records in the registry derivation reads,
    /// then offer the envelopes that were waiting on them again.
    ///
    /// Seating runs on the loop rather than off it, unlike the artifact
    /// install beside it: a record is small, and what follows it here is
    /// the re-admission that has to see the registry it grew.
    pub(crate) fn handle_instance_records_fetched(&mut self, records: Vec<(Address, Vec<u8>)>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let ids: Vec<Address> = records.iter().map(|(address, _)| *address).collect();
        for (instance, record) in records {
            executor.install_instance(instance, &record);
        }
        self.drive_fetch::<InstanceRecordBinding>(FetchInput::Admitted { ids: ids.clone() });
        self.release_deferred(&ids);
    }

    /// Offer every envelope `arrived` releases back to the door it came
    /// in by.
    ///
    /// A record and a package release alike: each is named by an
    /// address, and what an envelope was waiting on says nothing about
    /// how it re-enters.
    pub(crate) fn release_deferred(&mut self, arrived: &[Address]) {
        let mut unplaced: Vec<TxHash> = Vec::new();
        for (tx, origin) in self.io.mempool.deferred_records.release(arrived) {
            match origin {
                DeferredOrigin::Validation => self.queue_validation(tx),
                // Back through the fan-out it never got: its source
                // shard, its passive co-hosts and its outbound gossip
                // are all decisions the routing it can now derive makes.
                DeferredOrigin::Submission => {
                    self.io.mempool.pending_validation.remove(&tx.hash());
                    if !self.process.submit_transaction(&tx) {
                        unplaced.push(tx.hash());
                    }
                }
            }
        }
        self.settle_deferred(&unplaced);
    }

    /// Retire the asks of the envelopes admission has answered for.
    ///
    /// The queue holds a re-offered envelope until this says what
    /// became of it: re-admission either holds it back again, naming
    /// what is still missing, or it leaves the node — and then the
    /// names only it wanted are owed to nobody.
    pub(crate) fn settle_deferred(&mut self, gone: &[TxHash]) {
        if gone.is_empty() || self.io.mempool.deferred_records.is_empty() {
            return;
        }
        let orphaned = self.io.mempool.deferred_records.settle(gone);
        self.retire_orphaned(orphaned);
    }

    /// Drop the envelopes whose validity window has closed while they
    /// waited, so a record that never arrives costs nothing standing.
    pub(crate) fn sweep_deferred_records(&mut self, now: LocalTimestamp) {
        if self.io.mempool.deferred_records.is_empty() {
            return;
        }
        let (expired, orphaned) = self
            .io
            .mempool
            .deferred_records
            .sweep_expired(now.as_millis());
        self.retire_orphaned(orphaned);
        self.handle_transaction_validations_failed(&expired);
    }

    /// Retire the asks nothing waits on any more.
    ///
    /// An envelope that leaves the queue takes its reasons with it, and
    /// an id no envelope names is one whose answer nobody would admit.
    /// The custodian may have none to give — an envelope naming a
    /// component that does not exist is one anyone can gossip — so
    /// without this the ask is re-dispatched every fetch tick for the
    /// life of the process.
    pub(crate) fn retire_orphaned(&mut self, orphaned: Orphaned) {
        if orphaned.is_empty() {
            return;
        }
        if !orphaned.instances.is_empty() {
            self.drive_fetch::<InstanceRecordBinding>(FetchInput::Abandoned {
                ids: orphaned.instances,
            });
        }
        if !orphaned.packages.is_empty() {
            self.drive_fetch::<PackageArtifactBinding>(FetchInput::Abandoned {
                ids: orphaned.packages,
            });
        }
    }
}
