//! Waiting on records: the envelopes a loop holds back until the host
//! can resolve what they name.
//!
//! A component's record is committed on the shard owning its own prefix
//! and a package's artifact under its content address, so every other
//! shard holds neither — yet each has to resolve a target to say what a
//! transaction naming it declares, and run the code a committed block
//! names. The host fetches both once, on its beacon loop, because the
//! registry and the code it seats are the host's and not any one loop's.
//! This loop asks it for what its derivations and commits name, holds the
//! envelopes waiting, and offers them again when the beacon loop says
//! what arrived.

use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{Address, Hash, LocalTimestamp, Transaction, TxHash, Unresolved};

use crate::beacon_loop::custodian;
use crate::event::{BeaconInput, BeaconScopedInput, HostEvent};
use crate::shard::ShardLoop;
use crate::shard::mempool::{DeferredTransaction, Orphaned};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Hold `wanted` back and ask the host for what each envelope's
    /// derivation could not resolve.
    ///
    /// The envelopes wait rather than being dropped because the gap is
    /// this node's, not theirs: every node that could propose one has
    /// the same gap, so dropping them all would leave the arriving
    /// record with nothing to admit.
    ///
    /// Derivation ran off the loop against a view pinned before it, so
    /// what it named may have landed since. That much is offered again at
    /// once rather than asked for: no arrival is coming for it. The check
    /// is the question derivation asks of the same view, so an envelope
    /// offered again on it derives past that name.
    ///
    /// A record and the code it names are asked for in turn, not
    /// together: the record is what says which package a target runs, so
    /// what is missing behind one is only knowable once it lands. An
    /// envelope wanting both comes back here after the first arrival.
    pub(crate) fn defer_for_records(&mut self, wanted: Vec<DeferredTransaction>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let mut evicted: Vec<TxHash> = Vec::new();
        let mut instances: Vec<Address> = Vec::new();
        let mut packages: Vec<Hash> = Vec::new();
        let mut landed: Vec<Address> = Vec::new();
        for deferred in wanted {
            for &instance in &deferred.wanted.instances {
                if executor.instance_known(instance) {
                    landed.push(instance);
                } else if !instances.contains(&instance) {
                    instances.push(instance);
                }
            }
            for &package in &deferred.wanted.packages {
                if executor.package_known(package) {
                    landed.push(custodian(package));
                } else if !packages.contains(&package) {
                    packages.push(package);
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
        self.ask_host(instances, packages);
        if !landed.is_empty() {
            self.release_deferred(&landed);
        }
    }

    /// What a transaction this node could not route is waiting on, or
    /// `None` where nothing it waits on can be fetched — a refusal names
    /// no gap, and a transaction that routes fine has none.
    pub(crate) fn unrouted_wants(&self, tx: &Transaction) -> Option<Unresolved> {
        let derivation = self.process.dispatch_handles.executor.derivation();
        tx.try_derived(derivation.as_ref())
            .err()
            .and_then(|error| error.unresolved().cloned())
    }

    /// Ask the host for the records `instances` names that derivation
    /// does not read here.
    pub(crate) fn fetch_instance_records(&self, instances: Vec<Address>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let wanted: Vec<Address> = instances
            .into_iter()
            .filter(|&instance| !executor.instance_known(instance))
            .collect();
        self.ask_host(wanted, Vec::new());
    }

    /// Ask the host for the code `packages` names that this node holds no
    /// bytes of.
    ///
    /// A package reaches a node because something asked to run it: a
    /// transaction admitted, a block committed, a tick waiting on it.
    /// Filtered here, so the common transaction, whose code is long since
    /// installed, sends nothing off the loop.
    pub(crate) fn fetch_wanted_packages(&self, packages: Vec<Hash>) {
        let executor = Arc::clone(&self.process.dispatch_handles.executor);
        let wanted: Vec<Hash> = packages
            .into_iter()
            .filter(|&package| executor.needs_artifact(package))
            .collect();
        self.ask_host(Vec::new(), wanted);
    }

    /// Send the host's beacon loop an ask under this loop's registration.
    fn ask_host(&self, instances: Vec<Address>, packages: Vec<Hash>) {
        if instances.is_empty() && packages.is_empty() {
            return;
        }
        self.send_to_beacon(BeaconInput::RecordsWanted {
            instances,
            packages,
        });
    }

    fn send_to_beacon(&self, input: BeaconInput) {
        let _ =
            self.process
                .beacon_event_sender
                .send(HostEvent::Beacon(BeaconScopedInput::Shard {
                    chain: self.chain,
                    input,
                }));
    }

    /// Offer every envelope `arrived` releases back to validation,
    /// through the origin it first arrived from.
    ///
    /// A record and a package release alike: each is named by an
    /// address the wait is indexed by. Queued past the dedup guard,
    /// which the held envelope already holds.
    pub(crate) fn release_deferred(&mut self, arrived: &[Address]) {
        for (tx, origin) in self.io.mempool.deferred_records.release_offers(arrived) {
            self.queue_validation(tx, origin);
        }
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
    /// without this the host re-asks for it every fetch tick for the life
    /// of the process.
    pub(crate) fn retire_orphaned(&self, orphaned: Orphaned) {
        if orphaned.is_empty() {
            return;
        }
        self.send_to_beacon(BeaconInput::RecordsAbandoned {
            instances: orphaned.instances,
            packages: orphaned.packages,
        });
    }
}
