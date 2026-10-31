//! The host's own submissions that wait on records.
//!
//! A submission names what it touches through components and code, and
//! a host that has not seen a seal derives no routing for an envelope
//! naming it. The gap is the host's, so the wait is the host's too: it is
//! held here, on the loop every host runs whether or not it is seated,
//! rather than on a shard loop that has nothing to do with the
//! transaction and may close while it waits. When what it named arrives,
//! it goes back through the fan-out it never got.

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{Address, Transaction};

use super::BeaconLoop;
use crate::event::BeaconOwner;
use crate::process::SubmitFanout;
use crate::shard::mempool::{DeferredTransaction, Orphaned};

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Hold `deferred` and ask for what it names.
    ///
    /// Derivation ran against a view that may be older than this step, so
    /// what it named may have landed since; [`Self::want_records`]
    /// answers that much at once, which offers the submission again,
    /// since no arrival is coming for it.
    pub(super) fn hold_submission(&mut self, deferred: DeferredTransaction) {
        let instances = deferred.wanted.instances.clone();
        let packages = deferred.wanted.packages.clone();
        // An evicted submission was reported submitted and goes no
        // further; nothing on this loop guards its hash.
        let (_, orphaned) = self.submissions.defer(deferred);
        self.retire_submission_asks(orphaned);
        self.want_records(BeaconOwner::Submissions, instances, packages);
    }

    /// Route every held submission `arrived` releases.
    ///
    /// A release that still derives no routing — a record that points at
    /// code this host lacks — is held again at once, under what it now
    /// names. Anything else is the fan-out's to carry out, and leaves the
    /// queue.
    pub(super) fn release_submissions(&mut self, arrived: &[Address]) {
        for tx in self.submissions.release(arrived) {
            self.route_submission(&tx);
        }
    }

    fn route_submission(&mut self, tx: &Transaction) {
        match self.process.compute_submit_fanout(tx) {
            SubmitFanout::WantsRecords { wanted } => {
                self.hold_submission(DeferredTransaction::new(tx.clone(), wanted));
            }
            fanout => {
                let _ = self.process.apply_submit_fanout(tx, fanout);
                let orphaned = self.submissions.settle(&[tx.hash()]);
                self.retire_submission_asks(orphaned);
            }
        }
    }

    /// Drop the held submissions whose validity window has closed.
    pub(super) fn sweep_submissions(&mut self) {
        if self.submissions.is_empty() {
            return;
        }
        let (_, orphaned) = self.submissions.sweep_expired(self.now.as_millis());
        self.retire_submission_asks(orphaned);
    }

    fn retire_submission_asks(&mut self, orphaned: Orphaned) {
        if orphaned.is_empty() {
            return;
        }
        self.abandon_records(
            BeaconOwner::Submissions,
            orphaned.instances,
            orphaned.packages,
        );
    }
}
