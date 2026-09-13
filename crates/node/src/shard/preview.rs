//! Answering what a transaction would do, without committing it.
//!
//! The one question a shard is asked that expects a reply. A preview
//! reads committed state and writes nothing: it takes no lock, enters no
//! mempool, and leaves the shard exactly as it found it — so it is
//! answered inline on the driver thread rather than dispatched, and the
//! asker's channel rides the question in.
//!
//! Committed state alone is also what makes it cheap to be correct
//! about. There is no tick in flight over the baseline it reads, so the
//! run needs no reservation and total locality covers every cell; and
//! the anchor is a height this shard already committed, so nothing here
//! depends on how far the beacon has folded on this particular node.
//!
//! What it cannot do is read a shard this node does not serve. That is
//! refused by name inside the report rather than guessed at — see
//! `Holds` in [`hyperscale_engine`] — which is the honest answer until a
//! fan-out stands behind this.

use std::iter::once;

use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{
    FetchedCells, Holds, PreviewGrants, PreviewInputs, PreviewReport, TickEnvironment,
};
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore};
use hyperscale_types::Transaction;

use super::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Run `tx` against this shard's committed state and answer on
    /// `reply`.
    ///
    /// A closed channel is not an error: the asker gave up first, and
    /// the report goes nowhere. Nothing else observed the run, so there
    /// is no state to unwind.
    pub(crate) fn handle_preview(
        &self,
        tx: &Transaction,
        grants: PreviewGrants,
        reply: &Sender<Box<PreviewReport>>,
    ) {
        let view = self.io.pending_chain.view_at_committed_tip();
        let at = self.io.storage.committed_height();
        let schedule = self.process.topology_schedule();
        let topology = schedule.head();
        // The tip's own QC timestamp, which is the nearest thing to the
        // clock a committing block would fix: a candidate has no
        // committing block, and this node's freshest committed reading
        // is what exists instead.
        let Some(tip) = self
            .io
            .pending_chain
            .certified_header(at)
            .map(|header| header.qc().weighted_timestamp())
        else {
            return;
        };
        let report = self.process.dispatch_handles.executor.preview(
            &view.snapshot(),
            tx,
            &PreviewInputs {
                prices: topology.prices(),
                clock: tip,
                env: TickEnvironment::governing(topology, schedule.windows()),
                // This shard's state and no other's. A declaration
                // reaching further is refused by name, which is what a
                // node with nothing fetching for it can say honestly.
                holds: Holds {
                    trie: topology.shard_trie().clone(),
                    shards: once(self.shard).collect(),
                    fetched: FetchedCells::default(),
                },
                grants,
            },
        );
        let _ = reply.send(Box::new(report));
    }
}
