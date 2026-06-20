//! Block-proposal helpers used by the shard consensus-driven dispatch arms.
//!
//! Both the post-dispatch proposal-retry hook and the QC-formed path build
//! proposals from the same triple — ready txs from mempool, finalized waves
//! from execution, queued provisions — so the gather logic lives once here.

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    FinalizedWave, MAX_TXS_PER_BLOCK, Provisions, RoutableTransaction, TopologySchedule,
    Verifiable, Verified,
};

use super::ShardParticipation;

/// Inputs gathered for building a block proposal.
pub(in crate::state) struct ProposalInputs {
    pub ready_txs: Vec<Arc<Verified<RoutableTransaction>>>,
    pub finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
    pub provisions: Vec<Arc<Verifiable<Provisions>>>,
}

impl ShardParticipation {
    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + abort intents + certificates gathering logic.
    pub(in crate::state) fn gather_proposal_inputs(
        &self,
        sched: &TopologySchedule,
        pending_txs: usize,
        pending_certs: usize,
    ) -> ProposalInputs {
        // Request extra transactions from the mempool to compensate for QC-chain
        // duplicates that will be filtered by shard consensus during proposal building.
        let max_txs = MAX_TXS_PER_BLOCK + self.shard_coordinator.dedup_overhead();
        // Reshape-boundary quiesce: in a shard's final epoch before it
        // terminates at a split or merge, stop selecting transactions that
        // can't settle before the cut. `None` in steady state, so the
        // mempool filter is inert.
        let quiesce = self.shard_coordinator.quiesce_cut(sched);
        let ready_txs = self.mempool_coordinator.ready_transactions(
            max_txs,
            pending_txs,
            pending_certs,
            self.now,
            quiesce,
        );
        let finalized_waves = self.execution_coordinator.get_finalized_waves();
        // Provisions coordinator stores `Verified` internally; lift each
        // batch into the `Verifiable` transport shape so the marker
        // survives across the proposal-build action.
        let provisions = self
            .provisions_coordinator
            .queued_provisions(self.now)
            .into_iter()
            .map(|v| Arc::new((*v).clone().into()))
            .collect();

        ProposalInputs {
            ready_txs,
            finalized_waves,
            provisions,
        }
    }

    /// Shared proposal logic for the post-dispatch retry hook and the
    /// QC-formed path.
    pub(in crate::state) fn try_event_driven_proposal(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let (pending_txs, pending_certs) = self.shard_coordinator.pending_block_counts();
        let inputs = self.gather_proposal_inputs(sched, pending_txs, pending_certs);

        self.shard_coordinator.try_propose(
            sched,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }
}
