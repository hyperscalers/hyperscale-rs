//! Block-proposal helpers used by the BFT-driven dispatch arms.
//!
//! Both `ContentAvailable` and the QC-formed path build proposals from the
//! same triple — ready txs from mempool, finalized waves from execution,
//! queued provisions — so the gather logic lives once here.

use super::NodeStateMachine;
use hyperscale_core::Action;
use hyperscale_types::{FinalizedWave, Provisions, RoutableTransaction};
use std::sync::Arc;

/// Inputs gathered for building a block proposal.
pub(super) struct ProposalInputs {
    pub ready_txs: Vec<Arc<RoutableTransaction>>,
    pub finalized_waves: Vec<Arc<FinalizedWave>>,
    pub provisions: Vec<Arc<Provisions>>,
}

impl NodeStateMachine {
    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + abort intents + certificates gathering logic.
    pub(super) fn gather_proposal_inputs(
        &self,
        pending_txs: usize,
        pending_certs: usize,
    ) -> ProposalInputs {
        // Request extra transactions from the mempool to compensate for QC-chain
        // duplicates that will be filtered by BFT during proposal building.
        let max_txs = self.bft.config().max_transactions_per_block + self.bft.dedup_overhead();
        let ready_txs =
            self.mempool
                .ready_transactions(max_txs, pending_txs, pending_certs, self.now);
        let finalized_waves = self.execution.get_finalized_waves();
        let provisions = self.provisions.queued_provisions(self.now);

        ProposalInputs {
            ready_txs,
            finalized_waves,
            provisions,
        }
    }

    /// Shared proposal logic for `ContentAvailable` and QC-formed paths.
    pub(super) fn try_event_driven_proposal(&mut self) -> Vec<Action> {
        let (pending_txs, pending_certs) = self.bft.pending_block_counts();
        let inputs = self.gather_proposal_inputs(pending_txs, pending_certs);

        self.bft.try_propose(
            self.topology.snapshot(),
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }
}
