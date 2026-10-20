//! Block-proposal helpers used by the shard consensus-driven dispatch arms.
//!
//! Both the post-dispatch proposal-retry hook and the QC-formed path build
//! proposals from the same triple — ready txs from mempool, finalizations
//! from execution, queued provisions — so the gather logic lives once here.
//! The shard coordinator asks for that content through
//! [`ProposalSources::gather`], with the readings of the parent the block
//! extends.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_execution::{ExecutionCoordinator, Offers};
use hyperscale_mempool::MempoolCoordinator;
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_shard::{ProposalAsk, ProposalInputs, ShardCoordinator};
use hyperscale_types::{
    LocalTimestamp, MAX_TXS_PER_BLOCK, Provisions, ShardId, TopologySchedule, Transaction, TxHash,
    Verified,
};

use super::ShardParticipation;

/// The coordinators a proposal's content is read from, borrowed beside
/// the shard coordinator that asks for it.
pub(super) struct ProposalSources<'a> {
    now: LocalTimestamp,
    mempool: &'a MempoolCoordinator,
    execution: &'a ExecutionCoordinator,
    provisions: &'a ProvisionCoordinator,
}

impl ProposalSources<'_> {
    /// Gather all inputs needed for the block proposal `ask` is for.
    pub(super) fn gather(&self, ask: &ProposalAsk<'_>) -> ProposalInputs {
        let finalizations = self.execution.get_finalizations();
        // What departed counterparts left of this chain's business, while
        // the settled sets that say so can still be read, and the proofs
        // of counterparts' cells this validator's fetches answered, for
        // every replica to fold at commit, less what the chain from
        // execution's folded height to the parent carries: execution may
        // park a commit the shard has announced, so its own height is
        // the gate.
        let Offers {
            state_claims,
            verdict_claims,
            boundary_claims,
            abandonment_records,
            local_crossings,
        } = self
            .execution
            .offers(&ask.carried_above(self.execution.committed_height()));
        let queued = self.provisions.queued_provisions(self.now);

        // The engagement gate: a non-payer shard proposes a cross-shard
        // transaction only beside its payer bundle — this proposal's
        // own provisions — or after a committed block engaged it. The
        // bundle is the transaction commit proof (verified against a
        // commit-proven payer header), so locks engage only on committed
        // payer evidence; a mis-paired inclusion is backstopped by the
        // dispatch gate's required-set check.
        //
        // Read inside selection, so a transaction waiting on its payer
        // holds neither a place nor a share of the block's budget.
        //
        // Filled against the ask's intake: the trie, the standing rows,
        // the drain and the carried transactions of the parent the block
        // is built on. Admission judges every transaction at that same
        // parent and is the rule; the intake only decides what is offered
        // to it. The count is the wire cap, not the packing bound — a
        // block cannot encode more than this however light its
        // transactions are — and what decides how many are actually
        // offered is the drain's count and the block's caps inside
        // `ready_transactions`.
        let riding = Self::riding_this_proposal(&queued);
        let engaged = |tx: &Arc<Verified<Transaction>>| {
            ask.engagement_held(tx, |payer, tx_hash| riding.contains(&(payer, tx_hash)))
        };
        let ready_txs =
            self.mempool
                .ready_transactions(MAX_TXS_PER_BLOCK, &ask.intake, self.now, engaged);
        // What the pool and the queue withhold only for its dwell: the
        // pace timer wakes the leader for it when no other event will.
        let ready_at = self
            .mempool
            .next_ready_at(self.now, &ask.intake, engaged)
            .into_iter()
            .chain(self.provisions.next_eligible_at(self.now))
            .min();

        // Provisions coordinator stores `Verified` internally; lift each
        // batch into the `Verifiable` transport shape so the marker
        // survives across the proposal-build action.
        let provisions = queued
            .into_iter()
            .map(|v| Arc::new((*v).clone().into()))
            .collect();

        ProposalInputs {
            ready_txs,
            finalizations,
            provisions,
            abandonment_records,
            state_claims,
            verdict_claims,
            boundary_claims,
            local_crossings,
            ready_at,
        }
    }

    /// What the queued bundles name, as a set: `(payer shard, tx)` for
    /// every transaction whose evidence would ride this proposal.
    ///
    /// Indexed once rather than rescanned, because selection asks the
    /// question of every pending entry in the pool and the queue is
    /// bounded only by what commit prunes — a scan per ask would be the
    /// pool times the queue times each bundle's list, for a question
    /// each bundle can answer once.
    fn riding_this_proposal(queued: &[Arc<Verified<Provisions>>]) -> HashSet<(ShardId, TxHash)> {
        queued
            .iter()
            .flat_map(|bundle| {
                let source = bundle.source_shard();
                bundle
                    .transactions()
                    .iter()
                    .map(move |entry| (source, entry.tx_hash))
            })
            .collect()
    }
}

impl ShardParticipation {
    /// The shard coordinator, beside the sources it gathers a proposal's
    /// content from.
    pub(super) const fn proposer(&mut self) -> (&mut ShardCoordinator, ProposalSources<'_>) {
        (
            &mut self.shard_coordinator,
            ProposalSources {
                now: self.now,
                mempool: &self.mempool_coordinator,
                execution: &self.execution_coordinator,
                provisions: &self.provisions_coordinator,
            },
        )
    }

    /// The proposal attempt of the post-dispatch retry hook and the
    /// proposal pace timer.
    pub(in crate::state) fn try_event_driven_proposal(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let (coordinator, sources) = self.proposer();
        coordinator.try_propose(sched, |ask| sources.gather(ask))
    }
}
