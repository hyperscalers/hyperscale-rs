//! Cross-coordinator orchestration: the flows that drive **both** the shard
//! half and the beacon coordinator from one event.
//!
//! These stay on [`NodeStateMachine`] rather than [`ShardParticipation`] because
//! they mutate `beacon_coordinator` — feeding it the local shard's committed
//! certified headers and advancing its committee anchor. Each destructures both
//! halves explicitly: the shard fields through `self.shard` and the beacon
//! coordinator through `self.beacon_coordinator`, disjoint field borrows the
//! borrow checker keeps separate.
//!
//! [`ShardParticipation`]: super::participation::ShardParticipation

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    Anchor, CertifiedBlock, CertifiedBlockHeader, Verified, derive_block_transactions,
};

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Block committed — notify all subsystems in commit order.
    ///
    /// The fanout sequence has load-bearing dependencies; reordering silently
    /// breaks invariants the downstream coordinators rely on:
    ///
    /// 1. `shard.on_block_committed_verification` marks the block's JMT snapshot
    ///    as a usable parent so pending child state-root verifications unblock.
    /// 2. `mempool.on_block_committed` drives `block.transactions` Pending →
    ///    Committed and `block.certificates` to their terminal state. Reads the
    ///    shard coordinator's `tx_retention` (populated synchronously in
    ///    `record_block_committed`) for tombstone retention.
    /// 3. `remote_headers.on_block_committed` updates liveness + cross-shard
    ///    timeouts. The schedule (not head) so the probe terminal-clamps a
    ///    drained reshape shard to the committee still serving it.
    /// 4. `provisions.on_block_committed` prunes + schedules fallback timeouts.
    /// 5. `outbound_provisions.on_block_committed` evicts on the consensus-
    ///    authenticated weighted timestamp so every validator evicts identically.
    /// 6. `beacon.on_local_block_committed` advances the committee anchor; the
    ///    local commit stream is the beacon's only source view of its own shard,
    ///    so `on_verified_source_header` feeds each certified header in.
    /// 7. `apply_block_to_execution` runs tick cleanup + dispatch + vote
    ///    emission last, after mempool's terminal-state transitions.
    ///
    /// Finally the terminal-chain sweep and a proposal-retry latch
    /// (in-flight counts changed) for the post-dispatch hook to turn into one
    /// `try_event_driven_proposal`.
    pub(super) fn on_block_committed(
        &mut self,
        certified: &Verified<CertifiedBlock>,
    ) -> Vec<Action> {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        let block_hash = certified.block().hash();
        derive_block_transactions(certified.block(), s.derivation.as_ref());

        s.shard_coordinator
            .on_block_committed_verification(block_hash);

        actions.extend(s.mempool_coordinator.on_block_committed(
            self.beacon_coordinator.current_topology_snapshot(),
            certified,
        ));
        // What the block's finalizations settle about the transactions
        // they name is the execution ledger's reading — a name that
        // decides nothing is a leg finalizing here, a deciding success
        // on a leg entry is the reclaim — taken before the same block
        // releases the entries below.
        let resolutions = s
            .execution_coordinator
            .resolutions_of(certified.block().certificates());
        actions.extend(s.mempool_coordinator.on_resolutions(&resolutions));
        // Committed bundles are engagement evidence: promote any parked
        // cross-shard transaction whose payer bundle just committed.
        // Covers the case where another proposer paired the bundle
        // before this node's provisions pipeline verified it.
        for bundle in certified.block().provisions() {
            s.mempool_coordinator.on_engagement_evidence(
                bundle.source_shard(),
                bundle.transactions().iter().map(|entry| entry.tx_hash),
            );
        }

        actions.extend(
            s.remote_headers_coordinator
                .on_block_committed(self.beacon_coordinator.topology_schedule(), certified),
        );

        actions.extend(
            s.provisions_coordinator
                .on_block_committed(self.beacon_coordinator.topology_schedule(), certified),
        );

        // Both take the block's own anchor and not a deadline clock's
        // running maximum ([`WeightedTimestamp::advanced_by_commit`]).
        // The eviction below has to be the same on every validator, and
        // the beacon's is a retention floor over topology windows: a
        // maximum there evicts a window the chain can still legitimately
        // be asked to verify against, on whichever node happens to have
        // seen the most history.
        s.outbound_provisions
            .on_block_committed(certified.block().header().parent_qc().weighted_timestamp());

        self.beacon_coordinator
            .on_local_block_committed(certified.block().header().parent_qc().weighted_timestamp());

        let certified_header = Arc::new(certified.certified_header());
        actions.extend(
            self.beacon_coordinator
                .on_verified_source_header(&certified_header),
        );

        actions.extend(
            s.apply_block_to_execution(self.beacon_coordinator.topology_schedule(), certified),
        );

        // The first coast commit quiesces the chain's content: finalization is a
        // finalization in a later block, and no later content block will
        // exist, so every still-in-flight transaction is permanently undecidable
        // here. Drive them to their terminal abort and drop the execution state
        // that was waiting on them — once. Keyed on quiescence, not dissolution:
        // the committee keeps coasting and serving past this point, but its
        // terminal block is the last that can decide a transaction. Runs after
        // the fan-out above so a final cert-carrying block terminalizes its
        // transactions through the normal path first.
        if !s.terminal_chain_swept
            && s.shard_coordinator
                .quiescent(self.beacon_coordinator.topology_schedule())
        {
            s.terminal_chain_swept = true;
            actions.extend(s.mempool_coordinator.abort_in_flight());
            actions.extend(s.execution_coordinator.abort_pending_ticks());
        }

        // Settlement order is judged over the execution fold, and only a
        // commit moves it — a member settles when a block carries the
        // half that settles it. Mirror the fold's answer into shard
        // consensus, where the proposer's selection and the vote path
        // both read it, so the two run one rule.
        s.shard_coordinator
            .set_owed_determined(s.execution_coordinator.owed_determined_ticks());

        s.shard_coordinator.queue_ready_proposal();

        // The fork-proof dedup fence clears once the attested recovery for
        // its shard completes — the coordinators self-clear their own
        // fences on the same edge, so a later re-fork can re-engage.
        if !s.fork_fence.is_empty() {
            let head = self.beacon_coordinator.topology_schedule().head();
            s.fork_fence.clear_completed(head.completed_recoveries());
        }

        actions
    }

    /// Fan a verified remote header to provisions, then feed it to the
    /// beacon coordinator. Shard consensus already received the header in
    /// `RemoteHeaderQcVerified` (early insertion for deferral proof validation).
    ///
    /// Admission arms expectations only — the header's exports (provisions,
    /// execution certificates) become consumable on `RemoteHeaderCommitted`,
    /// once its commit proof is held.
    pub(super) fn on_remote_header_admitted(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };

        let mut actions = s
            .provisions_coordinator
            .on_verified_remote_header(certified_header);
        actions.extend(
            self.beacon_coordinator
                .on_verified_source_header(certified_header),
        );
        actions
    }

    /// Fan a commit-proven remote header to the cross-shard consumers: the
    /// provisions coordinator opens the header for provision verification
    /// and drains bundles parked on it; the execution coordinator marks the
    /// source block proven and drains execution certificates deferred on the
    /// proof.
    pub(super) fn on_remote_header_committed(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let topology_schedule = self.beacon_coordinator.topology_schedule();
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };

        // The anchor lands first and in one place: the vote fence holds a
        // block's state proofs to what this validator has commit-proven,
        // and the certificate gate and the probe anchor read the same
        // mirror, so nothing downstream may run before it is in.
        s.shard_coordinator
            .record_proven_anchor(Anchor::of(certified_header));
        let mut actions = s
            .provisions_coordinator
            .on_committed_remote_header(topology_schedule, certified_header);
        actions.extend(
            s.execution_coordinator
                .on_committed_remote_header(topology_schedule, certified_header.shard_id()),
        );
        actions
    }
}
