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
use hyperscale_types::{CertifiedBlock, CertifiedBlockHeader, Verified};

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
    /// 7. `apply_block_to_execution` runs wave cleanup + dispatch + vote
    ///    emission last, after mempool's terminal-state transitions.
    ///
    /// Finally the counterpart sweep, the terminal-chain sweep, and a
    /// proposal-retry latch (in-flight counts changed) for the post-dispatch hook
    /// to turn into one `try_event_driven_proposal`.
    pub(super) fn on_block_committed(
        &mut self,
        certified: &Verified<CertifiedBlock>,
    ) -> Vec<Action> {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        let block_hash = certified.block().hash();

        s.shard_coordinator
            .on_block_committed_verification(block_hash);

        actions.extend(s.mempool_coordinator.on_block_committed(
            self.beacon_coordinator.current_topology_snapshot(),
            certified,
        ));

        actions.extend(
            s.remote_headers_coordinator
                .on_block_committed(self.beacon_coordinator.topology_schedule(), certified),
        );

        actions.extend(s.provisions_coordinator.on_block_committed(certified));

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

        actions.extend(s.sweep_ready_counterpart_straddlers());

        // The first coast commit terminates the chain: finalization is a wave
        // certificate in a later block, and no later block will exist, so every
        // still-in-flight transaction is permanently undecidable here. Drive them
        // to their terminal abort and drop the execution state that was waiting
        // on them — once. Runs after the fan-out above so a final cert-carrying
        // block terminalizes its transactions through the normal path first.
        if !s.terminal_chain_swept
            && s.shard_coordinator
                .chain_terminated(self.beacon_coordinator.topology_schedule())
        {
            s.terminal_chain_swept = true;
            actions.extend(s.mempool_coordinator.abort_in_flight());
            actions.extend(s.execution_coordinator.abort_pending_waves());
        }

        s.shard_coordinator.queue_ready_proposal();

        actions
    }

    /// Fan a verified remote header to execution and provisions, then feed it to
    /// the beacon coordinator. Shard consensus already received the header in
    /// `RemoteHeaderQcVerified` (early insertion for deferral proof validation).
    pub(super) fn on_remote_header_admitted(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };

        s.execution_coordinator.on_verified_remote_header(
            shard,
            certified_header.header().height(),
            certified_header.header().waves(),
        );

        let mut actions = s
            .provisions_coordinator
            .on_verified_remote_header(certified_header);
        actions.extend(
            self.beacon_coordinator
                .on_verified_source_header(certified_header),
        );
        actions
    }
}
