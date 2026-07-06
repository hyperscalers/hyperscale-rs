//! Sync-flow dispatch arms.
//!
//! When `BlockSyncComplete` fires we fan out across all three
//! coordinators in one pass: shard consensus exits sync mode and re-issues any
//! pending block fetches it had suppressed; remote-headers and
//! provisions flush their expected sets so we can immediately
//! participate in execution for blocks within the `WAVE_TIMEOUT` window.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_shard::SettledWaveSet;
use hyperscale_types::TopologySchedule;

use super::ShardParticipation;

impl ShardParticipation {
    /// Dispatch a sync-category `ProtocolEvent`.
    pub(in crate::state) fn handle_sync(
        &mut self,
        topology_schedule: &TopologySchedule,
        event: ProtocolEvent,
    ) -> Vec<Action> {
        match event {
            ProtocolEvent::BlockSyncReadyToApply { certified } => {
                self.shard_coordinator.on_sync_block_ready_to_apply(
                    topology_schedule,
                    std::sync::Arc::unwrap_or_clone(certified),
                )
            }
            // BlockSync finished fetching: exit shard consensus sync mode + flush
            // expected provisions + flush expected headers, all in one
            // pass.
            ProtocolEvent::BlockSyncComplete { .. } => {
                let mut actions = self
                    .shard_coordinator
                    .on_block_sync_complete(topology_schedule);
                actions.extend(
                    self.remote_headers_coordinator
                        .flush_expected_headers(topology_schedule),
                );
                actions.extend(self.provisions_coordinator.flush_expected_provisions());
                actions
            }
            ProtocolEvent::CommittedStateRestored { height, hash, qc } => self
                .shard_coordinator
                .on_committed_state_restored(height, hash, qc),
            // Remote-header catch-up finished. The coordinator keeps no
            // sync-mode state to reconcile on completion, so the event is
            // an acknowledged no-op.
            ProtocolEvent::RemoteHeaderSyncComplete { .. } => vec![],
            // A past-terminal shard's settled set is reconstructed: record
            // it for the split-boundary fence, then re-drive any votes
            // that deferred for want of it.
            ProtocolEvent::SettledWavesReconstructed {
                shard,
                waves,
                terminal_wt,
            } => {
                let set = SettledWaveSet { waves, terminal_wt };
                self.execution_coordinator
                    .record_settled_waves(shard, set.clone());
                self.shard_coordinator.record_settled_waves(shard, set);
                let mut actions = self
                    .shard_coordinator
                    .redrive_pending_votes(topology_schedule);
                actions.extend(
                    self.execution_coordinator
                        .redrive_gated_finalizations(topology_schedule),
                );
                // Settled certificates ingested before the set was
                // reconstructed leave the counterpart sweep immediately
                // ready: abort the straddlers the partner never settled.
                actions.extend(self.sweep_ready_counterpart_straddlers());
                actions
            }
            _ => unreachable!("non-sync event routed to handle_sync"),
        }
    }

    /// Beacon advanced an epoch — replay any cross-shard artifacts buffered
    /// because their committee epoch wasn't yet in the schedule (remote headers,
    /// ECs, finalized waves), then acquire any newly-attested settled-waves set
    /// the fence needs. Dispatched from `handle_beacon`'s `BeaconBlockPersisted`
    /// arm via the option guard, so a vnode that only follows the beacon no-ops.
    pub(in crate::state) fn on_beacon_block_persisted(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self
            .remote_headers_coordinator
            .on_beacon_block_persisted(sched);
        actions.extend(self.execution_coordinator.on_beacon_block_persisted(sched));
        actions.extend(self.shard_coordinator.on_beacon_block_persisted(sched));
        // A proposer whose committee lookup stalled on the missing epoch has no
        // other retry signal: without this kick the view-change timer fires
        // first, the height is re-proposed in a later round, and the
        // round-contiguous commit rule never sees the consecutive rounds it
        // needs. The post-dispatch hook turns the latch into one `try_propose`.
        self.shard_coordinator.queue_ready_proposal();
        actions.extend(self.scan_settled_waves_acquisitions(sched));
        actions
    }

    /// Start a one-shot settled-waves acquisition for every past-terminal shard
    /// whose beacon-attested `settled_waves_root` this node's own fold now
    /// carries and whose `S_P` the fence doesn't yet hold.
    ///
    /// Everything the acquisition needs comes from the node's beacon projection:
    /// the terminal block and attested root from the boundary anchor, the
    /// terminal weighted timestamp from the schedule's terminal cut, and the
    /// peers from the terminal-clamped routing committees. A shard already
    /// recorded (or live) is skipped, so the scan re-runs harmlessly each commit
    /// until the set is acquired.
    fn scan_settled_waves_acquisitions(&self, sched: &TopologySchedule) -> Vec<Action> {
        let head = sched.head();
        let mut actions = Vec::new();
        for (shard, peers) in sched.routing_committees() {
            if shard == self.local_shard {
                continue;
            }
            let Some(anchor) = head.boundary(shard) else {
                continue;
            };
            let Some(attested_root) = anchor.settled_waves_root else {
                continue;
            };
            if self.shard_coordinator.settled_set(shard).is_some() {
                continue;
            }
            let Some(terminal_wt) = sched.terminal_cut_wt(shard) else {
                continue;
            };
            actions.push(Action::StartSettledWavesAcquisition {
                shard,
                terminal_height: anchor.height,
                terminal_block_hash: anchor.block_hash,
                terminal_wt,
                attested_root,
                peers,
            });
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_core::{Action, FetchRequest, ProtocolEvent, StateMachine};
    use hyperscale_types::test_utils::make_live_block;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight,
        CertifiedBlockHeader, ChainOrigin, LocalTimestamp, QuorumCertificate, ShardId, ValidatorId,
        Verified, WaveId,
    };

    use crate::assert_emits;
    use crate::state::test_support::TestNode;

    /// `BlockSyncComplete` fans out to shard consensus, remote-headers, and
    /// provisions in one pass. The provisions flush is the most
    /// directly observable: when a verified remote header has seeded
    /// `expected_provisions`, the flush surfaces an
    /// `Action::Fetch(FetchRequest::RemoteProvisions { .. })`. This
    /// test catches a regression where the provisions flush is
    /// dropped from the sync-complete arm.
    #[test]
    fn block_sync_complete_flushes_expected_provisions() {
        let TestNode { mut node, .. } = TestNode::builder().build();

        // Seed provisions.expected via a verified remote header whose
        // wave depends on local.
        let mut remote_shards = BTreeSet::new();
        remote_shards.insert(ShardId::ROOT);
        let wave = WaveId::new(ShardId::leaf(1, 1), BlockHeight::new(5), remote_shards);
        let mut block = make_live_block(
            ShardId::leaf(1, 1),
            BlockHeight::new(5),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        if let Block::Live { ref mut header, .. } = block {
            *header = BlockHeader::new(
                header.shard_id(),
                header.height(),
                header.parent_block_hash(),
                header.parent_qc().clone(),
                header.proposer(),
                header.timestamp(),
                header.round(),
                header.is_fallback(),
                header.state_root(),
                header.transaction_root(),
                header.certificate_root(),
                header.local_receipt_root(),
                header.provision_root(),
                vec![wave],
                header.provision_tx_roots().clone().into_inner(),
                header.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            );
        }
        let certified_header =
            Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
                block.header().clone(),
                QuorumCertificate::genesis(ShardId::leaf(1, 1), ChainOrigin::ROOT),
            )));
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::RemoteHeaderAdmitted { certified_header },
        );

        // Now trigger sync-complete. The provisions flush must surface
        // a fetch request for the seeded expected entry.
        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BlockSyncComplete {
                height: BlockHeight::new(5),
            },
        );

        assert_emits!(
            actions,
            Action::Fetch(FetchRequest::RemoteProvisions { source_shard, .. })
                if *source_shard == ShardId::leaf(1, 1)
        );
    }

    /// `CommittedStateRestored` is the boot-time hand-off from `RocksDB`
    /// to the in-memory shard consensus state. The orchestrator routes it to
    /// `shard.on_committed_state_restored`, which restores
    /// `committed_height` so subsequent header validation and pending-
    /// block routing accept blocks at the correct tip. A regression
    /// that drops the routing leaves a freshly-booted node convinced
    /// it's still at genesis — silent until the first real header
    /// arrives and gets rejected as "below committed height".
    #[test]
    fn committed_state_restored_advances_shard_committed_height() {
        let TestNode { mut node, .. } = TestNode::new();
        assert_eq!(
            node.shard_coordinator().committed_height(),
            BlockHeight::new(0),
            "fresh node must start at genesis",
        );

        let restored_height = BlockHeight::new(42);
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::CommittedStateRestored {
                height: restored_height,
                hash: Some(BlockHash::ZERO),
                qc: None,
            },
        );

        assert_eq!(
            node.shard_coordinator().committed_height(),
            restored_height,
            "committed height must reflect the restored value",
        );
    }
}
