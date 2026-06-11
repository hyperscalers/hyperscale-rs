//! Sync-flow dispatch arms.
//!
//! When `BlockSyncComplete` fires we fan out across all three
//! coordinators in one pass: shard consensus exits sync mode and re-issues any
//! pending block fetches it had suppressed; remote-headers and
//! provisions flush their expected sets so we can immediately
//! participate in execution for blocks within the `WAVE_TIMEOUT` window.

use hyperscale_core::{Action, ProtocolEvent};

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Dispatch a sync-category `ProtocolEvent`.
    pub(super) fn handle_sync(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::BlockSyncReadyToApply { certified } => {
                self.shard_coordinator.on_sync_block_ready_to_apply(
                    self.beacon_coordinator.topology_schedule(),
                    std::sync::Arc::unwrap_or_clone(certified),
                )
            }
            // BlockSync finished fetching: exit shard consensus sync mode + flush
            // expected provisions + flush expected headers, all in one
            // pass.
            ProtocolEvent::BlockSyncComplete { .. } => {
                let topo = self.beacon_coordinator.current_topology_snapshot();
                let mut actions = self
                    .shard_coordinator
                    .on_block_sync_complete(self.beacon_coordinator.topology_schedule());
                actions.extend(self.remote_headers_coordinator.flush_expected_headers(topo));
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
            _ => unreachable!("non-sync event routed to handle_sync"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_core::{Action, FetchRequest, ProtocolEvent, StateMachine};
    use hyperscale_test_helpers::make_live_block;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight,
        CertifiedBlockHeader, ChainOrigin, LocalTimestamp, QuorumCertificate, ShardId, ValidatorId,
        Verified, WaveId,
    };

    use super::super::test_support::TestNode;
    use crate::assert_emits;

    /// `BlockSyncComplete` fans out to shard consensus, remote-headers, and
    /// provisions in one pass. The provisions flush is the most
    /// directly observable: when a verified remote header has seeded
    /// `expected_provisions`, the flush surfaces an
    /// `Action::Fetch(FetchRequest::RemoteProvisions { .. })`. This
    /// test catches a regression where the provisions flush is
    /// dropped from the sync-complete arm.
    #[test]
    fn block_sync_complete_flushes_expected_provisions() {
        let TestNode { mut node, .. } = TestNode::builder().num_shards(2).build();

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
