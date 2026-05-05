//! Sync-flow dispatch arms.
//!
//! When `BlockSyncComplete` fires we fan out across all three
//! coordinators in one pass: BFT exits sync mode and re-issues any
//! pending block fetches it had suppressed; remote-headers and
//! provisions flush their expected sets so we can immediately
//! participate in execution for blocks within the `WAVE_TIMEOUT` window.

use hyperscale_core::{Action, ProtocolEvent};

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Dispatch a sync-category `ProtocolEvent`.
    pub(super) fn handle_sync(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::BlockSyncReadyToApply { certified } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), certified),
            // BlockSync finished fetching: exit BFT sync mode + flush
            // expected provisions + flush expected headers, all in one
            // pass.
            ProtocolEvent::BlockSyncComplete { .. } => {
                let topo = self.topology.snapshot();
                let mut actions = self.bft.on_block_sync_complete(topo);
                actions.extend(self.remote_headers.flush_expected_headers(topo));
                actions.extend(self.provisions.flush_expected_provisions(topo));
                actions
            }
            ProtocolEvent::CommittedStateRestored { height, hash, qc } => self
                .bft
                .on_committed_state_restored(self.topology.snapshot(), height, hash, qc),
            // Acknowledged but unused for now. Commit 4 wires
            // `RemoteHeaderCoordinator` to clear its per-shard "syncing"
            // flag here.
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
        Block, BlockHash, BlockHeight, CommittedBlockHeader, QuorumCertificate, ShardGroupId,
        ValidatorId, WaveId,
    };

    use super::super::test_support::TestNode;
    use crate::assert_emits;

    /// `BlockSyncComplete` fans out to BFT, remote-headers, and
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
        remote_shards.insert(ShardGroupId(0));
        let wave = WaveId::new(ShardGroupId(1), BlockHeight(5), remote_shards);
        let mut block = make_live_block(
            ShardGroupId(1),
            BlockHeight(5),
            /* timestamp_ms */ 1_000,
            ValidatorId(0),
            vec![],
            vec![],
        );
        if let Block::Live { ref mut header, .. } = block {
            header.waves = vec![wave];
        }
        let committed_header = Arc::new(CommittedBlockHeader::new(
            block.header().clone(),
            QuorumCertificate::genesis(ShardGroupId(0)),
        ));
        let _ = node.handle(ProtocolEvent::RemoteHeaderAdmitted { committed_header });

        // Now trigger sync-complete. The provisions flush must surface
        // a fetch request for the seeded expected entry.
        let actions = node.handle(ProtocolEvent::BlockSyncComplete {
            height: BlockHeight(5),
        });

        assert_emits!(
            actions,
            Action::Fetch(FetchRequest::RemoteProvisions { source_shard, .. })
                if *source_shard == ShardGroupId(1)
        );
    }

    /// `CommittedStateRestored` is the boot-time hand-off from `RocksDB`
    /// to the in-memory BFT state. The orchestrator routes it to
    /// `bft.on_committed_state_restored`, which restores
    /// `committed_height` so subsequent header validation and pending-
    /// block routing accept blocks at the correct tip. A regression
    /// that drops the routing leaves a freshly-booted node convinced
    /// it's still at genesis — silent until the first real header
    /// arrives and gets rejected as "below committed height".
    #[test]
    fn committed_state_restored_advances_bft_committed_height() {
        let TestNode { mut node, .. } = TestNode::new();
        assert_eq!(
            node.bft().committed_height(),
            BlockHeight(0),
            "fresh node must start at genesis",
        );

        let restored_height = BlockHeight(42);
        let _ = node.handle(ProtocolEvent::CommittedStateRestored {
            height: restored_height,
            hash: Some(BlockHash::ZERO),
            qc: None,
        });

        assert_eq!(
            node.bft().committed_height(),
            restored_height,
            "committed height must reflect the restored value",
        );
    }
}
