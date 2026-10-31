//! Sync-flow handlers.
//!
//! When `BlockSyncComplete` fires we fan out across all three
//! coordinators in one pass: shard consensus exits sync mode and re-issues any
//! pending block fetches it had suppressed; remote-headers and
//! provisions flush their expected sets so we can immediately
//! participate in execution for blocks within the `MAX_FINALIZATION_DELAY` window.

use std::sync::Arc;

use hyperscale_core::{Action, FetchRequest};
use hyperscale_shard::SettledTxSet;
use hyperscale_types::network::response::ServedValue;
use hyperscale_types::{
    Anchor, BlockHash, BlockHeight, CertifiedBlock, CheckedStateProof, MerkleInclusionProof,
    QuorumCertificate, ShardId, SubstateKey, TopologySchedule, VerdictCells, Verified,
    derive_block_transactions,
};

use super::ShardParticipation;

impl ShardParticipation {
    /// A synced block is ready to apply: derive its transactions, then
    /// hand it to shard consensus.
    pub(in crate::replica) fn on_block_sync_ready_to_apply(
        &mut self,
        sched: &TopologySchedule,
        certified: Arc<CertifiedBlock>,
    ) -> Vec<Action> {
        derive_block_transactions(certified.block(), self.derivation.as_ref());
        self.shard_coordinator
            .on_sync_block_ready_to_apply(sched, Arc::unwrap_or_clone(certified))
    }

    /// Block sync finished fetching: exit shard consensus sync mode, and
    /// flush expected provisions and expected headers, all in one pass.
    pub(in crate::replica) fn on_block_sync_complete(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self.shard_coordinator.on_block_sync_complete(sched);
        actions.extend(
            self.remote_headers_coordinator
                .flush_expected_headers(sched),
        );
        actions.extend(self.provisions_coordinator.flush_expected_provisions());
        actions
    }

    /// Both halves resume from the same recovered tip: consensus from the
    /// frontier it stored, execution from the transactions that frontier
    /// still owes an outcome for. The replay's folds are handed off as a
    /// live commit's are, and the tip is settled once over the last of
    /// them, so the restarted voter refuses by the fold's owed ticks
    /// before its first live commit.
    pub(in crate::replica) fn on_committed_state_restored(
        &mut self,
        sched: &TopologySchedule,
        height: BlockHeight,
        hash: Option<BlockHash>,
        qc: Option<Verified<QuorumCertificate>>,
    ) -> Vec<Action> {
        let mut actions = self
            .shard_coordinator
            .on_committed_state_restored(height, hash, qc);
        self.shard_coordinator.latch_dissolution(sched);
        let effects = self
            .execution_coordinator
            .on_committed_state_restored(sched, self.derivation.as_ref());
        actions.extend(self.apply_commit_effects(effects));
        actions.extend(self.settle_tip(sched));
        actions
    }

    /// A state proof against a commit-proven header verified. A proof
    /// against the parent terminal this chain asks answers which markers
    /// it holds: record them and re-drive the proposal that was filtering
    /// them out; the votes that deferred for want of them re-drive off the
    /// fence's evidence. The execution coordinator reads its own probes
    /// off every proof and ignores keys it never asked.
    pub(in crate::replica) fn on_fetched_state_proof_verified(
        &mut self,
        proof: &CheckedStateProof,
        values: &[ServedValue],
    ) {
        let anchor = proof.anchor();
        if self.shard_coordinator.precut_terminal() == Some(anchor) {
            let presences: Vec<(SubstateKey, bool)> = proof
                .inclusions()
                .iter()
                .map(|&(key, inclusion)| (key, inclusion.is_present()))
                .collect();
            self.shard_coordinator
                .record_precut_proof(anchor, &presences);
        }
        self.execution_coordinator.on_proof_fetched(proof, values);
        self.shard_coordinator.queue_ready_proposal();
    }

    /// A proof for verdict questions verified: the execution coordinator
    /// holds what a hearing row here would take.
    pub(in crate::replica) fn on_fetched_verdict_proof_verified(
        &mut self,
        sched: &TopologySchedule,
        anchor: Anchor,
        questions: &[VerdictCells],
        proof: &MerkleInclusionProof,
    ) {
        self.execution_coordinator.on_verdict_proof_fetched(
            anchor,
            questions,
            proof,
            sched.windows(),
        );
        self.shard_coordinator.queue_ready_proposal();
    }

    /// Beacon advanced an epoch — replay any cross-shard artifacts buffered
    /// because their committee epoch wasn't yet in the schedule (remote headers,
    /// ECs, finalized txs), and re-derive the settled sets the fence still
    /// wants. Dispatched from the `BeaconBlockPersisted` arm, once the
    /// schedule it carries is held.
    pub(in crate::replica) fn on_beacon_block_persisted(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self
            .remote_headers_coordinator
            .on_beacon_block_persisted(sched);
        let effects = self.execution_coordinator.on_beacon_block_persisted(sched);
        actions.extend(self.apply_commit_effects(effects));
        actions.extend(self.shard_coordinator.on_beacon_block_persisted(sched));
        // Settled after the shard's own redrive, since a commit parked on
        // this window may have folded. Its proposal latch is also the
        // only retry a proposer whose committee lookup stalled on the
        // missing epoch has: without it the view-change timer fires
        // first, the height is re-proposed in a later round, and the
        // round-contiguous commit rule never sees the consecutive rounds
        // it needs.
        actions.extend(self.settle_tip(sched));
        actions
    }

    /// Ask the parent's terminal for the markers of the pre-cut
    /// transactions this right child is still holding a refusal over.
    ///
    /// One request carrying the complete outstanding set — the io side
    /// diffs it against what the fetch already holds under the terminal,
    /// so a key that drops out of the set here is what releases its slot.
    /// That is why nothing outstanding still sends a request: an empty set
    /// is how the last query retires.
    ///
    /// Once the rule retires the outstanding set is empty rather than
    /// unasked, so the last release still goes out; the terminal is
    /// dropped immediately after, which is what makes this the final pass.
    pub(in crate::replica) fn scan_precut_queries(&mut self) -> Vec<Action> {
        let Some(terminal) = self.shard_coordinator.precut_terminal() else {
            return Vec::new();
        };
        let live = self.shard_coordinator.precut_rule_live();
        let keys = if live {
            let cut = self.shard_coordinator.chain_origin().cut();
            let candidates = self.mempool_coordinator.pending_opening_before(cut);
            self.shard_coordinator
                .outstanding_precut_queries(candidates)
        } else {
            Vec::new()
        };
        if !live {
            self.shard_coordinator.retire_precut();
        }
        vec![Action::Fetch(FetchRequest::PrecutProofs {
            terminal,
            keys,
            preferred: None,
            class: None,
        })]
    }

    /// Record a past-terminal shard's settled set, which releases what
    /// the execution coordinator held for want of it; the votes that
    /// deferred re-drive off the fence's evidence.
    pub(in crate::replica) fn on_settled_txs_reconstructed(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        set: SettledTxSet,
    ) -> Vec<Action> {
        let actions = self
            .execution_coordinator
            .record_settled_txs(topology_schedule, shard, set);
        self.shard_coordinator.queue_ready_proposal();
        actions
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_core::{
        Action, BeaconFetchIds, FetchIds, FetchRequest, ProtocolEvent, StateMachine,
    };
    use hyperscale_hbor::Capped;
    use hyperscale_storage::{RecoveredState, ReplayWindow};
    use hyperscale_types::test_utils::{
        certify, make_live_block, naming_its_own, test_transaction,
    };
    use hyperscale_types::{
        Block, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, CertifiedBlock,
        CertifiedBlockHeader, ChainOrigin, Hash, LocalTimestamp, ProvisionTxRoot,
        QuorumCertificate, ShardId, ValidatorId, Verified, WeightedTimestamp,
    };

    use crate::assert_emits;
    use crate::replica::NodeStateMachine;
    use crate::replica::test_support::TestNode;

    /// `BlockSyncComplete` fans out to shard consensus, remote-headers, and
    /// provisions in one pass. The provisions flush is the most
    /// directly observable: when a verified remote header has seeded
    /// `expected_provisions`, the flush surfaces an
    /// `Action::Fetch(FetchRequest::Ask { ids: FetchIds::RemoteProvisions(..), .. })`. This
    /// test catches a regression where the provisions flush is
    /// dropped from the sync-complete arm.
    #[test]
    fn block_sync_complete_flushes_expected_provisions() {
        let TestNode { mut node, .. } = TestNode::builder().build();

        // Seed provisions.expected via a verified remote header whose
        // tick depends on local.
        let mut block = make_live_block(
            ShardId::leaf(1, 1),
            BlockHeight::new(5),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        if let Block::Live { ref mut header, .. } = block {
            *header = BlockHeader::new(BlockHeaderParts {
                shard_id: header.shard_id(),
                height: header.height(),
                parent_block_hash: header.parent_block_hash(),
                parent_qc: header.parent_qc().clone().into(),
                proposer: header.proposer(),
                timestamp: header.timestamp(),
                round: header.round(),
                is_fallback: header.is_fallback(),
                state_root: header.state_root(),
                body_root: header.body_root(),
                provision_tx_roots: Capped::new(std::collections::BTreeMap::from([(
                    ShardId::ROOT,
                    ProvisionTxRoot::from_raw(Hash::from_bytes(b"placeholder-tx-root")),
                )]))
                .expect("a map written out in a test"),
                txs_in_flight: header.txs_in_flight(),
                ..Default::default()
            });
        }
        let certified_header = Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            block.header().clone(),
            QuorumCertificate::genesis(
                ShardId::leaf(1, 1),
                ChainOrigin::root(WeightedTimestamp::ZERO),
            ),
        ));
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
            Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::RemoteProvisions(..),
                shard: source_shard,
                ..
            })
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

    fn replay_window(count: u64) -> (RecoveredState, BlockHash) {
        let mut blocks = Vec::new();
        let mut tip = BlockHash::ZERO;
        for height in 1..=count {
            let block = make_live_block(
                ShardId::ROOT,
                BlockHeight::new(height),
                height * 1_000,
                ValidatorId::new(0),
                vec![(test_transaction(u8::try_from(height).unwrap()))],
                vec![],
            );
            tip = block.hash();
            blocks.push(Verified::<CertifiedBlock>::from_persisted(naming_its_own(
                &certify(block, height * 1_000),
            )));
        }
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(count),
            replay: ReplayWindow {
                blocks,
                dispatch_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::ZERO),
            },
            ..RecoveredState::default()
        };
        (recovered, tip)
    }

    fn restore(node: &mut NodeStateMachine, height: u64, tip: BlockHash) -> Vec<Action> {
        node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::CommittedStateRestored {
                height: BlockHeight::new(height),
                hash: Some(tip),
                qc: None,
            },
        )
    }

    /// A replay feeds only the execution fold and the tip: none of the
    /// hooks the live commit stream feeds. The mempool marks a block's
    /// transactions committed off that stream, so a live commit of the
    /// same blocks reports each one and the replay reports none.
    #[test]
    fn a_replay_runs_no_liveness_hook() {
        let (recovered, tip) = replay_window(20);

        let TestNode { node: mut live, .. } = TestNode::new();
        let mut reported = 0;
        for certified in &recovered.replay.blocks {
            reported += live
                .handle(
                    LocalTimestamp::ZERO,
                    ProtocolEvent::BlockCommitted {
                        certified: Arc::new(certified.clone()),
                        committee_anchor: certified
                            .block()
                            .header()
                            .parent_qc()
                            .weighted_timestamp(),
                    },
                )
                .iter()
                .filter(|action| matches!(action, Action::EmitTransactionStatus { .. }))
                .count();
        }
        assert_eq!(
            reported, 20,
            "the live stream reports every committed transaction"
        );

        let TestNode { mut node, .. } = TestNode::builder().recovered(recovered).build();
        let actions = restore(&mut node, 20, tip);
        for action in &actions {
            assert!(
                !matches!(
                    action,
                    Action::EmitTransactionStatus { .. }
                        | Action::StartRemoteHeaderSync { .. }
                        | Action::Fetch(FetchRequest::Ask {
                            ids: FetchIds::Beacon(BeaconFetchIds::Witnesses(_)),
                            ..
                        })
                ),
                "a replay ran a live hook: {action:?}",
            );
        }
    }
}
