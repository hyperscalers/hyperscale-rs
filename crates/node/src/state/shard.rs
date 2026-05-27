//! Shard consensus dispatch arms and the multi-coordinator orchestrators that
//! sit alongside them.
//!
//! Routing arms forward to `ShardCoordinator`. The orchestrators that span
//! multiple coordinators live here too because each is fundamentally a
//! shard-consensus-flow response — the coordinators that get notified are the
//! downstream subscribers:
//!
//! - `on_block_header_received` validates in-flight before shard ingest;
//! - `on_qc_formed` gathers proposal inputs to feed `shard.on_qc_formed`;
//! - `on_block_committed` fans out to mempool, remote-headers, provisions,
//!   outbound-provisions, and execution in commit order;
//! - `RemoteHeaderAdmitted` fans verified headers to execution + provisions.
//!
//! # Orchestration ordering — `on_block_committed`
//!
//! The fanout sequence has load-bearing dependencies. Reordering will
//! silently break invariants the downstream coordinators rely on; the edges
//! are not enforced by the type system.
//!
//! Dedup-index registration is owned by
//! [`crate::coordinator::ShardCoordinator::record_block_committed`] (in the
//! `shard` crate) and runs synchronously when the shard coordinator internally commits the
//! block — earlier than this fanout. So mempool's tombstone-retention pass
//! in step 2 already sees the up-to-date `tx_retention` map.
//!
//! The order is, with the dependency edge that motivates each step:
//!
//! 1. `shard.on_block_committed_verification` — marks the block's JMT
//!    snapshot as a usable parent in `PendingChain`. Child state-root
//!    verifications in subsequent dispatches need this; if any are pending
//!    against this block as their parent, they unblock here. Must precede
//!    any path that may emit child verifications.
//! 2. `mempool.on_block_committed` — Pending → Committed → Completed
//!    transitions for `block.transactions` and `block.certificates`.
//!    Reads the shard coordinator's `dedup_index.tx_retention` (populated synchronously in
//!    `record_block_committed`) for tombstone retention bounds.
//! 3. `remote_headers.on_block_committed` — liveness updates and
//!    cross-shard timeout scheduling. Independent of the local coordinators
//!    above; ordered here so all "cross-shard" work runs before execution.
//! 4. `provisions.on_block_committed` — pruning + fallback timeouts. Reads
//!    provision hashes directly off the block (`Block::Live` carries them
//!    inline; `Block::Sealed` has none). Independent of mempool and
//!    remote-headers; sequenced before execution because execution may
//!    consume provisions queued here on the next proposal attempt.
//! 5. `outbound_provisions.on_block_committed(qc.weighted_timestamp())` —
//!    deterministic eviction sweep. Uses the shard consensus-authenticated weighted
//!    timestamp from the QC so every validator evicts identically. Must
//!    follow earlier steps because eviction reads the now-up-to-date
//!    provisions state.
//! 6. `apply_block_to_execution` — per-wave cleanup, wave dispatch (Live)
//!    or wave-assignment recording (Sealed), and vote emission. Last
//!    because (a) execution's wave-cleanup reads `block.certificates` after
//!    mempool has finished its terminal-state transitions, and (b) vote
//!    emission may produce actions whose ordering with respect to mempool
//!    state matters.
//!
//! Finally, the function latches a proposal-retry via
//! `shard.queue_ready_proposal()` — in-flight counts changed, so the next
//! proposer needs to re-evaluate. The post-dispatch drain in `mod.rs::handle`
//! invokes `try_event_driven_proposal` once.

use hyperscale_core::{Action, ProtocolEvent, TimerId};
use hyperscale_types::{
    BlockHash, BlockHeader, BlockManifest, CertifiedBlock, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISIONS_PER_BLOCK, MAX_TXS_PER_BLOCK, VerifiedQuorumCertificate,
};

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Dispatch a shard-category `ProtocolEvent`.
    #[allow(clippy::too_many_lines)] // single dispatch, one arm per shard variant
    pub(super) fn handle_shard(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::BlockHeaderReceived { header, manifest } => {
                self.on_block_header_received(&header, manifest)
            }
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.on_qc_formed(block_hash, &qc)
            }
            ProtocolEvent::RemoteHeaderReceived {
                committed_header,
                sender,
            } => {
                // Route through the centralized remote header coordinator.
                // Structural pre-checks happen there; downstream consumers
                // receive headers via `RemoteHeaderAdmitted`.
                let topology = &self.topology_snapshot;
                self.remote_headers_coordinator.on_remote_header_received(
                    topology,
                    committed_header,
                    sender,
                )
            }
            ProtocolEvent::BlockVoteReceived { vote } => self
                .shard_coordinator
                .on_block_vote(&self.topology_snapshot, vote),
            ProtocolEvent::ReadySignalReceived { signal } => {
                self.shard_coordinator
                    .on_ready_signal_received(&self.topology_snapshot, signal);
                Vec::new()
            }
            ProtocolEvent::BlockReadyToCommit {
                block_hash,
                qc,
                source,
            } => self.shard_coordinator.on_block_ready_to_commit(
                &self.topology_snapshot,
                block_hash,
                qc,
                source,
            ),
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => self.shard_coordinator.on_qc_result(
                &self.topology_snapshot,
                block_hash,
                qc,
                verified_votes,
            ),
            ProtocolEvent::QcSignatureVerified { block_hash, result } => self
                .shard_coordinator
                .on_qc_signature_verified(&self.topology_snapshot, block_hash, result),
            ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                committed_header,
                result,
            } => self
                .remote_headers_coordinator
                .on_remote_header_qc_verified(
                    &self.topology_snapshot,
                    shard,
                    height,
                    committed_header,
                    result,
                ),
            ProtocolEvent::RemoteHeaderAdmitted { committed_header } => {
                // Fan out the verified header to downstream consumers. Shard consensus
                // already received the header in `RemoteHeaderQcVerified`
                // (early insertion for deferral proof validation).
                let topology = &self.topology_snapshot;
                let shard = committed_header.shard_group_id();

                self.execution_coordinator.on_verified_remote_header(
                    topology,
                    shard,
                    committed_header.header().height(),
                    committed_header.header().waves(),
                );

                self.provisions_coordinator
                    .on_verified_remote_header(topology, &committed_header)
            }
            ProtocolEvent::BlockRootVerified {
                kind,
                block_hash,
                valid,
            } => self.shard_coordinator.on_block_root_verified(
                &self.topology_snapshot,
                kind,
                block_hash,
                valid,
            ),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                manifest,
                finalized_waves,
                provisions,
            } => self.shard_coordinator.on_proposal_built(
                &self.topology_snapshot,
                height,
                round,
                &block,
                block_hash,
                &manifest,
                finalized_waves,
                provisions,
            ),
            ProtocolEvent::BlockCommitted { certified } => self.on_block_committed(&certified),
            // `BlockPersisted` advances `last_persisted_height`, a fallback
            // gate for deferred state root verifications. Steady-state
            // unblocking happens on `BlockCommitted`; this still matters for
            // boot-time catch-up (freshly-booted node has persisted state
            // but an empty in-memory set, so child verifications of just-
            // persisted parents unblock here) and for auto-resume-from-sync.
            ProtocolEvent::BlockPersisted { height, .. } => {
                let mut actions = self
                    .shard_coordinator
                    .on_block_persisted(&self.topology_snapshot, height);
                // If shard consensus just resumed from sync, reschedule the cleanup timer.
                if !actions.is_empty() {
                    actions.push(Action::SetTimer {
                        id: TimerId::Cleanup,
                        duration: self.shard_coordinator.config().cleanup_interval,
                    });
                }
                actions
            }
            ProtocolEvent::FinalizedWavesAdmitted { waves } => self
                .shard_coordinator
                .on_finalized_waves_admitted(&self.topology_snapshot, &waves),
            _ => unreachable!("non-shard event routed to handle_shard"),
        }
    }

    /// Validate in-flight before letting shard ingest a received header.
    fn on_block_header_received(
        &mut self,
        header: &BlockHeader,
        manifest: BlockManifest,
    ) -> Vec<Action> {
        let total_tx_count = manifest.transaction_count();

        // Absolute per-block bound on manifest list lengths. Applied at every
        // height (not just the next-block in-flight check) so a Byzantine
        // proposer scheduled at a future height can't ship a header carrying
        // millions of fake hashes — `assemble_pending_block` would otherwise
        // populate `missing_transaction_hashes` and trigger a fetch storm.
        // The per-list cap matches the chain-wide in-flight limit; no honest
        // proposer can legitimately exceed it.
        if total_tx_count > MAX_TXS_PER_BLOCK
            || manifest.cert_ids().len() > MAX_FINALIZED_TX_PER_BLOCK
            || manifest.provision_hashes().len() > MAX_PROVISIONS_PER_BLOCK
        {
            tracing::warn!(
                block_hash = ?header.hash(),
                height = header.height().inner(),
                tx_hashes = total_tx_count,
                cert_ids = manifest.cert_ids().len(),
                provision_hashes = manifest.provision_hashes().len(),
                "Rejecting block: manifest list length exceeds per-block cap"
            );
            return vec![];
        }

        // Validate in-flight limits only for the next block after committed
        // height. For blocks further ahead, validators at different heights
        // see different in_flight() counts — checking would split votes and
        // trigger view changes.
        let committed_height = self.shard_coordinator.committed_height();
        let is_next_block = header.height() == committed_height + 1;

        if is_next_block
            && self
                .mempool_coordinator
                .would_exceed_in_flight(total_tx_count, manifest.cert_ids().len())
        {
            tracing::warn!(
                block_hash = ?header.hash(),
                height = header.height().inner(),
                "Rejecting block that would exceed in-flight limit"
            );
            return vec![];
        }

        self.shard_coordinator.on_block_header(
            &self.topology_snapshot,
            header,
            manifest,
            |h| self.mempool_coordinator.get_transaction(h),
            |id| self.execution_coordinator.get_finalized_wave(id),
            |h| self.provisions_coordinator.get_provisions_by_hash(*h),
        )
    }

    /// QC formed — may trigger immediate next proposal.
    fn on_qc_formed(
        &mut self,
        block_hash: BlockHash,
        qc: &VerifiedQuorumCertificate,
    ) -> Vec<Action> {
        // Count transactions and certificates in the block that will be
        // committed. Critical for in-flight limits: the `BlockCommitted`
        // event won't be processed until after we select transactions, so
        // we preemptively account for txs that will INCREASE in-flight (new
        // commits) and certificates that will DECREASE it (completions).
        let (pending_tx_count, pending_cert_count) =
            self.shard_coordinator.pending_commit_counts(qc);
        let inputs = self.gather_proposal_inputs(pending_tx_count, pending_cert_count);

        self.shard_coordinator.on_qc_formed(
            &self.topology_snapshot,
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }

    /// Block committed — notify all subsystems in commit order.
    fn on_block_committed(&mut self, certified: &CertifiedBlock) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_hash = certified.block().hash();

        // Mark this block as a usable parent for child state-root
        // verifications. By the time `BlockCommitted` fires, the block's JMT
        // snapshot is in `PendingChain` (populated either by a prior
        // `VerifyStateRoot` or by the inline `CommitBlockByQcOnly`
        // computation), so children verify against it without waiting on
        // RocksDB persistence.
        self.shard_coordinator
            .on_block_committed_verification(block_hash);

        // Mempool: marks Pending → Committed for `block.transactions`, then
        // drives each tx in `block.certificates` to its terminal state
        // (Completed + tombstone). Same behavior for consensus and sync
        // commit paths.
        actions.extend(
            self.mempool_coordinator
                .on_block_committed(&self.topology_snapshot, certified),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers_coordinator
                .on_block_committed(&self.topology_snapshot, certified),
        );

        // Provisions coordinator: prune + schedule fallback timeouts. Reads
        // provision hashes directly off the block — `Live` carries them
        // inline, `Sealed` has none (empty slice).
        actions.extend(self.provisions_coordinator.on_block_committed(certified));

        // Outbound provision safety sweep — runs on the shard consensus-authenticated
        // weighted timestamp so every validator evicts deterministically.
        self.outbound_provisions
            .on_block_committed(certified.qc().weighted_timestamp());

        actions.extend(self.apply_block_to_execution(certified));

        // In-flight counts changed — latch a proposal attempt so the next
        // proposer can include newly ready transactions.
        self.shard_coordinator.queue_ready_proposal();

        actions
    }

    /// Apply a committed block to execution: cert cleanup, wave setup +
    /// dispatch (Live) or wave-assignment recording only (Sealed), and
    /// vote emission. Provisions live inline on `Block::Live` — no separate
    /// argument needed.
    fn apply_block_to_execution(&mut self, certified: &CertifiedBlock) -> Vec<Action> {
        let mut actions = Vec::new();

        // Release execution's per-wave bookkeeping for wave certs included
        // in this block. Per-tx terminal state for the mempool is already
        // handled separately by `on_block_committed` reading
        // `block.certificates`.
        self.execution_coordinator
            .cleanup_committed_waves(certified.block().certificates());

        actions.extend(
            self.execution_coordinator
                .on_block_committed(&self.topology_snapshot, certified),
        );

        // Round voting: scan all incomplete waves and emit votes for
        // complete ones. Single path to execution voting — abort intents
        // have already been processed above (with override semantics), so
        // the accumulator state is deterministic at this height. All
        // validators at this height produce the same votes.
        actions.extend(
            self.execution_coordinator
                .emit_vote_actions(&self.topology_snapshot),
        );

        actions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
    use hyperscale_test_helpers::{certify, make_live_block};
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHeader, BlockHeight, BlockManifest,
        CommittedBlockHeader, Hash, LinkedCertifiedBlock, LocalTimestamp, MerkleInclusionProof,
        ProvisionEntry, Provisions, QuorumCertificate, RETENTION_HORIZON, Round, ShardGroupId,
        TransactionStatus, TxHash, ValidatorId, WaveId,
    };

    use super::super::test_support::TestNode;

    /// `RemoteHeaderAdmitted` must fan out to **both** execution and
    /// provisions: execution registers expected ECs from the header's
    /// wave list (only for waves whose `remote_shards` includes local);
    /// provisions records the verified header for cross-shard provision
    /// flows. Dropping either side leaves the shard blind to one half of
    /// cross-shard work.
    #[test]
    fn remote_header_admitted_fans_to_execution_and_provisions() {
        let TestNode { mut node, .. } = TestNode::builder().num_shards(2).build();

        // Wave on remote shard 1 listing local shard 0 as a dependency.
        let mut remote_shards = BTreeSet::new();
        remote_shards.insert(ShardGroupId::new(0));
        let wave = WaveId::new(ShardGroupId::new(1), BlockHeight::new(5), remote_shards);

        let mut block = make_live_block(
            ShardGroupId::new(1),
            BlockHeight::new(5),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        if let Block::Live { ref mut header, .. } = block {
            *header = BlockHeader::new(
                header.shard_group_id(),
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
            );
        }
        let committed_header = Arc::new(CommittedBlockHeader::new(
            block.header().clone(),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
        ));

        let pre_exec = node
            .execution_coordinator
            .memory_stats()
            .expected_exec_certs;
        let pre_prov = node.provisions_coordinator.verified_remote_header_count();

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::RemoteHeaderAdmitted { committed_header },
        );

        assert_eq!(
            node.execution_coordinator
                .memory_stats()
                .expected_exec_certs,
            pre_exec + 1,
            "execution must register the wave from the verified header as an expected EC",
        );
        assert_eq!(
            node.provisions_coordinator.verified_remote_header_count(),
            pre_prov + 1,
            "provisions must record the verified remote header",
        );
    }

    /// `TransactionsAdmitted` latches a proposal-retry via
    /// `shard.queue_ready_proposal()`; the post-dispatch hook in
    /// `mod.rs::handle` calls `try_event_driven_proposal()` when the
    /// latch fires. End-to-end: when the local validator is the
    /// round-0 proposer for height 1, this chain must surface a
    /// `BuildProposal` action. Without the latch (or without the
    /// post-dispatch hook), no proposal would emerge — and that
    /// regression is silent until liveness breaks.
    #[test]
    fn transactions_admitted_drives_proposal_through_post_dispatch_hook() {
        // proposer_for(h=1, r=0) = committee[(1+0) % 4] = committee[1]
        // = ValidatorId::new(1). Pick local_idx=1 to be the leader.
        let TestNode { mut node, .. } = TestNode::builder().local_idx(1).build();
        assert!(
            node.topology()
                .should_propose(BlockHeight::new(1), Round::INITIAL),
            "local must be the round-0 height-1 proposer for this test",
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionsAdmitted { txs: vec![] },
        );

        let saw_proposal = actions
            .iter()
            .any(|a| matches!(a, Action::BuildProposal { .. }));
        assert!(
            saw_proposal,
            "expected BuildProposal after TransactionsAdmitted on a leader; got {actions:?}",
        );
    }

    /// Counterpart: a non-leader still latches the retry, but the
    /// post-dispatch `try_propose` returns empty (the leader check
    /// short-circuits inside shard consensus). The latch fires regardless — the
    /// guard is at the proposer level, not the latch level.
    #[test]
    fn transactions_admitted_does_not_emit_proposal_on_non_leader() {
        // local_idx=0 → ValidatorId::new(0); committee[1] = ValidatorId::new(1)
        // is the proposer, so we are not.
        let TestNode { mut node, .. } = TestNode::new();
        assert!(
            !node
                .topology()
                .should_propose(BlockHeight::new(1), Round::INITIAL),
            "local must NOT be the round-0 height-1 proposer for this test",
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionsAdmitted { txs: vec![] },
        );

        let saw_proposal = actions
            .iter()
            .any(|a| matches!(a, Action::BuildProposal { .. }));
        assert!(
            !saw_proposal,
            "non-leader must not emit BuildProposal; got {actions:?}",
        );
    }

    /// `BlockPersisted` only re-arms the cleanup timer when shard consensus signals
    /// it just exited sync mode (non-empty action list). On a steady-
    /// state node, the post-persist call is a no-op and no `SetTimer`
    /// must be appended.
    #[test]
    fn block_persisted_does_not_reschedule_cleanup_timer_in_steady_state() {
        let TestNode { mut node, .. } = TestNode::new();

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BlockPersisted {
                height: BlockHeight::new(10),
            },
        );

        let cleanup_timer_set = actions.iter().any(|a| {
            matches!(
                a,
                Action::SetTimer {
                    id: TimerId::Cleanup,
                    ..
                }
            )
        });
        assert!(
            !cleanup_timer_set,
            "steady-state BlockPersisted must not duplicate the cleanup timer; got {actions:?}",
        );
    }

    /// The orchestrator's outbound-provisions sweep on `BlockCommitted` must
    /// run on `qc.weighted_timestamp()` — never on local clock. Every
    /// validator sees the same QC, so they evict in lockstep; if local
    /// clock leaks in, validators with skew evict at different commits
    /// and the outbound tracker forks across the network.
    ///
    /// Test pumps local clock far past the entry's deadline and commits a
    /// block whose `qc.weighted_timestamp()` is BELOW that deadline. The
    /// entry must survive — proves the sweep ignored the local clock. A
    /// second commit with `weighted_timestamp` past the deadline then
    /// confirms the eviction path itself works.
    #[test]
    fn block_committed_evicts_outbound_provisions_on_qc_weighted_timestamp_not_local_clock() {
        let TestNode { mut node, .. } = TestNode::builder().num_shards(2).build();

        // Register an outbound batch (local shard 0 → remote shard 1).
        // Deadline = self.now (ZERO) + RETENTION_HORIZON ≈ 5m24s.
        let provisions = Arc::new(Provisions::new(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(1),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"outbound-tx")),
                vec![],
                vec![],
                vec![],
            )],
        ));
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::OutboundProvisionBroadcast {
                provisions,
                target_shard: ShardGroupId::new(1),
            },
        );
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            1,
            "broadcast must register the outbound entry",
        );

        // Pump local clock WAY past the deadline. If the orchestrator
        // were using `self.now`, the next commit would evict.
        let retention_ms =
            u64::try_from(RETENTION_HORIZON.as_millis()).expect("RETENTION_HORIZON fits u64");
        let past_deadline_ms = retention_ms * 10;
        let past_deadline = LocalTimestamp::from_millis(past_deadline_ms);

        // Commit a block whose qc.weighted_timestamp() is BELOW the entry
        // deadline. The orchestrator passes this into the outbound sweep.
        let block = make_live_block(
            ShardGroupId::new(0),
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let certified = Arc::new(LinkedCertifiedBlock::new_unchecked(certify(
            block, /* weighted_timestamp_ms */ 1_000,
        )));
        let _ = node.handle(past_deadline, ProtocolEvent::BlockCommitted { certified });
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            1,
            "outbound entry must survive — qc.weighted_timestamp() is below the deadline, \
             local clock past it must not leak in",
        );

        // Commit a second block whose qc.weighted_timestamp() IS past the
        // deadline. Now the eviction path proper must fire.
        let block = make_live_block(
            ShardGroupId::new(0),
            BlockHeight::new(2),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let certified = Arc::new(LinkedCertifiedBlock::new_unchecked(certify(
            block,
            past_deadline_ms,
        )));
        let _ = node.handle(past_deadline, ProtocolEvent::BlockCommitted { certified });
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            0,
            "outbound entry must be evicted — qc.weighted_timestamp() now exceeds the deadline",
        );
    }

    /// Counterpart to the gate-fires test: when the manifest fits inside
    /// the in-flight cap, the orchestrator must let shard ingest the header
    /// and the pending-block count must reflect it. Catches the
    /// regression where the gate over-fires (e.g. flipped predicate,
    /// off-by-one bound) — symptom would be the same as the network
    /// silently dropping all incoming headers.
    #[test]
    fn block_header_received_admits_next_block_within_in_flight_cap() {
        // Default mempool cap is well above 1 tx; pair with a
        // single-tx manifest so the projection cleanly fits.
        let TestNode { mut node, .. } = TestNode::new();

        let manifest = BlockManifest::new(vec![TxHash::ZERO], vec![], vec![], vec![]);

        // proposer_for(h=1, r=0) = committee[(1+0) % 4] = ValidatorId::new(1).
        // the shard coordinator's header validation rejects on proposer mismatch, so the
        // header must name the actual round-0 height-1 leader to reach
        // the pending-blocks insert.
        let header = make_live_block(
            ShardGroupId::new(0),
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(1),
            vec![],
            vec![],
        )
        .header()
        .clone();

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BlockHeaderReceived {
                header: Arc::new(header),
                manifest,
            },
        );

        let (pending_blocks, _) = node.shard_coordinator().pending_block_counts();
        assert_eq!(
            pending_blocks, 1,
            "header within cap must reach shard consensus exactly once — pending_blocks should be 1",
        );
    }

    /// Step 2 of the `on_block_committed` orchestration ordering
    /// ([shard.rs module head]) hands the certified block to
    /// `mempool.on_block_committed`, which flips every entry in
    /// `block.transactions()` from `Pending` to `Committed(height)`.
    /// The edges of that ordering are not enforced by the type system —
    /// reordering or dropping the mempool fanout silently breaks status
    /// reporting and leaves locks untaken. This test pins the visible
    /// transition: admit a tx via gossip, commit a block carrying it,
    /// and assert the mempool entry is now `Committed(h)`.
    #[test]
    fn block_committed_flips_admitted_tx_to_committed_in_mempool() {
        let TestNode { mut node, .. } = TestNode::new();

        let tx = Arc::new(test_transaction(/* seed */ 1));
        let tx_hash = tx.hash();

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionValidated {
                tx: Arc::clone(&tx),
                submitted_locally: true,
            },
        );
        assert_eq!(
            node.mempool_coordinator().status(&tx_hash),
            Some(TransactionStatus::Pending),
            "tx must be admitted as Pending before commit",
        );

        let block = make_live_block(
            ShardGroupId::new(0),
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![tx],
            vec![],
        );
        let certified = Arc::new(LinkedCertifiedBlock::new_unchecked(certify(
            block, /* weighted_timestamp_ms */ 1_000,
        )));
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BlockCommitted { certified },
        );

        assert_eq!(
            node.mempool_coordinator().status(&tx_hash),
            Some(TransactionStatus::Committed(BlockHeight::new(1))),
            "on_block_committed must flip the included tx from Pending to Committed(1)",
        );
    }
}
