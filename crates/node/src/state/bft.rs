//! BFT consensus dispatch arms and the multi-coordinator orchestrators that
//! sit alongside them.
//!
//! Routing arms forward to `BftCoordinator`. The orchestrators that span
//! multiple coordinators live here too because each is fundamentally a
//! BFT-flow response — the coordinators that get notified are the
//! downstream subscribers:
//!
//! - `on_block_header_received` validates in-flight before BFT ingest;
//! - `on_qc_formed` gathers proposal inputs to feed `bft.on_qc_formed`;
//! - `on_block_committed` fans out to mempool, remote-headers, provisions,
//!   outbound-provisions, and execution in commit order;
//! - `RemoteHeaderAdmitted` fans verified headers to execution + provisions.

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent, TimerId};
use hyperscale_types::{BlockHash, BlockHeader, BlockManifest, CertifiedBlock, QuorumCertificate};
use std::sync::Arc;

impl NodeStateMachine {
    /// Dispatch a BFT-category `ProtocolEvent`.
    #[allow(clippy::too_many_lines)] // single dispatch, one arm per BFT variant
    pub(super) fn handle_bft(&mut self, event: ProtocolEvent) -> Vec<Action> {
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
                let header = Arc::new(committed_header);
                let topology = self.topology.snapshot();
                self.remote_headers
                    .on_remote_header_received(topology, header, sender)
            }
            ProtocolEvent::BlockVoteReceived { vote } => {
                self.bft.on_block_vote(self.topology.snapshot(), vote)
            }
            ProtocolEvent::BlockReadyToCommit {
                block_hash,
                qc,
                source,
            } => {
                self.bft
                    .on_block_ready_to_commit(self.topology.snapshot(), block_hash, qc, source)
            }
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => self
                .bft
                .on_qc_result(self.topology.snapshot(), block_hash, qc, verified_votes),
            ProtocolEvent::QcSignatureVerified { block_hash, valid } => self
                .bft
                .on_qc_signature_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                header,
                valid,
            } => self.remote_headers.on_remote_header_qc_verified(
                self.topology.snapshot(),
                shard,
                height,
                header,
                valid,
            ),
            ProtocolEvent::RemoteHeaderAdmitted { committed_header } => {
                // Fan out the verified header to downstream consumers. BFT
                // already received the header in `RemoteHeaderQcVerified`
                // (early insertion for deferral proof validation).
                let topology = self.topology.snapshot();
                let shard = committed_header.shard_group_id();

                self.execution.on_verified_remote_header(
                    topology,
                    shard,
                    committed_header.header.height,
                    &committed_header.header.waves,
                );

                self.provisions
                    .on_verified_remote_header(topology, &committed_header)
            }
            ProtocolEvent::BlockRootVerified {
                kind,
                block_hash,
                valid,
            } => self
                .bft
                .on_block_root_verified(self.topology.snapshot(), kind, block_hash, valid),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                finalized_waves,
                provisions,
            } => self.bft.on_proposal_built(
                self.topology.snapshot(),
                height,
                round,
                &block,
                block_hash,
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
            ProtocolEvent::BlockPersisted { height } => {
                let mut actions = self
                    .bft
                    .on_block_persisted(self.topology.snapshot(), height);
                // If BFT just resumed from sync, reschedule the cleanup timer.
                if !actions.is_empty() {
                    actions.push(Action::SetTimer {
                        id: TimerId::Cleanup,
                        duration: self.bft.config().cleanup_interval,
                    });
                }
                actions
            }
            ProtocolEvent::FinalizedWavesAdmitted { waves } => self
                .bft
                .on_finalized_waves_admitted(self.topology.snapshot(), &waves),
            _ => unreachable!("non-BFT event routed to handle_bft"),
        }
    }

    /// Validate in-flight before letting BFT ingest a received header.
    fn on_block_header_received(
        &mut self,
        header: &BlockHeader,
        manifest: BlockManifest,
    ) -> Vec<Action> {
        let total_tx_count = manifest.transaction_count();

        // Validate in-flight limits only for the next block after committed
        // height. For blocks further ahead, validators at different heights
        // see different in_flight() counts — checking would split votes and
        // trigger view changes.
        let committed_height = self.bft.committed_height();
        let is_next_block = header.height == committed_height + 1;

        if is_next_block
            && self
                .mempool
                .would_exceed_in_flight(total_tx_count, manifest.cert_hashes.len())
        {
            tracing::warn!(
                block_hash = ?header.hash(),
                height = header.height.0,
                "Rejecting block that would exceed in-flight limit"
            );
            return vec![];
        }

        self.bft.on_block_header(
            self.topology.snapshot(),
            header,
            manifest,
            |h| self.mempool.get_transaction(h),
            |h| self.execution.get_finalized_wave_by_hash(h),
            |h| self.provisions.get_provisions_by_hash(h),
        )
    }

    /// QC formed — may trigger immediate next proposal.
    fn on_qc_formed(&mut self, block_hash: BlockHash, qc: &QuorumCertificate) -> Vec<Action> {
        // Count transactions and certificates in the block that will be
        // committed. Critical for in-flight limits: the `BlockCommitted`
        // event won't be processed until after we select transactions, so
        // we preemptively account for txs that will INCREASE in-flight (new
        // commits) and certificates that will DECREASE it (completions).
        let (pending_tx_count, pending_cert_count) = self.bft.pending_commit_counts(qc);
        let inputs = self.gather_proposal_inputs(pending_tx_count, pending_cert_count);

        self.bft.on_qc_formed(
            self.topology.snapshot(),
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
        let block_hash = certified.block.hash();

        // Register committed transactions with BFT for proposal dedup. The
        // tx_cache reads each tx's `validity_range.end_timestamp_exclusive`
        // to bound its own retention.
        self.bft
            .register_committed_transactions(certified.block.transactions());

        // Mark this block as a usable parent for child state-root
        // verifications. By the time `BlockCommitted` fires, the block's JMT
        // snapshot is in `PendingChain` (populated either by a prior
        // `VerifyStateRoot` or by the inline `CommitBlockByQcOnly`
        // computation), so children verify against it without waiting on
        // RocksDB persistence.
        self.bft.on_block_committed_verification(block_hash);

        // Mempool: marks Pending → Committed for `block.transactions`, then
        // drives each tx in `block.certificates` to its terminal state
        // (Completed + tombstone). Same behavior for consensus and sync
        // commit paths.
        actions.extend(
            self.mempool
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Provisions coordinator: prune + schedule fallback timeouts. Reads
        // provision hashes directly off the block — `Live` carries them
        // inline, `Sealed` has none (empty slice).
        actions.extend(
            self.provisions
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Outbound provision safety sweep — runs on the BFT-authenticated
        // weighted timestamp so every validator evicts deterministically.
        self.outbound_provisions
            .on_block_committed(certified.qc.weighted_timestamp);

        actions.extend(self.apply_block_to_execution(certified));

        // In-flight counts changed — latch a proposal attempt so the next
        // proposer can include newly ready transactions.
        self.bft.queue_ready_proposal();

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
        self.execution
            .cleanup_committed_waves(certified.block.certificates());

        actions.extend(
            self.execution
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Round voting: scan all incomplete waves and emit votes for
        // complete ones. Single path to execution voting — abort intents
        // have already been processed above (with override semantics), so
        // the accumulator state is deterministic at this height. All
        // validators at this height produce the same votes.
        actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));

        actions
    }
}
