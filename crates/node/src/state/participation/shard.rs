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

use std::sync::Arc;

use hyperscale_core::{Action, ProtocolEvent, TimerId};
use hyperscale_types::{
    BlockHash, BlockHeader, BlockManifest, CertifiedBlock, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISIONS_PER_BLOCK, MAX_TXS_PER_BLOCK, QuorumCertificate, ShardForkProof,
    TopologySchedule, Verifiable, Verified,
};

use super::ShardParticipation;

impl ShardParticipation {
    /// Dispatch a shard-category `ProtocolEvent`.
    ///
    /// `BlockCommitted` and `RemoteHeaderAdmitted` are not routed here — they
    /// also drive the beacon coordinator, so they stay on
    /// [`NodeStateMachine`](crate::state::NodeStateMachine) as orchestrators.
    #[allow(clippy::too_many_lines)] // single dispatch, one arm per shard variant
    pub(in crate::state) fn handle_shard(
        &mut self,
        topology_schedule: &TopologySchedule,
        event: ProtocolEvent,
    ) -> Vec<Action> {
        match event {
            ProtocolEvent::BlockHeaderReceived { header, manifest } => {
                self.on_block_header_received(topology_schedule, &header, manifest)
            }
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.on_qc_formed(topology_schedule, block_hash, &qc)
            }
            ProtocolEvent::UnverifiedRemoteHeaderReceived {
                certified_header,
                sender,
            } => {
                // Route through the centralized remote header coordinator.
                // Structural pre-checks happen there; downstream consumers
                // receive headers via `RemoteHeaderAdmitted`.
                self.remote_headers_coordinator.on_remote_header_received(
                    topology_schedule,
                    certified_header,
                    sender,
                )
            }
            ProtocolEvent::VerifiedRemoteHeaderReceived {
                certified_header,
                sender,
            } => self
                .remote_headers_coordinator
                .on_verified_remote_header_received(certified_header, sender),
            ProtocolEvent::VerifiedBlockVoteReceived { vote } => self
                .shard_coordinator
                .on_verified_block_vote(topology_schedule, vote),
            ProtocolEvent::UnverifiedBlockVoteReceived { vote } => self
                .shard_coordinator
                .on_unverified_block_vote(topology_schedule, vote),
            ProtocolEvent::VerifiedTimeoutReceived { timeout } => self
                .shard_coordinator
                .on_verified_timeout(topology_schedule, timeout),
            ProtocolEvent::UnverifiedTimeoutReceived { timeout } => self
                .shard_coordinator
                .on_unverified_timeout(topology_schedule, &timeout),
            ProtocolEvent::ReadySignalReceived { signal } => {
                self.shard_coordinator
                    .on_ready_signal_received(topology_schedule, signal);
                Vec::new()
            }
            ProtocolEvent::BlockReadyToCommit { certified, source } => self
                .shard_coordinator
                .on_block_ready_to_commit(topology_schedule, certified, source),
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => self.shard_coordinator.on_qc_result(
                topology_schedule,
                block_hash,
                qc,
                verified_votes,
            ),
            ProtocolEvent::QcSignatureVerified { block_hash, result } => self
                .shard_coordinator
                .on_qc_signature_verified(topology_schedule, block_hash, result),
            ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                sender,
                result,
            } => self
                .remote_headers_coordinator
                .on_remote_header_qc_verified(topology_schedule, shard, height, sender, *result),
            ProtocolEvent::TransactionRootVerified { block_hash, result } => self
                .shard_coordinator
                .on_transaction_root_verified(topology_schedule, block_hash, result),
            ProtocolEvent::CertificateRootVerified { block_hash, result } => self
                .shard_coordinator
                .on_certificate_root_verified(topology_schedule, block_hash, result),
            ProtocolEvent::LocalReceiptRootVerified { block_hash, result } => self
                .shard_coordinator
                .on_local_receipt_root_verified(topology_schedule, block_hash, result),
            ProtocolEvent::ProvisionsRootVerified { block_hash, result } => self
                .shard_coordinator
                .on_provisions_root_verified(topology_schedule, block_hash, result),
            ProtocolEvent::ProvisionTxRootsVerified { block_hash, result } => self
                .shard_coordinator
                .on_provision_tx_roots_verified(topology_schedule, block_hash, result),
            ProtocolEvent::BeaconWitnessRootVerified { block_hash, result } => self
                .shard_coordinator
                .on_beacon_witness_root_verified(topology_schedule, block_hash, result),
            ProtocolEvent::StateRootVerified {
                block_hash,
                result,
                bytes_delta,
            } => self.shard_coordinator.on_state_root_verified(
                topology_schedule,
                block_hash,
                result,
                bytes_delta,
            ),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                finalized_waves,
                provisions,
                bytes_delta,
            } => self.shard_coordinator.on_proposal_built(
                topology_schedule,
                height,
                round,
                &block,
                block_hash,
                finalized_waves,
                provisions,
                bytes_delta,
            ),
            // `BlockPersisted` advances `last_persisted_height`, a fallback
            // gate for deferred state root verifications. Steady-state
            // unblocking happens on `BlockCommitted`; this still matters for
            // boot-time catch-up (freshly-booted node has persisted state
            // but an empty in-memory set, so child verifications of just-
            // persisted parents unblock here) and for auto-resume-from-sync.
            ProtocolEvent::BlockPersisted {
                height,
                substate_bytes,
            } => {
                let mut actions = self.shard_coordinator.on_block_persisted(
                    topology_schedule,
                    height,
                    substate_bytes,
                );
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
                .on_finalized_waves_admitted(topology_schedule, &waves),
            // Locally assembled from already-verified headers — engage the
            // fence and re-gossip directly (no re-verification needed).
            ProtocolEvent::ShardForkDetected { proof } => {
                self.on_fork_proven(topology_schedule, *proof)
            }
            // A peer's proof finished verification: fence + re-gossip on a
            // real verdict, discard a forgery.
            ProtocolEvent::ShardForkProofVerified { proof, verified } => {
                if verified {
                    self.on_fork_proven(topology_schedule, *proof)
                } else {
                    tracing::warn!("discarding a shard fork proof that failed verification");
                    Vec::new()
                }
            }
            // A gossiped proof: resolve committees from the local schedule
            // and dispatch off-thread verification (self-authenticating, no
            // sender trust).
            ProtocolEvent::UnverifiedShardForkProofReceived { proof } => {
                self.on_unverified_fork_proof(topology_schedule, *proof)
            }
            _ => unreachable!("non-shard event routed to handle_shard"),
        }
    }

    /// A shard fork is locally proven (assembled here, or a peer's proof
    /// verified). Engage the local provisional fence on every consuming
    /// coordinator and re-gossip the proof — once per forked shard. A
    /// second proof for an already-fenced shard is a no-op.
    ///
    /// The fence is gossip-timed, so it may not touch block validity (an
    /// honest committee whose replicas hear the proof at different times
    /// would fork if it did): it only quiesces the local node — provisions
    /// from the forked shard above the fork height are dropped so no block
    /// depending on them assembles (the replica abstains), the mempool
    /// stops admitting transactions bound to it, and its headers stop
    /// promoting. The beacon-attested `ShardRecovery` fold supersedes it.
    fn on_fork_proven(
        &mut self,
        topology_schedule: &TopologySchedule,
        proof: ShardForkProof,
    ) -> Vec<Action> {
        let shard = proof.shard();
        let fork_height = proof.height();

        // One fence per forked shard; a later proof only re-engages if it
        // fences a strictly lower height.
        if self
            .fork_fenced_shards
            .get(&shard)
            .is_some_and(|&existing| existing <= fork_height)
        {
            return Vec::new();
        }
        self.fork_fenced_shards.insert(shard, fork_height);

        tracing::error!(
            shard = shard.inner(),
            height = fork_height.inner(),
            "shard fork proven — engaging local fence and re-gossiping"
        );

        let mut actions = self
            .provisions_coordinator
            .engage_fork_fence(shard, fork_height);
        self.remote_headers_coordinator
            .engage_fork_fence(shard, fork_height);
        self.mempool_coordinator.engage_fork_fence(shard);
        // A fenced provision might already sit in a proposal the shard is
        // waiting to complete; nudge the proposer to re-evaluate without it.
        self.shard_coordinator.queue_ready_proposal();
        let _ = topology_schedule;

        actions.push(Action::BroadcastShardForkProof {
            proof: Box::new(proof),
        });
        actions
    }

    /// A fork proof arrived over gossip. Dedup against the already-fenced
    /// shards, then resolve committees from the local schedule and dispatch
    /// off-thread verification (the proof self-authenticates — no sender
    /// trust). An unresolvable epoch drops the proof; a re-gossip retries.
    fn on_unverified_fork_proof(
        &self,
        topology_schedule: &TopologySchedule,
        proof: ShardForkProof,
    ) -> Vec<Action> {
        if self
            .fork_fenced_shards
            .get(&proof.shard())
            .is_some_and(|&existing| existing <= proof.height())
        {
            return Vec::new();
        }
        let Some(committees) = proof.resolve_committees(topology_schedule) else {
            tracing::warn!(
                shard = proof.shard().inner(),
                "dropping fork proof whose committees the local schedule cannot resolve"
            );
            return Vec::new();
        };
        vec![Action::VerifyShardForkProof {
            proof: Box::new(proof),
            committees,
        }]
    }

    /// Validate in-flight before letting shard ingest a received header.
    fn on_block_header_received(
        &mut self,
        sched: &TopologySchedule,
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
            sched,
            header,
            manifest,
            |h| {
                self.mempool_coordinator
                    .get_transaction(h)
                    .map(|tx| Arc::new(Verifiable::from((*tx).clone())))
            },
            |id| self.execution_coordinator.get_finalized_wave(id),
            |h| {
                self.provisions_coordinator
                    .get_provisions_by_hash(*h)
                    .map(|v| Arc::new((*v).clone().into()))
            },
        )
    }

    /// QC formed — may trigger immediate next proposal.
    fn on_qc_formed(
        &mut self,
        sched: &TopologySchedule,
        block_hash: BlockHash,
        qc: &Verified<QuorumCertificate>,
    ) -> Vec<Action> {
        // Count transactions and certificates in the block that will be
        // committed. Critical for in-flight limits: the `BlockCommitted`
        // event won't be processed until after we select transactions, so
        // we preemptively account for txs that will INCREASE in-flight (new
        // commits) and certificates that will DECREASE it (completions).
        let (pending_tx_count, pending_cert_count) =
            self.shard_coordinator.pending_commit_counts(qc);
        let inputs = self.gather_proposal_inputs(sched, pending_tx_count, pending_cert_count);

        self.shard_coordinator.on_qc_formed(
            sched,
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }

    /// Apply a committed block to execution: cert cleanup, wave setup +
    /// dispatch (Live) or wave-assignment recording only (Sealed), and
    /// vote emission. Provisions live inline on `Block::Live` — no separate
    /// argument needed.
    pub(in crate::state) fn apply_block_to_execution(
        &mut self,
        sched: &TopologySchedule,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Release execution's per-wave bookkeeping for wave certs included
        // in this block. Per-tx terminal state for the mempool is already
        // handled separately by `on_block_committed` reading
        // `block.certificates`.
        self.execution_coordinator
            .cleanup_committed_waves(certified.block().certificates());

        actions.extend(
            self.execution_coordinator
                .on_block_committed(sched, certified),
        );

        // Round voting: scan all incomplete waves and emit votes for
        // complete ones. Single path to execution voting — abort intents
        // have already been processed above (with override semantics), so
        // the accumulator state is deterministic at this height. All
        // validators at this height produce the same votes.
        actions.extend(self.execution_coordinator.emit_vote_actions(sched));

        actions
    }

    /// Run any counterpart abort sweeps whose terminated partner's settled
    /// coverage is now complete: execution drops the doomed local waves and
    /// hands back their transaction hashes; the mempool releases their locks
    /// and drives them to `Completed(Aborted)`. A no-op when no partner is
    /// past-terminal.
    pub(in crate::state) fn sweep_ready_counterpart_straddlers(&mut self) -> Vec<Action> {
        let aborts = self.execution_coordinator.take_ready_counterpart_aborts();
        if aborts.is_empty() {
            return Vec::new();
        }
        self.mempool_coordinator.abort_transactions(&aborts)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
    use hyperscale_types::test_utils::{certify, make_live_block, test_transaction};
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight,
        BlockManifest, CertificateRoot, CertifiedBlock, CertifiedBlockHeader, ChainOrigin,
        CommitProof, Hash, InFlightCount, LocalReceiptRoot, LocalTimestamp, MerkleInclusionProof,
        ProposerTimestamp, ProvisionEntry, Provisions, ProvisionsRoot, QuorumCertificate,
        RETENTION_HORIZON, Round, ShardForkProof, ShardId, StateRoot, TransactionRoot,
        TransactionStatus, TxHash, ValidatorId, Verified, WaveId, WitnessSources,
    };

    use crate::state::test_support::TestNode;

    /// `RemoteHeaderAdmitted` must fan out to **both** execution and
    /// provisions: each registers its expectations from the header's wave
    /// list (only for waves whose `remote_shards` includes local). The
    /// header opens for provision verification only on
    /// `RemoteHeaderCommitted`, once its commit proof is held. Dropping
    /// either fan-out side leaves the shard blind to one half of
    /// cross-shard work.
    #[test]
    fn remote_header_admitted_fans_to_execution_and_provisions() {
        let TestNode { mut node, .. } = TestNode::builder().build();

        // Wave on a remote leaf shard listing the local root shard as a dependency.
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

        let pre_exec = node
            .execution_coordinator()
            .memory_stats()
            .expected_exec_certs;
        let pre_prov = node
            .provisions_coordinator()
            .memory_stats()
            .expected_provisions;

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::RemoteHeaderAdmitted {
                certified_header: Arc::clone(&certified_header),
            },
        );

        assert_eq!(
            node.execution_coordinator()
                .memory_stats()
                .expected_exec_certs,
            pre_exec + 1,
            "execution must register the wave from the verified header as an expected EC",
        );
        assert_eq!(
            node.provisions_coordinator()
                .memory_stats()
                .expected_provisions,
            pre_prov + 1,
            "provisions must register the expected provisions",
        );
        assert_eq!(
            node.provisions_coordinator().verified_remote_header_count(),
            0,
            "a merely-certified header must not open provision verification",
        );

        // The committed event opens the header for provision verification.
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::RemoteHeaderCommitted { certified_header },
        );
        assert_eq!(
            node.provisions_coordinator().verified_remote_header_count(),
            1,
            "the commit-proven header must be recorded for provision verification",
        );
    }

    /// A minimal certified header (dummy QC) on `shard` — enough for the
    /// orchestration paths that read only `shard`/`height`, not the crypto.
    fn dummy_header(
        shard: ShardId,
        height: u64,
        round: u64,
        parent: BlockHash,
        salt: u64,
    ) -> CertifiedBlockHeader {
        let h = BlockHeight::new(height);
        let header = BlockHeader::new(
            shard,
            h,
            parent,
            QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(salt),
            Round::new(round),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        CertifiedBlockHeader::new(header, QuorumCertificate::genesis(shard, ChainOrigin::ROOT))
    }

    /// A `ConflictingCommits` on `shard` forked at height 5. The dummy QCs
    /// do not verify — sufficient for the `ShardForkDetected` path, which
    /// trusts locally-assembled evidence.
    fn make_fork_proof(shard: ShardId) -> ShardForkProof {
        let parent = BlockHash::from_raw(Hash::from_bytes(b"fork-parent"));
        ShardForkProof::ConflictingCommits {
            a: CommitProof::direct(
                dummy_header(shard, 5, 5, parent, 1),
                dummy_header(
                    shard,
                    6,
                    6,
                    dummy_header(shard, 5, 5, parent, 1).block_hash(),
                    2,
                ),
            ),
            b: CommitProof::direct(
                dummy_header(shard, 5, 7, parent, 3),
                dummy_header(
                    shard,
                    6,
                    8,
                    dummy_header(shard, 5, 7, parent, 3).block_hash(),
                    4,
                ),
            ),
        }
    }

    /// A locally-assembled fork engages the fence and re-gossips exactly
    /// once per forked shard.
    #[test]
    fn shard_fork_detected_engages_fence_and_regossips_once() {
        let TestNode { mut node, .. } = TestNode::builder().build();
        let forked = ShardId::leaf(1, 1);
        let proof = make_fork_proof(forked);

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ShardForkDetected {
                proof: Box::new(proof.clone()),
            },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastShardForkProof { .. })),
            "a newly proven fork must re-gossip",
        );

        let again = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ShardForkDetected {
                proof: Box::new(proof),
            },
        );
        assert!(
            !again
                .iter()
                .any(|a| matches!(a, Action::BroadcastShardForkProof { .. })),
            "an already-fenced shard is not re-gossiped",
        );
    }

    /// `TransactionsAdmitted` latches a proposal-retry via
    /// `shard.queue_ready_proposal()`; the post-dispatch hook in
    /// `mod.rs::handle` calls `try_event_driven_proposal()` when the
    /// latch fires. End-to-end: when the local validator is the
    /// height-1 proposer, this chain must surface a `BuildProposal`
    /// action. Without the latch (or without the post-dispatch hook),
    /// no proposal would emerge — and that regression is silent until
    /// liveness breaks.
    #[test]
    fn transactions_admitted_drives_proposal_through_post_dispatch_hook() {
        // Rounds increase per block, so height 1 is round 1:
        // proposer_for(r=1) = committee[1 % 4] = committee[1]
        // = ValidatorId::new(1). Pick local_idx=1 to be the leader.
        let TestNode { mut node, .. } = TestNode::builder().local_idx(1).build();
        assert!(
            node.topology_snapshot()
                .proposer_for(node.shard_id(), Round::new(1))
                == node.validator_id(),
            "local must be the height-1 proposer for this test",
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
        // local_idx=0 → ValidatorId::new(0); a fresh node proposes height 1 in
        // round 1, whose proposer is committee[1] = ValidatorId::new(1), so we
        // are not the leader.
        let TestNode { mut node, .. } = TestNode::new();
        assert!(
            node.topology_snapshot()
                .proposer_for(node.shard_id(), Round::new(1))
                != node.validator_id(),
            "local must NOT be the height-1 proposer for this test",
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
                substate_bytes: 0,
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
    /// run on the committed block's BFT weighted timestamp — never on local
    /// clock. The timestamp is hash-pinned in the block's parent QC, so every
    /// validator reads the same value and they evict in lockstep; if local
    /// clock leaks in, validators with skew evict at different commits and the
    /// outbound tracker forks across the network.
    ///
    /// Test pumps local clock far past the entry's deadline and commits a
    /// block whose weighted timestamp is BELOW that deadline. The entry must
    /// survive — proves the sweep ignored the local clock. A second commit
    /// with a weighted timestamp past the deadline then confirms the eviction
    /// path itself works.
    #[test]
    fn block_committed_evicts_outbound_provisions_on_weighted_timestamp_not_local_clock() {
        let TestNode { mut node, .. } = TestNode::builder().build();

        // Register an outbound batch (local root shard → remote leaf shard).
        // Deadline = self.now (ZERO) + RETENTION_HORIZON ≈ 5m24s.
        let provisions = Arc::new(Verified::new_unchecked_for_test(Provisions::new(
            ShardId::ROOT,
            ShardId::leaf(1, 1),
            BlockHeight::new(1),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"outbound-tx")),
                vec![],
                vec![],
                vec![],
            )],
        )));
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::OutboundProvisionBroadcast {
                provisions,
                target_shard: ShardId::leaf(1, 1),
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

        // Commit a block whose weighted timestamp is BELOW the entry
        // deadline. The orchestrator passes this into the outbound sweep.
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        // SAFETY: test fixture; block and synthesized QC are produced
        // in-process for the orchestrator test, no adversarial input.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(certify(
            block, /* weighted_timestamp_ms */ 1_000,
        )));
        let _ = node.handle(past_deadline, ProtocolEvent::BlockCommitted { certified });
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            1,
            "outbound entry must survive — the block's weighted timestamp is below the deadline, \
             local clock past it must not leak in",
        );

        // Commit a second block whose weighted timestamp IS past the
        // deadline. Now the eviction path proper must fire.
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(2),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        // SAFETY: test fixture; same rationale as above.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(certify(
            block,
            past_deadline_ms,
        )));
        let _ = node.handle(past_deadline, ProtocolEvent::BlockCommitted { certified });
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            0,
            "outbound entry must be evicted — the block's weighted timestamp now exceeds the deadline",
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

        let manifest =
            BlockManifest::new(vec![TxHash::ZERO], vec![], vec![], WitnessSources::empty());

        // `make_live_block` stamps round 0, and proposer_for(r=0) =
        // committee[0] = ValidatorId::new(0). The shard coordinator's header
        // validation rejects on proposer mismatch, so the header must name the
        // round-0 leader to reach the pending-blocks insert.
        let header = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
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

        let raw_tx = Arc::new(test_transaction(/* seed */ 1));
        let tx_hash = raw_tx.hash();
        let verified_tx = Arc::new(Verified::new_unchecked_for_test((*raw_tx).clone()));

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionValidated {
                tx: Arc::clone(&verified_tx),
                submitted_locally: true,
            },
        );
        assert_eq!(
            node.mempool_coordinator().status(&tx_hash),
            Some(TransactionStatus::Pending),
            "tx must be admitted as Pending before commit",
        );

        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            /* timestamp_ms */ 1_000,
            ValidatorId::new(0),
            vec![raw_tx],
            vec![],
        );
        // SAFETY: test fixture; block and synthesized QC are produced
        // in-process to exercise the commit fan-out, no adversarial
        // input.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(certify(
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
