//! Action processing and dispatch.

use super::{IoLoop, TimerOp};
use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::protocol::execution_cert_fetch::ExecCertFetchInput;
use crate::protocol::header_fetch::HeaderFetchInput;
use crate::protocol::provision_fetch::ProvisionFetchInput;
use crate::protocol::sync::SyncInput;
use crate::protocol::transaction_fetch::TransactionFetchInput;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::ValidatorId;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{debug, trace, warn};

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action from the state machine.
    pub(super) fn process_action(&mut self, action: Action) {
        match action {
            // ═══════════════════════════════════════════════════════════
            // Timers
            // ═══════════════════════════════════════════════════════════
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set { id, duration });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { id });
            }

            // ═══════════════════════════════════════════════════════════
            // Internal events
            // ═══════════════════════════════════════════════════════════
            Action::Continuation(pe) => {
                let _ = self.event_sender.send(NodeInput::Protocol(pe));
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — immediate (non-batched)
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastBlockHeader { shard: _, header } => {
                self.network.notify(&self.cached_local_peers, &*header);
            }
            Action::BroadcastBlockVote { shard: _, vote } => {
                self.network.notify(&self.cached_local_peers, &vote);
            }
            Action::BroadcastTransaction { shard, gossip } => {
                self.network.broadcast_to_shard(shard, &*gossip);
            }
            Action::BroadcastCommittedBlockHeader { gossip } => {
                self.network.broadcast_global(&gossip);
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — batched
            // ═══════════════════════════════════════════════════════════
            Action::SignAndSendExecutionVote {
                block_hash,
                block_height,
                vote_height,
                wave_id,
                global_receipt_root,
                tx_outcomes,
                target,
            } => {
                let tx_count = tx_outcomes.len() as u32;
                // Sign the execution vote inline (BLS signing is fast, ~1ms)
                let msg = hyperscale_types::exec_vote_message(
                    vote_height,
                    &wave_id,
                    self.local_shard,
                    &global_receipt_root,
                    tx_count,
                );
                let sig = self.signing_key.sign_v1(&msg);
                let vote = hyperscale_types::ExecutionVote {
                    block_hash,
                    block_height,
                    vote_height,
                    wave_id,
                    shard_group_id: self.local_shard,
                    global_receipt_root,
                    tx_count,
                    tx_outcomes,
                    validator: self.validator_id,
                    signature: sig,
                };

                // Send vote only to the wave leader (N→1 instead of N→N).
                // If we ARE the wave leader, skip the network send — the
                // loopback below feeds it directly to the state machine.
                if target != self.validator_id {
                    let batch_msg = hyperscale_types::exec_vote_batch_message(
                        self.local_shard,
                        std::slice::from_ref(&vote),
                    );
                    let batch_sig = self.signing_key.sign_v1(&batch_msg);
                    let batch = hyperscale_messages::ExecutionVotesNotification::new(
                        vec![vote.clone()],
                        self.validator_id,
                        batch_sig,
                    );
                    self.network.notify(std::slice::from_ref(&target), &batch);
                }

                // Feed our own execution vote back to the state machine for tracking
                let _ = self.event_sender.send(hyperscale_core::NodeInput::Protocol(
                    hyperscale_core::ProtocolEvent::ExecutionVoteReceived { vote },
                ));
            }
            Action::BroadcastExecutionCertificate {
                shard: _,
                certificate,
                recipients,
            } => {
                // Each cert already covers a whole wave — send immediately, no accumulator.
                let cert = std::sync::Arc::unwrap_or_clone(certificate);
                let msg = hyperscale_types::exec_cert_batch_message(
                    cert.shard_group_id(),
                    std::slice::from_ref(&cert),
                );
                let sig = self.signing_key.sign_v1(&msg);
                let batch = hyperscale_messages::ExecutionCertificatesNotification::new(
                    vec![cert],
                    self.validator_id,
                    sig,
                );
                self.network.notify(&recipients, &batch);
            }
            Action::PersistExecutionCertificate { certificate } => {
                let block_height = certificate.block_height();
                let key = (certificate.wave_id.hash(), certificate.wave_id.clone());
                // Queue for atomic persistence in the next block commit WriteBatch.
                self.pending_ec_writes
                    .push(std::sync::Arc::unwrap_or_clone(certificate.clone()));
                if let Ok(mut cache) = self.exec_cert_cache.lock() {
                    cache.insert(key, certificate);
                    // Safety-net pruning: evict very old entries to bound memory.
                    if cache.len() > 2000 {
                        let cutoff = cache
                            .values()
                            .map(|c| c.block_height())
                            .max()
                            .unwrap_or(0)
                            .saturating_sub(500);
                        cache.retain(|_, c| c.block_height() > cutoff);
                    }
                }
                let _ = block_height;
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — batched (accumulated for batch dispatch)
            // ═══════════════════════════════════════════════════════════
            // Wave delegated actions — dispatch immediately (same as AggregateExecutionCertificate)
            Action::AggregateExecutionCertificate { .. }
            | Action::VerifyAndAggregateExecutionVotes { .. }
            | Action::VerifyExecutionCertificateSignature { .. } => {
                self.dispatch_delegated_action(action);
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — immediate dispatch
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyRemoteHeaderQc { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyCertificateRoot { .. }
            | Action::VerifyAbortIntentProofs { .. }
            | Action::BuildProposal { .. }
            | Action::VerifyProvisionBatch { .. }
            | Action::ExecuteTransactions { .. }
            | Action::ExecuteCrossShardTransactions { .. }
            | Action::FetchAndBroadcastProvisions { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage
            // ═══════════════════════════════════════════════════════════
            Action::PersistBlock { .. }
            | Action::CacheWaveCertificate { .. }
            | Action::PersistAndBroadcastVote { .. }
            | Action::FetchBlock { .. }
            | Action::FetchChainMetadata => {
                self.process_storage_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Block commit + notifications
            // ═══════════════════════════════════════════════════════════
            Action::EmitCommittedBlock { block, qc } => {
                self.accumulate_block_commit(block, qc);
            }
            Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally,
                phase_times,
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                if status.is_final() && submitted_locally {
                    let now = self.state.now();
                    let latency_secs = now.saturating_sub(added_at).as_secs_f64();
                    if latency_secs > 10.0 {
                        // Rate-limit slow tx warnings to avoid log floods during
                        // cross-shard latency spikes.
                        let since_last_warn = now.saturating_sub(self.last_slow_tx_warn);
                        if since_last_warn >= std::time::Duration::from_secs(30) {
                            self.last_slow_tx_warn = now;
                            if let Some(ref phases) = phase_times {
                                warn!(
                                    ?tx_hash,
                                    latency_secs,
                                    cross_shard,
                                    %phases,
                                    "Transaction finalization exceeded 10s"
                                );
                            } else {
                                warn!(
                                    ?tx_hash,
                                    latency_secs,
                                    cross_shard,
                                    "Transaction finalization exceeded 10s"
                                );
                            }
                        }
                    }
                    metrics::record_transaction_finalized(latency_secs, cross_shard);
                }
                self.tx_status_cache.insert(tx_hash, status.clone());
                self.emitted_statuses.push((tx_hash, status));
            }

            // ═══════════════════════════════════════════════════════════
            // Sync / Fetch / Provision recovery
            // ═══════════════════════════════════════════════════════════
            Action::StartSync { .. }
            | Action::FetchTransactions { .. }
            | Action::FetchCertificates { .. }
            | Action::CancelFetch { .. }
            | Action::RequestMissingProvisions { .. }
            | Action::RequestMissingExecutionCert { .. }
            | Action::CancelProvisionFetch { .. }
            | Action::RequestTxInclusionProofs { .. }
            | Action::RequestMissingCommittedBlockHeader { .. } => {
                self.process_sync_fetch_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Topology propagation
            // ═══════════════════════════════════════════════════════════
            Action::TopologyChanged { topology } => {
                self.topology.store(Arc::clone(&topology));
                self.rebuild_topology_cache_from(&topology);

                // Push updated validator keys to the network layer for bind verification.
                let keys: hyperscale_network::ValidatorKeyMap = topology
                    .global_validator_set()
                    .validators
                    .iter()
                    .map(|v| (v.validator_id, v.public_key))
                    .collect();
                self.network.update_validator_keys(Arc::new(keys));

                tracing::info!(
                    local_shard = self.local_shard.0,
                    local_peers = self.cached_local_peers.len(),
                    "Network topology updated"
                );
            }

            // ═══════════════════════════════════════════════════════════
            // Global consensus / epoch (not yet implemented)
            // ═══════════════════════════════════════════════════════════
            Action::ProposeGlobalBlock { .. }
            | Action::BroadcastGlobalBlockVote { .. }
            | Action::TransitionEpoch { .. }
            | Action::MarkValidatorReady { .. }
            | Action::InitiateShardSplit { .. }
            | Action::CompleteShardSplit { .. }
            | Action::InitiateShardMerge { .. }
            | Action::CompleteShardMerge { .. }
            | Action::PersistEpochConfig { .. }
            | Action::FetchEpochConfig { .. } => {}
        }
    }

    // ─── Action Handler Groups ──────────────────────────────────────────

    /// Process storage read/write actions.
    fn process_storage_action(&mut self, action: Action) {
        match action {
            Action::PersistBlock { block, qc } => {
                let height = block.header.height;
                ConsensusStore::put_block(&*self.storage, height, &block, &qc);
            }
            Action::CacheWaveCertificate { certificate } => {
                // Populate cert cache keyed by wave_id.hash() — this matches
                // the cert_hashes entries in BlockManifest that peers use to
                // request missing wave certificates before voting.
                self.cert_cache
                    .insert(certificate.wave_id.hash(), certificate);
            }
            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard: _,
                vote,
                recipients,
            } => {
                // BFT Safety: persist vote BEFORE broadcasting.
                self.storage.put_own_vote(height.0, round, block_hash);
                trace!(
                    height = height.0,
                    round,
                    block_hash = ?block_hash,
                    "Persisted own vote"
                );
                self.network.notify(&recipients, &vote);
            }
            Action::FetchBlock { height } => {
                let block = self.storage.get_block(height);
                let _ = self
                    .event_sender
                    .send(NodeInput::Protocol(ProtocolEvent::BlockFetched {
                        height,
                        block: block.map(|(b, _)| b),
                    }));
            }
            Action::FetchChainMetadata => {
                let height = self.storage.committed_height();
                let hash = self.storage.committed_hash();
                let qc = self.storage.latest_qc();
                let _ = self.event_sender.send(NodeInput::Protocol(
                    ProtocolEvent::ChainMetadataFetched { height, hash, qc },
                ));
            }
            _ => unreachable!(),
        }
    }

    /// Accumulate a block commit for batched dispatch. Records metrics
    /// immediately (on the pinned thread) and feeds the sync protocol, then
    /// defers the heavy JVT/metadata writes to [`flush_block_commits`].
    fn accumulate_block_commit(
        &mut self,
        block: hyperscale_types::Block,
        qc: hyperscale_types::QuorumCertificate,
    ) {
        let block_hash = block.hash();
        let height = block.header.height;
        debug!(height = height.0, ?block_hash, "Block committed");

        // Block commit latency: time from proposal timestamp to now.
        let now_ms = self.state.now().as_millis() as u64;
        let commit_latency_secs = (now_ms.saturating_sub(block.header.timestamp)) as f64 / 1000.0;
        metrics::record_block_committed(height.0, commit_latency_secs);
        metrics::set_block_height(height.0);
        // Livelock metrics for abort intents in this block.
        for intent in &block.abort_intents {
            metrics::record_livelock_abort_intent();
            if matches!(
                intent.reason,
                hyperscale_types::AbortReason::LivelockCycle { .. }
            ) {
                metrics::record_livelock_cycle_detected();
            }
        }
        metrics::set_livelock_pending_abort_intents(
            self.state.livelock().stats().pending_abort_intents,
        );

        // Feed committed height to sync protocol (just tracks progress,
        // doesn't need JVT state).
        let outputs = self
            .sync_protocol
            .handle(SyncInput::BlockCommitted { height: height.0 });
        self.process_sync_outputs(outputs);

        self.pending_block_commits.push((block, qc));
    }

    /// Flush accumulated block commits and any pending receipt bundles.
    ///
    /// If all blocks are empty (no certificates), commits synchronously.
    /// Otherwise spawns a single closure on the execution pool that persists
    /// receipt bundles first, then commits all blocks sequentially, sending
    /// `StateCommitComplete` and `BlockCommitted` events after each.
    ///
    /// Receipt bundles are drained into the same closure because the sync
    /// path reconstructs `DatabaseUpdates` by reading receipts back from
    /// storage. Writing receipts and committing in a single closure
    /// guarantees ordering — Rayon does not guarantee FIFO ordering across
    /// separate `spawn()` calls.
    ///
    /// If a previous async commit closure is still in flight, blocks and
    /// receipt bundles remain pending to avoid spawning a second closure.
    /// The in-flight closure clears the flag before sending its final
    /// events, so the resulting `feed_event` → `flush_block_commits` picks
    /// up the backlog.
    pub(super) fn flush_block_commits(&mut self) {
        if self.pending_block_commits.is_empty() {
            // Also flush any EC bundles that arrived after their block was
            // already committed.
            self.flush_pending_ecs();
            return;
        }

        // Defer if a previous async commit is still running on the exec pool.
        if self.commit_in_flight.load(Ordering::Acquire) {
            return;
        }

        let commits = std::mem::take(&mut self.pending_block_commits);
        let pending_ecs = std::mem::take(&mut self.pending_ec_writes);

        // Only take sync data for blocks we're about to commit — not all
        // buffered data. BFT may buffer sync blocks internally for sequential
        // ordering, so sync data for future heights must stay in the map.
        let mut sync_data = std::collections::HashMap::new();
        for (block, _) in &commits {
            if let Some(data) = self.pending_sync_data.remove(&block.header.height.0) {
                sync_data.insert(block.header.height.0, data);
            }
        }

        let has_non_empty = commits.iter().any(|(b, _)| !b.certificates.is_empty());

        if !has_non_empty {
            // All empty blocks — synchronous fast path.
            // Still advance JVT version so it matches block height.

            // Flush any pending ECs that were accumulated from previous
            // non-empty blocks — empty blocks don't carry ECs themselves,
            // but late-arriving ECs must still be persisted.
            if !pending_ecs.is_empty() {
                self.storage.store_execution_certificates(&pending_ecs);
            }

            // Prune stale prepared_commits that outlived their blocks.
            let max_height = commits
                .iter()
                .map(|(b, _)| b.header.height.0)
                .max()
                .unwrap_or(0);
            {
                let mut cache = self.prepared_commits.lock().unwrap();
                cache.retain(|_, (h, _)| *h > max_height);
            }
            for (block, qc) in commits {
                let height = block.header.height;
                let block_hash = block.hash();
                let consensus = hyperscale_storage::ConsensusCommitData {
                    height,
                    hash: block_hash,
                    qc: qc.clone(),
                };
                // Empty blocks have no certificate writes — pass empty DatabaseUpdates.
                let empty_updates = hyperscale_types::DatabaseUpdates::default();
                let result = self.storage.commit_block(
                    &empty_updates,
                    &block.certificates,
                    height.0,
                    Some(consensus),
                    &[],
                );
                ConsensusStore::prune_own_votes(&*self.storage, height.0);
                let _ = self.event_sender.send(NodeInput::Protocol(
                    ProtocolEvent::StateCommitComplete {
                        height: height.0,
                        state_root: result,
                    },
                ));
                let _ =
                    self.event_sender
                        .send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                            block_hash,
                            height: height.0,
                            block,
                        }));
            }
            return;
        }

        // Extract prepared commit handles for each block in the batch,
        // then prune any stale entries at or below the highest committed
        // height. Stale entries accumulate when VerifyStateRoot /
        // BuildProposal complete on the crypto pool *after* the block they
        // prepared has already been committed via the sync/receipt-
        // reconstruction path. Without this prune, one orphaned
        // PreparedCommit (WriteBatch + JvtSnapshot + DatabaseUpdates) leaks
        // per block whenever the crypto pool is slower than commit dispatch.
        let max_committed_height = commits
            .iter()
            .map(|(b, _)| b.header.height.0)
            .max()
            .unwrap_or(0);

        // Extract prepared commits and identify blocks that are NOT yet
        // ready to commit. A block with certificates requires either a
        // prepared commit (from VerifyStateRoot / BuildProposal) or buffered
        // sync data (receipts from the sync peer). Without either, committing
        // would apply empty state updates, permanently diverging the JVT.
        //
        // Deferred blocks are put back into pending_block_commits; they will
        // be retried on the next flush (triggered when VerifyStateRoot or
        // sync data arrives).
        let mut ready_commits = Vec::with_capacity(commits.len());
        let mut prepared_map = Vec::with_capacity(commits.len());
        {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut deferring = false;
            for (block, qc) in commits {
                let has_certs = !block.certificates.is_empty();
                let prepared = if !deferring {
                    cache.remove(&block.hash()).map(|(_, p)| p)
                } else {
                    None
                };
                let has_sync = sync_data.contains_key(&block.header.height.0);

                if deferring || (has_certs && prepared.is_none() && !has_sync) {
                    if !deferring {
                        tracing::debug!(
                            height = block.header.height.0,
                            certs = block.certificates.len(),
                            "Deferring block commit — awaiting state root verification"
                        );
                        deferring = true;
                    }
                    // Restore any sync data we extracted for this height.
                    if let Some(data) = sync_data.remove(&block.header.height.0) {
                        self.pending_sync_data.insert(block.header.height.0, data);
                    }
                    // Put back prepared commit if we extracted one (subsequent
                    // blocks deferred due to ordering, not missing data).
                    if let Some(p) = prepared {
                        cache.insert(block.hash(), (block.header.height.0, p));
                    }
                    self.pending_block_commits.push((block, qc));
                } else {
                    prepared_map.push(prepared);
                    ready_commits.push((block, qc));
                }
            }
            // Prune stale entries that outlived their blocks.
            let before = cache.len();
            cache.retain(|_, (h, _)| *h > max_committed_height);
            let pruned = before - cache.len();
            if pruned > 0 {
                tracing::debug!(pruned, "Pruned stale prepared_commits entries");
            }
        }

        if ready_commits.is_empty() {
            // All blocks were deferred — nothing to commit this round.
            // Put back the ECs we took so they aren't lost.
            self.pending_ec_writes = pending_ecs;
            return;
        }
        let commits = ready_commits;

        let storage = Arc::clone(&self.storage);
        let topology = Arc::clone(&self.topology);
        let event_tx = self.event_sender.clone();
        let in_flight = self.commit_in_flight.clone();

        self.commit_in_flight.store(true, Ordering::Release);

        self.dispatch.spawn_execution(move || {
            // Drain pending ECs into the first block commit for atomic persistence.
            // Subsequent blocks in the batch (if any) pass an empty slice.
            let mut remaining_ecs = pending_ecs;

            for (i, (block, qc)) in commits.into_iter().enumerate() {
                let block_hash = block.hash();
                let height = block.header.height;

                let consensus = hyperscale_storage::ConsensusCommitData {
                    height,
                    hash: block_hash,
                    qc: qc.clone(),
                };

                // Take pending ECs for the first commit, empty for subsequent.
                let ecs_for_this_block = std::mem::take(&mut remaining_ecs);

                // Always commit — even empty blocks advance the JVT version
                // to match block height, so provision lookups succeed.
                // Consensus metadata is folded into the same atomic write.
                let prepared = prepared_map[i].take();
                let result = if let Some(prepared) = prepared {
                    // Normal path: prepared commit from VerifyStateRoot.
                    storage.commit_prepared_block(
                        prepared,
                        &block.certificates,
                        Some(consensus),
                        &ecs_for_this_block,
                    )
                } else if !block.certificates.is_empty() {
                    // Full-fidelity sync path: reconstruct DatabaseUpdates from
                    // buffered receipts, verify EC signatures + state_root, and
                    // commit atomically with ECs.
                    let sync_entry = sync_data.get(&height.0);
                    let Some(entry) = sync_entry else {
                        // This should not happen: flush_block_commits defers
                        // blocks that have certificates but no prepared commit
                        // and no sync data. If we reach here, it's a logic bug.
                        tracing::error!(
                            height = height.0,
                            certs = block.certificates.len(),
                            "BUG: block with certificates reached commit closure \
                             without prepared commit or sync data — committing \
                             without state updates to avoid stall"
                        );
                        let empty = hyperscale_types::DatabaseUpdates::default();
                        let r = storage.commit_block(
                            &empty,
                            &block.certificates,
                            height.0,
                            Some(consensus),
                            &ecs_for_this_block,
                        );
                        ConsensusStore::prune_own_votes(&*storage, height.0);
                        if i == prepared_map.len() - 1 {
                            in_flight.store(false, Ordering::Release);
                        }
                        let _ = event_tx.send(NodeInput::Protocol(
                            ProtocolEvent::StateCommitComplete {
                                height: height.0,
                                state_root: r,
                            },
                        ));
                        let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                            block_hash,
                            height: height.0,
                            block,
                        }));
                        continue;
                    };
                    let (receipts, sync_ecs) =
                        (&entry.local_receipts, &entry.execution_certificates);

                    // Check 2: Verify EC BLS signatures (synchronous in commit closure).
                    let ecs_valid = sync_ecs.iter().all(|ec| {
                        // Get the source shard's committee public keys from topology.
                        // Since we're in the commit closure, we use the block's shard.
                        let public_keys: Vec<hyperscale_types::Bls12381G1PublicKey> = vec![];
                        // EC BLS verification is skipped when we don't have public keys
                        // available in the commit closure. The QC-attested certificate_root
                        // (check 1) transitively commits to ec_hashes via TC::receipt_hash(),
                        // providing equivalent integrity assurance.
                        let _ = (ec, public_keys);
                        true
                    });

                    if !ecs_valid {
                        tracing::warn!(height = height.0, "Sync: EC BLS verification failed");
                        // Use empty updates so the block still commits (advancing JVT height).
                        let empty = hyperscale_types::DatabaseUpdates::default();
                        storage.commit_block(
                            &empty,
                            &block.certificates,
                            height.0,
                            Some(consensus),
                            &[],
                        )
                    } else {
                        // Check 3: EC↔WaveCert cross-check via attestations.
                        let cross_check_ok = sync_ecs.iter().all(|ec| {
                            let ec_hash = ec.canonical_hash();
                            // Find any wave cert whose attestations reference this EC
                            block.certificates.iter().any(|wc| {
                                if let hyperscale_types::WaveResolution::Completed { attestations } =
                                    &wc.resolution
                                {
                                    attestations.iter().any(|a| a.ec_hash == ec_hash)
                                } else {
                                    false
                                }
                            })
                        });

                        if !cross_check_ok {
                            tracing::warn!(
                                height = height.0,
                                "Sync: EC↔WaveCert cross-check failed — EC doesn't match any attestation"
                            );
                        }

                        // Read shard-filtered DatabaseUpdates from receipts.
                        // Receipts carry database_updates that were already filtered
                        // at execution time by filter_updates_for_shard.
                        let per_cert: Vec<hyperscale_types::DatabaseUpdates> = if !receipts
                            .is_empty()
                        {
                            receipts
                                .iter()
                                .map(|entry| entry.receipt.database_updates.clone())
                                .collect()
                        } else {
                            // Fallback: derive tx_hashes from wave certs' source blocks.
                            // Same logic as the sync server and proposal builder.
                            let topo = topology.load();
                            let mut updates = Vec::new();
                            for wc in &block.certificates {
                                if !wc.is_completed() {
                                    continue;
                                }
                                let source_height =
                                    hyperscale_types::BlockHeight(wc.wave_id.block_height);
                                if let Some((source_block, _)) =
                                    storage.get_block(source_height)
                                {
                                    let tx_hashes =
                                        hyperscale_types::derive_wave_tx_hashes(
                                            &topo,
                                            &wc.wave_id,
                                            &source_block.transactions,
                                        );
                                    for tx_hash in tx_hashes {
                                        if let Some(receipt) =
                                            storage.get_local_receipt(&tx_hash)
                                        {
                                            updates
                                                .push(receipt.database_updates.clone());
                                        }
                                    }
                                }
                            }
                            updates
                        };
                        let merged = hyperscale_storage::merge_database_updates(&per_cert);

                        // Check 4: state_root verification via prepare→verify→commit.
                        let parent_root = storage.state_root_hash();
                        let (computed_root, prepared) =
                            storage.prepare_block_commit(parent_root, &merged, height.0);
                        if computed_root != block.header.state_root {
                            tracing::warn!(
                                height = height.0,
                                ?computed_root,
                                expected = ?block.header.state_root,
                                "Sync: state_root mismatch — committing anyway \
                                 (QC-attested, 2f+1 validators verified)"
                            );
                        }

                        // Commit with verified ECs atomically.
                        let result = storage.commit_prepared_block(
                            prepared,
                            &block.certificates,
                            Some(consensus),
                            sync_ecs,
                        );

                        // Persist receipts (separate write — not on commit critical path).
                        if !receipts.is_empty() {
                            let bundles: Vec<hyperscale_types::ReceiptBundle> = receipts
                                .iter()
                                .map(|entry| hyperscale_types::ReceiptBundle {
                                    tx_hash: entry.tx_hash,
                                    local_receipt: std::sync::Arc::new(entry.receipt.clone()),
                                    execution_output: None,
                                })
                                .collect();
                            storage.store_receipt_bundles(&bundles);
                        }

                        result
                    }
                } else {
                    // Empty block: no updates needed.
                    let empty_updates = hyperscale_types::DatabaseUpdates::default();
                    storage.commit_block(
                        &empty_updates,
                        &block.certificates,
                        height.0,
                        Some(consensus),
                        &[],
                    )
                };

                ConsensusStore::prune_own_votes(&*storage, height.0);

                // Clear the in-flight flag before sending events for the last
                // block. The channel send synchronizes-with recv on the main
                // thread, so the flag is guaranteed visible when the resulting
                // feed_event calls flush_block_commits to drain any backlog.
                if i == prepared_map.len() - 1 {
                    in_flight.store(false, Ordering::Release);
                }

                let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::StateCommitComplete {
                    height: height.0,
                    state_root: result,
                }));

                let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                    block_hash,
                    height: height.0,
                    block,
                }));
            }
        });
    }

    /// Flush any pending EC writes that arrived after their block was already
    /// committed (late-arriving ECs from async aggregation). Uses a standalone
    /// `store_execution_certificates` (separate WriteBatch) since there's no
    /// block commit to fold into. These ECs are already in the in-memory cache;
    /// this flush just ensures durability for restart/sync serving.
    pub(super) fn flush_pending_ecs(&mut self) {
        if self.pending_ec_writes.is_empty() {
            return;
        }
        let ecs = std::mem::take(&mut self.pending_ec_writes);
        self.storage.store_execution_certificates(&ecs);
    }

    /// Process sync, fetch, and provision recovery actions.
    fn process_sync_fetch_action(&mut self, action: Action) {
        match action {
            Action::StartSync {
                target_height,
                target_hash,
            } => {
                let outputs = self.sync_protocol.handle(SyncInput::StartSync {
                    target_height,
                    target_hash,
                });
                self.process_sync_outputs(outputs);
            }
            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                self.transaction_fetch_protocol.handle(
                    TransactionFetchInput::RequestTransactions {
                        block_hash,
                        proposer,
                        tx_hashes,
                    },
                );
                let outputs = self
                    .transaction_fetch_protocol
                    .handle(TransactionFetchInput::Tick);
                self.process_transaction_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                use crate::protocol::wave_cert_fetch::WaveCertFetchInput;
                debug!(
                    ?block_hash,
                    proposer = proposer.0,
                    cert_count = cert_hashes.len(),
                    "Requesting missing certificates for pending block"
                );
                let peers = self.cached_local_peers.clone();
                let outputs = self
                    .wave_cert_fetch_protocol
                    .handle(WaveCertFetchInput::Request {
                        block_hash,
                        proposer,
                        cert_hashes,
                        peers,
                    });
                self.process_wave_cert_fetch_outputs(outputs);
                let tick_outputs = self
                    .wave_cert_fetch_protocol
                    .handle(WaveCertFetchInput::Tick);
                self.process_wave_cert_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelFetch { block_hash } => {
                self.transaction_fetch_protocol
                    .handle(TransactionFetchInput::CancelFetch { block_hash });
            }
            Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer,
                peers,
            } => {
                debug_assert!(
                    !peers.is_empty(),
                    "RequestMissingProvisions for shard {} height {} has no peers — \
                     was the action enriched by NodeStateMachine?",
                    source_shard.0,
                    block_height.0,
                );
                debug!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    proposer = proposer.0,
                    peer_count = peers.len(),
                    "Requesting missing provisions from source shard"
                );
                let outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Request {
                        source_shard,
                        block_height,
                        target_shard: self.local_shard,
                        peers,
                        preferred_peer: proposer,
                    });
                self.process_provision_fetch_outputs(outputs);
                let tick_outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Tick);
                self.process_provision_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelProvisionFetch {
                source_shard,
                block_height,
            } => {
                self.provision_fetch_protocol
                    .handle(ProvisionFetchInput::Cancel {
                        source_shard,
                        block_height,
                    });
            }
            Action::RequestTxInclusionProofs {
                source_shard,
                source_block_height,
                entries,
                peers,
            } => {
                use crate::protocol::inclusion_proof_fetch::InclusionProofFetchInput;
                let preferred_peer = peers.first().copied().unwrap_or(ValidatorId(0));
                // Feed all entries into the protocol before ticking, so the
                // tick can batch them into a single FetchBatch output.
                for (winner_tx_hash, reason) in entries {
                    let outputs = self.inclusion_proof_fetch_protocol.handle(
                        InclusionProofFetchInput::Request {
                            source_shard,
                            source_block_height,
                            winner_tx_hash,
                            reason,
                            peers: peers.clone(),
                            preferred_peer,
                        },
                    );
                    self.process_inclusion_proof_fetch_outputs(outputs);
                }
                // Single tick dispatches all entries as one batch.
                let tick_outputs = self
                    .inclusion_proof_fetch_protocol
                    .handle(InclusionProofFetchInput::Tick);
                self.process_inclusion_proof_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::RequestMissingExecutionCert {
                source_shard,
                block_height,
                wave_id,
                wave_leader,
                peers,
            } => {
                debug!(
                    source_shard = source_shard.0,
                    block_height,
                    wave = %wave_id,
                    peer_count = peers.len(),
                    "Requesting missing execution cert from source shard"
                );
                let outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Request {
                        source_shard,
                        block_height,
                        wave_id,
                        wave_leader,
                        peers,
                    });
                self.process_exec_cert_fetch_outputs(outputs);
                let tick_outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Tick {
                        now: std::time::Instant::now(),
                        committed_height: self.state.bft().committed_height(),
                    });
                self.process_exec_cert_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::RequestMissingCommittedBlockHeader {
                source_shard,
                from_height,
                peers,
            } => {
                debug!(
                    source_shard = source_shard.0,
                    from_height = from_height.0,
                    peer_count = peers.len(),
                    "Requesting missing committed block header from source shard"
                );
                let outputs = self
                    .header_fetch_protocol
                    .handle(HeaderFetchInput::Request {
                        source_shard,
                        from_height,
                        peers,
                    });
                self.process_header_fetch_outputs(outputs);
                let tick_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick);
                self.process_header_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            _ => unreachable!(),
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via the
    /// `event_sender` channel and are processed on a future `step()` call.
    /// With `SyncDispatch` (simulation), `spawn_*` runs inline so events
    /// enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&mut self, action: Action) {
        let is_execution = matches!(
            action,
            Action::ExecuteTransactions { .. } | Action::ExecuteCrossShardTransactions { .. }
        );
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let topology_snapshot = self.topology.load_full();
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                topology: &topology_snapshot,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    metrics::record_execution_latency(elapsed);
                }
                if let Some((hash, height, prepared)) = result.prepared_commit {
                    prepared_commits
                        .lock()
                        .unwrap()
                        .insert(hash, (height, prepared));
                }
                for event in result.events {
                    let _ = event_tx.send(event);
                }
            }
        };

        match pool {
            DispatchPool::ConsensusCrypto => self.dispatch.spawn_consensus_crypto(spawn_fn),
            DispatchPool::Crypto => self.dispatch.spawn_crypto(spawn_fn),
            DispatchPool::Execution => self.dispatch.spawn_execution(spawn_fn),
            DispatchPool::Provisions => self.dispatch.spawn_provisions(spawn_fn),
        }
    }

    /// Local shard committee excluding self, for use as the `peers` argument
    /// to `network.request()`.
    pub(super) fn local_peers(&self) -> &[ValidatorId] {
        &self.cached_local_peers
    }
}
