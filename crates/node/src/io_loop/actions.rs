//! Action processing and dispatch.

use super::{IoLoop, TimerOp};
use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::protocol::fetch::FetchInput;
use crate::protocol::provision_fetch::ProvisionFetchInput;
use crate::protocol::sync::SyncInput;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_messages::TransactionCertificateNotification;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::ValidatorId;
use std::sync::Arc;
use tracing::{debug, trace};

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
            Action::BroadcastTransactionCertificate { shard: _, gossip } => {
                self.network.notify(&self.cached_local_peers, &gossip);
            }
            Action::BroadcastCommittedBlockHeader { gossip } => {
                self.network.broadcast_global(&gossip);
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — batched
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastExecutionVote { shard, vote } => {
                self.accumulate_broadcast_vote(shard, vote);
            }
            Action::BroadcastExecutionCertificate {
                shard,
                certificate,
                recipients,
            } => {
                // Use the first recipients list for each shard within a batch window.
                // All certificates for the same shard should target the same committee,
                // so subsequent entries are expected to be identical.
                debug_assert!(
                    !self.cert_broadcast_recipients.contains_key(&shard)
                        || self.cert_broadcast_recipients[&shard] == recipients,
                    "BroadcastExecutionCertificate recipients changed within batch for shard {}",
                    shard.0
                );
                self.cert_broadcast_recipients
                    .entry(shard)
                    .or_insert(recipients);
                self.accumulate_broadcast_cert(shard, certificate);
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — batched (accumulated for batch dispatch)
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndAggregateExecutionVotes { tx_hash, votes } => {
                self.accumulate_execution_vote_verification((tx_hash, votes));
            }
            Action::VerifyExecutionCertificateSignature {
                certificate,
                public_keys,
            } => {
                self.accumulate_execution_certificate_verification(certificate, public_keys);
            }
            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                self.accumulate_cross_shard_execution(tx_hash, transaction, provisions);
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated work — immediate dispatch
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyCommitmentProof { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::BuildProposal { .. }
            | Action::AggregateExecutionCertificate { .. }
            | Action::VerifyStateProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::SpeculativeExecute { .. }
            | Action::FetchAndBroadcastProvisions { .. }
            | Action::StoreReceiptBundles { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage
            // ═══════════════════════════════════════════════════════════
            Action::PersistBlock { .. }
            | Action::PersistTransactionCertificate { .. }
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
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                if status.is_final() && submitted_locally {
                    let now = self.state.now();
                    let latency_secs = now.saturating_sub(added_at).as_secs_f64();
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
            | Action::RequestMissingProvisions { .. } => {
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
            Action::PersistTransactionCertificate { certificate } => {
                // Populate cert cache before persisting — serves peer fetch requests
                // from memory even if storage write hasn't completed.
                self.cert_cache
                    .insert(certificate.transaction_hash, Arc::new(certificate.clone()));
                self.storage.store_certificate(&certificate);
                // Notify local shard peers about cross-shard certificates.
                if certificate.shard_proofs.len() > 1 {
                    let msg = hyperscale_types::tx_cert_gossip_message(
                        self.local_shard,
                        &certificate.transaction_hash,
                    );
                    let sig = self.signing_key.sign_v1(&msg);
                    let gossip = TransactionCertificateNotification::new(
                        certificate,
                        self.validator_id,
                        sig,
                    );
                    self.network.notify(&self.cached_local_peers, &gossip);
                }
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
    /// defers the heavy JMT/metadata writes to [`flush_block_commits`].
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
        metrics::set_txs_with_commitment_proof(block.commitment_proofs.len());

        // Livelock metrics for deferrals in this block.
        for _deferral in &block.deferred {
            metrics::record_livelock_deferral();
            metrics::record_livelock_cycle_detected();
        }
        metrics::set_livelock_deferred_count(self.state.livelock().stats().pending_deferrals);

        // Feed committed height to sync protocol (just tracks progress,
        // doesn't need JMT state).
        let outputs = self
            .sync_protocol
            .handle(SyncInput::BlockCommitted { height: height.0 });
        self.process_sync_outputs(outputs);

        self.pending_block_commits.push((block, qc));
    }

    /// Flush accumulated block commits. If all blocks are empty (no
    /// certificates), commits synchronously. Otherwise spawns a single
    /// closure on the execution pool that commits all blocks sequentially,
    /// sending `StateCommitComplete` and `BlockCommitted` events after each.
    pub(super) fn flush_block_commits(&mut self) {
        let commits = std::mem::take(&mut self.pending_block_commits);
        if commits.is_empty() {
            return;
        }

        let has_non_empty = commits.iter().any(|(b, _)| !b.certificates.is_empty());

        if !has_non_empty {
            // All empty blocks — synchronous fast path.
            // Still advance JMT version so it matches block height.
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

        // Extract prepared commit handles for each block in the batch.
        let mut prepared_map = {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut map = Vec::with_capacity(commits.len());
            for (block, _) in &commits {
                map.push(cache.remove(&block.hash()));
            }
            map
        };

        let storage = Arc::clone(&self.storage);
        let event_tx = self.event_sender.clone();

        self.dispatch.spawn_execution(move || {
            for (i, (block, qc)) in commits.into_iter().enumerate() {
                let block_hash = block.hash();
                let height = block.header.height;

                let consensus = hyperscale_storage::ConsensusCommitData {
                    height,
                    hash: block_hash,
                    qc: qc.clone(),
                };

                // Always commit — even empty blocks advance the JMT version
                // to match block height, so provision lookups succeed.
                // Consensus metadata is folded into the same atomic write.
                let prepared = prepared_map[i].take();
                let result = if let Some(prepared) = prepared {
                    storage.commit_prepared_block(prepared, &block.certificates, Some(consensus))
                } else {
                    // No prepared commit — fallback with empty updates.
                    // The prepared path is the normal case; this only hits for
                    // empty blocks or when the prepared commit was stale.
                    let empty_updates = hyperscale_types::DatabaseUpdates::default();
                    storage.commit_block(
                        &empty_updates,
                        &block.certificates,
                        height.0,
                        Some(consensus),
                    )
                };

                ConsensusStore::prune_own_votes(&*storage, height.0);

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
                self.fetch_protocol.handle(FetchInput::RequestTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                });
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                self.fetch_protocol.handle(FetchInput::RequestCertificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                });
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelFetch { block_hash } => {
                self.fetch_protocol
                    .handle(FetchInput::CancelFetch { block_hash });
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
        let is_speculative = matches!(action, Action::SpeculativeExecute { .. });
        let is_execution = is_speculative || matches!(action, Action::ExecuteTransactions { .. });
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let signing_key = Arc::clone(&self.signing_key);
        let dispatch = self.dispatch.clone();
        let local_shard = self.local_shard;
        let validator_id = self.validator_id;
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                signing_key: &signing_key,
                local_shard,
                validator_id,
                dispatch: &dispatch,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    if is_speculative {
                        metrics::record_speculative_execution_latency(elapsed);
                    } else {
                        metrics::record_execution_latency(elapsed);
                    }
                }
                if let Some((hash, prepared)) = result.prepared_commit {
                    prepared_commits.lock().unwrap().insert(hash, prepared);
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
        }
    }

    /// Local shard committee excluding self, for use as the `peers` argument
    /// to `network.request()`.
    pub(super) fn local_peers(&self) -> &[ValidatorId] {
        &self.cached_local_peers
    }
}
