//! Sync, fetch, and provision fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::protocol::execution_cert_fetch::ExecCertFetchOutput;
use crate::protocol::finalized_wave_fetch::FinalizedWaveFetchOutput;
use crate::protocol::local_provision_fetch::LocalProvisionFetchOutput;
use crate::protocol::sync::{SyncInput, SyncOutput};
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::ValidatorId;
use std::sync::Arc;
use std::time::Duration;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Process `SyncProtocol` outputs internally.
    ///
    /// `DeliverBlock` and `SyncComplete` are fed directly to the state machine
    /// (no round-trip through the runner). `FetchBlock` uses the `Network` trait.
    pub(super) fn process_sync_outputs(&mut self, outputs: Vec<SyncOutput>) {
        // Snapshot the sync inventory once per batch so every FetchBlock in
        // this tick shares a consistent view of mempool / cert-cache /
        // provision-store membership. Built lazily: if the batch contains
        // no FetchBlock outputs the snapshot is skipped entirely.
        let mut inventory_cache: Option<hyperscale_messages::request::Inventory> = None;
        for output in outputs {
            match output {
                SyncOutput::FetchBlock {
                    height,
                    target_height,
                } => {
                    use hyperscale_messages::request::GetBlockRequest;
                    let inventory = inventory_cache
                        .get_or_insert_with(|| self.build_sync_inventory())
                        .clone();
                    let es = self.event_sender.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        None,
                        GetBlockRequest::new(height, target_height).with_inventory(inventory),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let block = resp.into_elided().map(Box::new);
                                let _ =
                                    es.send(NodeInput::SyncBlockResponseReceived { height, block });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                            }
                        }),
                    );
                }
                SyncOutput::DeliverBlock { certified } => {
                    metrics::record_sync_block_received_by_bft();
                    metrics::record_sync_block_submitted_for_verification();
                    self.feed_event(ProtocolEvent::SyncBlockReadyToApply {
                        certified: *certified,
                    });
                }
                SyncOutput::SyncComplete { height } => {
                    tracing::info!(
                        height = height.0,
                        "Sync protocol complete, resuming consensus"
                    );
                    // Tell BftCoordinator to exit sync mode. The previous
                    // BlockPersisted → on_block_persisted path was unreliable
                    // because BlockPersisted requires PreparedCommit which
                    // may not be available yet for synced blocks.
                    self.feed_event(ProtocolEvent::SyncProtocolComplete { height });
                }
            }
        }
    }

    /// Snapshot local mempool / finalized-wave cache / provision store
    /// into an [`Inventory`](hyperscale_messages::request::Inventory) so
    /// sync requests can tell the responder which bodies to elide.
    ///
    /// Each category degrades independently to `None` when the cached set
    /// exceeds the filter size cap — the responder treats absence as
    /// "send everything for this category."
    fn build_sync_inventory(&self) -> hyperscale_messages::request::Inventory {
        hyperscale_messages::request::Inventory {
            tx_have: self.state.mempool().tx_bloom_snapshot(),
            cert_have: self.state.execution().cert_bloom_snapshot(),
            provision_have: self.caches.provision_store.provision_bloom_snapshot(),
        }
    }

    /// Rehydrate an elided sync response into a full `CertifiedBlock` by
    /// resolving any omitted body against local caches. On miss returns
    /// the list of hashes the lookups couldn't resolve — the caller uses
    /// that list to issue a [`GetBlockTopUpRequest`] and retry.
    pub(super) fn rehydrate_elided_block(
        &self,
        elided: &hyperscale_messages::response::ElidedCertifiedBlock,
    ) -> Result<hyperscale_types::CertifiedBlock, hyperscale_messages::response::RehydrationMiss>
    {
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| mempool.get_transaction(h),
            |h| execution.get_finalized_wave_by_hash(h),
            |h| provision_store.get(h),
        )
    }

    /// Second-pass rehydration after a [`GetBlockTopUpResponse`] arrives:
    /// augment the local-cache lookups with the topup bodies so hashes
    /// that missed the first pass can be resolved. On any residual miss
    /// the block is dropped — the sync retry machinery refetches it from
    /// scratch (losing the inventory win for this block but making
    /// forward progress).
    pub(super) fn rehydrate_with_topup(
        &self,
        elided: &hyperscale_messages::response::ElidedCertifiedBlock,
        topup: hyperscale_messages::response::GetBlockTopUpResponse,
    ) -> Result<hyperscale_types::CertifiedBlock, hyperscale_messages::response::RehydrationMiss>
    {
        use std::collections::HashMap;

        let mut topup_tx: HashMap<_, _> = topup.transactions.into_iter().collect();
        let mut topup_cert: HashMap<_, _> = topup.certificates.into_iter().collect();
        let mut topup_prov: HashMap<_, _> = topup.provisions.into_iter().collect();
        let mempool = self.state.mempool();
        let execution = self.state.execution();
        let provision_store = &self.caches.provision_store;
        elided.try_rehydrate(
            |h| topup_tx.remove(h).or_else(|| mempool.get_transaction(h)),
            |h| {
                topup_cert
                    .remove(h)
                    .or_else(|| execution.get_finalized_wave_by_hash(h))
            },
            |h| topup_prov.remove(h).or_else(|| provision_store.get(h)),
        )
    }

    /// Fire off a [`GetBlockTopUpRequest`] targeting `miss`, stashing
    /// `elided` for rehydration when the response arrives. The closure
    /// translates the network callback into
    /// [`NodeInput::SyncBlockTopUpReceived`] / [`SyncBlockTopUpFailed`]
    /// so the state handler does the actual rehydration on the main
    /// thread.
    pub(super) fn issue_sync_topup(
        &mut self,
        height: hyperscale_types::BlockHeight,
        elided: Box<hyperscale_messages::response::ElidedCertifiedBlock>,
        miss: hyperscale_messages::response::RehydrationMiss,
    ) {
        use hyperscale_messages::request::GetBlockTopUpRequest;

        self.pending_block_topups.insert(height, elided);

        let req = GetBlockTopUpRequest::new(
            height,
            miss.missing_tx,
            miss.missing_cert,
            miss.missing_provision,
        );
        let es = self.event_sender.clone();
        let peers = self.local_peers();
        self.network.request(
            &peers,
            None,
            req,
            Box::new(move |result| match result {
                Ok(resp) => {
                    let _ = es.send(NodeInput::SyncBlockTopUpReceived {
                        height,
                        response: Some(Box::new(resp)),
                    });
                }
                Err(_) => {
                    let _ = es.send(NodeInput::SyncBlockTopUpFailed { height });
                }
            }),
        );
    }

    /// Run the post-rehydration sync pipeline: certificate-root check,
    /// then feed the block into the sync state machine (or pass through
    /// `None` for not-found). Shared between the main-response path and
    /// the top-up completion path.
    pub(super) fn deliver_sync_block(
        &mut self,
        height: hyperscale_types::BlockHeight,
        block: Option<Box<hyperscale_types::CertifiedBlock>>,
    ) {
        let certificate_root_valid = match block.as_deref() {
            Some(fetched) if !fetched.block.certificates().is_empty() => {
                let computed =
                    hyperscale_types::compute_certificate_root(fetched.block.certificates());
                let matches = computed == fetched.block.header().certificate_root;
                if !matches {
                    tracing::warn!(
                        height = height.0,
                        ?computed,
                        expected = ?fetched.block.header().certificate_root,
                        "Sync: certificate_root mismatch — rejecting response"
                    );
                }
                matches
            }
            _ => true, // Empty block or no block — no root to check
        };

        if certificate_root_valid {
            let outputs = self
                .sync_protocol
                .handle(SyncInput::BlockResponseReceived { height, block });
            self.process_sync_outputs(outputs);
        } else {
            let _ = self
                .event_sender
                .send(NodeInput::SyncBlockFetchFailed { height });
        }
    }

    /// Dispatch outputs from the per-block transaction fetch.
    pub(super) fn process_transaction_fetch_outputs(
        &self,
        outputs: Vec<
            crate::protocol::fetch::HashSetFetchOutput<
                crate::protocol::fetch::instances::transactions::Scope,
                hyperscale_types::TxHash,
            >,
        >,
    ) {
        use crate::protocol::fetch::HashSetFetchOutput;

        for output in outputs {
            match output {
                HashSetFetchOutput::Send {
                    scope: block_hash,
                    ids: tx_hashes,
                    peer: proposer,
                } => {
                    use hyperscale_messages::request::GetTransactionsRequest;
                    let es = self.event_sender.clone();
                    let hs = tx_hashes.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        Some(proposer),
                        GetTransactionsRequest::new(block_hash, tx_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let _ = es.send(NodeInput::TransactionReceived {
                                    block_hash,
                                    transactions: resp.into_transactions(),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::FetchTransactionsFailed {
                                    block_hash,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                HashSetFetchOutput::ScopeComplete { .. } => {
                    // Scope completion is purely an internal protocol signal;
                    // BFT readiness is driven by `TransactionFetchDelivered`.
                }
            }
        }
    }

    /// Process `LocalProvisionFetchProtocol` outputs.
    ///
    /// `Fetch` uses the Network trait to request batches from the proposer/local peers.
    /// `Deliver` feeds each batch into the state machine via `ProvisionsVerified`.
    pub(super) fn process_local_provision_fetch_outputs(
        &mut self,
        outputs: Vec<LocalProvisionFetchOutput>,
    ) {
        for output in outputs {
            match output {
                LocalProvisionFetchOutput::Fetch {
                    block_hash,
                    proposer,
                    batch_hashes,
                } => {
                    use hyperscale_messages::request::GetLocalProvisionsRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = batch_hashes.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        Some(proposer),
                        GetLocalProvisionsRequest::new(block_hash, batch_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let batches = resp.batches.into_iter().map(Arc::new).collect();
                                let _ = es.send(NodeInput::LocalProvisionReceived {
                                    block_hash: bh,
                                    batches,
                                    missing_hashes: resp.missing_hashes,
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::LocalProvisionsFetchFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                LocalProvisionFetchOutput::Deliver { batches } => {
                    // Route through the coordinator's receive path so each
                    // batch hits the per-target completeness check against
                    // the source header's `provision_tx_roots`. The content-
                    // hash match inside `LocalProvisionFetchProtocol` only
                    // proves the batch matches what the proposer committed
                    // to in BlockManifest; it doesn't catch a proposer that
                    // committed to an incomplete batch.
                    for provisions in batches {
                        self.feed_event(ProtocolEvent::ProvisionsReceived {
                            provisions: (*provisions).clone(),
                        });
                    }
                }
            }
        }
    }

    /// Process `ProvisionFetchProtocol` outputs.
    ///
    /// Dispatch outputs from the cross-shard provision fetch.
    ///
    /// On a successful response, the verified-shape provisions are fed
    /// straight into the state machine as `ProvisionsReceived` and the
    /// `ProvisionsVerified` continuation triggers admission.
    pub(super) fn process_provision_fetch_outputs(
        &self,
        outputs: Vec<
            crate::protocol::fetch::ScopeFetchOutput<
                crate::protocol::fetch::instances::provisions::Scope,
            >,
        >,
    ) {
        use crate::protocol::fetch::ScopeFetchOutput;

        for output in outputs {
            match output {
                ScopeFetchOutput::Send {
                    scope: (source_shard, block_height),
                    peer,
                } => {
                    use hyperscale_messages::request::GetProvisionsRequest;
                    let target_shard = self.local_shard;
                    let request = GetProvisionsRequest {
                        block_height,
                        target_shard,
                    };
                    let sender = self.event_sender.clone();
                    self.network.request(
                        &[peer],
                        None,
                        request,
                        Box::new(move |result| match result {
                            Ok(response) => match response.provisions {
                                Some(provisions) => {
                                    // A peer responded with a bundle scoped to the
                                    // wrong (source, target) pair — treat as a fetch
                                    // failure so the protocol tries the next peer.
                                    if provisions.source_shard != source_shard
                                        || provisions.target_shard != target_shard
                                        || provisions.block_height != block_height
                                    {
                                        tracing::warn!(
                                            expected_source = source_shard.0,
                                            got_source = provisions.source_shard.0,
                                            expected_target = target_shard.0,
                                            got_target = provisions.target_shard.0,
                                            expected_height = block_height.0,
                                            got_height = provisions.block_height.0,
                                            "Dropping provision fetch response: scope mismatch"
                                        );
                                        let _ = sender.send(NodeInput::ProvisionsFetchFailed {
                                            source_shard,
                                            block_height,
                                        });
                                        return;
                                    }
                                    if provisions.transactions.is_empty() {
                                        return;
                                    }
                                    let _ = sender.send(NodeInput::Protocol(
                                        ProtocolEvent::ProvisionsReceived { provisions },
                                    ));
                                }
                                None => {
                                    // Peer cannot serve (state version GC'd) → fail
                                    // so the protocol tries the next peer.
                                    let _ = sender.send(NodeInput::ProvisionsFetchFailed {
                                        source_shard,
                                        block_height,
                                    });
                                }
                            },
                            Err(_) => {
                                let _ = sender.send(NodeInput::ProvisionsFetchFailed {
                                    source_shard,
                                    block_height,
                                });
                            }
                        }),
                    );
                }
            }
        }
    }

    /// Process `ExecCertFetchProtocol` outputs.
    ///
    /// `Fetch` sends a single-peer network request for execution certificates.
    /// `Deliver` feeds certificates into the state machine via `ExecutionCertificateReceived`.
    pub(super) fn process_exec_cert_fetch_outputs(&mut self, outputs: Vec<ExecCertFetchOutput>) {
        for output in outputs {
            match output {
                ExecCertFetchOutput::Fetch {
                    source_shard,
                    block_height,
                    wave_ids,
                    peer,
                } => {
                    use hyperscale_messages::request::GetExecutionCertsRequest;
                    let request = GetExecutionCertsRequest {
                        block_height,
                        wave_ids,
                    };
                    let sender = self.event_sender.clone();
                    self.network.request(
                        &[peer],
                        None,
                        request,
                        Box::new(move |result| match result {
                            Ok(response) => match response.certificates {
                                Some(certs) if !certs.is_empty() => {
                                    let _ = sender.send(NodeInput::ExecCertFetchReceived {
                                        source_shard,
                                        block_height,
                                        certificates: certs,
                                    });
                                }
                                _ => {
                                    let _ = sender.send(NodeInput::ExecCertFetchFailed {
                                        source_shard,
                                        block_height,
                                    });
                                }
                            },
                            Err(_) => {
                                let _ = sender.send(NodeInput::ExecCertFetchFailed {
                                    source_shard,
                                    block_height,
                                });
                            }
                        }),
                    );
                }
                ExecCertFetchOutput::Deliver { certificates } => {
                    for cert in certificates {
                        self.feed_event(ProtocolEvent::ExecutionCertificateReceived { cert });
                    }
                }
            }
        }
    }

    /// Dispatch outputs from the cross-shard header fetch.
    ///
    /// On a successful response, the fetched header is fed straight into the
    /// state machine as a `RemoteBlockCommitted` event — the same path taken
    /// by gossiped headers — and the QC verification flow signals admission.
    pub(super) fn process_header_fetch_outputs(
        &self,
        outputs: Vec<
            crate::protocol::fetch::ScopeFetchOutput<
                crate::protocol::fetch::instances::headers::Scope,
            >,
        >,
    ) {
        use crate::protocol::fetch::ScopeFetchOutput;

        for output in outputs {
            match output {
                ScopeFetchOutput::Send {
                    scope: (source_shard, from_height),
                    peer,
                } => {
                    use hyperscale_messages::request::GetCommittedBlockHeaderRequest;
                    let request = GetCommittedBlockHeaderRequest {
                        shard: source_shard,
                        height: from_height,
                    };
                    let sender = self.event_sender.clone();
                    self.network.request(
                        &[peer],
                        None,
                        request,
                        Box::new(move |result| match result {
                            Ok(response) => match response.header {
                                Some(header) => {
                                    let _ = sender.send(NodeInput::Protocol(
                                        ProtocolEvent::RemoteBlockCommitted {
                                            committed_header: header,
                                            sender: ValidatorId(0),
                                        },
                                    ));
                                }
                                None => {
                                    let _ = sender.send(NodeInput::HeaderFetchFailed {
                                        source_shard,
                                        from_height,
                                    });
                                }
                            },
                            Err(_) => {
                                let _ = sender.send(NodeInput::HeaderFetchFailed {
                                    source_shard,
                                    from_height,
                                });
                            }
                        }),
                    );
                }
            }
        }
    }

    /// Set or cancel the periodic fetch tick timer based on protocol state.
    ///
    /// When the fetch protocol has pending work, a recurring timer fires
    /// `NodeInput::FetchTick` to retry deferred or failed fetch operations.
    /// When all fetches are complete, the timer is cancelled.
    /// Process `FinalizedWaveFetchProtocol` outputs.
    ///
    /// `Fetch` uses the Network trait to request finalized waves from the proposer/local peers.
    /// `Deliver` feeds each wave into the state machine for pending block completion.
    pub(super) fn process_finalized_wave_fetch_outputs(
        &mut self,
        outputs: Vec<FinalizedWaveFetchOutput>,
    ) {
        for output in outputs {
            match output {
                FinalizedWaveFetchOutput::Fetch {
                    block_hash,
                    peer,
                    wave_id_hashes,
                } => {
                    use hyperscale_messages::request::GetFinalizedWavesRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = wave_id_hashes.clone();
                    // Pin the request to the chosen peer (no fallback set):
                    // the protocol drives rotation itself, retrying with the
                    // next peer on `Failed` / empty `Received`. Letting the
                    // network's request manager rotate would defeat the
                    // protocol-level tried-peer tracking.
                    let pinned = [peer];
                    self.network.request(
                        &pinned,
                        Some(peer),
                        GetFinalizedWavesRequest::new(block_hash, wave_id_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let waves = resp.waves.into_iter().map(Arc::new).collect();
                                let _ = es.send(NodeInput::FinalizedWaveReceived {
                                    block_hash: bh,
                                    peer,
                                    waves,
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::FinalizedWaveFetchFailed {
                                    block_hash: bh,
                                    peer,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                FinalizedWaveFetchOutput::Deliver { waves } => {
                    for wave in waves {
                        self.feed_event(ProtocolEvent::FinalizedWaveFetchDelivered { wave });
                    }
                }
            }
        }
    }

    pub(super) fn update_fetch_tick_timer(&mut self) {
        let has_fetch_work = self.transaction_fetch.has_pending();
        let has_local_provision_work = self.local_provision_fetch_protocol.has_pending();
        let has_finalized_wave_work = self.finalized_wave_fetch_protocol.has_pending();
        let has_provision_work = self.provision_fetch.has_pending();
        let has_exec_cert_work = self.exec_cert_fetch_protocol.has_pending();
        let has_header_work = self.header_fetch.has_pending();
        if has_fetch_work
            || has_local_provision_work
            || has_finalized_wave_work
            || has_provision_work
            || has_exec_cert_work
            || has_header_work
        {
            self.pending_timer_ops.push(TimerOp::Set {
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            });
        } else {
            self.pending_timer_ops.push(TimerOp::Cancel {
                id: TimerId::FetchTick,
            });
        }
    }
}
