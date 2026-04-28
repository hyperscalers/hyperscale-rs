//! Sync and fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::protocol::sync::{SyncInput, SyncOutput};
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::{Network, ResponseVerdict};
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
                        Box::new(move |result| {
                            match result {
                                Ok(resp) => {
                                    let block = resp.into_elided().map(Box::new);
                                    let _ = es.send(NodeInput::SyncBlockResponseReceived {
                                        height,
                                        block,
                                    });
                                }
                                Err(_) => {
                                    let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                                }
                            }
                            // Sync's "peer doesn't have this height" is ambiguous
                            // (peer may simply be behind us) — never Reject.
                            ResponseVerdict::Accept
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
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let _ = es.send(NodeInput::SyncBlockTopUpReceived {
                        height,
                        response: Some(Box::new(resp)),
                    });
                } else {
                    let _ = es.send(NodeInput::SyncBlockTopUpFailed { height });
                }
                ResponseVerdict::Accept
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
            let outputs = self.sync_protocol.handle(SyncInput::BlockResponseReceived {
                height,
                block,
                now: std::time::Instant::now(),
            });
            self.process_sync_outputs(outputs);
        } else {
            let _ = self
                .event_sender
                .send(NodeInput::SyncBlockFetchFailed { height });
        }
    }

    /// Dispatch outputs from the transaction fetch.
    pub(super) fn process_transaction_fetch_outputs(
        &self,
        outputs: Vec<crate::protocol::fetch::IdFetchOutput<hyperscale_types::TxHash>>,
    ) {
        use crate::protocol::fetch::IdFetchOutput;
        use hyperscale_messages::request::GetTransactionsRequest;

        for output in outputs {
            let IdFetchOutput::Send {
                ids: tx_hashes,
                peer: proposer,
            } = output;
            let es = self.event_sender.clone();
            let hs = tx_hashes.clone();
            let peers = self.local_peers();
            self.network.request(
                &peers,
                Some(proposer),
                GetTransactionsRequest::new(tx_hashes),
                Box::new(move |result| {
                    if let Ok(resp) = result {
                        let txs = resp.into_transactions();
                        let returned = txs.len();
                        let requested = hs.len();
                        let _ = es.send(NodeInput::TransactionReceived { transactions: txs });
                        // Peer returned strictly fewer txs than requested →
                        // they don't have part of the set we asked for.
                        if returned < requested {
                            ResponseVerdict::Reject
                        } else {
                            ResponseVerdict::Accept
                        }
                    } else {
                        let _ = es.send(NodeInput::FetchTransactionsFailed { hashes: hs });
                        ResponseVerdict::Accept
                    }
                }),
            );
        }
    }

    /// Dispatch outputs from the local-provision fetch.
    pub(super) fn process_local_provision_fetch_outputs(
        &self,
        outputs: Vec<crate::protocol::fetch::IdFetchOutput<hyperscale_types::ProvisionHash>>,
    ) {
        use crate::protocol::fetch::IdFetchOutput;
        use hyperscale_messages::request::GetLocalProvisionsRequest;

        for output in outputs {
            let IdFetchOutput::Send {
                ids: batch_hashes,
                peer: proposer,
            } = output;
            let es = self.event_sender.clone();
            let hs = batch_hashes.clone();
            let peers = self.local_peers();
            self.network.request(
                &peers,
                Some(proposer),
                GetLocalProvisionsRequest::new(batch_hashes),
                Box::new(move |result| {
                    if let Ok(resp) = result {
                        let had_misses = !resp.missing_hashes.is_empty();
                        let batches = resp.batches.into_iter().map(Arc::new).collect();
                        let _ = es.send(NodeInput::LocalProvisionReceived {
                            batches,
                            missing_hashes: resp.missing_hashes,
                        });
                        if had_misses {
                            ResponseVerdict::Reject
                        } else {
                            ResponseVerdict::Accept
                        }
                    } else {
                        let _ = es.send(NodeInput::LocalProvisionsFetchFailed { hashes: hs });
                        ResponseVerdict::Accept
                    }
                }),
            );
        }
    }

    /// Dispatch outputs from the cross-shard provision fetch.
    ///
    /// On a successful response, the verified-shape provisions are fed
    /// straight into the state machine as `ProvisionsReceived` and the
    /// `ProvisionsAdmitted` continuation triggers admission.
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
                        Box::new(move |result| {
                            let Ok(response) = result else {
                                let _ = sender.send(NodeInput::ProvisionsFetchFailed {
                                    source_shard,
                                    block_height,
                                });
                                return ResponseVerdict::Accept;
                            };
                            let Some(provisions) = response.provisions else {
                                // Peer cannot serve (state version GC'd).
                                let _ = sender.send(NodeInput::ProvisionsFetchFailed {
                                    source_shard,
                                    block_height,
                                });
                                return ResponseVerdict::Reject;
                            };
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
                                return ResponseVerdict::Reject;
                            }
                            if provisions.transactions.is_empty() {
                                return ResponseVerdict::Reject;
                            }
                            let _ = sender.send(NodeInput::Protocol(
                                ProtocolEvent::ProvisionsReceived { provisions },
                            ));
                            ResponseVerdict::Accept
                        }),
                    );
                }
            }
        }
    }

    /// Dispatch outputs from the cross-shard execution-cert fetch.
    pub(super) fn process_exec_cert_fetch_outputs(
        &self,
        outputs: Vec<crate::protocol::fetch::IdFetchOutput<hyperscale_types::WaveId>>,
    ) {
        use crate::protocol::fetch::IdFetchOutput;
        use hyperscale_messages::request::GetExecutionCertsRequest;

        for output in outputs {
            let IdFetchOutput::Send {
                ids: wave_ids,
                peer,
            } = output;
            let failed_ids = wave_ids.clone();
            let request = GetExecutionCertsRequest { wave_ids };
            let sender = self.event_sender.clone();
            self.network.request(
                &[peer],
                None,
                request,
                Box::new(move |result| {
                    if let Ok(response) = result {
                        match response.certificates {
                            Some(certs) if !certs.is_empty() => {
                                let _ = sender.send(NodeInput::ExecutionCertsReceived {
                                    certificates: certs,
                                });
                                ResponseVerdict::Accept
                            }
                            _ => {
                                let _ = sender
                                    .send(NodeInput::ExecCertFetchFailed { hashes: failed_ids });
                                ResponseVerdict::Reject
                            }
                        }
                    } else {
                        let _ = sender.send(NodeInput::ExecCertFetchFailed { hashes: failed_ids });
                        ResponseVerdict::Accept
                    }
                }),
            );
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
                        Box::new(move |result| {
                            let Ok(response) = result else {
                                let _ = sender.send(NodeInput::HeaderFetchFailed {
                                    source_shard,
                                    from_height,
                                });
                                return ResponseVerdict::Accept;
                            };
                            let Some(header) = response.header else {
                                let _ = sender.send(NodeInput::HeaderFetchFailed {
                                    source_shard,
                                    from_height,
                                });
                                return ResponseVerdict::Reject;
                            };
                            let _ = sender.send(NodeInput::Protocol(
                                ProtocolEvent::RemoteBlockCommitted {
                                    committed_header: header,
                                    sender: ValidatorId(0),
                                },
                            ));
                            ResponseVerdict::Accept
                        }),
                    );
                }
            }
        }
    }

    /// Dispatch outputs from the finalized-wave fetch.
    ///
    /// Pin each request to the chosen peer (the protocol drives rotation
    /// itself; letting `Network::request` rotate would defeat per-peer
    /// tried-set tracking).
    pub(super) fn process_finalized_wave_fetch_outputs(
        &self,
        outputs: Vec<crate::protocol::fetch::IdFetchOutput<hyperscale_types::WaveIdHash>>,
    ) {
        use crate::protocol::fetch::IdFetchOutput;
        use hyperscale_messages::request::GetFinalizedWavesRequest;

        for output in outputs {
            let IdFetchOutput::Send {
                ids: wave_id_hashes,
                peer,
            } = output;
            let es = self.event_sender.clone();
            let hs = wave_id_hashes.clone();
            let pinned = [peer];
            self.network.request(
                &pinned,
                Some(peer),
                GetFinalizedWavesRequest::new(wave_id_hashes),
                Box::new(move |result| {
                    if let Ok(resp) = result {
                        let returned = resp.waves.len();
                        let requested = hs.len();
                        let waves = resp.waves.into_iter().map(Arc::new).collect();
                        let _ = es.send(NodeInput::FinalizedWaveReceived { waves });
                        // Peer didn't have all the waves we asked for.
                        if returned < requested {
                            ResponseVerdict::Reject
                        } else {
                            ResponseVerdict::Accept
                        }
                    } else {
                        let _ = es.send(NodeInput::FinalizedWaveFetchFailed { hashes: hs });
                        ResponseVerdict::Accept
                    }
                }),
            );
        }
    }

    pub(super) fn update_fetch_tick_timer(&mut self) {
        let any_pending = self.transaction_fetch.has_pending()
            || self.local_provision_fetch.has_pending()
            || self.finalized_wave_fetch.has_pending()
            || self.provision_fetch.has_pending()
            || self.exec_cert_fetch.has_pending()
            || self.header_fetch.has_pending()
            || self.sync_protocol.has_deferred();
        let op = if any_pending {
            TimerOp::Set {
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            }
        } else {
            TimerOp::Cancel {
                id: TimerId::FetchTick,
            }
        };
        self.pending_timer_ops.push(op);
    }
}
