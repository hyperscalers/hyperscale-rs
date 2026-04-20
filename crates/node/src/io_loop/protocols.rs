//! Sync, fetch, and provision fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::protocol::execution_cert_fetch::ExecCertFetchOutput;
use crate::protocol::finalized_wave_fetch::FinalizedWaveFetchOutput;
use crate::protocol::local_provision_fetch::LocalProvisionFetchOutput;
use crate::protocol::provision_fetch::ProvisionFetchOutput;
use crate::protocol::sync::SyncOutput;
use crate::protocol::transaction_fetch::TransactionFetchOutput;
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::{BlockHeight, ValidatorId};
use std::sync::Arc;
use std::time::Duration;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: ChainWriter
        + SubstateStore
        + hyperscale_storage::VersionedStore
        + ChainReader
        + hyperscale_storage::JmtTreeReader
        + Send
        + Sync,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Process SyncProtocol outputs internally.
    ///
    /// DeliverBlock and SyncComplete are fed directly to the state machine
    /// (no round-trip through the runner). FetchBlock uses the Network trait.
    pub(super) fn process_sync_outputs(&mut self, outputs: Vec<SyncOutput>) {
        for output in outputs {
            match output {
                SyncOutput::FetchBlock {
                    height,
                    target_height,
                } => {
                    use hyperscale_messages::request::GetBlockRequest;
                    let es = self.event_sender.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        None,
                        GetBlockRequest {
                            height: BlockHeight(height),
                            target_height: BlockHeight(target_height),
                        },
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let (block_opt, qc_opt, provision_hashes) = resp.into_parts();
                                let block = match (block_opt, qc_opt) {
                                    (Some(b), Some(q)) => Some((b, q, provision_hashes)),
                                    _ => None,
                                };
                                let _ = es.send(NodeInput::SyncBlockResponseReceived {
                                    height,
                                    block: Box::new(block),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                            }
                        }),
                    );
                }
                SyncOutput::DeliverBlock {
                    block,
                    qc,
                    provision_hashes,
                } => {
                    metrics::record_sync_block_received_by_bft();
                    metrics::record_sync_block_submitted_for_verification();
                    self.feed_event(ProtocolEvent::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                        provision_hashes,
                    });
                }
                SyncOutput::SyncComplete { height } => {
                    tracing::info!(height, "Sync protocol complete, resuming consensus");
                    // Tell BftState to exit sync mode. The previous
                    // BlockPersisted → on_block_persisted path was unreliable
                    // because BlockPersisted requires PreparedCommit which
                    // may not be available yet for synced blocks.
                    self.feed_event(ProtocolEvent::SyncProtocolComplete { height });
                }
            }
        }
    }

    /// Process TransactionFetchProtocol outputs.
    ///
    /// FetchTransactions uses the Network trait to make requests.
    /// DeliverTransactions feeds events directly to the state machine.
    pub(super) fn process_transaction_fetch_outputs(
        &mut self,
        outputs: Vec<TransactionFetchOutput>,
    ) {
        for output in outputs {
            match output {
                TransactionFetchOutput::FetchTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                } => {
                    use hyperscale_messages::request::GetTransactionsRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = tx_hashes.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        Some(proposer),
                        GetTransactionsRequest::new(block_hash, tx_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let _ = es.send(NodeInput::TransactionReceived {
                                    block_hash: bh,
                                    transactions: resp.into_transactions(),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::FetchTransactionsFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                TransactionFetchOutput::DeliverTransactions {
                    block_hash,
                    transactions,
                } => {
                    self.feed_event(ProtocolEvent::TransactionFetchDelivered {
                        block_hash,
                        transactions,
                    });
                }
            }
        }
    }

    /// Process LocalProvisionFetchProtocol outputs.
    ///
    /// `Fetch` uses the Network trait to request batches from the proposer/local peers.
    /// `Deliver` feeds each batch into the state machine via `ProvisionVerified`.
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
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::LocalProvisionFetchFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                LocalProvisionFetchOutput::Deliver { batches } => {
                    for batch in batches {
                        self.feed_event(ProtocolEvent::ProvisionVerified { batch });
                    }
                }
            }
        }
    }

    /// Process ProvisionFetchProtocol outputs.
    ///
    /// `Fetch` uses the Network trait to send a single-peer request.
    /// `Deliver` feeds provisions into the state machine via `StateProvisionReceived`.
    pub(super) fn process_provision_fetch_outputs(&mut self, outputs: Vec<ProvisionFetchOutput>) {
        for output in outputs {
            match output {
                ProvisionFetchOutput::Fetch {
                    source_shard,
                    block_height,
                    target_shard,
                    peer,
                } => {
                    use hyperscale_messages::request::GetProvisionRequest;
                    let request = GetProvisionRequest {
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
                                    // Build a Provision from the response.
                                    let proof = response.proof.unwrap_or_else(
                                        hyperscale_types::MerkleInclusionProof::dummy,
                                    );
                                    let transactions: Vec<hyperscale_types::TxEntries> = provisions
                                        .into_iter()
                                        .map(|p| hyperscale_types::TxEntries {
                                            tx_hash: p.transaction_hash,
                                            entries: (*p.entries).clone(),
                                            target_nodes: vec![],
                                        })
                                        .collect();
                                    let batch = hyperscale_types::Provision::new(
                                        source_shard,
                                        block_height,
                                        proof,
                                        transactions,
                                    );
                                    let _ =
                                        sender.send(NodeInput::ProvisionFetchReceived { batch });
                                }
                                None => {
                                    // Peer cannot serve (state version GC'd) → fail
                                    // so the protocol tries the next peer.
                                    let _ = sender.send(NodeInput::ProvisionFetchFailed {
                                        source_shard,
                                        block_height,
                                    });
                                }
                            },
                            Err(_) => {
                                let _ = sender.send(NodeInput::ProvisionFetchFailed {
                                    source_shard,
                                    block_height,
                                });
                            }
                        }),
                    );
                }
                ProvisionFetchOutput::Deliver { batch } => {
                    if !batch.transactions.is_empty() {
                        self.feed_event(ProtocolEvent::StateProvisionReceived { batch });
                    }
                }
            }
        }
    }

    /// Process ExecCertFetchProtocol outputs.
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

    /// Process HeaderFetchProtocol outputs.
    ///
    /// `Fetch` sends a single-peer network request for committed block headers.
    /// `Deliver` feeds the header into the state machine via `RemoteBlockCommitted`.
    pub(super) fn process_header_fetch_outputs(
        &mut self,
        outputs: Vec<crate::protocol::header_fetch::HeaderFetchOutput>,
    ) {
        use crate::protocol::header_fetch::HeaderFetchOutput;

        for output in outputs {
            match output {
                HeaderFetchOutput::Fetch {
                    source_shard,
                    from_height,
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
                                    let _ = sender.send(NodeInput::HeaderFetchReceived {
                                        source_shard,
                                        from_height,
                                        header,
                                    });
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
                HeaderFetchOutput::Deliver { header } => {
                    // Feed fetched header into the state machine as RemoteBlockCommitted.
                    // The coordinator will verify and fan out as normal.
                    // Use ValidatorId(0) as placeholder sender — the QC is what matters.
                    self.feed_event(ProtocolEvent::RemoteBlockCommitted {
                        committed_header: *header,
                        sender: ValidatorId(0),
                    });
                }
            }
        }
    }

    /// Set or cancel the periodic fetch tick timer based on protocol state.
    ///
    /// When the fetch protocol has pending work, a recurring timer fires
    /// `NodeInput::FetchTick` to retry deferred or failed fetch operations.
    /// When all fetches are complete, the timer is cancelled.
    /// Process FinalizedWaveFetchProtocol outputs.
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
                    proposer,
                    wave_id_hashes,
                } => {
                    use hyperscale_messages::request::GetFinalizedWavesRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = wave_id_hashes.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        &peers,
                        Some(proposer),
                        GetFinalizedWavesRequest::new(block_hash, wave_id_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let waves = resp.waves.into_iter().map(Arc::new).collect();
                                let _ = es.send(NodeInput::FinalizedWaveReceived {
                                    block_hash: bh,
                                    waves,
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::FinalizedWaveFetchFailed {
                                    block_hash: bh,
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
        let status = self.transaction_fetch_protocol.status();
        let has_fetch_work = status.pending_tx_blocks > 0;
        let has_local_provision_work = self.local_provision_fetch_protocol.has_pending();
        let has_finalized_wave_work = self.finalized_wave_fetch_protocol.has_pending();
        let has_provision_work = self.provision_fetch_protocol.has_pending();
        let has_exec_cert_work = self.exec_cert_fetch_protocol.has_pending();
        let has_header_work = self.header_fetch_protocol.has_pending();
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
