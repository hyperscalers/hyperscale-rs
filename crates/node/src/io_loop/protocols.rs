//! Sync, fetch, and provision fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::protocol::execution_cert_fetch::ExecCertFetchOutput;
use crate::protocol::inclusion_proof_fetch::InclusionProofFetchOutput;
use crate::protocol::provision_fetch::ProvisionFetchOutput;
use crate::protocol::sync::SyncOutput;
use crate::protocol::transaction_fetch::TransactionFetchOutput;
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::{BlockHeight, ValidatorId};
use std::time::Duration;

impl<S, N, D> IoLoop<S, N, D>
where
    S: ChainWriter + SubstateStore + ChainReader + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
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
                SyncOutput::FetchBlock { height } => {
                    use hyperscale_messages::request::GetBlockRequest;
                    let es = self.event_sender.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        peers,
                        None,
                        GetBlockRequest {
                            height: BlockHeight(height),
                        },
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let (block_opt, qc_opt, local_receipts, execution_certificates) =
                                    resp.into_parts();
                                let block = match (block_opt, qc_opt) {
                                    (Some(b), Some(q)) => Some((b, q)),
                                    _ => None,
                                };

                                // Validate that the peer included receipts.
                                // If the block has completed (non-aborted) wave certs,
                                // the peer must include receipts for the covered txs.
                                // Basic sanity check: completed wave certs → non-empty receipts.
                                // Full correctness is verified by state-root check later.
                                let has_certs = block
                                    .as_ref()
                                    .is_some_and(|(b, _)| !b.certificates.is_empty());
                                let receipts_complete = !has_certs || !local_receipts.is_empty();

                                if receipts_complete {
                                    let _ = es.send(NodeInput::SyncBlockResponseReceived {
                                        height,
                                        block: Box::new(block),
                                        local_receipts,
                                        execution_certificates,
                                    });
                                } else {
                                    tracing::warn!(
                                        height,
                                        "Sync peer sent block with incomplete receipts — \
                                         treating as fetch failure"
                                    );
                                    let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                                }
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::SyncBlockFetchFailed { height });
                            }
                        }),
                    );
                }
                SyncOutput::DeliverBlock { block, qc } => {
                    metrics::record_sync_block_received_by_bft();
                    metrics::record_sync_block_submitted_for_verification();
                    self.feed_event(ProtocolEvent::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                    });
                }
                SyncOutput::SyncComplete { height } => {
                    self.feed_event(ProtocolEvent::SyncComplete { height });
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
                        peers,
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

    /// Process ProvisionFetchProtocol outputs.
    ///
    /// `Fetch` uses the Network trait to send a single-peer request.
    /// `Deliver` feeds provisions into the state machine via `StateProvisionsReceived`.
    pub(super) fn process_provision_fetch_outputs(&mut self, outputs: Vec<ProvisionFetchOutput>) {
        for output in outputs {
            match output {
                ProvisionFetchOutput::Fetch {
                    source_shard,
                    block_height,
                    target_shard,
                    peer,
                } => {
                    use hyperscale_messages::request::GetProvisionsRequest;
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
                                    // Build a ProvisionBatch from the response.
                                    let proof = response.proof.unwrap_or_else(
                                        hyperscale_types::SubstateInclusionProof::dummy,
                                    );
                                    let transactions: Vec<hyperscale_types::TxEntries> = provisions
                                        .into_iter()
                                        .map(|p| hyperscale_types::TxEntries {
                                            tx_hash: p.transaction_hash,
                                            entries: (*p.entries).clone(),
                                        })
                                        .collect();
                                    let batch = hyperscale_types::ProvisionBatch {
                                        source_shard,
                                        block_height,
                                        proof,
                                        transactions,
                                    };
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
                        self.feed_event(ProtocolEvent::StateProvisionsReceived { batch });
                    }
                }
            }
        }
    }

    /// Process InclusionProofFetchProtocol outputs.
    ///
    /// `FetchBatch` sends a batched network request for multiple proofs from the same block.
    /// `Deliver` forwards the proof to the state machine for livelock processing.
    pub(super) fn process_inclusion_proof_fetch_outputs(
        &mut self,
        outputs: Vec<InclusionProofFetchOutput>,
    ) {
        for output in outputs {
            match output {
                InclusionProofFetchOutput::FetchBatch {
                    source_shard,
                    block_height,
                    entries,
                    peer,
                } => {
                    use hyperscale_messages::request::GetTxInclusionProofRequest;
                    let tx_hashes: Vec<_> = entries.iter().map(|(h, _)| *h).collect();
                    let request = GetTxInclusionProofRequest {
                        block_height,
                        tx_hashes,
                    };
                    let sender = self.event_sender.clone();
                    self.network.request(
                        &[peer],
                        None,
                        request,
                        Box::new(move |result| match result {
                            Ok(response) => {
                                // Build lookup map from response.
                                let proof_map: std::collections::HashMap<_, _> = response
                                    .proofs
                                    .into_iter()
                                    .map(|e| (e.tx_hash, e.proof))
                                    .collect();

                                // Fan out per-tx events.
                                for (winner_tx_hash, reason) in entries {
                                    match proof_map.get(&winner_tx_hash).and_then(|p| p.clone()) {
                                        Some(proof) => {
                                            let _ = sender.send(
                                                NodeInput::InclusionProofFetchReceived {
                                                    winner_tx_hash,
                                                    reason,
                                                    source_shard,
                                                    source_block_height: block_height,
                                                    proof,
                                                },
                                            );
                                        }
                                        None => {
                                            let _ =
                                                sender.send(NodeInput::InclusionProofFetchFailed {
                                                    winner_tx_hash,
                                                });
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                for (winner_tx_hash, _) in entries {
                                    let _ = sender.send(NodeInput::InclusionProofFetchFailed {
                                        winner_tx_hash,
                                    });
                                }
                            }
                        }),
                    );
                }
                InclusionProofFetchOutput::Deliver {
                    winner_tx_hash,
                    reason,
                    source_shard,
                    source_block_height,
                    proof,
                } => {
                    use hyperscale_core::InclusionProofFetchReason;
                    let actions = match reason {
                        InclusionProofFetchReason::Deferral { loser_tx_hash } => {
                            self.state.on_inclusion_proof_received(
                                winner_tx_hash,
                                loser_tx_hash,
                                source_shard,
                                source_block_height,
                                proof,
                            )
                        }
                    };
                    for action in actions {
                        self.process_action(action);
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
    pub(super) fn update_fetch_tick_timer(&mut self) {
        let status = self.transaction_fetch_protocol.status();
        let has_fetch_work = status.pending_tx_blocks > 0;
        let has_provision_work = self.provision_fetch_protocol.has_pending();
        let has_inclusion_proof_work = self.inclusion_proof_fetch_protocol.has_pending();
        let has_exec_cert_work = self.exec_cert_fetch_protocol.has_pending();
        let has_header_work = self.header_fetch_protocol.has_pending();
        if has_fetch_work
            || has_provision_work
            || has_inclusion_proof_work
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
