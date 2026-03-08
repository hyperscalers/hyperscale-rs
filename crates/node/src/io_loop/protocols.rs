//! Sync, fetch, and provision fetch protocol output processing.

use super::{IoLoop, TimerOp};
use crate::protocol::fetch::FetchOutput;
use crate::protocol::provision_fetch::ProvisionFetchOutput;
use crate::protocol::sync::SyncOutput;
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::BlockHeight;
use std::time::Duration;

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
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
                                let block = match (resp.block, resp.qc) {
                                    (Some(b), Some(q)) => Some((b, q)),
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

    /// Process FetchProtocol outputs.
    ///
    /// FetchTransactions/FetchCertificates use the Network trait to make requests.
    /// DeliverTransactions/DeliverCertificates feed events directly to the state machine.
    pub(super) fn process_fetch_outputs(&mut self, outputs: Vec<FetchOutput>) {
        for output in outputs {
            match output {
                FetchOutput::FetchTransactions {
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
                FetchOutput::FetchCertificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                } => {
                    use hyperscale_messages::request::GetCertificatesRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = cert_hashes.clone();
                    let peers = self.local_peers();
                    self.network.request(
                        peers,
                        Some(proposer),
                        GetCertificatesRequest::new(block_hash, cert_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let _ = es.send(NodeInput::CertificateReceived {
                                    block_hash: bh,
                                    certificates: resp.into_certificates(),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(NodeInput::FetchCertificatesFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                FetchOutput::DeliverTransactions {
                    block_hash,
                    transactions,
                } => {
                    self.feed_event(ProtocolEvent::TransactionFetchDelivered {
                        block_hash,
                        transactions,
                    });
                }
                FetchOutput::DeliverCertificates {
                    block_hash,
                    certificates,
                } => {
                    // Persist fetched certificates to storage so they survive restarts.
                    for cert in &certificates {
                        self.storage.store_certificate(cert);
                    }
                    self.feed_event(ProtocolEvent::CertificateFetchDelivered {
                        block_hash,
                        certificates,
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
                                Some(provisions) if !provisions.is_empty() => {
                                    let _ = sender.send(NodeInput::ProvisionFetchReceived {
                                        source_shard,
                                        block_height,
                                        provisions,
                                    });
                                }
                                Some(_) => {
                                    // Empty provisions — no matching transactions for
                                    // our shard at this block height. Treat as success
                                    // (removes the pending entry).
                                    let _ = sender.send(NodeInput::ProvisionFetchReceived {
                                        source_shard,
                                        block_height,
                                        provisions: vec![],
                                    });
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
                ProvisionFetchOutput::Deliver { provisions } => {
                    if !provisions.is_empty() {
                        self.feed_event(ProtocolEvent::StateProvisionsReceived { provisions });
                    }
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
        let status = self.fetch_protocol.status();
        let has_fetch_work = status.pending_tx_blocks > 0 || status.pending_cert_blocks > 0;
        let has_provision_work = self.provision_fetch_protocol.has_pending();
        if has_fetch_work || has_provision_work {
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
