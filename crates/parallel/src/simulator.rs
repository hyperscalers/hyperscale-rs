//! Parallel simulator using rayon for CPU parallelism.
//!
//! Processes nodes in a step-based loop, using rayon to parallelize
//! event processing across CPU cores. This gives us:
//! - Deterministic simulated time (we control when time advances)
//! - CPU parallelism (rayon processes nodes on multiple cores)
//! - No scheduling issues (no tokio task coordination needed)
//!
//! Each step:
//! 1. Advance time by 1ms and fire any due timers
//! 2. Process events (single pass - no drain loop)
//! 3. Collect and route messages
//! 4. Process fetch requests (sync, transactions, certificates)
//! 5. Collect status updates
//!
//! Events enqueued during processing wait until the next step.

use crate::cache::SimulationCache;
use crate::config::ParallelConfig;
use crate::metrics::SimulationReport;
use crate::router::Destination;
use hyperscale_bft::{BftConfig, RecoveredState};
use hyperscale_core::{Action, Event, OutboundMessage, StateMachine, TimerId};
use hyperscale_node::NodeStateMachine;
use hyperscale_simulation::{NetworkTrafficAnalyzer, SimStorage, SimulatedNetwork};
use hyperscale_storage::{CommitStore, ConsensusStore};
use hyperscale_types::{
    batch_verify_bls_same_message, bls_keypair_from_seed, verify_bls12381_v1, zero_bls_signature,
    Block, BlockHeader, BlockHeight, BlockVote, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, CommitmentProof, Hash, NodeId, QuorumCertificate, RoutableTransaction,
    ShardGroupId, SignerBitfield, StateCertificate, StateVoteBlock, StaticTopology, Topology,
    TransactionDecision, TransactionStatus, ValidatorId, ValidatorInfo, ValidatorSet, VotePower,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace};

/// A fetch request emitted by a node that needs data from another node.
///
/// These are collected by the ParallelSimulator and processed with network
/// latency simulation, similar to how outbound messages are handled.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Request to sync blocks from peers.
    Sync {
        /// Target height to sync to.
        target_height: u64,
    },
    /// Request to fetch missing transactions from proposer.
    Transactions {
        /// Block hash the transactions are needed for.
        block_hash: Hash,
        /// Proposer who has the transactions.
        proposer: ValidatorId,
        /// Hashes of missing transactions.
        tx_hashes: Vec<Hash>,
    },
    /// Request to fetch missing certificates from proposer.
    Certificates {
        /// Block hash the certificates are needed for.
        block_hash: Hash,
        /// Proposer who has the certificates.
        proposer: ValidatorId,
        /// Hashes of missing certificates (transaction hashes).
        cert_hashes: Vec<Hash>,
    },
}

/// A pending fetch response waiting for delivery at a scheduled time.
#[derive(Debug)]
struct PendingFetchResponse {
    /// When this response should be delivered (simulated time).
    delivery_time: Duration,
    /// Recipient node index.
    recipient: u32,
    /// The event to deliver.
    event: Event,
}

/// Wrapper for ordering PendingFetchResponse by delivery_time.
#[derive(Debug)]
struct PendingFetchResponseOrd(PendingFetchResponse);

impl PartialEq for PendingFetchResponseOrd {
    fn eq(&self, other: &Self) -> bool {
        self.0.delivery_time == other.0.delivery_time
    }
}

impl Eq for PendingFetchResponseOrd {}

impl PartialOrd for PendingFetchResponseOrd {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingFetchResponseOrd {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.delivery_time.cmp(&other.0.delivery_time)
    }
}

/// Queue for pending fetch responses.
struct FetchResponseQueue {
    responses: BinaryHeap<std::cmp::Reverse<PendingFetchResponseOrd>>,
}

impl FetchResponseQueue {
    fn new() -> Self {
        Self {
            responses: BinaryHeap::new(),
        }
    }

    fn push(&mut self, resp: PendingFetchResponse) {
        self.responses
            .push(std::cmp::Reverse(PendingFetchResponseOrd(resp)));
    }

    /// Pop all responses ready for delivery at the given time.
    fn pop_ready(&mut self, now: Duration) -> Vec<PendingFetchResponse> {
        let mut ready = Vec::new();
        while let Some(std::cmp::Reverse(PendingFetchResponseOrd(resp))) = self.responses.peek() {
            if resp.delivery_time <= now {
                let std::cmp::Reverse(PendingFetchResponseOrd(resp)) =
                    self.responses.pop().unwrap();
                ready.push(resp);
            } else {
                break;
            }
        }
        ready
    }
}

/// A pending message waiting for delivery at a scheduled time.
#[derive(Debug)]
struct PendingMessage {
    /// When this message should be delivered (simulated time).
    delivery_time: Duration,
    /// Recipient node index.
    recipient: u32,
    /// The message to deliver.
    message: Arc<OutboundMessage>,
}

/// Wrapper for BinaryHeap that orders by earliest delivery time first.
#[derive(Debug)]
struct MessageQueue {
    /// Messages ordered by delivery_time (earliest first via Reverse ordering).
    messages: BinaryHeap<std::cmp::Reverse<PendingMessageOrd>>,
}

/// Wrapper for ordering PendingMessage by delivery_time.
#[derive(Debug)]
struct PendingMessageOrd(PendingMessage);

impl PartialEq for PendingMessageOrd {
    fn eq(&self, other: &Self) -> bool {
        self.0.delivery_time == other.0.delivery_time
    }
}

impl Eq for PendingMessageOrd {}

impl PartialOrd for PendingMessageOrd {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingMessageOrd {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.delivery_time.cmp(&other.0.delivery_time)
    }
}

impl MessageQueue {
    fn new() -> Self {
        Self {
            messages: BinaryHeap::new(),
        }
    }

    fn push(&mut self, msg: PendingMessage) {
        self.messages
            .push(std::cmp::Reverse(PendingMessageOrd(msg)));
    }

    /// Pop all messages ready for delivery at the given time.
    fn pop_ready(&mut self, now: Duration) -> Vec<PendingMessage> {
        let mut ready = Vec::new();
        while let Some(std::cmp::Reverse(PendingMessageOrd(msg))) = self.messages.peek() {
            if msg.delivery_time <= now {
                let std::cmp::Reverse(PendingMessageOrd(msg)) = self.messages.pop().unwrap();
                ready.push(msg);
            } else {
                break;
            }
        }
        ready
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.messages.len()
    }
}

/// A simulated node in the parallel simulator.
pub struct SimNode {
    index: u32,
    state: NodeStateMachine,
    storage: SimStorage,
    /// Signing key for state vote signing (cloned from state machine).
    signing_key: Bls12381G1PrivateKey,
    /// Pending inbound messages from other nodes.
    inbound_queue: VecDeque<Arc<OutboundMessage>>,
    /// Pending internal events (timer fires, crypto results, etc.)
    internal_queue: VecDeque<Event>,
    /// Pending transaction submissions.
    tx_queue: VecDeque<Event>,
    /// Outbound messages to be routed after processing.
    outbound_messages: Vec<(Destination, Arc<OutboundMessage>)>,
    /// Fetch requests to be processed by ParallelSimulator.
    fetch_requests: Vec<FetchRequest>,
    /// Transaction status updates to report.
    status_updates: Vec<(Hash, TransactionStatus)>,
    /// Pending timers: timer_id -> fire_time
    pending_timers: HashMap<TimerId, Duration>,
    /// Simulated time for this node.
    simulated_time: Duration,
    /// Outbound events that need to be broadcast to shard peers.
    outbound_events: Vec<(ShardGroupId, Event)>,
    /// Precomputed commit handles from `prepare_block_commit`, keyed by block hash.
    /// Populated by `VerifyStateRoot` / `BuildProposal`, consumed by `EmitCommittedBlock`.
    prepared_commits: HashMap<Hash, <SimStorage as CommitStore>::PreparedCommit>,
}

impl SimNode {
    /// Create a new simulated node.
    pub fn new(
        index: u32,
        state: NodeStateMachine,
        storage: SimStorage,
        signing_key: Bls12381G1PrivateKey,
    ) -> Self {
        Self {
            index,
            state,
            storage,
            signing_key,
            inbound_queue: VecDeque::new(),
            internal_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            outbound_messages: Vec::new(),
            fetch_requests: Vec::new(),
            status_updates: Vec::new(),
            pending_timers: HashMap::new(),
            simulated_time: Duration::ZERO,
            outbound_events: Vec::new(),
            prepared_commits: HashMap::new(),
        }
    }

    /// Submit a transaction to this node.
    pub fn submit_transaction(&mut self, event: Event) {
        self.tx_queue.push_back(event);
    }

    /// Deliver an inbound message to this node.
    pub fn deliver_message(&mut self, message: Arc<OutboundMessage>) {
        self.inbound_queue.push_back(message);
    }

    /// Process pending events (single pass, no drain loop).
    ///
    /// Processes all events that were queued before this call, but events
    /// enqueued during processing wait until the next step. This models
    /// realistic timing where internal event propagation takes some time.
    ///
    /// Returns the number of events processed.
    pub fn process_events(&mut self, cache: &SimulationCache) -> usize {
        let mut processed = 0;

        // Snapshot queue lengths - only process events queued before this call
        let internal_count = self.internal_queue.len();
        let inbound_count = self.inbound_queue.len();
        let tx_count = self.tx_queue.len();

        // Process internal events first (highest priority)
        for _ in 0..internal_count {
            if let Some(event) = self.internal_queue.pop_front() {
                self.handle_event(event, cache);
                processed += 1;
            }
        }

        // Process inbound messages (batched messages expand to multiple events)
        for _ in 0..inbound_count {
            if let Some(msg) = self.inbound_queue.pop_front() {
                for event in msg.to_received_events() {
                    self.handle_event(event, cache);
                }
                processed += 1;
            }
        }

        // Process transaction submissions
        for _ in 0..tx_count {
            if let Some(event) = self.tx_queue.pop_front() {
                self.handle_event(event, cache);
                processed += 1;
            }
        }

        processed
    }

    /// Take outbound messages (clears the buffer).
    pub fn take_outbound_messages(&mut self) -> Vec<(Destination, Arc<OutboundMessage>)> {
        std::mem::take(&mut self.outbound_messages)
    }

    /// Take fetch requests (clears the buffer).
    pub fn take_fetch_requests(&mut self) -> Vec<FetchRequest> {
        std::mem::take(&mut self.fetch_requests)
    }

    /// Take status updates (clears the buffer).
    pub fn take_status_updates(&mut self) -> Vec<(Hash, TransactionStatus)> {
        std::mem::take(&mut self.status_updates)
    }

    /// Advance simulated time and fire any due timers.
    pub fn advance_time(&mut self, new_time: Duration) {
        self.simulated_time = new_time;
        self.state.set_time(new_time);

        // Check for timers that should fire
        let due_timers: Vec<TimerId> = self
            .pending_timers
            .iter()
            .filter(|(_, fire_time)| **fire_time <= new_time)
            .map(|(id, _)| id.clone())
            .collect();

        for timer_id in due_timers {
            self.pending_timers.remove(&timer_id);
            let event = match timer_id {
                TimerId::Proposal => Event::ProposalTimer,
                TimerId::Cleanup => Event::CleanupTimer,
                TimerId::GlobalConsensus => Event::GlobalConsensusTimer,
            };
            self.internal_queue.push_back(event);
        }
    }

    /// Handle a single event.
    fn handle_event(&mut self, event: Event, cache: &SimulationCache) {
        // For SubmitTransaction events, gossip to all relevant shards first.
        // This mirrors production behavior where the runner handles gossip,
        // not the state machine.
        if let Event::SubmitTransaction { ref tx } = event {
            let topology = self.state.topology();
            let gossip =
                hyperscale_messages::TransactionGossip::from_arc(std::sync::Arc::clone(tx));
            for shard in topology.all_shards_for_transaction(tx) {
                let message = OutboundMessage::TransactionGossip(Box::new(gossip.clone()));
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }
        }

        // Handle TransactionCertificateReceived directly in runner (like production).
        // Verify and persist before notifying state machine.
        if let Event::TransactionCertificateReceived { ref certificate } = event {
            let tx_hash = certificate.transaction_hash;

            // Skip if already in storage
            if self.storage.get_certificate(&tx_hash).is_some() {
                return;
            }

            // In parallel simulation, we trust certificates (skip BLS verification for speed).
            // Production verifies signatures before persisting.
            // Store certificate WITHOUT committing state writes. State writes are
            // only applied when the certificate is included in a committed block
            // (via PersistTransactionCertificate). This matches production and sim runner.
            self.storage.store_certificate(certificate);

            // Notify state machine to cancel local building and add to finalized
            let actions = self.state.handle(Event::GossipedCertificateVerified {
                certificate: certificate.clone(),
            });
            for action in actions {
                self.execute_action(action, cache);
            }
            return;
        }

        // Process through state machine (time is set by advance_time)
        let actions = self.state.handle(event);

        // Execute actions
        for action in actions {
            self.execute_action(action, cache);
        }
    }

    /// Execute an action from the state machine.
    fn execute_action(&mut self, action: Action, cache: &SimulationCache) {
        match action {
            Action::BroadcastToShard { shard, message } => {
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }

            Action::BroadcastGlobal { message } => {
                self.outbound_messages
                    .push((Destination::Global, Arc::new(message)));
            }

            // Domain-specific execution broadcasts - convert to batch OutboundMessage
            Action::BroadcastStateVote { shard, vote } => {
                let batch = hyperscale_messages::StateVoteBatch::single(vote);
                let message = OutboundMessage::StateVoteBatch(batch);
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }

            Action::BroadcastStateCertificate { shard, certificate } => {
                let batch = hyperscale_messages::StateCertificateBatch::single(
                    Arc::unwrap_or_clone(certificate),
                );
                let message = OutboundMessage::StateCertificateBatch(batch);
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }

            Action::BroadcastStateProvision { shard, provision } => {
                let batch = hyperscale_messages::StateProvisionBatch::single(provision);
                let message = OutboundMessage::StateProvisionBatch(batch);
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }

            Action::SetTimer { id, duration } => {
                // Schedule timer to fire at current_time + duration
                let fire_time = self.simulated_time + duration;
                self.pending_timers.insert(id, fire_time);
            }

            Action::CancelTimer { id } => {
                self.pending_timers.remove(&id);
            }

            Action::EnqueueInternal { event } => {
                self.internal_queue.push_back(event);
            }

            Action::EmitTransactionStatus {
                tx_hash, status, ..
            } => {
                if status.is_final() {
                    self.status_updates.push((tx_hash, status));
                }
            }

            // Block vote verification + QC building - synchronous (uses deferred verification)
            Action::VerifyAndBuildQuorumCertificate {
                block_hash,
                height,
                round,
                parent_block_hash,
                signing_message,
                votes_to_verify,
                verified_votes: already_verified,
                total_voting_power,
            } => {
                // Start with already-verified votes (e.g., our own vote)
                let mut all_verified: Vec<(usize, BlockVote, u64)> = already_verified;
                let mut all_signatures: Vec<Bls12381G2Signature> =
                    all_verified.iter().map(|(_, v, _)| v.signature).collect();

                // Batch verify all new signatures (same message optimization)
                let signatures: Vec<Bls12381G2Signature> = votes_to_verify
                    .iter()
                    .map(|(_, v, _, _)| v.signature)
                    .collect();
                let public_keys: Vec<Bls12381G1PublicKey> =
                    votes_to_verify.iter().map(|(_, _, pk, _)| *pk).collect();

                let batch_valid = if votes_to_verify.is_empty() {
                    true
                } else {
                    batch_verify_bls_same_message(&signing_message, &signatures, &public_keys)
                };

                if batch_valid {
                    // Happy path: all new signatures valid, add them to verified set
                    for (idx, vote, _, power) in votes_to_verify {
                        all_signatures.push(vote.signature);
                        all_verified.push((idx, vote, power));
                    }
                } else {
                    // Some invalid - verify individually
                    for (idx, vote, pk, power) in &votes_to_verify {
                        if verify_bls12381_v1(&signing_message, pk, &vote.signature) {
                            all_signatures.push(vote.signature);
                            all_verified.push((*idx, vote.clone(), *power));
                        }
                    }
                }

                let verified_power: u64 = all_verified.iter().map(|(_, _, power)| power).sum();

                // Check if we have quorum with all verified votes
                if VotePower::has_quorum(verified_power, total_voting_power)
                    && !all_signatures.is_empty()
                {
                    let qc = Bls12381G2Signature::aggregate(&all_signatures, true)
                        .ok()
                        .map(|aggregated_signature| {
                            let mut sorted_votes = all_verified.clone();
                            sorted_votes.sort_by_key(|(idx, _, _)| *idx);

                            let max_idx = sorted_votes
                                .iter()
                                .map(|(idx, _, _)| *idx)
                                .max()
                                .unwrap_or(0);
                            let mut signers = SignerBitfield::new(max_idx + 1);
                            let mut timestamp_weight_sum: u128 = 0;

                            for (idx, vote, power) in &sorted_votes {
                                signers.set(*idx);
                                timestamp_weight_sum += vote.timestamp as u128 * *power as u128;
                            }

                            let weighted_timestamp_ms = if verified_power == 0 {
                                0
                            } else {
                                (timestamp_weight_sum / verified_power as u128) as u64
                            };

                            QuorumCertificate {
                                block_hash,
                                height,
                                parent_block_hash,
                                round,
                                aggregated_signature,
                                signers,
                                voting_power: VotePower(verified_power),
                                weighted_timestamp_ms,
                            }
                        });

                    let return_votes = if qc.is_none() { all_verified } else { vec![] };
                    self.internal_queue
                        .push_back(Event::QuorumCertificateResult {
                            block_hash,
                            qc,
                            verified_votes: return_votes,
                        });
                } else {
                    // No quorum - return all verified votes
                    self.internal_queue
                        .push_back(Event::QuorumCertificateResult {
                            block_hash,
                            qc: None,
                            verified_votes: all_verified,
                        });
                }
            }

            Action::VerifyAndAggregateProvisions {
                tx_hash,
                source_shard,
                block_height,
                block_timestamp,
                entries,
                provisions,
                public_keys,
                committee_size,
            } => {
                // All provisions for the same (tx, source_shard) sign the SAME message.
                // Happy path: aggregate verification with single pairing check.
                let signatures: Vec<Bls12381G2Signature> =
                    provisions.iter().map(|p| p.signature).collect();
                let message = provisions
                    .first()
                    .map(|p| p.signing_message())
                    .unwrap_or_default();

                let topology = self.state.topology();
                let all_valid = batch_verify_bls_same_message(&message, &signatures, &public_keys);

                let (verified_provisions, commitment_proof) = if all_valid {
                    // Fast path: all valid
                    let mut signers = SignerBitfield::new(committee_size);
                    for provision in &provisions {
                        if let Some(idx) =
                            topology.committee_index_for_shard(source_shard, provision.validator_id)
                        {
                            signers.set(idx);
                        }
                    }

                    let aggregated_signature = Bls12381G2Signature::aggregate(&signatures, true)
                        .unwrap_or_else(|_| zero_bls_signature());

                    let proof = CommitmentProof::new(
                        tx_hash,
                        source_shard,
                        signers,
                        aggregated_signature,
                        block_height,
                        block_timestamp,
                        entries,
                    );

                    (provisions, Some(proof))
                } else {
                    // Slow path: find valid signatures individually
                    let mut verified = Vec::new();
                    let mut valid_sigs = Vec::new();
                    let mut signer_indices = Vec::new();

                    for (provision, pk) in provisions.iter().zip(public_keys.iter()) {
                        if verify_bls12381_v1(&message, pk, &provision.signature) {
                            verified.push(provision.clone());
                            valid_sigs.push(provision.signature);
                            if let Some(idx) = topology
                                .committee_index_for_shard(source_shard, provision.validator_id)
                            {
                                signer_indices.push(idx);
                            }
                        }
                    }

                    let proof = if !valid_sigs.is_empty() {
                        let mut signers = SignerBitfield::new(committee_size);
                        for idx in &signer_indices {
                            signers.set(*idx);
                        }

                        let aggregated_signature =
                            Bls12381G2Signature::aggregate(&valid_sigs, true)
                                .unwrap_or_else(|_| zero_bls_signature());

                        Some(CommitmentProof::new(
                            tx_hash,
                            source_shard,
                            signers,
                            aggregated_signature,
                            block_height,
                            block_timestamp,
                            entries,
                        ))
                    } else {
                        None
                    };

                    (verified, proof)
                };

                self.internal_queue
                    .push_back(Event::ProvisionsVerifiedAndAggregated {
                        tx_hash,
                        source_shard,
                        verified_provisions,
                        commitment_proof,
                    });
            }

            Action::AggregateStateCertificate {
                tx_hash,
                shard,
                merkle_root,
                votes,
                read_nodes,
                voting_power,
                committee_size,
            } => {
                // Deduplicate votes by validator
                let mut seen_validators = std::collections::HashSet::new();
                let unique_votes: Vec<_> = votes
                    .iter()
                    .filter(|vote| seen_validators.insert(vote.validator))
                    .collect();

                // Aggregate BLS signatures
                let bls_signatures: Vec<Bls12381G2Signature> =
                    unique_votes.iter().map(|vote| vote.signature).collect();

                let aggregated_signature = if !bls_signatures.is_empty() {
                    Bls12381G2Signature::aggregate(&bls_signatures, true)
                        .unwrap_or_else(|_| zero_bls_signature())
                } else {
                    zero_bls_signature()
                };

                // Create signer bitfield
                // Use topology to get correct committee index for the shard.
                let topology = self.state.topology();
                let mut signers = SignerBitfield::new(committee_size);
                for vote in &unique_votes {
                    if let Some(idx) = topology.committee_index_for_shard(shard, vote.validator) {
                        signers.set(idx);
                    }
                }

                let success = votes.first().map(|v| v.success).unwrap_or(false);

                let certificate = StateCertificate {
                    transaction_hash: tx_hash,
                    shard_group_id: shard,
                    read_nodes,
                    state_writes: vec![],
                    outputs_merkle_root: merkle_root,
                    success,
                    aggregated_signature,
                    signers,
                    voting_power: voting_power.0,
                };

                self.internal_queue
                    .push_back(Event::StateCertificateAggregated {
                        tx_hash,
                        certificate,
                    });
            }

            Action::VerifyAndAggregateStateVotes { tx_hash, votes } => {
                // Batch verify state votes - deferred verification pattern.
                let verified_votes: Vec<(StateVoteBlock, u64)> = votes
                    .into_iter()
                    .filter_map(|(vote, public_key, voting_power)| {
                        let msg = vote.signing_message();
                        let valid = verify_bls12381_v1(&msg, &public_key, &vote.signature);
                        if valid {
                            Some((vote, voting_power))
                        } else {
                            None
                        }
                    })
                    .collect();
                self.internal_queue
                    .push_back(Event::StateVotesVerifiedAndAggregated {
                        tx_hash,
                        verified_votes,
                    });
            }

            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                let msg = certificate.signing_message();
                let signer_keys: Vec<_> = public_keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| certificate.signers.is_set(*i))
                    .map(|(_, pk)| *pk)
                    .collect();
                let valid =
                    cache.verify_aggregated(&signer_keys, &msg, &certificate.aggregated_signature);
                self.internal_queue
                    .push_back(Event::StateCertificateSignatureVerified { certificate, valid });
            }

            Action::VerifyQcSignature {
                qc,
                public_keys,
                block_hash,
                signing_message,
            } => {
                let signer_keys: Vec<_> = public_keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| qc.signers.is_set(*i))
                    .map(|(_, pk)| *pk)
                    .collect();
                let valid = if signer_keys.is_empty() {
                    false
                } else {
                    cache.verify_aggregated(
                        &signer_keys,
                        &signing_message,
                        &qc.aggregated_signature,
                    )
                };
                self.internal_queue
                    .push_back(Event::QcSignatureVerified { block_hash, valid });
            }

            Action::VerifyCycleProof {
                block_hash,
                deferral_index,
                cycle_proof,
                public_keys,
                signing_message,
                quorum_threshold,
            } => {
                let valid = if public_keys.is_empty() {
                    false
                } else {
                    let sig_valid = cache.verify_aggregated(
                        &public_keys,
                        &signing_message,
                        &cycle_proof.winner_commitment.aggregated_signature,
                    );
                    sig_valid
                        && cycle_proof.winner_commitment.signer_count() as u64 >= quorum_threshold
                };
                self.internal_queue.push_back(Event::CycleProofVerified {
                    block_hash,
                    deferral_index,
                    valid,
                });
            }

            Action::VerifyStateRoot {
                block_hash,
                parent_state_root,
                expected_root,
                certificates,
            } => {
                let local_shard = self.state.shard();
                let (computed_root, prepared) = self.storage.prepare_block_commit(
                    parent_state_root,
                    &certificates,
                    local_shard,
                );

                let valid = computed_root == expected_root;
                if valid {
                    self.prepared_commits.insert(block_hash, prepared);
                }

                self.internal_queue
                    .push_back(Event::StateRootVerified { block_hash, valid });
            }

            Action::VerifyTransactionRoot {
                block_hash,
                expected_root,
                retry_transactions,
                priority_transactions,
                transactions,
            } => {
                // Compute transaction merkle root from all sections
                let computed_root = hyperscale_types::compute_transaction_root(
                    &retry_transactions,
                    &priority_transactions,
                    &transactions,
                );

                let valid = computed_root == expected_root;

                self.internal_queue
                    .push_back(Event::TransactionRootVerified { block_hash, valid });
            }

            Action::BuildProposal {
                proposer,
                height,
                round,
                parent_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_state_version,
                retry_transactions,
                priority_transactions,
                transactions,
                certificates,
                commitment_proofs,
                deferred,
                aborted,
            } => {
                use hyperscale_types::{Block, BlockHeader};

                // In parallel simulation, JMT commits are synchronous so compute immediately.
                let local_shard = self.state.shard();
                use hyperscale_storage::SubstateStore;
                let current_root = self.storage.state_root_hash();

                // Check if JMT is ready for certificates
                let jmt_ready = current_root == parent_state_root;
                let include_certs = jmt_ready && !certificates.is_empty();

                let (state_root, state_version, certs_to_include, prepared) = if include_certs {
                    // JMT ready - compute speculative root from certificates
                    let (root, prepared) = self.storage.prepare_block_commit(
                        parent_state_root,
                        &certificates,
                        local_shard,
                    );

                    let version = parent_state_version + certificates.len() as u64;
                    (root, version, certificates, Some(prepared))
                } else {
                    // Either no certificates, or JMT not ready - inherit parent state
                    (parent_state_root, parent_state_version, vec![], None)
                };

                // Compute transaction root from all transaction sections
                let transaction_root = hyperscale_types::compute_transaction_root(
                    &retry_transactions,
                    &priority_transactions,
                    &transactions,
                );

                // Build the block
                let header = BlockHeader {
                    height,
                    parent_hash,
                    parent_qc,
                    proposer,
                    timestamp,
                    round,
                    is_fallback,
                    state_root,
                    state_version,
                    transaction_root,
                };

                let block = Block {
                    header,
                    retry_transactions,
                    priority_transactions,
                    transactions,
                    certificates: certs_to_include,
                    deferred,
                    aborted,
                    commitment_proofs,
                };

                let block_hash = block.hash();

                if let Some(prepared) = prepared {
                    self.prepared_commits.insert(block_hash, prepared);
                }

                self.internal_queue.push_back(Event::ProposalBuilt {
                    height,
                    round,
                    block: std::sync::Arc::new(block),
                    block_hash,
                });
            }

            // Note: BuildQuorumCertificate replaced by VerifyAndBuildQuorumCertificate above

            // Note: View change verification actions removed - using HotStuff-2 implicit rounds

            // Transaction execution - cached per shard using real Radix engine.
            // All validators in a shard execute the same block, so results are cached.
            // After execution, sign votes and send StateVoteReceived (matches production runner).
            Action::ExecuteTransactions {
                block_hash,
                transactions,
                ..
            } => {
                let shard_id = self.state.shard().0;
                let local_shard = self.state.shard();
                let validator_id = self.state.topology().local_validator_id();
                let results = cache.execute_block(shard_id, block_hash, &transactions);

                // Sign votes and send StateVoteReceived for each result
                for result in results {
                    let message = hyperscale_types::exec_vote_message(
                        &result.transaction_hash,
                        &result.state_root,
                        local_shard,
                        result.success,
                    );
                    let signature = self.signing_key.sign_v1(&message);

                    let vote = StateVoteBlock {
                        transaction_hash: result.transaction_hash,
                        shard_group_id: local_shard,
                        state_root: result.state_root,
                        success: result.success,
                        state_writes: result.writes.clone(),
                        validator: validator_id,
                        signature,
                    };

                    // Broadcast to shard peers
                    self.outbound_events
                        .push((local_shard, Event::StateVoteReceived { vote: vote.clone() }));

                    // Handle locally
                    self.internal_queue
                        .push_back(Event::StateVoteReceived { vote });
                }
            }

            // Speculative execution - execute AND sign inline (same as ExecuteTransactions)
            Action::SpeculativeExecute {
                block_hash,
                transactions,
            } => {
                let shard_id = self.state.shard().0;
                let local_shard = self.state.shard();
                let validator_id = self.state.topology().local_validator_id();

                let execution_results = cache.execute_block(shard_id, block_hash, &transactions);

                // Sign and broadcast votes for each result (same as ExecuteTransactions)
                let mut tx_hashes = Vec::new();
                for result in execution_results {
                    tx_hashes.push(result.transaction_hash);

                    let message = hyperscale_types::exec_vote_message(
                        &result.transaction_hash,
                        &result.state_root,
                        local_shard,
                        result.success,
                    );
                    let signature = self.signing_key.sign_v1(&message);

                    let vote = StateVoteBlock {
                        transaction_hash: result.transaction_hash,
                        shard_group_id: local_shard,
                        state_root: result.state_root,
                        success: result.success,
                        state_writes: result.writes.clone(),
                        validator: validator_id,
                        signature,
                    };

                    // Broadcast to shard peers
                    self.outbound_events
                        .push((local_shard, Event::StateVoteReceived { vote: vote.clone() }));

                    // Handle locally
                    self.internal_queue
                        .push_back(Event::StateVoteReceived { vote });
                }

                // Notify state machine (for cache tracking)
                self.internal_queue
                    .push_back(Event::SpeculativeExecutionComplete {
                        block_hash,
                        tx_hashes,
                    });
            }

            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                // Execute single cross-shard transaction, sign vote and send StateVoteReceived
                // (matches production runner pattern)
                let shard_id = self.state.shard().0;
                let local_shard = self.state.shard();
                let validator_id = self.state.topology().local_validator_id();
                let topology = self.state.topology();
                let is_local_node = |node_id: &NodeId| -> bool {
                    topology.shard_for_node_id(node_id) == local_shard
                };
                let result = cache.execute_cross_shard(
                    shard_id,
                    tx_hash,
                    &transaction,
                    &provisions,
                    is_local_node,
                );

                // Sign vote and send StateVoteReceived
                let message = hyperscale_types::exec_vote_message(
                    &result.transaction_hash,
                    &result.state_root,
                    local_shard,
                    result.success,
                );
                let signature = self.signing_key.sign_v1(&message);

                let vote = StateVoteBlock {
                    transaction_hash: result.transaction_hash,
                    shard_group_id: local_shard,
                    state_root: result.state_root,
                    success: result.success,
                    state_writes: result.writes.clone(),
                    validator: validator_id,
                    signature,
                };

                // Broadcast to shard peers
                self.outbound_events
                    .push((local_shard, Event::StateVoteReceived { vote: vote.clone() }));

                // Handle locally
                self.internal_queue
                    .push_back(Event::StateVoteReceived { vote });
            }

            Action::ComputeMerkleRoot { tx_hash, .. } => {
                self.internal_queue.push_back(Event::MerkleRootComputed {
                    tx_hash,
                    root: Hash::ZERO,
                });
            }

            // Storage actions
            Action::PersistBlock { block, qc } => {
                let height = block.header.height;
                self.storage.put_block(height, &block, &qc);
            }

            Action::PersistTransactionCertificate { certificate } => {
                let local_shard = self.state.shard();

                // Only store certificate metadata; state writes are committed
                // at EmitCommittedBlock time via commit_prepared_block/commit_block.
                self.storage.store_certificate(&certificate);

                // Commit to the shared cache storage so future executions see the state
                let writes = certificate
                    .shard_proofs
                    .get(&local_shard)
                    .map(|proof| proof.state_writes.as_slice())
                    .unwrap_or(&[]);
                if !writes.is_empty() {
                    cache.commit_writes(local_shard.0, writes);
                }

                // After persisting, gossip certificate to same-shard peers.
                // This ensures other validators have the certificate before the proposer
                // includes it in a block, avoiding fetch delays.
                let gossip =
                    hyperscale_messages::TransactionCertificateGossip::new(certificate.clone());
                let message = OutboundMessage::TransactionCertificateGossip(gossip);
                self.outbound_messages
                    .push((Destination::Shard(local_shard), Arc::new(message)));
            }

            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard,
                message,
            } => {
                // Persist vote first (BFT safety)
                self.storage.put_own_vote(height.0, round, block_hash);

                // Then broadcast (just like BroadcastToShard)
                self.outbound_messages
                    .push((Destination::Shard(shard), Arc::new(message)));
            }

            Action::FetchStateEntries { tx_hash, nodes } => {
                // Fetch state entries from the shared cache storage (not node's local storage)
                // This is necessary because genesis state is only in the cache storage
                let shard_id = self.state.shard().0;
                let entries = cache.fetch_state_entries(shard_id, &nodes);
                self.internal_queue
                    .push_back(Event::StateEntriesFetched { tx_hash, entries });
            }

            Action::FetchBlock { height } => {
                let block = self.storage.get_block(height).map(|(b, _)| b);
                self.internal_queue
                    .push_back(Event::BlockFetched { height, block });
            }

            Action::FetchChainMetadata => {
                let height = self.storage.committed_height();
                let (hash, qc) = self
                    .storage
                    .get_block(height)
                    .map(|(b, q)| (Some(b.hash()), Some(q)))
                    .unwrap_or((None, None));
                self.internal_queue
                    .push_back(Event::ChainMetadataFetched { height, hash, qc });
            }

            Action::EmitCommittedBlock { block, qc: _ } => {
                let local_shard = self.state.shard();
                let block_hash = block.hash();

                let result = if let Some(prepared) = self.prepared_commits.remove(&block_hash) {
                    self.storage.commit_prepared_block(prepared)
                } else {
                    self.storage.commit_block(&block.certificates, local_shard)
                };

                debug!(
                    node = self.index,
                    height = block.header.height.0,
                    state_version = result.state_version,
                    "Block committed"
                );
            }

            // Global Consensus Actions (TODO: implement when GlobalConsensusState exists)
            Action::ProposeGlobalBlock { .. }
            | Action::BroadcastGlobalBlockVote { .. }
            | Action::TransitionEpoch { .. }
            | Action::MarkValidatorReady { .. }
            | Action::InitiateShardSplit { .. }
            | Action::CompleteShardSplit { .. }
            | Action::InitiateShardMerge { .. }
            | Action::CompleteShardMerge { .. }
            | Action::PersistEpochConfig { .. }
            | Action::FetchEpochConfig { .. } => {
                // Not yet implemented - will be handled by GlobalConsensusState
            }

            // Runner I/O actions - emit as fetch requests for ParallelSimulator to handle
            Action::StartSync { target_height, .. } => {
                self.fetch_requests
                    .push(FetchRequest::Sync { target_height });
            }

            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                self.fetch_requests.push(FetchRequest::Transactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                });
            }

            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                self.fetch_requests.push(FetchRequest::Certificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                });
            }

            Action::CancelFetch { .. } => {
                // In parallel simulator, fetches are handled synchronously in process_fetch_requests,
                // so there's nothing to cancel. This action is only relevant for production.
            }
        }
    }
}

/// Parallel simulator using rayon for multi-core CPU parallelism.
///
/// Processes nodes synchronously in a step-based loop, using rayon to
/// parallelize event processing across CPU cores. Each step:
/// 1. Advances simulated time and fires due timers
/// 2. Delivers messages that have reached their delivery time
/// 3. Processes all pending events on all nodes (in parallel)
/// 4. Collects outbound messages and schedules them with network latency
/// 5. Collects transaction status updates
pub struct ParallelSimulator {
    config: ParallelConfig,
    nodes: Vec<SimNode>,
    /// Shard membership: shard -> list of node indices
    shard_members: HashMap<ShardGroupId, Vec<u32>>,
    /// Simulated time
    simulated_time: Duration,
    /// Metrics
    submitted: AtomicU64,
    completed: AtomicU64,
    rejected: AtomicU64,
    /// In-flight transaction hashes
    in_flight: HashSet<Hash>,
    /// Latencies in microseconds
    latencies: Vec<u64>,
    /// Submission times for latency calculation (simulated time)
    submission_times: HashMap<Hash, Duration>,
    /// Optional traffic analyzer for bandwidth estimation.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,
    /// Pending messages waiting for delivery (with network latency).
    pending_messages: MessageQueue,
    /// Pending fetch responses waiting for delivery (with network latency).
    pending_fetch_responses: FetchResponseQueue,
    /// Sync targets: node_index -> target_height
    sync_targets: HashMap<u32, u64>,
    /// Simulated network for latency/loss/partition modeling.
    network: SimulatedNetwork,
    /// RNG for network latency jitter (seeded for determinism).
    rng: ChaCha8Rng,
    /// Shared cache for signature verifications and execution results.
    simulation_cache: Arc<SimulationCache>,
}

impl ParallelSimulator {
    /// Create a new parallel simulator.
    pub fn new(config: ParallelConfig) -> Self {
        let rng = ChaCha8Rng::seed_from_u64(config.seed.wrapping_add(0xDEAD_BEEF));
        let network = SimulatedNetwork::new(config.network.clone());
        Self {
            config,
            nodes: Vec::new(),
            shard_members: HashMap::new(),
            simulated_time: Duration::ZERO,
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            in_flight: HashSet::new(),
            latencies: Vec::new(),
            submission_times: HashMap::new(),
            traffic_analyzer: None,
            pending_messages: MessageQueue::new(),
            pending_fetch_responses: FetchResponseQueue::new(),
            sync_targets: HashMap::new(),
            network,
            rng,
            simulation_cache: Arc::new(SimulationCache::new()),
        }
    }

    /// Enable network traffic analysis for bandwidth estimation.
    pub fn enable_traffic_analysis(&mut self) {
        if self.traffic_analyzer.is_none() {
            self.traffic_analyzer = Some(Arc::new(NetworkTrafficAnalyzer::new()));
        }
    }

    /// Check if traffic analysis is enabled.
    pub fn has_traffic_analysis(&self) -> bool {
        self.traffic_analyzer.is_some()
    }

    /// Get a bandwidth report from the traffic analyzer.
    ///
    /// Returns `None` if traffic analysis is not enabled.
    pub fn traffic_report(&self) -> Option<hyperscale_simulation::BandwidthReport> {
        self.traffic_analyzer
            .as_ref()
            .map(|analyzer| analyzer.generate_report(self.simulated_time, self.nodes.len()))
    }

    /// Initialize the simulator (create nodes, run genesis).
    pub fn initialize(&mut self) {
        let num_shards = self.config.num_shards;
        let validators_per_shard = self.config.validators_per_shard as u32;
        let total_nodes = num_shards * self.config.validators_per_shard;

        info!(
            num_shards,
            validators_per_shard, total_nodes, "Initializing parallel simulator"
        );

        // Generate keys deterministically
        let seed = self.config.seed;
        let keys: Vec<Bls12381G1PrivateKey> = (0..total_nodes)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();
        let public_keys: Vec<Bls12381G1PublicKey> = keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..total_nodes)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: public_keys[i],
                voting_power: 1,
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build shard committees
        let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * self.config.validators_per_shard;
            let shard_end = shard_start + self.config.validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId(i as u64))
                .collect();
            shard_committees.insert(shard, committee);
            self.shard_members
                .insert(shard, (shard_start..shard_end).map(|i| i as u32).collect());
        }

        // Create nodes
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * self.config.validators_per_shard;

            for v in 0..self.config.validators_per_shard {
                let node_index = shard_start + v;
                let validator_id = ValidatorId(node_index as u64);

                let topology: Arc<dyn Topology> = Arc::new(StaticTopology::with_shard_committees(
                    validator_id,
                    shard,
                    num_shards as u64,
                    &global_validator_set,
                    shard_committees.clone(),
                ));

                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = keys[node_index].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let signing_key2 =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let state = NodeStateMachine::new(
                    node_index as u32,
                    topology,
                    signing_key,
                    BftConfig::default(),
                    RecoveredState::default(),
                );

                let storage = SimStorage::new();
                let node = SimNode::new(node_index as u32, state, storage, signing_key2);
                self.nodes.push(node);
            }
        }

        // Initialize Radix Engine executors for each shard
        for shard_id in 0..num_shards {
            self.simulation_cache.init_shard(shard_id as u64);
        }
        info!(
            num_shards,
            "Radix Engine executors initialized for all shards"
        );

        // Initialize genesis for each shard
        for shard_id in 0..num_shards {
            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * self.config.validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            };
            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            let shard_start = shard_id * self.config.validators_per_shard;
            let shard_end = shard_start + self.config.validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index];
                let actions = node.state.initialize_genesis(genesis_block.clone());
                for action in actions {
                    node.execute_action(action, &self.simulation_cache);
                }
            }
        }

        info!("Genesis initialized for all shards");
    }

    /// Initialize with funded accounts at genesis.
    ///
    /// Like `initialize()`, but also funds the specified accounts at genesis time.
    /// Each shard only receives balances for accounts belonging to that shard.
    ///
    /// `shard_balances` is a function that returns the balances for a given shard.
    pub fn initialize_with_balances<F>(&mut self, shard_balances: F)
    where
        F: Fn(
            u64,
        ) -> Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    {
        let num_shards = self.config.num_shards;
        let validators_per_shard = self.config.validators_per_shard as u32;
        let total_nodes = num_shards * self.config.validators_per_shard;

        info!(
            num_shards,
            validators_per_shard,
            total_nodes,
            "Initializing parallel simulator with funded accounts"
        );

        // Generate keys deterministically
        let seed = self.config.seed;
        let keys: Vec<Bls12381G1PrivateKey> = (0..total_nodes)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();
        let public_keys: Vec<Bls12381G1PublicKey> = keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..total_nodes)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: public_keys[i],
                voting_power: 1,
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build shard committees
        let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * self.config.validators_per_shard;
            let shard_end = shard_start + self.config.validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId(i as u64))
                .collect();
            shard_committees.insert(shard, committee);
            self.shard_members
                .insert(shard, (shard_start..shard_end).map(|i| i as u32).collect());
        }

        // Create nodes
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * self.config.validators_per_shard;

            for v in 0..self.config.validators_per_shard {
                let node_index = shard_start + v;
                let validator_id = ValidatorId(node_index as u64);

                let topology: Arc<dyn Topology> = Arc::new(StaticTopology::with_shard_committees(
                    validator_id,
                    shard,
                    num_shards as u64,
                    &global_validator_set,
                    shard_committees.clone(),
                ));

                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = keys[node_index].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let signing_key2 =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let state = NodeStateMachine::new(
                    node_index as u32,
                    topology,
                    signing_key,
                    BftConfig::default(),
                    RecoveredState::default(),
                );

                let storage = SimStorage::new();
                let node = SimNode::new(node_index as u32, state, storage, signing_key2);
                self.nodes.push(node);
            }
        }

        // Initialize Radix Engine executors for each shard WITH balances
        for shard_id in 0..num_shards {
            let balances = shard_balances(shard_id as u64);
            self.simulation_cache
                .init_shard_with_balances(shard_id as u64, balances);
        }
        info!(
            num_shards,
            "Radix Engine executors initialized with funded accounts"
        );

        // Initialize genesis for each shard
        for shard_id in 0..num_shards {
            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * self.config.validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            };
            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            let shard_start = shard_id * self.config.validators_per_shard;
            let shard_end = shard_start + self.config.validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index];
                let actions = node.state.initialize_genesis(genesis_block.clone());
                for action in actions {
                    node.execute_action(action, &self.simulation_cache);
                }
            }
        }

        info!("Genesis initialized for all shards with funded accounts");
    }

    /// Submit a transaction to the appropriate node.
    pub fn submit_transaction(&mut self, tx: RoutableTransaction) {
        let tx_hash = tx.hash();
        let target_shard = tx
            .declared_writes
            .first()
            .map(|w| hyperscale_types::shard_for_node(w, self.config.num_shards as u64))
            .unwrap_or(ShardGroupId(0));

        // Submit to first validator in target shard (wrap in Arc)
        let node_index = (target_shard.0 as usize * self.config.validators_per_shard) as u32;
        let event = Event::SubmitTransaction {
            tx: std::sync::Arc::new(tx),
        };
        self.nodes[node_index as usize].submit_transaction(event);

        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.in_flight.insert(tx_hash);
        self.submission_times.insert(tx_hash, self.simulated_time);
    }

    /// Run one step of the simulation.
    ///
    /// Each step represents 1ms of simulated time:
    /// 1. Advance time and fire any due timers
    /// 2. Deliver messages that have reached their delivery time
    /// 3. Process events (single pass - newly enqueued events wait for next step)
    /// 4. Collect outbound messages and schedule with network latency
    /// 5. Collect transaction status updates
    ///
    /// Returns the number of events processed across all nodes.
    pub fn step(&mut self) -> usize {
        // Step 1: Advance simulated time and fire due timers on all nodes
        self.simulated_time += Duration::from_millis(1);
        for node in &mut self.nodes {
            node.advance_time(self.simulated_time);
        }

        // Step 2: Deliver messages that have reached their delivery time
        let ready_messages = self.pending_messages.pop_ready(self.simulated_time);
        for msg in ready_messages {
            self.nodes[msg.recipient as usize].deliver_message(msg.message);
        }

        // Step 2b: Deliver fetch responses that have reached their delivery time
        let ready_responses = self.pending_fetch_responses.pop_ready(self.simulated_time);
        for resp in ready_responses {
            self.nodes[resp.recipient as usize]
                .internal_queue
                .push_back(resp.event);
        }

        // Step 3: Process all nodes in parallel (single pass)
        let cache = &self.simulation_cache;
        let events_processed: usize = self
            .nodes
            .par_iter_mut()
            .map(|node| node.process_events(cache))
            .sum();

        // Step 4: Collect outbound messages from all nodes
        let mut all_messages: Vec<(u32, Destination, Arc<OutboundMessage>)> = Vec::new();
        let mut all_fetch_requests: Vec<(u32, FetchRequest)> = Vec::new();
        for (i, node) in self.nodes.iter_mut().enumerate() {
            for (dest, msg) in node.take_outbound_messages() {
                all_messages.push((i as u32, dest, msg));
            }
            for req in node.take_fetch_requests() {
                all_fetch_requests.push((i as u32, req));
            }
        }

        // Step 5: Schedule messages for delivery with network latency
        for (from, dest, msg) in all_messages {
            let recipients = self.get_recipients(from, &dest);
            for recipient in recipients {
                // Record traffic for bandwidth analysis (if enabled)
                if let Some(ref analyzer) = self.traffic_analyzer {
                    let (payload_size, wire_size) = msg.encoded_size();
                    analyzer.record_message(
                        msg.type_name(),
                        payload_size,
                        wire_size,
                        from,
                        recipient,
                    );
                }

                // Calculate delivery time based on network latency
                let latency = self.network.sample_latency(from, recipient, &mut self.rng);
                let delivery_time = self.simulated_time + latency;

                self.pending_messages.push(PendingMessage {
                    delivery_time,
                    recipient,
                    message: msg.clone(),
                });
            }
        }

        // Step 5b: Process fetch requests (sync, transaction fetch, certificate fetch)
        for (requester, request) in all_fetch_requests {
            match request {
                FetchRequest::Sync { target_height } => {
                    self.process_sync_request(requester, target_height);
                }
                FetchRequest::Transactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                } => {
                    self.process_transaction_fetch_request(
                        requester, block_hash, proposer, tx_hashes,
                    );
                }
                FetchRequest::Certificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                } => {
                    self.process_certificate_fetch_request(
                        requester,
                        block_hash,
                        proposer,
                        cert_hashes,
                    );
                }
            }
        }

        // Step 6: Collect status updates
        for node in &mut self.nodes {
            for (tx_hash, status) in node.take_status_updates() {
                if self.in_flight.remove(&tx_hash) {
                    // Calculate latency
                    if let Some(submit_time) = self.submission_times.remove(&tx_hash) {
                        let latency = self.simulated_time.saturating_sub(submit_time);
                        self.latencies.push(latency.as_micros() as u64);
                    }

                    match status {
                        TransactionStatus::Completed(TransactionDecision::Accept) => {
                            self.completed.fetch_add(1, Ordering::Relaxed);
                        }
                        TransactionStatus::Completed(TransactionDecision::Reject)
                        | TransactionStatus::Aborted { .. } => {
                            self.rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        TransactionStatus::Retried { new_tx } => {
                            // Track new hash
                            self.in_flight.insert(new_tx);
                            if let Some(submit_time) = self.submission_times.get(&tx_hash) {
                                self.submission_times.insert(new_tx, *submit_time);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Step 7: Check if any syncing nodes have reached their target
        // This handles the case where blocks were committed during this step
        let completed_syncs: Vec<(u32, u64)> = self
            .sync_targets
            .iter()
            .filter_map(|(&node_idx, &target)| {
                let committed = self.nodes[node_idx as usize].state.bft().committed_height();
                if committed >= target {
                    Some((node_idx, target))
                } else {
                    None
                }
            })
            .collect();

        for (node_idx, target) in completed_syncs {
            self.sync_targets.remove(&node_idx);
            // Send SyncComplete event to the node
            let event = Event::SyncComplete { height: target };
            self.nodes[node_idx as usize]
                .internal_queue
                .push_back(event);
        }

        events_processed
    }

    /// Get recipient node indices for a destination.
    fn get_recipients(&self, _from: u32, dest: &Destination) -> Vec<u32> {
        match dest {
            Destination::Shard(shard) => self.shard_members.get(shard).cloned().unwrap_or_default(),
            Destination::Global => (0..self.nodes.len() as u32).collect(),
        }
    }

    /// Simulate a request/response round-trip with network latency.
    ///
    /// Returns `None` if the request would be dropped due to partition or packet loss.
    /// Returns `Some(delivery_time)` with the time the response would arrive.
    fn simulate_request_response(&mut self, requester: u32, responder: u32) -> Option<Duration> {
        // Check partition (either direction)
        if self.network.is_partitioned(requester, responder) {
            trace!(
                requester,
                responder,
                "Fetch request dropped due to partition"
            );
            return None;
        }

        // Check packet loss for request
        if self.network.should_drop_packet(&mut self.rng) {
            trace!(
                requester,
                responder,
                "Fetch request dropped due to packet loss"
            );
            return None;
        }

        // Check packet loss for response
        if self.network.should_drop_packet(&mut self.rng) {
            trace!(
                requester,
                responder,
                "Fetch response dropped due to packet loss"
            );
            return None;
        }

        // Sample latency for request and response
        let request_latency = self
            .network
            .sample_latency(requester, responder, &mut self.rng);
        let response_latency = self
            .network
            .sample_latency(responder, requester, &mut self.rng);
        let round_trip = request_latency + response_latency;

        Some(self.simulated_time + round_trip)
    }

    /// Process a sync fetch request from a node.
    fn process_sync_request(&mut self, requester: u32, target_height: u64) {
        // Track the sync target
        let current_target = self.sync_targets.get(&requester).copied().unwrap_or(0);
        if target_height > current_target {
            self.sync_targets.insert(requester, target_height);
        }
        let effective_target = target_height.max(current_target);

        // Get node's current committed height
        let committed_height = self.nodes[requester as usize]
            .state
            .bft()
            .committed_height();
        let next_height = committed_height + 1;

        // Check if sync is complete
        if committed_height >= effective_target {
            self.sync_targets.remove(&requester);
            // Send SyncComplete event to the node so it can resume view changes
            let event = Event::SyncComplete {
                height: effective_target,
            };
            self.nodes[requester as usize]
                .internal_queue
                .push_back(event);
            return;
        }

        // Find a peer with the next block
        if next_height <= effective_target {
            if let Some((peer, block, qc)) = self.find_block_from_any_peer(next_height) {
                // Simulate network round-trip
                if let Some(delivery_time) = self.simulate_request_response(requester, peer) {
                    let event = Event::SyncBlockReadyToApply { block, qc };
                    self.pending_fetch_responses.push(PendingFetchResponse {
                        delivery_time,
                        recipient: requester,
                        event,
                    });
                    trace!(requester, peer, next_height, "Sync: scheduled block fetch");
                }
            }
        }
    }

    /// Find a block at a given height from any peer's storage.
    fn find_block_from_any_peer(&self, height: u64) -> Option<(u32, Block, QuorumCertificate)> {
        for (idx, node) in self.nodes.iter().enumerate() {
            if let Some((block, qc)) = node.storage.get_block(BlockHeight(height)) {
                return Some((idx as u32, block, qc));
            }
        }
        None
    }

    /// Process a transaction fetch request from a node.
    fn process_transaction_fetch_request(
        &mut self,
        requester: u32,
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    ) {
        let proposer_node = proposer.0 as u32;
        if proposer_node as usize >= self.nodes.len() {
            return;
        }

        // Simulate network round-trip
        let delivery_time = match self.simulate_request_response(requester, proposer_node) {
            Some(time) => time,
            None => return,
        };

        // Look up transactions from proposer's mempool
        let mut found_transactions = Vec::new();
        {
            let mempool = self.nodes[proposer_node as usize].state.mempool();
            for tx_hash in &tx_hashes {
                if let Some(tx) = mempool.get_transaction(tx_hash) {
                    found_transactions.push(tx);
                }
            }
        }

        if found_transactions.is_empty() {
            return;
        }

        let event = Event::TransactionReceived {
            block_hash,
            transactions: found_transactions,
        };
        self.pending_fetch_responses.push(PendingFetchResponse {
            delivery_time,
            recipient: requester,
            event,
        });
    }

    /// Process a certificate fetch request from a node.
    fn process_certificate_fetch_request(
        &mut self,
        requester: u32,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    ) {
        let proposer_node = proposer.0 as u32;
        if proposer_node as usize >= self.nodes.len() {
            return;
        }

        // Simulate network round-trip
        let delivery_time = match self.simulate_request_response(requester, proposer_node) {
            Some(time) => time,
            None => return,
        };

        // Look up certificates from proposer's storage
        let mut found_certificates = Vec::new();
        let proposer_storage = &self.nodes[proposer_node as usize].storage;
        for cert_hash in &cert_hashes {
            if let Some(cert) = proposer_storage.get_certificate(cert_hash) {
                found_certificates.push(cert);
            }
        }

        if found_certificates.is_empty() {
            return;
        }

        let event = Event::CertificateReceived {
            block_hash,
            certificates: found_certificates,
        };
        self.pending_fetch_responses.push(PendingFetchResponse {
            delivery_time,
            recipient: requester,
            event,
        });
    }

    /// Get current metrics.
    pub fn metrics(&self) -> (u64, u64, u64, usize) {
        (
            self.submitted.load(Ordering::Relaxed),
            self.completed.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.in_flight.len(),
        )
    }

    /// Get simulated time.
    pub fn simulated_time(&self) -> Duration {
        self.simulated_time
    }

    /// Finalize and produce report.
    ///
    /// Latency is in simulated time (milliseconds converted to microseconds).
    pub fn finalize(mut self, wall_clock_duration: Duration) -> SimulationReport {
        let (submitted, completed, rejected, in_flight) = self.metrics();
        let simulated_time = self.simulated_time;

        // Compute latency percentiles (in simulated microseconds)
        self.latencies.sort_unstable();
        let p50 = percentile(&self.latencies, 0.50);
        let p90 = percentile(&self.latencies, 0.90);
        let p99 = percentile(&self.latencies, 0.99);
        let max = self.latencies.last().copied().unwrap_or(0);
        let avg = if self.latencies.is_empty() {
            0
        } else {
            self.latencies.iter().sum::<u64>() / self.latencies.len() as u64
        };

        // Average TPS: protocol throughput in simulated time
        let avg_tps = if simulated_time.as_secs_f64() > 0.0 {
            completed as f64 / simulated_time.as_secs_f64()
        } else {
            0.0
        };

        SimulationReport {
            wall_duration: wall_clock_duration,
            simulated_duration: simulated_time,
            submitted,
            completed,
            rejected,
            retries: 0,
            in_flight: in_flight as u64,
            messages_dropped_loss: 0,
            messages_dropped_partition: 0,
            avg_tps,
            latency_p50_us: p50,
            latency_p90_us: p90,
            latency_p99_us: p99,
            latency_max_us: max,
            latency_avg_us: avg,
        }
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p) as usize).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_simulator_basic() {
        let config = ParallelConfig::new(2, 3);
        let mut sim = ParallelSimulator::new(config);
        sim.initialize();

        // Run a few steps
        for _ in 0..10 {
            sim.step();
        }

        let (submitted, _completed, _rejected, in_flight) = sim.metrics();
        assert_eq!(submitted, 0);
        assert_eq!(in_flight, 0);
    }
}
