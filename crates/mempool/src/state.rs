//! Mempool state.

use hyperscale_core::{Action, Event, OutboundMessage, SubStateMachine, TransactionStatus};
use hyperscale_types::{
    AbortReason, Block, BlockHeight, DeferReason, Hash, NodeId, RoutableTransaction, Topology,
    TransactionAbort, TransactionDecision,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Lock contention statistics from the mempool.
#[derive(Clone, Copy, Debug, Default)]
pub struct LockContentionStats {
    /// Number of nodes currently locked by in-flight transactions.
    pub locked_nodes: u64,
    /// Number of transactions blocked waiting for a winner to complete.
    pub blocked_count: u64,
    /// Number of transactions in Pending status.
    pub pending_count: u64,
    /// Number of pending transactions that conflict with locked nodes.
    pub pending_blocked: u64,
}

impl LockContentionStats {
    /// Contention ratio: what fraction of pending transactions are blocked.
    pub fn contention_ratio(&self) -> f64 {
        if self.pending_count > 0 {
            self.pending_blocked as f64 / self.pending_count as f64
        } else {
            0.0
        }
    }
}

/// Entry in the transaction pool.
#[derive(Debug)]
struct PoolEntry {
    tx: Arc<RoutableTransaction>,
    status: TransactionStatus,
    #[allow(dead_code)]
    added_at: Duration,
}

/// Mempool state machine.
///
/// Handles transaction lifecycle from submission to completion.
/// Uses `HashMap` instead of `DashMap` since access is serialized.
pub struct MempoolState {
    /// Transaction pool (HashMap, not DashMap - no concurrent access).
    pool: HashMap<Hash, PoolEntry>,

    /// Blocked transactions waiting for their winner to complete.
    /// Maps: loser_tx_hash -> (loser_tx, winner_tx_hash)
    ///
    /// When a deferral commits, the loser is added here with status Blocked.
    /// When the winner's certificate commits, we create a retry.
    blocked_by: HashMap<Hash, (Arc<RoutableTransaction>, Hash)>,

    /// Reverse index: winner_tx_hash -> Vec<loser_tx_hash>
    /// Allows O(1) lookup of all losers blocked by a winner.
    blocked_losers_by_winner: HashMap<Hash, Vec<Hash>>,

    /// Current time.
    now: Duration,

    /// Network topology for shard-aware transaction routing.
    topology: Arc<dyn Topology>,

    /// Current committed block height (for retry transaction creation).
    current_height: BlockHeight,
}

impl MempoolState {
    /// Create a new mempool state machine.
    pub fn new(topology: Arc<dyn Topology>) -> Self {
        Self {
            pool: HashMap::new(),
            blocked_by: HashMap::new(),
            blocked_losers_by_winner: HashMap::new(),
            now: Duration::ZERO,
            topology,
            current_height: BlockHeight(0),
        }
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction_arc(&mut self, tx: Arc<RoutableTransaction>) -> Vec<Action> {
        let hash = tx.hash();

        // Check for duplicate
        if self.pool.contains_key(&hash) {
            return vec![Action::EmitTransactionStatus {
                tx_hash: hash,
                status: TransactionStatus::Pending, // Already exists
            }];
        }

        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(&tx),
                status: TransactionStatus::Pending,
                added_at: self.now,
            },
        );
        tracing::info!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via submit");

        // Broadcast to all shards involved in this transaction (consensus + provisioning)
        // Note: We don't emit TransactionAccepted as an event - it was purely informational
        // and would flood the consensus channel under high transaction load.
        let mut actions = self.broadcast_to_transaction_shards(&tx);

        actions.push(Action::EmitTransactionStatus {
            tx_hash: hash,
            status: TransactionStatus::Pending,
        });
        actions
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction(&mut self, tx: RoutableTransaction) -> Vec<Action> {
        self.on_submit_transaction_arc(Arc::new(tx))
    }

    /// Handle transaction received via gossip.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip_arc(&mut self, tx: Arc<RoutableTransaction>) -> Vec<Action> {
        let hash = tx.hash();

        // Ignore if already have it
        if self.pool.contains_key(&hash) {
            return vec![];
        }

        self.pool.insert(
            hash,
            PoolEntry {
                tx,
                status: TransactionStatus::Pending,
                added_at: self.now,
            },
        );
        tracing::debug!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via gossip");

        // Note: We don't emit TransactionAccepted as an event - it was purely informational
        // and would flood the consensus channel under high transaction load.
        vec![]
    }

    /// Handle transaction received via gossip.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip(&mut self, tx: RoutableTransaction) -> Vec<Action> {
        self.on_transaction_gossip_arc(Arc::new(tx))
    }

    /// Broadcast a transaction to all shards involved in it.
    ///
    /// Uses topology to determine which shards need to receive the transaction
    /// based on its declared reads and writes.
    fn broadcast_to_transaction_shards(&self, tx: &Arc<RoutableTransaction>) -> Vec<Action> {
        let shards = self.topology.all_shards_for_transaction(tx.as_ref());
        let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(tx));

        shards
            .into_iter()
            .map(|shard| Action::BroadcastToShard {
                shard,
                message: OutboundMessage::TransactionGossip(Box::new(gossip.clone())),
            })
            .collect()
    }

    /// Process a committed block - update statuses and trigger retries.
    ///
    /// This handles:
    /// 1. Mark committed transactions
    /// 2. Process deferrals → update status to Blocked
    /// 3. Process certificates → mark completed, trigger retries for blocked TXs
    /// 4. Process aborts → update status to terminal
    #[instrument(skip(self, block), fields(
        height = block.header.height.0,
        tx_count = block.transactions.len()
    ))]
    pub fn on_block_committed_full(&mut self, block: &Block) -> Vec<Action> {
        let height = block.header.height;
        let mut actions = Vec::new();

        // Track current height for retry creation
        self.current_height = height;

        // Note: We do NOT update transaction status to Committed here.
        // Status updates flow through TransactionStatusChanged events from the
        // execution state machine, which ensures proper ordering when early
        // votes/provisions are replayed.

        // 1. Process deferrals - update status to Blocked
        for deferral in &block.deferred {
            actions.extend(self.on_deferral_committed(deferral.tx_hash, &deferral.reason, height));
        }

        // 3. Process certificates - mark completed, trigger retries
        for cert in &block.committed_certificates {
            actions.extend(self.on_certificate_committed(
                cert.transaction_hash,
                cert.decision,
                height,
            ));
        }

        // 4. Process aborts - mark as aborted with reason
        for abort in &block.aborted {
            if let Some(entry) = self.pool.get_mut(&abort.tx_hash) {
                let status = TransactionStatus::Aborted {
                    reason: abort.reason.clone(),
                };
                entry.status = status.clone();
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: abort.tx_hash,
                    status,
                });
            }
        }

        actions
    }

    /// Handle a deferral committed in a block.
    ///
    /// Updates the deferred TX's status to Blocked and tracks it for retry.
    fn on_deferral_committed(
        &mut self,
        tx_hash: Hash,
        reason: &DeferReason,
        _height: BlockHeight,
    ) -> Vec<Action> {
        let DeferReason::LivelockCycle { winner_tx_hash } = reason;

        // Get the transaction and update its status
        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            // Update status to Blocked
            let new_status = TransactionStatus::Blocked {
                by: *winner_tx_hash,
            };
            if entry.status.can_transition_to(&new_status) {
                tracing::info!(
                    tx_hash = %tx_hash,
                    winner = %winner_tx_hash,
                    from = %entry.status,
                    "Transaction deferred due to livelock cycle"
                );
                entry.status = new_status.clone();

                // Track for retry when winner completes
                self.blocked_by
                    .insert(tx_hash, (Arc::clone(&entry.tx), *winner_tx_hash));

                // Maintain reverse index for O(1) lookup
                self.blocked_losers_by_winner
                    .entry(*winner_tx_hash)
                    .or_default()
                    .push(tx_hash);

                return vec![Action::EmitTransactionStatus {
                    tx_hash,
                    status: new_status,
                }];
            }
        }

        vec![]
    }

    /// Handle a certificate committed in a block.
    ///
    /// Marks the transaction as completed and triggers retries for any TXs blocked by it.
    fn on_certificate_committed(
        &mut self,
        tx_hash: Hash,
        decision: TransactionDecision,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Mark the certificate's TX as completed with the final decision
        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            entry.status = TransactionStatus::Completed(decision);
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Completed(decision),
            });
        }

        // Check if any blocked TXs were waiting for this winner using reverse index (O(1) lookup)
        let loser_hashes = self
            .blocked_losers_by_winner
            .remove(&tx_hash)
            .unwrap_or_default();

        for loser_hash in loser_hashes {
            // Get the loser transaction from blocked_by
            let Some((loser_tx, winner_hash)) = self.blocked_by.remove(&loser_hash) else {
                continue;
            };
            // Create retry transaction
            let retry_tx = loser_tx.create_retry(winner_hash, height);
            let retry_hash = retry_tx.hash();

            tracing::info!(
                original = %loser_hash,
                retry = %retry_hash,
                winner = %winner_hash,
                retry_count = retry_tx.retry_count(),
                "Creating retry for deferred transaction"
            );

            // Update original's status to Retried
            if let Some(entry) = self.pool.get_mut(&loser_hash) {
                entry.status = TransactionStatus::Retried { new_tx: retry_hash };
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: loser_hash,
                    status: TransactionStatus::Retried { new_tx: retry_hash },
                });
            }

            // Note: loser_hash already removed from blocked_by above

            // Add retry to mempool if not already present (dedup by hash)
            if !self.pool.contains_key(&retry_hash) {
                let retry_tx = Arc::new(retry_tx);
                self.pool.insert(
                    retry_hash,
                    PoolEntry {
                        tx: Arc::clone(&retry_tx),
                        status: TransactionStatus::Pending,
                        added_at: self.now,
                    },
                );

                // Emit status for retry transaction
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: retry_hash,
                    status: TransactionStatus::Pending,
                });

                // Gossip the retry to relevant shards
                actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
            }
        }

        actions
    }

    /// Mark transactions as committed when block is committed (legacy method).
    #[deprecated(note = "Use on_block_committed_full instead")]
    pub fn on_block_committed(&mut self, tx_hashes: &[Hash], height: BlockHeight) {
        for hash in tx_hashes {
            if let Some(entry) = self.pool.get_mut(hash) {
                entry.status = TransactionStatus::Committed(height);
            }
        }
    }

    /// Mark a transaction as executed (execution complete, certificate created).
    ///
    /// Called when ExecutionState creates a TransactionCertificate.
    /// Also triggers retries for any transactions blocked by this winner.
    #[instrument(skip(self), fields(tx_hash = ?tx_hash, accepted = accepted))]
    pub fn on_transaction_executed(&mut self, tx_hash: Hash, accepted: bool) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            let decision = if accepted {
                TransactionDecision::Accept
            } else {
                TransactionDecision::Reject
            };
            entry.status = TransactionStatus::Executed(decision);
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Executed(decision),
            });
        }

        // Check if any blocked transactions were waiting for this winner to complete.
        // This triggers retries immediately when the winner executes, rather than
        // waiting for the certificate to be committed in a block.
        // Using reverse index for O(1) lookup
        let loser_hashes = self
            .blocked_losers_by_winner
            .remove(&tx_hash)
            .unwrap_or_default();

        let height = self.current_height;
        for loser_hash in loser_hashes {
            // Get the loser transaction from blocked_by
            let Some((loser_tx, winner_hash)) = self.blocked_by.remove(&loser_hash) else {
                continue;
            };
            // Create retry transaction
            let retry_tx = loser_tx.create_retry(winner_hash, height);
            let retry_hash = retry_tx.hash();

            tracing::info!(
                original = %loser_hash,
                retry = %retry_hash,
                winner = %winner_hash,
                retry_count = retry_tx.retry_count(),
                "Creating retry for blocked transaction (winner finalized)"
            );

            // Update original's status to Retried
            if let Some(entry) = self.pool.get_mut(&loser_hash) {
                entry.status = TransactionStatus::Retried { new_tx: retry_hash };
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: loser_hash,
                    status: TransactionStatus::Retried { new_tx: retry_hash },
                });
            }

            // Note: loser_hash already removed from blocked_by above

            // Add retry to mempool if not already present (dedup by hash)
            if !self.pool.contains_key(&retry_hash) {
                let retry_tx = Arc::new(retry_tx);
                self.pool.insert(
                    retry_hash,
                    PoolEntry {
                        tx: Arc::clone(&retry_tx),
                        status: TransactionStatus::Pending,
                        added_at: self.now,
                    },
                );

                // Emit status for retry transaction
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: retry_hash,
                    status: TransactionStatus::Pending,
                });

                // Gossip the retry to relevant shards
                actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
            }
        }

        actions
    }

    /// Mark a transaction as completed (certificate committed in block).
    ///
    /// This is the terminal state - the transaction can be evicted from mempool.
    pub fn mark_completed(&mut self, tx_hash: &Hash, decision: TransactionDecision) -> Vec<Action> {
        if let Some(entry) = self.pool.get_mut(tx_hash) {
            entry.status = TransactionStatus::Completed(decision);
            return vec![Action::EmitTransactionStatus {
                tx_hash: *tx_hash,
                status: TransactionStatus::Completed(decision),
            }];
        }
        vec![]
    }

    /// Update transaction status to a new state.
    ///
    /// This is used by the execution state machine to update status during
    /// the transaction lifecycle (Committed, Executed, etc.).
    ///
    /// Returns an action to emit the status update if the transition was valid.
    pub fn update_status(&mut self, tx_hash: &Hash, new_status: TransactionStatus) -> Vec<Action> {
        if let Some(entry) = self.pool.get_mut(tx_hash) {
            // Case 1: Idempotent update - already in the target state
            if entry.status == new_status {
                tracing::trace!(
                    tx_hash = ?tx_hash,
                    status = %entry.status,
                    "Ignoring duplicate status update"
                );
                return vec![];
            }

            // Case 2: Valid transition - apply it
            if entry.status.can_transition_to(&new_status) {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    from = %entry.status,
                    to = %new_status,
                    "Transaction status transition"
                );
                entry.status = new_status.clone();
                return vec![Action::EmitTransactionStatus {
                    tx_hash: *tx_hash,
                    status: new_status,
                }];
            }

            // Case 3: Invalid transition - determine if stale or truly invalid
            if new_status.ordinal() < entry.status.ordinal() {
                // Stale update: we've already progressed past this state.
                // This can happen due to message reordering in distributed systems.
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    current = %entry.status,
                    stale = %new_status,
                    "Ignoring stale status update (already progressed past this state)"
                );
            } else {
                // Truly invalid transition - this indicates a bug in the state machine
                tracing::warn!(
                    tx_hash = ?tx_hash,
                    from = %entry.status,
                    to = %new_status,
                    "Invalid transaction status transition"
                );
            }
        }
        vec![]
    }

    /// Get all NodeIds that are currently locked by in-flight transactions.
    ///
    /// A node is locked if any transaction that declares it (read or write)
    /// is in a lock-holding state (Committed or Executed).
    fn locked_nodes(&self) -> HashSet<NodeId> {
        self.pool
            .values()
            .filter(|e| e.status.holds_state_lock())
            .flat_map(|e| e.tx.all_declared_nodes().cloned())
            .collect()
    }

    /// Check if a transaction conflicts with any locked nodes.
    fn conflicts_with_locked(&self, tx: &RoutableTransaction, locked: &HashSet<NodeId>) -> bool {
        tx.all_declared_nodes().any(|node| locked.contains(node))
    }

    /// Get transactions ready for inclusion in a block.
    ///
    /// Returns transactions that are:
    /// 1. In Pending status (not yet accepted)
    /// 2. Do not conflict with any in-flight transaction (no shared nodes)
    /// 3. Sorted by hash (ascending) to reduce cross-shard conflicts
    ///
    /// The hash-ordering ensures different shards are more likely to pick
    /// the same transactions, reducing cycle formation in cross-shard execution.
    pub fn ready_transactions(&self, max_count: usize) -> Vec<Arc<RoutableTransaction>> {
        // Get all nodes currently locked by in-flight transactions
        // TODO: Cache locked_nodes() to avoid O(n) scan on every call
        let locked = self.locked_nodes();

        // Collect pending transactions that don't conflict
        // TODO: Use partial sort / bounded heap to avoid sorting all txs
        let mut ready: Vec<_> = self
            .pool
            .values()
            .filter(|e| e.status == TransactionStatus::Pending)
            .filter(|e| !self.conflicts_with_locked(&e.tx, &locked))
            .map(|e| Arc::clone(&e.tx))
            .collect();

        // Sort by hash (ascending) - lower hashes are selected first
        // This makes different shards more likely to select the same TXs,
        // reducing the chance of cross-shard cycles
        ready.sort_by_key(|tx| tx.hash());

        ready.into_iter().take(max_count).collect()
    }

    /// Get lock contention statistics.
    ///
    /// Returns counts of:
    /// - `locked_nodes`: Number of nodes currently locked by in-flight transactions
    /// - `blocked_count`: Number of transactions blocked waiting for a winner
    /// - `pending_count`: Number of transactions in Pending status
    /// - `pending_blocked`: Number of pending transactions that conflict with locked nodes
    pub fn lock_contention_stats(&self) -> LockContentionStats {
        let locked = self.locked_nodes();
        let locked_nodes = locked.len() as u64;
        let blocked_count = self.blocked_by.len() as u64;

        // Single pass over pending transactions to count both total and blocked
        let (pending_count, pending_blocked) = self
            .pool
            .values()
            .filter(|e| e.status == TransactionStatus::Pending)
            .fold((0u64, 0u64), |(total, blocked), e| {
                let is_blocked = self.conflicts_with_locked(&e.tx, &locked);
                (total + 1, blocked + is_blocked as u64)
            });

        LockContentionStats {
            locked_nodes,
            blocked_count,
            pending_count,
            pending_blocked,
        }
    }

    /// Check if we have a transaction.
    pub fn has_transaction(&self, hash: &Hash) -> bool {
        self.pool.contains_key(hash)
    }

    /// Get a transaction Arc by hash.
    pub fn get_transaction(&self, hash: &Hash) -> Option<Arc<RoutableTransaction>> {
        self.pool.get(hash).map(|e| Arc::clone(&e.tx))
    }

    /// Get transaction status.
    pub fn status(&self, hash: &Hash) -> Option<TransactionStatus> {
        self.pool.get(hash).map(|e| e.status.clone())
    }

    /// Get all transactions as a HashMap (for block header validation).
    ///
    /// This allows BFT to look up transactions by hash when receiving block headers.
    pub fn transactions_by_hash(&self) -> HashMap<Hash, Arc<RoutableTransaction>> {
        self.pool
            .iter()
            .map(|(hash, entry)| (*hash, Arc::clone(&entry.tx)))
            .collect()
    }

    /// Get the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Get the mempool as a hash map for BFT pending block completion.
    pub fn as_hash_map(&self) -> std::collections::HashMap<Hash, Arc<RoutableTransaction>> {
        self.pool
            .iter()
            .map(|(hash, entry)| (*hash, Arc::clone(&entry.tx)))
            .collect()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Get all incomplete transactions (not yet finalized or completed).
    ///
    /// Returns tuples of (hash, status, transaction Arc) for analysis.
    pub fn incomplete_transactions(
        &self,
    ) -> Vec<(Hash, TransactionStatus, Arc<RoutableTransaction>)> {
        self.pool
            .iter()
            .filter(|(_, entry)| {
                !matches!(
                    entry.status,
                    TransactionStatus::Executed(_) | TransactionStatus::Completed(_)
                )
            })
            .map(|(hash, entry)| (*hash, entry.status.clone(), Arc::clone(&entry.tx)))
            .collect()
    }

    /// Get transactions that have timed out waiting for execution.
    ///
    /// Transactions timeout if they've been holding state locks for too long.
    /// This is a safety net for N-way cycles that aren't detected by pairwise
    /// cycle detection.
    ///
    /// Returns `TransactionAbort` entries ready for inclusion in a block.
    ///
    /// # Parameters
    /// - `current_height`: The current block height
    /// - `timeout_blocks`: Number of blocks after which a TX is considered timed out
    /// - `max_retries`: Maximum retry count before aborting
    pub fn get_timed_out_transactions(
        &self,
        current_height: BlockHeight,
        timeout_blocks: u64,
        max_retries: u32,
    ) -> Vec<TransactionAbort> {
        let mut aborts = Vec::new();

        for (hash, entry) in &self.pool {
            // Skip transactions that are already finalized or completed
            if matches!(
                entry.status,
                TransactionStatus::Executed(_) | TransactionStatus::Completed(_)
            ) {
                continue;
            }

            // Check for execution timeout (TX stuck in lock-holding state too long)
            if let TransactionStatus::Committed(committed_at) = &entry.status {
                let blocks_elapsed = current_height.0.saturating_sub(committed_at.0);
                if blocks_elapsed >= timeout_blocks {
                    tracing::info!(
                        tx_hash = %hash,
                        committed_at = committed_at.0,
                        current_height = current_height.0,
                        blocks_elapsed = blocks_elapsed,
                        "Transaction timed out waiting for execution"
                    );
                    aborts.push(TransactionAbort {
                        tx_hash: *hash,
                        reason: AbortReason::ExecutionTimeout {
                            committed_at: *committed_at,
                        },
                        block_height: BlockHeight(0), // Filled in by proposer
                    });
                }
            }

            // Note: Executed transactions also hold locks but don't have a
            // committed height embedded. For simplicity, we only timeout from
            // Committed state. Executed→Completed should happen quickly anyway.

            // Check for too many retries
            if entry.tx.exceeds_max_retries(max_retries) {
                tracing::info!(
                    tx_hash = %hash,
                    retry_count = entry.tx.retry_count(),
                    max_retries = max_retries,
                    "Transaction exceeded maximum retry count"
                );
                aborts.push(TransactionAbort {
                    tx_hash: *hash,
                    reason: AbortReason::TooManyRetries {
                        retry_count: entry.tx.retry_count(),
                    },
                    block_height: BlockHeight(0), // Filled in by proposer
                });
            }
        }

        aborts
    }
}

impl SubStateMachine for MempoolState {
    fn try_handle(&mut self, event: &Event) -> Option<Vec<Action>> {
        match event {
            Event::SubmitTransaction { tx } => Some(self.on_submit_transaction_arc(Arc::clone(tx))),
            Event::TransactionGossipReceived { tx } => {
                Some(self.on_transaction_gossip_arc(Arc::clone(tx)))
            }
            Event::BlockCommitted { block, .. } => {
                // Process block fully including deferrals, certificates, and aborts
                Some(self.on_block_committed_full(block))
            }
            Event::TransactionExecuted { tx_hash, accepted } => {
                Some(self.on_transaction_executed(*tx_hash, *accepted))
            }
            // Handle status update events from execution
            Event::TransactionStatusChanged { tx_hash, status } => {
                Some(self.update_status(tx_hash, status.clone()))
            }
            _ => None,
        }
    }

    fn set_time(&mut self, now: Duration) {
        self.now = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        test_utils::test_transaction, Block, BlockHeader, DeferReason, KeyPair, QuorumCertificate,
        StaticTopology, TransactionCertificate, TransactionDefer, ValidatorId, ValidatorInfo,
        ValidatorSet,
    };
    use std::collections::BTreeMap;

    fn make_test_topology() -> Arc<dyn Topology> {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: KeyPair::generate_ed25519().public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set))
    }

    fn make_test_block(
        height: u64,
        transactions: Vec<RoutableTransaction>,
        deferred: Vec<TransactionDefer>,
        certificates: Vec<TransactionCertificate>,
        aborted: Vec<TransactionAbort>,
    ) -> Block {
        Block {
            header: BlockHeader {
                height: BlockHeight(height),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
            },
            transactions: transactions.into_iter().map(Arc::new).collect(),
            committed_certificates: certificates.into_iter().map(Arc::new).collect(),
            deferred,
            aborted,
        }
    }

    fn make_test_certificate(tx_hash: Hash) -> TransactionCertificate {
        TransactionCertificate {
            transaction_hash: tx_hash,
            decision: TransactionDecision::Accept,
            shard_proofs: BTreeMap::new(), // Empty for test - just need tx_hash
        }
    }

    #[test]
    fn test_deferral_updates_status_to_blocked() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and add a transaction
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        // Commit the transaction first (deferrals apply to committed TXs)
        let commit_block = make_test_block(1, vec![tx.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Simulate the TransactionStatusChanged event from execution
        mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));

        // Verify status is Committed
        assert!(matches!(
            mempool.status(&tx_hash),
            Some(TransactionStatus::Committed(_))
        ));

        // Create another TX as the "winner"
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();
        mempool.on_submit_transaction(winner_tx.clone());

        // Create a deferral for our TX
        let deferral = TransactionDefer {
            tx_hash,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(2),
        };

        // Process block with deferral
        let defer_block = make_test_block(2, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&defer_block);

        // Verify status is now Blocked
        let status = mempool.status(&tx_hash);
        assert!(matches!(
            status,
            Some(TransactionStatus::Blocked { by }) if by == winner_hash
        ));

        // Verify it's tracked in blocked_by
        assert!(mempool.blocked_by.contains_key(&tx_hash));
    }

    #[test]
    fn test_winner_certificate_triggers_retry() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create loser TX and submit
        let loser_tx = test_transaction(1);
        let loser_hash = loser_tx.hash();
        mempool.on_submit_transaction(loser_tx.clone());

        // Create winner TX and submit
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();
        mempool.on_submit_transaction(winner_tx.clone());

        // Commit both
        let commit_block = make_test_block(
            1,
            vec![loser_tx.clone(), winner_tx.clone()],
            vec![],
            vec![],
            vec![],
        );
        mempool.on_block_committed_full(&commit_block);

        // Defer the loser
        let deferral = TransactionDefer {
            tx_hash: loser_hash,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(2),
        };
        let defer_block = make_test_block(2, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&defer_block);

        // Verify loser is blocked
        assert!(matches!(
            mempool.status(&loser_hash),
            Some(TransactionStatus::Blocked { .. })
        ));

        // Winner's certificate commits
        let winner_cert = make_test_certificate(winner_hash);
        let cert_block = make_test_block(3, vec![], vec![], vec![winner_cert], vec![]);
        let actions = mempool.on_block_committed_full(&cert_block);

        // Should have created a retry TX (gossip action)
        assert!(
            !actions.is_empty(),
            "Should have gossiped retry transaction"
        );

        // Loser should now be Retried
        let loser_status = mempool.status(&loser_hash);
        assert!(
            matches!(loser_status, Some(TransactionStatus::Retried { .. })),
            "Loser should be Retried, got {:?}",
            loser_status
        );

        // Retry should exist in pool as Pending
        if let Some(TransactionStatus::Retried { new_tx }) = loser_status {
            let retry_status = mempool.status(&new_tx);
            assert!(
                matches!(retry_status, Some(TransactionStatus::Pending)),
                "Retry should be Pending, got {:?}",
                retry_status
            );
        }

        // blocked_by should be cleared
        assert!(!mempool.blocked_by.contains_key(&loser_hash));
    }

    #[test]
    fn test_timeout_detection() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Simulate the TransactionStatusChanged event from execution
        mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));

        // Check for timeouts - not enough blocks elapsed
        let aborts = mempool.get_timed_out_transactions(BlockHeight(20), 30, 3);
        assert!(aborts.is_empty(), "Should not timeout yet");

        // Check for timeouts - now enough blocks
        let aborts = mempool.get_timed_out_transactions(BlockHeight(35), 30, 3);
        assert_eq!(aborts.len(), 1);
        assert_eq!(aborts[0].tx_hash, tx_hash);
        assert!(matches!(
            aborts[0].reason,
            AbortReason::ExecutionTimeout { .. }
        ));
    }

    #[test]
    fn test_too_many_retries_detection() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create a TX that has already been retried multiple times
        let tx = test_transaction(1);
        let _tx_hash = tx.hash();

        // Manually create a retry TX (simulating previous retries)
        let retry1 = tx.create_retry(Hash::from_bytes(b"winner1"), BlockHeight(1));
        let retry2 = retry1.create_retry(Hash::from_bytes(b"winner2"), BlockHeight(2));
        let retry3 = retry2.create_retry(Hash::from_bytes(b"winner3"), BlockHeight(3));

        assert_eq!(retry3.retry_count(), 3);

        // Submit the multiply-retried TX
        mempool.on_submit_transaction(retry3.clone());

        // Should detect too many retries (max_retries = 3 means 3 retries allowed, 4th would be rejected)
        let aborts = mempool.get_timed_out_transactions(BlockHeight(10), 100, 3);
        assert_eq!(aborts.len(), 1);
        assert!(matches!(
            aborts[0].reason,
            AbortReason::TooManyRetries { retry_count: 3 }
        ));
    }

    #[test]
    fn test_abort_updates_status() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Process an abort
        let abort = TransactionAbort {
            tx_hash,
            reason: AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1),
            },
            block_height: BlockHeight(35),
        };
        let abort_block = make_test_block(35, vec![], vec![], vec![], vec![abort]);
        mempool.on_block_committed_full(&abort_block);

        // Status should be Aborted (terminal)
        assert!(matches!(
            mempool.status(&tx_hash),
            Some(TransactionStatus::Aborted { .. })
        ));
    }

    #[test]
    fn test_retry_has_different_hash() {
        let tx = test_transaction(1);
        let original_hash = tx.hash();

        let retry = tx.create_retry(Hash::from_bytes(b"winner"), BlockHeight(5));
        let retry_hash = retry.hash();

        // Retry must have different hash
        assert_ne!(
            original_hash, retry_hash,
            "Retry must have different hash from original"
        );

        // But same underlying transaction content (declared reads/writes are fields)
        assert_eq!(tx.declared_reads, retry.declared_reads);
        assert_eq!(tx.declared_writes, retry.declared_writes);

        // Retry knows its original
        assert_eq!(retry.original_hash(), original_hash);
        assert_eq!(retry.retry_count(), 1);
    }
}
