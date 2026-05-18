//! Transaction-flow dispatch arms.
//!
//! Three `ProtocolEvent` variants drive the transaction pipeline:
//! - `TransactionValidated` — gossip-delivered tx that passed async validation
//!   → mempool admission;
//! - `TransactionsReceived` — fetch-delivered batch → mempool admission;
//! - `TransactionsAdmitted` — mempool emits this after admission; BFT's
//!   pending-block subscriber consumes it and we latch a proposal-retry.
//!
//! Raw gossip arrivals enter `IoLoop` as `NodeInput::TransactionGossipReceived`
//! and never reach the state machine; the validated form does.

use std::sync::Arc;

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::RoutableTransaction;

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Dispatch a transaction-category `ProtocolEvent`.
    pub(super) fn handle_transaction(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::TransactionValidated {
                tx,
                submitted_locally,
            } => self.on_transaction_validated(tx, submitted_locally),
            ProtocolEvent::TransactionsReceived { transactions } => {
                self.on_transactions_fetched(transactions)
            }
            ProtocolEvent::TransactionsAdmitted { txs } => {
                let actions = self
                    .bft
                    .on_transactions_admitted(self.topology.snapshot(), &txs);
                self.bft.queue_ready_proposal();
                actions
            }
            _ => unreachable!("non-transaction event routed to handle_transaction"),
        }
    }

    /// Hand a validated gossip transaction to the canonical mempool. Mempool
    /// emits `Continuation(TransactionsAdmitted)` for whatever it admits;
    /// that arm latches the proposal-retry — no need to do it optimistically
    /// here.
    fn on_transaction_validated(
        &mut self,
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        if !self.topology.snapshot().involves_local_shard(&tx) {
            return vec![];
        }

        self.mempool.on_transaction_gossip(
            self.topology.snapshot(),
            tx,
            submitted_locally,
            self.now,
        )
    }

    /// Admit a batch of fetch-delivered transactions through mempool. Bypasses
    /// the gossip-side validation pipeline (the txs came from a peer we
    /// asked). Mempool emits `Continuation(TransactionsAdmitted)` for the
    /// admitted subset; the admission arm latches the proposal-retry.
    fn on_transactions_fetched(&mut self, txs: Vec<Arc<RoutableTransaction>>) -> Vec<Action> {
        if txs.is_empty() {
            return vec![];
        }
        self.mempool
            .on_fetched_transactions(self.topology.snapshot(), txs, self.now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_core::{ProtocolEvent, StateMachine};
    use hyperscale_types::LocalTimestamp;
    use hyperscale_types::test_utils::{test_transaction, test_transaction_with_nodes};

    use super::super::test_support::TestNode;

    /// Validated gossip transactions are gated by the local-shard filter
    /// before reaching mempool. A tx with empty reads/writes never
    /// involves any shard, so the local-shard predicate rejects it and
    /// the mempool stays empty.
    #[test]
    fn transaction_validated_drops_tx_with_no_local_shard_involvement() {
        let TestNode { mut node, .. } = TestNode::new();

        let tx = Arc::new(test_transaction_with_nodes(
            b"empty-shards-xyz",
            /* read_nodes */ vec![],
            /* write_nodes */ vec![],
        ));

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionValidated {
                tx,
                submitted_locally: false,
            },
        );

        assert!(actions.is_empty());
        assert_eq!(
            node.mempool.len(),
            0,
            "non-local tx must not enter the mempool",
        );
    }

    /// Counterpart to the rejection test: a tx that touches a local node
    /// must reach the mempool (with `num_shards = 1` every node maps to
    /// `ShardGroupId::new(0)`).
    #[test]
    fn transaction_validated_routes_local_shard_tx_to_mempool() {
        let TestNode { mut node, .. } = TestNode::new();
        let tx = Arc::new(test_transaction(/* seed */ 1));

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionValidated {
                tx,
                submitted_locally: true,
            },
        );

        assert_eq!(
            node.mempool.len(),
            1,
            "local-shard tx must be admitted to the mempool",
        );
    }

    /// `TransactionsReceived` is the fetch-delivery counterpart to
    /// `TransactionValidated` — txs arrive from a peer we asked, so the
    /// gossip-side validation pipeline is skipped and the orchestrator
    /// hands the batch directly to mempool's `on_fetched_transactions`.
    /// Distinct mempool method, distinct admission flags (gossip path
    /// passes `submitted_locally`; this path always treats them as
    /// remote). Bug surface: dropping the call entirely, or routing
    /// fetch txs through the gossip path and inheriting its validation.
    #[test]
    fn transactions_received_admits_fetched_batch_to_mempool() {
        let TestNode { mut node, .. } = TestNode::new();
        let txs = vec![
            Arc::new(test_transaction(/* seed */ 1)),
            Arc::new(test_transaction(/* seed */ 2)),
        ];

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionsReceived { transactions: txs },
        );

        assert_eq!(
            node.mempool.len(),
            2,
            "fetched txs must be admitted via the fetch path",
        );
    }
}
