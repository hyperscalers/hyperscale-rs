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

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::RoutableTransaction;
use std::sync::Arc;

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
