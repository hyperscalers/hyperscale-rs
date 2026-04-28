//! Transaction-flow dispatch arms.
//!
//! Three `ProtocolEvent` variants drive the transaction pipeline:
//! - `TransactionGossipReceived` — gossip-delivered tx → mempool admission;
//! - `TransactionsAdmitted` — mempool emits this after admission; BFT's
//!   pending-block subscriber consumes it;
//! - `ExecutionCertificateCreated` — local EC creation re-checks mempool
//!   tombstoning for the included txs.

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{RoutableTransaction, TxHash};
use std::sync::Arc;

impl NodeStateMachine {
    /// Dispatch a transaction-category `ProtocolEvent`.
    pub(super) fn handle_transaction(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::TransactionGossipReceived {
                tx,
                submitted_locally,
            } => self.on_transaction_gossip_received(tx, submitted_locally),
            ProtocolEvent::TransactionsAdmitted { txs } => self
                .bft
                .on_transactions_admitted(self.topology.snapshot(), &txs),
            ProtocolEvent::ExecutionCertificateCreated { tx_hashes } => {
                self.on_ec_created(&tx_hashes)
            }
            _ => unreachable!("non-transaction event routed to handle_transaction"),
        }
    }

    fn on_ec_created(&self, tx_hashes: &[TxHash]) -> Vec<Action> {
        self.mempool.on_ec_created(tx_hashes)
    }

    /// Hand a gossiped transaction to the canonical mempool. Mempool emits
    /// `Continuation(ProtocolEvent::TransactionsAdmitted)` for whatever it
    /// admits; `io_loop` drains the fetch protocol and BFT's pending-block
    /// subscriber receives the txs from there.
    fn on_transaction_gossip_received(
        &mut self,
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        if !self.topology.snapshot().involves_local_shard(&tx) {
            return vec![];
        }

        let mut actions = self.mempool.on_transaction_gossip(
            self.topology.snapshot(),
            tx,
            submitted_locally,
            self.now,
        );

        // New transaction available — signal for event-driven proposal.
        actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));

        actions
    }

    /// Admit a batch of fetch-delivered transactions through mempool. Called
    /// directly from `io_loop` when a fetch response arrives — bypasses the
    /// gossip-side validation pipeline (the txs came from a peer we asked).
    /// Mempool emits `Continuation(ProtocolEvent::TransactionsAdmitted)` for
    /// the admitted subset; `io_loop`'s interception arm drains the fetch
    /// protocol.
    pub fn on_transactions_fetched(&mut self, txs: Vec<Arc<RoutableTransaction>>) -> Vec<Action> {
        if txs.is_empty() {
            return vec![];
        }
        let mut actions =
            self.mempool
                .on_fetched_transactions(self.topology.snapshot(), txs, self.now);
        actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
        actions
    }
}
