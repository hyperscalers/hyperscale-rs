//! Transaction-flow handlers.
//!
//! Four `ProtocolEvent` variants drive the transaction pipeline:
//! - `TransactionValidated` — gossip-delivered tx that passed async validation
//!   → mempool admission;
//! - `TransactionsReceived` — fetch-delivered batch → mempool admission;
//! - `TransactionsAdmitted` — mempool emits this after admission; shard consensus's
//!   pending-block subscriber consumes it and we latch a proposal-retry;
//! - `TransactionsResolved` — the execution coordinator settled what a core's
//!   certificates mean for legs issued here → mempool status.
//!
//! Raw gossip arrivals enter `NodeHost` as `ShardScopedInput::TransactionGossipReceived`
//! and never reach the state machine; the validated form does.

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{TopologySchedule, Transaction, Verified};

use super::ShardParticipation;

impl ShardParticipation {
    /// The mempool admitted `txs`: shard consensus's pending-block
    /// subscriber takes them, and the next proposal may carry them.
    ///
    /// A newly-admitted transaction that opened before this chain did is
    /// refused until a predecessor answers for it. Asking here rather
    /// than waiting for the cleanup tick is what keeps the refusal from
    /// costing a full tick of latency per arrival.
    pub(in crate::replica) fn on_transactions_admitted(
        &mut self,
        sched: &TopologySchedule,
        txs: &[Arc<Verified<Transaction>>],
    ) -> Vec<Action> {
        let mut actions = self.shard_coordinator.on_transactions_admitted(sched, txs);
        actions.extend(self.scan_precut_queries());
        self.shard_coordinator.queue_ready_proposal();
        actions
    }

    /// Hand a validated transaction to the canonical mempool: one a client
    /// of this node submitted through the submission path, which records
    /// its `Pending` status for the client's lookup, and a peer's through
    /// the gossip path. Mempool emits `Continuation(TransactionsAdmitted)`
    /// for whatever it admits; that arm latches the proposal-retry — no
    /// need to do it optimistically here.
    pub(in crate::replica) fn on_transaction_validated(
        &mut self,
        sched: &TopologySchedule,
        tx: Arc<Verified<Transaction>>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        if !sched.head().involves_shard(self.local_shard, &tx) {
            return vec![];
        }

        if submitted_locally {
            self.mempool_coordinator
                .on_submit_transaction(sched.head(), tx, self.now)
        } else {
            self.mempool_coordinator
                .on_transaction_gossip(sched.head(), tx, self.now)
        }
    }

    /// Admit a batch of fetch-delivered transactions through mempool. The
    /// batch already passed the io-loop's validation pipeline upstream
    /// (`handle_fetched_txs_for_validation`); invalid-signature txs were
    /// dropped before reaching this arm. Mempool emits
    /// `Continuation(TransactionsAdmitted)` for the admitted subset; the
    /// admission arm latches the proposal-retry.
    pub(in crate::replica) fn on_transactions_fetched(
        &mut self,
        sched: &TopologySchedule,
        txs: Vec<Arc<Verified<Transaction>>>,
    ) -> Vec<Action> {
        if txs.is_empty() {
            return vec![];
        }
        self.mempool_coordinator
            .on_fetched_transactions(sched.head(), txs, self.now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_core::{ProtocolEvent, StateMachine};
    use hyperscale_types::test_utils::{test_transaction, test_transaction_with_prefixes};
    use hyperscale_types::{LocalTimestamp, Verified};

    use crate::replica::test_support::TestNode;

    /// Validated gossip transactions are gated by the local-shard filter
    /// before reaching mempool. A tx with empty reads/writes never
    /// involves any shard, so the local-shard predicate rejects it and
    /// the mempool stays empty.
    #[test]
    fn transaction_validated_drops_tx_with_no_local_shard_involvement() {
        let TestNode { mut node, .. } = TestNode::new();

        let tx = Arc::new(Verified::new_unchecked_for_test(
            test_transaction_with_prefixes(
                b"empty-shards-xyz",
                /* read_nodes */ &[],
                /* write_nodes */ &[],
            ),
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
            node.mempool_coordinator().len(),
            0,
            "non-local tx must not enter the mempool",
        );
    }

    /// Counterpart to the rejection test: a tx that touches a local node
    /// must reach the mempool (with `num_shards = 1` every node maps to
    /// `ShardId::ROOT`).
    #[test]
    fn transaction_validated_routes_local_shard_tx_to_mempool() {
        let TestNode { mut node, .. } = TestNode::new();
        let tx = Arc::new(Verified::new_unchecked_for_test(test_transaction(
            /* seed */ 1,
        )));

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionValidated {
                tx,
                submitted_locally: true,
            },
        );

        assert_eq!(
            node.mempool_coordinator().len(),
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
            Arc::new(Verified::new_unchecked_for_test(test_transaction(
                /* seed */ 1,
            ))),
            Arc::new(Verified::new_unchecked_for_test(test_transaction(
                /* seed */ 2,
            ))),
        ];

        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::TransactionsReceived { transactions: txs },
        );

        assert_eq!(
            node.mempool_coordinator().len(),
            2,
            "fetched txs must be admitted via the fetch path",
        );
    }
}
