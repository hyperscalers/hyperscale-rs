//! Fetch-delivery step handlers.
//!
//! Five `NodeInput` variants funnel delivered payloads (txs, ECs,
//! provisions, finalized waves, outbound provisions) into the appropriate
//! state-machine entry point. Most do `let actions = state.on_*(payload);
//! process_actions(actions);` then refresh the tick timer; the
//! `LocalProvisionReceived` path additionally signals `Failed` for any
//! missing hashes so the in-flight set retries.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::binding::TransactionBinding;
use crate::io_loop::protocol::fetch::FetchInput;
use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{
    ExecutionCertificate, FinalizedWave, ProvisionHash, Provisions, RoutableTransaction, TxHash,
    WaveIdHash,
};
use std::sync::Arc;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Route delivered txs through mempool admission, then drain every
    /// delivered hash from the fetch protocol and signal `Failed` for
    /// hashes the peer didn't return. Mempool's `TransactionsAdmitted`
    /// event covers only newly-admitted txs — txs rejected as duplicates
    /// / tombstoned / validity-expired don't surface there, so we drop
    /// them from the fetch FSM directly. Without the explicit
    /// `Admitted` drain, redundant fetch responses pin entries in the
    /// pending set forever; without the `Failed` signal for missing
    /// hashes, partial responses leak `in_flight=true` entries that the
    /// next tick can't redispatch — both leaks ratchet
    /// `fetch_in_flight{kind=transaction}` upward.
    pub(in crate::io_loop) fn handle_transactions_received(
        &mut self,
        transactions: Vec<Arc<RoutableTransaction>>,
        missing_hashes: Vec<TxHash>,
    ) {
        let delivered_hashes: Vec<TxHash> = transactions.iter().map(|tx| tx.hash()).collect();
        let actions = self.state.on_transactions_fetched(transactions);
        self.process_actions(actions);
        if !delivered_hashes.is_empty() {
            self.drive_fetch::<TransactionBinding>(FetchInput::Admitted {
                ids: delivered_hashes,
            });
        }
        if !missing_hashes.is_empty() {
            self.drive_fetch::<TransactionBinding>(FetchInput::Failed {
                ids: missing_hashes,
            });
        }
    }

    /// Each delivered cert flows through `on_wave_certificate`, which emits
    /// `Continuation(ExecutionCertificateAdmitted)`. `io_loop`'s
    /// interception arm drains the exec-cert fetch protocol per wave.
    pub(in crate::io_loop) fn handle_execution_certs_received(
        &mut self,
        certificates: Vec<ExecutionCertificate>,
    ) {
        let actions = self.state.on_execution_certs_received(certificates);
        self.process_actions(actions);
        self.update_fetch_tick_timer();
    }

    /// Fetched batches enter the verification pipeline. Successful
    /// verification emits `Continuation(ProvisionsAdmitted)`, which drains
    /// both the cross-shard `provision_fetch` (by scope) and the local-block
    /// `local_provision_fetch` (by hash). Missing hashes still need a
    /// `Failed` signal so the in-flight set can retry; admission events
    /// drain the rest.
    pub(in crate::io_loop) fn handle_local_provision_received(
        &mut self,
        batches: Vec<Arc<Provisions>>,
        missing_hashes: Vec<ProvisionHash>,
    ) {
        if !missing_hashes.is_empty() {
            self.protocols.local_provision.handle(FetchInput::Failed {
                ids: missing_hashes,
            });
        }
        for provisions in batches {
            self.feed_event(ProtocolEvent::ProvisionsReceived {
                provisions: (*provisions).clone(),
            });
        }
        self.update_fetch_tick_timer();
    }

    /// Each delivered wave is funnelled through
    /// `ExecutionCoordinator::admit_finalized_wave`, which emits
    /// `Continuation(FinalizedWavesAdmitted)`. `io_loop`'s interception arm
    /// drains the fetch protocol; state.rs forwards to the BFT subscriber.
    /// `missing_hashes` (requested but not returned by the peer) are fed
    /// to the fetch FSM as `Failed` so the next tick redispatches them.
    pub(in crate::io_loop) fn handle_finalized_wave_received(
        &mut self,
        waves: Vec<Arc<FinalizedWave>>,
        missing_hashes: Vec<WaveIdHash>,
    ) {
        if !missing_hashes.is_empty() {
            self.protocols.finalized_wave.handle(FetchInput::Failed {
                ids: missing_hashes,
            });
        }
        for wave in waves {
            let actions = self.state.execution().admit_finalized_wave(wave);
            self.process_actions(actions);
        }
        self.update_fetch_tick_timer();
    }
}
