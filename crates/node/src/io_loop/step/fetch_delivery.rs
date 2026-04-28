//! Fetch-delivery step handlers.
//!
//! Five `NodeInput` variants funnel delivered payloads (txs, ECs,
//! provisions, finalized waves, outbound provisions) into the appropriate
//! state-machine entry point. Most do `let actions = state.on_*(payload);
//! process_actions(actions);` then refresh the tick timer; the
//! `LocalProvisionReceived` path additionally signals `Failed` for any
//! missing hashes so the in-flight set retries.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::fetch::FetchInput;
use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{
    ExecutionCertificate, FinalizedWave, ProvisionHash, Provisions, RoutableTransaction,
};
use std::sync::Arc;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Route delivered txs through mempool admission. Fetch-protocol drain
    /// happens via the resulting `Continuation(TransactionsAdmitted)`
    /// interception.
    pub(in crate::io_loop) fn handle_transactions_received(
        &mut self,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) {
        let actions = self.state.on_transactions_fetched(transactions);
        self.process_actions(actions);
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
    pub(in crate::io_loop) fn handle_finalized_wave_received(
        &mut self,
        waves: Vec<Arc<FinalizedWave>>,
    ) {
        for wave in waves {
            let actions = self.state.execution().admit_finalized_wave(wave);
            self.process_actions(actions);
        }
        self.update_fetch_tick_timer();
    }
}
