//! Periodic fetch-tick step handler.
//!
//! `NodeInput::FetchTick` fires on the periodic `FetchTick` timer. It
//! advances every fetch protocol's idle clock so retries / chunk emission
//! progresses without waiting for an admission event. Cross-shard
//! provisions also evict abandoned scopes here via a `state`-reading
//! predicate.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::io_loop::protocol::fetch::FetchInput;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    pub(in crate::io_loop) fn handle_fetch_tick(&mut self) {
        // Tick every fetch protocol. Per-payload bindings drain via
        // `apply_admission` on canonical admission events; cross-shard
        // provisions also evict abandoned scopes via a predicate.
        let now = std::time::Instant::now();
        let outputs = self.protocols.block_sync_tick(now);
        self.process_block_sync_outputs(outputs);

        let outputs = self.protocols.remote_header_sync_tick(now);
        self.process_remote_header_sync_outputs(outputs);

        self.drive_fetch::<TransactionBinding>(FetchInput::Tick);
        self.drive_fetch::<LocalProvisionBinding>(FetchInput::Tick);
        self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Tick);

        self.protocols.provision.evict_abandoned(|id| {
            crate::io_loop::protocol::binding::provisions_is_abandoned(&self.state, id)
        });
        self.drive_fetch::<ProvisionBinding>(FetchInput::Tick);

        self.drive_fetch::<ExecCertBinding>(FetchInput::Tick);

        self.update_fetch_tick_timer();
    }
}
