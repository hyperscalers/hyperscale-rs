//! Periodic fetch-tick step handler.
//!
//! `NodeInput::FetchTick` fires on the periodic `FetchTick` timer. It
//! advances every fetch protocol's idle clock so retries / chunk emission
//! progresses without waiting for an admission event. Pending entries
//! are drained by `drive_fetch_admission` on canonical admission events
//! and by explicit `Action::AbandonFetch` actions emitted from the
//! originating coordinator at every expected-set drop site.

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;

use crate::io_loop::IoLoop;
use crate::shard::fetch::FetchInput;
use crate::shard::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    pub(in crate::io_loop) fn handle_fetch_tick(&mut self) {
        let now = std::time::Instant::now();
        let outputs = self.shard_syncs_mut().block_tick(now);
        self.process_block_sync_outputs(outputs);

        let outputs = self.shard_syncs_mut().remote_header_tick(now);
        self.process_remote_header_sync_outputs(outputs);

        self.drive_fetch::<TransactionBinding>(FetchInput::Tick);
        self.drive_fetch::<LocalProvisionBinding>(FetchInput::Tick);
        self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Tick);
        self.drive_fetch::<ProvisionBinding>(FetchInput::Tick);
        self.drive_fetch::<ExecCertBinding>(FetchInput::Tick);

        self.update_fetch_tick_timer();
    }
}
