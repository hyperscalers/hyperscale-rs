//! Periodic fetch-tick step handler.
//!
//! `ProcessScopedInput::FetchTick` fires on the periodic `FetchTick` timer. It
//! advances every fetch protocol's idle clock so retries / chunk emission
//! progresses without waiting for an admission event. Pending entries
//! are drained by `drive_fetch_admission` on canonical admission events
//! and by explicit `Action::AbandonFetch` actions emitted from the
//! originating coordinator at every expected-set drop site.

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::ShardGroupId;

use crate::io_loop::IoLoop;
use crate::shard_io::fetch::FetchInput;
use crate::shard_io::fetch::binding::{
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
        let hosted: Vec<ShardGroupId> = self.hosted_shards().collect();
        for shard in hosted {
            let sl = self.shard_loop_mut(shard);
            let outputs = sl.io.syncs.block_tick(now);
            sl.process_block_sync_outputs(outputs);

            let sl = self.shard_loop_mut(shard);
            let outputs = sl.io.syncs.remote_header_tick(now);
            sl.process_remote_header_sync_outputs(outputs);

            let sl = self.shard_loop_mut(shard);
            sl.drive_fetch::<TransactionBinding>(FetchInput::Tick);
            sl.drive_fetch::<LocalProvisionBinding>(FetchInput::Tick);
            sl.drive_fetch::<FinalizedWaveBinding>(FetchInput::Tick);
            sl.drive_fetch::<ProvisionBinding>(FetchInput::Tick);
            sl.drive_fetch::<ExecCertBinding>(FetchInput::Tick);
        }
    }
}
