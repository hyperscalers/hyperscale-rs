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
            let outputs = self.shard_io_mut(shard).syncs.block_tick(now);
            self.process_block_sync_outputs(shard, outputs);

            let outputs = self.shard_io_mut(shard).syncs.remote_header_tick(now);
            self.process_remote_header_sync_outputs(shard, outputs);

            self.drive_fetch::<TransactionBinding>(shard, FetchInput::Tick);
            self.drive_fetch::<LocalProvisionBinding>(shard, FetchInput::Tick);
            self.drive_fetch::<FinalizedWaveBinding>(shard, FetchInput::Tick);
            self.drive_fetch::<ProvisionBinding>(shard, FetchInput::Tick);
            self.drive_fetch::<ExecCertBinding>(shard, FetchInput::Tick);
        }
    }
}
