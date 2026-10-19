//! Periodic fetch-tick step handler.
//!
//! `ShardScopedInput::FetchTick` fires on the periodic `FetchTick` timer
//! this shard schedules for itself. It advances every fetch protocol's
//! idle clock so retries / chunk emission progresses without waiting for
//! an admission event. Pending entries are drained by
//! `drive_fetch_admission` on canonical admission events and by explicit
//! `Action::AbandonFetch` actions emitted from the originating coordinator
//! at every expected-set drop site.

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;

use crate::beacon;
use crate::shard::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    pub(crate) fn handle_fetch_tick(&mut self) {
        self.fetch_tick.fired();
        let now = self.now;
        let outputs = self.io.consensus.block_tick(now);
        self.process_block_sync_outputs(outputs);

        beacon::on_tick(self);

        let outputs = self.io.cross_shard.remote_header_tick(now);
        self.process_remote_header_sync_outputs(outputs);

        self.tick_every_fetch();
    }
}
