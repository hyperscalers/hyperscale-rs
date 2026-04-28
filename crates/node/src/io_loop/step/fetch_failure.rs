//! Fetch-failure step handlers.
//!
//! Each `*FetchFailed` `NodeInput` variant feeds one binding's `Failed`
//! input then ticks the timer. The shape is uniform across all six
//! payloads — drive the binding, refresh the tick timer, done.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::binding::{
    ExecCertBinding, FinalizedWaveBinding, HeaderBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::io_loop::protocol::fetch::FetchInput;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHeight, ProvisionHash, ShardGroupId, TxHash, WaveId, WaveIdHash};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    pub(in crate::io_loop) fn handle_fetch_transactions_failed(&mut self, hashes: Vec<TxHash>) {
        self.drive_fetch::<TransactionBinding>(FetchInput::Failed { ids: hashes });
    }

    pub(in crate::io_loop) fn handle_local_provisions_fetch_failed(
        &mut self,
        hashes: Vec<ProvisionHash>,
    ) {
        self.drive_fetch::<LocalProvisionBinding>(FetchInput::Failed { ids: hashes });
        self.update_fetch_tick_timer();
    }

    pub(in crate::io_loop) fn handle_finalized_wave_fetch_failed(
        &mut self,
        hashes: Vec<WaveIdHash>,
    ) {
        self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Failed { ids: hashes });
        self.update_fetch_tick_timer();
    }

    pub(in crate::io_loop) fn handle_provisions_fetch_failed(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    ) {
        self.drive_fetch::<ProvisionBinding>(FetchInput::Failed {
            ids: vec![(source_shard, block_height)],
        });
        self.update_fetch_tick_timer();
    }

    pub(in crate::io_loop) fn handle_exec_cert_fetch_failed(&mut self, hashes: Vec<WaveId>) {
        self.drive_fetch::<ExecCertBinding>(FetchInput::Failed { ids: hashes });
        self.update_fetch_tick_timer();
    }

    pub(in crate::io_loop) fn handle_header_fetch_failed(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    ) {
        self.drive_fetch::<HeaderBinding>(FetchInput::Failed {
            ids: vec![(source_shard, from_height)],
        });
        self.update_fetch_tick_timer();
    }
}
