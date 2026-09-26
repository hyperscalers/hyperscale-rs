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

use crate::beacon::{self, BeaconProposalBinding, ShardWitnessBinding};
use crate::fetch::FetchInput;
use crate::shard::ShardLoop;
use crate::shard::cross_shard::{
    ExecCertBinding, FinalizationBinding, LocalProvisionBinding, ProvisionBinding,
    SettledTxsBinding, StateProofBinding,
};
use crate::shard::instances::InstanceRecordBinding;
use crate::shard::mempool::TransactionBinding;
use crate::shard::packages::PackageArtifactBinding;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    pub(crate) fn handle_fetch_tick(&mut self) {
        let now = self.now;
        let outputs = self.io.consensus.block_tick(now);
        self.process_block_sync_outputs(outputs);

        beacon::on_tick(self);

        let outputs = self.io.cross_shard.remote_header_tick(now);
        self.process_remote_header_sync_outputs(outputs);

        self.drive_fetch::<TransactionBinding>(FetchInput::Tick);
        self.drive_fetch::<LocalProvisionBinding>(FetchInput::Tick);
        self.drive_fetch::<FinalizationBinding>(FetchInput::Tick);
        self.drive_fetch::<ProvisionBinding>(FetchInput::Tick);
        self.drive_fetch::<ExecCertBinding>(FetchInput::Tick);
        self.drive_fetch::<StateProofBinding>(FetchInput::Tick);
        self.drive_fetch::<SettledTxsBinding>(FetchInput::Tick);
        self.drive_fetch::<ShardWitnessBinding>(FetchInput::Tick);
        self.drive_fetch::<BeaconProposalBinding>(FetchInput::Tick);
        self.drive_fetch::<PackageArtifactBinding>(FetchInput::Tick);
        self.drive_fetch::<InstanceRecordBinding>(FetchInput::Tick);
    }
}
