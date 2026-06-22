//! Settled-waves acquisition I/O glue.
//!
//! Bridges
//! [`SettledWavesAcquisitionHost`](crate::shard::settled_set::SettledWavesAcquisitionHost)'s
//! scheduling to the network and to the state machine. The host owns the
//! one-shot fetch-and-verify; this layer turns its
//! [`SettledWavesAcquisitionOutput`]s into `GetSettledWavesRequest`
//! fetches and the verified `Complete` into a `SettledWavesReconstructed`
//! event for the fence.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, BoundedVec, MAX_FINALIZED_TX_PER_BLOCK, SettledWavesRoot, ShardId,
    ValidatorId, WaveId, WeightedTimestamp,
};

use crate::shard::settled_set::SettledWavesAcquisitionOutput;
use crate::shard_loop::{ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartSettledWavesAcquisition`: begin (or retry) a
    /// terminated shard's settled-waves acquisition and dispatch the
    /// window fetch.
    pub(in crate::shard_loop) fn process_start_settled_waves_acquisition(
        &mut self,
        shard: ShardId,
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        terminal_wt: WeightedTimestamp,
        attested_root: SettledWavesRoot,
        peers: Vec<ValidatorId>,
    ) {
        let outputs = self.io.settled_set_sync.start(
            shard,
            terminal_height,
            terminal_block_hash,
            terminal_wt,
            attested_root,
            peers,
        );
        self.process_settled_waves_acquisition_outputs(outputs);
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a settled-waves window list arrived for
    /// `source_shard` (`None` when the peer didn't hold the terminal).
    pub(in crate::shard_loop) fn handle_settled_waves_response_received(
        &mut self,
        source_shard: ShardId,
        waves: Option<BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK>>,
    ) {
        let response = GetSettledWavesResponse { waves };
        let outputs = self
            .io
            .settled_set_sync
            .on_response(source_shard, &response);
        self.process_settled_waves_acquisition_outputs(outputs);
    }

    /// Network callback: a settled-waves fetch failed at the transport
    /// level. The host re-arms and the next `FetchTick` retries.
    pub(in crate::shard_loop) fn handle_settled_waves_fetch_failed(
        &mut self,
        source_shard: ShardId,
    ) {
        self.io.settled_set_sync.on_failure(source_shard);
    }

    /// Drop expired acquisitions and re-issue every parked one on the
    /// periodic tick. The node's current chain weighted timestamp bounds
    /// the self-expiry.
    pub(in crate::shard_loop) fn settled_set_tick(&mut self) {
        let now_wt = self
            .io
            .pending_chain
            .latest_qc()
            .map(|qc| qc.weighted_timestamp());
        let outputs = self.io.settled_set_sync.on_tick(now_wt);
        self.process_settled_waves_acquisition_outputs(outputs);
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route host outputs: `Fetch` → network request, `Complete` →
    /// `SettledWavesReconstructed` event for the fence.
    fn process_settled_waves_acquisition_outputs(
        &mut self,
        outputs: Vec<SettledWavesAcquisitionOutput>,
    ) {
        let local_shard = self.shard;
        for output in outputs {
            match output {
                SettledWavesAcquisitionOutput::Fetch {
                    shard,
                    peer,
                    request,
                } => {
                    let es = self.event_sender().clone();
                    self.process.network.request(
                        shard,
                        peer,
                        request,
                        None,
                        Box::new(move |result: Result<GetSettledWavesResponse, _>| {
                            match result {
                                Ok(response) => push_shard_input(
                                    &es,
                                    local_shard,
                                    ShardScopedInput::SettledWavesResponseReceived {
                                        source_shard: shard,
                                        waves: response.waves,
                                    },
                                ),
                                Err(_) => push_shard_input(
                                    &es,
                                    local_shard,
                                    ShardScopedInput::SettledWavesFetchFailed {
                                        source_shard: shard,
                                    },
                                ),
                            }
                            ResponseVerdict::Accept
                        }),
                    );
                }
                SettledWavesAcquisitionOutput::Complete {
                    shard,
                    waves,
                    terminal_wt,
                } => {
                    self.dispatch_event(ProtocolEvent::SettledWavesReconstructed {
                        shard,
                        waves,
                        terminal_wt,
                    });
                }
            }
        }
    }
}
