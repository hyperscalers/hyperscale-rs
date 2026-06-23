//! Shard-side beacon-block-sync wiring.
//!
//! The driving logic lives in [`crate::beacon`]; this file supplies the
//! shard's [`BeaconSyncSink`] (block delivery via the event channel, fetch
//! routing to its own committee) and the thin entry points the dispatch
//! match calls.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{CertifiedBeaconBlock, Epoch, Verifiable};

use crate::beacon::{self, BeaconBlockSync, BeaconSyncSink};
use crate::event::{FetchFailureKind, classify_fetch_error};
use crate::shard::{ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D> BeaconSyncSink for ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    fn beacon_fsm(&mut self) -> &mut BeaconBlockSync {
        &mut self.beacon_block
    }

    fn deliver_block(&mut self, block: Arc<Verifiable<CertifiedBeaconBlock>>) {
        // The block is delivered straight to the coordinator, which runs the
        // same cert verification + adoption as a gossiped block — no inventory
        // bloom, no rehydration, no off-thread structural validation.
        self.dispatch_event(ProtocolEvent::BeaconBlockSyncReadyToApply { block });
    }

    fn dispatch_fetch(&self, epoch: Epoch) {
        let es = self.event_sender().clone();
        let local_shard = self.shard;
        self.process.network.request(
            self.shard,
            None,
            GetBeaconBlockRequest::new(epoch),
            None,
            Box::new(
                move |result: Result<GetBeaconBlockResponse, RequestError>| {
                    match result {
                        Ok(resp) => push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BeaconBlockSyncResponseReceived {
                                epoch,
                                block: resp.block,
                            },
                        ),
                        Err(err) => push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::BeaconBlockSyncFetchFailed {
                                epoch,
                                kind: classify_fetch_error(&err),
                            },
                        ),
                    }
                    // "Peer doesn't have this epoch" is ambiguous (the peer
                    // may simply be behind us) — never Reject.
                    ResponseVerdict::Accept
                },
            ),
        );
    }

    fn beacon_tip(&self) -> Option<Epoch> {
        self.process.beacon_storage.latest_committed_epoch()
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Handle `Action::StartBeaconBlockSync`: feed the FSM and dispatch any
    /// fetch it emits.
    pub(in crate::shard) fn process_start_beacon_block_sync(&mut self, target: Epoch) {
        beacon::start(self, target);
    }

    /// A beacon-block sync response landed.
    pub(in crate::shard) fn handle_beacon_block_sync_response_received(
        &mut self,
        epoch: Epoch,
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    ) {
        beacon::on_response(self, epoch, block);
    }

    /// A beacon-block sync fetch failed at the transport layer.
    pub(in crate::shard) fn handle_beacon_block_sync_fetch_failed(
        &mut self,
        epoch: Epoch,
        kind: FetchFailureKind,
    ) {
        beacon::on_fetch_failed(self, epoch, kind);
    }
}
