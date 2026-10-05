//! Per-shard cross-shard subsystem.
//!
//! Owns the per-shard state and code for everything a shard does *across*
//! shard boundaries: tracking other shards' certified headers, fetching and
//! serving cross-shard data (provisions, execution certificates, finalized
//! ticks, a departed shard's settled set).
//!
//! [`CrossShardState`] is the per-shard state struct `ShardIo` composes;
//! subsystem-specific FSM instances, bindings, serves, and glue live here
//! beside it.

pub mod crossing_push;
mod exec_cert_serve;
mod fetch;
mod finalization_serve;
mod local_provision_serve;
mod provision_serve;
mod remote_header;
mod remote_header_serve;
mod remote_header_sync;
mod settled_txs_serve;
mod state_proof_serve;

use std::collections::{BTreeMap, BTreeSet};

pub use exec_cert_serve::serve_execution_certs_request;
pub use fetch::{
    ExecCertBinding, ExecCertFetch, FinalizationBinding, FinalizationFetch, LocalProvisionBinding,
    LocalProvisionFetch, ProvisionBinding, ProvisionFetch, SettledTxsBinding, SettledTxsFetch,
    StateProofBinding, StateProofFetch,
};
pub use finalization_serve::serve_finalizations_request;
use hyperscale_types::{Anchor, LocalTimestamp, SubstateKey, TerminalEvidence, ValidatorId};
pub use local_provision_serve::serve_local_provisions_request;
pub use provision_serve::serve_provision_request;
pub use remote_header::RemoteHeaderSyncInput;
use remote_header::{RemoteHeaderSync, RemoteHeaderSyncOutput};
pub use remote_header_serve::{serve_local_certified_headers, serve_remote_headers_request};
pub use settled_txs_serve::{SettledTxsCache, serve_settled_txs_request};
pub use state_proof_serve::{serve_cells_request, serve_state_proof_request};

use crate::config::NodeConfig;
use crate::fetch::FetchConfig;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct CrossShardState {
    /// Multi-shard remote-header sync: tracks other shards' certified header
    /// chains for the cross-shard data dependencies a shard provisions against.
    pub(crate) remote_header_sync: RemoteHeaderSync,

    /// Cross-shard provision fetch (rotates through source committee).
    pub(crate) provision: ProvisionFetch,
    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub(crate) exec_cert: ExecCertFetch,
    /// Finalization fetch (rotates through committee).
    pub(crate) finalization: FinalizationFetch,
    /// Local-provision fetch (pinned to proposer).
    pub(crate) local_provision: LocalProvisionFetch,
    /// State-proof fetch against other shards' commit-proven headers
    /// (rotates through the anchor's committee).
    pub(crate) state_proof: StateProofFetch,
    /// Settled-set fetch against departed shards' terminals (rotates
    /// through the terminal committee).
    pub(crate) settled_txs: SettledTxsFetch,
    /// The pre-cut proofs each seat last named, by terminal.
    pub(crate) precut_wants: SeatWants<(Anchor, SubstateKey)>,
    /// The settled sets each seat last named.
    pub(crate) settled_wants: SeatWants<TerminalEvidence>,
}

/// What each seat last named of a fetch whose consumer re-derives its
/// whole wanted set each pass.
///
/// One fetch serves every seat on the loop, and each seat names its set
/// from its own progress, so a seat behind its siblings still wants ids
/// they have finished with. The fetch keeps every id any seat names: a
/// pass from a caught-up sibling releases nothing a slower seat still
/// asks for.
#[derive(Debug)]
pub struct SeatWants<Id> {
    by_seat: BTreeMap<ValidatorId, BTreeSet<Id>>,
}

impl<Id> Default for SeatWants<Id> {
    fn default() -> Self {
        Self {
            by_seat: BTreeMap::new(),
        }
    }
}

impl<Id: Ord + Clone> SeatWants<Id> {
    /// `seat` now names exactly `wanted` among the ids `within` selects.
    /// Returns every id there that any seat names.
    pub(crate) fn replace(
        &mut self,
        seat: ValidatorId,
        wanted: &BTreeSet<Id>,
        within: impl Fn(&Id) -> bool,
    ) -> BTreeSet<Id> {
        let named = self.by_seat.entry(seat).or_default();
        named.retain(|id| !within(id));
        named.extend(wanted.iter().cloned());
        if named.is_empty() {
            self.by_seat.remove(&seat);
        }
        self.by_seat
            .values()
            .flatten()
            .filter(|id| within(id))
            .cloned()
            .collect()
    }

    /// `seat` left the loop.
    pub(crate) fn forget(&mut self, seat: ValidatorId) {
        self.by_seat.remove(&seat);
    }
}

impl CrossShardState {
    /// Build cross-shard state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        Self {
            remote_header_sync: RemoteHeaderSync::new(remote_header::default_config()),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
            finalization: FinalizationFetch::new(
                "finalization",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            state_proof: StateProofFetch::new(
                "state_proof",
                FetchConfig {
                    max_in_flight: 256,
                    max_ids_per_request: 64,
                    parallel_chunks_per_tick: 2,
                },
            ),
            settled_txs: SettledTxsFetch::new(
                "settled_txs",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 8,
                    parallel_chunks_per_tick: 2,
                },
            ),
            precut_wants: SeatWants::default(),
            settled_wants: SeatWants::default(),
        }
    }

    /// True if any cross-shard FSM (remote-header sync or the cross-shard
    /// fetches) has pending work — keeps this shard's `FetchTick` alive so
    /// deferred work retries.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
            || self.finalization.has_pending()
            || self.local_provision.has_pending()
            || self.state_proof.has_pending()
            || self.settled_txs.has_pending()
    }

    /// Drive the remote-header-sync FSM's periodic tick. Returns range
    /// fetches and any newly-emitted `SyncComplete` for shards that just
    /// caught up.
    pub(crate) fn remote_header_tick(
        &mut self,
        now: LocalTimestamp,
    ) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Tick { now })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::ValidatorId;

    use super::SeatWants;

    const A: ValidatorId = ValidatorId::new(1);
    const B: ValidatorId = ValidatorId::new(2);

    /// A caught-up seat naming nothing keeps what a slower seat still
    /// names; once neither names an id, it goes.
    #[test]
    fn an_id_stays_wanted_while_any_seat_names_it() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        assert_eq!(wants.replace(B, &BTreeSet::from([7]), |_| true), [7].into());
        assert_eq!(wants.replace(A, &BTreeSet::new(), |_| true), [7].into());
        assert!(wants.replace(B, &BTreeSet::new(), |_| true).is_empty());
    }

    /// A pass scoped to some ids leaves the seat's others named.
    #[test]
    fn a_scoped_pass_replaces_only_its_scope() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        let _ = wants.replace(A, &BTreeSet::from([1, 12]), |_| true);
        assert!(wants.replace(A, &BTreeSet::new(), |id| *id < 10).is_empty());
        assert_eq!(
            wants.replace(B, &BTreeSet::new(), |id| *id >= 10),
            [12].into()
        );
    }

    /// A seat that leaves stops holding its ids.
    #[test]
    fn a_seat_that_leaves_names_nothing() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        let _ = wants.replace(B, &BTreeSet::from([7]), |_| true);
        wants.forget(B);
        assert!(wants.replace(A, &BTreeSet::new(), |_| true).is_empty());
    }
}
