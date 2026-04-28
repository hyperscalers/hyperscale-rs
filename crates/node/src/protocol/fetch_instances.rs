//! Per-payload bindings of the generic [`Fetch`] state machine.
//!
//! Each payload type gets a `FooFetch` type alias and an `apply_*_admission`
//! shim that converts the canonical admission `ProtocolEvent` into a
//! [`FetchInput::Admitted`] drop. Shims are called from `io_loop`'s
//! `Action::Continuation` interception arm; they are no-ops for events the
//! instance doesn't subscribe to.

use crate::protocol::fetch::{Fetch, FetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHeight, ProvisionHash, ShardGroupId, TxHash, WaveId, WaveIdHash};

// ─── Transaction fetch ──────────────────────────────────────────────

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;

/// Drain admitted ids on `TransactionsAdmitted`.
pub fn apply_transactions_admission(fetch: &mut TransactionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::TransactionsAdmitted { txs } = event {
        let ids: Vec<TxHash> = txs.iter().map(|tx| tx.hash()).collect();
        fetch.handle(FetchInput::Admitted { ids });
    }
}

// ─── Local-provision fetch ──────────────────────────────────────────

/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;

/// Drain admitted ids on `ProvisionsAdmitted`.
pub fn apply_local_provisions_admission(fetch: &mut LocalProvisionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
        fetch.handle(FetchInput::Admitted {
            ids: vec![provisions.hash()],
        });
    }
}

// ─── Finalized-wave fetch ───────────────────────────────────────────

/// Finalized-wave fetch keyed by [`WaveIdHash`].
pub type FinalizedWaveFetch = Fetch<WaveIdHash>;

/// Drain admitted ids on `FinalizedWavesAdmitted`.
pub fn apply_finalized_waves_admission(fetch: &mut FinalizedWaveFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::FinalizedWavesAdmitted { waves } = event {
        let ids: Vec<WaveIdHash> = waves.iter().map(|w| w.wave_id_hash()).collect();
        fetch.handle(FetchInput::Admitted { ids });
    }
}

// ─── Execution-cert fetch ───────────────────────────────────────────

/// Cross-shard execution-cert fetch keyed by [`WaveId`].
pub type ExecCertFetch = Fetch<WaveId>;

/// Drain the admitted `wave_id` on `ExecutionCertificateAdmitted`.
pub fn apply_exec_certs_admission(fetch: &mut ExecCertFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ExecutionCertificateAdmitted { wave_id } = event {
        fetch.handle(FetchInput::Admitted {
            ids: vec![wave_id.clone()],
        });
    }
}

// ─── Cross-shard provision fetch ────────────────────────────────────

/// Cross-shard provision fetch keyed by `(source_shard, block_height)`.
pub type ProvisionFetch = Fetch<(ShardGroupId, BlockHeight)>;

/// Drain the matching scope on `ProvisionsAdmitted`.
pub fn apply_provisions_admission(fetch: &mut ProvisionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
        fetch.handle(FetchInput::Admitted {
            ids: vec![(provisions.source_shard, provisions.block_height)],
        });
    }
}

/// A cross-shard provision id is abandoned once `ProvisionCoordinator` no
/// longer expects provisions for it — the verified remote header that
/// registered the expectation has either been satisfied or pruned.
/// Lifetime is bound by `ProvisionCoordinator`'s expected-set, not by
/// admission events alone.
#[must_use]
pub fn provisions_is_abandoned(state: &NodeStateMachine, id: &(ShardGroupId, BlockHeight)) -> bool {
    let (shard, height) = *id;
    !state.provisions().is_expected(shard, height)
}

// ─── Cross-shard header fetch ───────────────────────────────────────

/// Cross-shard header fetch keyed by `(source_shard, block_height)`.
pub type HeaderFetch = Fetch<(ShardGroupId, BlockHeight)>;

/// Drain the matching scope on `RemoteHeaderAdmitted`.
pub fn apply_headers_admission(fetch: &mut HeaderFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = event {
        fetch.handle(FetchInput::Admitted {
            ids: vec![(committed_header.shard_group_id(), committed_header.height())],
        });
    }
}
