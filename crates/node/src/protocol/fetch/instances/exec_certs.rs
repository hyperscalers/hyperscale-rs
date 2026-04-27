//! Execution-certificate fetch instance binding.
//!
//! Wires `IdFetch<WaveId>` to cross-shard execution-cert fetches that rotate
//! through the source committee. Lifetime is bounded by
//! `ExecutionCertificateAdmitted` admission and explicit cancels from
//! `ExecutionCoordinator` when waves age out of relevance.

use crate::protocol::fetch::{IdFetch, IdFetchInput};
use hyperscale_core::ProtocolEvent;
use hyperscale_types::WaveId;

/// The typed fetch protocol instance for execution certificates.
pub type ExecCertFetch = IdFetch<WaveId>;

/// Drain the admitted `wave_id` from the fetch protocol on the canonical
/// admission event.
pub fn apply_admission(fetch: &mut ExecCertFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ExecutionCertificateAdmitted { wave_id } = event {
        fetch.handle(IdFetchInput::Admitted {
            ids: vec![wave_id.clone()],
        });
    }
}
