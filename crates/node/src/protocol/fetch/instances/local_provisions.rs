//! Local-provision fetch instance binding.
//!
//! Wires `IdFetch<ProvisionHash>` to local-provision fetches. Drains via the
//! same `ProvisionsAdmitted` event the cross-shard `ProvisionFetch` uses.

use crate::protocol::fetch::{IdFetch, IdFetchInput};
use hyperscale_core::ProtocolEvent;
use hyperscale_types::ProvisionHash;

/// The typed fetch protocol instance for local provisions.
pub type LocalProvisionFetch = IdFetch<ProvisionHash>;

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event.
pub fn apply_admission(fetch: &mut LocalProvisionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
        fetch.handle(IdFetchInput::Admitted {
            ids: vec![provisions.hash()],
        });
    }
}
