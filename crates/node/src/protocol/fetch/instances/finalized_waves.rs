//! Finalized-wave fetch instance binding.
//!
//! Wires `IdFetch<WaveIdHash>` to finalized-wave fetches.

use crate::protocol::fetch::{IdFetch, IdFetchInput};
use hyperscale_core::ProtocolEvent;
use hyperscale_types::WaveIdHash;

/// The typed fetch protocol instance for finalized waves.
pub type FinalizedWaveFetch = IdFetch<WaveIdHash>;

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event.
pub fn apply_admission(fetch: &mut FinalizedWaveFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::FinalizedWavesAdmitted { waves } = event {
        let ids: Vec<WaveIdHash> = waves.iter().map(|w| w.wave_id_hash()).collect();
        fetch.handle(IdFetchInput::Admitted { ids });
    }
}
