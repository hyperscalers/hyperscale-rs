//! Finalized-wave fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, WaveIdHash>` to per-block finalized-wave
//! fetches that rotate from the proposer through local-committee peers.

use crate::protocol::fetch::{HashSetFetch, HashSetFetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHash, WaveIdHash};

/// Composite scope key — the block whose finalized-wave set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for finalized waves.
pub type FinalizedWaveFetch = HashSetFetch<Scope, WaveIdHash>;

/// A scope is abandoned once BFT no longer holds a pending block for it.
#[must_use]
pub fn is_abandoned(state: &NodeStateMachine, scope: &Scope) -> bool {
    !state.bft().has_pending_block(*scope)
}

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event.
pub fn apply_admission(fetch: &mut FinalizedWaveFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::FinalizedWavesAdmitted { waves } = event {
        let ids: Vec<WaveIdHash> = waves.iter().map(|w| w.wave_id_hash()).collect();
        fetch.handle(HashSetFetchInput::Admitted { ids });
    }
}
