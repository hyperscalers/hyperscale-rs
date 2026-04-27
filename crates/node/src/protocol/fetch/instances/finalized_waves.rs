//! Finalized-wave fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, WaveIdHash>` to per-block finalized-wave
//! fetches that rotate from the proposer through local-committee peers.

use crate::protocol::fetch::HashSetFetch;
use hyperscale_types::{BlockHash, WaveIdHash};

/// Composite scope key — the block whose finalized-wave set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for finalized waves.
pub type FinalizedWaveFetch = HashSetFetch<Scope, WaveIdHash>;
