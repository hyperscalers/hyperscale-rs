//! Local-provision fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, ProvisionHash>` to per-block local provision
//! fetches pinned to the proposer.

use crate::protocol::fetch::HashSetFetch;
use hyperscale_types::{BlockHash, ProvisionHash};

/// Composite scope key — the block whose provision set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for local provisions.
pub type LocalProvisionFetch = HashSetFetch<Scope, ProvisionHash>;
