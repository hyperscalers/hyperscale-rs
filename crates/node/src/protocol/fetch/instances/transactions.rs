//! Transaction fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, TxHash>` to per-block transaction fetches
//! pinned to the proposer.

use crate::protocol::fetch::HashSetFetch;
use hyperscale_types::{BlockHash, TxHash};

/// Composite scope key — the block whose tx set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for transactions.
pub type TransactionFetch = HashSetFetch<Scope, TxHash>;
