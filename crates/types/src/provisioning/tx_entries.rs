//! Per-transaction state entries within a provision.

use crate::{NodeId, StateEntry, TxHash};
use sbor::prelude::*;
use std::collections::HashSet;

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction, what state it touched on the source shard,
/// and what nodes it needs from the target shard (for conflict detection).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxEntries {
    /// Hash of the transaction.
    pub tx_hash: TxHash,

    /// The state entries this transaction touched on the source shard.
    pub entries: Vec<StateEntry>,

    /// Node IDs this transaction needs from the target shard.
    ///
    /// Used for bidirectional conflict detection: a true deadlock requires
    /// overlap in both directions (source nodes vs local needs, AND target
    /// nodes vs local owns).
    pub target_nodes: Vec<NodeId>,
}

impl TxEntries {
    /// Get the node IDs referenced by this transaction's entries.
    #[must_use]
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries
            .iter()
            .filter_map(StateEntry::node_id)
            .collect()
    }
}
