//! Writes collected during state tree computation.

use std::sync::Arc;

use hyperscale_jmt::{Node, NodeKey};

/// Writes collected during a `put_at_version` computation.
///
/// Nodes are stored as `(NodeKey, Arc<Node>)` — the canonical hydrated
/// form from the JMT library. Storage backends serialize at write time.
#[derive(Default)]
pub struct CollectedWrites {
    /// New tree nodes created during computation.
    pub nodes: Vec<(NodeKey, Arc<Node>)>,
    /// Keys of nodes that became stale (replaced by new versions).
    pub stale_node_keys: Vec<NodeKey>,
}
