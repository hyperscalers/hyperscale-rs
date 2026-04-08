//! Writes collected during state tree computation.

use std::sync::Arc;

use jellyfish_verkle_tree as jvt;

/// Writes collected during a `put_at_version` computation.
///
/// Nodes are stored as `(jvt::NodeKey, Arc<jvt::Node>)` — the canonical hydrated
/// form from the JVT library. Storage backends serialize at write time.
/// The cache takes the hydrated form directly.
#[derive(Default)]
pub struct CollectedWrites {
    /// New tree nodes created during computation.
    pub nodes: Vec<(jvt::NodeKey, Arc<jvt::Node>)>,
    /// Keys of nodes that became stale (replaced by new versions).
    pub stale_node_keys: Vec<jvt::NodeKey>,
}
