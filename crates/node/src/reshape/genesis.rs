//! A reshape successor's locally derived genesis.

use hyperscale_types::{Anchor, Block, ChainOrigin};

/// A successor genesis derived locally from its predecessors' terminal
/// blocks: a split child's from its parent's terminal, a merged parent's
/// from both children's.
#[derive(Debug, Clone)]
pub struct DerivedGenesis {
    /// The genesis block the successor adopts.
    pub block: Block,
    /// The chain origin it starts from.
    pub origin: ChainOrigin,
    /// The terminals the successor succeeds, carried off the same headers
    /// the genesis derives from — one for a split child, two for a merged
    /// parent, none when a terminal carries no terminal settled root.
    pub predecessors: Vec<Anchor>,
}
