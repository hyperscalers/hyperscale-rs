//! Which copies of a tick's execution certificate a store keeps.
//!
//! A certificate carries the outcomes naming its holder, so one tick can
//! reach a shard as more than one copy — a broadcast and a narrower fetch
//! answer for the same batch, or the two halves a shard's own tick
//! finalizes in, each carrying the members that half settles. Copies can
//! be nested or disjoint, and a disjoint pair is two answers: neither
//! carries the other's transactions, and for a shard's own tick nobody
//! else holds them. So a store keeps every copy of a tick that no other
//! copy carries, and answers a transaction with whichever copy carries
//! it. Both backends resolve it here.

use std::borrow::Borrow;
use std::collections::BTreeMap;

use hyperscale_types::{Block, ExecutionCertificate, TickId};

/// Every copy of each tick the block's finalizations carry that no other
/// copy in the block carries.
///
/// Resolves the copies within one block. A store folds each against what
/// it already holds with [`fold_tick_copy`].
#[must_use]
pub fn tick_copies(block: &Block) -> BTreeMap<TickId, Vec<&ExecutionCertificate>> {
    let mut copies: BTreeMap<TickId, Vec<&ExecutionCertificate>> = BTreeMap::new();
    for finalization in block.certificates().iter() {
        for cert in finalization.execution_certificates() {
            let cert = cert.as_unverified();
            fold_tick_copy(copies.entry(*cert.tick_id()).or_default(), cert);
        }
    }
    copies
}

/// Fold `candidate` into the copies held of its tick: kept unless a held
/// copy already carries every outcome it does, and evicting each held copy
/// it carries every outcome of. Returns whether it was kept.
///
/// The held copies never lose ground — every outcome one of them carried
/// is still carried by some copy afterwards — which is what keeps a
/// transaction index pointing at a copy that answers for it.
pub fn fold_tick_copy<C: Borrow<ExecutionCertificate>>(held: &mut Vec<C>, candidate: C) -> bool {
    if held
        .iter()
        .any(|copy| carries_all_of(copy.borrow(), candidate.borrow()))
    {
        return false;
    }
    held.retain(|copy| !carries_all_of(candidate.borrow(), copy.borrow()));
    held.push(candidate);
    true
}

/// Whether `wider` carries every outcome `narrower` does.
fn carries_all_of(wider: &ExecutionCertificate, narrower: &ExecutionCertificate) -> bool {
    if wider.leaf_indices().len() < narrower.leaf_indices().len() {
        return false;
    }
    // Leaf indices are ascending and distinct on both sides, so one
    // forward walk of the wider copy decides containment.
    let mut carried = wider.leaf_indices().iter();
    narrower
        .leaf_indices()
        .iter()
        .all(|index| carried.any(|leaf| leaf == index))
}
