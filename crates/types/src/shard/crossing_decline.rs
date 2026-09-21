//! What a block carries when this shard refuses a crossing it was
//! handed.
//!
//! A crossing obliges its consumer to answer. Taking it is a claim,
//! written inside the session that took the value; refusing it is this,
//! and it cannot be written the same way — a refused member's writes are
//! discarded, and a member that was never composed writes nothing at
//! all, which is the case a decline exists for. So the chain writes it,
//! from what the block carries, and every replica folds the same cell.
//!
//! What the block has to carry is the crossing's own record cell. The
//! consumer holds no leaf for a crossing it has not answered — that is
//! the whole asymmetry of this direction — and the terms the rule reads
//! live nowhere else it can reach: the deadline the refusal is fenced
//! at, the claim cell that must be absent, the transaction whose members
//! must all be gone, and whether the crossing may be declined at all.
//!
//! Carrying them is not trusting them. The record key pins the edge,
//! since the cell's own value must re-derive it; the rest is pinned by
//! the [`StateClaim`](crate::StateClaim) the same block carries, whose
//! presence reading is the leaf's **value hash** — so every field is the
//! producer's own committed bytes or the entry is refused.

use hyperscale_hbor::Hbor;
use hyperscale_vm_effects::{CrossingCell, ProtocolHasher, escrow_record_key};

use crate::state_key::jmt_value_hash;
use crate::{Inclusion, SubstateKey};

/// One crossing this block declines: the record on the producer's chain,
/// and the record's own committed cell.
///
/// Ordered by the record it names, which is one per crossing, so a
/// block's declines have one encoding and a voter walking them walks the
/// order it would have built.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct CrossingDecline {
    /// The record cell, under the producing node's target.
    pub record: SubstateKey,
    /// What that cell holds, as the producer committed it.
    pub cell: CrossingCell,
}

impl CrossingDecline {
    /// The decline of the crossing `cell` records, which sits at
    /// `record` on its producer's chain.
    #[must_use]
    pub const fn new(record: SubstateKey, cell: CrossingCell) -> Self {
        Self { record, cell }
    }

    /// Whether the cell names the record it is carried for: the edge
    /// re-derives the key under the record's owner, as a record's own
    /// value does.
    ///
    /// What this pins is the edge — the intent, the node and the output
    /// — and so the claim key the rule reads absent and the decline key
    /// the block writes, both of which derive from that edge under the
    /// consuming node's target. What it does not pin is the rest of the
    /// cell, and that is the [`StateClaim`](crate::StateClaim)'s job:
    /// the value hash a presence reading carries is what makes the
    /// deadline, the transaction and the terms the producer's own bytes
    /// rather than the proposer's.
    #[must_use]
    pub fn names_its_record(&self) -> bool {
        escrow_record_key(
            &ProtocolHasher,
            self.record.owner,
            self.cell.intent,
            self.cell.local,
            self.cell.output,
        ) == self.record
    }

    /// Whether `reading` of the record is the producer's own bytes for
    /// the cell this decline carries.
    ///
    /// A presence carries the leaf's value hash and nothing else a
    /// reader could weigh, so this is the whole of what ties a carried
    /// cell to committed state — and it is what the rule's every other
    /// term is read off, since a key pins only the edge.
    #[must_use]
    pub fn stands_against(&self, reading: Inclusion) -> bool {
        reading.value_hash() == Some(jmt_value_hash(&self.cell.to_bytes()))
    }
}
