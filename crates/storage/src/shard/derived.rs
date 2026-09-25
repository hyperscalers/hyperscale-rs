//! The rows a store derives from one committed leaf.

use hyperscale_types::{EntryKey, Hash, SubstateKey};
use hyperscale_vm_effects::{CrossingLeaf, ProtocolHasher};

use crate::{SweepRows, entry_from_leaf, package_of_cell, sweepable_expiry};

/// What a store indexes beside a leaf, judged from the leaf alone.
///
/// Every index over the cells is derived state — the leaves are the
/// authority — and each family is one judgement of the bytes, so an
/// index built at commit and one rebuilt from imported leaves hold the
/// same rows. A site that lands leaves destructures this whole: a
/// family added here is a family every such site has to place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafRows {
    /// The ordered-collection entry the leaf commits, keyed for range
    /// scans.
    pub entry: Option<(EntryKey, Vec<u8>)>,
    /// The content address the leaf publishes; the artifact is the
    /// leaf's own bytes.
    pub package: Option<Hash>,
    /// The expiry the leaf carries, which is the sweep bucket it counts
    /// under.
    pub sweep: Option<u64>,
    /// Whether the leaf is a crossing record or answer, which is a row of
    /// the crossing index.
    pub crossing: bool,
}

impl LeafRows {
    /// The rows `value` at `key` yields.
    #[must_use]
    pub fn of(key: SubstateKey, value: &[u8]) -> Self {
        Self {
            entry: entry_from_leaf(key, value),
            package: package_of_cell(key, value),
            sweep: sweepable_expiry(key, value),
            crossing: is_crossing(key, value),
        }
    }
}

/// Whether `value` at `key` is a crossing leaf: a record or an answer.
fn is_crossing(key: SubstateKey, value: &[u8]) -> bool {
    CrossingLeaf::read(&ProtocolHasher, key, value).is_some()
}

/// What a committed leaf does to its crossing index row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowChange {
    /// The new value is a crossing leaf: the row is written.
    Put,
    /// The prior was a crossing leaf and the new value is not: the row
    /// goes.
    Delete,
    /// Neither: nothing moves.
    Keep,
}

/// The rows one committed leaf moves that a backend places itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Indexed {
    /// The package the leaf publishes, whose artifact is its own bytes.
    pub package: Option<Hash>,
    /// The leaf's crossing index row.
    pub crossing: RowChange,
}

/// Fold one committed leaf's derived rows: retract the sweep row its
/// prior held, take the one its new value holds, and hand back the
/// package it publishes and what happens to its crossing row.
///
/// The judgement both backends share, so a family added to [`LeafRows`]
/// reaches memory and `RocksDB` at once rather than in two edits that have
/// to agree. What differs between them is where the package artifact
/// lands — a map or a write batch — which is why that half is returned
/// rather than applied.
///
/// Of the prior's rows the sweep row and the crossing row move: the
/// package index is content-addressed and never retracts, and an entry's
/// index row is written from the settled entries. Classifying the prior
/// is what makes a crossing row's delete exact without one per removed
/// cell.
#[must_use]
pub fn index_leaf(
    key: SubstateKey,
    prior: Option<&[u8]>,
    change: Option<&[u8]>,
    sweep_rows: &mut SweepRows,
) -> Indexed {
    let was = prior.and_then(|bytes| sweepable_expiry(key, bytes));
    let LeafRows {
        entry: _,
        package,
        sweep: now,
        crossing,
    } = change.map_or_else(LeafRows::default, |bytes| LeafRows::of(key, bytes));
    sweep_rows.delta(key.owner, was, now);
    let crossing = if crossing {
        RowChange::Put
    } else if prior.is_some_and(|bytes| is_crossing(key, bytes)) {
        RowChange::Delete
    } else {
        RowChange::Keep
    };
    Indexed { package, crossing }
}
