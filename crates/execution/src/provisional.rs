//! What unresolved cross-shard legs hold, and the test a candidate
//! transaction has to pass to join a tick.
//!
//! A cross-shard leg's local writes are provisional until its tick
//! resolves. Whether that stops a later transaction depends entirely on
//! *how* each of them reaches the cell, and the kernel already decides
//! that: [`compatible`] is the same relation it uses to schedule a batch,
//! asked here across a boundary the batch cannot see.
//!
//! The two commutative modes are what make this worth asking. A delta and
//! a reservation each say what they moved rather than what the cell ends
//! at, so neither depends on seeing the other and settlement composes
//! them in any order — two payments on one vault need not take turns. A
//! fresh read does depend on seeing it, and an exclusive write carries an
//! absolute that cannot be composed with anything, so both still wait.
//!
//! The claim is a leg's *declared* access rather than the writes it
//! turned out to make: every substate a transaction touches is declared,
//! so the declaration covers the outcome, and it is known when the leg
//! joins its tick rather than when its batch comes back.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    Address, CollectionId, DeclaredKey, Mode, ModeKind, SubstateKey, compatible,
};

/// How unresolved legs are reaching the cells they claimed.
///
/// Claims and candidates are both [`DeclaredKey`]s, which name one cell
/// or one collection interval. A collection interval covers other
/// intervals of the same collection and nothing else — an interval is
/// over entries, and no point cell is an entry. Overlap alone decides
/// nothing; what decides is whether the modes on the two sides can be in
/// flight together.
#[derive(Debug, Default)]
pub struct ProvisionalCells {
    cells: BTreeMap<SubstateKey, BTreeSet<ModeKind>>,
    /// Modes held per collection, interval-insensitive: two intervals of
    /// one collection contend by mode alone, the conservative half of
    /// the kernel's overlap arithmetic.
    collections: BTreeMap<(Address, CollectionId), BTreeSet<ModeKind>>,
}

impl ProvisionalCells {
    /// Record how one unresolved leg declared it would reach each cell.
    pub(crate) fn claim(&mut self, declared: &[(DeclaredKey, Mode)]) {
        for (key, mode) in declared {
            let kind = mode.kind();
            match key {
                DeclaredKey::Cell(cell) => {
                    self.cells.entry(*cell).or_default().insert(kind);
                }
                DeclaredKey::Range(range) => {
                    self.collections
                        .entry((range.owner, range.collection))
                        .or_default()
                        .insert(kind);
                }
            }
        }
    }

    /// Whether nothing is claimed — the common case, and worth
    /// short-circuiting on since it spares every candidate the walk.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.collections.is_empty()
    }

    /// Whether a candidate's declared access cannot be in flight beside
    /// what is already held.
    ///
    /// Incompatible on any one cell is enough: the candidate is one
    /// transaction and it executes whole or not at all.
    #[must_use]
    pub(crate) fn blocks(&self, declared: &[(DeclaredKey, Mode)]) -> bool {
        declared.iter().any(|(key, mode)| {
            let candidate = mode.kind();
            let held = match key {
                DeclaredKey::Cell(cell) => self.cells.get(cell),
                // A candidate interval contends with claims on its own
                // collection — never with point cells, which no interval
                // contains.
                DeclaredKey::Range(range) => self.collections.get(&(range.owner, range.collection)),
            };
            held.into_iter()
                .flat_map(BTreeSet::iter)
                .any(|held| !compatible(*held, candidate))
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{AddressClass, DeclaredRange, LocalKey};
    use hyperscale_vm_types::Moves;

    use super::*;

    fn cell(owner: u8, local: u8) -> DeclaredKey {
        DeclaredKey::Cell(SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local: LocalKey([local; 16]),
        })
    }

    fn interval(owner: u8, lo: u128, hi: u128) -> DeclaredKey {
        DeclaredKey::Range(DeclaredRange {
            owner: Address::new([owner; 31], AddressClass::Component),
            collection: CollectionId([7; 16]),
            lo,
            hi,
            cap: 8,
        })
    }

    const RESERVE: Mode = Mode::Reserve { amount: 5 };
    const WRITE: Mode = Mode::Write { moves: Moves::Both };

    #[test]
    fn nothing_is_blocked_by_an_empty_claim_set() {
        let claims = ProvisionalCells::default();
        assert!(claims.is_empty());
        assert!(!claims.blocks(&[(cell(1, 1), WRITE)]));
    }

    /// The reason the whole relation is here: payment traffic is delta
    /// and reserve, and those compose. A vault an unresolved leg is
    /// moving does not stop the next payment from moving it too.
    #[test]
    fn commutative_access_does_not_wait_on_commutative_access() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]);
        assert!(!claims.blocks(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]));
        assert!(!claims.blocks(&[(cell(1, 1), RESERVE)]));

        let mut reserved = ProvisionalCells::default();
        reserved.claim(&[(cell(1, 1), RESERVE)]);
        assert!(!reserved.blocks(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]));
        assert!(!reserved.blocks(&[(cell(1, 1), RESERVE)]));
    }

    /// A read depends on the value, and an exclusive write replaces it.
    /// Neither survives a change it cannot see.
    #[test]
    fn a_read_or_an_exclusive_write_still_waits() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]);
        assert!(claims.blocks(&[(cell(1, 1), Mode::Read)]));
        assert!(claims.blocks(&[(cell(1, 1), WRITE)]));
    }

    /// An exclusive claim excludes everything, commutative included: it
    /// carries an absolute, and an absolute composes with nothing.
    #[test]
    fn an_exclusive_claim_excludes_every_mode() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), WRITE)]);
        for mode in [
            Mode::Delta { moves: Moves::Both },
            RESERVE,
            Mode::Read,
            WRITE,
        ] {
            assert!(
                claims.blocks(&[(cell(1, 1), mode)]),
                "{mode:?} slipped past"
            );
        }
    }

    #[test]
    fn a_claim_leaves_siblings_and_other_owners_alone() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), WRITE)]);
        assert!(!claims.blocks(&[(cell(1, 2), WRITE)]), "sibling cell");
        assert!(!claims.blocks(&[(cell(2, 1), WRITE)]), "other owner");
    }

    /// Two intervals of one collection contend by mode alone — the
    /// interval-insensitive half of the kernel's overlap arithmetic —
    /// and an interval never contends with a point cell, which no
    /// interval contains.
    #[test]
    fn intervals_contend_by_collection_and_leave_points_alone() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(interval(1, 0, 10), WRITE)]);
        assert!(claims.blocks(&[(interval(1, 20, 30), Mode::Read)]));
        assert!(!claims.blocks(&[(cell(1, 1), WRITE)]));

        let mut over_cell = ProvisionalCells::default();
        over_cell.claim(&[(cell(1, 1), WRITE)]);
        assert!(!over_cell.blocks(&[(interval(1, 0, 10), WRITE)]));
    }
}
