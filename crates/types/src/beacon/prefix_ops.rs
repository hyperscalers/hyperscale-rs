//! Prefix algebra used by the inner PC FSM.
//!
//! - [`mcp`] — maximum common prefix.
//! - [`mce`] — minimum common extension. Defined only when inputs are
//!   pairwise consistent; the y / z values flowing through PC's QC2 /
//!   QC3 satisfy that precondition.
//! - [`qc1_certify`] — longest prefix shared by some `f+1`-subset of
//!   votes. Computed via prefix counting.

use std::collections::BTreeMap;

use crate::{PcValueElement, PcVector};

/// Maximum common prefix.
///
/// Returns `None` on empty input — MCP is
/// mathematically undefined there, and propagating `None` lets
/// verifier hot paths reject crafted-empty input without panicking.
#[must_use]
pub fn mcp(vectors: &[PcVector]) -> Option<PcVector> {
    let first = vectors.first()?;
    let first_slice = first.as_slice();
    let mut len = first.len();
    for v in &vectors[1..] {
        let v_slice = v.as_slice();
        len = len.min(v.len());
        let mut k = 0;
        while k < len && v_slice[k] == first_slice[k] {
            k += 1;
        }
        len = k;
        if len == 0 {
            break;
        }
    }
    Some(PcVector::new(first_slice[..len].iter().copied()))
}

/// Minimum common extension.
///
/// `Some(longest)` if inputs are non-empty and pairwise consistent (one
/// is a prefix of the other); `None` if the set is empty or any pair
/// conflicts. The combined-failure signal is fine for hot-path
/// verifiers: both branches indicate the caller can't extract a single
/// common extension.
#[must_use]
pub fn mce(vectors: &[PcVector]) -> Option<PcVector> {
    let longest = vectors.iter().max_by_key(|v| v.len())?;
    let longest_slice = longest.as_slice();
    for v in vectors {
        if v.as_slice() != &longest_slice[..v.len()] {
            return None;
        }
    }
    Some(longest.clone())
}

/// The longest vector `x` such that some subset of `f+1` votes share
/// `x` as a (not necessarily proper) prefix.
///
/// Implemented by counting, for every prefix `p` appearing in any vote,
/// the number of votes that extend `p`. The deepest prefix with count
/// ≥ `f+1` is `x`; this is unique because no two distinct depth-k
/// prefixes can each be extended by `f+1` votes when only `2f+1` votes
/// are present.
///
/// Returns `None` when `votes.len() < f + 1` — no subset of size `f+1`
/// exists, so the certify operation is undefined. The legitimate
/// "shared prefix is empty" answer returns `Some(empty PcVector)`, so
/// callers must distinguish the two cases explicitly.
#[must_use]
pub fn qc1_certify(votes: &[PcVector], f: usize) -> Option<PcVector> {
    let threshold = f + 1;
    if votes.len() < threshold {
        return None;
    }
    let mut counts: BTreeMap<Vec<PcValueElement>, usize> = BTreeMap::new();
    for v in votes {
        let slice = v.as_slice();
        for k in 0..=v.len() {
            *counts.entry(slice[..k].to_vec()).or_insert(0) += 1;
        }
    }
    let best = counts
        .iter()
        .filter(|(_, c)| **c >= threshold)
        .max_by_key(|(p, _)| p.len())
        .map(|(p, _)| p.clone())
        .unwrap_or_default();
    Some(PcVector::new(best))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PC_VALUE_ELEMENT_BYTES;

    fn ve(n: u8) -> PcValueElement {
        PcValueElement::new([n; PC_VALUE_ELEMENT_BYTES])
    }

    fn vector_of<I: IntoIterator<Item = u8>>(iter: I) -> PcVector {
        PcVector::new(iter.into_iter().map(ve))
    }

    #[test]
    fn mcp_basic() {
        let a = vector_of([1, 2, 3]);
        let b = vector_of([1, 2, 4]);
        let c = vector_of([1, 2]);
        assert_eq!(
            mcp(&[a.clone(), b.clone()]).unwrap().as_slice(),
            &[ve(1), ve(2)]
        );
        assert_eq!(
            mcp(&[a.clone(), c.clone()]).unwrap().as_slice(),
            &[ve(1), ve(2)]
        );
        assert_eq!(mcp(&[a, b, c]).unwrap().as_slice(), &[ve(1), ve(2)]);
    }

    #[test]
    fn mcp_empty_when_disjoint() {
        let a = vector_of([1]);
        let b = vector_of([2]);
        assert_eq!(mcp(&[a, b]).unwrap().len(), 0);
    }

    #[test]
    fn mcp_empty_input_returns_none() {
        assert!(mcp(&[]).is_none());
    }

    #[test]
    fn mce_consistent() {
        let a = vector_of([1, 2]);
        let b = vector_of([1, 2, 3]);
        assert_eq!(mce(&[a, b]).unwrap().as_slice(), &[ve(1), ve(2), ve(3)]);
    }

    #[test]
    fn mce_conflicting() {
        let a = vector_of([1, 2]);
        let b = vector_of([1, 3]);
        assert!(mce(&[a, b]).is_none());
    }

    #[test]
    fn mce_empty_input_returns_none() {
        assert!(mce(&[]).is_none());
    }

    #[test]
    fn qc1_certify_picks_deepest_majority_prefix() {
        // f = 1, so threshold f+1 = 2.
        // Three votes: two share [1,2,3], one is [1,5].
        // Deepest prefix with count ≥ 2 is [1,2,3].
        let votes = vec![
            vector_of([1, 2, 3]),
            vector_of([1, 2, 3]),
            vector_of([1, 5]),
        ];
        assert_eq!(
            qc1_certify(&votes, 1).unwrap().as_slice(),
            &[ve(1), ve(2), ve(3)]
        );
    }

    #[test]
    fn qc1_certify_respects_threshold() {
        // f = 1, threshold 2. Three votes, all distinct except for prefix [1].
        let votes = vec![vector_of([1, 2]), vector_of([1, 3]), vector_of([1, 4])];
        assert_eq!(qc1_certify(&votes, 1).unwrap().as_slice(), &[ve(1)]);
    }

    #[test]
    fn qc1_certify_empty_when_no_prefix_majority() {
        // f = 1, threshold 2. Three completely disjoint votes share only [].
        let votes = vec![vector_of([1]), vector_of([2]), vector_of([3])];
        assert_eq!(qc1_certify(&votes, 1).unwrap().len(), 0);
    }

    /// Fewer than `f+1` votes returns `None`, distinguishing the
    /// precondition violation from the legitimate `Some([])` "shared
    /// prefix is empty" answer.
    #[test]
    fn qc1_certify_underflow_returns_none() {
        // f = 1, threshold 2. Only one vote → underflow.
        let votes = vec![vector_of([1, 2])];
        assert!(qc1_certify(&votes, 1).is_none());
        // f = 2, threshold 3. Two votes → underflow.
        let votes = vec![vector_of([1]), vector_of([1])];
        assert!(qc1_certify(&votes, 2).is_none());
    }

    // ─── Property tests ────────────────────────────────────────────────

    use proptest::prelude::*;

    fn arb_value_element() -> impl Strategy<Value = PcValueElement> {
        // Tiny alphabet so the prefix structure is meaningful. Two
        // random 32-byte elements would almost never agree.
        (0u8..5).prop_map(ve)
    }

    fn arb_vector(max_len: usize) -> impl Strategy<Value = PcVector> {
        prop::collection::vec(arb_value_element(), 0..=max_len).prop_map(PcVector::new)
    }

    fn arb_vector_set(
        min_size: usize,
        max_size: usize,
        max_len: usize,
    ) -> impl Strategy<Value = Vec<PcVector>> {
        prop::collection::vec(arb_vector(max_len), min_size..=max_size)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `mcp(S)` is a prefix of every member of `S`.
        #[test]
        fn mcp_is_prefix_of_every_input(set in arb_vector_set(1, 8, 8)) {
            let m = mcp(&set).expect("non-empty set");
            for v in &set {
                prop_assert!(m.is_prefix_of(v), "mcp not prefix of an input");
            }
        }

        /// `mcp` is order-independent.
        #[test]
        fn mcp_commutative_under_shuffle(
            set in arb_vector_set(1, 8, 8),
            seed in 0u64..1_000_000,
        ) {
            let mut shuffled = set.clone();
            let n = shuffled.len();
            for i in 0..n {
                let j = usize::try_from(seed.wrapping_mul(i as u64 + 1) % n as u64)
                    .expect("n fits in u64 ⇒ n - 1 fits in usize");
                shuffled.swap(i, j);
            }
            prop_assert_eq!(mcp(&set), mcp(&shuffled));
        }

        /// `mcp(S ∪ S) = mcp(S)` — duplicates don't shift the prefix.
        #[test]
        fn mcp_idempotent_under_duplication(set in arb_vector_set(1, 6, 8)) {
            let m1 = mcp(&set);
            let mut doubled = set.clone();
            doubled.extend(set.iter().cloned());
            prop_assert_eq!(m1, mcp(&doubled));
        }

        /// `mce` is `Some` iff every pair is consistent.
        #[test]
        fn mce_some_iff_pairwise_consistent(set in arb_vector_set(1, 6, 8)) {
            let all_consistent = set.iter().enumerate().all(|(i, a)| {
                set.iter().skip(i + 1).all(|b| a.is_consistent_with(b))
            });
            let result = mce(&set);
            prop_assert_eq!(result.is_some(), all_consistent);
        }

        /// When `mce(S)` is defined, every input is a prefix of it.
        #[test]
        fn mce_extends_every_input(set in arb_vector_set(1, 6, 8)) {
            if let Some(extension) = mce(&set) {
                for v in &set {
                    prop_assert!(v.is_prefix_of(&extension));
                }
            }
        }

        /// When `mce(S)` is defined, `mcp(S) ⪯ mce(S)`.
        #[test]
        fn mcp_is_prefix_of_mce_when_defined(set in arb_vector_set(1, 6, 8)) {
            if let Some(extension) = mce(&set) {
                let lower = mcp(&set).expect("non-empty set");
                prop_assert!(lower.is_prefix_of(&extension));
            }
        }

        /// `qc1_certify` output is a prefix of at least `f + 1` votes.
        #[test]
        fn qc1_certify_witnessed_by_f_plus_one(
            votes in arb_vector_set(3, 9, 8),
            f in 0usize..3,
        ) {
            prop_assume!(votes.len() > f);
            let x = qc1_certify(&votes, f).expect("votes.len() > f satisfies precondition");
            let witnesses = votes.iter().filter(|v| x.is_prefix_of(v)).count();
            prop_assert!(
                witnesses > f,
                "qc1_certify has {witnesses} witnesses but needs > f={f}",
            );
        }

        /// `qc1_certify` returns the *longest* such prefix — no
        /// strictly longer prefix is shared by `f + 1` votes.
        #[test]
        fn qc1_certify_maximal(
            votes in arb_vector_set(3, 8, 6),
            f in 0usize..3,
        ) {
            prop_assume!(votes.len() > f);
            let x = qc1_certify(&votes, f).expect("votes.len() > f satisfies precondition");
            for candidate in &votes {
                if x.len() >= candidate.len() {
                    continue;
                }
                // Extend x by one element toward this candidate; check
                // the extension can't reach f+1 witnesses.
                let mut extended: Vec<PcValueElement> = x.iter().copied().collect();
                extended.push(candidate.as_slice()[x.len()]);
                let extended = PcVector::new(extended);
                let witnesses = votes.iter().filter(|v| extended.is_prefix_of(v)).count();
                prop_assert!(
                    witnesses <= f,
                    "qc1_certify wasn't maximal: extension reached {witnesses} > f={f} witnesses",
                );
            }
        }
    }
}
