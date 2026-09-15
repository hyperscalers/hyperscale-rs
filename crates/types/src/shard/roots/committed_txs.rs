//! [`CommittedTxsRoot`] computation and absence proofs over it.
//!
//! The root commits every transaction a shard committed within its
//! retention window up to a terminal block. A successor reads it off the
//! terminal header it commit-proved and asks, for a transaction whose
//! validity window opened before the cut, whether the predecessor already
//! committed it — the question that separates a replay from a first
//! inclusion the predecessor never made.
//!
//! Absence is what the successor needs, and sorted leaves are what make it
//! provable. The set is ordered by transaction hash, so a transaction is
//! absent exactly when the two members that bracket it sit at adjacent leaf
//! indices. [`CommittedTxAbsence`] carries that bracket and a range proof
//! over it; verifying one costs at most `2 × ceil(log2 N)` nodes however
//! large the set is.
//!
//! [`CommittedTxsRoot`]: crate::CommittedTxsRoot

use hyperscale_hbor::Hbor;

use crate::shard::roots::SetRoot;
use crate::{
    CommittedTxsRoot, Hash, TxHash, TypedHash, compute_range_proof, verify_range_inclusion,
};

/// Wire cap on an absence proof's node count.
///
/// A range proof carries at most one left and one right flank per level,
/// and `leaf_count` is a `u32`, so no honest proof exceeds `2 × 32`
/// however large the committed set grows. Unrelated to the set's own size.
const MAX_ABSENCE_PROOF_NODES: usize = 64;

/// Domain tag separating a committed-transaction merkle leaf from every
/// other leaf preimage the codebase hashes.
const COMMITTED_TX_LEAF_TAG: &[u8] = b"hyperscale.committed_tx_leaf.v1";

/// The merkle leaf for one committed transaction.
#[must_use]
pub fn committed_tx_leaf(tx_hash: &TxHash) -> Hash {
    let mut preimage = COMMITTED_TX_LEAF_TAG.to_vec();
    preimage.extend_from_slice(tx_hash.as_raw().as_bytes());
    Hash::from_bytes(&preimage)
}

impl SetRoot for CommittedTxsRoot {
    type Member = TxHash;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    fn leaf(tx_hash: &TxHash) -> Hash {
        committed_tx_leaf(tx_hash)
    }
}

/// Merkle root over a shard's committed transactions.
///
/// The hashes are taken as a set — sorted and deduplicated — so the root is
/// a pure function of the membership. The sort is what an absence proof
/// rests on: leaf order is transaction-hash order, so a bracketing pair at
/// adjacent indices rules out everything between them. Empty →
/// [`CommittedTxsRoot::ZERO`].
#[must_use]
pub fn committed_txs_root_from_hashes<'a>(
    tx_hashes: impl IntoIterator<Item = &'a TxHash>,
) -> CommittedTxsRoot {
    SetRoot::over(tx_hashes)
}

/// Proof that a transaction is **not** in a shard's committed set.
///
/// The bracket is the pair of set members either side of the queried hash,
/// at leaf indices `(lo, lo + 1)`. Either side is absent at the ends of the
/// set: a hash below every member brackets on `right` alone at `lo = 0`, one
/// above every member on `left` alone at `lo = leaf_count - 1`. A set with
/// no members at all needs no bracket, and roots to
/// [`CommittedTxsRoot::ZERO`].
///
/// The proof binds the bracket to the attested root, and the ordering check
/// binds the bracket to the query. Neither alone is enough: a real pair
/// proves nothing about a hash outside it, and an ordering claim over
/// fabricated neighbours proves nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct CommittedTxAbsence {
    /// The set member immediately below the queried hash, if any.
    pub(crate) left: Option<TxHash>,
    /// The set member immediately above the queried hash, if any.
    pub(crate) right: Option<TxHash>,
    /// Leaf index of `left`, or of `right` when `left` is absent.
    pub(crate) lo: u32,
    /// Total leaves in the committed set.
    pub(crate) leaf_count: u32,
    /// Range proof lifting the bracket to the root.
    #[hbor(max = MAX_ABSENCE_PROOF_NODES)]
    pub(crate) proof: Vec<Hash>,
}

impl CommittedTxAbsence {
    /// Whether this proves `tx_hash` absent from the set `root` commits.
    ///
    /// Four things must hold together. The bracket must be ordered around
    /// `tx_hash`, so the proof speaks about this query and not another. It
    /// must be contiguous, so nothing sits between its two halves. A
    /// one-sided bracket must sit at the end of the set it claims, so a
    /// middle pair cannot pass for an edge. And the bracket must lift to
    /// `root`, which is what makes its members real.
    #[must_use]
    pub fn proves_absent(&self, tx_hash: &TxHash, root: CommittedTxsRoot) -> bool {
        let leaf_count = self.leaf_count as usize;
        if leaf_count == 0 {
            // Nothing was committed, so nothing needs bracketing — but a
            // claim of emptiness only stands against the empty root.
            return self.left.is_none()
                && self.right.is_none()
                && self.proof.is_empty()
                && root == CommittedTxsRoot::ZERO;
        }
        if root == CommittedTxsRoot::ZERO {
            return false;
        }
        let lo = self.lo as usize;
        let (leaves, span) = match (&self.left, &self.right) {
            (Some(left), Some(right)) => {
                if left >= tx_hash || tx_hash >= right {
                    return false;
                }
                // Adjacent by construction: a two-sided bracket is the
                // contiguous run `[lo, lo + 2)`, so no member can hide
                // between its halves.
                (vec![committed_tx_leaf(left), committed_tx_leaf(right)], 2)
            }
            (None, Some(right)) => {
                // Below the whole set: only the first leaf can bracket it.
                if lo != 0 || tx_hash >= right {
                    return false;
                }
                (vec![committed_tx_leaf(right)], 1)
            }
            (Some(left), None) => {
                // Above the whole set: only the last leaf can bracket it.
                if lo != leaf_count - 1 || left >= tx_hash {
                    return false;
                }
                (vec![committed_tx_leaf(left)], 1)
            }
            // A non-empty set always has a neighbour on one side.
            (None, None) => return false,
        };
        if lo.saturating_add(span) > leaf_count {
            return false;
        }
        verify_range_inclusion(root.into_raw(), &leaves, lo, leaf_count, &self.proof)
    }
}

/// Build the absence proof for `tx_hash` against the sorted set `members`.
///
/// `None` when `tx_hash` is in the set — absence is not the answer, and a
/// caller holding the set answers membership directly.
///
/// # Panics
///
/// Panics if `members` is not sorted ascending, which would make every
/// index the proof names meaningless.
#[must_use]
pub fn prove_committed_tx_absent(
    members: &[TxHash],
    tx_hash: &TxHash,
) -> Option<CommittedTxAbsence> {
    assert!(
        members.windows(2).all(|pair| pair[0] < pair[1]),
        "committed set must be sorted ascending and deduplicated"
    );
    let leaf_count = members.len();
    let leaves: Vec<Hash> = members.iter().map(committed_tx_leaf).collect();
    if leaf_count == 0 {
        return Some(CommittedTxAbsence {
            left: None,
            right: None,
            lo: 0,
            leaf_count: 0,
            proof: Vec::new(),
        });
    }
    // `Err` is the insertion point: the count of members below `tx_hash`.
    let Err(above) = members.binary_search(tx_hash) else {
        return None;
    };
    let (left, right, lo, span) = if above == 0 {
        (None, Some(members[0]), 0, 1)
    } else if above == leaf_count {
        (Some(members[leaf_count - 1]), None, leaf_count - 1, 1)
    } else {
        (Some(members[above - 1]), Some(members[above]), above - 1, 2)
    };
    Some(CommittedTxAbsence {
        left,
        right,
        lo: u32::try_from(lo).unwrap_or(u32::MAX),
        leaf_count: u32::try_from(leaf_count).unwrap_or(u32::MAX),
        proof: compute_range_proof(&leaves, lo, lo + span),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settled_txs_root_from_hashes;

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    /// A sorted, deduplicated set of `n` distinct hashes.
    fn members(n: u8) -> Vec<TxHash> {
        let mut set: Vec<TxHash> = (0..n).map(tx).collect();
        set.sort_unstable();
        set
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(
            committed_txs_root_from_hashes(std::iter::empty()),
            CommittedTxsRoot::ZERO
        );
    }

    #[test]
    fn order_independent_and_deduplicated() {
        let (a, b, c) = (tx(1), tx(2), tx(3));
        let forward = committed_txs_root_from_hashes([&a, &b, &c]);
        assert_eq!(forward, committed_txs_root_from_hashes([&c, &a, &b]));
        assert_eq!(
            forward,
            committed_txs_root_from_hashes([&c, &a, &b, &a, &c])
        );
    }

    #[test]
    fn membership_changes_the_root() {
        let (a, b) = (tx(1), tx(2));
        let just_a = committed_txs_root_from_hashes([&a]);
        assert_ne!(just_a, committed_txs_root_from_hashes([&a, &b]));
        assert_ne!(just_a, CommittedTxsRoot::ZERO);
    }

    /// The committed and settled roots are domain-separated: the same
    /// membership under the two tags cannot collide. A single-leaf tree
    /// roots to its leaf, so comparing the two roots compares the two
    /// leaf preimages directly.
    #[test]
    fn the_leaf_tag_separates_it_from_the_settled_root() {
        let a = tx(1);
        assert_ne!(
            committed_txs_root_from_hashes([&a]).into_raw(),
            settled_txs_root_from_hashes([&a]).into_raw(),
        );
    }

    /// Every hash outside a set proves absent against that set's root, at
    /// every position: below it, above it, and in each interior gap.
    #[test]
    fn absence_verifies_at_every_gap() {
        for n in 0..=24u8 {
            // Even seeds are members; odd seeds fall in the gaps between
            // them, plus one below and one above the whole set.
            let set: Vec<TxHash> = {
                let mut s: Vec<TxHash> = (0..n).map(|i| tx(i * 2)).collect();
                s.sort_unstable();
                s.dedup();
                s
            };
            let root = committed_txs_root_from_hashes(set.iter());
            for probe_seed in 0..=(n * 2 + 1) {
                let probe = tx(probe_seed);
                if set.binary_search(&probe).is_ok() {
                    assert!(
                        prove_committed_tx_absent(&set, &probe).is_none(),
                        "n={n}: a member must not produce an absence proof"
                    );
                    continue;
                }
                let absence = prove_committed_tx_absent(&set, &probe)
                    .expect("a non-member must produce an absence proof");
                assert!(
                    absence.proves_absent(&probe, root),
                    "n={n} probe={probe_seed}: absence must verify"
                );
            }
        }
    }

    /// An absence proof for one hash does not carry to another, even when
    /// both are absent — the bracket has to straddle the hash it answers
    /// for.
    #[test]
    fn an_absence_proof_does_not_transfer_to_another_hash() {
        let set = members(16);
        let root = committed_txs_root_from_hashes(set.iter());
        let absent_low = tx(200);
        let absent_high = tx(201);
        let proof = prove_committed_tx_absent(&set, &absent_low).unwrap();
        assert!(proof.proves_absent(&absent_low, root));
        assert!(!proof.proves_absent(&absent_high, root));
    }

    /// A member of the set cannot be shown absent by any bracket, however
    /// the bracket is chosen — this is the property the whole design rests
    /// on, so it is checked against every member.
    #[test]
    fn no_bracket_shows_a_member_absent() {
        let set = members(24);
        let n = set.len();
        let root = committed_txs_root_from_hashes(set.iter());
        let leaves: Vec<Hash> = set.iter().map(committed_tx_leaf).collect();
        let count = u32::try_from(n).unwrap();

        // Every bracket backed by a genuine range proof: each adjacent
        // interior pair, and each one-sided end.
        let mut brackets: Vec<CommittedTxAbsence> = (0..n - 1)
            .map(|lo| CommittedTxAbsence {
                left: Some(set[lo]),
                right: Some(set[lo + 1]),
                lo: u32::try_from(lo).unwrap(),
                leaf_count: count,
                proof: compute_range_proof(&leaves, lo, lo + 2),
            })
            .collect();
        brackets.push(CommittedTxAbsence {
            left: None,
            right: Some(set[0]),
            lo: 0,
            leaf_count: count,
            proof: compute_range_proof(&leaves, 0, 1),
        });
        brackets.push(CommittedTxAbsence {
            left: Some(set[n - 1]),
            right: None,
            lo: count - 1,
            leaf_count: count,
            proof: compute_range_proof(&leaves, n - 1, n),
        });

        for member in &set {
            for bracket in &brackets {
                assert!(
                    !bracket.proves_absent(member, root),
                    "member {member:?} must not verify absent"
                );
            }
        }
    }

    /// A bracket whose halves are real but not adjacent hides every member
    /// between them. Contiguity is structural in the range proof, so the
    /// forgery fails to reach the root rather than being caught by a check.
    #[test]
    fn a_non_adjacent_bracket_fails() {
        let set = members(16);
        let root = committed_txs_root_from_hashes(set.iter());
        let leaves: Vec<Hash> = set.iter().map(committed_tx_leaf).collect();
        // Claim leaves 2 and 5 bracket the members between them.
        let hidden = set[3];
        let forged = CommittedTxAbsence {
            left: Some(set[2]),
            right: Some(set[5]),
            lo: 2,
            leaf_count: u32::try_from(set.len()).unwrap(),
            proof: compute_range_proof(&leaves, 2, 4),
        };
        assert!(!forged.proves_absent(&hidden, root));
    }

    /// A proof built over one set does not verify against another's root.
    #[test]
    fn a_proof_from_another_set_fails() {
        let set = members(16);
        let other: Vec<TxHash> = {
            let mut s: Vec<TxHash> = (100..116u8).map(tx).collect();
            s.sort_unstable();
            s
        };
        let probe = tx(200);
        let proof = prove_committed_tx_absent(&other, &probe).unwrap();
        assert!(!proof.proves_absent(&probe, committed_txs_root_from_hashes(set.iter())));
    }

    /// An emptiness claim stands only against the empty root, and the
    /// empty root admits no other claim.
    #[test]
    fn emptiness_binds_to_the_zero_root() {
        let probe = tx(200);
        let empty = prove_committed_tx_absent(&[], &probe).unwrap();
        assert!(empty.proves_absent(&probe, CommittedTxsRoot::ZERO));

        let set = members(8);
        let root = committed_txs_root_from_hashes(set.iter());
        assert!(
            !empty.proves_absent(&probe, root),
            "an emptiness claim must not pass against a populated root"
        );

        let real = prove_committed_tx_absent(&set, &probe).unwrap();
        assert!(
            !real.proves_absent(&probe, CommittedTxsRoot::ZERO),
            "a populated bracket must not pass against the empty root"
        );
    }

    /// A one-sided bracket must sit at the end it claims: an interior leaf
    /// presented as the set's first or last member is refused.
    #[test]
    fn a_one_sided_bracket_must_sit_at_the_end() {
        let set = members(16);
        let root = committed_txs_root_from_hashes(set.iter());
        let leaves: Vec<Hash> = set.iter().map(committed_tx_leaf).collect();
        let probe = tx(200);

        // `right`-only must be leaf 0; leaf 4 is interior.
        let not_first = CommittedTxAbsence {
            left: None,
            right: Some(set[4]),
            lo: 4,
            leaf_count: u32::try_from(set.len()).unwrap(),
            proof: compute_range_proof(&leaves, 4, 5),
        };
        assert!(!not_first.proves_absent(&set[0], root));

        // `left`-only must be the last leaf; leaf 4 is interior.
        let not_last = CommittedTxAbsence {
            left: Some(set[4]),
            right: None,
            lo: 4,
            leaf_count: u32::try_from(set.len()).unwrap(),
            proof: compute_range_proof(&leaves, 4, 5),
        };
        assert!(!not_last.proves_absent(&probe, root));
    }

    /// A padded or truncated range proof is rejected rather than ignored.
    #[test]
    fn a_tampered_proof_fails() {
        let set = members(16);
        let root = committed_txs_root_from_hashes(set.iter());
        let probe = tx(200);
        let good = prove_committed_tx_absent(&set, &probe).unwrap();
        assert!(good.proves_absent(&probe, root));

        let mut padded = good.clone();
        padded.proof.push(Hash::ZERO);
        assert!(!padded.proves_absent(&probe, root));

        let mut truncated = good.clone();
        truncated.proof.pop();
        assert!(!truncated.proves_absent(&probe, root));

        let mut wrong_count = good;
        wrong_count.leaf_count += 1;
        assert!(!wrong_count.proves_absent(&probe, root));
    }
}
