//! Binary merkle tree helpers over [`Hash`].
//!
//! Trees pad the leaf list to the next power of two with `Hash::ZERO`,
//! producing a perfect binary tree of depth `ceil(log2(N))`. This makes
//! inclusion proofs fixed-size and eliminates the odd-node-promotion
//! second-preimage attractor.

use crate::Hash;

/// Compute a binary merkle root from a list of hashes.
///
/// Pads the leaf list to the next power of two with `Hash::ZERO` so the
/// tree is always perfect. Returns `Hash::ZERO` for an empty list.
#[must_use]
pub fn compute_merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::ZERO;
    }
    let padded_len = hashes.len().next_power_of_two();
    let mut level: Vec<Hash> = Vec::with_capacity(padded_len);
    level.extend_from_slice(hashes);
    level.resize(padded_len, Hash::ZERO);

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            next_level.push(Hash::from_parts(&[
                level[i].as_bytes(),
                level[i + 1].as_bytes(),
            ]));
        }
        level = next_level;
    }
    level[0]
}

/// Compute a binary merkle root AND a proof (siblings + leaf index) for a specific leaf.
///
/// Produces the same root as [`compute_merkle_root`] for the same input.
/// Proofs are fixed-size at `ceil(log2(N))` siblings.
///
/// Returns `(root, siblings, leaf_index)`.
///
/// # Panics
///
/// Panics if `index >= hashes.len()` or `hashes` is empty.
#[must_use]
pub fn compute_merkle_root_with_proof(hashes: &[Hash], index: usize) -> (Hash, Vec<Hash>, u32) {
    assert!(!hashes.is_empty(), "cannot prove in empty tree");
    assert!(index < hashes.len(), "index out of bounds");

    // Pad to next power of 2
    let padded_len = hashes.len().next_power_of_two();
    let mut level: Vec<Hash> = Vec::with_capacity(padded_len);
    level.extend_from_slice(hashes);
    level.resize(padded_len, Hash::ZERO);

    let mut siblings = Vec::new();
    let mut target = index;

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);

        for i in (0..level.len()).step_by(2) {
            let combined = Hash::from_parts(&[level[i].as_bytes(), level[i + 1].as_bytes()]);
            if target == i {
                siblings.push(level[i + 1]);
            } else if target == i + 1 {
                siblings.push(level[i]);
            }
            next_level.push(combined);
        }

        target /= 2;
        level = next_level;
    }

    (level[0], siblings, u32::try_from(index).unwrap_or(u32::MAX))
}

/// Verify a merkle inclusion proof against a known root.
///
/// Reconstructs the root from the leaf hash and sibling path, then compares
/// against the expected root.
#[must_use]
pub fn verify_merkle_inclusion(
    root: Hash,
    leaf_hash: Hash,
    siblings: &[Hash],
    leaf_index: u32,
) -> bool {
    let mut current = leaf_hash;
    let mut index = leaf_index as usize;

    for sibling in siblings {
        if index.is_multiple_of(2) {
            current = Hash::from_parts(&[current.as_bytes(), sibling.as_bytes()]);
        } else {
            current = Hash::from_parts(&[sibling.as_bytes(), current.as_bytes()]);
        }
        index /= 2;
    }

    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(compute_merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash::from_bytes(b"single");
        assert_eq!(compute_merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_two() {
        let h0 = Hash::from_bytes(b"left");
        let h1 = Hash::from_bytes(b"right");
        let expected = Hash::from_parts(&[h0.as_bytes(), h1.as_bytes()]);
        assert_eq!(compute_merkle_root(&[h0, h1]), expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes: Vec<Hash> = (0..5).map(|i| Hash::from_bytes(&[i])).collect();
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let h0 = Hash::from_bytes(b"a");
        let h1 = Hash::from_bytes(b"b");
        let root_ab = compute_merkle_root(&[h0, h1]);
        let root_ba = compute_merkle_root(&[h1, h0]);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn test_merkle_root_odd_count_pads_with_zero() {
        // 3 leaves pad to 4: [h0, h1, h2, ZERO]
        let h0 = Hash::from_bytes(b"0");
        let h1 = Hash::from_bytes(b"1");
        let h2 = Hash::from_bytes(b"2");

        let level1_left = Hash::from_parts(&[h0.as_bytes(), h1.as_bytes()]);
        let level1_right = Hash::from_parts(&[h2.as_bytes(), Hash::ZERO.as_bytes()]);
        let expected = Hash::from_parts(&[level1_left.as_bytes(), level1_right.as_bytes()]);

        assert_eq!(compute_merkle_root(&[h0, h1, h2]), expected);
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let h0 = Hash::from_bytes(b"left");
        let h1 = Hash::from_bytes(b"right");
        let hashes = vec![h0, h1];
        let expected_root = compute_merkle_root(&hashes);

        for idx in 0..2 {
            let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(root, expected_root);
            assert!(verify_merkle_inclusion(
                root,
                hashes[idx],
                &siblings,
                leaf_index
            ));
        }
    }

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let h = Hash::from_bytes(b"only");
        let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&[h], 0);
        assert_eq!(root, h);
        assert!(siblings.is_empty());
        assert!(verify_merkle_inclusion(root, h, &siblings, leaf_index));
    }

    #[test]
    fn test_inclusion_proof_odd_count() {
        let hashes: Vec<Hash> = (0..5u8).map(|i| Hash::from_bytes(&[i])).collect();
        let root = compute_merkle_root(&hashes);

        for idx in 0..5 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, root);
            assert!(
                verify_merkle_inclusion(root, hashes[idx], &siblings, leaf_index),
                "proof failed for index {idx}"
            );
        }
    }

    #[test]
    fn test_inclusion_proof_large_tree() {
        let hashes: Vec<Hash> = (0..100u8).map(|i| Hash::from_bytes(&[i])).collect();
        let root = compute_merkle_root(&hashes);

        for idx in 0..100 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, root);
            assert!(
                verify_merkle_inclusion(root, hashes[idx], &siblings, leaf_index),
                "proof failed for index {idx}"
            );
        }
    }

    #[test]
    fn test_inclusion_proof_tampered_rejected() {
        let hashes: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes(&[i])).collect();
        let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, 3);

        // Wrong leaf hash should fail
        let wrong_leaf = Hash::from_bytes(b"wrong");
        assert!(!verify_merkle_inclusion(
            root, wrong_leaf, &siblings, leaf_index
        ));

        // Wrong root should fail
        let wrong_root = Hash::from_bytes(b"bad_root");
        assert!(!verify_merkle_inclusion(
            wrong_root, hashes[3], &siblings, leaf_index
        ));
    }

    #[test]
    fn test_inclusion_proof_power_of_two() {
        let hashes: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes(&[i])).collect();
        let root = compute_merkle_root(&hashes);

        for idx in 0..8 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, root);
            assert_eq!(siblings.len(), 3); // log2(8) = 3
            assert!(verify_merkle_inclusion(
                root,
                hashes[idx],
                &siblings,
                leaf_index
            ));
        }
    }
}
