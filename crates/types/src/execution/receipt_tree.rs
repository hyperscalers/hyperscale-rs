//! Receipt tree leaves and `global_receipt_root` computation/proof helpers.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{
    GlobalReceiptRoot, Hash, TxOutcome, compute_merkle_root, compute_merkle_root_with_proof,
};

/// Domain tag separating a transaction outcome's receipt-tree leaf from
/// every other leaf preimage the codebase hashes.
const TX_OUTCOME_LEAF_TAG: &[u8] = b"hyperscale.tx_outcome_leaf.v1";

/// The leaf hash of a transaction outcome in the receipt tree: the tag
/// and the outcome's canonical encoding.
///
/// The vote signature covers only the receipt root, and decoding
/// recomputes that root from the outcomes, so every field of the
/// outcome has to sit under the leaf or it is an aggregator's to forge:
/// the verdict, the attested and reserved work, any settled fee receipt,
/// the shards the settlement waits on, what the execution escrowed and
/// where those crossings land, and what the outcome says of its own
/// role. The encoding admits one reading of all of them, so nothing is
/// packed by hand.
///
/// # Panics
///
/// If the outcome does not encode, which one built under its caps
/// always does.
#[must_use]
pub fn tx_outcome_leaf(outcome: &TxOutcome) -> Hash {
    let bytes = hbor_to_vec(outcome).expect("a transaction outcome encodes");
    Hash::from_parts(&[TX_OUTCOME_LEAF_TAG, &bytes])
}

/// Compute the receipt root from a list of transaction outcomes.
///
/// Uses padded merkle tree (power-of-2 padding with `Hash::ZERO`) so that
/// merkle inclusion proofs have a fixed `ceil(log2(N))` siblings.
///
/// Outcomes must be in tick order (= block order within the tick).
pub fn compute_global_receipt_root(outcomes: &[TxOutcome]) -> GlobalReceiptRoot {
    let leaves: Vec<Hash> = outcomes.iter().map(tx_outcome_leaf).collect();
    GlobalReceiptRoot::from_raw(compute_merkle_root(&leaves))
}

/// Compute receipt root and a merkle inclusion proof for a specific tx.
///
/// Returns `(root, proof_siblings, leaf_index, leaf_hash)`.
///
/// # Panics
///
/// Panics if `tx_index >= outcomes.len()` or `outcomes` is empty.
pub fn compute_global_receipt_root_with_proof(
    outcomes: &[TxOutcome],
    tx_index: usize,
) -> (Hash, Vec<Hash>, u32, Hash) {
    let leaves: Vec<Hash> = outcomes.iter().map(tx_outcome_leaf).collect();

    let leaf_hash = leaves[tx_index];
    let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&leaves, tx_index);
    (root, siblings, leaf_index, leaf_hash)
}

#[cfg(test)]
mod reservation_tests {
    use super::{compute_global_receipt_root, tx_outcome_leaf};
    use crate::{ExecutionOutcome, GlobalReceiptHash, Hash, TxHash, TxOutcome};

    fn outcome(reserved: u128) -> TxOutcome {
        TxOutcome::attesting(
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
            7,
        )
        .reserving(reserved)
    }

    /// What a transaction reserved is signed content like what it cost.
    /// An aggregator that could restate it could hand a block a release
    /// larger than the reservation it settles, and the running drain
    /// total would fall below what is actually in flight.
    #[test]
    fn the_reservation_is_covered_by_the_outcome_leaf() {
        assert_ne!(
            tx_outcome_leaf(&outcome(100)),
            tx_outcome_leaf(&outcome(101))
        );
        assert_ne!(
            compute_global_receipt_root(&[outcome(100)]),
            compute_global_receipt_root(&[outcome(101)])
        );
    }

    /// The two work quantities are separate axes: one shard's share of
    /// what a transaction cost, and what every shard agrees it reserved.
    /// Folding them into one leaf position would let a difference in
    /// either hide a difference in the other.
    #[test]
    fn cost_and_reservation_move_the_leaf_independently() {
        let costed = TxOutcome::attesting(
            TxHash::from(Hash::from_bytes(b"tx")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
            8,
        )
        .reserving(100);
        assert_ne!(tx_outcome_leaf(&costed), tx_outcome_leaf(&outcome(100)));
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass, LocalKey, SubstateKey};

    use super::*;
    use crate::{ExecutionOutcome, GlobalReceiptHash, Role, ShardId, TxHash};

    /// Whether an outcome decides its transaction is under the signed
    /// leaf: a leg's success and a core's are otherwise identical bytes.
    #[test]
    fn a_leg_that_decides_nothing_leafs_differently() {
        let outcome = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"leg")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        assert!(
            outcome.decides(),
            "an outcome decides unless told otherwise"
        );
        assert_ne!(
            tx_outcome_leaf(&outcome),
            tx_outcome_leaf(&outcome.clone().as_role(Role::Leg)),
        );
    }

    /// Whether an outcome is the transaction's own execution is under
    /// the signed leaf: a reclaim's success and a single-shard core's
    /// are otherwise identical bytes.
    #[test]
    fn a_member_that_settles_leafs_differently() {
        let outcome = TxOutcome::new(
            TxHash::from(Hash::from_bytes(b"reclaim")),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        assert!(
            outcome.executes(),
            "an outcome executes unless told otherwise"
        );
        assert_ne!(
            tx_outcome_leaf(&outcome),
            tx_outcome_leaf(&outcome.clone().as_role(Role::Settling)),
        );
    }

    fn tx_hash() -> TxHash {
        TxHash::from(Hash::from_bytes(b"leaf-tx"))
    }

    fn escrowed(node: u32) -> SubstateKey {
        SubstateKey {
            owner: Address::new([0xC1; 31], AddressClass::Component),
            local: LocalKey([u8::try_from(node).expect("a test node fits a byte"); 16]),
        }
    }

    fn base() -> TxOutcome {
        TxOutcome::attesting(tx_hash(), ExecutionOutcome::Aborted, 7)
    }

    /// The list region is one byte string whatever the split between
    /// its three lists, so the counts have to be what fixes the reading:
    /// three escrowed entries and twenty-six shards are the same 312
    /// bytes of region, and the leaves differ.
    #[test]
    fn two_list_splits_of_equal_length_give_different_leaves() {
        let escrowing = base().escrowing((0..3).map(escrowed));
        let crossing = base().crossing_to((0..12).map(|path| ShardId::leaf(4, path)));
        assert_eq!(
            escrowing.escrowed().len() * 48,
            crossing.crossing_targets().len() * 12,
            "the two regions have to be the same length, or this proves nothing"
        );
        assert_ne!(tx_outcome_leaf(&escrowing), tx_outcome_leaf(&crossing));

        // And the same shards awaited rather than crossed to is a third
        // reading of the same bytes.
        let awaiting = base().awaiting((0..12).map(|path| ShardId::leaf(4, path)));
        assert_ne!(tx_outcome_leaf(&awaiting), tx_outcome_leaf(&crossing));
    }

    /// The cells an execution escrowed are under the leaf: an aggregator
    /// restating which of them left fails the root recompute.
    #[test]
    fn leaf_covers_which_cells_were_escrowed() {
        let one = base().escrowing([escrowed(1)]);
        let moved = base().escrowing([escrowed(2)]);
        let both = base().escrowing([escrowed(1), escrowed(2)]);
        assert_ne!(tx_outcome_leaf(&one), tx_outcome_leaf(&moved));
        assert_ne!(tx_outcome_leaf(&one), tx_outcome_leaf(&both));
        assert_ne!(tx_outcome_leaf(&one), tx_outcome_leaf(&base()));
    }

    /// One form: the builder sorts on the whole entry and keeps one per
    /// edge, so two callers offering the same set in different orders
    /// build the same outcome.
    #[test]
    fn escrowed_entries_take_one_form() {
        let forward = base().escrowing([escrowed(1), escrowed(2)]);
        let backward = base().escrowing([escrowed(2), escrowed(1), escrowed(2)]);
        assert_eq!(forward, backward);
        assert_eq!(forward.escrowed().len(), 2);
    }

    /// `work` is folded into the leaf: outcomes identical but for their
    /// attested work hash to different leaves, so a forged work fails
    /// the receipt-root recompute every EC decode runs.
    #[test]
    fn leaf_covers_attested_work() {
        let outcome = |work| TxOutcome::attesting(tx_hash(), ExecutionOutcome::Aborted, work);
        assert_ne!(
            tx_outcome_leaf(&outcome(7)),
            tx_outcome_leaf(&outcome(8)),
            "work must be covered by the leaf"
        );
    }

    /// The fee-receipt extension composes with the work fold — a forged
    /// work is still caught on outcomes that settle a fee receipt.
    #[test]
    fn leaf_covers_attested_work_with_fee_receipt() {
        let fee = GlobalReceiptHash::from_raw(Hash::from_bytes(b"fee"));
        let outcome = |work| TxOutcome::with_fee(tx_hash(), ExecutionOutcome::Failed, fee, work);
        assert_ne!(
            tx_outcome_leaf(&outcome(7)),
            tx_outcome_leaf(&outcome(8)),
            "work must be covered by the leaf on fee-settling outcomes"
        );
    }
}
