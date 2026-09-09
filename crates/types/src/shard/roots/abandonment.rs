//! [`AbandonmentRoot`]: the root over a block's abandonment records,
//! one leaf per record.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{AbandonmentRecord, AbandonmentRoot, Hash, LeafRoot};

/// Domain tag separating an abandonment record's merkle leaf from every
/// other leaf preimage the codebase hashes.
const ABANDONMENT_LEAF_TAG: &[u8] = b"hyperscale.abandonment_leaf.v1";

impl LeafRoot for AbandonmentRoot {
    type Leaf = AbandonmentRecord;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One record's leaf: the tag and its canonical encoding, which
    /// covers the shard, the evidence whole, and every figure of every
    /// name — a figure the root does not commit to is a figure two
    /// bodies can disagree on under one certificate.
    ///
    /// # Panics
    ///
    /// If the record does not encode, which a value built through
    /// [`AbandonmentRecord::new`] under its caps always does.
    fn leaf(record: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(record).expect("an abandonment record encodes");
        Hash::from_parts(&[ABANDONMENT_LEAF_TAG, &bytes])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AbortCharge, Address, AddressClass, BlockHeight, CommittedAt, Deadline, Hash, LocalKey,
        RootMismatch, RoutePrefix, ShardId, SubstateKey, TxHash, UnsettledTx, Verified, Verify,
        WeightedTimestamp,
    };

    fn tx(seed: u8) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
            deadline: Deadline::of(WeightedTimestamp::from_millis(500)),
            declared_work: 7,
            charge: AbortCharge {
                vault: SubstateKey {
                    owner: Address::new([seed; 31], AddressClass::Component),
                    local: LocalKey([seed; 16]),
                },
                amount: 11,
            },
            committed: CommittedAt {
                height: BlockHeight::new(3),
                anchor: WeightedTimestamp::from_millis(100),
            },
            reach: vec![RoutePrefix::of(Address::new(
                [seed; 31],
                AddressClass::Component,
            ))],
        }
    }

    fn record(shard: ShardId, seeds: &[u8]) -> AbandonmentRecord {
        AbandonmentRecord::new(
            shard,
            WeightedTimestamp::from_millis(1_000),
            seeds.iter().copied().map(tx),
        )
    }

    fn root_of(record: &AbandonmentRecord) -> AbandonmentRoot {
        AbandonmentRoot::over(std::slice::from_ref(record))
    }

    /// A block carrying no records commits nothing, which is a value of
    /// its own rather than the root of an empty tree.
    #[test]
    fn no_records_is_the_zero_root() {
        assert_eq!(AbandonmentRoot::over(&[]), AbandonmentRoot::ZERO);
    }

    /// The leaf covers what the record claims: change the shard, the
    /// moment, or the transactions named, and the root moves.
    #[test]
    fn the_root_covers_every_term_of_the_claim() {
        let base = record(ShardId::ROOT, &[1, 2]);
        let root = root_of(&base);

        assert_ne!(root, root_of(&record(ShardId::leaf(1, 0), &[1, 2])));
        assert_ne!(root, root_of(&record(ShardId::ROOT, &[1, 3])));
        assert_ne!(
            root,
            root_of(&AbandonmentRecord::new(
                ShardId::ROOT,
                WeightedTimestamp::from_millis(2_000),
                [tx(1), tx(2)],
            )),
        );

        // The figures a name carries are part of the claim: the record
        // licenses an abort that returns exactly this much, at exactly
        // this deadline, burning exactly this out of exactly this vault,
        // so a block restating any of them differently is a different
        // block.
        let restated = |entry: UnsettledTx| {
            root_of(&AbandonmentRecord::new(
                ShardId::ROOT,
                WeightedTimestamp::from_millis(1_000),
                [entry, tx(2)],
            ))
        };
        assert_ne!(
            root,
            restated(UnsettledTx {
                declared_work: 8,
                ..tx(1)
            })
        );
        assert_ne!(
            root,
            restated(UnsettledTx {
                deadline: Deadline::of(WeightedTimestamp::from_millis(501)),
                ..tx(1)
            })
        );
        assert_ne!(
            root,
            restated(UnsettledTx {
                charge: AbortCharge {
                    amount: 12,
                    ..tx(1).charge
                },
                ..tx(1)
            })
        );
        assert_ne!(
            root,
            restated(UnsettledTx {
                charge: AbortCharge {
                    vault: tx(9).charge.vault,
                    ..tx(1).charge
                },
                ..tx(1)
            })
        );
    }

    /// Verification is the recomputation, so a claimed root the records do
    /// not produce is refused with both figures named.
    #[test]
    fn a_root_the_records_do_not_produce_is_refused() {
        let records = vec![record(ShardId::ROOT, &[1])];
        let claimed = AbandonmentRoot::over(&records);
        assert_eq!(
            claimed.verify(&records[..]).map(Verified::into_inner),
            Ok(claimed)
        );
        assert_eq!(
            AbandonmentRoot::ZERO.verify(&records[..]),
            Err(RootMismatch {
                expected: AbandonmentRoot::ZERO,
                computed: claimed,
            }),
        );
    }
}
