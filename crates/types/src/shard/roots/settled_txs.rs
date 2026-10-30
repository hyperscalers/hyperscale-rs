//! [`SettledTxsRoot`] computation.
//!
//! The root commits the set of transactions a shard settled within its
//! retention window up to a terminal block. A terminating shard carries it
//! on its boundary header; a surviving counterpart fetches the same set and
//! accepts it only when its recomputed root equals the attested one, so the
//! complete set — and therefore the absence of any transaction from it — is
//! authenticated.
//!
//! [`SettledTxsRoot`]: crate::SettledTxsRoot

use std::sync::Arc;

use crate::shard::roots::SetRoot;
use crate::{
    ExecutionOutcome, Finalization, Hash, SettledTxsRoot, ShardId, TxHash, TxOutcome, TypedHash,
    Verifiable,
};

/// The cross-shard transactions `shard` reached a verdict on in
/// `certificates`.
///
/// One entry per transaction of each committed finalization whose local
/// execution certificate is keyed on this shard — its block's own shard,
/// `block.header().shard_id()` — that a counterpart could ask about: one
/// this shard completed whose reach goes beyond it — a core's claim, a
/// delivery, a leg that ran — and every
/// core member a legs half accepts. The outcome states its reach, since
/// a member that answers to nobody leaves no other trace of the shards
/// that will ask.
///
/// A verdict this shard reached alone and did not complete is excluded:
/// a refusal or an abort names nothing a counterpart may treat as
/// settled, and the abandonment record composed against this set is what
/// licenses the counterpart's own answer to it. **Single-shard
/// transactions are excluded** too: nothing elsewhere ever asks about
/// them, so the set stays proportional to cross-shard traffic rather
/// than total throughput.
///
/// The consequence of that exclusion is what a chain observer can conclude:
/// a single-shard transaction that settled and one abandoned at a terminal
/// are indistinguishable here, because neither appears. Abandonment is a
/// record of its own, not the absence of one.
#[must_use]
pub fn local_settled_tx_hashes<'a>(
    certificates: impl IntoIterator<Item = &'a Arc<Verifiable<Finalization>>>,
    shard: ShardId,
) -> Vec<TxHash> {
    certificates
        .into_iter()
        .filter(|fw| fw.tick_id().shard_id() == shard)
        .flat_map(|fw| {
            fw.settled_outcomes()
                .filter(|outcome| {
                    outcome.reaches_beyond()
                        && matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. })
                })
                .map(TxOutcome::tx_hash)
                .chain(fw.accepted_names())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Domain tag separating a settled-transaction merkle leaf from every other
/// leaf preimage the codebase hashes.
const SETTLED_TX_LEAF_TAG: &[u8] = b"hyperscale.settled_tx_leaf.v1";

/// The merkle leaf for one settled transaction.
fn settled_tx_leaf(tx_hash: &TxHash) -> Hash {
    let mut preimage = SETTLED_TX_LEAF_TAG.to_vec();
    preimage.extend_from_slice(tx_hash.as_raw().as_bytes());
    Hash::from_bytes(&preimage)
}

impl SetRoot for SettledTxsRoot {
    type Member = TxHash;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    fn leaf(tx_hash: &TxHash) -> Hash {
        settled_tx_leaf(tx_hash)
    }
}

/// Merkle root over a shard's settled transactions.
///
/// The hashes are taken as a set — sorted and deduplicated — so the root is
/// a pure function of the membership, independent of the order they were
/// discovered in. Empty → [`SettledTxsRoot::ZERO`].
#[must_use]
pub fn settled_txs_root_from_hashes<'a>(
    tx_hashes: impl IntoIterator<Item = &'a TxHash>,
) -> SettledTxsRoot {
    SetRoot::over(tx_hashes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_hbor::Capped;

    use super::*;
    use crate::{
        AggregateSignature, BlockHeight, ExecutionCertificate, GlobalReceiptHash,
        GlobalReceiptRoot, Role, SignerBitfield, TickHalf, TickId, WeightedTimestamp,
    };

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(
            settled_txs_root_from_hashes(std::iter::empty()),
            SettledTxsRoot::ZERO
        );
    }

    #[test]
    fn order_independent_and_deduplicated() {
        let a = tx(1);
        let b = tx(2);
        let c = tx(3);
        let forward = settled_txs_root_from_hashes([&a, &b, &c]);
        let shuffled = settled_txs_root_from_hashes([&c, &a, &b]);
        let with_dup = settled_txs_root_from_hashes([&c, &a, &b, &a, &c]);
        assert_eq!(forward, shuffled);
        assert_eq!(forward, with_dup);
    }

    fn finalization(local: ShardId, ec: ExecutionCertificate) -> Arc<Verifiable<Finalization>> {
        Arc::new(Verifiable::from(Finalization::new(
            TickId::new(local, BlockHeight::new(1)),
            TickHalf::Determined,
            Some(ec),
            Capped::from_array([]),
        )))
    }

    fn certificate(shard: ShardId, outcomes: Vec<TxOutcome>) -> ExecutionCertificate {
        ExecutionCertificate::new(
            TickId::new(shard, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )
    }

    fn succeeded() -> ExecutionOutcome {
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        }
    }

    /// A verdict is named only where it completed and reaches beyond the
    /// shard.
    #[test]
    fn the_set_names_what_a_counterpart_could_ask_about() {
        let (local, remote) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let (aborted, leg, refusal, abandonment, alone) = (tx(1), tx(2), tx(3), tx(4), tx(5));
        let fw = finalization(
            local,
            certificate(
                local,
                vec![
                    TxOutcome::new(aborted, ExecutionOutcome::Aborted).awaiting([remote]),
                    TxOutcome::new(leg, succeeded()).as_role(Role::Leg),
                    TxOutcome::new(refusal, ExecutionOutcome::Failed).as_role(Role::Leg),
                    TxOutcome::new(abandonment, ExecutionOutcome::Aborted).awaiting([remote]),
                    TxOutcome::new(alone, succeeded()),
                ],
            ),
        );
        let named: BTreeSet<TxHash> = local_settled_tx_hashes([&fw], local).into_iter().collect();
        assert_eq!(named, BTreeSet::from([leg]));
        assert!(
            local_settled_tx_hashes([&fw], remote).is_empty(),
            "a finalization names only its own shard's verdicts",
        );
    }

    /// A refusal this shard settles in a stating half carries no
    /// counterpart's certificate and completed nothing, so the settled
    /// set does not name it; nor does it name the yes the half states,
    /// which nothing has settled yet.
    #[test]
    fn a_refusal_settled_in_a_stating_half_is_not_in_the_settled_set() {
        use crate::test_utils::stating_half_on;

        let (local, remote) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let (refused, aborted, yes) = (tx(1), tx(2), tx(3));
        let core = |tx_hash, outcome| {
            TxOutcome::new(tx_hash, outcome)
                .awaiting([remote])
                .as_role(Role::Core)
        };
        let half = Arc::new(Verifiable::from(stating_half_on(
            local,
            BlockHeight::new(1),
            vec![
                core(refused, ExecutionOutcome::Failed),
                core(aborted, ExecutionOutcome::Aborted),
                core(yes, succeeded()),
            ],
            Vec::new(),
        )));
        assert_eq!(local_settled_tx_hashes([&half], local), vec![]);
    }

    /// A legs half carries no certificate, and every member it names is
    /// a core accept a sibling may ask about: the settled set names each
    /// one, so an abandonment record against the set never aborts what
    /// this shard accepted. A legs half of another shard's tick names
    /// nothing here.
    #[test]
    fn a_legs_half_puts_its_accepts_in_the_settled_set() {
        use crate::{ConsensusReceipt, StateWrites, StoredReceipt};

        let local = ShardId::leaf(1, 0);
        let accepting = |shard: ShardId, members: &[TxHash]| {
            Arc::new(Verifiable::from(Finalization::accepting(
                TickId::new(shard, BlockHeight::new(2)),
                Capped::new(
                    members
                        .iter()
                        .map(|&tx_hash| StoredReceipt {
                            tx_hash,
                            consensus: Arc::new(ConsensusReceipt::Succeeded {
                                receipt_hash: GlobalReceiptHash::ZERO,
                                writes: StateWrites::default(),
                                beacon_witness_events: Capped::empty(),
                                events: Capped::empty(),
                            }),
                        })
                        .collect(),
                )
                .expect("a list written out in a test"),
            )))
        };
        let mut named = local_settled_tx_hashes(
            [
                &accepting(local, &[tx(1), tx(2)]),
                &accepting(ShardId::leaf(1, 1), &[tx(3)]),
            ],
            local,
        );
        named.sort_unstable();
        let mut expected = vec![tx(1), tx(2)];
        expected.sort_unstable();
        assert_eq!(named, expected);
    }

    #[test]
    fn membership_changes_the_root() {
        let a = tx(1);
        let b = tx(2);
        let just_a = settled_txs_root_from_hashes([&a]);
        let a_and_b = settled_txs_root_from_hashes([&a, &b]);
        assert_ne!(just_a, a_and_b);
        assert_ne!(just_a, SettledTxsRoot::ZERO);
    }
}
