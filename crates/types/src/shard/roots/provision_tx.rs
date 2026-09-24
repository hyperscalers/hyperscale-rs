//! Per-target-shard [`ProvisionTxRoot`] verification.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::Capped;
use thiserror::Error;

use crate::{
    Hash, MAX_PROVISION_TARGET_SHARDS, ProvisionTxRoot, ShardId, TopologySnapshot, Transaction,
    Verifiable, Verified, Verify, compute_merkle_root,
};

/// Inputs the provision-tx-roots verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionTxRootsContext<'a> {
    /// Source shard the block belongs to — excluded from the per-target
    /// fan-out so each shard's own provision-tx root isn't included in
    /// its own map.
    pub local_shard: ShardId,
    /// Topology snapshot anchoring shard routing — drives which target
    /// shards each cross-shard tx contributes to.
    pub topology_snapshot: &'a TopologySnapshot,
    /// The block's transactions in block order.
    pub transactions: &'a [Arc<Verifiable<Transaction>>],
}

/// Provision-tx roots map type as carried by [`BlockHeader`](crate::BlockHeader),
/// at the entry cap a block's provision targets are held to.
///
/// [`MAX_PROVISION_TARGET_SHARDS`]: crate::MAX_PROVISION_TARGET_SHARDS
pub type ProvisionTxRootsMap =
    Capped<BTreeMap<ShardId, ProvisionTxRoot>, MAX_PROVISION_TARGET_SHARDS>;

/// Failure modes of provision-tx-roots verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionTxRootsVerifyError {
    /// The per-target-shard map computed from the supplied transactions
    /// does not match the claimed map.
    #[error("computed provision_tx_roots {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed per-target-shard provision-tx roots.
        expected: ProvisionTxRootsMap,
        /// Map computed from the supplied transactions.
        computed: ProvisionTxRootsMap,
    },
}

impl Verified<ProvisionTxRootsMap> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the
    /// header's claimed map is empty (no cross-shard targets) or an
    /// earlier verifier run already accepted `map`.
    #[must_use]
    pub const fn from_pipeline_attestation(map: ProvisionTxRootsMap) -> Self {
        Self::new_unchecked(map)
    }

    /// Compute the per-target-shard provision-tx roots from
    /// `transactions` under `topology`. Verified by construction.
    ///
    /// For each cross-shard tx, the tx hash lands in the bucket of every
    /// remote shard it touches. Each bucket is merkle-committed in that
    /// order so the target shard can verify a received `Provisions`
    /// carries the full set it was meant to receive, and the bundle
    /// builder stages requests in the same order. Only emits an entry
    /// for targets with ≥1 tx. A block promises read sets only: a
    /// crossing record reaches its consumer as a state claim, never as
    /// a bundle.
    ///
    /// # Panics
    ///
    /// Never: a block exports to at most one entry per other shard,
    /// which is what [`MAX_PROVISION_TARGET_SHARDS`] counts.
    ///
    /// [`MAX_PROVISION_TARGET_SHARDS`]: crate::MAX_PROVISION_TARGET_SHARDS
    #[must_use]
    pub fn compute(
        local_shard: ShardId,
        topology_snapshot: &TopologySnapshot,
        transactions: &[Arc<Verifiable<Transaction>>],
    ) -> Self {
        let mut per_target: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();

        for tx in transactions {
            if topology_snapshot.is_single_shard_transaction(tx) {
                continue;
            }
            // A transaction's fan-out is role-shaped. The payer shard and
            // the shards owning part of its read set attest toward every
            // participant: the payer's bundle is the engagement evidence
            // and flows even with no state, an owner's carries its
            // read-set values. Every other participant owes exactly one
            // edge — the engagement echo toward the payer: its commitment
            // of the transaction is what the payer's vote waits for, and
            // nobody else consumes anything from it.
            let trie = topology_snapshot.shard_trie();
            let payer_shard = trie.shard_for_prefix(tx.fee_payer());
            let owns_read_set = tx
                .routing()
                .provision_prefixes
                .iter()
                .any(|prefix| trie.shard_for_prefix(*prefix) == local_shard);
            if payer_shard != local_shard && !owns_read_set {
                per_target
                    .entry(payer_shard)
                    .or_default()
                    .push(Hash::from(tx.hash()));
                continue;
            }
            for shard in topology_snapshot.all_shards_for_transaction(tx) {
                if shard == local_shard {
                    continue;
                }
                per_target
                    .entry(shard)
                    .or_default()
                    .push(Hash::from(tx.hash()));
            }
        }

        let map: ProvisionTxRootsMap = Capped::new(
            per_target
                .into_iter()
                .map(|(shard, hashes)| {
                    (
                        shard,
                        ProvisionTxRoot::from_raw(compute_merkle_root(&hashes)),
                    )
                })
                .collect(),
        )
        .expect("a block exports one entry per other shard");
        Self::new_unchecked(map)
    }
}

/// Construction asserts: the wrapped map equals
/// [`Verified::<ProvisionTxRootsMap>::compute`] of the block's
/// transactions under the supplied topology.
impl Verify<&ProvisionTxRootsContext<'_>> for ProvisionTxRootsMap {
    type Error = ProvisionTxRootsVerifyError;

    fn verify(&self, ctx: &ProvisionTxRootsContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed =
            Verified::<Self>::compute(ctx.local_shard, ctx.topology_snapshot, ctx.transactions);
        if computed.as_ref() != self {
            return Err(ProvisionTxRootsVerifyError::Mismatch {
                expected: self.clone(),
                computed: computed.into_inner(),
            });
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        TestCommittee, install_stub_protocol_statics, stub_transaction, test_prefix, test_principal,
    };
    use crate::{PrincipalAddr, TimestampRange, WeightedTimestamp};

    fn cross_shard_tx(payer: PrincipalAddr) -> Arc<Verifiable<Transaction>> {
        install_stub_protocol_statics();
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(100_000),
        );
        Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
            stub_transaction(
                payer,
                &[test_prefix(0x01), test_prefix(0x81)],
                1_000,
                validity,
            ),
        )))
    }

    #[test]
    fn a_pure_counterpart_fans_out_to_the_payer_alone() {
        // The stub derivation carries no provision prefixes, so the
        // non-payer shard owns nothing to attest: its only edge is the
        // engagement echo toward the payer.
        let topo = TestCommittee::new(4, 42).topology_snapshot(2);
        let payer_shard = ShardId::leaf(1, 1);
        let counterpart = ShardId::leaf(1, 0);
        let txs = vec![cross_shard_tx(test_principal(0x81))];

        let at_counterpart = Verified::<ProvisionTxRootsMap>::compute(counterpart, &topo, &txs);
        let targets: Vec<ShardId> = at_counterpart.as_ref().keys().copied().collect();
        assert_eq!(targets, vec![payer_shard]);

        // The payer still fans out to every participant: its bundle is
        // the engagement evidence.
        let at_payer = Verified::<ProvisionTxRootsMap>::compute(payer_shard, &topo, &txs);
        let targets: Vec<ShardId> = at_payer.as_ref().keys().copied().collect();
        assert_eq!(targets, vec![counterpart]);
    }
}
