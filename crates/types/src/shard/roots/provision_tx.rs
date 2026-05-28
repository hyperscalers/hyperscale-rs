//! Per-target-shard [`ProvisionTxRoot`] verification.

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use crate::{
    BoundedBTreeMap, Hash, MAX_REMOTE_SHARDS_PER_WAVE, ProvisionTxRoot, RoutableTransaction,
    ShardGroupId, TopologySnapshot, Verifiable, Verified, Verify, compute_merkle_root,
};

/// Inputs the provision-tx-roots verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionTxRootsContext<'a> {
    /// Topology snapshot anchoring shard routing — drives which target
    /// shards each cross-shard tx contributes to.
    pub topology: &'a TopologySnapshot,
    /// The block's transactions in block order.
    pub transactions: &'a [Arc<Verifiable<RoutableTransaction>>],
}

/// Provision-tx roots map type as carried by [`BlockHeader`](crate::BlockHeader).
///
/// Type alias rather than a separate newtype because the bound `MAX_REMOTE_SHARDS_PER_WAVE`
/// is invariant across every site that touches this map.
pub type ProvisionTxRootsMap =
    BoundedBTreeMap<ShardGroupId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>;

/// Failure modes of provision-tx-roots verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionTxRootsVerifyError {
    /// The per-target-shard map computed from the supplied transactions
    /// does not match the claimed map.
    #[error("computed provision_tx_roots {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed per-target-shard provision-tx roots.
        expected: BTreeMap<ShardGroupId, ProvisionTxRoot>,
        /// Map computed from the supplied transactions.
        computed: BTreeMap<ShardGroupId, ProvisionTxRoot>,
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
    /// remote shard it touches. Each bucket is merkle-committed in
    /// already-hash-ascending block order so the target shard can verify
    /// a received `Provisions` carries the full set it was meant to
    /// receive. Only emits an entry for targets with ≥1 tx — empty for
    /// blocks with no cross-shard txs.
    ///
    /// # Panics
    ///
    /// Panics if the computed map exceeds [`MAX_REMOTE_SHARDS_PER_WAVE`]
    /// entries — that would require a single block to fan out across
    /// more shards than the consensus configuration allows.
    #[must_use]
    pub fn compute(
        topology: &TopologySnapshot,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
    ) -> Self {
        let local_shard = topology.local_shard();
        let mut per_target: BTreeMap<ShardGroupId, Vec<Hash>> = BTreeMap::new();

        for tx in transactions {
            if topology.is_single_shard_transaction(tx) {
                continue;
            }
            for shard in topology.all_shards_for_transaction(tx) {
                if shard == local_shard {
                    continue;
                }
                per_target
                    .entry(shard)
                    .or_default()
                    .push(tx.hash().into_raw());
            }
        }

        let map: BTreeMap<ShardGroupId, ProvisionTxRoot> = per_target
            .into_iter()
            .map(|(shard, hashes)| {
                (
                    shard,
                    ProvisionTxRoot::from_raw(compute_merkle_root(&hashes)),
                )
            })
            .collect();
        Self::new_unchecked(map.into())
    }
}

/// Construction asserts: the wrapped map equals
/// [`Verified::<ProvisionTxRootsMap>::compute`] of the block's
/// transactions under the supplied topology.
impl Verify<&ProvisionTxRootsContext<'_>> for ProvisionTxRootsMap {
    type Error = ProvisionTxRootsVerifyError;

    fn verify(&self, ctx: &ProvisionTxRootsContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = Verified::<ProvisionTxRootsMap>::compute(ctx.topology, ctx.transactions);
        if computed.as_ref() != self {
            let expected: BTreeMap<_, _> = self.iter().map(|(k, v)| (*k, *v)).collect();
            let computed: BTreeMap<_, _> =
                computed.as_ref().iter().map(|(k, v)| (*k, *v)).collect();
            return Err(ProvisionTxRootsVerifyError::Mismatch { expected, computed });
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}
