//! [`BeaconBlock`] — the per-epoch committed-proposal record.
//!
//! A `BeaconBlock` carries the epoch's committed proposals and the
//! chain linkage to its parent. The authenticating cert
//! ([`BeaconCert`](crate::BeaconCert)) lives outside the block hash —
//! see [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock). This
//! mirrors the shard
//! [`CertifiedBlock`](crate::CertifiedBlock) shape and gives skip
//! blocks the load-bearing property that different valid certs (with
//! different signer subsets) at the same `(anchor, epoch)` all
//! authenticate the same block hash, so adoption converges.

use sbor::prelude::*;

use crate::primitives::signer_bitfield::MAX_VALIDATORS;
use crate::{BeaconBlockHash, BeaconProposal, BoundedVec, Epoch, Hash, ValidatorId};

/// One epoch's committed-proposal record.
///
/// `block_hash` is the canonical SBOR-hash of the three flat fields. The
/// cert that authenticates this block sits on the wrapping
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) — chain
/// linkage via `prev_block_hash` references the block hash, never the
/// wrapper.
///
/// Skip and Genesis blocks have empty `committed_proposals`; the
/// authenticating cert kind distinguishes them.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlock {
    epoch: Epoch,
    prev_block_hash: BeaconBlockHash,
    committed_proposals: BoundedVec<(ValidatorId, BeaconProposal), MAX_VALIDATORS>,
}

impl BeaconBlock {
    /// Build a `BeaconBlock` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `committed_proposals.len() > MAX_VALIDATORS`.
    #[must_use]
    pub fn new(
        epoch: Epoch,
        prev_block_hash: BeaconBlockHash,
        committed_proposals: Vec<(ValidatorId, BeaconProposal)>,
    ) -> Self {
        Self {
            epoch,
            prev_block_hash,
            committed_proposals: committed_proposals.into(),
        }
    }

    /// Bare genesis-shaped block: epoch 0, zero parent, no proposals.
    /// Pair with [`BeaconCert::Genesis`](crate::BeaconCert::Genesis) via
    /// [`CertifiedBeaconBlock::genesis`](crate::CertifiedBeaconBlock::genesis).
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            epoch: Epoch::GENESIS,
            prev_block_hash: BeaconBlockHash::ZERO,
            committed_proposals: BoundedVec::new(),
        }
    }

    /// Bare skip-shaped block at `epoch` linking back to `prev_block_hash`.
    /// Pair with [`BeaconCert::Skip`](crate::BeaconCert::Skip) via
    /// [`CertifiedBeaconBlock::new_checked`](crate::CertifiedBeaconBlock::new_checked).
    #[must_use]
    pub const fn skip(epoch: Epoch, prev_block_hash: BeaconBlockHash) -> Self {
        Self {
            epoch,
            prev_block_hash,
            committed_proposals: BoundedVec::new(),
        }
    }

    /// Epoch this block finalises.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Hash of the previous finalised beacon block. `BeaconBlockHash::ZERO`
    /// at genesis.
    #[must_use]
    pub const fn prev_block_hash(&self) -> BeaconBlockHash {
        self.prev_block_hash
    }

    /// Committee members' proposals committed at this epoch. Empty for
    /// Genesis and Skip blocks.
    #[must_use]
    pub fn committed_proposals(&self) -> &[(ValidatorId, BeaconProposal)] {
        &self.committed_proposals
    }

    /// Canonical SBOR-hash of the block — the chain-linkage identity.
    /// Independent of which cert authenticates the block.
    ///
    /// # Panics
    ///
    /// Never in practice: every field is `BasicSbor` and the struct is
    /// closed, so encoding is total.
    #[must_use]
    pub fn block_hash(&self) -> BeaconBlockHash {
        let bytes = basic_encode(self).expect("BeaconBlock serialization is infallible");
        BeaconBlockHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Whether this is the genesis block (epoch 0).
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.epoch == Epoch::GENESIS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VRF_PROOF_BYTES, VrfOutput, VrfProof};

    fn sample_proposal(seed: u8) -> BeaconProposal {
        BeaconProposal::new(
            Vec::new(),
            VrfOutput::new([seed; 32]),
            VrfProof::new([seed; VRF_PROOF_BYTES]),
        )
    }

    #[test]
    fn sbor_round_trip_empty_proposals() {
        let original = BeaconBlock::new(
            Epoch::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            Vec::new(),
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn sbor_round_trip_with_proposals() {
        let original = BeaconBlock::new(
            Epoch::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            vec![
                (ValidatorId::new(0), sample_proposal(0)),
                (ValidatorId::new(1), sample_proposal(1)),
            ],
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_hash_changes_with_any_field() {
        let base = BeaconBlock::new(
            Epoch::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            Vec::new(),
        );
        let h_base = base.block_hash();

        let diff_epoch = BeaconBlock::new(Epoch::new(8), base.prev_block_hash(), Vec::new());
        assert_ne!(h_base, diff_epoch.block_hash());

        let diff_parent = BeaconBlock::new(
            base.epoch(),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"other-prev")),
            Vec::new(),
        );
        assert_ne!(h_base, diff_parent.block_hash());

        let diff_proposals = BeaconBlock::new(
            base.epoch(),
            base.prev_block_hash(),
            vec![(ValidatorId::new(0), sample_proposal(0))],
        );
        assert_ne!(h_base, diff_proposals.block_hash());
    }

    #[test]
    fn genesis_has_zero_parent_and_empty_proposals() {
        let g = BeaconBlock::genesis();
        assert!(g.is_genesis());
        assert_eq!(g.epoch(), Epoch::GENESIS);
        assert_eq!(g.prev_block_hash(), BeaconBlockHash::ZERO);
        assert!(g.committed_proposals().is_empty());
    }

    /// Block hash is independent of any cert: a Skip-shaped block and a
    /// Normal-shaped block with the same `(epoch, prev_block_hash,
    /// empty_proposals)` produce identical hashes. The discriminator
    /// lives on the cert.
    #[test]
    fn skip_and_empty_normal_have_identical_block_hash() {
        let epoch = Epoch::new(5);
        let prev = BeaconBlockHash::from_raw(Hash::from_bytes(b"prev"));
        let skip = BeaconBlock::skip(epoch, prev);
        let empty_normal = BeaconBlock::new(epoch, prev, Vec::new());
        assert_eq!(skip.block_hash(), empty_normal.block_hash());
    }
}
