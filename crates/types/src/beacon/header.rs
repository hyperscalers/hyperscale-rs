//! Beacon block header — what the slot committee signs to finalize a slot.

use sbor::prelude::*;

use crate::{BeaconBlockHash, BeaconProposalsRoot, BeaconStateRoot, Hash, RecoveryCertHash, Slot};

/// Beacon block header — what the slot's committee signs to finalize a slot.
///
/// Two roots pair input with outcome:
///
/// - [`proposals_root`](Self::proposals_root) commits to the *inputs*
///   the committee decided over (every committee member's encoded
///   proposal).
/// - [`state_root`](Self::state_root) commits to the *outcome* — the
///   beacon chain's state after the slot's deterministic application
///   logic runs.
///
/// `prev_block_hash` chains slots; `recovery_cert_hash` binds an
/// optional recovery certificate (committee-replacement evidence) into
/// the aggregate signature so the cert body cannot be swapped post-hoc.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlockHeader {
    slot: Slot,
    prev_block_hash: BeaconBlockHash,
    proposals_root: BeaconProposalsRoot,
    state_root: BeaconStateRoot,
    recovery_cert_hash: RecoveryCertHash,
}

impl BeaconBlockHeader {
    /// Build a `BeaconBlockHeader` from its parts.
    #[must_use]
    pub const fn new(
        slot: Slot,
        prev_block_hash: BeaconBlockHash,
        proposals_root: BeaconProposalsRoot,
        state_root: BeaconStateRoot,
        recovery_cert_hash: RecoveryCertHash,
    ) -> Self {
        Self {
            slot,
            prev_block_hash,
            proposals_root,
            state_root,
            recovery_cert_hash,
        }
    }

    /// Genesis header (slot 0): zero parent hash, no proposals, given
    /// state root, no recovery cert.
    #[must_use]
    pub const fn genesis(state_root: BeaconStateRoot) -> Self {
        Self {
            slot: Slot::GENESIS,
            prev_block_hash: BeaconBlockHash::ZERO,
            proposals_root: BeaconProposalsRoot::ZERO,
            state_root,
            recovery_cert_hash: RecoveryCertHash::ZERO,
        }
    }

    /// Slot this header finalizes.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    /// Hash of the previous finalized beacon block.
    ///
    /// `BeaconBlockHash::ZERO` for the genesis header.
    #[must_use]
    pub const fn prev_block_hash(&self) -> BeaconBlockHash {
        self.prev_block_hash
    }

    /// Merkle root over the slot's committed proposals (each committee
    /// member's `(validator_id, encoded_proposal)`, sorted by id).
    ///
    /// `BeaconProposalsRoot::ZERO` for the genesis header.
    #[must_use]
    pub const fn proposals_root(&self) -> BeaconProposalsRoot {
        self.proposals_root
    }

    /// Merkle commitment to the beacon-chain state after applying this
    /// slot's committed proposals.
    #[must_use]
    pub const fn state_root(&self) -> BeaconStateRoot {
        self.state_root
    }

    /// Content hash of the recovery certificate riding in this block, or
    /// [`RecoveryCertHash::ZERO`] when no cert is attached.
    #[must_use]
    pub const fn recovery_cert_hash(&self) -> RecoveryCertHash {
        self.recovery_cert_hash
    }

    /// Content hash of the header — used as the next block's
    /// [`prev_block_hash`](Self::prev_block_hash) and as the message the
    /// slot committee signs.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — `BeaconBlockHeader` is a closed
    /// SBOR type and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> BeaconBlockHash {
        let bytes = basic_encode(self).expect("BeaconBlockHeader serialization should never fail");
        BeaconBlockHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Whether this is the genesis header (slot 0).
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.slot == Slot::GENESIS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            Slot::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
            RecoveryCertHash::from_raw(Hash::from_bytes(b"recovery")),
        )
    }

    #[test]
    fn hash_is_deterministic() {
        let h = sample_header();
        assert_eq!(h.hash(), h.hash());
    }

    #[test]
    fn hash_is_content_sensitive() {
        let a = sample_header();
        let b = BeaconBlockHeader::new(
            a.slot().next(),
            a.prev_block_hash(),
            a.proposals_root(),
            a.state_root(),
            a.recovery_cert_hash(),
        );
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn sbor_round_trip() {
        let original = sample_header();
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlockHeader = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn genesis_has_zero_predecessor_and_zero_proposals() {
        let g = BeaconBlockHeader::genesis(BeaconStateRoot::from_raw(Hash::from_bytes(b"s")));
        assert!(g.is_genesis());
        assert_eq!(g.slot(), Slot::GENESIS);
        assert_eq!(g.prev_block_hash(), BeaconBlockHash::ZERO);
        assert_eq!(g.proposals_root(), BeaconProposalsRoot::ZERO);
        assert_eq!(g.recovery_cert_hash(), RecoveryCertHash::ZERO);
    }
}
