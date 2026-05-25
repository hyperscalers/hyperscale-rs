//! [`BeaconBlock`] — the SPC-cert-authenticated record of one epoch.
//!
//! A `BeaconBlock` carries the epoch's committed proposals, the SPC
//! cert that decided them (sole authenticator), and an optional
//! `RecoveryCertificate` feeding into the next epoch's committee
//! sampling. There is no separate header or aggregate signature: the
//! [`cert`](BeaconBlock::cert) is the block's signature, verifiable
//! against the beacon committee resolved from the previous epoch's
//! state.

use sbor::prelude::*;

use crate::primitives::signer_bitfield::MAX_VALIDATORS;
use crate::{
    BeaconBlockHash, BeaconProposal, BoundedVec, Epoch, GenesisConfigHash, Hash,
    RecoveryCertificate, SpcCert, ValidatorId,
};

/// One epoch's finalized beacon block.
///
/// The [`cert`](Self::cert) is the sole committee authentication —
/// `SpcCert::Direct`/`Indirect` for a normal epoch, `SpcCert::Genesis`
/// for the bootstrap. Verification is the beacon crate's job; this
/// type is a pure data container.
///
/// `block_hash` is the canonical SBOR-hash of the whole block, so any
/// tampering with the cert, committed proposals, recovery cert, or
/// chain linkage changes the identity. The next block's
/// [`prev_block_hash`](Self::prev_block_hash) references it.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlock {
    epoch: Epoch,
    prev_block_hash: BeaconBlockHash,
    cert: SpcCert,
    recovery_cert: Option<RecoveryCertificate>,
    committed_proposals: BoundedVec<(ValidatorId, BeaconProposal), MAX_VALIDATORS>,
}

impl BeaconBlock {
    /// Build a `BeaconBlock` from its parts.
    ///
    /// Cert/cert-committee/recovery-cert validation is the beacon
    /// crate's job — this is a pure data constructor.
    ///
    /// # Panics
    ///
    /// Panics if `committed_proposals.len() > MAX_VALIDATORS`.
    #[must_use]
    pub fn new(
        epoch: Epoch,
        prev_block_hash: BeaconBlockHash,
        cert: SpcCert,
        recovery_cert: Option<RecoveryCertificate>,
        committed_proposals: Vec<(ValidatorId, BeaconProposal)>,
    ) -> Self {
        Self {
            epoch,
            prev_block_hash,
            cert,
            recovery_cert,
            committed_proposals: committed_proposals.into(),
        }
    }

    /// Genesis block: epoch 0, zero parent, vacuous Genesis cert
    /// binding the chain to `config_hash`, no recovery cert, no
    /// proposals.
    #[must_use]
    pub const fn genesis(config_hash: GenesisConfigHash) -> Self {
        Self {
            epoch: Epoch::GENESIS,
            prev_block_hash: BeaconBlockHash::ZERO,
            cert: SpcCert::Genesis { config_hash },
            recovery_cert: None,
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

    /// SPC cert authenticating this block's committed proposal set.
    #[must_use]
    pub const fn cert(&self) -> &SpcCert {
        &self.cert
    }

    /// Recovery certificate carried by this block, if any. `Some` for
    /// the block at which an active-pool quorum's recovery request
    /// landed; consumed by `apply_epoch` to resample the next epoch's
    /// committee.
    #[must_use]
    pub const fn recovery_cert(&self) -> Option<&RecoveryCertificate> {
        self.recovery_cert.as_ref()
    }

    /// Committee members' proposals committed at this epoch, in the
    /// order they appear on the wire. `apply_epoch` re-sorts as needed.
    #[must_use]
    pub fn committed_proposals(&self) -> &[(ValidatorId, BeaconProposal)] {
        &self.committed_proposals
    }

    /// Canonical SBOR-hash of the whole block — the identity used for
    /// chain linkage and storage lookup.
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

    /// Whether this is the genesis block.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.epoch == Epoch::GENESIS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Bls12381G2Signature, PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, RecoveryRound,
        SignerBitfield, SpcView, VRF_PROOF_BYTES, VrfOutput, VrfProof,
    };

    fn sample_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_direct_cert() -> SpcCert {
        SpcCert::Direct {
            prev_view: SpcView::new(1),
            value: PcVector::empty(),
            proof: sample_pc_qc3(),
        }
    }

    fn sample_proposal(seed: u8) -> BeaconProposal {
        BeaconProposal::new(
            Vec::new(),
            VrfOutput([seed; 32]),
            VrfProof([seed; VRF_PROOF_BYTES]),
        )
    }

    fn sample_recovery_cert() -> RecoveryCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(5),
            RecoveryRound::new(1),
            Vec::new(),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn sbor_round_trip_without_recovery_cert() {
        let original = BeaconBlock::new(
            Epoch::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            sample_direct_cert(),
            None,
            vec![(ValidatorId::new(0), sample_proposal(0))],
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn sbor_round_trip_with_recovery_cert() {
        let original = BeaconBlock::new(
            Epoch::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            sample_direct_cert(),
            Some(sample_recovery_cert()),
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
            sample_direct_cert(),
            None,
            Vec::new(),
        );
        let h_base = base.block_hash();

        let diff_epoch = BeaconBlock::new(
            Epoch::new(8),
            base.prev_block_hash(),
            base.cert().clone(),
            None,
            Vec::new(),
        );
        assert_ne!(h_base, diff_epoch.block_hash());

        let diff_parent = BeaconBlock::new(
            base.epoch(),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"other-prev")),
            base.cert().clone(),
            None,
            Vec::new(),
        );
        assert_ne!(h_base, diff_parent.block_hash());

        let diff_recovery = BeaconBlock::new(
            base.epoch(),
            base.prev_block_hash(),
            base.cert().clone(),
            Some(sample_recovery_cert()),
            Vec::new(),
        );
        assert_ne!(h_base, diff_recovery.block_hash());
    }

    #[test]
    fn genesis_has_zero_parent_and_genesis_cert() {
        let config_hash = GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg"));
        let g = BeaconBlock::genesis(config_hash);
        assert!(g.is_genesis());
        assert_eq!(g.epoch(), Epoch::GENESIS);
        assert_eq!(g.prev_block_hash(), BeaconBlockHash::ZERO);
        assert!(g.recovery_cert().is_none());
        assert!(g.committed_proposals().is_empty());
        match g.cert() {
            SpcCert::Genesis {
                config_hash: stored,
            } => {
                assert_eq!(*stored, config_hash);
            }
            _ => panic!("expected Genesis cert"),
        }
    }

    #[test]
    fn genesis_blocks_with_different_configs_have_different_hashes() {
        let a = BeaconBlock::genesis(GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg-a")));
        let b = BeaconBlock::genesis(GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg-b")));
        assert_ne!(a.block_hash(), b.block_hash());
    }
}
