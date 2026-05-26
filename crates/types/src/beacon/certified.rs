//! A [`BeaconBlock`] paired with its authenticating [`BeaconCert`].
//!
//! Mirrors the shard [`CertifiedBlock`](crate::CertifiedBlock) shape:
//! the block is the chain-linkage identity (its hash is what
//! `prev_block_hash` references on the next block); the cert is
//! side-data that authenticates it. Two nodes holding byte-different
//! `CertifiedBeaconBlock`s of the same logical block (different valid
//! Skip-cert signer subsets, for example) agree on the block hash used
//! for chain linkage — the wrapper is never hashed.
//!
//! Pairing invariant — `cert` shape must match `block` shape:
//!
//! - [`BeaconCert::Genesis`] ⇔ `block.epoch == GENESIS` ∧ no proposals.
//! - [`BeaconCert::Normal`] ⇔ `block.epoch > GENESIS`.
//! - [`BeaconCert::Skip`] ⇔ `block.epoch > GENESIS` ∧ no proposals.
//!
//! Enforced at [`new_checked`](CertifiedBeaconBlock::new_checked) and
//! at SBOR-decode (manual `Decode` impl below). Wire bytes carrying a
//! mismatched pairing reject with `DecodeError::InvalidCustomValue`.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{BeaconBlock, BeaconBlockHash, BeaconCert, Epoch, GenesisConfigHash};

/// A beacon block paired with the cert that authenticates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedBeaconBlock {
    block: BeaconBlock,
    cert: BeaconCert,
}

/// Error variants for the cert-body pairing invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedBeaconBlockPairingError {
    /// `Genesis` cert at a non-genesis epoch.
    GenesisCertWithNonGenesisBlock,
    /// `Genesis` cert with non-empty committed proposals.
    GenesisCertWithProposals,
    /// `Normal` cert at the genesis epoch.
    NormalCertAtGenesis,
    /// `Skip` cert at the genesis epoch.
    SkipCertAtGenesis,
    /// `Skip` cert with non-empty committed proposals.
    SkipCertWithProposals,
}

impl CertifiedBeaconBlock {
    /// Pair a block with a cert, checking the pairing invariant.
    ///
    /// # Errors
    ///
    /// Returns `CertifiedBeaconBlockPairingError` if the cert shape
    /// doesn't match the block shape (see [module docs](self)).
    pub fn new_checked(
        block: BeaconBlock,
        cert: BeaconCert,
    ) -> Result<Self, CertifiedBeaconBlockPairingError> {
        Self::check_pairing(&block, &cert)?;
        Ok(Self { block, cert })
    }

    /// Pair a block with a cert, panicking on pairing mismatch. Use at
    /// call sites where the pair is constructed together (genesis,
    /// freshly produced blocks, test fixtures) and a mismatch is a
    /// programmer error. Use [`new_checked`](Self::new_checked) for any
    /// path that consumes externally-sourced pairs (wire decode,
    /// storage load).
    ///
    /// # Panics
    ///
    /// Panics if `cert`'s shape doesn't match `block`'s shape.
    #[must_use]
    pub fn new_unchecked(block: BeaconBlock, cert: BeaconCert) -> Self {
        match Self::new_checked(block, cert) {
            Ok(this) => this,
            Err(e) => panic!("CertifiedBeaconBlock pairing invariant: {e:?}"),
        }
    }

    /// Genesis bootstrap pair.
    #[must_use]
    pub const fn genesis(config_hash: GenesisConfigHash) -> Self {
        Self {
            block: BeaconBlock::genesis(),
            cert: BeaconCert::Genesis(config_hash),
        }
    }

    /// Inner block.
    #[must_use]
    pub const fn block(&self) -> &BeaconBlock {
        &self.block
    }

    /// Authenticating cert.
    #[must_use]
    pub const fn cert(&self) -> &BeaconCert {
        &self.cert
    }

    /// Block hash — chain-linkage identity. Delegates to the inner
    /// block; the wrapper is never hashed.
    #[must_use]
    pub fn block_hash(&self) -> BeaconBlockHash {
        self.block.block_hash()
    }

    /// Epoch of the inner block.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.block.epoch()
    }

    /// `prev_block_hash` of the inner block.
    #[must_use]
    pub const fn prev_block_hash(&self) -> BeaconBlockHash {
        self.block.prev_block_hash()
    }

    /// Whether the inner block is the genesis block.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.block.is_genesis()
    }

    /// Consume and return parts.
    #[must_use]
    pub fn into_parts(self) -> (BeaconBlock, BeaconCert) {
        (self.block, self.cert)
    }

    fn check_pairing(
        block: &BeaconBlock,
        cert: &BeaconCert,
    ) -> Result<(), CertifiedBeaconBlockPairingError> {
        use CertifiedBeaconBlockPairingError as E;
        let is_genesis_epoch = block.epoch() == Epoch::GENESIS;
        let has_proposals = !block.committed_proposals().is_empty();
        match cert {
            BeaconCert::Genesis(_) => {
                if !is_genesis_epoch {
                    return Err(E::GenesisCertWithNonGenesisBlock);
                }
                if has_proposals {
                    return Err(E::GenesisCertWithProposals);
                }
            }
            BeaconCert::Normal(_) => {
                if is_genesis_epoch {
                    return Err(E::NormalCertAtGenesis);
                }
            }
            BeaconCert::Skip(_) => {
                if is_genesis_epoch {
                    return Err(E::SkipCertAtGenesis);
                }
                if has_proposals {
                    return Err(E::SkipCertWithProposals);
                }
            }
        }
        Ok(())
    }
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for CertifiedBeaconBlock {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.block)?;
        encoder.encode(&self.cert)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for CertifiedBeaconBlock {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let block: BeaconBlock = decoder.decode()?;
        let cert: BeaconCert = decoder.decode()?;
        Self::new_checked(block, cert).map_err(|_| DecodeError::InvalidCustomValue)
    }
}

impl Categorize<NoCustomValueKind> for CertifiedBeaconBlock {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for CertifiedBeaconBlock {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("CertifiedBeaconBlock", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BeaconBlockHash, BeaconProposal, Bls12381G2Signature, Hash, PcQc2, PcQc3, PcSignerLengths,
        PcVector, PcXpProof, SignerBitfield, SkipEpochCert, SpcCert, SpcView, VRF_PROOF_BYTES,
        ValidatorId, VrfOutput, VrfProof,
    };

    fn proposal(seed: u8) -> BeaconProposal {
        BeaconProposal::new(
            Vec::new(),
            VrfOutput::new([seed; 32]),
            VrfProof::new([seed; VRF_PROOF_BYTES]),
        )
    }

    fn direct_cert() -> SpcCert {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        let proof = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        );
        SpcCert::Direct {
            prev_view: SpcView::new(1),
            value: PcVector::empty(),
            proof,
        }
    }

    fn skip_cert() -> SkipEpochCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(5),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn genesis_pair_round_trip() {
        let g =
            CertifiedBeaconBlock::genesis(GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg")));
        let bytes = basic_encode(&g).unwrap();
        let decoded: CertifiedBeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
        assert!(decoded.is_genesis());
    }

    #[test]
    fn normal_pair_round_trip() {
        let block = BeaconBlock::new(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            vec![(ValidatorId::new(0), proposal(0))],
        );
        let pair =
            CertifiedBeaconBlock::new_checked(block, BeaconCert::Normal(Box::new(direct_cert())))
                .unwrap();
        let bytes = basic_encode(&pair).unwrap();
        let decoded: CertifiedBeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(pair, decoded);
    }

    #[test]
    fn skip_pair_round_trip() {
        let block = BeaconBlock::skip(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
        );
        let pair = CertifiedBeaconBlock::new_checked(block, BeaconCert::Skip(skip_cert())).unwrap();
        let bytes = basic_encode(&pair).unwrap();
        let decoded: CertifiedBeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(pair, decoded);
    }

    /// Two different `SkipEpochCert`s (different signer subsets) paired
    /// with byte-identical `BeaconBlock`s produce identical block
    /// hashes — adoption convergence property.
    #[test]
    fn skip_certs_with_different_signers_share_block_hash() {
        let epoch = Epoch::new(5);
        let prev = BeaconBlockHash::from_raw(Hash::from_bytes(b"prev"));
        let block_a = BeaconBlock::skip(epoch, prev);
        let block_b = BeaconBlock::skip(epoch, prev);

        let mut signers_a = SignerBitfield::new(4);
        signers_a.set(0);
        signers_a.set(1);
        signers_a.set(2);
        let cert_a = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            epoch,
            signers_a,
            Bls12381G2Signature([0x22; 96]),
        );

        let mut signers_b = SignerBitfield::new(4);
        signers_b.set(0);
        signers_b.set(2);
        signers_b.set(3);
        let cert_b = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            epoch,
            signers_b,
            Bls12381G2Signature([0x44; 96]),
        );

        let pair_a = CertifiedBeaconBlock::new_checked(block_a, BeaconCert::Skip(cert_a)).unwrap();
        let pair_b = CertifiedBeaconBlock::new_checked(block_b, BeaconCert::Skip(cert_b)).unwrap();
        assert_eq!(pair_a.block_hash(), pair_b.block_hash());
    }

    #[test]
    fn rejects_genesis_cert_at_non_genesis_epoch() {
        let block = BeaconBlock::new(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            Vec::new(),
        );
        let err =
            CertifiedBeaconBlock::new_checked(block, BeaconCert::Genesis(GenesisConfigHash::ZERO))
                .unwrap_err();
        assert_eq!(
            err,
            CertifiedBeaconBlockPairingError::GenesisCertWithNonGenesisBlock
        );
    }

    #[test]
    fn rejects_normal_cert_at_genesis() {
        let block = BeaconBlock::genesis();
        let err =
            CertifiedBeaconBlock::new_checked(block, BeaconCert::Normal(Box::new(direct_cert())))
                .unwrap_err();
        assert_eq!(err, CertifiedBeaconBlockPairingError::NormalCertAtGenesis);
    }

    #[test]
    fn rejects_skip_cert_with_proposals() {
        let block = BeaconBlock::new(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            vec![(ValidatorId::new(0), proposal(0))],
        );
        let err =
            CertifiedBeaconBlock::new_checked(block, BeaconCert::Skip(skip_cert())).unwrap_err();
        assert_eq!(err, CertifiedBeaconBlockPairingError::SkipCertWithProposals);
    }

    /// Forge a wire-byte stream carrying a `Skip` cert paired with a
    /// non-empty proposal list. SBOR decode must reject via the
    /// pairing-invariant check, same way the shard
    /// `CertifiedBlock` decoder rejects `qc.block_hash` mismatches.
    #[test]
    fn decode_rejects_skip_cert_with_proposals() {
        let block = BeaconBlock::new(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            vec![(ValidatorId::new(0), proposal(0))],
        );
        let bytes = basic_encode(&CertifiedBeaconBlockWire {
            block,
            cert: BeaconCert::Skip(skip_cert()),
        })
        .unwrap();
        let err = basic_decode::<CertifiedBeaconBlock>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    #[test]
    fn decode_rejects_genesis_cert_at_non_genesis_epoch() {
        let block = BeaconBlock::new(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            Vec::new(),
        );
        let bytes = basic_encode(&CertifiedBeaconBlockWire {
            block,
            cert: BeaconCert::Genesis(GenesisConfigHash::ZERO),
        })
        .unwrap();
        let err = basic_decode::<CertifiedBeaconBlock>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    #[test]
    fn decode_rejects_normal_cert_at_genesis() {
        let block = BeaconBlock::genesis();
        let bytes = basic_encode(&CertifiedBeaconBlockWire {
            block,
            cert: BeaconCert::Normal(Box::new(direct_cert())),
        })
        .unwrap();
        let err = basic_decode::<CertifiedBeaconBlock>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    /// Wire-shape twin of `CertifiedBeaconBlock` that skips the pairing
    /// invariant during encode, so tests can construct adversarial byte
    /// streams. Mirrors the shard
    /// `CertifiedBlockWire`.
    #[derive(sbor::BasicSbor)]
    #[sbor(transparent_name)]
    struct CertifiedBeaconBlockWire {
        block: BeaconBlock,
        cert: BeaconCert,
    }
}
