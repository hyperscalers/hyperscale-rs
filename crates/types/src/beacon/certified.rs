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
use thiserror::Error;

use crate::{
    BeaconBlock, BeaconBlockHash, BeaconCert, Bls12381G1PublicKey, Epoch, GenesisConfigHash,
    NetworkDefinition, PcValueElement, ValidatorId, Verified, Verify, spc_context,
    verify_block_cert, verify_skip_cert, verify_vote_equivocation,
};

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

// ─── Verifiers ─────────────────────────────────────────────────────────────

/// Verify a [`CertifiedBeaconBlock`] under the cert variant's required
/// signer pool.
///
/// Dispatches: SPC cert against the beacon committee, Skip cert against
/// the active pool. `Genesis` certs reject — past-tip genesis blocks
/// have no replayable verification.
#[must_use]
pub fn verify_certified(
    block: &CertifiedBeaconBlock,
    network: &NetworkDefinition,
    signers: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match block.cert() {
        BeaconCert::Normal(cert) => {
            verify_block_cert(cert, network, &spc_context(block.epoch()), signers).is_ok()
        }
        BeaconCert::Skip(cert) => verify_skip_cert(cert, network, signers).is_ok(),
        BeaconCert::Genesis(_) => false,
    }
}

/// Verify every `PcVoteEquivocation` carried in `block`'s committed
/// proposals against the supplied `signers` lookup.
///
/// `signers` must cover every equivocating validator referenced by the
/// block's witnesses — the coordinator filters `state.validators` down
/// to the referenced subset before dispatch. Missing pubkeys reject the
/// block at admission, matching the "fail closed" stance.
///
/// Returns `true` when the block carries no equivocations.
#[must_use]
pub fn verify_block_equivocations(
    block: &CertifiedBeaconBlock,
    network: &NetworkDefinition,
    signers: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    for (_, proposal) in block.block().committed_proposals() {
        for ev in proposal.equivocations().iter() {
            if verify_vote_equivocation(ev.as_unverified(), network, signers).is_err() {
                return false;
            }
        }
    }
    true
}

// ─── Typestate ─────────────────────────────────────────────────────────────

/// Verification context for [`CertifiedBeaconBlock`].
///
/// The cert variant determines which signer pool the BLS aggregate
/// verifies under: SPC certs against the beacon committee for the
/// block's epoch, Skip certs against the active validator pool at the
/// anchor's epoch. Equivocation witnesses bring their own per-validator
/// pubkey lookup since the equivocating validator need not be on the
/// current signer pool.
#[derive(Debug, Clone, Copy)]
pub struct CertifiedBeaconBlockVerifyContext<'a> {
    /// Network the cert and equivocation evidence were bound to.
    pub network: &'a NetworkDefinition,
    /// Signer pool the cert verifies against (committee for Normal,
    /// active pool for Skip). Positional ordering matches the cert's
    /// signer bitfield.
    pub signers: &'a [(ValidatorId, Bls12381G1PublicKey)],
    /// Pubkeys for the validators referenced by embedded
    /// `PcVoteEquivocation` evidence. The coordinator filters
    /// `state.validators` down to the referenced subset; an evidence
    /// signer missing from this lookup rejects the block.
    pub equivocation_signers: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Bind a block's committed proposals to the value its cert
/// authenticates.
///
/// A `Normal` cert's [`committed_value`](crate::SpcCert::committed_value)
/// is the committee-agreed `PcVector`: one
/// [`pc_element_hash`](crate::BeaconProposal::pc_element_hash) per
/// committee position, `ZERO` where no proposal was committed. A
/// well-formed block carries exactly those proposals — each at its
/// proposer's committee position. This recomputes the vector from the
/// block's proposals and requires byte equality, so a relay can't pair
/// a genuine cert with substituted proposal bytes. `Skip`/`Genesis`
/// carry no proposals (enforced by the pairing invariant) and bind
/// trivially.
///
/// `committee` is the cert's signer pool in positional order (committee
/// for `Normal`) — the same slice the cert itself verifies against.
#[must_use]
fn verify_committed_proposal_binding(
    block: &CertifiedBeaconBlock,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let BeaconCert::Normal(cert) = block.cert() else {
        return true;
    };
    let certified: Vec<PcValueElement> = cert.committed_value().iter().copied().collect();
    let epoch = block.epoch();
    let mut canonical = vec![PcValueElement::ZERO; certified.len()];
    for (validator, proposal) in block.block().committed_proposals() {
        let Some(pos) = committee.iter().position(|(id, _)| id == validator) else {
            return false;
        };
        // A second proposal at the same position, or a position past the
        // certified vector, can't be a faithful reconstruction.
        if pos >= canonical.len() || canonical[pos] != PcValueElement::ZERO {
            return false;
        }
        canonical[pos] = proposal.pc_element_hash(epoch);
    }
    canonical == certified
}

/// Failure modes of a certified beacon block.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedBeaconBlockVerifyError {
    /// Cert (Normal or Skip) did not verify under its required signer
    /// pool, or `Genesis` cert reached the verifier (genesis blocks
    /// have no replayable verification).
    #[error("authenticating cert rejected")]
    BadCert,
    /// One or more embedded `PcVoteEquivocation` did not verify
    /// against the equivocation signer pool.
    #[error("embedded equivocation witness rejected")]
    BadEquivocationWitness,
    /// The block's committed proposals don't reconstruct the
    /// `PcVector` the cert authenticates — a relay paired a genuine
    /// cert with substituted proposal bytes.
    #[error("committed proposals don't match the authenticating cert")]
    ProposalCertMismatch,
}

impl Verify<&CertifiedBeaconBlockVerifyContext<'_>> for CertifiedBeaconBlock {
    type Error = CertifiedBeaconBlockVerifyError;

    /// Composite predicate: the cert verifies under the variant's
    /// required signer pool (via [`verify_certified`]) and every
    /// embedded `PcVoteEquivocation` verifies against
    /// `equivocation_signers` (via [`verify_block_equivocations`]).
    fn verify(
        &self,
        ctx: &CertifiedBeaconBlockVerifyContext<'_>,
    ) -> Result<Verified<Self>, Self::Error> {
        if !verify_certified(self, ctx.network, ctx.signers) {
            return Err(CertifiedBeaconBlockVerifyError::BadCert);
        }
        if !verify_block_equivocations(self, ctx.network, ctx.equivocation_signers) {
            return Err(CertifiedBeaconBlockVerifyError::BadEquivocationWitness);
        }
        if !verify_committed_proposal_binding(self, ctx.signers) {
            return Err(CertifiedBeaconBlockVerifyError::ProposalCertMismatch);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<CertifiedBeaconBlock> {
    /// Pair a locally-assembled block with its authenticating cert
    /// after the SPC FSM committed and the coordinator built the
    /// `CertifiedBeaconBlock` from verified inputs. The pairing
    /// invariant is checked at [`CertifiedBeaconBlock::new_checked`];
    /// trust source: the FSM's committed-block path produces the cert
    /// directly from verified PC outputs, the block from
    /// pool-accepted proposals.
    ///
    /// Mirror of the shard `Verified::<CertifiedBlock>::assemble`
    /// pattern. Returns the underlying pairing error if the cert
    /// shape doesn't match the block shape.
    ///
    /// # Errors
    ///
    /// Returns [`CertifiedBeaconBlockPairingError`] when the cert
    /// shape doesn't match the block shape.
    pub fn from_committed_assembly(
        block: BeaconBlock,
        cert: BeaconCert,
    ) -> Result<Self, CertifiedBeaconBlockPairingError> {
        CertifiedBeaconBlock::new_checked(block, cert).map(Self::new_unchecked)
    }

    /// Genesis bootstrap pair, verified by construction — the genesis
    /// `config_hash` doesn't need a cryptographic check; identity is
    /// established by the operator config the node was launched with.
    #[must_use]
    pub const fn genesis(config_hash: GenesisConfigHash) -> Self {
        Self::new_unchecked(CertifiedBeaconBlock::genesis(config_hash))
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
        ValidatorId, VrfOutput, VrfProof, bls_keypair_from_seed,
    };

    fn proposal(seed: u8) -> BeaconProposal {
        BeaconProposal::new(
            Vec::new(),
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
            proof: proof.into(),
        }
    }

    fn committee_of(n: u64) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&i.to_le_bytes());
                (
                    ValidatorId::new(i),
                    bls_keypair_from_seed(&seed).public_key(),
                )
            })
            .collect()
    }

    /// A `Normal` cert whose committed value is `value`. The binding
    /// check only reads `committed_value()`, so the embedded proof is a
    /// placeholder — this exercises `verify_committed_proposal_binding`
    /// in isolation, not the cert's BLS verification.
    fn normal_cert_with_value(value: PcVector) -> BeaconCert {
        let qc2 = PcQc2::new(
            value.clone(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        let proof = PcQc3::new(
            value.clone(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        );
        BeaconCert::Normal(Box::new(SpcCert::Direct {
            prev_view: SpcView::new(1),
            value,
            proof: proof.into(),
        }))
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

    /// A `Normal` block binds to its cert only when every committed
    /// proposal hashes, at its committee position, to the matching
    /// element of the cert's committed value. Substituted proposal
    /// bytes, a wrong position, or a missing proposal all break the
    /// binding — the C1 forgery defence.
    #[test]
    fn committed_proposals_bind_to_cert_value() {
        let epoch = Epoch::new(5);
        let prev = BeaconBlockHash::from_raw(Hash::from_bytes(b"prev"));
        let committee = committee_of(4);
        let proposer = ValidatorId::new(1);
        let good = proposal(7);
        let h = good.pc_element_hash(epoch);
        // Committed value: the proposer sits at committee position 1.
        let value = PcVector::new([
            PcValueElement::ZERO,
            h,
            PcValueElement::ZERO,
            PcValueElement::ZERO,
        ]);

        let bind = |proposals: Vec<(ValidatorId, BeaconProposal)>| {
            let block = BeaconBlock::new(epoch, prev, proposals);
            let certified =
                CertifiedBeaconBlock::new_checked(block, normal_cert_with_value(value.clone()))
                    .unwrap();
            verify_committed_proposal_binding(&certified, &committee)
        };

        // Faithful block binds.
        assert!(bind(vec![(proposer, good.clone())]));
        // Substituted proposal bytes (different VRF) hash differently.
        assert!(!bind(vec![(proposer, proposal(8))]));
        // Right proposal, wrong committee position.
        assert!(!bind(vec![(ValidatorId::new(2), good.clone())]));
        // Cert expects a proposal the block omits.
        assert!(!bind(Vec::new()));
        // A proposer absent from the committee can't be placed.
        assert!(!bind(vec![(ValidatorId::new(9), good)]));
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
